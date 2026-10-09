require "./go_route_extractor_ts"
require "../models/route_evidence"

module Noir
  # Adapter for AfterShip's `golang-common/http/server/gins/apiserver`
  # wrapper layered on top of Gin:
  #
  #   server := apiserver.NewApiServer(apiserver.ServerConfig{BasePath: "/x"})
  #   server.AddApiGroup(v2.BuildApiGroup(conf))          // root mount
  #   func BuildApiGroup() apiserver.ApiGroup {            // builder
  #     g := apiserver.ApiGroup{RelativePath: "/orders"}   // group literal
  #     g.AddApi(apiserver.NewPostApi("/items", h))        // route
  #     g.AddSubGroup(child.BuildApiGroup())               // nesting edge
  #   }
  #
  # The model is value-shaped (ApiGroup structs) rather than pointer
  # RouterGroups, so it runs as its own pass beside GinMountResolver.
  # Facts stay source-level: a builder with no reachable AddApiGroup
  # root keeps relative paths and `registration_status: unknown`.
  class ApiserverAdapter
    alias TS = TreeSitter
    alias Node = LibTreeSitter::TSNode

    APISERVER_IMPORT = "github.com/AfterShip/golang-common/http/server/gins/apiserver"
    IMPORT_MARKER    = "/gins/apiserver"

    VERB_CONSTRUCTORS = {
      "NewGetApi"     => "GET",
      "NewPostApi"    => "POST",
      "NewPutApi"     => "PUT",
      "NewPatchApi"   => "PATCH",
      "NewDeleteApi"  => "DELETE",
      "NewHeadApi"    => "HEAD",
      "NewOptionApi"  => "OPTIONS",
      "NewOptionsApi" => "OPTIONS",
      "NewAnyApi"     => "ANY",
    }

    record Builder, symbol : String, file : String, line : Int32, prefix : String
    record ApiHit, route : TreeSitterGoRouteExtractor::Route, file : String,
      evidence : RouteEvidence, builder : String
    record MountEdge, parent : String, child : String, file : String, line : Int32
    record RootMount, child : String, base_path : String, base_resolved : Bool,
      file : String, line : Int32

    @imports = {} of String => Hash(String, String)

    def initialize(@sources : Hash(String, String), @module_paths : Hash(String, String))
      @sources.each do |file, source|
        next unless source.includes?(IMPORT_MARKER)
        @imports[file] = imports_for(source)
      end
    end

    def resolve : Array(GinMountResolver::Hit)
      builders = {} of String => Builder
      hits = [] of ApiHit
      edges = [] of MountEdge
      roots = [] of RootMount

      @sources.each do |file, source|
        next unless source.includes?(IMPORT_MARKER)
        imports = @imports[file]
        TS.parse_go(source) do |root|
          TS.each_named_child(root) do |node|
            next unless {"function_declaration", "method_declaration"}.includes?(TS.node_type(node))
            scan_function(node, file, source, imports) do |builder, routes, func_edges, func_roots|
              if builder
                existing = builders[builder.symbol]?
                builders[builder.symbol] = existing ? existing : builder
                routes.each { |h| hits << ApiHit.new(h.route, h.file, h.evidence, builder.symbol) }
              else
                routes.each { |h| hits << h }
              end
              edges.concat(func_edges)
              roots.concat(func_roots)
            end
          end
        end
      end

      # BFS from AddApiGroup roots: builder full path = base + prefix chain.
      full = {} of String => Tuple(String, String, Bool) # symbol => {path, entrypoint, base_resolved}
      roots.each do |root|
        next if full.has_key?(root.child)
        queue = [{root.child, root.base_resolved ? root.base_path : "", entry_for(root), root.base_resolved}]
        until queue.empty?
          symbol, path, entrypoint, base_resolved = queue.shift
          next if full.has_key?(symbol)
          builder = builders[symbol]?
          next unless builder
          full[symbol] = {join(path, builder.prefix), entrypoint, base_resolved}
          edges.each do |edge|
            queue << {edge.child, full[symbol][0], entrypoint, base_resolved} if edge.parent == symbol
          end
        end
      end

      hits.map do |hit|
        evidence = hit.evidence
        builder = builders[hit.builder]?
        if mount = full[hit.builder]?
          evidence.entrypoint = mount[1]
          evidence.registration_status = "registered"
          evidence.path_resolution = mount[2] ? "resolved" : "partial"
          unless mount[2]
            evidence.issues << "server_base_path_unknown"
          end
          path = hit.route.raw_path.empty? ? mount[0] : join(mount[0], hit.route.raw_path)
        else
          evidence.registration_status = "unknown"
          evidence.path_resolution = "partial"
          evidence.issues << "external_mount_unresolved"
          rel = builder ? builder.prefix : ""
          path = hit.route.raw_path.empty? ? rel : join(rel, hit.route.raw_path)
        end
        route = hit.route
        GinMountResolver::Hit.new(
          TreeSitterGoRouteExtractor::Route.new(route.router_name, route.verb, path,
            route.raw_path, route.handler, route.line),
          hit.file, evidence)
      end.uniq { |hit| {hit.file, hit.route.line, hit.route.verb, hit.route.path} }
    end

    private def entry_for(root : RootMount) : String
      "#{File.dirname(root.file)}::apiserver.NewApiServer"
    end

    private def join(prefix : String, path : String) : String
      return path.empty? ? "/" : path if prefix.empty?
      return prefix if path.empty?
      prefix.rchop('/') + "/" + path.lchop('/')
    end

    private def scan_function(node, file : String, source : String, imports)
      name_node = TS.field(node, "name")
      body = TS.field(node, "body")
      return unless name_node && body
      symbol = "#{File.dirname(file)}::#{TS.node_text(name_node, source)}"

      group_vars = {} of String => GroupInfo        # var => group literal info
      builder_vars = {} of String => String         # var => builder symbol
      field_groups = {} of String => String         # "x.ApiGroup" => group var name
      server_bases = {} of String => Tuple(String, Bool) # server var => {BasePath, resolved}
      config_vars = {} of String => String          # ServerConfig var => BasePath literal

      routes = [] of ApiHit
      edges = [] of MountEdge
      roots = [] of RootMount

      builder_prefix = ""
      builder_prefix_known = false
      builder_file = file
      builder_line = TS.node_start_row(node) + 1
      api_group_fn = returns_api_group?(node, source, imports)

      walk(body) do |n|
        kind = TS.node_type(n)
        if {"short_var_declaration", "assignment_statement", "var_spec"}.includes?(kind)
          left = TS.field(n, "left") || TS.field(n, "name")
          right = TS.field(n, "right") || TS.field(n, "value")
          next unless left && right
          lhs = TS.node_type(left) == "expression_list" ? each_child(left) : [left]
          rhs = TS.node_type(right) == "expression_list" ? each_child(right) : [right]
          lhs.each_with_index do |name_node2, i|
            expression = rhs[i]?
            next unless expression
            name = TS.node_text(name_node2, source)
            if TS.node_type(name_node2) == "identifier"
              if info = api_group_literal(expression, file, source, imports)
                group_vars[name] = info
                unless builder_prefix_known
                  builder_prefix = info.prefix
                  builder_prefix_known = true
                  builder_file = info.file
                  builder_line = info.line + 1
                end
              elsif target = builder_call_symbol(expression, file, source, imports)
                builder_vars[name] = target
              elsif base = new_api_server_base(expression, source, imports, config_vars)
                server_bases[name] = base
              elsif config_base = server_config_base(expression, source)
                config_vars[name] = config_base if config_base
              end
            elsif TS.node_type(name_node2) == "selector_expression"
              field = TS.field(name_node2, "field")
              operand = TS.field(name_node2, "operand")
              if field && operand && TS.node_text(field, source) == "ApiGroup"
                field_groups["#{TS.node_text(operand, source)}.ApiGroup"] = TS.node_text(expression, source)
              end
            end
          end
        elsif kind == "call_expression"
          fn = TS.field(n, "function")
          args_node = TS.field(n, "arguments")
          next unless fn && args_node
          next unless TS.node_type(fn) == "selector_expression"
          operand = TS.field(fn, "operand")
          field = TS.field(fn, "field")
          next unless operand && field
          receiver = TS.node_text(operand, source)
          method = TS.node_text(field, source)
          args = each_child(args_node)
          case method
          when "AddApi"
            arg = args.first?
            if route = add_api_route(arg, receiver, group_vars, file, source, imports)
              routes << ApiHit.new(route[0], file, route[1], symbol)
            end
          when "AddGzipApi"
            # gzip.AddGzipApi(&apiGroup, apiserver.NewXxxApi(...)): the api
            # constructor is the second argument, the group a pointer to the
            # receiver-name variable.
            next unless args.size >= 2
            group_arg = args[0]
            group_name = TS.node_text(group_arg, source).lchop('&')
            if route = add_api_route(args[1], group_name, group_vars, file, source, imports)
              routes << ApiHit.new(route[0], file, route[1], symbol)
            end
          when "AddSubGroup"
            if arg = args.first?
              if child = subgroup_symbol(arg, builder_vars, field_groups, file, source, imports)
                edges << MountEdge.new(symbol, child, file, TS.node_start_row(n) + 1)
              end
            end
          when "AddApiGroup"
            if arg = args.first?
              if child = subgroup_symbol(arg, builder_vars, field_groups, file, source, imports)
                base = server_bases[receiver]? || {"", false}
                roots << RootMount.new(child, base[0], base[1], file, TS.node_start_row(n) + 1)
              elsif TS.node_type(arg) == "identifier" && (group = group_vars[TS.node_text(arg, source)]?)
                # Local-group mount: RegisterAPIEndpoints(apiServer) builds a
                # group literal and hands it straight to AddApiGroup. The
                # enclosing function becomes its own root mounted at the
                # group's RelativePath; the server BasePath stays unknown
                # unless NewApiServer was seen in this function.
                base = server_bases[receiver]? || {"", false}
                roots << RootMount.new(symbol, base[0], base[1], file, TS.node_start_row(n) + 1)
              end
            end
          end
        end
      end

      builder = nil
      if api_group_fn || builder_prefix_known || !routes.empty?
        builder = Builder.new(symbol, builder_file, builder_line, builder_prefix)
      end
      yield builder, routes, edges, roots
    end

    private def walk(node : Node, &block : Node ->)
      yield node
      each_child(node).each { |child| walk(child, &block) }
    end

    private def returns_api_group?(node, source, imports) : Bool
      result = TS.field(node, "result")
      return false unless result
      text = TS.node_text(result, source)
      text.includes?("ApiGroup") && apiserver_qualifier?(text, imports)
    end

    private def api_group_literal(node, file : String, source : String, imports)
      return unless TS.node_type(node) == "composite_literal"
      type = TS.field(node, "type")
      return unless type
      type_text = TS.node_text(type, source)
      return unless type_text.includes?("ApiGroup") && apiserver_qualifier?(type_text, imports)
      prefix = ""
      each_child(node).each do |child|
        next unless TS.node_type(child) == "literal_value"
        each_child(child).each do |elem|
          next unless TS.node_type(elem) == "keyed_element"
          pair = each_child(elem)
          key = pair.first?
          value = pair.last?
          next unless key && value
          next unless TS.node_text(key, source).ends_with?("RelativePath")
          if match = TS.node_text(value, source).match(/\A"([^"]*)"\z/)
            prefix = match[1]
          end
        end
      end
      GroupInfo.new(prefix, file, TS.node_start_row(node))
    end

    private def builder_call_symbol(node, file : String, source : String, imports) : String?
      return unless TS.node_type(node) == "call_expression"
      fn = TS.field(node, "function")
      return unless fn && TS.node_type(fn) == "selector_expression"
      operand = TS.field(fn, "operand")
      field = TS.field(fn, "field")
      return unless operand && field
      qualifier = TS.node_text(operand, source)
      imported = imports[qualifier]?
      return unless imported
      dir = package_dir(file, imported)
      return unless dir
      "#{dir}::#{TS.node_text(field, source)}"
    end

    private def new_api_server_base(node, source : String, imports, config_vars)
      return unless TS.node_type(node) == "call_expression"
      fn = TS.field(node, "function")
      return unless fn
      return unless apiserver_qualifier?(TS.node_text(fn, source), imports) &&
                    TS.node_text(fn, source).ends_with?("NewApiServer")
      args_node = TS.field(node, "arguments")
      return {"", false} unless args_node
      arg = each_child(args_node).first?
      return {"", false} unless arg
      if TS.node_type(arg) == "identifier" && (config_base = config_vars[TS.node_text(arg, source)]?)
        return {config_base, true}
      end
      base = base_path_from_config(arg, source)
      base ? {base, true} : {"", false}
    end

    private def server_config_base(node, source) : String?
      return unless TS.node_type(node) == "composite_literal"
      type = TS.field(node, "type")
      return unless type
      return unless TS.node_text(type, source).includes?("ServerConfig")
      base_path_from_config(node, source)
    end

    private def base_path_from_config(node, source) : String?
      # `apiserver.ServerConfig{... BasePath: "/x" ...}` literal, or a
      # parenthesized variant; identifiers resolve via assignment walk
      # elsewhere — only literal bodies are readable here.
      return unless TS.node_type(node) == "composite_literal"
      type = TS.field(node, "type")
      return unless type
      return unless TS.node_text(type, source).includes?("ServerConfig")
      each_child(node).each do |child|
        next unless TS.node_type(child) == "literal_value"
        each_child(child).each do |elem|
          next unless TS.node_type(elem) == "keyed_element"
          pair = each_child(elem)
          key = pair.first?
          value = pair.last?
          next unless key && value
          next unless TS.node_text(key, source) == "BasePath"
          if match = TS.node_text(value, source).match(/\A"([^"]*)"\z/)
            return match[1]
          end
        end
      end
      nil
    end

    private def add_api_route(arg, receiver : String, group_vars, file : String,
                              source : String, imports)
      ctor = find_api_constructor(arg, source, 2)
      return unless ctor
      fn = TS.field(ctor, "function")
      field = fn ? TS.field(fn, "field") : nil
      return unless fn && field
      verb = VERB_CONSTRUCTORS[TS.node_text(field, source)]?
      return unless verb
      args_node = TS.field(ctor, "arguments")
      return unless args_node
      args = each_child(args_node)
      path_node = args.first?
      return unless path_node
      unless match = TS.node_text(path_node, source).match(/\A"([^"]*)"\z/)
        return # dynamic path literal — leave to diagnostics
      end
      raw_path = match[1]
      handler = args[1]? ? TS.node_text(args[1], source) : ""
      handler = "inline" unless handler.matches?(/\A[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\z/)
      group = group_vars[receiver]?
      prefix = group ? group.prefix : ""
      # Route path stays the raw literal; builder prefix is applied once
      # at materialize time (mounted chain or relative fallback).
      route = TreeSitterGoRouteExtractor::Route.new(receiver, verb,
        raw_path, raw_path, handler, TS.node_start_row(ctor))
      evidence = RouteEvidence.new
      evidence.handler = handler
      evidence.mount_expression = group ? "apiserver.ApiGroup{RelativePath: \"#{group.prefix}\"}" : receiver
      evidence.mount_file = file
      evidence.mount_line = group ? group.line + 1 : TS.node_start_row(ctor) + 1
      {route, evidence}
    end

    # Locates the `apiserver.NewXxxApi(...)` constructor inside an AddApi
    # argument, unwrapping up to `depth` middleware layers such as
    # `idempotency.SetIdempotencyToContext(apiserver.NewPostApi(...))`.
    private def find_api_constructor(node, source : String, depth : Int32)
      return unless node && TS.node_type(node) == "call_expression"
      fn = TS.field(node, "function")
      if fn && TS.node_type(fn) == "selector_expression"
        field = TS.field(fn, "field")
        if field && VERB_CONSTRUCTORS.has_key?(TS.node_text(field, source))
          return node
        end
      end
      return unless depth > 0
      args_node = TS.field(node, "arguments")
      return unless args_node
      each_child(args_node).each do |arg|
        if found = find_api_constructor(arg, source, depth - 1)
          return found
        end
      end
      nil
    end

    private def subgroup_symbol(node, builder_vars, field_groups, file : String,
                                source : String, imports) : String?
      if target = builder_call_symbol(node, file, source, imports)
        return target
      end
      text = TS.node_text(node, source)
      if TS.node_type(node) == "identifier"
        return builder_vars[text]?
      end
      if TS.node_type(node) == "selector_expression" && text.ends_with?(".ApiGroup")
        if group_name = field_groups[text]?
          return builder_vars[group_name]?
        end
      end
      nil
    end

    private def apiserver_qualifier?(text : String, imports) : Bool
      return true if text.includes?(APISERVER_IMPORT)
      qualifier = text.split('.').first?
      return false unless qualifier
      imports[qualifier]? == APISERVER_IMPORT || qualifier == "apiserver"
    end

    private def package_dir(file : String, import_path : String) : String?
      pair = @module_paths.to_a.select { |_, mod| import_path == mod || import_path.starts_with?(mod + "/") }
        .max_by? { |_, mod| mod.size }
      return unless pair
      root, mod = pair
      directory = File.join(root, import_path.lchop(mod).lchop('/'))
      @sources.each_key do |path|
        candidate = File.dirname(path)
        return candidate if File.expand_path(candidate) == File.expand_path(directory)
      end
      directory
    end

    private def each_child(node : Node) : Array(Node)
      list = [] of Node
      TS.each_named_child(node) { |child| list << child }
      list
    end

    private def imports_for(source : String) : Hash(String, String)
      imports = {} of String => String
      TS.parse_go(source) do |root|
        TS.walk(root) do |node|
          next unless TS.node_type(node) == "import_spec"
          path = TS.field(node, "path")
          next unless path
          value = TS.node_text(path, source).strip('"')
          alias_node = TS.field(node, "name")
          name = alias_node ? TS.node_text(alias_node, source) : value.split('/').last
          imports[name] = value unless {"_", "."}.includes?(name)
        end
      end
      imports
    end

    record GroupInfo, prefix : String, file : String, line : Int32
  end
end
