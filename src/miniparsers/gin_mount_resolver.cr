require "./go_route_extractor_ts"
require "../models/route_evidence"

module Noir
  # A bounded source-only registration graph. Symbols include the package
  # directory and receiver type; a method name alone is never a call target.
  class GinMountResolver
    alias TS = TreeSitter
    alias Node = LibTreeSitter::TSNode
    alias Types = Hash(String, Set(String))

    record Mount, path : String, expression : String, file : String, line : Int32,
      resolution : String, entrypoint : String
    record Scope, file : String, name : String, receiver : String, receiver_name : String,
      param : String, param_index : Int32, start_row : Int32, end_row : Int32, symbol : String
    record Hit, route : TreeSitterGoRouteExtractor::Route, file : String, evidence : RouteEvidence

    @scopes = [] of Scope
    @imports = {} of String => Hash(String, String)
    @returns = {} of String => Set(String)
    @contexts = {} of String => Array(Mount)
    @collections = {} of String => Set(String)
    @hits = [] of Hit
    @limit_hit = false
    @global_environments = {} of String => Tuple(Hash(String, Mount), Types)

    def initialize(@sources : Hash(String, String), @module_paths : Hash(String, String),
                   @root_overrides : Hash(String, String) = {} of String => String)
      @sources.each do |file, source|
        @imports[file] = imports_for(source)
        collect_scopes(file, source)
      end
    end

    def resolve : Array(Hit)
      # First seed concrete constructors/collections and non-parameter roots.
      # Subsequent passes propagate mounted parameters through delegates.
      16.times do |iteration|
        previous = @contexts.values.sum(&.size) + @collections.values.sum(&.size)
        @hits.clear
        @scopes.each do |scope|
          mounts = @contexts[scope.symbol]?
          if mounts && !mounts.empty?
            mounts.each { |mount| analyze_scope(scope, mount, true) }
          else
            unknown = Mount.new("", scope.symbol, scope.file, scope.start_row + 1,
              "partial", scope.symbol)
            analyze_scope(scope, unknown, scope.param.empty?)
          end
        end
        break if previous == @contexts.values.sum(&.size) + @collections.values.sum(&.size)
        @limit_hit = true if iteration == 15
      end
      if @limit_hit
        @hits.map! do |hit|
          evidence = hit.evidence.detached_copy
          evidence.issues << "registration_graph_limit_reached"
          evidence.registration_status = "unknown"
          Hit.new(hit.route, hit.file, evidence)
        end
      end
      @hits.uniq { |hit| {hit.file, hit.route.line, hit.route.verb, hit.route.path, hit.evidence.scope} }
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

    private def package_dir(file : String, import_path : String) : String?
      pair = @module_paths.to_a.select { |_, mod| import_path == mod || import_path.starts_with?(mod + "/") }
        .max_by? { |_, mod| mod.size }
      return unless pair
      root, mod = pair
      directory = File.join(root, import_path.lchop(mod).lchop('/'))
      # Library/fixture callers may index relative filenames. Keep the same
      # representation in symbol keys rather than mixing it with module roots.
      @sources.each_key do |path|
        candidate = File.dirname(path)
        return candidate if File.expand_path(candidate) == File.expand_path(directory)
      end
      directory
    end

    private def type_symbol(file : String, text : String) : String
      name = text.strip.lchop('*')
      if name.includes?('.')
        qualifier, type = name.split('.', 2)
        if imported = @imports[file][qualifier]?
          if dir = package_dir(file, imported)
            return "#{dir}::#{type}"
          end
          return "#{imported}::#{type}"
        end
      end
      "#{File.dirname(file)}::#{name}"
    end

    private def collect_scopes(file : String, source : String)
      TS.parse_go(source) do |root|
        TS.walk(root) do |node|
          next unless {"function_declaration", "method_declaration"}.includes?(TS.node_type(node))
          nn = TS.field(node, "name")
          params = TS.field(node, "parameters")
          next unless nn && params
          name = TS.node_text(nn, source)
          receiver = ""
          receiver_name = ""
          if receiver_node = TS.field(node, "receiver")
            TS.each_named_child(receiver_node) do |decl|
              if type = TS.field(decl, "type")
                receiver = type_symbol(file, TS.node_text(type, source))
              end
              if rn = TS.field(decl, "name")
                receiver_name = TS.node_text(rn, source)
              end
            end
          end
          param = ""
          param_index = 0
          index = 0
          TS.each_named_child(params) do |decl|
            type = TS.field(decl, "type")
            pn = TS.field(decl, "name")
            if type && pn && TS.node_text(type, source).lchop('*').split('.').last == "RouterGroup"
              param = TS.node_text(pn, source)
              param_index = index
            end
            index += 1
          end
          symbol = receiver.empty? ? "#{File.dirname(file)}::#{name}" : "#{receiver}.#{name}"
          @scopes << Scope.new(file, name, receiver, receiver_name, param, param_index,
            TS.node_start_row(node), TS.node_end_row(node), symbol)
          if result = TS.field(node, "result")
            text = TS.node_text(result, source)
            if first = text.match(/\A\(\s*(\*?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*,/)
              text = first[1]
            end
            if text.matches?(/\A\*?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?\z/) && text != "error"
              (@returns[symbol] ||= Set(String).new) << type_symbol(file, text)
            end
          end
        end
      end
    end

    private def analyze_scope(scope : Scope, mount : Mount, bound : Bool)
      source = @sources[scope.file]
      TS.parse_go(source) do |root|
        TS.each_named_child(root) do |node|
          next unless TS.node_start_row(node) == scope.start_row &&
                      {"function_declaration", "method_declaration"}.includes?(TS.node_type(node))
          body = TS.field(node, "body")
          next unless body
          globals, global_types = global_environment(File.dirname(scope.file))
          groups = globals.dup
          types = global_types.transform_values(&.dup)
          groups[scope.param] = mount unless scope.param.empty?
          types[scope.receiver_name] = Set{scope.receiver} unless scope.receiver_name.empty?
          if params = TS.field(node, "parameters")
            TS.each_named_child(params) do |decl|
              pn = TS.field(decl, "name")
              pt = TS.field(decl, "type")
              next unless pn && pt
              name = TS.node_text(pn, source)
              text = TS.node_text(pt, source)
              types[name] = Set{type_symbol(scope.file, text)}
              if text.lchop('*').split('.').last == "Engine"
                groups[name] = Mount.new("", "", scope.file, TS.node_start_row(decl) + 1,
                  "resolved", "#{scope.symbol}:#{name}")
              end
            end
          end
          visit(body, scope, source, groups, types, bound)
        end
      end
    end

    private def global_environment(directory : String) : Tuple(Hash(String, Mount), Types)
      if cached = @global_environments[directory]?
        return cached
      end
      groups = {} of String => Mount
      types = {} of String => Set(String)
      # Parse each package's declarations once, not once per function/pass.
      @sources.each do |file, source|
        next unless File.dirname(file) == directory
        scope = Scope.new(file, "global", "", "", "", 0, 0, 0, "#{directory}::global")
        TS.parse_go(source) do |root|
          TS.each_named_child(root) do |declaration|
            next unless TS.node_type(declaration) == "var_declaration"
            visit(declaration, scope, source, groups, types, true)
          end
        end
      end
      @global_environments[directory] = {groups, types}
    end

    private def children(node : Node) : Array(Node)
      list = [] of Node
      TS.each_named_child(node) { |child| list << child }
      list
    end

    # Environments are copied at lexical blocks. Assignment visits occur in
    # source order; inner shadowing never changes a sibling function/block.
    private def visit(node : Node, scope : Scope, source : String,
                      groups : Hash(String, Mount), types : Types, bound : Bool)
      kind = TS.node_type(node)
      if {"short_var_declaration", "assignment_statement", "var_spec"}.includes?(kind)
        left = TS.field(node, "left") || TS.field(node, "name")
        right = TS.field(node, "right") || TS.field(node, "value")
        if left && right
          lhs = TS.node_type(left) == "expression_list" ? children(left) : [left]
          rhs = TS.node_type(right) == "expression_list" ? children(right) : [right]
          lhs.each_with_index do |name_node, i|
            expression = rhs[i]?
            next unless expression
            name = TS.node_text(name_node, source)
            if group = group_for(expression, scope, source, groups)
              if group.entrypoint.ends_with?(":gin-root")
                group = Mount.new(group.path, group.expression, group.file, group.line,
                  group.resolution, "#{scope.symbol}:#{name}")
              end
              groups[name] = group
            else
              groups.delete(name)
            end
            inferred = types_for(expression, scope, source, types)
            types[name] = inferred unless inferred.empty?
            if TS.node_type(expression) == "call_expression"
              fn = TS.field(expression, "function")
              args = TS.field(expression, "arguments")
              if fn && args && TS.node_text(fn, source) == "append"
                elements = children(args)
                if head = elements.first?
                  key = collection_key(TS.node_text(head, source), scope, types)
                  set = (@collections[key] ||= Set(String).new)
                  elements.skip(1).each { |arg| set.concat(types_for(arg, scope, source, types)) }
                end
              end
            end
          end
        end
      elsif kind == "range_clause"
        left = TS.field(node, "left")
        right = TS.field(node, "right")
        if left && right
          names = children(left)
          name = names.last?
          if name
            key = collection_key(TS.node_text(right, source), scope, types)
            if members = @collections[key]?
              types[TS.node_text(name, source)] = members.dup
            end
          end
        end
      elsif kind == "call_expression"
        handle_call(node, scope, source, groups, types, bound)
      end
      children(node).each do |child|
        # Closures need their own parameter analysis; do not attribute routes
        # in an arbitrary callback to the enclosing registration scope.
        next if TS.node_type(child) == "func_literal"
        if {"block", "for_statement", "if_statement", "expression_switch_statement"}.includes?(TS.node_type(child))
          visit(child, scope, source, groups.dup, types.dup, bound)
        else
          visit(child, scope, source, groups, types, bound)
        end
      end
    end

    private def group_for(node : Node, scope : Scope, source : String,
                          groups : Hash(String, Mount)) : Mount?
      text = TS.node_text(node, source)
      return groups[text]? unless TS.node_type(node) == "call_expression"
      fn = TS.field(node, "function")
      args = TS.field(node, "arguments")
      return unless fn && args
      if TS.node_type(fn) == "selector_expression"
        operand = TS.field(fn, "operand")
        field = TS.field(fn, "field")
        return unless operand && field
        name = TS.node_text(field, source)
        if {"Group", "Use"}.includes?(name)
          parent = group_for(operand, scope, source, groups)
          return unless parent
          return parent if name == "Use"
          arg = children(args).first?
          return unless arg
          literal = literal_path(arg, source)
          return Mount.new(parent.path, text, scope.file, TS.node_start_row(node) + 1,
            "partial", parent.entrypoint) unless literal
          return Mount.new(join(parent.path, literal), parent.expression, parent.file,
            parent.line, parent.resolution, parent.entrypoint)
        elsif name == "GetAPIRouteGroup"
          # Known company accessor semantics, but its prefix is not guessed.
          override = @root_overrides[name]?
          return Mount.new(override || "", text, scope.file, TS.node_start_row(node) + 1,
            override ? "resolved" : "partial", "#{scope.symbol}:#{TS.node_text(operand, source)}")
        elsif name == "GetAPIEngine"
          return Mount.new("", text, scope.file, TS.node_start_row(node) + 1,
            "resolved", "#{scope.symbol}:#{TS.node_text(operand, source)}:engine")
        elsif {"New", "Default"}.includes?(name)
          qualifier = TS.node_text(operand, source)
          if @imports[scope.file][qualifier]? == "github.com/gin-gonic/gin"
            return Mount.new("", "", scope.file, TS.node_start_row(node) + 1,
              "resolved", "#{scope.symbol}:gin-root")
          end
        end
      end
      nil
    end

    private def literal_path(node : Node, source : String) : String?
      return unless {"interpreted_string_literal", "raw_string_literal"}.includes?(TS.node_type(node))
      text = TS.node_text(node, source)
      value = text[1...-1]
      return if value.matches?(/[\x00-\x1f\\]/) || value.includes?("://")
      value
    end

    private def types_for(node : Node, scope : Scope, source : String, types : Types) : Set(String)
      text = TS.node_text(node, source)
      if TS.node_type(node) == "unary_expression"
        if operand = TS.field(node, "operand")
          return types_for(operand, scope, source, types)
        end
      elsif TS.node_type(node) == "composite_literal"
        if type = TS.field(node, "type")
          return Set{type_symbol(scope.file, TS.node_text(type, source))}
        end
      end
      return types[text]?.try(&.dup) || Set(String).new unless TS.node_type(node) == "call_expression"
      fn = TS.field(node, "function")
      return Set(String).new unless fn
      target = TS.node_text(fn, source)
      key = "#{File.dirname(scope.file)}::#{target}"
      if TS.node_type(fn) == "selector_expression"
        operand = TS.field(fn, "operand")
        field = TS.field(fn, "field")
        if operand && field
          qualifier = TS.node_text(operand, source)
          if imported = @imports[scope.file][qualifier]?
            if dir = package_dir(scope.file, imported)
              key = "#{dir}::#{TS.node_text(field, source)}"
            end
          end
        end
      end
      @returns[key]?.try(&.dup) || Set(String).new
    end

    private def collection_key(text : String, scope : Scope, types : Types) : String
      if text.includes?('.')
        receiver, field = text.split('.', 2)
        if known = types[receiver]?
          return "#{known.first}.#{field}" if known.size == 1
        end
      end
      "#{scope.symbol}:#{text}"
    end

    private def handle_call(node : Node, scope : Scope, source : String,
                            groups : Hash(String, Mount), types : Types, bound : Bool)
      fn = TS.field(node, "function")
      args_node = TS.field(node, "arguments")
      return unless fn && args_node
      args = children(args_node)
      method = TS.node_text(fn, source)
      targets = [] of Scope
      operand = TS.field(fn, "operand")
      field = TS.field(fn, "field")
      if operand && field
        method = TS.node_text(field, source)
        qualifier = TS.node_text(operand, source)
        if imported = @imports[scope.file][qualifier]?
          if dir = package_dir(scope.file, imported)
            targets = @scopes.select { |s| s.receiver.empty? && s.name == method && File.dirname(s.file) == dir && !s.param.empty? }
          end
        else
          receiver_types = types_for(operand, scope, source, types)
          targets = @scopes.select { |s| receiver_types.includes?(s.receiver) && s.name == method && !s.param.empty? }
        end
      else
        targets = @scopes.select { |s| s.receiver.empty? && s.name == method && File.dirname(s.file) == File.dirname(scope.file) && !s.param.empty? }
      end
      targets.each do |target|
        arg = args[target.param_index]?
        next unless arg
        group = group_for(arg, scope, source, groups)
        next unless group && bound
        mounts = (@contexts[target.symbol] ||= [] of Mount)
        unless mounts.includes?(group)
          if mounts.size >= 64
            @limit_hit = true
          else
            mounts << group
          end
        end
      end

      return unless operand && field
      return unless TreeSitterGoRouteExtractor::HTTP_VERB_METHODS.includes?(method) || method == "Handle"
      group = group_for(operand, scope, source, groups)
      return unless group
      offset = method == "Handle" ? 1 : 0
      path_node = args[offset]?
      return unless path_node && args.size > offset + 1
      raw = literal_path(path_node, source)
      # Dynamic registrations remain discoverable as unresolved candidates.
      path = raw ? join(group.path, raw) : (group.path.empty? ? "/" : group.path)
      verb = method.upcase
      if method == "Handle"
        vn = args.first?
        verb = vn ? (literal_path(vn, source) || "UNKNOWN") : "UNKNOWN"
      end
      handler = TS.node_text(args.last, source)
      handler = "inline" unless handler.matches?(/\A[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\z/)
      if !scope.receiver_name.empty? && handler.starts_with?(scope.receiver_name + ".")
        handler = "#{scope.receiver}.#{handler.lchop(scope.receiver_name + ".")}"
      end
      evidence = RouteEvidence.new
      evidence.entrypoint = group.entrypoint
      evidence.handler = handler
      evidence.path_resolution = raw ? group.resolution : "unresolved"
      unless raw
        expression = TS.node_text(path_node, source)
        evidence.path_expression = expression.matches?(/\A[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\z/) ? expression : "dynamic"
        evidence.candidate_identity = "#{scope.file}:#{TS.node_start_row(node)}"
      end
      evidence.registration_status = bound ? "registered" : "unknown"
      evidence.mount_expression = group.expression
      evidence.mount_file = group.file
      evidence.mount_line = group.line
      evidence.issues << "external_mount_unresolved" if group.resolution != "resolved"
      evidence.issues << "registration_target_unresolved" unless bound
      evidence.issues << "dynamic_route_path" unless raw
      route = TreeSitterGoRouteExtractor::Route.new(TS.node_text(operand, source), verb,
        path, raw || "", handler, TS.node_start_row(node))
      @hits << Hit.new(route, scope.file, evidence)
    end

    private def join(prefix : String, path : String) : String
      return path.empty? ? "/" : path if prefix.empty?
      return prefix if path.empty?
      prefix.rchop('/') + "/" + path.lchop('/')
    end
  end
end
