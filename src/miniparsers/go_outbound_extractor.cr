require "../models/endpoint"
require "../ext/tree_sitter/tree_sitter"
require "../models/route_evidence"

module Noir
  # Extracts outbound HTTP calls from Go services: resty chains
  # (`c.restyClient.R()...Post(path)`), net/http (`http.Get`, `client.Do`),
  # with URL from literals/package constants/fmt.Sprintf and base URLs from
  # constructor wiring (`NewClient(cfg.Section.Url)` → TOML value).
  #
  # Attribution walks the REVERSE call graph from each client call site up
  # to a registered route handler (bounded depth, struct-field types resolve
  # method receivers); unattached calls become service-level records.
  module GoOutboundExtractor
    extend self


    alias TS = TreeSitter
    alias Node = LibTreeSitter::TSNode

    VERBS = {"Get", "Post", "Put", "Patch", "Delete", "Head", "Options",
             "GET", "POST", "PUT", "PATCH", "DELETE"}

    record CallSite, func : String, verb : String, url : String, dynamic : Bool,
      file : String, line : Int32

    # symbol(dir-prefixed) => {file, start_row, end_row}
    alias FnTable = Hash(String, Tuple(String, Int32, Int32))

    def extract(sources : Hash(String, String), module_paths : Hash(String, String),
                route_handlers : Array(String), toml_sources : Array(String) = [] of String,
                base_path : String = "") : Array(Endpoint)
      imports = {} of String => Hash(String, String)
      fns = FnTable.new
      consts = {} of String => String             # "dir::name" => literal
      struct_fields = {} of String => Hash(String, String) # "dir::Type" => field => type_sym
      interfaces = Set(String).new                       # "ns::Interface" symbols
      toml = {} of String => String               # "Section.Key" => value

      toml_sources.each { |t| collect_toml("", t, toml) }
      sources.each do |file, source|
        imports[file] = imports_for(source)
        collect_fns(file, source, fns)
        collect_consts(file, source, consts)
        collect_struct_fields(file, source, imports[file], struct_fields)
        collect_interfaces(file, source, imports[file], interfaces)

      end

      # Reverse caller index: callee-symbol => [caller symbols]
      callers = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
      sources.each do |file, source|
        index_callers(file, source, imports[file], fns, struct_fields, callers, module_paths, interfaces)
      end

      handler_set = route_handlers.to_set
      sites = [] of CallSite
      sources.each do |file, source|
        next unless needs_scan?(source)
        collect_call_sites(file, source, imports[file], consts, sites)
      end
      return [] of Endpoint if sites.empty?

      endpoints = [] of Endpoint
      sites.each do |site|
        base = resolve_base(sources, imports, struct_fields, toml, site.func,
                            module_paths)
        url = base.empty? ? site.url : join_url(base, site.url)
        owner = attribute_up(callers, handler_set, site.func, 5)
        owner = owner.lchop("#{base_path}/") unless owner.empty? || base_path.empty?
        endpoints << build(site, url, owner, base)
      end
      endpoints
    end

    # -- symbol tables ------------------------------------------------------
    private def needs_scan?(source : String) : Bool
      source.includes?("resty") || source.includes?("net/http") ||
        source.includes?(".R()") || source.includes?("http.Get")
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

    private def collect_fns(file : String, source : String, fns : FnTable)
      TS.parse_go(source) do |root|
        TS.each_named_child(root) do |node|
          next unless {"function_declaration", "method_declaration"}.includes?(TS.node_type(node))
          nn = TS.field(node, "name")
          next unless nn
          symbol = fn_symbol(file, node, source)
          fns[symbol] = {file, TS.node_start_row(node), TS.node_end_row(node)}
        end
      end
    end

    private def fn_symbol(file : String, node : Node, source : String) : String
      dir = File.dirname(file)
      nn = TS.field(node, "name")
      return "" unless nn
      name = TS.node_text(nn, source)
      if receiver = TS.field(node, "receiver")
        TS.each_named_child(receiver) do |decl|
          if t = TS.field(decl, "type")
            text = TS.node_text(t, source).lchop('*')
            return "#{dir}::#{text}.#{name}"
          end
        end
      end
      "#{dir}::#{name}"
    end

    private def collect_consts(file : String, source : String, consts)
      dir = File.dirname(file)
      TS.parse_go(source) do |root|
        TS.each_named_child(root) do |node|
          next unless TS.node_type(node) == "const_declaration"
          TS.each_named_child(node) do |spec|
            next unless TS.node_type(spec) == "const_spec"
            name_n = TS.field(spec, "name")
            value = TS.field(spec, "value")
            next unless name_n && value
            text = TS.node_text(value, source)
            if m = text.match(/\A"([^"]*)"\z/)
              consts["#{dir}::#{TS.node_text(name_n, source)}"] = m[1]
            end
          end
        end
      end
    end

    private def collect_struct_fields(file : String, source : String,
                                      imports : Hash(String, String), struct_fields)
      dir = File.dirname(file)
      TS.parse_go(source) do |root|
        TS.each_named_child(root) do |node|
          next unless TS.node_type(node) == "type_declaration"
          TS.each_named_child(node) do |spec|
            next unless TS.node_type(spec) == "type_spec"
            name_n = TS.field(spec, "name")
            type_node = TS.field(spec, "type")
            next unless name_n && type_node && TS.node_type(type_node) == "struct_type"
            fields = {} of String => String
            # field_declaration may sit directly under struct_type or under
            # a field_declaration_list wrapper, depending on grammar version.
            TS.each_named_child(type_node) do |c1|
              candidates = TS.node_type(c1) == "field_declaration_list" ?
                             each_node(c1) : [c1]
              candidates.each do |fd|
                next unless TS.node_type(fd) == "field_declaration"
                ft = TS.field(fd, "type")
                next unless ft
                type_text = TS.node_text(ft, source).lchop('*')
                TS.each_named_child(fd) do |id|
                  if TS.node_type(id) == "field_identifier"
                    fields[TS.node_text(id, source)] = resolve_type(dir, type_text, imports)
                  end
                end
              end
            end
            struct_fields["#{dir}::#{TS.node_text(name_n, source)}"] = fields unless fields.empty?
          end
        end
      end
    end

    private def each_node(node : Node) : Array(Node)
      list = [] of Node
      TS.each_named_child(node) { |c| list << c }
      list
    end

    private def resolve_type(dir : String, text : String, imports : Hash(String, String)) : String
      if text.includes?('.')
        qualifier, base = text.split('.', 2)
        if imported = imports[qualifier]?
          # package name → source dir via module map is done lazily by the
          # caller; here we keep the import path as namespace.
          return "#{imported}::#{base}"
        end
      end
      "#{dir}::#{text}"
    end

    private def collect_interfaces(file : String, source : String,
                                    imports : Hash(String, String), interfaces : Set(String))
      dir = File.dirname(file)
      TS.parse_go(source) do |root|
        TS.each_named_child(root) do |node|
          next unless TS.node_type(node) == "type_declaration"
          TS.each_named_child(node) do |spec|
            next unless TS.node_type(spec) == "type_spec"
            name_n = TS.field(spec, "name")
            it = TS.field(spec, "type")
            next unless name_n && it && TS.node_type(it) == "interface_type"
            interfaces << resolve_type(dir, TS.node_text(name_n, source), imports)
          end
        end
      end
    end

    def self.collect_toml(file : String, source : String, toml)
      section = ""
      source.each_line do |line|
        if m = line.match(/^\s*\[([^\]]+)\]\s*$/)
          section = m[1]
        elsif m = line.match(/^\s*([A-Za-z_][\w]*)\s*=\s*"([^"]*)"/)
          key = section.empty? ? m[1] : "#{section}.#{m[1]}"
          toml[key] = m[2]
        end
      end
    end

    # -- reverse caller index ------------------------------------------------
    private def index_callers(file : String, source : String,
                              imports : Hash(String, String), fns : FnTable,
                              struct_fields : Hash(String, Hash(String, String)),
                              callers : Hash(String, Array(String)),
                              module_paths : Hash(String, String),
                              interfaces : Set(String))
      dir = File.dirname(file)
      TS.parse_go(source) do |root|
        TS.each_named_child(root) do |node|
          next unless {"function_declaration", "method_declaration"}.includes?(TS.node_type(node))
          caller = fn_symbol(file, node, source)
          receiver_name, receiver_type = receiver_info(file, node, source)
          body = TS.field(node, "body")
          next unless body
          TS.walk(body) do |call|
            next unless TS.node_type(call) == "call_expression"
            fn = TS.field(call, "function")
            next unless fn
            case TS.node_type(fn)
            when "identifier"
              callee = "#{dir}::#{TS.node_text(fn, source)}"
              callers[callee] << caller if fns.has_key?(callee)
            when "selector_expression"
              field = TS.field(fn, "field")
              operand = TS.field(fn, "operand")
              next unless field && operand
              mname = TS.node_text(field, source)
              otext = TS.node_text(operand, source)
              if otext.includes?('.')
                qualifier, sel = otext.split('.', 2)
                if imported = imports[qualifier]?
                  target = "#{pkg_dir(imported, module_paths) || imported}::#{mname}"
                  callers[target] << caller if fns.has_key?(target)
                elsif qualifier == receiver_name && !receiver_type.empty?
                  # receiver field: s.recommender.Recommend → field type's method.
                  # Interface field types (common DI style) connect by method
                  # name to every implementation — loose but handler-scoped.
                  if (fields = struct_fields["#{dir}::#{receiver_type}"]?) &&
                     (ftype = fields[sel]?)
                    ns, _, base = ftype.rpartition("::")
                    ns_dir = ns.includes?('/') ? (pkg_dir(ns, module_paths) || ns) : ns
                    target = "#{ns_dir}::#{base}.#{mname}"
                    if fns.has_key?(target)
                      callers[target] << caller
                    else
                      # interface field or unresolvable namespace: loose
                      # method-name edges, scoped later by handler reach.
                      fns.each_key do |sym|
                        callers[sym] << caller if sym.ends_with?(".#{mname}")
                      end
                    end
                  end
                end
              elsif otext == receiver_name && !receiver_type.empty?
                # receiver method call: s.Method() → Type.Method in this package
                target = "#{dir}::#{receiver_type}.#{mname}"
                callers[target] << caller if fns.has_key?(target)
              else
                # bare identifier receiver: loose method-name edges
                fns.each_key do |sym|
                  callers[sym] << caller if sym.ends_with?(".#{mname}")
                end
              end
            end
          end
        end
      end
    end

    private def receiver_info(file : String, node : Node, source : String)
      TS.field(node, "name") # presence guard
      if receiver = TS.field(node, "receiver")
        TS.each_named_child(receiver) do |decl|
          t = TS.field(decl, "type")
          n = TS.field(decl, "name")
          if t && n
            return {TS.node_text(n, source), TS.node_text(t, source).lchop('*')}
          end
        end
      end
      {"", ""}
    end

    private def pkg_dir(import_path : String, module_paths : Hash(String, String)) : String?
      pair = module_paths.to_a.select { |_, mod| import_path == mod || import_path.starts_with?(mod + "/") }
        .max_by? { |_, mod| mod.size }
      return unless pair
      root, mod = pair
      File.join(root, import_path.lchop(mod).lchop('/'))
    end

    # -- client call sites ---------------------------------------------------
    private def collect_call_sites(file : String, source : String,
                                   imports : Hash(String, String),
                                   consts : Hash(String, String), sites : Array(CallSite))
      dir = File.dirname(file)
      # Verb-first matching: a `.Post(path)` whose enclosing statement chain
      # contains a resty `.R()` builder (lookback window), or a direct
      # `client.Post(path)`. Robust to nested parens in middleware calls.
      source.scan(/\.\s*(#{VERBS.join("|")})\s*\(\s*([A-Za-z_][\w.]*)\s*\)/) do |m|
        start = m.begin.not_nil!
        lookback = source[{start - 220, 0}.max, 220]? || ""
        next unless lookback.includes?(".R()") || lookback.includes?("restyClient.") ||
                    lookback.includes?("client.")
        url, dynamic = url_of(m[2], dir, consts, source)
        sites << CallSite.new(enclosing_fn(file, source, start), m[1].upcase,
          url, dynamic, file, line_of(source, start))
      end
      # net/http shortcuts: http.Get/Post(url)
      if imports.values.any? { |v| v == "net/http" }
        source.scan(/\bhttp\s*\.\s*(Get|Post|Head)\s*\(\s*([A-Za-z_][\w.]*)\s*[,)]/) do |m|
          url, dynamic = url_of(m[2], dir, consts, source)
          sites << CallSite.new(enclosing_fn(file, source, m.begin.not_nil!), m[1].upcase,
            url, dynamic, file, line_of(source, m.begin.not_nil!))
        end
        source.scan(/\bhttp\s*\.\s*NewRequest\s*\(\s*([A-Za-z_][\w.]*)\s*,\s*([A-Za-z_][\w.]*)\s*,/) do |m|
          url, dynamic = url_of(m[2], dir, consts, source)
          verb = VERBS.includes?(m[1]) ? m[1].upcase : "GET"
          sites << CallSite.new(enclosing_fn(file, source, m.begin.not_nil!), verb,
            url, dynamic, file, line_of(source, m.begin.not_nil!))
        end
      end
      sites.uniq! { |s| {s.file, s.line, s.verb} }
    end

    private def url_of(expr : String, dir : String, consts : Hash(String, String),
                       source : String) : Tuple(String, Bool)
      if m = expr.match(/\A"([^"]*)"\z/)
        return {m[1], false}
      end
      if (v = consts["#{dir}::#{expr}"]?)
        return {v, false}
      end
      if source.includes?("fmt.Sprintf(#{expr}") ||
         source.includes?("#{expr} = fmt.Sprintf")
        # static prefix up to the first % verb, if the format is a literal
        if m = source.match(/fmt\.Sprintf\(\s*"([^"]*)"[^)]*#{Regex.escape(expr)}/)
          return {m[1].split('%').first, true}
        end
      end
      {expr, true}
    end

    private def enclosing_fn(file : String, source : String, offset : Int32) : String
      line = line_of(source, offset)
      dir = File.dirname(file)
      best = ""
      TS.parse_go(source) do |root|
        TS.each_named_child(root) do |node|
          next unless {"function_declaration", "method_declaration"}.includes?(TS.node_type(node))
          if TS.node_start_row(node) <= line - 1 && TS.node_end_row(node) >= line - 1
            best = fn_symbol(file, node, source)
          end
        end
      end
      best
    end

    private def line_of(source : String, offset : Int32) : Int32
      source.byte_slice(0, offset).count('\n') + 1
    end

    # -- base URL resolution ---------------------------------------------------
    # The client's constructor (NewClient in the same package) receives the
    # base URL from config at its wiring site: pkg.NewClient(cfg.Section.Url).
    # Only call sites in files importing the client's own package count.
    private def resolve_base(sources : Hash(String, String),
                             imports : Hash(String, Hash(String, String)),
                             struct_fields : Hash(String, Hash(String, String)),
                             toml : Hash(String, String), client_fn : String,
                             module_paths : Hash(String, String)) : String
      return "" if client_fn.empty?
      pkg_dir = client_fn.split("::").first?
      return "" unless pkg_dir && !pkg_dir.empty?
      sources.each do |file, source|
        file_imports = imports[file]? || Hash(String, String).new
        aliases = file_imports.select do |_k, v|
          if d = pkg_dir(v, module_paths)
            File.expand_path(d) == File.expand_path(pkg_dir)
          else
            v.ends_with?(pkg_dir)
          end
        end.keys
        next if aliases.empty?
        aliases.each do |a|
          source.scan(/#{Regex.escape(a)}\.New\w*Client\s*\(\s*([A-Za-z_][\w.]*)\s*[,)]/) do |m|
            if cv = toml_value(m[1], toml)
              return cv
            end
          end
        end
        source.scan(/SetBaseURL\s*\(\s*([A-Za-z_][\w.]*)\s*\)/) do |m|
          if cv = toml_value(m[1], toml)
            return cv
          end
        end
      end
      ""
    end

    private def toml_value(expr : String, toml : Hash(String, String)) : String?
      # cfg.SampleRecommendationAPI.Url / conf.X.Y → section.key lookup
      parts = expr.split('.')
      return nil unless parts.size >= 2
      if parts.size == 2
        key = parts[-1]
        # single-key sectionless TOML value
        return toml[expr]? || toml[key]?
      end
      section = parts[-2]
      key = parts[-1]
      toml["#{section}.#{key}"]? || toml["#{parts[-3]}.#{section}.#{key}"]?
    end

    # -- attribution ------------------------------------------------------------
    private def attribute_up(callers : Hash(String, Array(String)),
                             handler_set : Set(String), start : String,
                             max_depth : Int32) : String
      return "" if start.empty?
      return start if handler_set.includes?(start)
      frontier = Set{start}
      visited = Set{start}
      max_depth.times do
        next_frontier = Set(String).new
        frontier.each do |sym|
          callers[sym]?.try &.each do |caller|
            next if visited.includes?(caller)
            visited << caller
            next_frontier << caller
            return caller if handler_set.includes?(caller)
          end
        end
        frontier = next_frontier
        break if frontier.empty?
      end
      ""
    end

    private def join_url(base : String, path : String) : String
      return path if base.empty?
      return base if path.empty?
      base.rchop('/') + "/" + path.lchop('/')
    end

    private def build(site : CallSite, url : String, owner : String, base : String = "") : Endpoint
      details = Details.new(PathInfo.new(site.file, site.line))
      details.technology = "outbound_call"
      evidence = RouteEvidence.new
      short = site.func.split("::").last? || site.func
      evidence.handler = short.presence || site.func
      evidence.entrypoint = owner
      evidence.path_resolution = site.dynamic ? "unresolved" : "resolved"
      evidence.registration_status = "registered"
      evidence.mount_expression = base.presence || ""
      evidence.issues << "dynamic_url" if site.dynamic
      evidence.issues << "service_level" if owner.empty?
      details.route_evidence = evidence
      Endpoint.new(url, site.verb, details)
    end
  end

end
