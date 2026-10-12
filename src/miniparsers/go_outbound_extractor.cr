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

    # Blanks comments and string/rune CONTENTS with spaces (quotes kept),
    # preserving byte offsets so scanning is offset/line-stable while
    # literals stay readable via spans into the original source.
    def self.sanitize_for_scan(source : String) : String
      chars = source.chars
      i = 0
      n = chars.size
      while i < n
        c = chars[i]
        if c == '/' && chars[i + 1]? == '/'
          while i < n && chars[i] != '\n'
            chars[i] = ' ' unless chars[i] == '\n'
            i += 1
          end
        elsif c == '/' && chars[i + 1]? == '*'
          chars[i] = ' '
          chars[i + 1] = ' ' if chars[i + 1]?
          i += 2
          while i < n && !(chars[i] == '*' && chars[i + 1]? == '/')
            chars[i] = ' ' unless chars[i] == '\n'
            i += 1
          end
          chars[i] = ' ' if i < n
          chars[i + 1] = ' ' if chars[i + 1]? && i + 1 < n
          i += 2 if i < n
        elsif c == '"' || c == '`'
          quote = c
          i += 1
          while i < n && chars[i] != quote
            if chars[i] == '\\' && chars[i + 1]?
              chars[i] = ' '
              i += 1
              chars[i] = ' ' unless chars[i] == '\n'
            else
              chars[i] = ' ' unless chars[i] == '\n'
            end
            i += 1
          end
          i += 1 # skip the closing quote — re-processing it would reopen
        elsif c == '\'' && chars[i + 1]? && chars[i + 2]? == '\''
          chars[i + 1] = ' ' unless chars[i + 1] == '\n'
          i += 3
        else
          i += 1
        end
      end
      chars.join
    end

    def extract(sources : Hash(String, String), module_paths : Hash(String, String),
                route_handlers : Array(String), toml_sources : Array(String) = [] of String,
                base_path : String = "",
                route_sites : Array(Tuple(String, Int32, String)) = [] of Tuple(String, Int32, String)) : Array(Endpoint)
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

      index_closure_callers(sources, route_sites, fns, callers)
      # Route evidence carries code-level short names
      # (`pkg_alias.Method`); fn symbols are `dir::Type.Method`. Resolve
      # via import aliases (aliased imports rename the dir) and directory
      # basenames so the reverse walk can land on real handler symbols.
      alias_dirs = {} of String => Set(String)
      sources.each do |file, source|
        imports[file]?.try &.each do |alias_name, import_path|
          next if {"_", "."}.includes?(alias_name)
          d = pkg_dir(import_path, module_paths) || import_path
          (alias_dirs[alias_name] ||= Set(String).new) << d
          (alias_dirs[import_path.split('/').last] ||= Set(String).new) << d
        end
      end
      handler_set = route_handlers.to_set
      route_handlers.each do |short|
        next if short.starts_with?("inline@")
        pkg, _, mname = short.rpartition('.')
        next if pkg.empty?
        # Local-var conventions: trackingHandler / trackingService point at
        # the `tracking` package's types. Strip common suffixes.
        candidates = Set(String).new
        {pkg, pkg.rchop("Handler"), pkg.rchop("Service"), pkg.rchop("Domain"),
         pkg.rchop("_handler"), pkg.rchop("_service")}.each do |c|
          candidates << c unless c.empty?
        end
        dirs = Set(String).new
        candidates.each { |c| alias_dirs[c]?.try &.each { |d| dirs << d } }
        # Handler-looking dirs only: local vars named xxxHandler may point
        # at service/domain packages with identical basenames.
        handler_dirs = dirs.select { |d| d.includes?("handler") }
        dirs = handler_dirs unless handler_dirs.empty?
        fns.each_key do |sym|
          dir, _, rest = sym.rpartition("::")
          next if dir.empty?
          method = rest.includes?('.') ? rest.split('.').last : rest
          next unless method == mname
          next unless (candidates.includes?(File.basename(dir)) && dir.includes?("handler")) || dirs.includes?(dir)
          handler_set << sym
        end
      end
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
        owner = attribute_up(callers, handler_set, site.func, 12)
        owner = attribute_inline(route_sites, site) if owner.empty?
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
              if otext.includes?('(')
                # Chained call (pkg.GetService().M(...)): resolve by method
                # name only — imprecise but the bounded walk to a handler
                # keeps false positives out of the final attribution.
                fns.each_key do |sym|
                  callers[sym] << caller if sym.ends_with?(".#{mname}") || sym.ends_with?("::#{mname}")
                end
              elsif otext.includes?('.')
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
                        callers[sym] << caller if sym.ends_with?(".#{mname}") || sym.ends_with?("::#{mname}")
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
                  callers[sym] << caller if sym.ends_with?(".#{mname}") || sym.ends_with?("::#{mname}")
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
    # Scans the SANITIZED source (comments and string contents blanked,
    # offsets preserved) so the verb regex and the arg scanner never see
    # comment text or string noise; literals are read back from the
    # original source via the identical offsets.
    private def collect_call_sites(file : String, source : String,
                                   imports : Hash(String, String),
                                   consts : Hash(String, String), sites : Array(CallSite))
      dir = File.dirname(file)
      san = GoOutboundExtractor.sanitize_for_scan(source)

      san.scan(/\.\s*(#{VERBS.join("|")})\s*\(/) do |m|
        start = m.begin.not_nil!
        lookback = san[{start - 260, 0}.max, 260]? || ""
        next unless lookback.includes?(".R()") || lookback.includes?("restyClient.") ||
                    lookback.includes?("client.") || lookback.includes?(".WithContext(") ||
                    lookback.matches?(/resty|lient|fetch|tpCli|apiCli/i)
        span = first_arg_span(san, m.end.not_nil! - 1)
        next unless span
        arg0 = source[span]? || ""
        next if arg0.empty?
        url, dynamic = classify_arg(arg0, dir, consts, source)
        sites << CallSite.new(enclosing_fn(file, source, start), m[1].upcase,
          url, dynamic, file, line_of(source, start))
      end
      if imports.values.any? { |v| v == "net/http" }
        san.scan(/\bhttp\s*\.\s*(Get|Post|Head)\s*\(/) do |m|
          span = first_arg_span(san, m.end.not_nil! - 1)
          next unless span
          arg0 = source[span]? || ""
          next if arg0.empty?
          url, dynamic = classify_arg(arg0, dir, consts, source)
          sites << CallSite.new(enclosing_fn(file, source, m.begin.not_nil!), m[1].upcase,
            url, dynamic, file, line_of(source, m.begin.not_nil!))
        end
        san.scan(/\bhttp\s*\.\s*NewRequest\s*\(/) do |m|
          args = split_args(san, m.end.not_nil! - 1)
          next unless args.size >= 2
          verb_arg = source[args[0]]? || ""
          url_arg = source[args[1]]? || ""
          next if url_arg.empty?
          verb = VERBS.includes?(verb_arg) ? verb_arg.upcase : "GET"
          url, dynamic = classify_arg(url_arg, dir, consts, source)
          sites << CallSite.new(enclosing_fn(file, source, m.begin.not_nil!), verb,
            url, dynamic, file, line_of(source, m.begin.not_nil!))
        end
      end
      sites.uniq! { |s| {s.file, s.line, s.verb} }
    end

    # First-argument byte span of the call whose '(' sits at open_paren.
    # Runs on sanitized text: no strings/comments to trip the state machine.
    private def first_arg_span(san : String, open_paren : Int32) : Range(Int32, Int32)?
      i = open_paren + 1
      depth = 0
      start = i
      while i < san.size
        case san[i]
        when '('
          depth += 1
        when ')'
          return (start...i) if depth == 0
          depth -= 1
        when ','
          return (start...i) if depth == 0
        end
        i += 1
      end
      nil
    end

    # All top-level argument spans of a call (used by NewRequest).
    private def split_args(san : String, open_paren : Int32) : Array(Range(Int32, Int32))
      spans = [] of Range(Int32, Int32)
      i = open_paren + 1
      depth = 0
      start = i
      while i < san.size
        case san[i]
        when '('
          depth += 1
        when ')'
          if depth == 0
            spans << (start...i)
            return spans
          end
          depth -= 1
        when ','
          if depth == 0
            spans << (start...i)
            start = i + 1
          end
        end
        i += 1
      end
      spans
    end

    # Classifies a first-argument text: Sprintf format -> static prefix,
    # literal, ident+"suffix", call expression -> literal prefix or token,
    # bare ident -> variable tracking in the source.
    private def classify_arg(arg : String, dir : String,
                             consts : Hash(String, String), source : String) : Tuple(String, Bool)
      if arg.starts_with?('"')
        return {arg[1..-2]? || "", false}
      end
      if m = arg.match(/\Afmt\.Sprintf\(\s*"([^"]*)"/)
        prefix = m[1].split('%').first
        # Empty prefix ("%s/v1/x"): keep the full format string as the
        # template — the optimizer drops empty-URL endpoints, and the
        # format still carries the path shape for suffix resolution.
        prefix = m[1] if prefix.empty?
        return {prefix, true}
      end
      if m = arg.match(/\A[A-Za-z_][\w.]*\s*\+\s*"([^"]*)"\z/)
        return {m[1], true}
      end
      if arg.includes?('(')
        lit = arg.match(/"([^"]*)"/).try(&.[1])
        if lit
          prefix = lit.split('%').first
          prefix = lit if prefix.empty?
          return {prefix, lit.includes?('%')}
        end
        return {arg.split(/[\s(]/).first?.to_s, true}
      end
      url_of(arg, dir, consts, source)
    end

    private def url_of(expr : String, dir : String, consts : Hash(String, String),
                       source : String) : Tuple(String, Bool)
      if m = expr.match(/\A"([^"]*)"\z/)
        return {m[1], false}
      end
      if (v = consts["#{dir}::#{expr}"]?)
        return {v, false}
      end
      if m = source.match(/#{Regex.escape(expr)}\s*:?=[^=]{0,120}?fmt\.Sprintf\(\s*"([^"]*)"/m)
        prefix = m[1].split('%').first
        prefix = m[1] if prefix.empty?
        return {prefix, m[1].includes?('%')}
      end
      if m = source.match(/#{Regex.escape(expr)}\s*:?=[^=\n]{0,80}"([^"\n]*)"/)
        return {m[1], false}
      end
      if m = source.match(/#{Regex.escape(expr)}\s*:?=[^=\n]{0,80}\w+\s*\+\s*"([^"\n]*)"/)
        return {m[1], false}
      end
      if m = source.match(/fmt\.Sprintf\(\s*"([^"]*)"[^)]*#{Regex.escape(expr)}/)
        return {m[1].split('%').first, true}
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

    # Closure attribution: the call site's nearest preceding inline-handler
    # registration in the same file owns the closure body.
    private def attribute_inline(route_sites : Array(Tuple(String, Int32, String)),
                                 site : CallSite) : String
      best = ""
      best_line = -1
      route_sites.each do |file, line, handler|
        next unless file == site.file && handler.starts_with?("inline@")
        if line <= site.line && site.line - line <= 200 && line >= best_line
          best = handler
          best_line = line
        end
      end
      best
    end

    # For each inline route registration, the source between its line and
    # the next registration is the closure body: its `x.Method(` calls make
    # the inline@ symbol a CALLER of those methods, closing the reverse
    # attribution path handler-closure -> domain -> outbound call.
    private def index_closure_callers(sources : Hash(String, String),
                                      route_sites : Array(Tuple(String, Int32, String)),
                                      fns : FnTable,
                                      callers : Hash(String, Array(String)))
      by_file = route_sites.select { |_, _, h| h.starts_with?("inline@") }
                           .sort_by { |_, line, _| line }
                           .group_by { |file, _, _| file }
      by_file.each do |file, sites|
        source = sources[file]? || next
        lines = source.split("\n")
        sites.each_with_index do |(_, line, handler), i|
          span_end = i + 1 < sites.size ? sites[i + 1][1] - 1 : {line + 60, lines.size}.min
          body = lines[line...{span_end, lines.size}.min]?.try(&.join("\n")) || next
          body.scan(/\b[A-Za-z_][\w.]*\.([A-Z][A-Za-z_]*)\s*\(/) do |m|
            mname = m[1]
            fns.each_key do |sym|
              callers[sym] << handler if sym.ends_with?(".#{mname}")
            end
          end
        end
      end
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
