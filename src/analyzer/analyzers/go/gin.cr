require "../../engines/go_engine"
require "../../../miniparsers/gin_mount_resolver"
require "../../../miniparsers/apiserver_adapter"

module Analyzer::Go
  class Gin < GoEngine
    analyzer_for "go_gin"

    IMPORT_MARKER = "github.com/gin-gonic/gin"

    # Shared read-only fallback for directories with no resolved
    # router-builder prefixes (never mutated).
    EMPTY_BUILDER_PREFIXES = Hash(String, Set(String)).new

    def analyze
      legacy = analyze_legacy.dup
      sources = read_package_file_contents
      modules = {} of String => String
      collect_go_modules.each { |mod, dir| modules[dir] = mod }
      hits = Noir::GinMountResolver.new(sources, modules, configured_root_groups).resolve
      hits += Noir::ApiserverAdapter.new(sources, modules).resolve
      replacements = Set(Tuple(String, Int32, String)).new
      corrected = [] of Endpoint
      hits.each do |hit|
        Noir::TreeSitterGoRouteExtractor.fan_out_verbs(hit.route.verb).each do |verb|
          next unless %w[GET POST PUT PATCH DELETE HEAD OPTIONS QUERY].includes?(verb)
          key = {hit.file, hit.route.line + 1, verb}
          replacements << key
          previous = legacy.find do |ep|
            ep.method == verb && ep.details.code_paths.any? { |cp| cp.path == hit.file && cp.line == hit.route.line + 1 }
          end
          details = previous ? previous.details.detached_copy : Details.new(PathInfo.new(hit.file, hit.route.line + 1))
          details.route_evidence = hit.evidence
          ep = Endpoint.new(hit.route.path, verb, previous ? previous.params : [] of Param, details)
          previous.try(&.callees.each { |callee| ep.push_callee(callee) })
          corrected << ep
        end
      end
      legacy.each do |ep|
        next if ep.details.code_paths.any? { |cp| replacements.includes?({cp.path, cp.line || 0, ep.method}) }
        corrected << ep
      end
      @result = corrected
    end

    private def analyze_legacy
      # Source Analysis
      public_dirs = [] of (Hash(String, String))
      package_groups, file_contents = collect_package_groups_ts(import_marker: IMPORT_MARKER)
      # Pre-pass for cross-file identifier-handler resolution. Built
      # once per analyze() so each per-file callee pass only does an
      # O(1) lookup into `package_function_bodies` rather than re-
      # walking every sibling source file.
      package_function_bodies = collect_package_function_bodies(file_contents)
      import_path_function_bodies = collect_import_path_function_bodies(package_function_bodies)
      # Cross-file router-builder prefix resolution: `{dir => {builder_fn
      # => set(call-site prefixes)}}`. Resolves the canonical gin layout
      # where `func addXRoutes(rg *gin.RouterGroup)` helpers are called
      # from a central function with a versioned group (`addUserRoutes(
      # router.Group("/v1"))`). The prefix lives at the call site, so it
      # must be grafted onto the helper's routes.
      apply_configured_root_groups(file_contents, package_groups)
      builder_prefixes_by_dir = resolve_router_builder_prefixes(file_contents, package_groups)
      method_prefixes = resolve_router_method_prefixes(file_contents, package_groups)
      framework_dirs = framework_package_dirs(file_contents, IMPORT_MARKER)
      parallel_analyze(get_files_by_extension(".go")) do |path|
        next if GoEngine.go_test_file?(base_relative_path(path))
        next unless File.exists?(path)
        content = file_contents[path]? || read_file_content(path)
        dir = File.dirname(path)
        next unless framework_route_source_candidate?(content, dir, framework_dirs, IMPORT_MARKER, ["Handle", "Static"])
        lines = content.lines
        last_endpoint = Endpoint.new("", "")

        # Tree-sitter pre-pass: harvest every verb route with its
        # group-resolved path in one go. Indexed by line so the
        # line loop below can attribute body params (Query/PostForm
        # /GetHeader/Cookie) to the most recently declared route —
        # matching the legacy `last_endpoint` semantics.
        cross_file_groups = ts_groups_for_directory(package_groups, dir)

        # Router-builder expansion: graft call-site prefixes onto
        # the routes of `func addXRoutes(rg *gin.RouterGroup)`
        # helpers DEFINED in this file. Only "case b" helpers are
        # expanded — those whose group parameter name is NOT
        # already a key in the package group map. ("Case a" helpers
        # whose parameter name happens to match a caller's group
        # variable, e.g. both named `v1`, are already resolved by
        # the whole-file pass below, so they're left untouched to
        # keep their params/callees.) Expanded helpers' bodies are
        # suppressed in the whole-file pass to avoid emitting the
        # prefix-less variant alongside the corrected one.
        dir_builder_prefixes = builder_prefixes_by_dir[dir]? || EMPTY_BUILDER_PREFIXES
        expand_builders = [] of Tuple(String, Noir::TreeSitterGoRouteExtractor::RouterBuilder, Set(String))
        suppress_ranges = [] of Range(Int32, Int32)
        reachable_only = option_flag?("gin_reachable_only")
        if content.includes?("*gin.RouterGroup")
          Noir::TreeSitterGoRouteExtractor.collect_router_group_builders(content).each do |fn, rb|
            pset = dir_builder_prefixes[fn]?
            if pset && !pset.empty? && !cross_file_groups.has_key?(rb.param)
              suppress_ranges << (rb.start_row..rb.end_row)
              expand_builders << {fn, rb, pset}
            elsif reachable_only && !cross_file_groups.has_key?(rb.param)
              suppress_ranges << (rb.start_row..rb.end_row)
            end
          end
          Noir::TreeSitterGoRouteExtractor.collect_router_group_methods(content).each do |fn, rb|
            pset = method_prefixes[fn]?
            if pset && !pset.empty?
              suppress_ranges << (rb.start_row..rb.end_row)
              expand_builders << {fn, rb, pset}
            elsif reachable_only
              suppress_ranges << (rb.start_row..rb.end_row)
            end
          end
        end

        # Gin also accepts `r.Handle(method, path, handler)`
        # alongside the verb shortcuts (`r.GET`, etc.),
        # so opt into the method-first decoder so those
        # registrations surface as endpoints too.
        ts_routes = Noir::TreeSitterGoRouteExtractor.extract_routes(content, cross_file_groups, handle_method: "Handle")
        routes_by_line = Hash(Int32, Array(Noir::TreeSitterGoRouteExtractor::Route)).new
        ts_routes.each do |r|
          routes_by_line[r.line] ||= [] of Noir::TreeSitterGoRouteExtractor::Route
          routes_by_line[r.line] << r
        end

        # Resolve 1-hop callees for every route in this file.
        # Inline-closure handlers walk in place; bare
        # identifier handlers fall through to sibling-file
        # function bodies via the per-directory map.
        route_rows = Set(Int32).new
        routes_by_line.each_key { |row| route_rows << row }
        external_fns = ts_function_bodies_for_directory(package_function_bodies, dir)
        callees_by_route = Noir::GoCalleeExtractor.callees_for_routes_if(
          callees_needed?,
          content,
          path,
          route_rows,
          external_fns,
          imported_functions: import_path_function_bodies
        )

        # Gin uses `r.Static("/url", "./dir")`. Pick these up
        # in a single tree-sitter pass up front; downstream
        # `resolve_public_dirs` still expects the legacy hash
        # shape, so we convert here.
        Noir::TreeSitterGoRouteExtractor.extract_simple_statics(content).each do |sp|
          public_dirs << static_dir_entry(path, sp.url_prefix, sp.disk_path)
        end

        # StaticFile / StaticFileFS register a single file URL —
        # emit the route directly. Do not feed them through
        # resolve_public_dirs (directory glob), which drops "/"
        # prefixes and skips common media extensions like .ico.
        ["StaticFile", "StaticFileFS"].each do |mn|
          Noir::TreeSitterGoRouteExtractor.extract_simple_statics(content, method_name: mn).each do |sp|
            sf_details = Details.new(PathInfo.new(path, sp.line + 1))
            result << Endpoint.new(sp.url_prefix, "GET", sf_details)
          end
        end

        lines.each_with_index do |line, index|
          # Skip lines inside an expanded router-builder body — its
          # routes (and any params) are emitted, with the call-site
          # prefix applied, by the expansion pass below.
          next if suppress_ranges.any?(&.includes?(index))

          details = Details.new(PathInfo.new(path, index + 1))

          # Emit endpoints for any verb route that begins on this
          # line. Gin allows the same verb method name upper/lower
          # (`r.GET` vs `r.Get`); both are covered by the TS
          # extractor's HTTP_VERB_METHODS set.
          if ts_hits = routes_by_line[index]?
            ts_hits.each do |route|
              # `r.Any(...)` / `r.All(...)` register one route under
              # every HTTP method. Fan out so downstream formats
              # (SARIF / Postman / openapi) get a usable verb per
              # endpoint instead of a non-HTTP "ANY" string they
              # can't ingest.
              Noir::TreeSitterGoRouteExtractor.fan_out_verbs(route.verb).each do |verb|
                new_endpoint = Endpoint.new(gin_route_path(route), verb, details)
                if entries = callees_by_route[route.line]?
                  entries.each do |entry|
                    name, callee_path, callee_line = entry
                    new_endpoint.push_callee(Callee.new(name, path: callee_path, line: callee_line))
                  end
                end
                result << new_endpoint
                last_endpoint = new_endpoint
              end
            end
          end

          add_gin_param_patterns(line, last_endpoint)
        end

        # Expansion pass: emit each suppressed router-builder's
        # routes once per resolved call-site prefix, with the
        # group parameter bound to that prefix. (A helper called
        # from two versioned groups — `addPingRoutes(v1)` and
        # `addPingRoutes(v2)` — yields both `/v1/ping` and
        # `/v2/ping`.)
        expand_builders.each do |fn, rb, pset|
          builder_emitted = [] of Endpoint
          pset.each do |prefix|
            Noir::TreeSitterGoRouteExtractor.extract_routes_from_function(
              content, fn, {rb.param => prefix}, handle_method: "Handle"
            ).each do |route|
              rdetails = Details.new(PathInfo.new(path, route.line + 1))
              Noir::TreeSitterGoRouteExtractor.fan_out_verbs(route.verb).each do |verb|
                ep = Endpoint.new(gin_route_path(route), verb, rdetails)
                if entries = callees_by_route[route.line]?
                  entries.each do |entry|
                    name, callee_path, callee_line = entry
                    ep.push_callee(Callee.new(name, path: callee_path, line: callee_line))
                  end
                end
                result << ep
                builder_emitted << ep
              end
            end
          end
          # Attach any Gin params (Query/Bind/Cookie/Param) and callees
          # from the builder function body to the expanded endpoints.
          # Mirrors chi's attach_router_function_params for Mount-expanded
          # routes (callees were attached in the emit above using the
          # precomputed callees_by_route; params via the dedicated attach).
          if !builder_emitted.empty?
            attach_gin_builder_params(builder_emitted, content, rb.start_row, rb.end_row)
          end
        end
      end

      resolve_public_dirs(public_dirs)

      result
    end

    private def add_gin_param_patterns(line : String, target : Endpoint)
      # Bind*/ShouldBind* already contribute a single generic body param.
      # Skip the accessor loop on those lines so `ShouldBindQuery(&x)` does
      # not also fabricate a bogus query param named "&x".
      is_bind_line = line.matches?(/\.(?:Should)?Bind(?:JSON|XML|YAML|TOML|Query|Header|Uri|With)?\s*\(/)

      unless is_bind_line
        ["Query", "PostForm", "GetHeader", "Param"].each do |pattern|
          if line.includes?("#{pattern}(")
            add_param_to_endpoint(get_param(line), target)
          end
        end
      end
      if is_bind_line
        add_param_to_endpoint(Param.new("body", "", "json"), target)
      end
      # Read accessor only: `.Cookie("name")`. The `.Cookie(` anchor excludes
      # Header.Get/Cookie.Get; the SetCookie exclusion avoids the write API.
      if line.includes?(".Cookie(") && !line.includes?("SetCookie(")
        match = line.match(/\.Cookie\s*\(\s*"([^"]*)"/)
        if match
          target.params << Param.new(match[1], "", "cookie")
        end
      end
    end

    private def gin_route_path(route : Noir::TreeSitterGoRouteExtractor::Route) : String
      if route.raw_path.empty? && route.path != "/" && route.path.ends_with?('/')
        route.path.rchop('/')
      else
        route.path
      end
    end

    private def add_gin_param_patterns_to_many(line : String, targets : Array(Endpoint))
      return if targets.empty?
      is_bind_line = line.matches?(/\.(?:Should)?Bind(?:JSON|XML|YAML|TOML|Query|Header|Uri|With)?\s*\(/)

      unless is_bind_line
        ["Query", "PostForm", "GetHeader", "Param"].each do |pattern|
          if line.includes?("#{pattern}(")
            p = get_param(line)
            targets.each { |t| add_param_to_endpoint(p, t) }
          end
        end
      end
      if is_bind_line
        b = Param.new("body", "", "json")
        targets.each { |t| add_param_to_endpoint(b, t) }
      end
      # Read accessor only (see add_gin_param_patterns).
      if line.includes?(".Cookie(") && !line.includes?("SetCookie(")
        match = line.match(/\.Cookie\s*\(\s*"([^"]*)"/)
        if match
          c = Param.new(match[1], "", "cookie")
          targets.each { |t| t.params << c }
        end
      end
    end

    private def attach_gin_builder_params(emitted : Array(Endpoint), content : String, start_row : Int32, end_row : Int32)
      return if emitted.empty?
      lines = content.lines
      eps_by_line = Hash(Int32, Array(Endpoint)).new { |h, k| h[k] = [] of Endpoint }
      emitted.each do |ep|
        ep.details.code_paths.each do |cp|
          if ln = cp.line
            eps_by_line[ln.to_i - 1] << ep
          end
        end
      end
      return if eps_by_line.empty?
      currents = [] of Endpoint
      in_inline = false
      brace_count = 0
      (start_row..[end_row, lines.size - 1].min).each do |i|
        line = lines[i]?
        next unless line
        apply_now = false
        if eps = eps_by_line[i]?
          currents = eps
          apply_now = true
          if line.includes?("func(")
            in_inline = true
            brace_count = line.count("{") - line.count("}")
            if brace_count <= 0
              in_inline = false
              brace_count = 0
            end
          end
        elsif in_inline
          brace_count += line.count("{") - line.count("}")
          if brace_count <= 0
            in_inline = false
            brace_count = 0
          end
          apply_now = true
        end
        if !currents.empty? && apply_now
          add_gin_param_patterns_to_many(line, currents)
        end
      end
    end

    # Builds `{dir => {builder_fn => set(prefixes)}}` for the package by
    # (1) collecting every `func F(rg *gin.RouterGroup)` helper across the
    # directory's files and (2) resolving each call site `F(arg)` to the
    # prefix `arg` denotes via the directory group map. A helper called
    # with several different groups accumulates each prefix.
    private def resolve_router_builder_prefixes(file_contents : Hash(String, String),
                                                package_groups : Hash(String, Hash(String, String))) : Hash(String, Hash(String, Set(String)))
      result = Hash(String, Hash(String, Set(String))).new
      files_by_dir = Hash(String, Array(String)).new
      file_contents.each_key { |p| (files_by_dir[File.dirname(p)] ||= [] of String) << p }

      files_by_dir.each do |dir, paths|
        builders = Set(String).new
        paths.each do |p|
          content = file_contents[p]?
          next unless content
          next unless content.includes?("*gin.RouterGroup")
          Noir::TreeSitterGoRouteExtractor.collect_router_group_builders(content).each_key { |fn| builders << fn }
        end
        next if builders.empty?

        group_map = package_groups[dir]? || Hash(String, String).new
        prefixes = Hash(String, Set(String)).new
        unresolved = Set(String).new
        paths.each do |p|
          content = file_contents[p]?
          next unless content
          Noir::TreeSitterGoRouteExtractor.collect_router_builder_callsites(content, builders).each do |fn, arg|
            prefix = group_map[arg]?
            if prefix.nil? && arg.starts_with?("/")
              prefix = arg
            end
            if prefix
              (prefixes[fn] ||= Set(String).new) << prefix
            else
              # Unresolved or complex arg (including "__unresolved__" marker).
              # This builder has at least one call site that didn't resolve
              # to a known group prefix — guard will prevent expansion for it.
              unresolved << fn
            end
          end
        end
        # Only keep prefixes for builders where *every* call site resolved.
        # Mixed (some resolved + some direct/root/complex) fall back to
        # whole-file pass to avoid losing routes from the unresolved calls.
        prefixes.reject! { |fn, _| unresolved.includes?(fn) }
        result[dir] = prefixes unless prefixes.empty?
      end

      result
    end

    # An external server wrapper can return a pre-prefixed Gin group. Bind
    # only explicitly configured accessor names, then replay Group calls in
    # that package so children inherit the supplied root. Without a binding
    # the scan keeps its existing relative paths; it never guesses one.
    private def apply_configured_root_groups(file_contents : Hash(String, String),
                                             package_groups : Hash(String, Hash(String, String)))
      roots = configured_root_groups
      return if roots.empty?
      files_by_dir = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
      file_contents.each_key { |path| files_by_dir[File.dirname(path)] << path }
      files_by_dir.each do |dir, paths|
        groups = (package_groups[dir]? || Hash(String, String).new).dup
        paths.each do |path|
          Noir::TreeSitterGoRouteExtractor.collect_accessor_group_bindings(file_contents[path], roots).each do |name, prefix|
            groups[name] = prefix
          end
        end
        next if groups.empty?
        paths.size.times do
          previous = groups.dup
          paths.each do |path|
            groups = Noir::TreeSitterGoRouteExtractor.extract_groups(file_contents[path], groups)
          end
          break if groups == previous
        end
        package_groups[dir] = groups
      end
    end

    private def configured_root_groups : Hash(String, String)
      groups = Hash(String, String).new
      option_string_map("gin_root_groups").each do |accessor, prefix|
        next unless accessor.matches?(/\A[A-Za-z_][A-Za-z_0-9]*\z/)
        next unless prefix.starts_with?('/') && !prefix.starts_with?("//")
        next if prefix.matches?(/[\x00-\x1f\\?#]/)
        groups[accessor] = prefix
      end
      groups
    end

    # Collect the concrete group passed to method registrations, including
    # calls from a different Go package (`h.RegisterRoutes(apiRoute)`). The
    # method bodies are expanded at that prefix in the per-file pass.
    private def resolve_router_method_prefixes(file_contents : Hash(String, String),
                                               package_groups : Hash(String, Hash(String, String))) : Hash(String, Set(String))
      methods = Set(String).new
      file_contents.each_value do |content|
        next unless content.includes?("*gin.RouterGroup")
        Noir::TreeSitterGoRouteExtractor.collect_router_group_methods(content).each_key { |name| methods << name }
      end
      prefixes = Hash(String, Set(String)).new { |h, k| h[k] = Set(String).new }
      return prefixes if methods.empty?
      file_contents.each do |path, content|
        groups = package_groups[File.dirname(path)]? || Hash(String, String).new
        Noir::TreeSitterGoRouteExtractor.collect_router_builder_callsites(content, methods).each do |name, argument|
          if prefix = groups[argument]?
            prefixes[name] << prefix
          end
        end
      end
      delegations = file_contents.values.flat_map do |content|
        Noir::TreeSitterGoRouteExtractor.collect_router_method_delegations(content, methods)
      end
      loop do
        changed = false
        delegations.each do |outer, inner|
          prefixes[outer].each do |prefix|
            changed = true if prefixes[inner].add?(prefix)
          end
        end
        break unless changed
      end
      prefixes
    end

    def get_param(line : String) : Param
      param_type = "json"
      if line.includes?("Query(")
        param_type = "query"
      end
      if line.includes?("PostForm(")
        param_type = "form"
      end
      if line.includes?("GetHeader(")
        param_type = "header"
      end
      # `c.Param("id")` — Gin path variable accessor. The optimizer
      # also derives `:id` path params from the URL pattern, but
      # surfacing the accessor lets us catch handlers whose route
      # path was resolved cross-file and avoids depending on the
      # optimizer pass for direct-analyzer consumers.
      if line.includes?(".Param(")
        param_type = "path"
      end

      # Capture only the accessor's first string-literal argument. Naive
      # split("(")/split(")") desyncs when DefaultQuery/DefaultPostForm's
      # default-value argument contains nested calls (e.g. strconv.Itoa(n)).
      if match = line.match(/(?:Query|PostForm|GetHeader|Param)\s*\(\s*"([^"]*)"/)
        return Param.new(match[1], "", param_type)
      end

      Param.new("", "", "")
    end
  end
end
