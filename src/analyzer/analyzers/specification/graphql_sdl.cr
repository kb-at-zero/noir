require "../../engines/specification_engine"
require "./graphql_sdl_parser"
require "../../../miniparsers/js_config_path_resolver"
require "../../../miniparsers/graphql_source_binding"
require "../../../miniparsers/js_route_extractor"

module Analyzer::Specification
  # Parses GraphQL SDL schema documents (`*.graphql`, `*.gql`, `*.graphqls`)
  # and emits one endpoint per Query / Mutation / Subscription field.
  #
  # Operation documents (`query Foo { ... }`) are intentionally not handled
  # here — the runtime file_analyzers/graphql_analyzer covers that surface.
  #
  # The SDL grammar itself lives in `GraphqlSdlParser` so other analyzers
  # (Apollo Server inline typeDefs, GraphQL Yoga, etc.) can share it.
  class GraphqlSdl < SpecificationEngine
    analyzer_for "graphql_sdl"

    def analyze
      sources = {} of String => String
      mounts_by_base = Hash(String, Array(Tuple(String, String, String?))).new
      get_files_by_extensions([".js", ".mjs", ".cjs", ".ts", ".tsx"]).each do |path|
        source = read_file_content(path)
        next if Noir::JSRouteExtractor.test_stub_only?(path, source)
        sources[path] = source
        next unless source.includes?(".applyMiddleware")
        root = configured_base_for(path)
        configs = get_files_by_relative_path("config/default.js", root)
        configs.concat(get_files_by_relative_path("config/production.js", root))
        config_sources = configs.map { |file| read_file_content(file) }
        Noir::JSConfigPathResolver.apollo_mount_expressions(source).each do |expression|
          resolved = Noir::JSConfigPathResolver.resolve_with_configs(expression, config_sources)
          (mounts_by_base[root] ||= [] of Tuple(String, String, String?)) << {path, expression, resolved}
        end
      end
      each_spec_file(Noir::LocatorKeys::GRAPHQL_SDL) do |sdl_file|
        content = read_file_content(sdl_file)
        root = configured_base_for(sdl_file)
        mounts = mounts_by_base[root]? || [] of Tuple(String, String, String?)
        if mounts.empty?
          mounts = [{"", "", nil}] of Tuple(String, String, String?)
        end
        mounts.each do |file, expression, resolved|
          suffix = expression.match(Noir::JSConfigPathResolver::CONFIG_REFERENCE).try(&.[2])
          mount = resolved || suffix || GraphqlSdlParser::DEFAULT_GRAPHQL_PATH
          binding = !file.empty? && Noir::GraphqlSourceBinding.bound?(sdl_file, file, sources, root)
          evidence = RouteEvidence.new
          evidence.entrypoint = file.empty? ? "#{sdl_file}:schema" : "#{file}:graphql:#{mount}"
          evidence.path_resolution = resolved ? "resolved" : "partial"
          evidence.registration_status = binding ? "registered" : "unknown"
          evidence.definition_only = !binding
          evidence.mount_file = file
          evidence.mount_expression = resolved ? "" : "graphql-mount-reference"
          evidence.issues << "graphql_mount_unresolved" unless resolved
          evidence.issues << "schema_server_binding_unresolved" unless binding
          GraphqlSdlParser.parse(content, sdl_file, default_path: mount).each do |ep|
            ep.details.route_evidence = evidence.detached_copy
            ep.details.add_path(PathInfo.new(file)) unless file.empty?
            @result << ep
          end
        end
      end

      @result
    end
  end
end
