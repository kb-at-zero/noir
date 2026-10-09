require "./js_config_path_resolver"
require "../models/endpoint"

module Noir
  # Koa middleware can answer an HTTP request without using koa-router.
  # Only a pathToRegexp guard with an explicit method and response body is
  # treated as a route; guards that merely call next() are not endpoints.
  module KoaMiddlewareRouteExtractor
    extend self

    PATH_DECLARATION = /\b(?:const|let)\s+([A-Za-z_][\w]*)\s*=\s*pathToRegexp\s*\(\s*(`[^`]+`|'[^']+'|"[^"]+")\s*\)/
    METHOD_GUARD     = /\b([A-Za-z_][\w]*)\.method\s*===?\s*['"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"]\s*&&\s*([A-Za-z_][\w]*)\.test\s*\(\s*\1\.path\s*\)/

    def extract(source : String, file_path : String, config_sources : Array(String)) : Array(Endpoint)
      return [] of Endpoint unless source.includes?("pathToRegexp") && source.includes?(".body")

      paths = Hash(String, Tuple(String, String?)).new
      source.scan(PATH_DECLARATION) do |match|
        expression = match[2][1...-1]
        resolved = JSConfigPathResolver.resolve_with_configs(expression, config_sources)
        paths[match[1]] = {expression, resolved}
      end

      endpoints = [] of Endpoint
      TreeSitter.parse_javascript(source) do |root|
        TreeSitter.walk(root) do |node|
          next unless TreeSitter.node_type(node) == "if_statement"
          condition = TreeSitter.field(node, "condition")
          branch = TreeSitter.field(node, "consequence")
          next unless condition && branch
          match = TreeSitter.node_text(condition, source).match(METHOD_GUARD)
          next unless match
          binding = paths[match[3]]?
          next unless binding
          expression, resolved = binding
          responds = false
          TreeSitter.walk(branch) do |assignment|
            next unless TreeSitter.node_type(assignment) == "assignment_expression"
            left = TreeSitter.field(assignment, "left")
            responds = true if left && TreeSitter.node_text(left, source) == "#{match[1]}.body"
          end
          next unless responds
          suffix = expression.match(JSConfigPathResolver::CONFIG_REFERENCE).try(&.[2])
          path = resolved || suffix || "/"
          evidence = RouteEvidence.new
          evidence.entrypoint = "#{file_path}:middleware"
          evidence.registration_status = "unknown"
          evidence.issues << "middleware_mount_unverified"
          evidence.path_resolution = resolved ? "resolved" : "partial"
          evidence.mount_expression = resolved ? "" : "config-path-reference"
          evidence.mount_file = file_path
          evidence.mount_line = TreeSitter.node_start_row(node) + 1
          evidence.issues << "config_path_unresolved" unless resolved
          details = Details.new(PathInfo.new(file_path, TreeSitter.node_start_row(node) + 1))
          details.route_evidence = evidence
          endpoints << Endpoint.new(path, match[2], details)
        end
      end
      endpoints
    end
  end
end
