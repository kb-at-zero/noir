require "../models/output_builder"
require "digest/sha256"
require "uri"

@[Noir::OutputFormat(name: "api-assets", description: "Versioned API source inventory", order: 35, structured: true)]
class OutputBuilderApiAssets < OutputBuilder
  SCHEMA_VERSION = "1.0"
  RULES_VERSION  = "aftership-source-2"

  def print(endpoints : Array(Endpoint), passive_results : Array(PassiveScanResult) = [] of PassiveScanResult)
    http = endpoints.reject(&.non_http?)
    client_documents = http.select { |ep| ep.details.technology == "graphql_operation" }
    operations = http.select { |ep| graphql_operation?(ep) }
    routes = http.reject { |ep| graphql_operation?(ep) || ep.details.technology == "graphql_operation" }
    definitions = operations.select { |ep| ep.details.route_evidence.try(&.definition_only) != false }
    bound_operations = operations - definitions
    transports = bound_operations.select { |ep| ep.protocol == "http" }.uniq { |ep| transport_id(ep) }
    unknown = http.count { |ep| ep.details.route_evidence.try(&.registration_status) != "registered" }
    unresolved = http.count { |ep| ep.details.route_evidence.try(&.path_resolution) != "resolved" }
    issues = http.count { |ep| !ep.details.route_evidence.try(&.issues.empty?) }
    degraded = !analyzer_failures.empty? || unknown > 0 || unresolved > 0 || issues > 0 || http.empty?

    document = JSON.build do |json|
      json.object do
        json.field "schema_version", SCHEMA_VERSION
        json.field "scanner" do
          json.object do
            json.field "name", "noir"
            json.field "version", Noir::VERSION
            json.field "rules_version", RULES_VERSION
          end
        end
        json.field "scope", "full_requested"
        json.field "status", degraded ? "partial" : "complete"
        json.field "capabilities" do
          json.object do
            json.field "inbound_routes", true
            json.field "outbound_calls", false
            json.field "deployment_verification", false
            json.field "coverage_proven", false
          end
        end
        json.field "routes" do
          json.array { routes.each { |ep| write_route(json, ep) } }
        end
        json.field "graphql_transports" do
          json.array { transports.each { |ep| write_route(json, ep, true) } }
        end
        json.field "operations" do
          json.array { bound_operations.each { |ep| write_operation(json, ep, true) } }
        end
        json.field "definitions" do
          json.array { definitions.each { |ep| write_operation(json, ep, false) } }
        end
        json.field "graphql_client_documents" do
          json.array do
            client_documents.each do |ep|
              json.object do
                json.field "kind", "graphql_client_document"
                json.field "sources" { write_sources(json, ep) }
                json.field "issues", ["client_document_not_server_registration"]
              end
            end
          end
        end
        json.field "outbound_calls" do
          json.array { }
        end
        json.field "diagnostics" do
          json.array do
            analyzer_failures.each do |failure|
              json.object do
                json.field "code", "analyzer_degraded"
                json.field "technology", failure.tech
              end
            end
            if http.empty?
              json.object { json.field "code", "empty_inventory_requires_review" }
            end
          end
        end
        json.field "summary" do
          json.object do
            json.field "http_routes", routes.size + transports.size
            json.field "graphql_operations", bound_operations.size
            json.field "definition_candidates", definitions.size
            json.field "graphql_client_documents", client_documents.size
            json.field "unknown_registration", unknown
            json.field "unresolved_paths", unresolved
            json.field "analyzer_errors", analyzer_failures.size
            json.field "other_protocol_endpoints", endpoints.size - http.size
          end
        end
      end
    end
    ob_puts document
  end

  private def graphql_operation?(ep : Endpoint) : Bool
    ep.tags.any? { |tag| tag.name == "graphql" } && ep.url.matches?(GRAPHQL_OPERATION_FRAGMENT)
  end

  private def path_for(ep : Endpoint) : String
    path = ep.url.split('#', 2).first
    if path.includes?("://")
      path = URI.parse(path).path
    end
    # Values from captured/imported URLs are not API asset evidence.
    path = path.split('?', 2).first if path.matches?(INLINE_QUERY)
    path.empty? ? "/" : path
  rescue URI::Error
    "/"
  end

  private def relative(file : String) : String?
    bases = @options["base"]?.try(&.as_a?).try(&.map(&.to_s)) || [] of String
    full = File.expand_path(file)
    roots = bases.map { |base| File.expand_path(base).rchop('/') }.sort_by { |base| -base.size }
    roots.each do |root|
      return "." if full == root
      return full.lchop(root + "/") if full.starts_with?(root + "/")
    end
    nil
  end

  private def entrypoint(ep : Endpoint) : String
    value = ep.details.route_evidence.try(&.entrypoint) || ""
    return "unknown" if value.empty?
    bases = @options["base"]?.try(&.as_a?).try(&.map(&.to_s)) || [] of String
    bases.sort_by { |base| -base.size }.each do |base|
      root = File.expand_path(base).rchop('/')
      value = value.gsub(root + "/", "")
      value = value.gsub(root + "::", ".::")
    end
    value
  end

  private def transport_id(ep : Endpoint) : String
    Digest::SHA256.hexdigest({entrypoint(ep), ep.method, path_for(ep),
                              ep.details.route_evidence.try(&.mount_expression).try { |expression| normalize_identity(expression) } || "",
                              ep.details.route_evidence.try(&.candidate_identity).try { |identity| normalize_identity(identity) } || ""}.join("|"))
  end

  private def write_sources(json : JSON::Builder, ep : Endpoint)
    json.array do
      ep.details.code_paths.each do |cp|
        file = relative(cp.path)
        next unless file
        json.object do
          json.field "file", file
          json.field "line", cp.line
        end
      end
    end
  end

  private def write_route(json : JSON::Builder, ep : Endpoint, transport : Bool = false)
    evidence = ep.details.route_evidence
    json.object do
      json.field "id", transport_id(ep)
      json.field "entrypoint_id", entrypoint(ep)
      json.field "protocol", "http"
      json.field "kind", transport ? "graphql_transport" : "http_route"
      json.field "method", ep.method
      json.field "path", path_for(ep)
      json.field "path_resolution", evidence.try(&.path_resolution) || "unknown"
      json.field "path_expression", evidence.try(&.path_expression) || ""
      json.field "registration_status", evidence.try(&.registration_status) || "unknown"
      json.field "handler", normalize_identity(evidence.try(&.handler) || "")
      json.field "technology", ep.details.technology
      json.field "sources" { write_sources(json, ep) }
      json.field "mount" do
        json.object do
          json.field "expression", normalize_identity(evidence.try(&.mount_expression) || "")
          json.field "file", evidence.try { |e| relative(e.mount_file) }
          json.field "line", evidence.try(&.mount_line)
        end
      end
      json.field "issues", evidence.try(&.issues) || ["registration_evidence_unavailable"]
    end
  end

  private def write_operation(json : JSON::Builder, ep : Endpoint, bound : Bool)
    fragment = ep.url.split('#', 2).last
    root, field = fragment.split('.', 2)
    json.object do
      json.field "id", Digest::SHA256.hexdigest(transport_id(ep) + "#" + fragment)
      json.field "transport_id", bound && ep.protocol == "http" ? transport_id(ep) : nil
      json.field "transport_protocol", ep.protocol
      json.field "operation_type", root.downcase
      json.field "field", field
      json.field "sources" { write_sources(json, ep) }
      json.field "issues", ep.details.route_evidence.try(&.issues) || ["schema_server_binding_unresolved"]
    end
  end

  private def normalize_identity(value : String) : String
    bases = @options["base"]?.try(&.as_a?).try(&.map(&.to_s)) || [] of String
    bases.sort_by { |base| -base.size }.each do |base|
      value = value.gsub(File.expand_path(base).rchop('/') + "/", "")
    end
    value
  end
end
