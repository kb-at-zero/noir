require "../../spec_helper"
require "../../../src/output_builder/api_assets"
require "../../../src/optimizer/optimizer"

describe OutputBuilderApiAssets do
  it "does not turn client GraphQL documents into a default server route" do
    details = Details.new(PathInfo.new("/repo/query.graphql", 1))
    details.technology = "graphql_operation"
    builder = OutputBuilderApiAssets.new(create_test_options)
    builder.io = IO::Memory.new
    builder.print([Endpoint.new("/graphql", "POST", details)])
    doc = JSON.parse(builder.io.to_s)
    doc["routes"].as_a.should be_empty
    doc["graphql_transports"].as_a.should be_empty
    doc["graphql_client_documents"].as_a.size.should eq(1)
  end

  it "separates operations from transports and retains definitions with no server binding" do
    options = create_test_options
    options["base"] = YAML::Any.new([YAML::Any.new("/repo")])
    evidence = RouteEvidence.new
    evidence.entrypoint = "/repo/src/app.ts:graphql"
    evidence.registration_status = "registered"
    details = Details.new(PathInfo.new("/repo/schema.graphql", 2))
    details.route_evidence = evidence
    endpoints = ["Query.one", "Mutation.two"].map do |operation|
      ep = Endpoint.new("/api/graphql##{operation}", "POST", details)
      ep.add_tag(Tag.new("graphql", operation, "test"))
      ep
    end
    candidate = Endpoint.new("/graphql#Query.client", "POST", Details.new(PathInfo.new("/repo/sdk.graphql", 1)))
    candidate.add_tag(Tag.new("graphql", "Query.client", "test"))
    endpoints << candidate
    builder = OutputBuilderApiAssets.new(options)
    builder.io = IO::Memory.new
    builder.print(endpoints)
    doc = JSON.parse(builder.io.to_s)
    doc["graphql_transports"].as_a.size.should eq(1)
    doc["operations"].as_a.size.should eq(2)
    doc["definitions"].as_a.size.should eq(1)
    doc["graphql_transports"][0]["sources"][0]["file"].as_s.should eq("schema.graphql")
    doc["operations"][0]["transport_id"].should eq(doc["graphql_transports"][0]["id"])
    doc["capabilities"]["outbound_calls"].as_bool.should be_false
  end

  it "does not publish empty inventories as proven complete" do
    builder = OutputBuilderApiAssets.new(create_test_options)
    builder.io = IO::Memory.new
    builder.print([] of Endpoint)
    doc = JSON.parse(builder.io.to_s)
    doc["status"].as_s.should eq("partial")
    doc["diagnostics"][0]["code"].as_s.should eq("empty_inventory_requires_review")
  end

  it "keeps same-path registrations on different entrypoints through optimizer copies" do
    eps = ["one", "two"].map do |entrypoint|
      evidence = RouteEvidence.new
      evidence.entrypoint = entrypoint
      details = Details.new(PathInfo.new("/repo/main.go", 1))
      details.route_evidence = evidence
      Endpoint.new("/ping", "GET", details)
    end
    options = create_test_options
    logger = NoirLogger.from_options(options)
    optimized = EndpointOptimizer.new(logger, options).optimize_endpoints(eps)
    optimized.size.should eq(2)
    optimized.map { |ep| ep.details.route_evidence.not_nil!.entrypoint }.sort.should eq(["one", "two"])
  end
end
