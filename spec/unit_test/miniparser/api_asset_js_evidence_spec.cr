require "../../spec_helper"
require "../../../src/miniparsers/koa_middleware_route_extractor"
require "../../../src/miniparsers/graphql_source_binding"

describe "API asset JS evidence" do
  it "retains a Koa route when its config path cannot be resolved" do
    source = <<-JS
      const route = pathToRegexp(`${config.get('basicPath')}/whoami`);
      if (ctx.method === 'GET' && route.test(ctx.path)) { ctx.body = {}; }
      JS
    ep = Noir::KoaMiddlewareRouteExtractor.extract(source, "/repo/middleware.js", [] of String).first
    ep.url.should eq("/whoami")
    ep.details.route_evidence.not_nil!.path_resolution.should eq("partial")
  end

  it "does not treat a response in an else or subsequent statement as a guarded route" do
    source = <<-JS
      const route = pathToRegexp('/guard');
      if (ctx.method === 'GET' && route.test(ctx.path)) { next(); } else { ctx.body = {}; }
      ctx.body = {};
      JS
    Noir::KoaMiddlewareRouteExtractor.extract(source, "/repo/middleware.js", [] of String).should be_empty
  end

  it "records all explicit Apollo mounts and unresolved path expressions" do
    source = "server.applyMiddleware({ app, path: '/one' }); other.applyMiddleware({ app, path: runtimePath });"
    Noir::JSConfigPathResolver.apollo_mount_expressions(source).should eq(["/one", "runtimePath"])
  end

  it "requires a reachable schema loader rather than an unrelated mount in the repo" do
    sources = {
      "/repo/app.js"    => "import schema from './schema'; server.applyMiddleware({ app, path: '/graphql' });",
      "/repo/schema.js" => "const dir = resolve(__dirname, './graphql/'); const types = loadFilesSync(resolve(dir, '**/*.graphql'));",
    }
    Noir::GraphqlSourceBinding.bound?("/repo/graphql/query.graphql", "/repo/app.js", sources, "/repo").should be_true
    Noir::GraphqlSourceBinding.bound?("/repo/sdk/schema.graphql", "/repo/app.js", sources, "/repo").should be_false
    Noir::GraphqlSourceBinding.bound?("/outside/schema.graphql", "/repo/app.js", sources, "/repo").should be_false
  end
end
