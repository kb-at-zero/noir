require "../../func_spec.cr"

gin_roots = {
  YAML::Any.new("GetAPIRouteGroup") => YAML::Any.new("/affiliates"),
}

FunctionalTester.new("fixtures/go/gin_cross_package_mount/", {
  :techs     => 1,
  :endpoints => 2,
}, [
  Endpoint.new("/affiliates/v1/items/:id", "GET", [Param.new("id", "", "path")]),
  Endpoint.new("/unused", "GET"),
], {
  "gin_root_groups"    => YAML::Any.new(gin_roots),
  "gin_reachable_only" => YAML::Any.new(true),
}).perform_tests
