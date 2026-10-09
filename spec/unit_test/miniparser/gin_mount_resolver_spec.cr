require "../../spec_helper"
require "../../../src/miniparsers/gin_mount_resolver"

describe Noir::GinMountResolver do
  it "resolves same-named methods by package and receiver without leaking mounts" do
    files = {
      "/repo/main.go" => <<-GO,
        package main
        import (
          "github.com/gin-gonic/gin"
          a "example/a"
          b "example/b"
        )
        func main() {
          r := gin.New()
          first := a.New()
          second := b.New()
          first.RegisterRoutes(r.Group("/one"))
          second.RegisterRoutes(r.Group("/two"))
        }
        GO
      "/repo/a/routes.go" => <<-GO,
        package a
        import "github.com/gin-gonic/gin"
        type Handler struct{}
        func New() *Handler { return &Handler{} }
        func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) { h.add(rg) }
        func (h *Handler) add(rg *gin.RouterGroup) { rg.GET("/a", h.Get) }
        GO
      "/repo/b/routes.go" => <<-GO,
        package b
        import "github.com/gin-gonic/gin"
        type Handler struct{}
        func New() *Handler { return &Handler{} }
        func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) { rg.GET("/b", h.Get) }
        GO
    }
    hits = Noir::GinMountResolver.new(files, {"/repo" => "example"}).resolve
    hits.map(&.route.path).sort.should eq(["/one/a", "/two/b"])
    hits.all? { |h| h.evidence.registration_status == "registered" }.should be_true
  end

  it "keeps two mounts, preserves unknown roots and distinguishes unbound candidates" do
    files = {
      "/repo/main.go" => <<-GO,
        package main
        import "github.com/gin-gonic/gin"
        type Handler struct{}
        func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) { rg.GET("/items", h.Get) }
        func (h *Handler) unused(rg *gin.RouterGroup) { rg.POST("/unused", h.Post) }
        func main() {
          h := New()
          root := srv.GetAPIRouteGroup()
          h.RegisterRoutes(root.Group("/v1"))
          h.RegisterRoutes(root.Group("/v2"))
        }
        func New() *Handler { return &Handler{} }
        GO
    }
    hits = Noir::GinMountResolver.new(files, {"/repo" => "example"}).resolve
    mounted = hits.select { |h| h.evidence.registration_status == "registered" }
    mounted.map(&.route.path).sort.should eq(["/v1/items", "/v2/items"])
    mounted.all? { |h| h.evidence.path_resolution == "partial" && h.evidence.mount_expression == "srv.GetAPIRouteGroup()" }.should be_true
    hits.find { |h| h.route.path == "/unused" }.not_nil!.evidence.registration_status.should eq("unknown")
  end

  it "follows concrete constructors in a Handler collection rather than every matching method" do
    files = {
      "/repo/main.go" => <<-GO,
        package main
        import "github.com/gin-gonic/gin"
        type Server struct{}
        type A struct{}
        type B struct{}
        func NewA() *A { return &A{} }
        func (a *A) RegisterRoutes(r *gin.RouterGroup) { r.GET("/a", a.Get) }
        func (b *B) RegisterRoutes(r *gin.RouterGroup) { r.GET("/b", b.Get) }
        func (s *Server) setup() {
          s.handlers = append(s.handlers, NewA())
          r := gin.New()
          v1 := r.Group("/v1")
          for _, h := range s.handlers { h.RegisterRoutes(v1) }
        }
        GO
    }
    hits = Noir::GinMountResolver.new(files, {"/repo" => "example"}).resolve
    hits.find { |h| h.route.path == "/v1/a" }.not_nil!.evidence.registration_status.should eq("registered")
    hits.find { |h| h.route.path == "/b" }.not_nil!.evidence.registration_status.should eq("unknown")
    hits.any? { |h| h.route.path == "/v1/b" }.should be_false
  end

  it "does not leak a shadowed group into its parent or sibling function" do
    source = <<-GO
      package main
      import "github.com/gin-gonic/gin"
      func main() {
        r := gin.New()
        g := r.Group("/outer")
        if enabled { g := r.Group("/inner"); g.GET("/inside", handler) }
        g.GET("/outside", handler)
      }
      func other() { r := gin.New(); r.GET("/other", handler) }
      GO
    hits = Noir::GinMountResolver.new({"/repo/main.go" => source}, {"/repo" => "example"}).resolve
    hits.map(&.route.path).sort.should eq(["/inner/inside", "/other", "/outer/outside"])
  end

  it "keeps a dynamic route as an unresolved candidate instead of dropping it" do
    source = <<-GO
      package main
      import "github.com/gin-gonic/gin"
      func main() { r := gin.New(); r.GET(runtimePath, handler) }
      GO
    hit = Noir::GinMountResolver.new({"/repo/main.go" => source}, {"/repo" => "example"}).resolve.first
    hit.evidence.path_resolution.should eq("unresolved")
    hit.evidence.issues.should contain("dynamic_route_path")
  end
end
