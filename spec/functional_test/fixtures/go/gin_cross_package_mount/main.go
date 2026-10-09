package main

import (
	"example.com/gin-cross-package-mount/handlers"
	"github.com/gin-gonic/gin"
)

type APIService struct{}

func (s *APIService) GetAPIRouteGroup() *gin.RouterGroup { return nil }

func setup(service *APIService, handler *handlers.Handler) {
	root := service.GetAPIRouteGroup()
	v1 := root.Group("/v1")
	handler.RegisterRoutes(v1)
}
