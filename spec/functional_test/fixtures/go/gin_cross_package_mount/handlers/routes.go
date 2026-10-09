package handlers

import "github.com/gin-gonic/gin"

type Handler struct{}

func (h *Handler) RegisterRoutes(router *gin.RouterGroup) {
	items := router.Group("/items")
	items.GET("/:id", func(c *gin.Context) {})
}

func RegisterUnusedRoutes(router *gin.RouterGroup) {
	router.GET("/unused", func(c *gin.Context) {})
}
