package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zeusln/ios-nwc-server/internal/handler"
	"github.com/zeusln/ios-nwc-server/internal/middleware"
)

func SetupRoutes(router *gin.Engine, securityManager *middleware.SecurityManager, handlerManager *handler.HandlerManager) {
	router.Use(securityManager.SecurityMiddleware())
	router.Use(securityManager.SecurityHeaders())
	router.Use(securityManager.CORS())
	router.Use(securityManager.RequestValidator())

	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Zeus NWC Server",
			"status":  "running",
			"version": "1.0.0",
		})
	})

	router.GET("/health", handler.HealthCheck)
	router.GET("/security/stats", func(c *gin.Context) {
		c.JSON(http.StatusOK, securityManager.GetSecurityStats())
	})

	api := router.Group("/api/v1")
	{
		eventsService := handlerManager.GetHandoffService()
		eventsHandler := handler.NewEventsHandlers(eventsService)

		api.POST("/handoff", eventsHandler.HandleHandoff)
		api.GET("/restore", eventsHandler.HandleRestore)
	}
}
