package server

import (
	"github.com/gin-gonic/gin"
	"github.com/zeusln/ios-nwc-server/internal/handler"
	"github.com/zeusln/ios-nwc-server/internal/middleware"
	"go.uber.org/zap"
)

func SetupRoutes(router *gin.Engine, securityConfig *middleware.SecurityConfig, handlerManager *handler.HandlerManager, logger *zap.Logger) {
	rateLimiter := middleware.NewRateLimiter(securityConfig)

	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.CORS(securityConfig))
	router.Use(middleware.IPFilter(securityConfig))
	router.Use(rateLimiter.RateLimit())
	router.Use(middleware.RequestLogger())

	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Zeus NWC Server",
			"status":  "running",
			"version": "1.0.0",
		})
	})

	router.GET("/health", handler.HealthCheck)

	api := router.Group("/api/v1")
	{
		handoffService := handlerManager.GetHandoffService()
		handoffHandler := handler.NewHandoffHandler(handoffService, logger)

		handoff := api.Group("/handoff")
		{
			handoff.POST("/", handoffHandler.HandleHandoff)
		}
	}
}
