package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zeusln/ios-nwc-server/internal/config"
	"github.com/zeusln/ios-nwc-server/internal/handler"
	"github.com/zeusln/ios-nwc-server/internal/middleware"
	"github.com/zeusln/ios-nwc-server/internal/server"
	"github.com/zeusln/ios-nwc-server/internal/services"
	"github.com/zeusln/ios-nwc-server/pkg/logger"
	"github.com/zeusln/ios-nwc-server/pkg/redis"
)

func main() {
	cfg := config.Load()

	err := logger.Init(logger.Config{
		Level:       "debug",
		Environment: cfg.Log.Environment,
		Service:     cfg.Log.ServiceName,
		Version:     "1.2.0",
		File:        "logs/app.log",
		MaxSize:     100,
		MaxBackups:  5,
		MaxAge:      30,
		Compress:    true,
	})
	if err != nil {
		panic(err)
	}

	logger.Info("Starting Zeus NWC Server for IOS devices")

	if err := redis.Init(cfg); err != nil {
		logger.WithError(err).Error("Failed to initialize Redis")
		os.Exit(1)
	}
	logger.Info("Redis initialized successfully")

	serviceManager := services.NewServiceManager(cfg)
	logger.Info("Services initialized successfully")

	securityConfig := middleware.DefaultSecurityConfig()

	if cfg.Log.Environment == "production" {
		securityConfig.AllowedOrigins = cfg.Security.AllowedOrigins
		securityConfig.AllowedMethods = cfg.Security.AllowedMethods
		securityConfig.AllowedHeaders = cfg.Security.AllowedHeaders
		securityConfig.MaxRequestsPerIP = cfg.Security.MaxRequestsPerIP
		securityConfig.BurstLimit = cfg.Security.BurstLimit
		securityConfig.BlockedIPs = cfg.Security.BlockedIPs
		securityConfig.TrustedProxies = cfg.Security.TrustedProxies
		securityConfig.EnableCORS = cfg.Security.EnableCORS
		securityConfig.EnableRateLimit = cfg.Security.EnableRateLimit
		securityConfig.EnableIPFilter = cfg.Security.EnableIPFilter
		securityConfig.EnableCSRF = true
		securityConfig.EnableHoneypot = true
		securityConfig.EnableSecurityLog = true
	}

	securityManager := middleware.NewSecurityManager(securityConfig)
	logger.Info("Security manager initialized successfully")

	router := gin.New()
	router.Use(gin.Recovery())
	handlerManager := handler.NewHandlerManager(serviceManager)
	server.SetupRoutes(router, securityManager, handlerManager)

	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	go func() {
		logger.WithFields(map[string]interface{}{
			"port":        cfg.Server.Port,
			"environment": cfg.Log.Environment,
		}).Info("Starting HTTP server")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Failed to start server")
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	}

	if err := redis.Close(); err != nil {
		logger.WithError(err).Error("Failed to close Redis connection")
	}

	logger.Info("Zeus NWC Server stopped")
}
