package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nbd-wtf/go-nostr"
	"github.com/zeusln/ios-nwc-server/internal/config"
	"github.com/zeusln/ios-nwc-server/internal/handler"
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

	logger.Info("Zeus NWC Server")

	if err := redis.Init(cfg); err != nil {
		logger.WithError(err).Error("Failed to initialize Redis")
		os.Exit(1)
	}
	logger.Info("Redis initialized successfully")

	ctx := context.Background()
	relay, err := nostr.RelayConnect(ctx, "wss://relay.getalby.com/v1")
	if err != nil {
		logger.Error("❌ relay connect failed")
		return
	}

	// Subscribe to NWC events (kinds 23194 for requests, 23195 for responses)
	// Replace the hardcoded pubkey with your actual client pubkey from the NWC service
	clientPubkey := []string{
		"aa211add5cea5958dd286a1aad0ee0143e096a33f93782fe1c7fdbe95f3652ef",
	}
	// clientPubkey2 := "1d3a093d85157e0cb3e768dd4b056af38b4e6b1f8f1591e802ad5a7e000d24d9"
	 // TODO: Replace with actual client pubkey

	//  filters=nostr.Filters{"kinds":[]int{23194,23195,9735},"authors":[]string{"294b59ffe41b7ff19cce16c0026f271b59d8d0754968f1120dfeaf90778fe902","5233be0ca6e77d1a173daf62d47c6271a317a5f51d38087397528c5642d866cd"},"since":},{"authors":["294b59ffe41b7ff19cce16c0026f271b59d8d0754968f1120dfeaf90778fe902","5233be0ca6e77d1a173daf62d47c6271a317a5f51d38087397528c5642d866cd"]}]
	now := nostr.Now()
	sub, err := relay.Subscribe(ctx, nostr.Filters{
		{
			Kinds:   []int{23194, 23195,9735}, // NWC request and response events
			Authors: clientPubkey,
			Since:   &now,
		},
		// Also isten for any events from the client (including other kinds)
		{
			Authors: clientPubkey,
		},
	})


	if err != nil {
		logger.Error("❌ subscribe failed")
		return
	}

	logger.Info("✅ Subscribed to relay",)
	logger.Info("🔍 Listening for events from client",)
	logger.Info("📋 To get your client pubkey, run your NWC service and copy the 'client pubkey' from the console output")
	logger.Info("📡 Listening for NWC events (kinds 23194/23195) - content will be shown as encrypted")

	go func() {
		// <-sub.EndOfStoredEvents
		logger.Info("📡 started")
		for ev := range sub.Events {
			// Enhanced logging for NWC events
			eventType := "Unknown"
			switch ev.Kind {
            case 23194:
				eventType = "NWC Request"
			case 23195:
				eventType = "NWC Response"
			case 1:
				eventType = "Text Note"
			}

			logger.Info("📩 Event received")

			// Log NWC-specific information (encrypted content)
			if ev.Kind == 23194 || ev.Kind == 23195 {
				logger.Info("🔍 NWC Event Details")
				logger.Info(eventType)
			}
		}
	}()


	serviceManager := services.NewServiceManager(cfg)
	logger.Info("Services initialized successfully")
	router := gin.New()
	router.Use(gin.Recovery())
	handlerManager := handler.NewHandlerManager(serviceManager)
	server.SetupRoutes(router, cfg.ToMiddlewareSecurityConfig(), handlerManager)

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