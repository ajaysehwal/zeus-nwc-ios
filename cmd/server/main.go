package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
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

	serviceManager := services.NewServiceManager(cfg)
	logger.Info("Services initialized successfully")

	ctx := context.Background()
	if err := serviceManager.RestoreConnections(ctx); err != nil {
		logger.WithError(err).Error("Failed to restore connections from Redis")
	}

	go serviceManager.StartEventListening(context.Background())
	go startNotificationProcessor(context.Background(), serviceManager)

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

func startNotificationProcessor(ctx context.Context, serviceManager *services.ServiceManager) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			processQueuedNotifications(ctx, serviceManager)
		}
	}
}

func processQueuedNotifications(ctx context.Context, serviceManager *services.ServiceManager) {
	redisClient := redis.GetClient()
	keys, err := redisClient.Keys(ctx, "notification_queue:*").Result()
	if err != nil {
		logger.WithError(err).Error("Failed to get notification queue keys")
		return
	}

	for _, key := range keys {
		servicePubkey := key[len("notification_queue:"):]

		notifications, err := serviceManager.GetNostrService().GetQueuedNotifications(ctx, servicePubkey)
		if err != nil {
			logger.WithError(err).Error("Failed to get queued notifications", "service_pubkey", servicePubkey)
			continue
		}

		for _, notificationData := range notifications {
			deviceToken, ok := notificationData["device_token"].(string)
			if !ok {
				logger.WithError(err).Error("Invalid device token in notification", "service_pubkey", servicePubkey)
				continue
			}

			title, _ := notificationData["title"].(string)
			body, _ := notificationData["body"].(string)

			notification := &services.Notification{
				Title:    title,
				Body:     body,
				Badge:    1,
				Sound:    "default",
				Category: "NWC_EVENT",
				Data: map[string]string{
					"event_id":   fmt.Sprintf("%v", notificationData["event_id"]),
					"event_kind": fmt.Sprintf("%v", notificationData["event_kind"]),
					"pubkey":     fmt.Sprintf("%v", notificationData["pubkey"]),
					"timestamp":  fmt.Sprintf("%v", notificationData["timestamp"]),
				},
				ThreadID: "zeus-nwc",
				Priority: 10,
			}

			if err := serviceManager.GetNotificationService().SendNotification(ctx, deviceToken, notification); err != nil {
				logger.WithError(err).Error("Failed to send notification", "service_pubkey", servicePubkey)
			} else {
				logger.WithFields(map[string]interface{}{
					"service_pubkey": servicePubkey,
					"title":          title,
				}).Info("Notification sent successfully")
			}
		}

		if err := serviceManager.GetNostrService().ClearNotificationQueue(ctx, servicePubkey); err != nil {
			logger.WithError(err).Error("Failed to clear notification queue", "service_pubkey", servicePubkey)
		}
	}
}
