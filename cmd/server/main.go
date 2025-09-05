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
	"github.com/zeusln/ios-nwc-server/pkg/redis"
	"github.com/zeusln/ios-nwc-server/pkg/utils"
	"go.uber.org/zap"
)

func main() {
	cfg := config.Load()

	logger, err := utils.NewLogger(&utils.Config{
		Level:       utils.LogLevel(cfg.Log.Level),
		Environment: cfg.Log.Environment,
		ServiceName: cfg.Log.ServiceName,
		PrettyPrint: cfg.Log.PrettyPrint,
		Colorful:    cfg.Log.Colorful,
	})
	if err != nil {
		fmt.Printf("❌ Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	logger.ServiceStart("Zeus NWC Server", "1.0.0",
		zap.String("environment", cfg.Log.Environment),
	)

	if err := redis.Init(cfg); err != nil {
		logger.Error("Failed to initialize Redis", zap.Error(err))
		os.Exit(1)
	}
	logger.Info("Redis initialized successfully")

	serviceManager := services.NewServiceManager(cfg, logger.Logger)
	logger.Info("Services initialized successfully")

	go startNotificationProcessor(context.Background(), serviceManager, logger.Logger)

	router := gin.New()
	router.Use(gin.Recovery())

	handlerManager := handler.NewHandlerManager(serviceManager)
	server.SetupRoutes(router, cfg.ToMiddlewareSecurityConfig(), handlerManager, logger.Logger)

	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	go func() {
		logger.Info("Starting HTTP server",
			zap.String("port", cfg.Server.Port),
			zap.String("environment", cfg.Log.Environment),
		)

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Critical("Failed to start server", zap.Error(err))
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
		logger.Error("Server forced to shutdown", zap.Error(err))
	}

	if err := redis.Close(); err != nil {
		logger.Error("Failed to close Redis connection", zap.Error(err))
	}

	logger.ServiceStop("Zeus NWC Server")
}

func startNotificationProcessor(ctx context.Context, serviceManager *services.ServiceManager, logger *zap.Logger) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			processQueuedNotifications(ctx, serviceManager, logger)
		}
	}
}

func processQueuedNotifications(ctx context.Context, serviceManager *services.ServiceManager, logger *zap.Logger) {
	redisClient := redis.GetClient()
	keys, err := redisClient.Keys(ctx, "notification_queue:*").Result()
	if err != nil {
		logger.Error("Failed to get notification queue keys", zap.Error(err))
		return
	}

	for _, key := range keys {
		servicePubkey := key[len("notification_queue:"):]

		notifications, err := serviceManager.GetNostrService().GetQueuedNotifications(ctx, servicePubkey)
		if err != nil {
			logger.Error("Failed to get queued notifications", zap.String("service_pubkey", servicePubkey), zap.Error(err))
			continue
		}

		for _, notificationData := range notifications {
			deviceToken, ok := notificationData["device_token"].(string)
			if !ok {
				logger.Error("Invalid device token in notification", zap.String("service_pubkey", servicePubkey))
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
				logger.Error("Failed to send notification", zap.String("service_pubkey", servicePubkey), zap.Error(err))
			} else {
				logger.Info("Notification sent successfully", zap.String("service_pubkey", servicePubkey), zap.String("title", title))
			}
		}

		if err := serviceManager.GetNostrService().ClearNotificationQueue(ctx, servicePubkey); err != nil {
			logger.Error("Failed to clear notification queue", zap.String("service_pubkey", servicePubkey), zap.Error(err))
		}
	}
}
