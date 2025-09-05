package services

import (
	"github.com/zeusln/ios-nwc-server/internal/config"
	"github.com/zeusln/ios-nwc-server/pkg/redis"
	"github.com/zeusln/ios-nwc-server/pkg/utils"
	"go.uber.org/zap"
)

type ServiceManager struct {
	Config              *config.Config
	NostrService        *NostrService
	HandoffService      *HandoffService
	NotificationService *NotificationService
}

func NewServiceManager(cfg *config.Config, logger *zap.Logger) *ServiceManager {
	redisClient := redis.GetClient()

	utilsLogger := &utils.Logger{Logger: logger}
	nostrService := NewNostrService(cfg, redisClient, utilsLogger)
	handoffService := NewHandoffService(cfg, nostrService, redisClient, logger)
	notificationService := NewNotificationService(&cfg.Notifications.APNS, redisClient, logger)

	return &ServiceManager{
		Config:              cfg,
		NostrService:        nostrService,
		HandoffService:      handoffService,
		NotificationService: notificationService,
	}
}

func (sm *ServiceManager) GetNostrService() *NostrService {
	return sm.NostrService
}

func (sm *ServiceManager) GetHandoffService() *HandoffService {
	return sm.HandoffService
}

func (sm *ServiceManager) GetNotificationService() *NotificationService {
	return sm.NotificationService
}

func (sm *ServiceManager) Shutdown() {
	// Cleanup any resources if needed
	// For now, just log shutdown
}
