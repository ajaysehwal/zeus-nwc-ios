package services

import (
	"github.com/zeusln/ios-nwc-server/internal/config"
	"github.com/zeusln/ios-nwc-server/pkg/redis"
)

type ServiceManager struct {
	Config              *config.Config
	NostrService        *NostrService
	HandoffService      *HandoffService
	NotificationService *NotificationService
}

func NewServiceManager(cfg *config.Config) *ServiceManager {
	redisClient := redis.GetClient()

	nostrService := NewNostrService(redisClient)
	handoffService := NewHandoffService(nostrService)
	notificationService := NewNotificationService(&cfg.Notifications.APNS, redisClient)

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
