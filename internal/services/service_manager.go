package services

import (
	"context"

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
	notificationService := NewNotificationService(cfg)
	nostrService := NewNostrService(redisClient,notificationService)
	handoffService := NewHandoffService(nostrService)
	nostrService.RestoreAllDevices(context.Background())
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
