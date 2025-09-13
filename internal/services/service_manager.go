package services

import (
	"context"

	"github.com/zeusln/ios-nwc-server/internal/config"
	"github.com/zeusln/ios-nwc-server/pkg/redis"
)

type ServiceManager struct {
	Config              *config.Config
	NostrService        *NostrService
	HandoffService      *EventsService
	NotificationService *NotificationService
}

func NewServiceManager(cfg *config.Config) *ServiceManager {
	redisClient := redis.GetClient()
	notificationService := NewNotificationService(cfg)
	nostrService := NewNostrService(redisClient,notificationService)
	handoffService := NewEventsService(nostrService)
	nostrService.ReconnectToAllDevices(context.Background())
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

func (sm *ServiceManager) GetEventsService() *EventsService {
	return sm.HandoffService
}

func (sm *ServiceManager) GetNotificationService() *NotificationService {
	return sm.NotificationService
}
