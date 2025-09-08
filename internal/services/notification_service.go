package services

import (
	"context"
	"fmt"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"
	"github.com/zeusln/ios-nwc-server/internal/config"
	"github.com/zeusln/ios-nwc-server/pkg/logger"
)

type NotificationService struct {
	client *apns2.Client
	config *config.APNSConfig
}

func NewNotificationService(config *config.Config) *NotificationService {
	service := &NotificationService{config: &config.Notifications.APNS}
	if config.Notifications.APNS.KeyPath == "" || config.Notifications.APNS.KeyID == "" || config.Notifications.APNS.TeamID == "" || config.Notifications.APNS.BundleID == "" {
		logger.Warn("APNS configuration incomplete, notifications disabled")
		return service
	}

	service.client = service.initAPNSClient()
	return service
}

func (s *NotificationService) initAPNSClient() *apns2.Client {
	authKey, err := token.AuthKeyFromFile(s.config.KeyPath)
	if err != nil {
		logger.WithError(err).Error("Failed to load APNS auth key")
		return nil
	}
	authToken := &token.Token{
		AuthKey: authKey,
		KeyID:   s.config.KeyID,
		TeamID:  s.config.TeamID,
	}

	if s.config.Production {
		return apns2.NewTokenClient(authToken).Production()
	}
	return apns2.NewTokenClient(authToken).Development()
}

func (s *NotificationService) SendNotification(ctx context.Context, deviceToken string) error {
	if !s.isEnabled() {
		logger.Debug("Notifications disabled, skipping send")
		return nil
	}
	notification := &apns2.Notification{
		DeviceToken: deviceToken,
		Topic:       s.config.BundleID,
		Payload:     payload.NewPayload().ContentAvailable(),
		Priority:    apns2.PriorityHigh,
	}
	response, err := s.client.Push(notification)
	if err != nil {
		return fmt.Errorf("failed to send notification: %w", err)
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("APNS error: %s (status: %d)", response.Reason, response.StatusCode)
	}

	logger.WithFields(map[string]interface{}{
		"device_token": s.maskToken(deviceToken),
		"apns_id":      response.ApnsID,
	}).Info("Notification sent")
	return nil
}

func (s *NotificationService) isEnabled() bool {
	return s.client != nil
}

func (s *NotificationService) maskToken(token string) string {
	const previewLength = 8
	if len(token) <= previewLength {
		return token
	}
	return token[:previewLength] + "..."
}
