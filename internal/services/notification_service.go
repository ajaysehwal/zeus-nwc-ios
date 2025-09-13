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

const (
	successStatusCode  = 200
	tokenPreviewLength = 8
)

type NotificationService struct {
	client *apns2.Client
	config *config.APNSConfig
}

func NewNotificationService(cfg *config.Config) *NotificationService {
	service := &NotificationService{
		config: &cfg.Notifications.APNS,
	}

	if !service.isConfigurationValid() {
		logger.Warn("APNS configuration incomplete, notifications disabled")
		return service
	}

	client, err := service.initializeAPNSClient()
	if err != nil {
		logger.WithError(err).Error("Failed to initialize APNS client")
		return service
	}

	service.client = client
	return service
}

func (s *NotificationService) SendNotification(ctx context.Context, deviceToken string) error {
	if !s.isEnabled() {
		logger.Debug("Notifications disabled, skipping send")
		return nil
	}

	if err := s.validateDeviceToken(deviceToken); err != nil {
		return fmt.Errorf("invalid device token: %w", err)
	}

	notification := s.buildNotification(deviceToken)
	response, err := s.client.Push(notification)
	if err != nil {
		return fmt.Errorf("failed to send notification: %w", err)
	}

	if err := s.validateResponse(response); err != nil {
		return err
	}

	s.logSuccessfulNotification(deviceToken, response)
	return nil
}

func (s *NotificationService) isConfigurationValid() bool {
	apnsConfig := s.config
	return apnsConfig.KeyPath != "" &&
		apnsConfig.KeyID != "" &&
		apnsConfig.TeamID != "" &&
		apnsConfig.BundleID != ""
}

func (s *NotificationService) initializeAPNSClient() (*apns2.Client, error) {
	authKey, err := token.AuthKeyFromFile(s.config.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load APNS auth key: %w", err)
	}

	authToken := &token.Token{
		AuthKey: authKey,
		KeyID:   s.config.KeyID,
		TeamID:  s.config.TeamID,
	}

	client := apns2.NewTokenClient(authToken)
	if s.config.Production {
		return client.Production(), nil
	}
	return client.Development(), nil
}

func (s *NotificationService) buildNotification(deviceToken string) *apns2.Notification {
	return &apns2.Notification{
		DeviceToken: deviceToken,
		Topic:       s.config.BundleID,
		Payload:     payload.NewPayload().ContentAvailable(),
		Priority:    apns2.PriorityHigh,
	}
}

func (s *NotificationService) validateDeviceToken(deviceToken string) error {
	if deviceToken == "" {
		return fmt.Errorf("device token cannot be empty")
	}
	return nil
}

func (s *NotificationService) validateResponse(response *apns2.Response) error {
	if response.StatusCode != successStatusCode {
		return fmt.Errorf("APNS error: %s (status: %d)", response.Reason, response.StatusCode)
	}
	return nil
}

func (s *NotificationService) logSuccessfulNotification(deviceToken string, response *apns2.Response) {
	logger.WithFields(map[string]interface{}{
		"device_token": s.maskToken(deviceToken),
		"apns_id":      response.ApnsID,
	}).Info("Notification sent successfully")
}

func (s *NotificationService) isEnabled() bool {
	return s.client != nil
}

func (s *NotificationService) maskToken(token string) string {
	if len(token) <= tokenPreviewLength {
		return token
	}
	return token[:tokenPreviewLength] + "..."
}
