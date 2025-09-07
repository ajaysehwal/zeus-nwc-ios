package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"
	"github.com/zeusln/ios-nwc-server/internal/config"
	"github.com/zeusln/ios-nwc-server/pkg/logger"
)

const (
	deviceTokenKeyPrefix = "device_token:"
	userByTokenKeyPrefix = "user_by_token:"
	
	defaultBadgeCount = 1
	defaultSound      = "default"
	defaultCategory   = "NWC_EVENT"
	defaultThreadID   = "zeus-nwc"
	
	tokenPreviewLength = 8
)

type NotificationService struct {
	config *config.APNSConfig
	redis  *redis.Client
	client *apns2.Client
}

type Notification struct {
	Title      string            `json:"title"`
	Body       string            `json:"body"`
	Badge      int               `json:"badge,omitempty"`
	Sound      string            `json:"sound,omitempty"`
	Category   string            `json:"category,omitempty"`
	Data       map[string]string `json:"data,omitempty"`
	ThreadID   string            `json:"thread_id,omitempty"`
	Priority   int               `json:"priority,omitempty"`
	Expiration int64             `json:"expiration,omitempty"`
}

type DeviceToken struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type NotificationTemplate struct {
	Title string
	Body  string
}

var notificationTemplates = map[string]NotificationTemplate{
	"NWC Request":  {Title: "New Wallet Request", Body: "You have a new wallet request"},
	"NWC Response": {Title: "Wallet Response", Body: "Your wallet request has been processed"},
	"Zap":          {Title: "Lightning Payment", Body: "You received a lightning payment"},
	"Text Note":    {Title: "New Message", Body: "You have a new message"},
	"Direct Message": {Title: "Direct Message", Body: "You have a new direct message"},
}

func NewNotificationService(cfg *config.APNSConfig, redisClient *redis.Client) *NotificationService {
	service := &NotificationService{
		config: cfg,
		redis:  redisClient,
	}

	if cfg.Enabled {
		service.client = service.initAPNSClient()
	}

	return service
}

func (ns *NotificationService) initAPNSClient() *apns2.Client {
	if ns.config.KeyPath == "" || ns.config.KeyID == "" || ns.config.TeamID == "" {
		logger.Warn("APNS configuration incomplete, notifications disabled")
		return nil
	}

	authKey, err := token.AuthKeyFromFile(ns.config.KeyPath)
	if err != nil {
		logger.WithError(err).Error("Failed to load APNS auth key")
		return nil
	}

	authToken := &token.Token{
		AuthKey: authKey,
		KeyID:   ns.config.KeyID,
		TeamID:  ns.config.TeamID,
	}

	if ns.config.Production {
		return apns2.NewTokenClient(authToken).Production()
	}
	return apns2.NewTokenClient(authToken).Development()
}

func (ns *NotificationService) SendNotification(ctx context.Context, deviceToken string, notification *Notification) error {
	if !ns.isEnabled() {
		logger.Debug("Notifications disabled, skipping send")
		return nil
	}

	apnsNotification := ns.buildAPNSNotification(deviceToken, notification)
	
	response, err := ns.client.Push(apnsNotification)
	if err != nil {
		return fmt.Errorf("failed to send notification: %w", err)
	}

	if response.StatusCode != 200 {
		return fmt.Errorf("APNS error: %s (status: %d)", response.Reason, response.StatusCode)
	}

	ns.logSuccessfulSend(deviceToken, notification.Title, response.ApnsID)
	return nil
}

func (ns *NotificationService) isEnabled() bool {
	return ns.config.Enabled && ns.client != nil
}

func (ns *NotificationService) buildAPNSNotification(deviceToken string, notification *Notification) *apns2.Notification {
	p := payload.NewPayload().
		Alert(notification.Title).
		AlertBody(notification.Body).
		Badge(notification.Badge).
		Sound(notification.Sound).
		Category(notification.Category).
		ThreadID(notification.ThreadID)

	for key, value := range notification.Data {
		p.Custom(key, value)
	}

	return &apns2.Notification{
		DeviceToken: deviceToken,
		Topic:       ns.config.BundleID,
		Payload:     p,
		Priority:    apns2.PriorityHigh,
	}
}

func (ns *NotificationService) logSuccessfulSend(deviceToken, title, apnsID string) {
	logger.WithFields(map[string]interface{}{
		"device_token": ns.maskToken(deviceToken),
		"title":        title,
		"apns_id":      apnsID,
	}).Info("Notification sent")
}

func (ns *NotificationService) maskToken(token string) string {
	if len(token) <= tokenPreviewLength {
		return token
	}
	return token[:tokenPreviewLength] + "..."
}

func (ns *NotificationService) SendBulkNotifications(ctx context.Context, deviceTokens []string, notification *Notification) error {
	if !ns.isEnabled() {
		return nil
	}

	var failedCount int
	for _, token := range deviceTokens {
		if err := ns.SendNotification(ctx, token, notification); err != nil {
			logger.WithError(err).WithField("device_token", ns.maskToken(token)).Error("Failed to send notification")
			failedCount++
		}
	}

	if failedCount > 0 {
		return fmt.Errorf("failed to send %d out of %d notifications", failedCount, len(deviceTokens))
	}

	logger.WithField("count", len(deviceTokens)).Info("Bulk notifications sent successfully")
	return nil
}

func (ns *NotificationService) RegisterDevice(ctx context.Context, userID, deviceToken string) error {
	if userID == "" || deviceToken == "" {
		return fmt.Errorf("userID and deviceToken are required")
	}

	device := &DeviceToken{
		Token:     deviceToken,
		UserID:    userID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := ns.storeDeviceToken(ctx, userID, device); err != nil {
		return fmt.Errorf("failed to store device token: %w", err)
	}

	if err := ns.storeTokenUserMapping(ctx, deviceToken, userID); err != nil {
		return fmt.Errorf("failed to store token mapping: %w", err)
	}

	logger.WithFields(map[string]interface{}{
		"user_id":      userID,
		"device_token": ns.maskToken(deviceToken),
	}).Info("Device registered")

	return nil
}

func (ns *NotificationService) storeDeviceToken(ctx context.Context, userID string, device *DeviceToken) error {
	key := deviceTokenKeyPrefix + userID
	data, err := json.Marshal(device)
	if err != nil {
		return err
	}
	return ns.redis.Set(ctx, key, data, 0).Err()
}

func (ns *NotificationService) storeTokenUserMapping(ctx context.Context, deviceToken, userID string) error {
	key := userByTokenKeyPrefix + deviceToken
	return ns.redis.Set(ctx, key, userID, 0).Err()
}

func (ns *NotificationService) GetDeviceToken(ctx context.Context, userID string) (*DeviceToken, error) {
	key := deviceTokenKeyPrefix + userID
	
	data, err := ns.redis.Get(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("device token not found: %w", err)
	}

	var device DeviceToken
	if err := json.Unmarshal([]byte(data), &device); err != nil {
		return nil, fmt.Errorf("failed to parse device data: %w", err)
	}

	return &device, nil
}

func (ns *NotificationService) UnregisterDevice(ctx context.Context, userID string) error {
	device, err := ns.GetDeviceToken(ctx, userID)
	if err == nil {
		ns.removeTokenUserMapping(ctx, device.Token)
	}

	if err := ns.removeDeviceToken(ctx, userID); err != nil {
		return fmt.Errorf("failed to remove device token: %w", err)
	}

	logger.WithField("user_id", userID).Info("Device unregistered")
	return nil
}

func (ns *NotificationService) removeTokenUserMapping(ctx context.Context, deviceToken string) {
	key := userByTokenKeyPrefix + deviceToken
	ns.redis.Del(ctx, key)
}

func (ns *NotificationService) removeDeviceToken(ctx context.Context, userID string) error {
	key := deviceTokenKeyPrefix + userID
	return ns.redis.Del(ctx, key).Err()
}

func (ns *NotificationService) IsDeviceRegistered(ctx context.Context, userID string) (bool, error) {
	key := deviceTokenKeyPrefix + userID
	exists, err := ns.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

func (ns *NotificationService) CreateNotification(eventType, content string) *Notification {
	template := ns.getNotificationTemplate(eventType)
	
	notification := &Notification{
		Title:    template.Title,
		Body:     ns.getNotificationBody(template.Body, content),
		Badge:    defaultBadgeCount,
		Sound:    defaultSound,
		Category: defaultCategory,
		ThreadID: defaultThreadID,
		Priority: apns2.PriorityHigh,
		Data: map[string]string{
			"event_type": eventType,
			"content":    content,
			"timestamp":  time.Now().Format(time.RFC3339),
		},
	}

	return notification
}

func (ns *NotificationService) getNotificationTemplate(eventType string) NotificationTemplate {
	if template, exists := notificationTemplates[eventType]; exists {
		return template
	}
	return NotificationTemplate{
		Title: "Zeus NWC Update",
		Body:  "New activity in your wallet",
	}
}

func (ns *NotificationService) getNotificationBody(defaultBody, content string) string {
	if content != "" && len(content) <= 100 {
		return content
	}
	return defaultBody
}

func (ns *NotificationService) CreateCustomNotification(title, body string, data map[string]string) *Notification {
	if data == nil {
		data = make(map[string]string)
	}
	
	data["timestamp"] = time.Now().Format(time.RFC3339)

	return &Notification{
		Title:    title,
		Body:     body,
		Badge:    defaultBadgeCount,
		Sound:    defaultSound,
		Category: defaultCategory,
		ThreadID: defaultThreadID,
		Priority: apns2.PriorityHigh,
		Data:     data,
	}
}

func (ns *NotificationService) GetUserByToken(ctx context.Context, deviceToken string) (string, error) {
	key := userByTokenKeyPrefix + deviceToken
	userID, err := ns.redis.Get(ctx, key).Result()
	if err != nil {
		return "", fmt.Errorf("user not found for token: %w", err)
	}
	return userID, nil
}

func (ns *NotificationService) UpdateDeviceToken(ctx context.Context, userID, newDeviceToken string) error {
	device, err := ns.GetDeviceToken(ctx, userID)
	if err != nil {
		return ns.RegisterDevice(ctx, userID, newDeviceToken)
	}

	oldToken := device.Token
	device.Token = newDeviceToken
	device.UpdatedAt = time.Now()

	if err := ns.storeDeviceToken(ctx, userID, device); err != nil {
		return fmt.Errorf("failed to update device token: %w", err)
	}

	ns.removeTokenUserMapping(ctx, oldToken)
	if err := ns.storeTokenUserMapping(ctx, newDeviceToken, userID); err != nil {
		return fmt.Errorf("failed to update token mapping: %w", err)
	}

	logger.WithFields(map[string]interface{}{
		"user_id":          userID,
		"old_device_token": ns.maskToken(oldToken),
		"new_device_token": ns.maskToken(newDeviceToken),
	}).Info("Device token updated")

	return nil
}