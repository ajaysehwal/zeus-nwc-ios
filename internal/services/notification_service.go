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
	"go.uber.org/zap"
)

type NotificationService struct {
	config *config.APNSConfig
	redis  *redis.Client
	logger *zap.Logger
	client *apns2.Client
}

type Notification struct {
	Title      string            `json:"title"`
	Body       string            `json:"body"`
	Badge      int               `json:"badge,omitempty"`
	Sound      string            `json:"sound,omitempty"`
	Category   string            `json:"category,omitempty"`
	Data       map[string]string `json:"data,omitempty"`
	ThreadID   string            `json:"thread-id,omitempty"`
	Priority   int               `json:"priority,omitempty"`
	Expiration int64             `json:"expiration,omitempty"`
}

type DeviceToken struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NewNotificationService(cfg *config.APNSConfig, redisClient *redis.Client, logger *zap.Logger) *NotificationService {
	var client *apns2.Client

	if cfg.Enabled && cfg.KeyPath != "" && cfg.KeyID != "" && cfg.TeamID != "" {
		authKey, err := token.AuthKeyFromFile(cfg.KeyPath)
		if err != nil {
			logger.Error("Failed to load APNS auth key", zap.Error(err))
		} else {
			authToken := &token.Token{
				AuthKey: authKey,
				KeyID:   cfg.KeyID,
				TeamID:  cfg.TeamID,
			}

			if cfg.Production {
				client = apns2.NewTokenClient(authToken).Production()
			} else {
				client = apns2.NewTokenClient(authToken).Development()
			}
		}
	}

	return &NotificationService{
		config: cfg,
		redis:  redisClient,
		logger: logger,
		client: client,
	}
}

func (ns *NotificationService) SendNotification(ctx context.Context, deviceToken string, notification *Notification) error {
	if !ns.config.Enabled || ns.client == nil {
		return nil
	}

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

	notificationReq := &apns2.Notification{
		DeviceToken: deviceToken,
		Topic:       ns.config.BundleID,
		Payload:     p,
		Priority:    apns2.PriorityHigh,
	}

	res, err := ns.client.Push(notificationReq)
	if err != nil {
		return fmt.Errorf("failed to send notification: %w", err)
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("APNS error: %s (status: %d)", res.Reason, res.StatusCode)
	}

	ns.logger.Info("Notification sent successfully",
		zap.String("device_token", deviceToken[:8]+"..."),
		zap.String("title", notification.Title),
		zap.String("apns_id", res.ApnsID),
	)

	return nil
}

func (ns *NotificationService) SendBulkNotifications(ctx context.Context, deviceTokens []string, notification *Notification) error {
	if !ns.config.Enabled {
		return nil
	}

	var errors []error
	for _, token := range deviceTokens {
		if err := ns.SendNotification(ctx, token, notification); err != nil {
			errors = append(errors, fmt.Errorf("failed to send to token %s: %w", token[:8]+"...", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to send %d out of %d notifications", len(errors), len(deviceTokens))
	}

	return nil
}

func (ns *NotificationService) RegisterDevice(ctx context.Context, userID, deviceToken string) error {
	device := &DeviceToken{
		Token:     deviceToken,
		UserID:    userID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	key := fmt.Sprintf("device_token:%s", userID)
	deviceData, err := json.Marshal(device)
	if err != nil {
		return fmt.Errorf("failed to marshal device data: %w", err)
	}

	err = ns.redis.Set(ctx, key, string(deviceData), 0).Err()
	if err != nil {
		return fmt.Errorf("failed to store device token: %w", err)
	}

	tokenKey := fmt.Sprintf("user_by_token:%s", deviceToken)
	ns.redis.Set(ctx, tokenKey, userID, 0)

	ns.logger.Info("Device registered successfully",
		zap.String("user_id", userID),
		zap.String("device_token", deviceToken[:8]+"..."),
	)

	return nil
}

func (ns *NotificationService) GetDeviceToken(ctx context.Context, userID string) (*DeviceToken, error) {
	key := fmt.Sprintf("device_token:%s", userID)

	deviceData, err := ns.redis.Get(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get device token: %w", err)
	}

	var device DeviceToken
	err = json.Unmarshal([]byte(deviceData), &device)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal device data: %w", err)
	}

	return &device, nil
}

func (ns *NotificationService) UnregisterDevice(ctx context.Context, userID string) error {
	device, err := ns.GetDeviceToken(ctx, userID)
	if err == nil {
		tokenKey := fmt.Sprintf("user_by_token:%s", device.Token)
		ns.redis.Del(ctx, tokenKey)
	}

	key := fmt.Sprintf("device_token:%s", userID)
	err = ns.redis.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to remove device token: %w", err)
	}

	ns.logger.Info("Device unregistered successfully", zap.String("user_id", userID))
	return nil
}

func (ns *NotificationService) IsDeviceRegistered(ctx context.Context, userID string) (bool, error) {
	key := fmt.Sprintf("device_token:%s", userID)
	exists, err := ns.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check device registration: %w", err)
	}
	return exists > 0, nil
}

func (ns *NotificationService) CreateNWCNotification(eventType, content string) *Notification {
	var title, body string

	switch eventType {
	case "NWC Request":
		title = "🔔 New Wallet Request"
		body = "You have a new wallet request"
	case "NWC Response":
		title = "✅ Wallet Response"
		body = "Your wallet request has been processed"
	default:
		title = "📱 Zeus NWC Update"
		body = "New activity in your wallet"
	}

	return &Notification{
		Title:    title,
		Body:     body,
		Badge:    1,
		Sound:    "default",
		Category: "NWC_EVENT",
		Data: map[string]string{
			"event_type": eventType,
			"content":    content,
			"timestamp":  time.Now().Format(time.RFC3339),
		},
		ThreadID: "zeus-nwc",
		Priority: 10,
	}
}
