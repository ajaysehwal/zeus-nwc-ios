package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/redis/go-redis/v9"
	"github.com/zeusln/ios-nwc-server/internal/config"
	"github.com/zeusln/ios-nwc-server/pkg/utils"
	"go.uber.org/zap"
)

type NostrService struct {
	config      *config.Config
	redis       *redis.Client
	logger      *utils.Logger
	connections map[string]*UserConnection
	mu          sync.RWMutex
}

type UserConnection struct {
	ServicePubkey string
	DeviceToken   string
	Connections   []Connection
	Relays        map[string]*nostr.Relay
	Subs          map[string]*nostr.Subscription
	CreatedAt     time.Time
	mu            sync.RWMutex
}

type Connection struct {
	RelayURL string `json:"relay"`
	PubKey   string `json:"pubkey"`
}

type HandoffRequest struct {
	ServicePubkey string       `json:"service_pubkey"`
	DeviceToken   string       `json:"device_token"`
	Connections   []Connection `json:"connections"`
}

func NewNostrService(cfg *config.Config, redisClient *redis.Client, logger *utils.Logger) *NostrService {
	return &NostrService{
		config:      cfg,
		redis:       redisClient,
		logger:      logger,
		connections: make(map[string]*UserConnection),
	}
}

func (s *NostrService) HandleHandoff(ctx context.Context, req *HandoffRequest) error {
	s.logger.Info("Processing handoff request",
		zap.String("service_pubkey", req.ServicePubkey),
		zap.Int("connections_count", len(req.Connections)),
	)

	if err := s.validateRequest(req); err != nil {
		return fmt.Errorf("invalid request: %w", err)
	}

	conn := &UserConnection{
		ServicePubkey: req.ServicePubkey,
		DeviceToken:   req.DeviceToken,
		Connections:   req.Connections,
		Relays:        make(map[string]*nostr.Relay),
		Subs:          make(map[string]*nostr.Subscription),
		CreatedAt:     time.Now(),
	}

	s.mu.Lock()
	s.connections[req.ServicePubkey] = conn
	s.mu.Unlock()

	if err := s.storeConnection(ctx, conn); err != nil {
		return fmt.Errorf("failed to store connection: %w", err)
	}

	go s.connectToRelays(ctx, conn)
	go s.startConnectionHealthCheck(ctx, conn)

	s.logger.Info("Handoff processed successfully",
		zap.String("service_pubkey", req.ServicePubkey),
		zap.Int("connections_count", len(req.Connections)),
	)

	return nil
}

func (s *NostrService) validateRequest(req *HandoffRequest) error {
	if req.ServicePubkey == "" {
		return fmt.Errorf("service_pubkey is required")
	}
	if req.DeviceToken == "" {
		return fmt.Errorf("device_token is required")
	}
	if len(req.Connections) == 0 {
		return fmt.Errorf("at least one connection is required")
	}
	for i, conn := range req.Connections {
		if conn.RelayURL == "" {
			return fmt.Errorf("relay URL is required for connection %d", i)
		}
		if conn.PubKey == "" {
			return fmt.Errorf("pubkey is required for connection %d", i)
		}
	}
	return nil
}

func (s *NostrService) storeConnection(ctx context.Context, conn *UserConnection) error {
	key := fmt.Sprintf("nostr_connection:%s", conn.ServicePubkey)

	connData := map[string]interface{}{
		"service_pubkey": conn.ServicePubkey,
		"device_token":   conn.DeviceToken,
		"connections":    conn.Connections,
		"created_at":     conn.CreatedAt,
	}

	data, err := json.Marshal(connData)
	if err != nil {
		return err
	}
	return s.redis.Set(ctx, key, data, 24*time.Hour).Err()
}

func (s *NostrService) connectToRelays(ctx context.Context, conn *UserConnection) {
	s.logger.Info("Connecting to relays",
		zap.String("service_pubkey", conn.ServicePubkey),
		zap.Int("connections_count", len(conn.Connections)),
	)

	relayPubkeys := make(map[string][]string)
	for _, connection := range conn.Connections {
		relayPubkeys[connection.RelayURL] = append(relayPubkeys[connection.RelayURL], connection.PubKey)
	}

	s.logger.Info("Unique relays identified",
		zap.String("service_pubkey", conn.ServicePubkey),
		zap.Int("unique_relays", len(relayPubkeys)),
	)
	for relayURL, pubkeys := range relayPubkeys {
		go s.connectToRelayAndSubscribe(ctx, conn, relayURL, pubkeys)
	}
}

func (s *NostrService) connectToRelayAndSubscribe(ctx context.Context, conn *UserConnection, relayURL string, pubkeys []string) {
	const maxRetries = 3
	const baseDelay = 2 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		relay, err := nostr.RelayConnect(ctx, relayURL)
		if err == nil {
			conn.mu.Lock()
			conn.Relays[relayURL] = relay
			conn.mu.Unlock()

			s.logger.RelayConnection(relayURL, "connected",
				zap.String("service_pubkey", conn.ServicePubkey),
				zap.Strings("pubkeys", pubkeys),
				zap.Int("attempt", attempt),
			)

			s.subscribeToEventsForRelay(ctx, conn, relay, relayURL, pubkeys)
			return
		}

		s.logger.RelayConnection(relayURL, "failed",
			zap.String("service_pubkey", conn.ServicePubkey),
			zap.Strings("pubkeys", pubkeys),
			zap.Int("attempt", attempt),
			zap.Int("max_retries", maxRetries),
			zap.Error(err),
		)

		if attempt < maxRetries {
			delay := time.Duration(attempt) * baseDelay
			s.logger.RelayConnection(relayURL, "retrying",
				zap.String("service_pubkey", conn.ServicePubkey),
				zap.Duration("delay", delay),
				zap.Int("next_attempt", attempt+1),
			)

			select {
			case <-ctx.Done():
				s.logger.Info("Context cancelled, stopping relay connection retry",
					zap.String("relay_url", relayURL),
					zap.String("service_pubkey", conn.ServicePubkey),
				)
				return
			case <-time.After(delay):
				// Continue to next attempt
			}
		}
	}
	s.logger.Error("Failed to connect to relay after all retries",
		zap.String("relay_url", relayURL),
		zap.String("service_pubkey", conn.ServicePubkey),
		zap.Strings("pubkeys", pubkeys),
		zap.Int("max_retries", maxRetries),
	)
}

func (s *NostrService) subscribeToEventsForRelay(ctx context.Context, conn *UserConnection, relay *nostr.Relay, relayURL string, pubkeys []string) {
	filter := nostr.Filter{
		Kinds:   []int{23194, 23195, 1, 4, 7, 9735},
		Authors: pubkeys,
	}

	sub, err := relay.Subscribe(ctx, nostr.Filters{filter})
	if err != nil {
		s.logger.Error("Failed to subscribe to events",
			zap.String("relay_url", relayURL),
			zap.String("service_pubkey", conn.ServicePubkey),
			zap.Strings("pubkeys", pubkeys),
			zap.Error(err),
		)
		return
	}

	conn.mu.Lock()
	conn.Subs[relayURL] = sub
	conn.mu.Unlock()

	s.logger.Info("Subscribed to events",
		zap.String("relay_url", relayURL),
		zap.String("service_pubkey", conn.ServicePubkey),
		zap.Strings("pubkeys", pubkeys),
	)

	go s.handleEvents(ctx, conn, sub, relayURL)
}

func (s *NostrService) handleEvents(ctx context.Context, conn *UserConnection, sub *nostr.Subscription, relayURL string) {
	for ev := range sub.Events {
		s.logger.NostrEvent("received", ev.ID, ev.PubKey,
			zap.String("service_pubkey", conn.ServicePubkey),
			zap.String("relay_url", relayURL),
			zap.Int("kind", ev.Kind),
		)

		eventData := map[string]interface{}{
			"id":         ev.ID,
			"pubkey":     ev.PubKey,
			"created_at": ev.CreatedAt,
			"kind":       ev.Kind,
			"tags":       ev.Tags,
			"content":    ev.Content,
			"sig":        ev.Sig,
			"relay_url":  relayURL,
			"timestamp":  time.Now().Unix(),
		}

		if err := s.storeEvent(ctx, conn.ServicePubkey, eventData); err != nil {
			s.logger.Error("Failed to store event", zap.Error(err))
		}

		if s.isImportantEvent(ev.Kind) {
			go s.sendNotification(ctx, conn, ev)
		}
	}
}

func (s *NostrService) isImportantEvent(kind int) bool {
	importantKinds := map[int]bool{
		1:     true, // Text note
		4:     true, // Direct message
		7:     true, // Reaction
		9735:  true, // Zap
		23194: true, // NWC Request
		23195: true, // NWC Response
	}
	return importantKinds[kind]
}

func (s *NostrService) storeEvent(ctx context.Context, userID string, eventData map[string]interface{}) error {
	key := fmt.Sprintf("nostr_event:%s:%d", userID, time.Now().UnixNano())
	data, err := json.Marshal(eventData)
	if err != nil {
		return err
	}
	return s.redis.Set(ctx, key, data, 7*24*time.Hour).Err()
}

func (s *NostrService) sendNotification(ctx context.Context, conn *UserConnection, ev *nostr.Event) {
	title := s.getEventTitle(ev.Kind)
	body := s.getEventBody(ev.Content)

	notificationData := map[string]interface{}{
		"service_pubkey": conn.ServicePubkey,
		"device_token":   conn.DeviceToken,
		"title":          title,
		"body":           body,
		"event_id":       ev.ID,
		"event_kind":     ev.Kind,
		"pubkey":         ev.PubKey,
		"timestamp":      time.Now().Unix(),
	}

	key := fmt.Sprintf("notification_queue:%s", conn.ServicePubkey)
	data, err := json.Marshal(notificationData)
	if err != nil {
		s.logger.Error("Failed to marshal notification", zap.Error(err))
		return
	}

	if err := s.redis.LPush(ctx, key, data).Err(); err != nil {
		s.logger.Error("Failed to queue notification", zap.Error(err))
	}

	s.logger.Info("Notification queued",
		zap.String("service_pubkey", conn.ServicePubkey),
		zap.String("title", title),
		zap.String("event_id", ev.ID),
	)
}

func (s *NostrService) getEventTitle(kind int) string {
	switch kind {
	case 1:
		return "📝 New Message"
	case 4:
		return "💬 New Direct Message"
	case 7:
		return "❤️ New Reaction"
	case 9735:
		return "⚡ New Zap"
	case 23194:
		return "🔔 New Wallet Request"
	case 23195:
		return "✅ Wallet Response"
	default:
		return "📱 New Event"
	}
}

func (s *NostrService) getEventBody(content string) string {
	if len(content) > 100 {
		return content[:100] + "..."
	}
	return content
}

func (s *NostrService) GetConnection(userID string) (*UserConnection, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	conn, exists := s.connections[userID]
	if !exists {
		return nil, fmt.Errorf("connection not found for user: %s", userID)
	}

	return conn, nil
}

func (s *NostrService) CloseConnection(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, exists := s.connections[userID]
	if !exists {
		return fmt.Errorf("connection not found for user: %s", userID)
	}

	for relayURL, relay := range conn.Relays {
		relay.Close()
		s.logger.Info("Closed relay connection",
			zap.String("relay_url", relayURL),
			zap.String("user_id", userID),
		)
	}

	for relayURL, sub := range conn.Subs {
		sub.Unsub()
		s.logger.Info("Unsubscribed from relay",
			zap.String("relay_url", relayURL),
			zap.String("user_id", userID),
		)
	}

	delete(s.connections, userID)

	ctx := context.Background()
	key := fmt.Sprintf("nostr_connection:%s", userID)
	s.redis.Del(ctx, key)

	s.logger.Info("Connection closed", zap.String("user_id", userID))
	return nil
}

func (s *NostrService) GetQueuedNotifications(ctx context.Context, userID string) ([]map[string]interface{}, error) {
	key := fmt.Sprintf("notification_queue:%s", userID)

	notifications, err := s.redis.LRange(ctx, key, 0, -1).Result()
	if err != nil {
		return nil, err
	}

	var result []map[string]interface{}
	for _, notification := range notifications {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(notification), &data); err != nil {
			s.logger.Error("Failed to unmarshal notification", zap.Error(err))
			continue
		}
		result = append(result, data)
	}

	return result, nil
}

func (s *NostrService) ClearNotificationQueue(ctx context.Context, userID string) error {
	key := fmt.Sprintf("notification_queue:%s", userID)
	return s.redis.Del(ctx, key).Err()
}

func (s *NostrService) reconnectToRelayWithPubkeys(ctx context.Context, conn *UserConnection, relayURL string, pubkeys []string) {
	const maxRetries = 5
	const baseDelay = 5 * time.Second
	const maxDelay = 60 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		s.mu.RLock()
		_, exists := s.connections[conn.ServicePubkey]
		s.mu.RUnlock()

		if !exists {
			s.logger.Info("Connection no longer exists, stopping reconnection",
				zap.String("service_pubkey", conn.ServicePubkey),
				zap.String("relay_url", relayURL),
			)
			return
		}
		delay := time.Duration(attempt) * baseDelay
		if delay > maxDelay {
			delay = maxDelay
		}

		s.logger.Info("Attempting relay reconnection",
			zap.String("relay_url", relayURL),
			zap.String("service_pubkey", conn.ServicePubkey),
			zap.Strings("pubkeys", pubkeys),
			zap.Int("attempt", attempt),
			zap.Duration("delay", delay),
		)

		select {
		case <-ctx.Done():
			s.logger.Info("Context cancelled, stopping relay reconnection",
				zap.String("relay_url", relayURL),
				zap.String("service_pubkey", conn.ServicePubkey),
			)
			return
		case <-time.After(delay):
			// Continue to reconnection attempt
		}

		relay, err := nostr.RelayConnect(ctx, relayURL)
		if err == nil {
			conn.mu.Lock()
			conn.Relays[relayURL] = relay
			conn.mu.Unlock()

			s.logger.Info("Successfully reconnected to relay",
				zap.String("relay_url", relayURL),
				zap.String("service_pubkey", conn.ServicePubkey),
				zap.Strings("pubkeys", pubkeys),
				zap.Int("attempt", attempt),
			)

			s.subscribeToEventsForRelay(ctx, conn, relay, relayURL, pubkeys)
			return
		}

		s.logger.Warn("Failed to reconnect to relay",
			zap.String("relay_url", relayURL),
			zap.String("service_pubkey", conn.ServicePubkey),
			zap.Strings("pubkeys", pubkeys),
			zap.Int("attempt", attempt),
			zap.Int("max_retries", maxRetries),
			zap.Error(err),
		)
	}

	s.logger.Error("Failed to reconnect to relay after all retries",
		zap.String("relay_url", relayURL),
		zap.String("service_pubkey", conn.ServicePubkey),
		zap.Strings("pubkeys", pubkeys),
		zap.Int("max_retries", maxRetries),
	)
}

func (s *NostrService) startConnectionHealthCheck(ctx context.Context, conn *UserConnection) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkConnectionHealth(ctx, conn)
		}
	}
}

func (s *NostrService) checkConnectionHealth(ctx context.Context, conn *UserConnection) {
	conn.mu.RLock()
	relays := make(map[string]*nostr.Relay)
	for url, relay := range conn.Relays {
		relays[url] = relay
	}
	conn.mu.RUnlock()

	for relayURL, relay := range relays {
		if relay.ConnectionError != nil {
			s.logger.Warn("Relay connection has error, attempting reconnection",
				zap.String("relay_url", relayURL),
				zap.String("service_pubkey", conn.ServicePubkey),
				zap.Error(relay.ConnectionError),
			)

			var pubkeys []string
			for _, connection := range conn.Connections {
				if connection.RelayURL == relayURL {
					pubkeys = append(pubkeys, connection.PubKey)
				}
			}

			if len(pubkeys) > 0 {
				conn.mu.Lock()
				delete(conn.Relays, relayURL)
				conn.mu.Unlock()

				go s.reconnectToRelayWithPubkeys(ctx, conn, relayURL, pubkeys)
			}
		}
	}
}
