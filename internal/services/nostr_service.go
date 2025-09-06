package services

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/redis/go-redis/v9"
	"github.com/zeusln/ios-nwc-server/internal/config"
	"github.com/zeusln/ios-nwc-server/pkg/logger"
)

type NostrService struct {
	config      *config.Config
	redis       *redis.Client
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

func NewNostrService(cfg *config.Config, redisClient *redis.Client) *NostrService {
	return &NostrService{
		config:      cfg,
		redis:       redisClient,
		connections: make(map[string]*UserConnection),
	}
}

func (s *NostrService) HandleHandoff(ctx context.Context, req *HandoffRequest) error {
	logger.WithFields(map[string]interface{}{
		"service_pubkey":    req.ServicePubkey,
		"connections_count": len(req.Connections),
	}).Info("Processing handoff request")

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

	// Use background context for long-running operations
	bgCtx := context.Background()
	go s.connectToRelays(bgCtx, conn)
	go s.startConnectionHealthCheck(bgCtx, conn)

	logger.WithFields(map[string]interface{}{
		"service_pubkey":    req.ServicePubkey,
		"connections_count": len(req.Connections),
	}).Info("Handoff request processed successfully")

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
	logger.WithFields(map[string]interface{}{
		"service_pubkey":    conn.ServicePubkey,
		"connections_count": len(conn.Connections),
	}).Info("🔌 Starting to connect to relays")

	relayPubkeys := make(map[string][]string)
	for _, connection := range conn.Connections {
		relayPubkeys[connection.RelayURL] = append(relayPubkeys[connection.RelayURL], connection.PubKey)
	}

	logger.WithFields(map[string]interface{}{
		"service_pubkey": conn.ServicePubkey,
		"unique_relays":  len(relayPubkeys),
	}).Info("Unique relays identified")

	for relayURL, pubkeys := range relayPubkeys {
		go s.connectToRelayAndSubscribe(ctx, conn, relayURL, pubkeys)
	}
}

func (s *NostrService) connectToRelayAndSubscribe(ctx context.Context, conn *UserConnection, relayURL string, pubkeys []string) {
	const maxRetries = 3
	const baseDelay = 2 * time.Second
	logger.WithFields(map[string]interface{}{
		"relay_url":      relayURL,
		"service_pubkey": conn.ServicePubkey,
		"pubkeys":        pubkeys,
	}).Info("🔗 Attempting to connect to relay")

	for attempt := 1; attempt <= maxRetries; attempt++ {
		relay, err := nostr.RelayConnect(ctx, relayURL)
		if err == nil {
			conn.mu.Lock()
			conn.Relays[relayURL] = relay
			conn.mu.Unlock()

			logger.WithFields(map[string]interface{}{
				"relay_url":      relayURL,
				"service_pubkey": conn.ServicePubkey,
				"pubkeys":        pubkeys,
				"attempt":        attempt,
			}).Info("✅ Relay connection successful - now subscribing to events")

			s.subscribeToEventsForRelay(ctx, conn, relay, relayURL, pubkeys)
			return
		}
		logger.WithFields(map[string]any{
			"service_pubkey": conn.ServicePubkey,
			"pubkeys":        pubkeys,
			"attempt":        attempt,
			"max_retries":    maxRetries,
			"error":          err,
		}).Info("Relay connection failed")

		if attempt < maxRetries {
			delay := time.Duration(attempt) * baseDelay
			logger.WithFields(map[string]any{
				"service_pubkey": conn.ServicePubkey,
				"pubkeys":        pubkeys,
				"attempt":        attempt,
				"max_retries":    maxRetries,
				"error":          err,
			}).Info("Relay connection failed")

			logger.WithFields(map[string]any{
				"relay_url":      relayURL,
				"service_pubkey": conn.ServicePubkey,
				"delay":          delay,
				"next_attempt":   attempt + 1,
			}).Info("Waiting before retry")
			select {
			case <-ctx.Done():
				logger.WithFields(map[string]any{
					"relay_url":      relayURL,
					"service_pubkey": conn.ServicePubkey,
				}).Info("Context cancelled, stopping relay connection retry")
				return
			case <-time.After(delay):
				// Continue to next attempt
			}
		}
	}

	logger.WithFields(map[string]interface{}{
		"relay_url":      relayURL,
		"service_pubkey": conn.ServicePubkey,
		"pubkeys":        pubkeys,
		"max_retries":    maxRetries,
	}).Error("Failed to connect to relay after all retries")
}

func (s *NostrService) subscribeToEventsForRelay(ctx context.Context, conn *UserConnection, relay *nostr.Relay, relayURL string, pubkeys []string) {
	filters := nostr.Filters{
		{
			Kinds:   []int{23194, 23195, 9735},
			Authors: pubkeys,
		},
		{
			Authors: pubkeys,
		},
	}

	sub, err := relay.Subscribe(ctx, filters)
	if err != nil {
		logger.WithFields(map[string]interface{}{
			"relay_url":      relayURL,
			"service_pubkey": conn.ServicePubkey,
			"pubkeys":        pubkeys,
			"error":          err,
		}).Error("❌ Failed to subscribe to events")
		return
	}

	conn.mu.Lock()
	conn.Subs[relayURL] = sub
	conn.mu.Unlock()

	logger.WithFields(map[string]interface{}{
		"relay_url":      relayURL,
		"service_pubkey": conn.ServicePubkey,
		"pubkeys":        pubkeys,
	}).Info("✅ Subscribed to relay")

	logger.WithFields(map[string]interface{}{
		"service_pubkey": conn.ServicePubkey,
		"pubkeys":        pubkeys,
	}).Info("🔍 Listening for events from client")

	logger.WithFields(map[string]interface{}{
		"service_pubkey": conn.ServicePubkey,
	}).Info("📡 Listening for NWC events (kinds 23194/23195) - content will be shown as encrypted")

	go s.handleEvents(ctx, conn, sub, relayURL)
}

func (s *NostrService) handleEvents(ctx context.Context, conn *UserConnection, sub *nostr.Subscription, relayURL string) {
	logger.WithFields(map[string]interface{}{
		"relay_url":      relayURL,
		"service_pubkey": conn.ServicePubkey,
	}).Info("🎧 Starting event listener for relay")

	<-sub.EndOfStoredEvents
	logger.WithFields(map[string]interface{}{
		"relay_url":      relayURL,
		"service_pubkey": conn.ServicePubkey,
	}).Info("📡 End of stored events reached - now listening for new events")

	for ev := range sub.Events {
		eventType := s.getEventType(ev.Kind)

		logger.WithFields(map[string]interface{}{
			"relay_url":      relayURL,
			"service_pubkey": conn.ServicePubkey,
			"event_id":       ev.ID,
			"event_pubkey":   ev.PubKey,
			"event_kind":     ev.Kind,
			"event_type":     eventType,
			"content_length": len(ev.Content),
		}).Info("📩 Event received")

		if ev.Kind == 23194 || ev.Kind == 23195 {
			logger.WithFields(map[string]interface{}{
				"event_id":        ev.ID,
				"content_preview": s.getContentPreview(ev.Content),
				"full_content":    ev.Content,
			}).Info("🔍 NWC Event Details")
		}
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
			logger.WithError(err).Error("Failed to store event")
		}

		if s.isImportantEvent(ev.Kind) {
			go s.sendNotification(ctx, conn, ev)
		}
	}

	logger.WithFields(map[string]interface{}{
		"relay_url":      relayURL,
		"service_pubkey": conn.ServicePubkey,
	}).Info("🔴 Event listening loop ended")
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
		logger.WithError(err).Error("Failed to marshal notification")
		return
	}

	if err := s.redis.LPush(ctx, key, data).Err(); err != nil {
		logger.WithError(err).Error("Failed to queue notification")
	}

	logger.WithFields(map[string]interface{}{
		"service_pubkey": conn.ServicePubkey,
		"title":          title,
		"event_id":       ev.ID,
	}).Info("Notification queued")
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

func (s *NostrService) getEventType(kind int) string {
	switch kind {
	case 1:
		return "Text Note"
	case 4:
		return "Direct Message"
	case 7:
		return "Reaction"
	case 9735:
		return "Zap"
	case 23194:
		return "NWC Request"
	case 23195:
		return "NWC Response"
	default:
		return "Unknown"
	}
}

func (s *NostrService) getContentPreview(content string) string {
	if len(content) > 80 {
		return content[:80] + "..."
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
		logger.WithFields(map[string]interface{}{
			"relay_url": relayURL,
			"user_id":   userID,
		}).Info("Closed relay connection")
	}

	for relayURL, sub := range conn.Subs {
		sub.Unsub()
		logger.WithFields(map[string]interface{}{
			"relay_url": relayURL,
			"user_id":   userID,
		}).Info("Unsubscribed from relay")
	}

	delete(s.connections, userID)

	ctx := context.Background()
	key := fmt.Sprintf("nostr_connection:%s", userID)
	s.redis.Del(ctx, key)

	logger.WithField("user_id", userID).Info("Connection closed")
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
			logger.WithError(err).Error("Failed to unmarshal notification")
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

func (s *NostrService) RestoreConnectionsFromRedis(ctx context.Context) error {
	logger.Info("🔄 Starting to restore connections from Redis")

	// Get all connection keys from Redis
	keys, err := s.redis.Keys(ctx, "nostr_connection:*").Result()
	if err != nil {
		return fmt.Errorf("failed to get connection keys from Redis: %w", err)
	}

	if len(keys) == 0 {
		logger.Info("📭 No existing connections found in Redis")
		return nil
	}

	logger.WithField("connection_count", len(keys)).Info("📦 Found existing connections in Redis")

	restoredCount := 0
	for _, key := range keys {
		servicePubkey := key[len("nostr_connection:"):]

		data, err := s.redis.Get(ctx, key).Result()
		if err != nil {
			logger.WithFields(map[string]interface{}{
				"service_pubkey": servicePubkey,
				"error":          err,
			}).Error("Failed to get connection data from Redis")
			continue
		}

		var connData map[string]interface{}
		if err := json.Unmarshal([]byte(data), &connData); err != nil {
			logger.WithFields(map[string]interface{}{
				"service_pubkey": servicePubkey,
				"error":          err,
			}).Error("Failed to unmarshal connection data")
			continue
		}

		connectionsData, ok := connData["connections"].([]interface{})
		if !ok {
			logger.WithField("service_pubkey", servicePubkey).Error("Invalid connections data format")
			continue
		}

		var connections []Connection
		for _, connData := range connectionsData {
			connMap, ok := connData.(map[string]interface{})
			if !ok {
				continue
			}

			relayURL, _ := connMap["relay"].(string)
			pubkey, _ := connMap["pubkey"].(string)

			if relayURL != "" && pubkey != "" {
				connections = append(connections, Connection{
					RelayURL: relayURL,
					PubKey:   pubkey,
				})
			}
		}

		if len(connections) == 0 {
			logger.WithField("service_pubkey", servicePubkey).Warn("No valid connections found for service")
			continue
		}

		// Extract device token
		deviceToken, _ := connData["device_token"].(string)
		if deviceToken == "" {
			logger.WithField("service_pubkey", servicePubkey).Warn("No device token found for service")
			continue
		}

		// Create UserConnection
		conn := &UserConnection{
			ServicePubkey: servicePubkey,
			DeviceToken:   deviceToken,
			Connections:   connections,
			Relays:        make(map[string]*nostr.Relay),
			Subs:          make(map[string]*nostr.Subscription),
			CreatedAt:     time.Now(), // Update creation time
		}

		// Store in memory
		s.mu.Lock()
		s.connections[servicePubkey] = conn
		s.mu.Unlock()

		// Start connecting to relays
		bgCtx := context.Background()
		go s.connectToRelays(bgCtx, conn)
		go s.startConnectionHealthCheck(bgCtx, conn)

		restoredCount++

		logger.WithFields(map[string]interface{}{
			"service_pubkey":    servicePubkey,
			"connections_count": len(connections),
		}).Info("✅ Restored connection from Redis")
	}

	logger.WithFields(map[string]interface{}{
		"total_found":    len(keys),
		"restored_count": restoredCount,
	}).Info("🎉 Connection restoration completed")

	return nil
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
			logger.WithFields(map[string]interface{}{
				"service_pubkey": conn.ServicePubkey,
				"relay_url":      relayURL,
			}).Info("Connection no longer exists, stopping reconnection")
			return
		}
		delay := time.Duration(attempt) * baseDelay
		if delay > maxDelay {
			delay = maxDelay
		}

		logger.WithFields(map[string]interface{}{
			"relay_url":      relayURL,
			"service_pubkey": conn.ServicePubkey,
			"pubkeys":        pubkeys,
			"attempt":        attempt,
			"delay":          delay,
		}).Info("Attempting relay reconnection")

		select {
		case <-ctx.Done():
			logger.WithFields(map[string]interface{}{
				"relay_url":      relayURL,
				"service_pubkey": conn.ServicePubkey,
			}).Info("Context cancelled, stopping relay reconnection")
			return
		case <-time.After(delay):
			// Continue to reconnection attempt
		}

		relay, err := nostr.RelayConnect(ctx, relayURL)
		if err == nil {
			conn.mu.Lock()
			conn.Relays[relayURL] = relay
			conn.mu.Unlock()

			logger.WithFields(map[string]interface{}{
				"relay_url":      relayURL,
				"service_pubkey": conn.ServicePubkey,
				"pubkeys":        pubkeys,
				"attempt":        attempt,
			}).Info("Successfully reconnected to relay")

			s.subscribeToEventsForRelay(ctx, conn, relay, relayURL, pubkeys)
			return
		}

		logger.WithFields(map[string]interface{}{
			"relay_url":      relayURL,
			"service_pubkey": conn.ServicePubkey,
			"pubkeys":        pubkeys,
			"attempt":        attempt,
			"max_retries":    maxRetries,
			"error":          err,
		}).Warn("Failed to reconnect to relay")
	}

	logger.WithFields(map[string]interface{}{
		"relay_url":      relayURL,
		"service_pubkey": conn.ServicePubkey,
		"pubkeys":        pubkeys,
		"max_retries":    maxRetries,
	}).Error("Failed to reconnect to relay after all retries")
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
			logger.WithFields(map[string]interface{}{
				"relay_url":      relayURL,
				"service_pubkey": conn.ServicePubkey,
				"error":          relay.ConnectionError,
			}).Warn("Relay connection has error, attempting reconnection")

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

func (s *NostrService) StartEventListening(ctx context.Context) {
	logger.Info("🚀 Starting continuous Nostr event listening service")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("🛑 Continuous event listening service stopped")
			return
		case <-ticker.C:
			s.monitorActiveConnections()
		}
	}
}

func (s *NostrService) monitorActiveConnections() {
	s.mu.RLock()
	connections := make(map[string]*UserConnection)
	maps.Copy(connections, s.connections)
	s.mu.RUnlock()

	if len(connections) == 0 {
		logger.Debug("No active connections to monitor")
		return
	}

	logger.WithField("active_connections", len(connections)).Info("🔍 Monitoring active connections")

	for servicePubkey, conn := range connections {
		conn.mu.RLock()
		relayCount := len(conn.Relays)
		subCount := len(conn.Subs)
		conn.mu.RUnlock()

		// Log connection status periodically
		logger.WithFields(map[string]interface{}{
			"service_pubkey":     servicePubkey,
			"relay_count":        relayCount,
			"subscription_count": subCount,
		}).Info("📊 Connection status check")

		// If we have connections but no relays or subscriptions, something is wrong
		if len(conn.Connections) > 0 && (relayCount == 0 || subCount == 0) {
			logger.WithFields(map[string]interface{}{
				"service_pubkey":     servicePubkey,
				"relay_count":        relayCount,
				"subscription_count": subCount,
				"connection_count":   len(conn.Connections),
			}).Warn("⚠️ Connection has no active relays or subscriptions - attempting to reconnect")

			// Attempt to reconnect
			bgCtx := context.Background()
			go s.connectToRelays(bgCtx, conn)
		}
	}
}
