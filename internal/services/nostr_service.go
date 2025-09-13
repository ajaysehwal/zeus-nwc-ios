package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/redis/go-redis/v9"
	"github.com/zeusln/ios-nwc-server/pkg/logger"
)

const (
	connectionKeyPrefix = "nwc:connections:"
	eventKeyPrefix      = "nwc:events:"
	eventIDKeyPrefix    = "nwc:event_ids:"
	connectionTTL       = 24 * time.Hour
	eventTTL            = 7 * 24 * time.Hour
	maxRetryAttempts    = 3
	retryDelay          = 5 * time.Second
	subscriptionDelay   = 3 * time.Second
)

type Connection struct {
	RelayURL string `json:"relay"`
	PubKey   string `json:"pubkey"`
}

type Handoff struct {
	DeviceToken string       `json:"device_token"`
	Connections []Connection `json:"connections"`
}

type NostrService struct {
	redis               *redis.Client
	relayPool           sync.Map
	listeners           sync.Map
	notificationService *NotificationService
}

func NewNostrService(redisClient *redis.Client, notificationService *NotificationService) *NostrService {
	return &NostrService{
		redis:               redisClient,
		notificationService: notificationService,
	}
}

func (s *NostrService) ProcessHandoff(ctx context.Context, req *Handoff) error {
	if err := s.validateHandoffRequest(req); err != nil {
		return err
	}

	if err := s.storeConnections(ctx, req); err != nil {
		return fmt.Errorf("failed to store connections: %w", err)
	}

	s.startListener(*req)
	return nil
}

func (s *NostrService) ReconnectToAllDevices(ctx context.Context) error {
	pattern := connectionKeyPrefix + "*"
	var cursor uint64

	for {
		keys, nextCursor, err := s.redis.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("failed to scan Redis keys: %w", err)
		}

		for _, key := range keys {
			if err := s.restoreDeviceConnections(ctx, key); err != nil {
				logger.WithFields(map[string]interface{}{
					"key":   key,
					"error": err,
				}).Error("Failed to restore device connections")
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}

func (s *NostrService) HandleRestore(ctx context.Context, deviceToken string) (Handoff, []string, error) {
	if deviceToken == "" {
		return Handoff{}, nil, fmt.Errorf("device_token required")
	}

	s.stopExistingListener(deviceToken)

	connections, err := s.getStoredConnections(ctx, deviceToken)
	if err != nil {
		return Handoff{}, nil, err
	}

	events, err := s.getStoredEvents(ctx, deviceToken)
	if err != nil {
		return Handoff{}, nil, err
	}

	s.cleanupEventData(ctx, deviceToken)

	return Handoff{
		DeviceToken: deviceToken,
		Connections: connections,
	}, events, nil
}

func (s *NostrService) Shutdown() {
	s.stopAllListeners()
	s.closeAllRelays()
}

func (s *NostrService) validateHandoffRequest(req *Handoff) error {
	if req.DeviceToken == "" || len(req.Connections) == 0 {
		return fmt.Errorf("device_token and connections required")
	}

	for _, conn := range req.Connections {
		if conn.RelayURL == "" || conn.PubKey == "" {
			return fmt.Errorf("invalid connection: relay URL and pubkey required")
		}
	}
	return nil
}

func (s *NostrService) storeConnections(ctx context.Context, req *Handoff) error {
	key := connectionKeyPrefix + req.DeviceToken
	data, err := json.Marshal(req.Connections)
	if err != nil {
		return fmt.Errorf("failed to marshal connections: %w", err)
	}

	return s.redis.Set(ctx, key, data, connectionTTL).Err()
}

func (s *NostrService) restoreDeviceConnections(ctx context.Context, key string) error {
	logger.WithField("key", key).Info("Restoring device connections")
	data, err := s.redis.Get(ctx, key).Bytes()
	if err == redis.Nil {
		logger.WithField("key", key).Warn("Connections not found")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to fetch connections: %w", err)
	}

	var connections []Connection
	if err := json.Unmarshal(data, &connections); err != nil {
		return fmt.Errorf("failed to parse connections: %w", err)
	}

	if len(connections) == 0 {
		logger.WithField("key", key).Debug("No connections found, skipping listener start")
		return nil
	}

	deviceToken := key[len(connectionKeyPrefix):]
	handoff := Handoff{
		DeviceToken: deviceToken,
		Connections: connections,
	}

	s.startListener(handoff)
	logger.WithFields(map[string]interface{}{
		"device_token": deviceToken,
		"connections":  len(connections),
	}).Info("Restored device connections")

	return nil
}

func (s *NostrService) getStoredConnections(ctx context.Context, deviceToken string) ([]Connection, error) {
	key := connectionKeyPrefix + deviceToken
	data, err := s.redis.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("no connections found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch connections: %w", err)
	}

	var connections []Connection
	if err := json.Unmarshal(data, &connections); err != nil {
		return nil, fmt.Errorf("failed to parse connections: %w", err)
	}

	return connections, nil
}

func (s *NostrService) getStoredEvents(ctx context.Context, deviceToken string) ([]string, error) {
	eventKey := eventKeyPrefix + deviceToken
	events, err := s.redis.LRange(ctx, eventKey, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch events: %w", err)
	}
	return events, nil
}

func (s *NostrService) cleanupEventData(ctx context.Context, deviceToken string) {
	eventKey := eventKeyPrefix + deviceToken
	eventIDKey := eventIDKeyPrefix + deviceToken
	s.redis.Del(ctx, eventKey, eventIDKey)
}

func (s *NostrService) startListener(handoff Handoff) {
	s.stopExistingListener(handoff.DeviceToken)

	ctx, cancel := context.WithTimeout(context.Background(), connectionTTL)
	s.listeners.Store(handoff.DeviceToken, cancel)

	for _, conn := range handoff.Connections {
		relay := s.getOrConnectRelay(conn.RelayURL)
		if relay == nil {
			continue
		}

		go s.listenAuthor(ctx, handoff.DeviceToken, relay, conn.RelayURL, conn.PubKey)
	}
}

func (s *NostrService) stopExistingListener(deviceToken string) {
	if cancel, ok := s.listeners.LoadAndDelete(deviceToken); ok {
		cancel.(context.CancelFunc)()
	}
}

func (s *NostrService) stopAllListeners() {
	s.listeners.Range(func(key, value interface{}) bool {
		value.(context.CancelFunc)()
		s.listeners.Delete(key)
		return true
	})
}

func (s *NostrService) closeAllRelays() {
	s.relayPool.Range(func(key, value interface{}) bool {
		value.(*nostr.Relay).Close()
		s.relayPool.Delete(key)
		return true
	})
}

func (s *NostrService) listenAuthor(ctx context.Context, deviceToken string, relay *nostr.Relay, relayURL, pubkey string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := s.subscribeAndListen(ctx, deviceToken, relay, relayURL, pubkey); err != nil {
			logger.WithFields(map[string]interface{}{
				"relay_url": relayURL,
				"author":    pubkey,
				"error":     err,
			}).Error("Subscription failed, retrying")
			time.Sleep(retryDelay)
		}
	}
}

func (s *NostrService) subscribeAndListen(ctx context.Context, deviceToken string, relay *nostr.Relay, relayURL, pubkey string) error {
	now := nostr.Now()
	filters := []nostr.Filter{{
		Kinds:   []int{nostr.KindNWCWalletRequest},
		Authors: []string{pubkey},
		Since:   &now,
	}}

	logger.WithFields(map[string]interface{}{
		"relay_url": relayURL,
		"author":    pubkey,
	}).Info("Subscribing with filter")

	sub, err := relay.Subscribe(ctx, filters)
	if err != nil {
		return fmt.Errorf("failed to subscribe: %w", err)
	}
	defer sub.Unsub()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sub.EndOfStoredEvents:
			logger.WithFields(map[string]interface{}{
				"relay_url": relayURL,
				"author":    pubkey,
			}).Info("End of stored events")
		case ev, ok := <-sub.Events:
			if !ok {
				logger.WithFields(map[string]interface{}{
					"relay_url": relayURL,
					"author":    pubkey,
				}).Warn("Subscription closed, retrying")
				time.Sleep(subscriptionDelay)
				return fmt.Errorf("subscription closed")
			}
			if ev == nil {
				continue
			}

			logger.WithFields(map[string]interface{}{
				"relay_url": relayURL,
				"author":    pubkey,
			}).Info("Event received")

			s.handleEvent(ctx, deviceToken, ev)
			s.cacheEvent(deviceToken, ev)
		}
	}
}

func (s *NostrService) handleEvent(ctx context.Context, deviceToken string, ev *nostr.Event) {
	if ev.Kind != nostr.KindNWCWalletRequest {
		return
	}

	if err := s.notificationService.SendNotification(ctx, deviceToken); err != nil {
		logger.WithFields(map[string]interface{}{
			"device_token": deviceToken,
			"error":        err,
		}).Error("Failed to send notification")
	}
}

func (s *NostrService) getOrConnectRelay(url string) *nostr.Relay {
	if relay, ok := s.relayPool.Load(url); ok {
		return relay.(*nostr.Relay)
	}

	for attempt := 0; attempt < maxRetryAttempts; attempt++ {
		relay, err := nostr.RelayConnect(context.Background(), url)
		if err == nil {
			s.relayPool.Store(url, relay)
			return relay
		}

		delay := time.Second << attempt
		time.Sleep(delay)
	}

	logger.WithField("url", url).Error("Failed to connect to relay after retries")
	return nil
}

func (s *NostrService) cacheEvent(deviceToken string, ev *nostr.Event) {
	eventKey := eventKeyPrefix + deviceToken
	eventIDKey := eventIDKeyPrefix + deviceToken

	data, err := json.Marshal(ev)
	if err != nil {
		logger.WithFields(map[string]interface{}{
			"device_token": deviceToken,
			"error":        err,
		}).Error("Failed to marshal event")
		return
	}

	if s.redis.SAdd(context.Background(), eventIDKey, ev.ID).Val() > 0 {
		s.redis.LPush(context.Background(), eventKey, data)
		s.redis.Expire(context.Background(), eventKey, eventTTL)
	}
}
