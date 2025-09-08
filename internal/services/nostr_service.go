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

type Connection struct {
	RelayURL string `json:"relay"`
	PubKey   string `json:"pubkey"`
}

type Handoff struct {
	DeviceToken string       `json:"device_token"`
	Connections []Connection `json:"connections"`
}

type NostrService struct {
	redis     *redis.Client
	relayPool sync.Map
	listeners sync.Map
	notificationService *NotificationService
}

func NewNostrService(redisClient *redis.Client, notificationService *NotificationService) *NostrService {
	return &NostrService{
		redis: redisClient,
		notificationService: notificationService,
	}
}

func (s *NostrService) ProcessHandoff(ctx context.Context, req *Handoff) error {
	if req.DeviceToken == "" || len(req.Connections) == 0 {
		return fmt.Errorf("device_token and connections required")
	}
	for _, conn := range req.Connections {
		if conn.RelayURL == "" || conn.PubKey == "" {
			return fmt.Errorf("invalid connection")
		}
	}

	key := "nwc:connections:" + req.DeviceToken
	data, _ := json.Marshal(req.Connections)
	if err := s.redis.Set(ctx, key, data, 24*time.Hour).Err(); err != nil {
		return fmt.Errorf("failed to store connections: %w", err)
	}

	s.startListener(*req)
	return nil
}

func (s *NostrService) RestoreAllDevices(ctx context.Context) error {
	const pattern = "nwc:connections:*"
	var cursor uint64
	for {
		keys, nextCursor, err := s.redis.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("failed to scan Redis keys: %w", err)
		}

		for _, key := range keys {
			data, err := s.redis.Get(ctx, key).Bytes()
			if err == redis.Nil {
				logger.WithField("key", key).Warn("Connections not found")
				continue
			} else if err != nil {
				logger.WithFields(map[string]interface{}{"key": key, "error": err}).Error("Failed to fetch connections")
				continue
			}

			var connections []Connection
			if err := json.Unmarshal(data, &connections); err != nil {
				logger.WithFields(map[string]interface{}{"key": key, "error": err}).Error("Failed to parse connections")
				continue
			}
            if (len(connections) == 0) {
				logger.Debug(fmt.Sprintf("no connections found for device %s , skipping start listener", key))
				continue
            }
			logger.WithField("connections", connections).Info(fmt.Sprintf("Found %d connections", len(connections)))
			deviceToken := key[len("nwc:connections:"):]
			handoff := Handoff{DeviceToken: deviceToken, Connections: connections}
			s.startListener(handoff)
			logger.WithField("device_token", deviceToken).Info("Restored device connections")
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

	key := "nwc:connections:" + deviceToken
	eventKey := "nwc:events:" + deviceToken

	if cancel, ok := s.listeners.LoadAndDelete(deviceToken); ok {
		cancel.(context.CancelFunc)()
	}
	data, err := s.redis.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return Handoff{}, nil, fmt.Errorf("no connections found")
	} else if err != nil {
		return Handoff{}, nil, fmt.Errorf("failed to fetch connections: %w", err)
	}
	var connections []Connection
	json.Unmarshal(data, &connections)

	events, err := s.redis.LRange(ctx, eventKey, 0, -1).Result()
	if err != nil {
		return Handoff{}, nil, fmt.Errorf("failed to fetch events: %w", err)
	}

	s.redis.Del(ctx, eventKey, "nwc:event_ids:"+deviceToken)
	return Handoff{DeviceToken: deviceToken, Connections: connections}, events, nil
}

func (s *NostrService) startListener(handoff Handoff) {
    if cancel, ok := s.listeners.LoadAndDelete(handoff.DeviceToken); ok {
        cancel.(context.CancelFunc)()
    }

    ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
    s.listeners.Store(handoff.DeviceToken, cancel)

    for _, conn := range handoff.Connections {
        relay := s.getOrConnectRelay(conn.RelayURL)
        if relay == nil {
            continue
        }

        go s.listenAuthor(ctx, handoff.DeviceToken, relay, conn.RelayURL, conn.PubKey)
    }
}

func (s *NostrService) listenAuthor(ctx context.Context, deviceToken string, relay *nostr.Relay, relayURL, pubkey string) {
    for {
        select {
        case <-ctx.Done():
            return
        default:
        }
        now := nostr.Now()
        filters := []nostr.Filter{{
            Kinds:   []int{nostr.KindNWCWalletRequest},
            Authors: []string{pubkey},
            Since:   &now,
        }}
        logger.WithField("relay_url", relayURL).WithField("author", pubkey).Info("subscribing with filter")

        sub, err := relay.Subscribe(ctx, filters)
        if err != nil {
            logger.WithField("relay_url", relayURL).WithError(err).Error("failed to subscribe")
            time.Sleep(5 * time.Second)
            continue // retry
        }
        // Listen loop
        for {
            select {
            case <-ctx.Done():
                sub.Unsub()
                return
            case <-sub.EndOfStoredEvents:
                logger.WithField("relay_url", relayURL).WithField("author", pubkey).Info("end of stored events")
            case ev, ok := <-sub.Events:
                if !ok {
                    logger.WithField("relay_url", relayURL).WithField("author", pubkey).Warn("subscription closed, retrying…")
                    time.Sleep(3 * time.Second)
                    sub.Unsub()
                    goto RETRY
                }
                if ev == nil {
                    continue
                }
                logger.WithField("relay_url", relayURL).WithField("author", pubkey).Info("event received")
				s.handleEvent(ctx, deviceToken, ev)
                s.cacheEvent(deviceToken, ev)
            }
        }

    RETRY:
        continue
    }
}


func (s *NostrService) handleEvent(ctx context.Context, deviceToken string, ev *nostr.Event) {
	switch ev.Kind {
	case nostr.KindNWCWalletRequest:
	   if err := s.notificationService.SendNotification(ctx, deviceToken); err != nil {
			logger.WithFields(map[string]interface{}{
				"device_token": deviceToken,
				"error":        err,
			}).Error("Failed to send notification")
		}
	}
}



func (s *NostrService) getOrConnectRelay(url string) *nostr.Relay {
	if r, ok := s.relayPool.Load(url); ok {
		return r.(*nostr.Relay)
	}
	for attempt := range 3 {
		relay, err := nostr.RelayConnect(context.Background(), url)
		if err == nil {
			s.relayPool.Store(url, relay)
			return relay
		}
		time.Sleep(time.Second << attempt)
	}
	return nil
}

func (s *NostrService) cacheEvent(deviceToken string, ev *nostr.Event) {
	eventKey := "nwc:events:" + deviceToken
	data, _ := json.Marshal(ev)
	if s.redis.SAdd(context.Background(), "nwc:event_ids:"+deviceToken, ev.ID).Val() > 0 {
		s.redis.LPush(context.Background(), eventKey, data)
		s.redis.Expire(context.Background(), eventKey, 7*24*time.Hour)
	}
}

func (s *NostrService) Shutdown() {
	s.listeners.Range(func(key, value interface{}) bool {
		value.(context.CancelFunc)()
		s.listeners.Delete(key)
		return true
	})
	s.relayPool.Range(func(key, value interface{}) bool {
		value.(*nostr.Relay).Close()
		s.relayPool.Delete(key)
		return true
	})
}