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
}

func NewNostrService(redisClient *redis.Client) *NostrService {
	return &NostrService{
		redis: redisClient,
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

	relayPubkeys := make(map[string][]string)
	for _, conn := range handoff.Connections {
		relayPubkeys[conn.RelayURL] = append(relayPubkeys[conn.RelayURL], conn.PubKey)
	}

	for relayURL, pubkeys := range relayPubkeys {
		relay := s.getOrConnectRelay(relayURL)
		if relay == nil {
			continue
		}
		now:=nostr.Now()
		filters := []nostr.Filter{{Kinds: []int{23194}, Authors: pubkeys,Since:&now}}
		logger.WithField("relay_url", relayURL).Info("filters", filters)
		sub, err := relay.Subscribe(ctx, filters)
		if err != nil {
			logger.WithField("relay_url", relayURL).Error("failed to subscribe")
			continue
		}

		go func(sub *nostr.Subscription) {
			logger.WithField("relay_url", relayURL).Info("event listening start")
			defer sub.Unsub()
			logger.WithField("relay_url", relayURL).Info("event listening start.......")
			logger.WithField("relay_url", relayURL).Info("event listening start....... wait for events")
			for {
				select {
				case <-ctx.Done():
					return
				case ev := <-sub.Events:
					logger.WithField("relay_url", relayURL).Info("event received")
					s.cacheEvent(handoff.DeviceToken, ev)
				}
			}
		}(sub)
	}
}

func (s *NostrService) getOrConnectRelay(url string) *nostr.Relay {
	if r, ok := s.relayPool.Load(url); ok {
		return r.(*nostr.Relay)
	}
	for attempt := 0; attempt < 3; attempt++ {
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