package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zeusln/ios-nwc-server/internal/config"
	"go.uber.org/zap"
)

type HandoffService struct {
	config       *config.Config
	nostrService *NostrService
	redis        *redis.Client
	logger       *zap.Logger
}

type HandoffResponse struct {
	Message       string       `json:"message"`
	ServicePubkey string       `json:"service_pubkey"`
	Status        string       `json:"status"`
	Connections   []Connection `json:"connections"`
}

func NewHandoffService(cfg *config.Config, nostrService *NostrService, redisClient *redis.Client, logger *zap.Logger) *HandoffService {
	return &HandoffService{
		config:       cfg,
		nostrService: nostrService,
		redis:        redisClient,
		logger:       logger,
	}
}

func (s *HandoffService) ProcessHandoff(ctx context.Context, req *HandoffRequest) (*HandoffResponse, error) {
	s.logger.Info("Processing handoff request",
		zap.String("service_pubkey", req.ServicePubkey),
		zap.Int("connections_count", len(req.Connections)),
	)

	if err := s.validateRequest(req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := s.storeDeviceInfo(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to store device info: %w", err)
	}

	if err := s.nostrService.HandleHandoff(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to process nostr handoff: %w", err)
	}

	response := &HandoffResponse{
		Message:       "Handoff processed successfully",
		ServicePubkey: req.ServicePubkey,
		Status:        "connected",
		Connections:   req.Connections,
	}

	s.logger.Info("Handoff processed successfully",
		zap.String("service_pubkey", req.ServicePubkey),
		zap.Int("connections_count", len(req.Connections)),
	)

	return response, nil
}

func (s *HandoffService) validateRequest(req *HandoffRequest) error {
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

func (s *HandoffService) storeDeviceInfo(ctx context.Context, req *HandoffRequest) error {
	deviceInfo := map[string]any{
		"service_pubkey": req.ServicePubkey,
		"device_token":   req.DeviceToken,
		"connections":    req.Connections,
		"connected_at":   time.Now().Unix(),
		"status":         "active",
	}

	key := fmt.Sprintf("device_info:%s", req.ServicePubkey)
	data, err := json.Marshal(deviceInfo)
	if err != nil {
		return err
	}

	return s.redis.Set(ctx, key, data, 365*24*time.Hour).Err()
}

func (s *HandoffService) GetDeviceInfo(ctx context.Context, userID string) (map[string]interface{}, error) {
	key := fmt.Sprintf("device_info:%s", userID)

	data, err := s.redis.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var deviceInfo map[string]interface{}
	if err := json.Unmarshal([]byte(data), &deviceInfo); err != nil {
		return nil, err
	}

	return deviceInfo, nil
}

func (s *HandoffService) DisconnectDevice(ctx context.Context, userID string) error {
	s.logger.Info("Disconnecting device", zap.String("user_id", userID))

	if err := s.nostrService.CloseConnection(userID); err != nil {
		s.logger.Error("Failed to close nostr connection", zap.Error(err))
	}

	key := fmt.Sprintf("device_info:%s", userID)
	deviceInfo := map[string]interface{}{
		"status":          "disconnected",
		"disconnected_at": time.Now().Unix(),
	}

	data, err := json.Marshal(deviceInfo)
	if err != nil {
		return err
	}

	if err := s.redis.Set(ctx, key, data, 365*24*time.Hour).Err(); err != nil {
		return err
	}

	s.logger.Info("Device disconnected successfully", zap.String("user_id", userID))
	return nil
}
