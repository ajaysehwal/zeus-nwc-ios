package testutils

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zeusln/ios-nwc-server/internal/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Port:         "8080",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
		Redis: config.RedisConfig{
			Host:     "localhost",
			Port:     6379,
			Password: "",
			DB:       1, // Use test database
		},
		Log: config.LogConfig{
			Level:       "debug",
			Environment: "test",
			ServiceName: "zeus-nwc-server-test",
			PrettyPrint: true,
			Colorful:    false,
		},
		Notifications: config.NotificationConfig{
			APNS: config.APNSConfig{
				Enabled:    false, // Disable for tests
				KeyPath:    "",
				KeyID:      "",
				TeamID:     "",
				Production: false,
			},
		},
	}
}

// TestRedisClient creates a test Redis client
func TestRedisClient() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       1, // Use test database
	})
}

// TestLogger creates a test logger
func TestLogger(t *testing.T) *zap.Logger {
	return zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel))
}

// TestConnection represents a test connection
type TestConnection struct {
	RelayURL string `json:"relay"`
	PubKey   string `json:"pubkey"`
}

// TestHandoffRequest represents a test handoff request
type TestHandoffRequest struct {
	ServicePubkey string           `json:"service_pubkey"`
	DeviceToken   string           `json:"device_token"`
	Connections   []TestConnection `json:"connections"`
}

// MockHandoffRequest creates a mock handoff request
func MockHandoffRequest() *TestHandoffRequest {
	return &TestHandoffRequest{
		ServicePubkey: "npub1test_service_pubkey",
		DeviceToken:   "test_device_token_123",
		Connections: []TestConnection{
			{
				RelayURL: "wss://relay.test.com",
				PubKey:   "npub1test_pubkey_1",
			},
			{
				RelayURL: "wss://relay2.test.com",
				PubKey:   "npub1test_pubkey_2",
			},
		},
	}
}

// MockNotificationData creates mock notification data
func MockNotificationData() map[string]interface{} {
	return map[string]interface{}{
		"service_pubkey": "npub1test_service_pubkey",
		"device_token":   "test_device_token_123",
		"title":          "Test Notification",
		"body":           "This is a test notification",
		"event_id":       "test_event_id_123",
		"event_kind":     23194,
		"pubkey":         "npub1test_pubkey_1",
		"timestamp":      time.Now().Unix(),
	}
}

// AssertJSONResponse checks if response matches expected JSON
func AssertJSONResponse(t *testing.T, expected, actual interface{}) {
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("Failed to marshal expected: %v", err)
	}

	actualJSON, err := json.Marshal(actual)
	if err != nil {
		t.Fatalf("Failed to marshal actual: %v", err)
	}

	if string(expectedJSON) != string(actualJSON) {
		t.Errorf("JSON mismatch:\nExpected: %s\nActual: %s", string(expectedJSON), string(actualJSON))
	}
}

// WaitForCondition waits for a condition to be true
func WaitForCondition(t *testing.T, condition func() bool, timeout time.Duration, message string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.Fatalf("Timeout waiting for condition: %s", message)
		case <-ticker.C:
			if condition() {
				return
			}
		}
	}
}

// SkipIfRedisNotAvailable skips test if Redis is not available
func SkipIfRedisNotAvailable(t *testing.T) {
	client := TestRedisClient()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis not available: %v", err)
	}
}

// CreateTestTempFile creates a temporary file for testing
func CreateTestTempFile(t *testing.T, content string) string {
	tmpfile, err := os.CreateTemp("", "test_*.tmp")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := tmpfile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	return tmpfile.Name()
}

// CleanupTempFile removes a temporary file
func CleanupTempFile(t *testing.T, filename string) {
	if err := os.Remove(filename); err != nil {
		t.Logf("Failed to remove temp file %s: %v", filename, err)
	}
}
