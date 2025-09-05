package redis

import (
	"context"
	"time"

	"github.com/zeusln/ios-nwc-server/pkg/utils"
	"go.uber.org/zap"
)

func ExampleUsage() {
	ctx := context.Background()
	redisOps := NewRedisOps()
	logger := utils.GetLogger()

	// String operations
	err := redisOps.Set(ctx, "user:123", "John Doe", 24*time.Hour)
	if err != nil {
		logger.Error("Failed to set user", zap.Error(err))
	}

	userData, err := redisOps.GetString(ctx, "user:123")
	if err != nil {
		logger.Error("Failed to get user", zap.Error(err))
	} else {
		logger.Info("Retrieved user", zap.String("data", userData))
	}

	// Object operations
	type User struct {
		ID      string    `json:"id"`
		Name    string    `json:"name"`
		Email   string    `json:"email"`
		Created time.Time `json:"created"`
	}

	user := User{
		ID:      "123",
		Name:    "John Doe",
		Email:   "john@example.com",
		Created: time.Now(),
	}

	err = redisOps.Set(ctx, "user:obj:123", user, 24*time.Hour)
	if err != nil {
		logger.Error("Failed to set user object", zap.Error(err))
	}

	var retrievedUser User
	err = redisOps.GetObject(ctx, "user:obj:123", &retrievedUser)
	if err != nil {
		logger.Error("Failed to get user object", zap.Error(err))
	} else {
		logger.Info("Retrieved user object", zap.String("name", retrievedUser.Name))
	}

	// Hash operations
	err = redisOps.HSet(ctx, "user:profile:123", "last_login", time.Now().String())
	if err != nil {
		logger.Error("Failed to set user profile", zap.Error(err))
	}

	lastLogin, err := redisOps.HGet(ctx, "user:profile:123", "last_login")
	if err != nil {
		logger.Error("Failed to get last login", zap.Error(err))
	} else {
		logger.Info("Last login", zap.String("time", string(lastLogin)))
	}

	// Counter operations
	count, err := redisOps.Incr(ctx, "page:views:home")
	if err != nil {
		logger.Error("Failed to increment counter", zap.Error(err))
	} else {
		logger.Info("Page views", zap.Int64("count", count))
	}

	// List operations
	err = redisOps.LPush(ctx, "user:123:notifications", "Welcome message", "System update")
	if err != nil {
		logger.Error("Failed to push notifications", zap.Error(err))
	}

	notification, err := redisOps.RPop(ctx, "user:123:notifications")
	if err != nil {
		logger.Error("Failed to pop notification", zap.Error(err))
	} else {
		logger.Info("Notification", zap.String("message", string(notification)))
	}

	// Check if key exists
	exists, err := redisOps.Exists(ctx, "user:123")
	if err != nil {
		logger.Error("Failed to check key existence", zap.Error(err))
	} else {
		logger.Info("User exists", zap.Bool("exists", exists))
	}

	// Get TTL
	ttl, err := redisOps.TTL(ctx, "user:123")
	if err != nil {
		logger.Error("Failed to get TTL", zap.Error(err))
	} else {
		logger.Info("Key TTL", zap.Duration("ttl", ttl))
	}

	// Delete keys
	err = redisOps.Delete(ctx, "user:123", "user:obj:123")
	if err != nil {
		logger.Error("Failed to delete keys", zap.Error(err))
	} else {
		logger.Info("Keys deleted successfully")
	}
}
