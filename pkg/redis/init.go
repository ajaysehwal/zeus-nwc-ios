package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zeusln/ios-nwc-server/internal/config"
	"github.com/zeusln/ios-nwc-server/pkg/utils"
	"go.uber.org/zap"
)

var (
	client *redis.Client
	logger *utils.Logger
)

type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
	PoolSize int
}

func Init(cfg *config.Config) error {
	logger = utils.GetLogger()

	redisConfig := &RedisConfig{
		Host:     cfg.Redis.Host,
		Port:     cfg.Redis.Port,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
		PoolSize: cfg.Redis.PoolSize,
	}

	client = redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", redisConfig.Host, redisConfig.Port),
		Password:     redisConfig.Password,
		DB:           redisConfig.DB,
		PoolSize:     redisConfig.PoolSize,
		MinIdleConns: 5,
		MaxRetries:   3,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolTimeout:  4 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		logger.Error("Failed to connect to Redis", zap.Error(err))
		return fmt.Errorf("redis connection failed: %w", err)
	}

	logger.Success("Redis connected successfully",
		zap.String("host", redisConfig.Host),
		zap.Int("port", redisConfig.Port),
		zap.Int("db", redisConfig.DB),
		zap.Int("pool_size", redisConfig.PoolSize),
	)

	return nil
}

func GetClient() *redis.Client {
	if client == nil {
		logger.Error("Redis client not initialized")
		return nil
	}
	return client
}

func Close() error {
	if client != nil {
		logger.Info("Closing Redis connection")
		return client.Close()
	}
	return nil
}

func HealthCheck() error {
	if client == nil {
		return fmt.Errorf("redis client not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return client.Ping(ctx).Err()
}
