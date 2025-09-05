package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zeusln/ios-nwc-server/pkg/utils"
	"go.uber.org/zap"
)

type RedisOps struct {
	client *redis.Client
	logger *utils.Logger
}

func NewRedisOps() *RedisOps {
	return &RedisOps{
		client: GetClient(),
		logger: utils.GetLogger(),
	}
}

func (r *RedisOps) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	if r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}

	var data []byte
	var err error

	switch v := value.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		data, err = json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
	}

	err = r.client.Set(ctx, key, data, expiration).Err()
	if err != nil {
		r.logger.Error("Redis SET failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return fmt.Errorf("redis set failed: %w", err)
	}

	r.logger.Debug("Redis SET successful", zap.String("key", key))
	return nil
}

func (r *RedisOps) Get(ctx context.Context, key string) ([]byte, error) {
	if r.client == nil {
		return nil, fmt.Errorf("redis client not initialized")
	}

	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			r.logger.Debug("Redis key not found", zap.String("key", key))
			return nil, nil
		}
		r.logger.Error("Redis GET failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return nil, fmt.Errorf("redis get failed: %w", err)
	}

	r.logger.Debug("Redis GET successful", zap.String("key", key))
	return data, nil
}

func (r *RedisOps) GetString(ctx context.Context, key string) (string, error) {
	if r.client == nil {
		return "", fmt.Errorf("redis client not initialized")
	}

	value, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			r.logger.Debug("Redis key not found", zap.String("key", key))
			return "", nil
		}
		r.logger.Error("Redis GET string failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return "", fmt.Errorf("redis get string failed: %w", err)
	}

	r.logger.Debug("Redis GET string successful", zap.String("key", key))
	return value, nil
}

func (r *RedisOps) GetObject(ctx context.Context, key string, dest interface{}) error {
	if r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}

	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			r.logger.Debug("Redis key not found", zap.String("key", key))
			return nil
		}
		r.logger.Error("Redis GET object failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return fmt.Errorf("redis get object failed: %w", err)
	}

	if err := json.Unmarshal(data, dest); err != nil {
		r.logger.Error("Failed to unmarshal Redis value",
			zap.String("key", key),
			zap.Error(err),
		)
		return fmt.Errorf("failed to unmarshal value: %w", err)
	}

	r.logger.Debug("Redis GET object successful", zap.String("key", key))
	return nil
}

func (r *RedisOps) Delete(ctx context.Context, keys ...string) error {
	if r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}

	err := r.client.Del(ctx, keys...).Err()
	if err != nil {
		r.logger.Error("Redis DELETE failed",
			zap.Strings("keys", keys),
			zap.Error(err),
		)
		return fmt.Errorf("redis delete failed: %w", err)
	}

	r.logger.Debug("Redis DELETE successful", zap.Strings("keys", keys))
	return nil
}

func (r *RedisOps) Exists(ctx context.Context, key string) (bool, error) {
	if r.client == nil {
		return false, fmt.Errorf("redis client not initialized")
	}

	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis EXISTS failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return false, fmt.Errorf("redis exists failed: %w", err)
	}

	return exists > 0, nil
}

func (r *RedisOps) Expire(ctx context.Context, key string, expiration time.Duration) error {
	if r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}

	err := r.client.Expire(ctx, key, expiration).Err()
	if err != nil {
		r.logger.Error("Redis EXPIRE failed",
			zap.String("key", key),
			zap.Duration("expiration", expiration),
			zap.Error(err),
		)
		return fmt.Errorf("redis expire failed: %w", err)
	}

	r.logger.Debug("Redis EXPIRE successful",
		zap.String("key", key),
		zap.Duration("expiration", expiration),
	)
	return nil
}

func (r *RedisOps) TTL(ctx context.Context, key string) (time.Duration, error) {
	if r.client == nil {
		return 0, fmt.Errorf("redis client not initialized")
	}

	ttl, err := r.client.TTL(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis TTL failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return 0, fmt.Errorf("redis ttl failed: %w", err)
	}

	return ttl, nil
}

func (r *RedisOps) Incr(ctx context.Context, key string) (int64, error) {
	if r.client == nil {
		return 0, fmt.Errorf("redis client not initialized")
	}

	value, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis INCR failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return 0, fmt.Errorf("redis incr failed: %w", err)
	}

	r.logger.Debug("Redis INCR successful",
		zap.String("key", key),
		zap.Int64("value", value),
	)
	return value, nil
}

func (r *RedisOps) IncrBy(ctx context.Context, key string, increment int64) (int64, error) {
	if r.client == nil {
		return 0, fmt.Errorf("redis client not initialized")
	}

	value, err := r.client.IncrBy(ctx, key, increment).Result()
	if err != nil {
		r.logger.Error("Redis INCRBY failed",
			zap.String("key", key),
			zap.Int64("increment", increment),
			zap.Error(err),
		)
		return 0, fmt.Errorf("redis incrby failed: %w", err)
	}

	r.logger.Debug("Redis INCRBY successful",
		zap.String("key", key),
		zap.Int64("value", value),
	)
	return value, nil
}

func (r *RedisOps) HSet(ctx context.Context, key string, field string, value interface{}) error {
	if r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}

	var data []byte
	var err error

	switch v := value.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		data, err = json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
	}

	err = r.client.HSet(ctx, key, field, data).Err()
	if err != nil {
		r.logger.Error("Redis HSET failed",
			zap.String("key", key),
			zap.String("field", field),
			zap.Error(err),
		)
		return fmt.Errorf("redis hset failed: %w", err)
	}

	r.logger.Debug("Redis HSET successful",
		zap.String("key", key),
		zap.String("field", field),
	)
	return nil
}

func (r *RedisOps) HGet(ctx context.Context, key string, field string) ([]byte, error) {
	if r.client == nil {
		return nil, fmt.Errorf("redis client not initialized")
	}

	data, err := r.client.HGet(ctx, key, field).Bytes()
	if err != nil {
		if err == redis.Nil {
			r.logger.Debug("Redis hash field not found",
				zap.String("key", key),
				zap.String("field", field),
			)
			return nil, nil
		}
		r.logger.Error("Redis HGET failed",
			zap.String("key", key),
			zap.String("field", field),
			zap.Error(err),
		)
		return nil, fmt.Errorf("redis hget failed: %w", err)
	}

	r.logger.Debug("Redis HGET successful",
		zap.String("key", key),
		zap.String("field", field),
	)
	return data, nil
}

func (r *RedisOps) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	if r.client == nil {
		return nil, fmt.Errorf("redis client not initialized")
	}

	result, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis HGETALL failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return nil, fmt.Errorf("redis hgetall failed: %w", err)
	}

	r.logger.Debug("Redis HGETALL successful", zap.String("key", key))
	return result, nil
}

func (r *RedisOps) LPush(ctx context.Context, key string, values ...interface{}) error {
	if r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}

	err := r.client.LPush(ctx, key, values...).Err()
	if err != nil {
		r.logger.Error("Redis LPUSH failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return fmt.Errorf("redis lpush failed: %w", err)
	}

	r.logger.Debug("Redis LPUSH successful", zap.String("key", key))
	return nil
}

func (r *RedisOps) RPop(ctx context.Context, key string) ([]byte, error) {
	if r.client == nil {
		return nil, fmt.Errorf("redis client not initialized")
	}

	data, err := r.client.RPop(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			r.logger.Debug("Redis list is empty", zap.String("key", key))
			return nil, nil
		}
		r.logger.Error("Redis RPOP failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return nil, fmt.Errorf("redis rpop failed: %w", err)
	}

	r.logger.Debug("Redis RPOP successful", zap.String("key", key))
	return data, nil
}

func (r *RedisOps) LLen(ctx context.Context, key string) (int64, error) {
	if r.client == nil {
		return 0, fmt.Errorf("redis client not initialized")
	}

	length, err := r.client.LLen(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis LLEN failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return 0, fmt.Errorf("redis llen failed: %w", err)
	}

	return length, nil
}

func (r *RedisOps) FlushDB(ctx context.Context) error {
	if r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}

	err := r.client.FlushDB(ctx).Err()
	if err != nil {
		r.logger.Error("Redis FLUSHDB failed", zap.Error(err))
		return fmt.Errorf("redis flushdb failed: %w", err)
	}

	r.logger.Warn("Redis database flushed")
	return nil
}
