package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zeusln/ios-nwc-server/pkg/logger"
)

type RedisOps struct {
	client *redis.Client
}

func NewRedisOps() *RedisOps {
	return &RedisOps{
		client: GetClient(),
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
		logger.WithFields(map[string]interface{}{
			"key":   key,
			"error": err,
		}).Error("Redis SET failed")
		return fmt.Errorf("redis set failed: %w", err)
	}

	logger.WithField("key", key).Debug("Redis SET successful")
	return nil
}

func (r *RedisOps) Get(ctx context.Context, key string) ([]byte, error) {
	if r.client == nil {
		return nil, fmt.Errorf("redis client not initialized")
	}

	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			logger.WithField("key", key).Debug("Redis key not found")
			return nil, nil
		}
		logger.WithFields(map[string]interface{}{
			"key":   key,
			"error": err,
		}).Error("Redis GET failed")
		return nil, fmt.Errorf("redis get failed: %w", err)
	}

	logger.WithField("key", key).Debug("Redis GET successful")
	return data, nil
}

func (r *RedisOps) GetString(ctx context.Context, key string) (string, error) {
	if r.client == nil {
		return "", fmt.Errorf("redis client not initialized")
	}

	value, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			logger.WithField("key", key).Debug("Redis key not found")
			return "", nil
		}
		logger.WithFields(map[string]interface{}{
			"key":   key,
			"error": err,
		}).Error("Redis GET string failed")
		return "", fmt.Errorf("redis get string failed: %w", err)
	}

	logger.WithField("key", key).Debug("Redis GET string successful")
	return value, nil
}

func (r *RedisOps) GetObject(ctx context.Context, key string, dest interface{}) error {
	if r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}

	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			logger.WithField("key", key).Debug("Redis key not found")
			return nil
		}
		logger.WithFields(map[string]interface{}{
			"key":   key,
			"error": err,
		}).Error("Redis GET object failed")
		return fmt.Errorf("redis get object failed: %w", err)
	}

	if err := json.Unmarshal(data, dest); err != nil {
		logger.WithFields(map[string]interface{}{
			"key":   key,
			"error": err,
		}).Error("Failed to unmarshal Redis value")
		return fmt.Errorf("failed to unmarshal value: %w", err)
	}

	logger.WithField("key", key).Debug("Redis GET object successful")
	return nil
}

func (r *RedisOps) Delete(ctx context.Context, keys ...string) error {
	if r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}

	err := r.client.Del(ctx, keys...).Err()
	if err != nil {
		logger.WithFields(map[string]interface{}{
			"keys":  keys,
			"error": err,
		}).Error("Redis DELETE failed")
		return fmt.Errorf("redis delete failed: %w", err)
	}

	logger.WithField("keys", keys).Debug("Redis DELETE successful")
	return nil
}

func (r *RedisOps) Exists(ctx context.Context, key string) (bool, error) {
	if r.client == nil {
		return false, fmt.Errorf("redis client not initialized")
	}

	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		logger.WithFields(map[string]interface{}{
			"key":   key,
			"error": err,
		}).Error("Redis EXISTS failed")
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
		logger.WithFields(map[string]interface{}{
			"key":        key,
			"expiration": expiration,
			"error":      err,
		}).Error("Redis EXPIRE failed")
		return fmt.Errorf("redis expire failed: %w", err)
	}

	logger.WithFields(map[string]interface{}{
		"key":        key,
		"expiration": expiration,
	}).Debug("Redis EXPIRE successful")
	return nil
}

func (r *RedisOps) TTL(ctx context.Context, key string) (time.Duration, error) {
	if r.client == nil {
		return 0, fmt.Errorf("redis client not initialized")
	}

	ttl, err := r.client.TTL(ctx, key).Result()
	if err != nil {
		logger.WithFields(map[string]interface{}{
			"key":   key,
			"error": err,
		}).Error("Redis TTL failed")
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
		logger.WithFields(map[string]interface{}{
			"key":   key,
			"error": err,
		}).Error("Redis INCR failed")
		return 0, fmt.Errorf("redis incr failed: %w", err)
	}

	logger.WithFields(map[string]interface{}{
		"key":   key,
		"value": value,
	}).Debug("Redis INCR successful")
	return value, nil
}

func (r *RedisOps) IncrBy(ctx context.Context, key string, increment int64) (int64, error) {
	if r.client == nil {
		return 0, fmt.Errorf("redis client not initialized")
	}

	value, err := r.client.IncrBy(ctx, key, increment).Result()
	if err != nil {
		logger.WithFields(map[string]any{
			"key":       key,
			"increment": increment,
			"error":     err,
		}).Error("Redis INCRBY failed")
		return 0, fmt.Errorf("redis incrby failed: %w", err)
	}

	logger.WithFields(map[string]interface{}{
		"key":   key,
		"value": value,
	}).Debug("Redis INCRBY successful")
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
		logger.WithFields(map[string]interface{}{
			"key":   key,
			"field": field,
			"error": err,
		}).Error("Redis HSET failed")
		return fmt.Errorf("redis hset failed: %w", err)
	}

	logger.WithFields(map[string]interface{}{
		"key":   key,
		"field": field,
	}).Debug("Redis HSET successful")
	return nil
}

func (r *RedisOps) HGet(ctx context.Context, key string, field string) ([]byte, error) {
	if r.client == nil {
		return nil, fmt.Errorf("redis client not initialized")
	}

	data, err := r.client.HGet(ctx, key, field).Bytes()
	if err != nil {
		if err == redis.Nil {
			logger.WithFields(map[string]interface{}{
				"key":   key,
				"field": field,
			}).Debug("Redis hash field not found")
			return nil, nil
		}
		logger.WithFields(map[string]interface{}{
			"key":   key,
			"field": field,
			"error": err,
		}).Error("Redis HGET failed")
		return nil, fmt.Errorf("redis hget failed: %w", err)
	}

	logger.WithFields(map[string]interface{}{
		"key":   key,
		"field": field,
	}).Debug("Redis HGET successful")
	return data, nil
}

func (r *RedisOps) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	if r.client == nil {
		return nil, fmt.Errorf("redis client not initialized")
	}

	result, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		logger.WithFields(map[string]interface{}{
			"key":   key,
			"error": err,
		}).Error("Redis HGETALL failed")
		return nil, fmt.Errorf("redis hgetall failed: %w", err)
	}

	logger.WithField("key", key).Debug("Redis HGETALL successful")
	return result, nil
}

func (r *RedisOps) LPush(ctx context.Context, key string, values ...interface{}) error {
	if r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}

	err := r.client.LPush(ctx, key, values...).Err()
	if err != nil {
		logger.WithFields(map[string]interface{}{
			"key":   key,
			"error": err,
		}).Error("Redis LPUSH failed")
		return fmt.Errorf("redis lpush failed: %w", err)
	}

	logger.WithField("key", key).Debug("Redis LPUSH successful")
	return nil
}

func (r *RedisOps) RPop(ctx context.Context, key string) ([]byte, error) {
	if r.client == nil {
		return nil, fmt.Errorf("redis client not initialized")
	}

	data, err := r.client.RPop(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			logger.WithField("key", key).Debug("Redis list is empty")
			return nil, nil
		}
		logger.WithFields(map[string]interface{}{
			"key":   key,
			"error": err,
		}).Error("Redis RPOP failed")
		return nil, fmt.Errorf("redis rpop failed: %w", err)
	}

	logger.WithField("key", key).Debug("Redis RPOP successful")
	return data, nil
}

func (r *RedisOps) LLen(ctx context.Context, key string) (int64, error) {
	if r.client == nil {
		return 0, fmt.Errorf("redis client not initialized")
	}

	length, err := r.client.LLen(ctx, key).Result()
	if err != nil {
		logger.WithFields(map[string]interface{}{
			"key":   key,
			"error": err,
		}).Error("Redis LLEN failed")
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
		logger.WithError(err).Error("Redis FLUSHDB failed")
		return fmt.Errorf("redis flushdb failed: %w", err)
	}

	logger.Warn("Redis database flushed")
	return nil
}
