package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

const keyPreffix = "tcbc:"

type Redis struct {
	Client *redis.ClusterClient
}

func NewRedis(client *redis.ClusterClient) Cache {
	return Redis{
		Client: client,
	}
}

func (r Redis) Get(ctx context.Context, key string) (string, error) {
	val := r.Client.Get(ctx, keyPreffix+key)
	if val.Err() != nil {
		if val.Err().Error() == redis.Nil.Error() {
			return "", ErrNotFound
		}
		return "", val.Err()
	}
	return val.Val(), nil
}
func (r Redis) Set(ctx context.Context, key string, value string) error {
	return r.SetWithTTL(ctx, key, value, 0)
}
func (r Redis) SetWithTTL(ctx context.Context, key string, value string, ttlSeconds int) error {
	return r.Client.Set(ctx, keyPreffix+key, value, time.Duration(ttlSeconds)*time.Second).Err()
}
