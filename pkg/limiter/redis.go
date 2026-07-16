package limiter

import (
	"context"

	"github.com/go-redis/redis_rate/v10"
	"github.com/pedromol/traefik-crowdsec-bouncer/pkg/config"
	"github.com/redis/go-redis/v9"
)

type Redis struct {
	Client  *redis.ClusterClient
	Limiter *redis_rate.Limiter
	Rate    int
	Bucket  int
}

const keyPreffix = "tcbl:"

func NewRedis(cfg config.Config, client *redis.ClusterClient) Limiter {
	return Redis{
		Client:  client,
		Limiter: redis_rate.NewLimiter(client),
		Rate:    cfg.RateLimit,
		Bucket:  cfg.BucketSize,
	}
}

func (r Redis) Allow(ctx context.Context, key string) bool {
	res, err := r.Limiter.Allow(ctx, keyPreffix+key, redis_rate.PerSecond(r.Rate))
	if err != nil {
		return false
	}

	return res.Allowed > 0
}
