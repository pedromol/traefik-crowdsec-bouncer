package limiter

import (
	"context"
	"sync"

	"github.com/pedromol/traefik-crowdsec-bouncer/pkg/config"
	"golang.org/x/time/rate"
)

type Local struct {
	IPs    map[string]*rate.Limiter
	Mutex  *sync.RWMutex
	Rate   rate.Limit
	Bucket int
}

func NewLocal(cfg config.Config) Limiter {
	return Local{
		IPs:    map[string]*rate.Limiter{},
		Mutex:  &sync.RWMutex{},
		Rate:   rate.Limit(cfg.RateLimit),
		Bucket: cfg.BucketSize,
	}
}

func (l Local) Allow(ctx context.Context, key string) bool {
	limit, ok := l.IPs[key]
	if !ok {
		l.Mutex.Lock()
		defer l.Mutex.Unlock()
		limit = rate.NewLimiter(l.Rate, l.Bucket)
		l.IPs[key] = limit
	}

	return limit.Allow()
}
