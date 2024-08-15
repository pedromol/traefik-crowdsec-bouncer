package main

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/pedromol/traefik-crowdsec-bouncer/pkg/cache"
	"github.com/pedromol/traefik-crowdsec-bouncer/pkg/config"
	"github.com/pedromol/traefik-crowdsec-bouncer/pkg/forwardAuth"
	"github.com/pedromol/traefik-crowdsec-bouncer/pkg/health"
	"github.com/pedromol/traefik-crowdsec-bouncer/pkg/limiter"
	"github.com/redis/go-redis/v9"
)

func main() {
	cfg := config.NewConfig()

	level := map[string]slog.Level{
		"DEBUG": slog.LevelDebug,
		"INFO":  slog.LevelInfo,
		"WARN":  slog.LevelWarn,
		"ERROR": slog.LevelError,
	}
	lvl, ok := level[cfg.LogLevel]
	if ok {
		slog.SetLogLoggerLevel(lvl)
	}

	h := health.NewHealth()

	var c cache.Cache
	var l limiter.Limiter
	if len(cfg.RedisAddresses) > 0 {
		slog.Debug("Using Redis as cache")
		client := redis.NewFailoverClusterClient(&redis.FailoverOptions{
			MasterName:       cfg.RedisMaster,
			SentinelAddrs:    cfg.RedisAddresses,
			SentinelPassword: cfg.RedisPassword,
			Password:         cfg.RedisPassword,
			RouteRandomly:    true,
		})

		c = cache.NewRedis(client)
		l = limiter.NewRedis(*cfg, client)
	} else {
		c = cache.NewMemory()
		l = limiter.NewLocal(*cfg)
	}

	f := forwardAuth.NewForwardAuth(*cfg, c, l)

	http.Handle("/api/v1/health", h)
	http.Handle("/api/v1/forwardAuth", f)

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	slog.Debug("Starting HTTP server", "addr", server.Addr)
	slog.Error("Failed to start HTTP server", "error", server.ListenAndServe())
}
