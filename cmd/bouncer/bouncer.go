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
)

func main() {
	cfg := config.NewConfig()
	h := health.NewHealth()
	c := cache.NewMemory()
	l := limiter.NewLocal(*cfg)
	f := forwardAuth.NewForwardAuth(*cfg, c, l)

	http.Handle("/api/v1/health", h)
	http.Handle("/api/v1/forwardAuth", f)

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	// slog.SetLogLoggerLevel(slog.LevelDebug)
	slog.Error("Failed to start HTTP server", "error", server.ListenAndServe())
}
