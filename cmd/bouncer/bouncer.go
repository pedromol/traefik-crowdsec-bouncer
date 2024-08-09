package main

import (
	"net/http"
	"time"

	"github.com/pedromol/traefik-crowdsec-bouncer/pkg/config"
	"github.com/pedromol/traefik-crowdsec-bouncer/pkg/forwardAuth"
	"github.com/pedromol/traefik-crowdsec-bouncer/pkg/health"
)

func main() {
	cfg := config.NewConfig()
	h := health.NewHealth()
	f := forwardAuth.NewForwardAuth(*cfg)

	http.Handle("/api/v1/health", h)
	http.Handle("/api/v1/forwardAuth", f)

	server := &http.Server{
		Addr:         "0.0.0.0:8080",
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	server.ListenAndServe()
}
