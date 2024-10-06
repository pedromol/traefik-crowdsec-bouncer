package health

import (
	"net/http"

	"github.com/redis/go-redis/v9"
)

type Health struct {
	Client *redis.ClusterClient
}

func NewHealth(client *redis.ClusterClient) *Health {
	return &Health{
		Client: client,
	}
}

func (h *Health) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Client != nil && h.Client.Ping(r.Context()).Err() != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}
