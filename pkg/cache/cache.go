package cache

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("cache miss")

type Cache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string) error
	SetWithTTL(ctx context.Context, key string, value string, ttlSeconds int) error
}
