package cache

import "context"

type Redis struct{}

func (r Redis) Get(ctx context.Context, key string) (string, error) {
	return "", nil
}
func (r Redis) Set(ctx context.Context, key string, value string) error {
	return nil
}
func (r Redis) SetWithTTL(ctx context.Context, key string, value string, ttlSeconds int) error {
	return nil
}
