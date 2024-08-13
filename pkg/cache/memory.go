package cache

import (
	"context"
	"strconv"
	"time"
)

type ValTTL struct {
	Value string
	TTL   time.Time
}

type Memory struct {
	Entries map[string]ValTTL
}

func NewMemory() Cache {
	return Memory{
		Entries: map[string]ValTTL{},
	}
}

func (m Memory) Get(_ context.Context, key string) (string, error) {
	val, ok := m.Entries[key]
	if !ok {
		return "", ErrNotFound
	}
	if !val.TTL.IsZero() && time.Now().After(val.TTL) {
		delete(m.Entries, key)
		return "", ErrNotFound
	}
	return val.Value, nil
}

func (m Memory) Set(_ context.Context, key string, value string) error {
	m.Entries[key] = ValTTL{Value: value}
	return nil
}

func (m Memory) SetWithTTL(_ context.Context, key string, value string, ttlSeconds int) error {
	d, err := time.ParseDuration(strconv.Itoa(ttlSeconds) + "s")
	if err != nil {
		return err
	}
	m.Entries[key] = ValTTL{Value: value, TTL: time.Now().Add(d)}
	return nil
}
