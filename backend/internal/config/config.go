// Package config loads process configuration from the environment. Required settings
// fail fast on boot rather than silently falling back to a default — see AGENTS.md §6
// (Go conventions). Only genuinely optional tuning knobs get a fallback value.
package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	// DatabaseURL is a postgres:// connection string, required — there's no sane
	// default for "which database," so a missing value is a boot-time error.
	DatabaseURL string

	// HTTPAddr is where the approval-UI REST API listens.
	HTTPAddr string

	// RequestTimeout bounds individual request handling.
	RequestTimeout time.Duration
}

// Load reads Config from the environment, returning an error if a required variable
// is missing rather than substituting a default.
func Load() (Config, error) {
	databaseURL, err := requireEnv("DATABASE_URL")
	if err != nil {
		return Config{}, err
	}

	return Config{
		DatabaseURL:    databaseURL,
		HTTPAddr:       envOr("HTTP_ADDR", ":8080"),
		RequestTimeout: envDurationOr("REQUEST_TIMEOUT", 10*time.Second),
	}, nil
}

func requireEnv(key string) (string, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return "", fmt.Errorf("config: required environment variable %s is not set", key)
	}
	return v, nil
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envDurationOr(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
