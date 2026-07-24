// Package config loads process configuration from the environment. Required settings
// fail fast on boot rather than silently falling back to a default — see AGENTS.md §6
// (Go conventions). Only genuinely optional tuning knobs get a fallback value.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"time"
)

type Config struct {
	// DatabaseURL is a postgres:// connection string, required — there's no sane
	// default for "which database," so a missing value is a boot-time error.
	DatabaseURL string

	// HTTPAddr is where the approval-UI REST API listens. Defaults to all
	// interfaces for now — nothing in this PR actually serves HTTP yet, so there's
	// no live exposure. This gets tightened to a loopback-only default once the
	// REST API (which does have real exposure implications — no auth yet on the
	// endpoint that commits facts) lands.
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
		// This is set-but-invalid, not merely unset — silently falling back here
		// would hide a typo from whoever configured it. Still non-fatal: it's a
		// tuning knob, not required config, so warn rather than fail boot.
		slog.Warn("config: invalid duration, using default", "key", key, "value", v, "default", fallback, "error", err)
		return fallback
	}
	return d
}
