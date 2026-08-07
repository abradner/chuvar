// Package config loads process configuration from the environment. Required settings
// fail fast on boot rather than silently falling back to a default — see AGENTS.md §6
// (Go conventions). Only genuinely optional tuning knobs get a fallback value.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// DatabaseURL is a postgres:// connection string, required — there's no sane
	// default for "which database," so a missing value is a boot-time error.
	DatabaseURL string

	// HTTPAddr is where the approval-UI REST API listens. Defaults to loopback-only
	// (127.0.0.1) now that the REST API (this PR) actually serves HTTP — it's
	// gated by a required auth token (internal/api's package comment) as the
	// primary control, but binding all interfaces by default on top of that would
	// still be needlessly wide open. Set it explicitly to widen on purpose.
	HTTPAddr string

	// RequestTimeout bounds individual request handling.
	RequestTimeout time.Duration

	// ProposeWriteRateLimit and ProposeWriteRateLimitWindow bound how many
	// propose_write calls a single subject may make per window before
	// bouncer.ProposeWrite starts returning store.ErrRateLimited — the defence
	// against an ungranted (or over-eager) subject flooding the human review
	// queue, which propose_write's own doc comment and the least-privilege-roles
	// migration both call out as the one resource this system cannot scale.
	// Tuning knobs, not required config: there's a safe, generous default
	// (20/minute), unlike DatabaseURL, so a missing or invalid value warns and
	// falls back rather than failing boot.
	ProposeWriteRateLimit       int
	ProposeWriteRateLimitWindow time.Duration
}

// Load reads Config from the environment, returning an error if a required variable
// is missing rather than substituting a default.
func Load() (Config, error) {
	databaseURL, err := requireSecret("DATABASE_URL")
	if err != nil {
		return Config{}, err
	}

	return Config{
		DatabaseURL:                 databaseURL,
		HTTPAddr:                    envOr("HTTP_ADDR", "127.0.0.1:8080"),
		RequestTimeout:              envDurationOr("REQUEST_TIMEOUT", 10*time.Second),
		ProposeWriteRateLimit:       envIntOr("PROPOSE_WRITE_RATE_LIMIT", 20),
		ProposeWriteRateLimitWindow: envDurationOr("PROPOSE_WRITE_RATE_LIMIT_WINDOW", time.Minute),
	}, nil
}

// requireSecret reads a required credential, preferring <KEY>_FILE over <KEY>.
//
// An environment variable is a poor place for a credential: it is readable via
// /proc for anything running as the same user, it is inherited by every child
// process a service spawns, and it turns up in crash dumps and process listings.
// A file read once at boot is narrower on all three counts — and it is how
// systemd (LoadCredential), Docker, and Kubernetes all expect secrets to be
// delivered, so this is the conventional shape rather than a bespoke one.
//
// Both are still supported: <KEY> alone remains fine for local development, and
// removing it would break every existing run for no gain. <KEY>_FILE wins when
// both are set, because a deployment that has bothered to provide a file has
// made the more deliberate choice.
//
// The file's permissions are checked, not assumed: a world-readable secret file
// is worse than an environment variable, since it grants every user on the host
// rather than just the one running the process. Refusing beats silently
// accepting a credential the whole machine can read.
// Secret is requireSecret exported for the cmd/ entrypoints, whose credentials
// (CHUVAR_API_TOKEN, REVIEWER_BOOTSTRAP_TOKEN) are not part of Config but
// deserve the same handling: an environment variable is a poor place for any of
// them, not just the database URL.
func Secret(key string) (string, error) { return requireSecret(key) }

func requireSecret(key string) (string, error) {
	path, ok := os.LookupEnv(key + "_FILE")
	if ok && path != "" {
		return readSecretFile(key+"_FILE", path)
	}
	return requireEnv(key)
}

func readSecretFile(key, path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("config: %s=%s: %w", key, path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("config: %s=%s is not a regular file", key, path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("config: %s=%s has mode %04o; a credential file must not be "+
			"readable or writable by group or other (chmod 600)", key, path, perm)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("config: reading %s=%s: %w", key, path, err)
	}
	// TrimSpace because every editor and `echo` leaves a trailing newline, and a
	// connection string with one appended fails later with a confusing parse
	// error rather than here with a clear one.
	v := strings.TrimSpace(string(raw))
	if v == "" {
		return "", fmt.Errorf("config: %s=%s is empty", key, path)
	}
	return v, nil
}

// ErrNotSet distinguishes "no value was supplied" from "a value was supplied and
// is unusable" — a permissions refusal on a credential file is a very different
// problem from a missing variable, and reporting both as "not set" sends the
// operator looking in the wrong place.
var ErrNotSet = errors.New("no value supplied")

func requireEnv(key string) (string, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return "", fmt.Errorf("config: required environment variable %s is not set (or %s_FILE): %w", key, key, ErrNotSet)
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

func envIntOr(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		// Same stance as envDurationOr: set-but-invalid is a typo worth a warning,
		// not a boot failure. A non-positive value is treated as invalid rather
		// than "unlimited" — a rate limit of 0 or less has no sane interpretation
		// here (store.CheckProposeWriteRateLimit rejects it outright, fail-closed,
		// if it ever got through), so falling back to the default is the safer
		// reading of a config mistake than silently disabling the limit.
		slog.Warn("config: invalid or non-positive integer, using default", "key", key, "value", v, "default", fallback)
		return fallback
	}
	return n
}
