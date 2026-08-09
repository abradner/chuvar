// Command brokerd is the Agent Capability Broker (issues #95, #79):
// preflight and payload-constrained git commit signing over capability
// grants, per docs/capability-broker.md's confirmed architecture. It never
// migrates, never holds DDL authority, and never touches facts/staged_diffs
// — see internal/broker's package doc and §3.6 of AGENTS.md, which this
// binary adds a row to.
//
// No capability-grant CREATION surface exists here or anywhere yet — that
// is issue #96, deliberately out of scope. Grants are provisioned by
// inserting rows directly today (tests do this; there is no other way to
// create one), which is why this binary's job is enforcement over rows that
// already exist, not minting them.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/abradner/chuvar/backend/internal/broker"
	"github.com/abradner/chuvar/backend/internal/broker/keyring"
	"github.com/abradner/chuvar/backend/internal/config"
	"github.com/abradner/chuvar/backend/internal/custody"
	"github.com/abradner/chuvar/backend/internal/db"
)

func main() {
	if err := run(); err != nil {
		slog.Error("brokerd: fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	// PR_SET_DUMPABLE(0) first, before anything touches key material — the
	// #74 custody spike's finding, restated in internal/broker/keyring's
	// package doc: no library in that evaluation sets this, and it must be
	// process-wide and set once, early, rather than per-buffer. This blocks
	// same-uid `ptrace`/`/proc/<pid>/{mem,environ,exe}` reads of this
	// process from the moment it takes effect — before that moment, this
	// process is exactly as exposed as any other, so "early" is load-bearing,
	// not stylistic.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("brokerd: PR_SET_DUMPABLE(0): %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	// Verifies the schema; does not change it — brokerd never migrates,
	// same posture as mcpserver (AGENTS.md §3.6) and for the same reason:
	// a runtime service asserting DDL authority on every boot is ambient
	// authority this binary specifically must not hold, given what else it
	// holds (decrypted signing key material).
	if err := db.CheckSchema(ctx, pool); err != nil {
		return err
	}
	db.WarnIfOverprivileged(ctx, pool, "brokerd")

	key, err := loadSigningKey(ctx)
	if err != nil {
		return err
	}
	defer key.Destroy()

	cache := broker.NewCache(pool)
	if err := cache.Load(ctx); err != nil {
		// Fatal, deliberately: an unloaded cache would silently serve
		// NO_GRANT to every request forever, which is fail-*open* in
		// effect (a broker nobody can use looks identical, from outside,
		// to one correctly denying everyone) — see NewCache's doc comment.
		// Failing to boot is the legible version of the same outcome.
		return fmt.Errorf("brokerd: initial grant cache load failed: %w", err)
	}
	go cache.Watch(ctx, reconcileInterval())

	b := broker.New(pool, cache, key, signRateLimit(), signRateWindow())

	socketPath := socketPath()
	ln, err := broker.Listen(socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()

	slog.Info("brokerd: listening", "socket", socketPath)
	broker.Serve(ctx, ln, b.Handle)
	slog.Info("brokerd: shutting down")
	return nil
}

// loadSigningKey unseals brokerd's one, process-lifetime git-signing key —
// see internal/broker/keyring's package doc, "Scope, honestly stated", for
// exactly what this does and does not claim about per-grant custody.
//
// Deliberately its own env vars (CHUVAR_BROKER_SIGNING_KEY_FILE /
// CHUVAR_BROKER_SIGNING_KEY_CREATE), not shared with apiserver's
// CHUVAR_CUSTODY_KEY_FILE / CHUVAR_CUSTODY_CREATE — same reasoning as
// apiserver's CORS_ALLOWED_ORIGIN comment: specific to this binary. Sharing
// the vault master key file with the signing key would also be a category
// error: they wrap different things (the master key wraps a DEK for
// sealed *columns*; this key signs *commits*), and "one mechanism, not two"
// (the 2026-08-01 decision this reuses) means one *kind* of custody backend
// (human-present unlock, pluggable storage), not one *key* for every
// purpose.
func loadSigningKey(ctx context.Context) (*keyring.SigningKey, error) {
	backend := &custody.FileBackend{
		Path:        os.Getenv("CHUVAR_BROKER_SIGNING_KEY_FILE"),
		AllowCreate: os.Getenv("CHUVAR_BROKER_SIGNING_KEY_CREATE") == "1",
	}
	// custody.FileBackend.Path empty means DefaultKeyPath, which is
	// ~/.local/state/chuvar/master.key — the wrong file for this binary.
	// Point it at a sibling path instead when the operator hasn't set one
	// explicitly.
	if backend.Path == "" {
		p, err := defaultSigningKeyPath()
		if err != nil {
			return nil, fmt.Errorf("brokerd: %w", err)
		}
		backend.Path = p
	}

	raw, err := backend.Unseal(ctx)
	if err != nil {
		return nil, fmt.Errorf("brokerd: unsealing the signing key: %w "+
			"(set CHUVAR_BROKER_SIGNING_KEY_CREATE=1 on a first run to mint one)", err)
	}
	key, err := keyring.Load(raw)
	if err != nil {
		return nil, fmt.Errorf("brokerd: loading signing key into guarded memory: %w", err)
	}
	slog.Info("brokerd: signing key loaded", "custody_backend", backend.Name(), "sealed_at_rest", backend.Sealed())
	return key, nil
}

// defaultSigningKeyPath mirrors custody.DefaultKeyPath's XDG_STATE_HOME
// convention (not reused directly — that function is hardcoded to
// "master.key", and this needs a different filename in the same
// directory).
func defaultSigningKeyPath() (string, error) {
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		return filepath.Join(dir, "chuvar", "broker-signing.key"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory: %w", err)
	}
	return filepath.Join(home, ".local", "state", "chuvar", "broker-signing.key"), nil
}

// socketPath honours BROKERD_SOCKET_PATH, then XDG_RUNTIME_DIR (the
// conventional, already-0700, tmpfs-backed location systemd sets up per
// login session — exactly the "restrictive dir+socket perms" posture
// broker.Listen also enforces itself, belt and braces), then falls back to
// the same XDG_STATE_HOME convention as the signing key.
func socketPath() string {
	if p := os.Getenv("BROKERD_SOCKET_PATH"); p != "" {
		return p
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "chuvar", "brokerd.sock")
	}
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		return filepath.Join(dir, "chuvar", "brokerd.sock")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// No sane fallback left — os.UserHomeDir failing here means the
		// process has no usable home directory at all, which every other
		// path above would also need. broker.Listen will surface a clear
		// error when it tries to create this directory; returning a
		// relative path here at least means it fails visibly rather than
		// on an empty string.
		return "chuvar-brokerd.sock"
	}
	return filepath.Join(home, ".local", "state", "chuvar", "brokerd.sock")
}

// reconcileInterval is Cache.Watch's periodic full-reload fallback period —
// see Watch's doc comment for why this exists alongside LISTEN/NOTIFY.
// BROKERD_RECONCILE_INTERVAL overrides it (Go duration syntax, e.g. "10s").
func reconcileInterval() time.Duration {
	return envDurationOr("BROKERD_RECONCILE_INTERVAL", 30*time.Second)
}

// signRateLimit and signRateWindow configure the per-grant sign-rate
// tripwire (ratelimit.go) — capability-broker.md's open question 5, "TTL is
// the control, count is an anomaly tripwire." Defaults are deliberately
// generous for personal/small-org scale (the doc's own framing: "a dozen
// over a night is normal"), not tuned to any specific deployment.
func signRateLimit() int {
	return envIntOr("BROKERD_SIGN_RATE_LIMIT", 30)
}

func signRateWindow() time.Duration {
	return envDurationOr("BROKERD_SIGN_RATE_LIMIT_WINDOW", time.Minute)
}

// envDurationOr and envIntOr are local, minimal re-implementations of
// internal/config's unexported helpers of the same shape (envDurationOr,
// envIntOr) — not reused because they're unexported (config's own doc
// comment on Secret: tuning knobs specific to one binary don't belong in
// the shared Config struct, the same reasoning apiserver's
// CORS_ALLOWED_ORIGIN comment gives for handling its own env vars locally).
func envDurationOr(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		slog.Warn("brokerd: invalid or non-positive duration, using default", "key", key, "value", v, "default", fallback)
		return fallback
	}
	return d
}

func envIntOr(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		slog.Warn("brokerd: invalid or non-positive integer, using default", "key", key, "value", v, "default", fallback)
		return fallback
	}
	return n
}
