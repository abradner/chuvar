// Command apiserver runs the REST API behind the approval UI. Separate process
// from cmd/mcpserver (which speaks MCP over stdio to agents) — this one speaks
// HTTP to the frontend, on a normal listening port.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/abradner/chuvar/backend/internal/api"
	"github.com/abradner/chuvar/backend/internal/config"
	"github.com/abradner/chuvar/backend/internal/db"
	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/store"
	"github.com/abradner/chuvar/backend/internal/summarize"
)

func main() {
	if err := run(); err != nil {
		slog.Error("apiserver: fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if err := db.Migrate(cfg.DatabaseURL); err != nil {
		return err
	}

	ctx := context.Background()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	st := store.New(pool)
	if err := bootstrapReviewerToken(ctx, st); err != nil {
		return err
	}

	// CORS_ALLOWED_ORIGIN is optional — the Vite dev server's default port is a
	// reasonable default for local dev, but this is deliberately not baked into
	// config.Config: it's specific to this binary, not shared with cmd/mcpserver.
	allowedOrigin := os.Getenv("CORS_ALLOWED_ORIGIN")
	if allowedOrigin == "" {
		allowedOrigin = "http://localhost:5173"
	}

	// TODO: swap for a real Summarizer once the Research track lands one, same as
	// embed.Stub below.
	a := api.New(st, embed.Stub{}, summarize.Stub{}, allowedOrigin, cfg.RequestTimeout)

	// Read/Write/IdleTimeout and ReadHeaderTimeout all come from cfg.RequestTimeout
	// rather than being left at the zero-value http.Server default (no timeout at
	// all) — an unbounded server is a slowloris/hung-connection risk, and there's
	// no reason to accept that when the config knob for it already existed.
	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           a.Routes(),
		ReadTimeout:       cfg.RequestTimeout,
		WriteTimeout:      cfg.RequestTimeout,
		IdleTimeout:       cfg.RequestTimeout,
		ReadHeaderTimeout: cfg.RequestTimeout,
	}

	slog.Info("apiserver: listening", "addr", cfg.HTTPAddr, "allowedOrigin", allowedOrigin)
	return server.ListenAndServe()
}

// bootstrapReviewerToken ensures there is always at least one way in. Reviewer
// tokens (internal/api's package comment) replaced the old single shared
// API_AUTH_TOKEN, but that created a new startup problem: a fresh install has zero
// tokens in reviewer_tokens, and nothing can create the first one through the API
// itself (every route requires an already-authenticated token). REVIEWER_BOOTSTRAP_TOKEN
// breaks that circularity — same "fail fast on missing required config" stance as
// the old API_AUTH_TOKEN, but scoped to exactly when it's actually needed:
//
//   - No active tokens exist yet (fresh install, or every token got revoked —
//     accidental full lockout is the "break glass" case this also covers): the env
//     var is required, and its value becomes a new token labeled "bootstrap". An
//     unset var here is a boot-time error, the same as the old API_AUTH_TOKEN being
//     unset — a server nobody can ever authenticate to is exactly the "silently
//     starts in a state worse than refusing to start" case that stance exists for.
//   - At least one active token already exists: the var is ignored if present
//     (harmless to leave set for a future lockout) and not required — the org has
//     already worked out its own device-token distribution, so there's no config
//     gap to fail fast on.
func bootstrapReviewerToken(ctx context.Context, st *store.Store) error {
	n, err := st.CountActiveReviewerTokens(ctx)
	if err != nil {
		return fmt.Errorf("apiserver: checking for existing reviewer tokens: %w", err)
	}
	if n > 0 {
		return nil
	}

	bootstrap, ok := os.LookupEnv("REVIEWER_BOOTSTRAP_TOKEN")
	if !ok || bootstrap == "" {
		return fmt.Errorf("apiserver: no reviewer tokens exist and required environment variable REVIEWER_BOOTSTRAP_TOKEN is not set")
	}
	// No TOTP secret for the bootstrap token itself (empty string — see
	// CreateReviewerToken): it's a break-glass way in, not a device meant for
	// ongoing use. Its first job is authenticating a POST /api/tokens call to
	// mint a real, TOTP-enrolled device token; requireTOTP-gated mutations stay
	// unreachable on the bootstrap token alone.
	if _, err := st.CreateReviewerToken(ctx, "bootstrap", bootstrap, ""); err != nil {
		return fmt.Errorf("apiserver: creating bootstrap reviewer token: %w", err)
	}
	slog.Info("apiserver: no reviewer tokens existed; created one from REVIEWER_BOOTSTRAP_TOKEN", "label", "bootstrap")
	return nil
}
