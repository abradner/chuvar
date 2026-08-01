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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abradner/chuvar/backend/internal/api"
	"github.com/abradner/chuvar/backend/internal/config"
	"github.com/abradner/chuvar/backend/internal/custody"
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

	st, err := openSealedStore(ctx, pool)
	if err != nil {
		return err
	}
	if err := bootstrapReviewerToken(ctx, st); err != nil {
		return err
	}
	if err := warnIfNoEnrolledDevice(ctx, st); err != nil {
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

// openSealedStore unseals the master key, resolves the secrets DEK, and returns
// a Store that can read and write sealed columns.
//
// Note which binary this lives in. apiserver is the only process that verifies
// TOTP codes, so it is the only one that needs the master key — cmd/mcpserver,
// the process an agent host spawns, never receives it. That asymmetry is the
// point of sealing the column: a process holding DATABASE_URL and nothing else
// reads ciphertext (2026-08-01 trust-boundary decision, Notion).
//
// CHUVAR_CUSTODY_KEY_FILE overrides the key's location; CHUVAR_CUSTODY_CREATE=1
// permits minting one when none exists. Creation is opt-in because a fresh key
// silently replaces the old one and orphans every secret sealed under it —
// an operator restoring a backup should hit an error, not a working server with
// unopenable enrollments.
func openSealedStore(ctx context.Context, pool *pgxpool.Pool) (*store.Store, error) {
	backend := &custody.FileBackend{
		Path:        os.Getenv("CHUVAR_CUSTODY_KEY_FILE"),
		AllowCreate: os.Getenv("CHUVAR_CUSTODY_CREATE") == "1",
	}

	raw, err := backend.Unseal(ctx)
	if err != nil {
		return nil, fmt.Errorf("apiserver: unsealing the master key: %w "+
			"(set CHUVAR_CUSTODY_CREATE=1 on a first run to mint one)", err)
	}
	master, err := custody.NewKey(raw)
	if err != nil {
		return nil, fmt.Errorf("apiserver: master key: %w", err)
	}

	dek, err := store.New(pool).LoadOrCreateDataKey(ctx, master, store.DataKeyPurposeSecrets)
	if err != nil {
		return nil, fmt.Errorf("apiserver: %w", err)
	}

	slog.Info("apiserver: secrets sealed at rest", "custody_backend", backend.Name(), "sealed_at_rest", backend.Sealed())
	return store.NewSealed(pool, dek), nil
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

// warnIfNoEnrolledDevice logs a prominent warning when no device has ever
// enrolled a TOTP secret, because that is the one state in which
// POST /api/tokens accepts a bearer token alone (see internal/api's
// createToken): with nothing to prove possession against, the enrollment gate
// cannot be closed without making the system unbootstrappable.
//
// This is not just the fresh-install case. Every deployment that predates the
// reviewer_totp migration lands here too: the migration adds totp_secret as a
// nullable column with no backfill, so existing tokens are all unenrolled, and
// nothing forces the operator to notice. Until they mint one enrolled device,
// anything holding a bearer token can mint another and enroll it — exactly the
// escalation the gate exists to stop. There is no UI for this yet; it is a
// deliberate operator action (see README.md's "Enrolling the first device").
//
// A warning rather than a hard failure: refusing to start would break every
// existing deployment on upgrade, turning a security gap into an outage.
func warnIfNoEnrolledDevice(ctx context.Context, st *store.Store) error {
	n, err := st.CountEverEnrolledReviewerTokens(ctx)
	if err != nil {
		return fmt.Errorf("apiserver: checking for enrolled reviewer tokens: %w", err)
	}
	if n > 0 {
		return nil
	}
	slog.Warn("apiserver: SECURITY — no reviewer device has enrolled a TOTP secret, " +
		"so POST /api/tokens currently accepts a bearer token alone and anything holding " +
		"that token can mint and enroll its own device. Enrol one now: POST /api/tokens " +
		"and scan the returned otpauth:// URI. See README.md.")
	return nil
}
