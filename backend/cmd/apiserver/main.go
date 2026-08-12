// Command apiserver runs the REST API behind the approval UI. Separate process
// from cmd/mcpserver (which speaks MCP over stdio to agents) — this one speaks
// HTTP to the frontend, on a normal listening port.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/abradner/chuvar/backend/internal/api"
	"github.com/abradner/chuvar/backend/internal/bouncer"
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

	ctx := context.Background()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	// Verifies the schema; does not change it. apiserver used to migrate on
	// boot, which was defensible when it ran as the database owner — but a
	// runtime service holding DDL is exactly what the least-privilege roles
	// (E8) remove, and chuvar_app has no DDL to migrate with. Completing the
	// split started in E2 leaves exactly one binary that migrates: cmd/migrate.
	//
	// The cost is one extra command on a fresh database. The gain is that
	// "who may change the schema" has a single answer instead of two.
	if err := db.CheckSchema(ctx, pool); err != nil {
		return err
	}
	db.WarnIfOverprivileged(ctx, pool, "apiserver")

	st, err := openSealedStore(ctx, pool)
	if err != nil {
		return err
	}
	if err := bootstrapReviewerToken(ctx, st); err != nil {
		return err
	}
	if _, err := warnIfNoEnrolledDevice(ctx, st); err != nil {
		return err
	}

	// CORS_ALLOWED_ORIGIN is optional — the Vite dev server's default port is a
	// reasonable default for local dev, but this is deliberately not baked into
	// config.Config: it's specific to this binary, not shared with cmd/mcpserver.
	allowedOrigin := os.Getenv("CORS_ALLOWED_ORIGIN")
	if allowedOrigin == "" {
		allowedOrigin = "http://localhost:5173"
	}

	wa, err := newWebAuthn(allowedOrigin)
	if err != nil {
		return err
	}

	// TODO: swap for a real Summarizer once the Research track lands one, same as
	// embed.Stub below.
	emb := embed.Stub{}

	// bouncer.New's classify -> embed -> dedupe -> stage pipeline backs
	// POST /api/agent/proposals (internal/api/agent_routes.go) exactly as it
	// backs the propose_write MCP tool in cmd/mcpserver/main.go — constructed
	// identically (same stub Embedder, same PassthroughClassifier, same
	// config-driven rate limit) so the two callers can never silently
	// diverge in how a proposal gets classified, embedded, or rate-limited.
	b := bouncer.New(st, emb, bouncer.PassthroughClassifier{})
	b.RateLimit = cfg.ProposeWriteRateLimit
	b.RateLimitWindow = cfg.ProposeWriteRateLimitWindow

	a := api.New(st, emb, summarize.Stub{}, allowedOrigin, cfg.RequestTimeout, wa, b)

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

	// CHUVAR_AGENT_ADDR is a second, entirely separate listener carrying only
	// AgentRoutes() (internal/api/agent_routes.go) — the agent-authenticated
	// HTTP surface a later PR points mcpserver at instead of a raw database
	// credential (AGENTS.md §3.6, ticket E3). This is deliberately not
	// cfg.HTTPAddr: an agent process holding nothing but its own agent token
	// must not be able to reach the reviewer routes even at the network
	// layer, on top of requireAgentAuth already rejecting a reviewer token
	// that tried and requireAuth already rejecting an agent token that tried
	// the other way. Not part of config.Config for the same reason
	// CORS_ALLOWED_ORIGIN above isn't: specific to this binary, not shared
	// with cmd/mcpserver. Defaults to loopback-only, same reasoning as
	// HTTP_ADDR's own default (config.Load's doc comment).
	agentAddr := os.Getenv("CHUVAR_AGENT_ADDR")
	if agentAddr == "" {
		agentAddr = "127.0.0.1:8081"
	}
	agentServer := &http.Server{
		Addr:              agentAddr,
		Handler:           a.AgentRoutes(),
		ReadTimeout:       cfg.RequestTimeout,
		WriteTimeout:      cfg.RequestTimeout,
		IdleTimeout:       cfg.RequestTimeout,
		ReadHeaderTimeout: cfg.RequestTimeout,
	}

	return runServers(cfg.RequestTimeout, allowedOrigin, server, agentServer)
}

// runServers runs the reviewer and agent listeners concurrently and blocks
// until either one exits. Neither listener is allowed to keep running
// unsupervised once the other has stopped (whether from a real error or an
// operator-triggered Shutdown) — an agent listener silently outliving a dead
// reviewer listener, or vice versa, is exactly the kind of half-up state
// that should be an outage, not a partially-working server (CLAUDE.md
// principle 5, fail closed, loudly).
func runServers(requestTimeout time.Duration, allowedOrigin string, server, agentServer *http.Server) error {
	errCh := make(chan error, 2)
	go func() {
		slog.Info("apiserver: listening (reviewer)", "addr", server.Addr, "allowedOrigin", allowedOrigin)
		errCh <- fmt.Errorf("reviewer listener: %w", server.ListenAndServe())
	}()
	go func() {
		slog.Info("apiserver: listening (agent)", "addr", agentServer.Addr)
		errCh <- fmt.Errorf("agent listener: %w", agentServer.ListenAndServe())
	}()

	firstErr := <-errCh

	shutdownCtx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	// Best-effort: whichever listener didn't fail gets a clean shutdown: we've
	// already decided the process is exiting, so its own shutdown error (if
	// any) doesn't change that outcome and isn't worth masking firstErr for.
	_ = server.Shutdown(shutdownCtx)
	_ = agentServer.Shutdown(shutdownCtx)

	if errors.Is(firstErr, http.ErrServerClosed) {
		return nil
	}
	return firstErr
}

// newWebAuthn builds the Relying Party configuration every WebAuthn
// (passkey) ceremony validates against — strict RP ID and origin checking is
// the whole security property (internal/api/webauthn.go's package comment),
// so this is deliberately derived from the same allowedOrigin CORS already
// trusts rather than a second, independently-configured origin:
// AGENTS.md's one-chokepoint principle — "which origin is real" should have
// one answer that can't silently drift from CORS_ALLOWED_ORIGIN, not two.
// The dev default (allowedOrigin's own default above) is
// http://localhost:5173, a loopback origin — matching how the frontend is
// actually served in development (Vite's dev server on localhost) — so RP ID
// defaults to "localhost", the conventional WebAuthn RP ID for local dev
// (browsers treat http://localhost as a secure context specifically to make
// this work without TLS).
//
// WEBAUTHN_RP_ID overrides the derived value for deployments where the
// public origin's hostname isn't the right RP ID (e.g. a path-based reverse
// proxy) — same override-with-a-derived-default shape as CORS_ALLOWED_ORIGIN
// itself. webauthn.New validates the resulting config eagerly (fails boot on
// a missing RP ID or origin), matching this package's fail-fast-on-missing-
// config stance rather than deferring the failure to the first ceremony.
func newWebAuthn(allowedOrigin string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(allowedOrigin)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("apiserver: could not derive a WebAuthn RP ID from origin %q: %w", allowedOrigin, err)
	}
	rpID := os.Getenv("WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = u.Hostname()
	}
	rpDisplayName := os.Getenv("WEBAUTHN_RP_DISPLAY_NAME")
	if rpDisplayName == "" {
		rpDisplayName = "Chuvar"
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     []string{allowedOrigin},
		// Required, not preferred: this factor stands in for a TOTP code
		// (requireStrongFactor accepts either), so it must carry the same
		// "the human just proved presence right now" weight — a bare
		// user-presence touch with no biometric/PIN would be a weaker
		// factor than the code it's an alternative to.
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("apiserver: configuring webauthn: %w", err)
	}
	return wa, nil
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

	// config.Secret so REVIEWER_BOOTSTRAP_TOKEN_FILE works here too. Only an
	// absent value is the "you must configure this" case; a file that exists but
	// is unreadable or group-readable is a different problem and says so.
	bootstrap, err := config.Secret("REVIEWER_BOOTSTRAP_TOKEN")
	if errors.Is(err, config.ErrNotSet) {
		return fmt.Errorf("apiserver: no reviewer tokens exist and REVIEWER_BOOTSTRAP_TOKEN (or REVIEWER_BOOTSTRAP_TOKEN_FILE) is not set")
	}
	if err != nil {
		return fmt.Errorf("apiserver: reading REVIEWER_BOOTSTRAP_TOKEN: %w", err)
	}
	// No TOTP secret for the bootstrap token itself (empty string — see
	// CreateReviewerToken): it's a break-glass way in, not a device meant for
	// ongoing use. Its first job is authenticating a POST /api/tokens call to
	// mint a real, TOTP-enrolled device token; requireStrongFactor-gated
	// mutations stay unreachable on the bootstrap token alone — including via
	// WebAuthn, because passkey registration (requireExistingSecondFactor,
	// internal/api) refuses any token with no enrolled factor, so the
	// bootstrap token can never mint itself the passkey that would otherwise
	// pass those gates.
	if _, err := st.CreateReviewerToken(ctx, "bootstrap", bootstrap, ""); err != nil {
		return fmt.Errorf("apiserver: creating bootstrap reviewer token: %w", err)
	}
	slog.Info("apiserver: no reviewer tokens existed; created one from REVIEWER_BOOTSTRAP_TOKEN", "label", "bootstrap")
	return nil
}

// warnIfNoEnrolledDevice logs a prominent warning when POST /api/tokens
// currently accepts a bearer token alone — i.e. when createToken's actual
// gate (internal/api/tokens.go: "latched || everEnrolledTOTP+everEnrolledWebAuthn
// > 0") would let it through unguarded. That gate ORs three signals together,
// so this warning must consult all three to stay true, not just the two live
// counts: with nothing to prove possession against, the enrollment gate
// cannot be closed without making the system unbootstrappable, but the
// durable latch (EnrollmentLatchSet) can hold the gate shut even when both
// counts have just been reset to zero.
//
// Checking only the counts (as an earlier version of this function did) was
// itself a principle-8 violation once the documented break-glass recovery
// (docs/operations.md) existed: Step 1 of that procedure deliberately clears
// every factor row while leaving the latch set, precisely so the gate stays
// closed across the reset — but a counts-only warning would fire right after
// Step 1, claiming "POST /api/tokens currently accepts a bearer token alone"
// when createToken would in fact still refuse it (latched == true), AND tell
// the operator to "enrol one now" via a call that cannot succeed without a
// factor to prove — Step 2 (resetting the latch) hasn't happened yet, deliberately.
// A security warning that's both false and gives an instruction that cannot
// be carried out is worse than silence: it teaches the operator to distrust
// (or worse, "fix" by resetting the latch early) the one warning meant to
// catch the real gap.
//
// This is not just the fresh-install / break-glass case. Every deployment
// that predates the reviewer_totp migration lands here too: it adds the
// secret column as a nullable column with no backfill, so existing tokens are
// all unenrolled, and nothing forces the operator to notice. Until they mint
// one enrolled device, anything holding a bearer token can mint another and
// enroll it — exactly the escalation the gate exists to stop. There is no UI
// for this yet; it is a deliberate operator action (see README.md's
// "Enrolling the first device").
//
// A warning rather than a hard failure: refusing to start would break every
// existing deployment on upgrade, turning a security gap into an outage.
//
// Returns whether it warned, purely so tests can assert the actual branch
// taken instead of only "did this return an error" — every path here returns
// a nil error regardless (see above), so an error-only check would exercise
// none of this function's real conditional logic (AGENTS.md §6, "every
// conditional branch that encodes real logic gets a test that exercises
// it"). Not consumed by run(); callers that only care about a real failure
// (a broken DB connection) can keep discarding it.
func warnIfNoEnrolledDevice(ctx context.Context, st *store.Store) (warned bool, err error) {
	totpCount, err := st.CountEverEnrolledReviewerTokens(ctx)
	if err != nil {
		return false, fmt.Errorf("apiserver: checking for enrolled reviewer tokens: %w", err)
	}
	webauthnCount, err := st.CountEverEnrolledWebAuthnCredentials(ctx)
	if err != nil {
		return false, fmt.Errorf("apiserver: checking for enrolled webauthn credentials: %w", err)
	}
	latched, err := st.EnrollmentLatchSet(ctx)
	if err != nil {
		return false, fmt.Errorf("apiserver: checking the durable enrollment latch: %w", err)
	}
	if latched || totpCount+webauthnCount > 0 {
		return false, nil
	}
	slog.Warn("apiserver: SECURITY — no reviewer device has enrolled a second factor (TOTP or passkey), " +
		"so POST /api/tokens currently accepts a bearer token alone and anything holding " +
		"that token can mint and enroll its own device. Enrol one now: POST /api/tokens " +
		"and scan the returned otpauth:// URI. See README.md.")
	return true, nil
}
