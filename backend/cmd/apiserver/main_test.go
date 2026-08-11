package main

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abradner/chuvar/backend/internal/custody"
	"github.com/abradner/chuvar/backend/internal/db"
	"github.com/abradner/chuvar/backend/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping apiserver integration tests")
	}
	if err := db.Migrate(url); err != nil {
		t.Fatalf("db.Migrate() error = %v", err)
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatalf("db.Open() error = %v", err)
	}
	t.Cleanup(pool.Close)
	// enrollment_latch is included alongside the factor tables: several tests
	// in this file (TestWarnIfNoEnrolledDevice_*) depend on its exact state,
	// and the latch is never truncated automatically by the schema (it's
	// meant to survive a factor reset — see the enrollment_latch migration),
	// so a prior test's enrollment would otherwise leak into this one via a
	// row TRUNCATE never used to touch.
	if _, err := pool.Exec(ctx, `TRUNCATE reviewer_tokens, webauthn_credentials, webauthn_challenges, data_keys, enrollment_latch`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}
	return testSealedStore(t, pool)
}

// clearAllFactors runs the documented break-glass recovery's factor-clearing
// step (docs/operations.md) directly against a scratch connection: null every
// TOTP secret and delete every passkey — the same technique
// store/enrollment_latch_test.go's clearAllFactors uses, reimplemented here
// since testStore (above) only returns the *store.Store, not its pool.
func clearAllFactors(t *testing.T, ctx context.Context) {
	t.Helper()
	pool, err := db.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db.Open() error = %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `UPDATE reviewer_tokens SET totp_secret_enc = NULL`); err != nil {
		t.Fatalf("clearing totp secrets: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM webauthn_credentials`); err != nil {
		t.Fatalf("deleting webauthn credentials: %v", err)
	}
}

func TestWarnIfNoEnrolledDevice_SucceedsInBothStates(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Zero enrolled, latch unset: this is the one state createToken actually
	// accepts a bearer token alone in, so the warning must fire. Never fails
	// boot either way — refusing to start would break every pre-TOTP-migration
	// deployment on upgrade, turning a security gap into an outage.
	warned, err := warnIfNoEnrolledDevice(ctx, st)
	if err != nil {
		t.Fatalf("warnIfNoEnrolledDevice() with no enrolled device: error = %v, want nil (warn, don't fail boot)", err)
	}
	if !warned {
		t.Error("warnIfNoEnrolledDevice() with no enrolled device and no latch = false, want true (this is exactly the state createToken accepts a bearer token alone in)")
	}

	if _, err := st.CreateReviewerToken(ctx, "device-a", "plaintext-a", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	warned, err = warnIfNoEnrolledDevice(ctx, st)
	if err != nil {
		t.Fatalf("warnIfNoEnrolledDevice() with an enrolled device: error = %v, want nil", err)
	}
	if warned {
		t.Error("warnIfNoEnrolledDevice() with an enrolled device (nonzero count) = true, want false")
	}
}

// TestWarnIfNoEnrolledDevice_ConsultsTheDurableLatch is the P2 regression
// test: an earlier version of this function checked only the two live
// ever-enrolled counts, never the durable latch createToken's real gate also
// ORs in. That made the warning both factually wrong and actively misleading
// in exactly the state the documented break-glass recovery leaves behind
// after its Step 1 (docs/operations.md): every factor row cleared (both
// counts zero) but the latch deliberately still set, pending the operator's
// separate Step 2. In that state createToken still refuses a factorless
// bearer token — the count-only warning would nonetheless have logged
// "POST /api/tokens currently accepts a bearer token alone" (false) and told
// the operator to "enrol one now" via a call that cannot succeed without a
// factor to prove (also false, since Step 2 hasn't run).
func TestWarnIfNoEnrolledDevice_ConsultsTheDurableLatch(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Enroll a device (sets the latch), then simulate break-glass recovery's
	// Step 1 only — clear the factor rows directly, the same technique
	// store/enrollment_latch_test.go's clearAllFactors uses, and deliberately
	// do NOT reset the latch (that's the separate, hand-run Step 2).
	if _, err := st.CreateReviewerToken(ctx, "device-a", "plaintext-a", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	clearAllFactors(t, ctx)

	latched, err := st.EnrollmentLatchSet(ctx)
	if err != nil {
		t.Fatalf("EnrollmentLatchSet() error = %v", err)
	}
	if !latched {
		t.Fatal("latch should still be set after clearing factor rows alone (Step 1 without Step 2)")
	}

	warned, err := warnIfNoEnrolledDevice(ctx, st)
	if err != nil {
		t.Fatalf("warnIfNoEnrolledDevice() error = %v", err)
	}
	if warned {
		t.Error("warnIfNoEnrolledDevice() with both counts zero but the latch still set = true, want false " +
			"(createToken still refuses a factorless bearer token here — warning would be both false and misleading)")
	}
}

func TestBootstrapReviewerToken_CreatesFirstTokenWhenNoneExist(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	t.Setenv("REVIEWER_BOOTSTRAP_TOKEN", "test-bootstrap-value")
	if err := bootstrapReviewerToken(ctx, st); err != nil {
		t.Fatalf("bootstrapReviewerToken() error = %v", err)
	}

	reviewer, ok, err := st.AuthenticateReviewerToken(ctx, "test-bootstrap-value")
	if err != nil {
		t.Fatalf("AuthenticateReviewerToken() error = %v", err)
	}
	if !ok || reviewer.Label != "bootstrap" {
		t.Fatalf("AuthenticateReviewerToken() = (%q, %v), want (bootstrap, true)", reviewer.Label, ok)
	}
}

func TestBootstrapReviewerToken_MissingEnvVarIsBootError(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	os.Unsetenv("REVIEWER_BOOTSTRAP_TOKEN")
	if err := bootstrapReviewerToken(ctx, st); err == nil {
		t.Fatal("bootstrapReviewerToken() with no REVIEWER_BOOTSTRAP_TOKEN and no existing tokens: want an error, got nil")
	}
}

func TestBootstrapReviewerToken_SkipsWhenActiveTokenExists(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if _, err := st.CreateReviewerToken(ctx, "already-here", "some-other-value", ""); err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}

	os.Unsetenv("REVIEWER_BOOTSTRAP_TOKEN") // must not be required once a token exists
	if err := bootstrapReviewerToken(ctx, st); err != nil {
		t.Fatalf("bootstrapReviewerToken() with an existing active token error = %v, want nil (env var not required)", err)
	}
}

// TestBootstrapReviewerToken_ReusableAfterFullRevocation is the regression
// test for the review finding (Codex P1): the documented break-glass
// recovery path — restart with the same REVIEWER_BOOTSTRAP_TOKEN after every
// token got revoked — used to fail on the revoked row's still-live global
// UNIQUE(token_hash) constraint. It must now succeed.
func TestBootstrapReviewerToken_ReusableAfterFullRevocation(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	t.Setenv("REVIEWER_BOOTSTRAP_TOKEN", "break-glass-value")
	if err := bootstrapReviewerToken(ctx, st); err != nil {
		t.Fatalf("initial bootstrapReviewerToken() error = %v", err)
	}

	tokens, err := st.ListReviewerTokens(ctx)
	if err != nil {
		t.Fatalf("ListReviewerTokens() error = %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("ListReviewerTokens() = %d tokens, want 1", len(tokens))
	}
	if err := st.RevokeReviewerToken(ctx, tokens[0].ID); err != nil {
		t.Fatalf("RevokeReviewerToken() error = %v", err)
	}

	// Simulate a restart with the exact same env var value, per the doc
	// comment's documented recovery flow.
	if err := bootstrapReviewerToken(ctx, st); err != nil {
		t.Fatalf("bootstrapReviewerToken() after full revocation, same token value: error = %v, want nil (break-glass recovery must work)", err)
	}

	reviewer, ok, err := st.AuthenticateReviewerToken(ctx, "break-glass-value")
	if err != nil {
		t.Fatalf("AuthenticateReviewerToken() error = %v", err)
	}
	if !ok || reviewer.Label != "bootstrap" {
		t.Fatalf("AuthenticateReviewerToken() after re-bootstrap = (%q, %v), want (bootstrap, true)", reviewer.Label, ok)
	}
}

func TestNewWebAuthn_DerivesRPIDFromOrigin(t *testing.T) {
	os.Unsetenv("WEBAUTHN_RP_ID")
	os.Unsetenv("WEBAUTHN_RP_DISPLAY_NAME")

	wa, err := newWebAuthn("http://localhost:5173")
	if err != nil {
		t.Fatalf("newWebAuthn() error = %v", err)
	}
	if wa.Config.RPID != "localhost" {
		t.Errorf("RPID = %q, want %q", wa.Config.RPID, "localhost")
	}
	if len(wa.Config.RPOrigins) != 1 || wa.Config.RPOrigins[0] != "http://localhost:5173" {
		t.Errorf("RPOrigins = %v, want [http://localhost:5173]", wa.Config.RPOrigins)
	}
	if wa.Config.RPDisplayName != "Chuvar" {
		t.Errorf("RPDisplayName = %q, want the default %q", wa.Config.RPDisplayName, "Chuvar")
	}
}

func TestNewWebAuthn_EnvOverridesTakePriority(t *testing.T) {
	t.Setenv("WEBAUTHN_RP_ID", "chuvar.example.com")
	t.Setenv("WEBAUTHN_RP_DISPLAY_NAME", "Custom Deployment")

	wa, err := newWebAuthn("https://app.example.com")
	if err != nil {
		t.Fatalf("newWebAuthn() error = %v", err)
	}
	if wa.Config.RPID != "chuvar.example.com" {
		t.Errorf("RPID = %q, want the WEBAUTHN_RP_ID override %q", wa.Config.RPID, "chuvar.example.com")
	}
	if wa.Config.RPDisplayName != "Custom Deployment" {
		t.Errorf("RPDisplayName = %q, want the WEBAUTHN_RP_DISPLAY_NAME override", wa.Config.RPDisplayName)
	}
}

func TestNewWebAuthn_OriginWithNoHostIsABootError(t *testing.T) {
	os.Unsetenv("WEBAUTHN_RP_ID")

	if _, err := newWebAuthn("not-a-url-at-all"); err == nil {
		t.Fatal("newWebAuthn() with an origin that has no host: want an error, got nil")
	}
}

// testSealedStore returns a Store whose sealing key lives only for this test.
// Enrolling a TOTP secret requires one — CreateReviewerToken refuses to write a
// secret in the clear — so tests that seed an enrolled reviewer go through here.
func testSealedStore(t *testing.T, pool *pgxpool.Pool) *store.Store {
	t.Helper()
	raw, err := (&custody.Ephemeral{}).Unseal(context.Background())
	if err != nil {
		t.Fatalf("custody.Ephemeral.Unseal() error = %v", err)
	}
	key, err := custody.NewKey(raw)
	if err != nil {
		t.Fatalf("custody.NewKey() error = %v", err)
	}
	return store.NewSealed(pool, key)
}
