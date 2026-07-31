package main

import (
	"context"
	"os"
	"testing"

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
	if _, err := pool.Exec(ctx, `TRUNCATE reviewer_tokens`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}
	return store.New(pool)
}

func TestWarnIfNoEnrolledDevice_SucceedsInBothStates(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Zero enrolled: warns (logged, not asserted here) but must not fail boot —
	// refusing to start would break every pre-TOTP-migration deployment on
	// upgrade, turning a security gap into an outage.
	if err := warnIfNoEnrolledDevice(ctx, st); err != nil {
		t.Fatalf("warnIfNoEnrolledDevice() with no enrolled device: error = %v, want nil (warn, don't fail boot)", err)
	}

	if _, err := st.CreateReviewerToken(ctx, "device-a", "plaintext-a", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	if err := warnIfNoEnrolledDevice(ctx, st); err != nil {
		t.Fatalf("warnIfNoEnrolledDevice() with an enrolled device: error = %v, want nil", err)
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
