package store

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAgentTokens_CreateAuthenticateTouchRevoke(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	tok, err := s.CreateAgentToken(ctx, "mcpserver-laptop", "alex-laptop mcpserver", "plaintext-one")
	if err != nil {
		t.Fatalf("CreateAgentToken() error = %v", err)
	}
	if tok.Subject != "mcpserver-laptop" {
		t.Errorf("Subject = %q, want %q", tok.Subject, "mcpserver-laptop")
	}
	if tok.Label != "alex-laptop mcpserver" {
		t.Errorf("Label = %q, want %q", tok.Label, "alex-laptop mcpserver")
	}
	if tok.LastUsedAt != nil {
		t.Errorf("LastUsedAt = %v, want nil before first authentication", tok.LastUsedAt)
	}

	agent, ok, err := s.AuthenticateAgentToken(ctx, "plaintext-one")
	if err != nil {
		t.Fatalf("AuthenticateAgentToken() error = %v", err)
	}
	if !ok || agent.Subject != "mcpserver-laptop" || agent.Label != "alex-laptop mcpserver" {
		t.Fatalf("AuthenticateAgentToken() = (%+v, %v), want subject %q, label %q, ok=true", agent, ok, "mcpserver-laptop", "alex-laptop mcpserver")
	}

	// last_used_at must advance as a side effect of a successful authentication.
	listed, err := s.ListAgentTokens(ctx)
	if err != nil {
		t.Fatalf("ListAgentTokens() error = %v", err)
	}
	if len(listed) != 1 || listed[0].LastUsedAt == nil {
		t.Fatalf("ListAgentTokens() after authenticate = %+v, want 1 token with non-nil LastUsedAt", listed)
	}

	// A never-issued plaintext must not authenticate.
	_, ok, err = s.AuthenticateAgentToken(ctx, "never-issued")
	if err != nil {
		t.Fatalf("AuthenticateAgentToken() error = %v", err)
	}
	if ok {
		t.Fatal("AuthenticateAgentToken() with a never-issued token succeeded, want failure")
	}

	if err := s.RevokeAgentToken(ctx, tok.ID); err != nil {
		t.Fatalf("RevokeAgentToken() error = %v", err)
	}

	// A revoked token must not authenticate, and must not be distinguishable
	// from a never-issued one via the returned error.
	_, ok, err = s.AuthenticateAgentToken(ctx, "plaintext-one")
	if err != nil {
		t.Fatalf("AuthenticateAgentToken() after revoke: error = %v", err)
	}
	if ok {
		t.Fatal("AuthenticateAgentToken() with a revoked token succeeded, want failure")
	}

	// Revoking again should fail, not silently succeed.
	if err := s.RevokeAgentToken(ctx, tok.ID); err == nil {
		t.Fatal("RevokeAgentToken() on an already-revoked token succeeded, want an error")
	}
}

func TestAgentTokens_NonexistentIDRevokeFails(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if err := s.RevokeAgentToken(ctx, "00000000-0000-0000-0000-000000000000"); err == nil {
		t.Fatal("RevokeAgentToken() on a nonexistent ID succeeded, want an error")
	}
}

func TestAgentTokens_ListIncludesRevoked(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	a, err := s.CreateAgentToken(ctx, "subject-a", "device-a", "plaintext-a")
	if err != nil {
		t.Fatalf("CreateAgentToken() error = %v", err)
	}
	if _, err := s.CreateAgentToken(ctx, "subject-b", "device-b", "plaintext-b"); err != nil {
		t.Fatalf("CreateAgentToken() error = %v", err)
	}
	if err := s.RevokeAgentToken(ctx, a.ID); err != nil {
		t.Fatalf("RevokeAgentToken() error = %v", err)
	}

	tokens, err := s.ListAgentTokens(ctx)
	if err != nil {
		t.Fatalf("ListAgentTokens() error = %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("ListAgentTokens() returned %d tokens, want 2 (including the revoked one)", len(tokens))
	}
	for _, tk := range tokens {
		if tk.Subject == "subject-a" && tk.RevokedAt == nil {
			t.Error("subject-a should have a non-nil RevokedAt")
		}
	}
}

func TestCreateAgentToken_EmptySubjectRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.CreateAgentToken(ctx, "", "label", "plaintext"); err == nil {
		t.Fatal("CreateAgentToken() with an empty subject succeeded, want an error")
	}
}

func TestCreateAgentToken_EmptyLabelRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.CreateAgentToken(ctx, "subject", "", "plaintext"); err == nil {
		t.Fatal("CreateAgentToken() with an empty label succeeded, want an error")
	}
}

// TestAgentTokens_DoNotAuthenticateAsReviewerAndViceVersa is the regression
// test for the invariant this table exists to hold: an agent-class token
// must be a structurally distinct credential from a reviewer token. A
// plaintext minted as one must never pass authentication as the other, even
// though both are hashed with the exact same store.HashToken function —
// distinctness comes from living in different tables/hash namespaces, not
// from different hashing.
func TestAgentTokens_DoNotAuthenticateAsReviewerAndViceVersa(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.CreateAgentToken(ctx, "agent-subject", "agent-label", "shared-plaintext-agent-side"); err != nil {
		t.Fatalf("CreateAgentToken() error = %v", err)
	}
	if _, err := s.CreateReviewerToken(ctx, "reviewer-label", "shared-plaintext-reviewer-side", ""); err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}

	// The agent token's plaintext must not authenticate as a reviewer.
	if _, ok, err := s.AuthenticateReviewerToken(ctx, "shared-plaintext-agent-side"); err != nil {
		t.Fatalf("AuthenticateReviewerToken() error = %v", err)
	} else if ok {
		t.Fatal("AuthenticateReviewerToken() accepted an agent token's plaintext, want failure")
	}

	// The reviewer token's plaintext must not authenticate as an agent.
	if _, ok, err := s.AuthenticateAgentToken(ctx, "shared-plaintext-reviewer-side"); err != nil {
		t.Fatalf("AuthenticateAgentToken() error = %v", err)
	} else if ok {
		t.Fatal("AuthenticateAgentToken() accepted a reviewer token's plaintext, want failure")
	}
}

// TestAuthenticateAgentToken_RealDBErrorIsReturnedNotMaskedAsUnauthenticated
// mirrors AuthenticateReviewerToken's identical regression test: a genuine
// database failure must surface as an error, never silently collapse into
// the same (false, nil) result as "no such token" — the fail-closed
// property this PR's brief calls out by name. A transient DB error that
// looked like "unauthenticated" would make an outage invisible instead of
// surfacing as the 500 it actually is.
func TestAuthenticateAgentToken_RealDBErrorIsReturnedNotMaskedAsUnauthenticated(t *testing.T) {
	s, _ := testStore(t)

	// An already-canceled context makes the query fail with something other
	// than pgx.ErrNoRows — a stand-in for any real connectivity failure,
	// without needing to actually take the database down mid-test.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, ok, err := s.AuthenticateAgentToken(ctx, "irrelevant-plaintext")
	if err == nil {
		t.Fatal("AuthenticateAgentToken() with a canceled context: want a non-nil error, got nil (real failure masked as unauthenticated)")
	}
	if ok {
		t.Error("AuthenticateAgentToken() reported ok=true despite a query error")
	}
}

// TestAuthenticateAgentToken_TouchFailureIsReturnedNotMaskedAsAuthenticated
// closes a gap the test above doesn't reach: a canceled context fails at
// LookupActiveAgentToken (the *first* query AuthenticateAgentToken runs), so
// it never exercises the second failure branch — the one right after it,
// where LookupActiveAgentToken succeeds but the following TouchAgentToken
// (the last_used_at side effect) fails. That branch is the actual proof this
// PR's brief asks for: a failed audit-adjacent write (last_used_at) must
// surface as a real error and ok=false, never silently authenticate the
// caller anyway just because the lookup itself worked.
//
// The trick: hold an EXCLUSIVE table lock on agent_tokens open in a separate,
// uncommitted transaction. EXCLUSIVE mode still permits concurrent ACCESS
// SHARE (plain SELECT, what LookupActiveAgentToken runs) but conflicts with
// ROW EXCLUSIVE (what TouchAgentToken's UPDATE needs) — so the lookup half
// succeeds exactly as normal, and only the touch half blocks. A second,
// single-connection pool with a short lock_timeout set on every connection
// (via AfterConnect, since MaxConns=1 guarantees Lookup and Touch reuse the
// same physical connection and its session-level setting) turns that block
// into a deterministic error within a few hundred milliseconds instead of a
// hang — no reliance on the test DB role being unprivileged (it's typically
// a superuser here, which would make a GRANT/REVOKE-based trick silently
// pass).
func TestAuthenticateAgentToken_TouchFailureIsReturnedNotMaskedAsAuthenticated(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	if _, err := s.CreateAgentToken(ctx, "agent-touch-failure", "device", "touch-failure-plaintext"); err != nil {
		t.Fatalf("CreateAgentToken() error = %v", err)
	}

	// Hold the table lock for the rest of this test, released by Rollback
	// (never committed — nothing here should persist).
	lockTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("pool.Begin() error = %v", err)
	}
	t.Cleanup(func() { _ = lockTx.Rollback(ctx) })
	if _, err := lockTx.Exec(ctx, "LOCK TABLE agent_tokens IN EXCLUSIVE MODE"); err != nil {
		t.Fatalf("LOCK TABLE agent_tokens IN EXCLUSIVE MODE: %v", err)
	}

	url := os.Getenv("DATABASE_URL")
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig() error = %v", err)
	}
	cfg.MaxConns = 1
	// A short lock_timeout, set once per connection (this pool only ever
	// opens one) rather than per-query: TouchAgentToken's UPDATE is what
	// this test needs to fail, and lock_timeout is the mechanism that turns
	// "blocked on the EXCLUSIVE lock above" into a real Postgres error
	// (55P03) instead of a hang.
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET lock_timeout = '500ms'")
		return err
	}
	limitedPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig() error = %v", err)
	}
	t.Cleanup(limitedPool.Close)

	limited := New(limitedPool)
	_, ok, err := limited.AuthenticateAgentToken(ctx, "touch-failure-plaintext")
	if err == nil {
		t.Fatal("AuthenticateAgentToken() with TouchAgentToken blocked past lock_timeout: want a non-nil error, got nil (a failed last_used_at update must not silently authenticate)")
	}
	if ok {
		t.Error("AuthenticateAgentToken() reported ok=true despite TouchAgentToken failing")
	}
	if !strings.Contains(err.Error(), "touch agent token") {
		t.Errorf("AuthenticateAgentToken() error = %q, want it to name the touch step (proves LookupActiveAgentToken itself succeeded)", err.Error())
	}
}
