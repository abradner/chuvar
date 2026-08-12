package store

import (
	"context"
	"testing"
)

func TestAgentTokens_CreateAuthenticateTouchRevoke(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	tok, err := s.CreateAgentToken(ctx, "agent-a", "laptop-agent-1", "plaintext-one")
	if err != nil {
		t.Fatalf("CreateAgentToken() error = %v", err)
	}
	if tok.Subject != "agent-a" {
		t.Errorf("Subject = %q, want %q", tok.Subject, "agent-a")
	}
	if tok.Label != "laptop-agent-1" {
		t.Errorf("Label = %q, want %q", tok.Label, "laptop-agent-1")
	}

	agent, ok, err := s.AuthenticateAgentToken(ctx, "plaintext-one")
	if err != nil {
		t.Fatalf("AuthenticateAgentToken() error = %v", err)
	}
	if !ok || agent.Subject != "agent-a" || agent.Label != "laptop-agent-1" {
		t.Fatalf("AuthenticateAgentToken() = (%+v, %v), want (subject=agent-a label=laptop-agent-1, true)", agent, ok)
	}

	// last_used_at must advance on a successful authentication.
	tokens, err := s.ListAgentTokens(ctx)
	if err != nil {
		t.Fatalf("ListAgentTokens() error = %v", err)
	}
	if len(tokens) != 1 || tokens[0].LastUsedAt == nil {
		t.Fatalf("ListAgentTokens() after authenticate = %+v, want 1 token with a non-nil LastUsedAt", tokens)
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
	// from a never-issued one via the returned error (see
	// AuthenticateAgentToken's doc comment).
	_, ok, err = s.AuthenticateAgentToken(ctx, "plaintext-one")
	if err != nil {
		t.Fatalf("AuthenticateAgentToken() after revoke: error = %v", err)
	}
	if ok {
		t.Fatal("AuthenticateAgentToken() with a revoked token succeeded, want failure")
	}

	// Revoking again should fail, not silently succeed — same stance as
	// RevokeReviewerToken/RevokeGrant.
	if err := s.RevokeAgentToken(ctx, tok.ID); err == nil {
		t.Fatal("RevokeAgentToken() on an already-revoked token succeeded, want an error")
	}
}

// TestAgentTokens_StructurallyDistinctFromReviewerTokens is the invariant
// this PR's brief names directly: "an agent-class token must be a
// structurally distinct credential from a reviewer token ... it lives in its
// own table, so it can never pass reviewer authentication." Mints an agent
// token and a reviewer token, then cross-checks that neither authentication
// path accepts the other's plaintext.
func TestAgentTokens_StructurallyDistinctFromReviewerTokens(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.CreateAgentToken(ctx, "agent-a", "agent-device", "agent-plaintext"); err != nil {
		t.Fatalf("CreateAgentToken() error = %v", err)
	}
	if _, err := s.CreateReviewerToken(ctx, "reviewer-device", "reviewer-plaintext", ""); err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}

	// The agent token's plaintext must not authenticate as a reviewer.
	_, ok, err := s.AuthenticateReviewerToken(ctx, "agent-plaintext")
	if err != nil {
		t.Fatalf("AuthenticateReviewerToken() with an agent token's plaintext: error = %v", err)
	}
	if ok {
		t.Fatal("AuthenticateReviewerToken() accepted an agent-class token's plaintext — the two credentials must be structurally distinct")
	}

	// The reviewer token's plaintext must not authenticate as an agent.
	_, ok, err = s.AuthenticateAgentToken(ctx, "reviewer-plaintext")
	if err != nil {
		t.Fatalf("AuthenticateAgentToken() with a reviewer token's plaintext: error = %v", err)
	}
	if ok {
		t.Fatal("AuthenticateAgentToken() accepted a reviewer token's plaintext — the two credentials must be structurally distinct")
	}
}

func TestAgentTokens_ListIncludesRevoked(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	a, err := s.CreateAgentToken(ctx, "agent-a", "device-a", "plaintext-a")
	if err != nil {
		t.Fatalf("CreateAgentToken() error = %v", err)
	}
	if _, err := s.CreateAgentToken(ctx, "agent-b", "device-b", "plaintext-b"); err != nil {
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
		if tk.Subject == "agent-a" && tk.RevokedAt == nil {
			t.Error("agent-a's token should have a non-nil RevokedAt")
		}
	}
}

func TestCreateAgentToken_EmptySubjectRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.CreateAgentToken(ctx, "", "device-a", "plaintext"); err == nil {
		t.Fatal("CreateAgentToken() with an empty subject succeeded, want an error")
	}
}

func TestCreateAgentToken_EmptyLabelRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.CreateAgentToken(ctx, "agent-a", "", "plaintext"); err == nil {
		t.Fatal("CreateAgentToken() with an empty label succeeded, want an error")
	}
}

// TestAuthenticateAgentToken_RealDBErrorIsReturnedNotMaskedAsFalse is the
// fail-closed proof this PR's brief demands: a genuine database failure must
// surface as an error, not silently collapse into the same (false, nil)
// result as "no such token" — the latter turns a real outage into an
// unlogged auth failure that never gets investigated. Mirrors
// TestAuthenticateReviewerToken_RealDBErrorIsReturnedNotMaskedAs401 exactly.
func TestAuthenticateAgentToken_RealDBErrorIsReturnedNotMaskedAsFalse(t *testing.T) {
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
