package store

import (
	"context"
	"testing"
)

func TestReviewerTokens_CreateAuthenticateRevoke(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	tok, err := s.CreateReviewerToken(ctx, "alex-laptop", "plaintext-one")
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	if tok.Label != "alex-laptop" {
		t.Errorf("Label = %q, want %q", tok.Label, "alex-laptop")
	}

	label, ok, err := s.AuthenticateReviewerToken(ctx, "plaintext-one")
	if err != nil {
		t.Fatalf("AuthenticateReviewerToken() error = %v", err)
	}
	if !ok || label != "alex-laptop" {
		t.Fatalf("AuthenticateReviewerToken() = (%q, %v), want (%q, true)", label, ok, "alex-laptop")
	}

	// A never-issued plaintext must not authenticate.
	_, ok, err = s.AuthenticateReviewerToken(ctx, "never-issued")
	if err != nil {
		t.Fatalf("AuthenticateReviewerToken() error = %v", err)
	}
	if ok {
		t.Fatal("AuthenticateReviewerToken() with a never-issued token succeeded, want failure")
	}

	if err := s.RevokeReviewerToken(ctx, tok.ID); err != nil {
		t.Fatalf("RevokeReviewerToken() error = %v", err)
	}

	// A revoked token must not authenticate, and must not be distinguishable from
	// a never-issued one via the returned error (see AuthenticateReviewerToken's
	// doc comment).
	_, ok, err = s.AuthenticateReviewerToken(ctx, "plaintext-one")
	if err != nil {
		t.Fatalf("AuthenticateReviewerToken() after revoke: error = %v", err)
	}
	if ok {
		t.Fatal("AuthenticateReviewerToken() with a revoked token succeeded, want failure")
	}

	// Revoking again should fail, not silently succeed — same stance as RevokeGrant.
	if err := s.RevokeReviewerToken(ctx, tok.ID); err == nil {
		t.Fatal("RevokeReviewerToken() on an already-revoked token succeeded, want an error")
	}
}

func TestReviewerTokens_ListIncludesRevoked(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	a, err := s.CreateReviewerToken(ctx, "device-a", "plaintext-a")
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	if _, err := s.CreateReviewerToken(ctx, "device-b", "plaintext-b"); err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	if err := s.RevokeReviewerToken(ctx, a.ID); err != nil {
		t.Fatalf("RevokeReviewerToken() error = %v", err)
	}

	tokens, err := s.ListReviewerTokens(ctx)
	if err != nil {
		t.Fatalf("ListReviewerTokens() error = %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("ListReviewerTokens() returned %d tokens, want 2 (including the revoked one)", len(tokens))
	}
	for _, tk := range tokens {
		if tk.Label == "device-a" && tk.RevokedAt == nil {
			t.Error("device-a should have a non-nil RevokedAt")
		}
	}
}

func TestReviewerTokens_CountActive(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	n, err := s.CountActiveReviewerTokens(ctx)
	if err != nil {
		t.Fatalf("CountActiveReviewerTokens() error = %v", err)
	}
	if n != 0 {
		t.Fatalf("CountActiveReviewerTokens() on empty table = %d, want 0", n)
	}

	tok, err := s.CreateReviewerToken(ctx, "device-a", "plaintext-a")
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	n, err = s.CountActiveReviewerTokens(ctx)
	if err != nil {
		t.Fatalf("CountActiveReviewerTokens() error = %v", err)
	}
	if n != 1 {
		t.Fatalf("CountActiveReviewerTokens() = %d, want 1", n)
	}

	if err := s.RevokeReviewerToken(ctx, tok.ID); err != nil {
		t.Fatalf("RevokeReviewerToken() error = %v", err)
	}
	n, err = s.CountActiveReviewerTokens(ctx)
	if err != nil {
		t.Fatalf("CountActiveReviewerTokens() error = %v", err)
	}
	if n != 0 {
		t.Fatalf("CountActiveReviewerTokens() after revoking the only token = %d, want 0", n)
	}
}

func TestCreateReviewerToken_EmptyLabelRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.CreateReviewerToken(ctx, "", "plaintext"); err == nil {
		t.Fatal("CreateReviewerToken() with an empty label succeeded, want an error")
	}
}

// TestAuthenticateReviewerToken_RealDBErrorIsReturnedNotMaskedAs401 is the
// regression test for the review finding: a genuine database failure must
// surface as an error, not silently collapse into the same (false, nil)
// result as "no such token" — the latter is what turns a real outage into an
// unlogged 401 that never gets investigated.
func TestAuthenticateReviewerToken_RealDBErrorIsReturnedNotMaskedAs401(t *testing.T) {
	s, _ := testStore(t)

	// An already-canceled context makes the query fail with something other
	// than pgx.ErrNoRows — a stand-in here for any real connectivity failure,
	// without needing to actually take the database down mid-test.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, ok, err := s.AuthenticateReviewerToken(ctx, "irrelevant-plaintext")
	if err == nil {
		t.Fatal("AuthenticateReviewerToken() with a canceled context: want a non-nil error, got nil (real failure masked as unauthenticated)")
	}
	if ok {
		t.Error("AuthenticateReviewerToken() reported ok=true despite a query error")
	}
}
