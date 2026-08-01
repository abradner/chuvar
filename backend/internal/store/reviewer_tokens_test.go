package store

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestReviewerTokens_CreateAuthenticateRevoke(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	tok, err := s.CreateReviewerToken(ctx, "alex-laptop", "plaintext-one", "")
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	if tok.Label != "alex-laptop" {
		t.Errorf("Label = %q, want %q", tok.Label, "alex-laptop")
	}

	reviewer, ok, err := s.AuthenticateReviewerToken(ctx, "plaintext-one")
	if err != nil {
		t.Fatalf("AuthenticateReviewerToken() error = %v", err)
	}
	if !ok || reviewer.Label != "alex-laptop" {
		t.Fatalf("AuthenticateReviewerToken() = (%q, %v), want (%q, true)", reviewer.Label, ok, "alex-laptop")
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

	a, err := s.CreateReviewerToken(ctx, "device-a", "plaintext-a", "")
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	if _, err := s.CreateReviewerToken(ctx, "device-b", "plaintext-b", ""); err != nil {
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

	tok, err := s.CreateReviewerToken(ctx, "device-a", "plaintext-a", "")
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

	if _, err := s.CreateReviewerToken(ctx, "", "plaintext", ""); err == nil {
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

func TestVerifyReviewerTOTP_CorrectCodeAcceptedWrongAndUnenrolledRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	const secret = "JBSWY3DPEHPK3PXP" // fixed base32 test secret, not a real credential
	enrolled, err := s.CreateReviewerToken(ctx, "enrolled-device", "plaintext-enrolled", secret)
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	unenrolled, err := s.CreateReviewerToken(ctx, "unenrolled-device", "plaintext-unenrolled", "")
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode() error = %v", err)
	}

	ok, err := s.VerifyReviewerTOTP(ctx, enrolled.ID, code)
	if err != nil {
		t.Fatalf("VerifyReviewerTOTP() error = %v", err)
	}
	if !ok {
		t.Error("VerifyReviewerTOTP() with the correct current code = false, want true")
	}

	ok, err = s.VerifyReviewerTOTP(ctx, enrolled.ID, "000000")
	if err != nil {
		t.Fatalf("VerifyReviewerTOTP() error = %v", err)
	}
	if ok {
		t.Error("VerifyReviewerTOTP() with a wrong code = true, want false")
	}

	// A token with no enrolled secret must fail closed, not error — a device
	// that never enrolled simply cannot pass the gate, matching a wrong code.
	ok, err = s.VerifyReviewerTOTP(ctx, unenrolled.ID, code)
	if err != nil {
		t.Fatalf("VerifyReviewerTOTP() error = %v", err)
	}
	if ok {
		t.Error("VerifyReviewerTOTP() for a token with no enrolled secret = true, want false")
	}
}
