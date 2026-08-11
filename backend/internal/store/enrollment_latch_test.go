package store

import (
	"context"
	"testing"
)

// clearAllFactors runs the documented break-glass recovery's factor-clearing
// step (docs/operations.md) directly against the pool: null every TOTP secret
// and delete every passkey. This is the exact mutation whose whole point is to
// drop the ever-enrolled counts to zero — the latch's job is to keep
// createToken's gate closed anyway.
func clearAllFactors(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, `UPDATE reviewer_tokens SET totp_secret_enc = NULL`); err != nil {
		t.Fatalf("clearing totp secrets: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM webauthn_credentials`); err != nil {
		t.Fatalf("deleting webauthn credentials: %v", err)
	}
}

func mustLatchSet(t *testing.T, s *Store, want bool, when string) {
	t.Helper()
	got, err := s.EnrollmentLatchSet(context.Background())
	if err != nil {
		t.Fatalf("EnrollmentLatchSet() error = %v", err)
	}
	if got != want {
		t.Fatalf("EnrollmentLatchSet() %s = %v, want %v", when, got, want)
	}
}

// TestEnrollmentLatch_SurvivesFactorReset is the durable-latch proof: after a
// factor is enrolled, running the break-glass recovery that clears every factor
// row (dropping both ever-enrolled counts to zero) leaves the latch SET — so
// createToken's gate ("latch OR counts > 0") stays closed and a factorless
// token cannot self-enroll during the re-bootstrap window. This is the
// append-only property principle 12 requires of the enrollment gate.
func TestEnrollmentLatch_SurvivesFactorReset(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	// Fresh deployment: nothing enrolled, latch unset.
	mustLatchSet(t, s, false, "on a fresh deployment")

	// A factorless bootstrap token must NOT latch — the bootstrap carve-out
	// depends on the deployment staying ungated until a real factor lands.
	if _, err := s.CreateReviewerToken(ctx, "bootstrap", "plaintext-bootstrap", ""); err != nil {
		t.Fatalf("CreateReviewerToken(bootstrap) error = %v", err)
	}
	mustLatchSet(t, s, false, "after a factorless bootstrap token")

	// Enrolling the operator's first real TOTP device sets the latch.
	if _, err := s.CreateReviewerToken(ctx, "operator-phone", "plaintext-operator", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("CreateReviewerToken(enrolled) error = %v", err)
	}
	mustLatchSet(t, s, true, "after enrolling a TOTP device")

	// Break-glass recovery: clear every factor row. Both ever-enrolled counts
	// return to zero...
	clearAllFactors(t, s)
	totpCount, err := s.CountEverEnrolledReviewerTokens(ctx)
	if err != nil {
		t.Fatalf("CountEverEnrolledReviewerTokens() error = %v", err)
	}
	waCount, err := s.CountEverEnrolledWebAuthnCredentials(ctx)
	if err != nil {
		t.Fatalf("CountEverEnrolledWebAuthnCredentials() error = %v", err)
	}
	if totpCount != 0 || waCount != 0 {
		t.Fatalf("after recovery: counts = (totp=%d, webauthn=%d), want (0, 0)", totpCount, waCount)
	}

	// ...but the latch does NOT. The gate stays closed across the reset. Only a
	// separate, deliberate operator action (DELETE FROM enrollment_latch) may
	// reopen it — nothing the recovery did clears it.
	mustLatchSet(t, s, true, "after a full factor reset")
}

// TestEnrollmentLatch_SetByPasskeyEnrollment proves the passkey path latches
// the deployment on its own, independent of TOTP: a credential enrolled against
// an otherwise-factorless token still trips the durable latch.
func TestEnrollmentLatch_SetByPasskeyEnrollment(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	// A factorless token to bind the credential to — this alone does not latch.
	reviewer := seedReviewer(t, s, "passkey-owner")
	mustLatchSet(t, s, false, "before any passkey is enrolled")

	if _, err := s.CreateWebAuthnCredential(ctx, reviewer, "yubikey",
		[]byte("cred-id"), []byte("pub-key"), "none", nil, nil, 0, false, false); err != nil {
		t.Fatalf("CreateWebAuthnCredential() error = %v", err)
	}
	mustLatchSet(t, s, true, "after enrolling a passkey")

	// The passkey rows are deleted by recovery; the latch survives that too.
	clearAllFactors(t, s)
	mustLatchSet(t, s, true, "after deleting every passkey")
}
