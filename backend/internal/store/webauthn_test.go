package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// jsonEqual compares two JSON documents by value, not by byte — Postgres'
// JSONB column reformats whitespace on round-trip (e.g. adds a space after
// ":"), which is semantically irrelevant since every real caller only ever
// json.Unmarshal's this column, never byte-compares it.
func jsonEqual(t *testing.T, got, want []byte) bool {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("jsonEqual: unmarshal got: %v", err)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("jsonEqual: unmarshal want: %v", err)
	}
	gj, _ := json.Marshal(g)
	wj, _ := json.Marshal(w)
	return string(gj) == string(wj)
}

// seedReviewer creates a reviewer token this file's tests can bind
// credentials/challenges to; the actual bearer plaintext is irrelevant to
// every test here, only the returned ID.
func seedReviewer(t *testing.T, s *Store, label string) string {
	t.Helper()
	tok, err := s.CreateReviewerToken(context.Background(), label, "plaintext-"+label, "")
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	return tok.ID
}

func TestWebAuthnCredential_CreateListActiveRoundtrip(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	reviewer := seedReviewer(t, s, "device-a")

	cred, err := s.CreateWebAuthnCredential(ctx, reviewer, "yubikey",
		[]byte("cred-id-1"), []byte("pubkey-1"), "none", []string{"usb", "nfc"}, []byte("aaguid-1"), 0, true, false)
	if err != nil {
		t.Fatalf("CreateWebAuthnCredential() error = %v", err)
	}
	if cred.Label != "yubikey" || cred.ReviewerTokenID != reviewer {
		t.Fatalf("CreateWebAuthnCredential() = %+v, want label=yubikey reviewer=%s", cred, reviewer)
	}
	if !cred.BackupEligible || cred.BackupState {
		t.Errorf("CreateWebAuthnCredential() Flags = (BE=%v, BS=%v), want (true, false)", cred.BackupEligible, cred.BackupState)
	}

	all, err := s.ListWebAuthnCredentialsForReviewer(ctx, reviewer)
	if err != nil {
		t.Fatalf("ListWebAuthnCredentialsForReviewer() error = %v", err)
	}
	if len(all) != 1 || all[0].ID != cred.ID {
		t.Fatalf("ListWebAuthnCredentialsForReviewer() = %+v, want exactly [%s]", all, cred.ID)
	}

	active, err := s.ActiveWebAuthnCredentialsForReviewer(ctx, reviewer)
	if err != nil {
		t.Fatalf("ActiveWebAuthnCredentialsForReviewer() error = %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("ActiveWebAuthnCredentialsForReviewer() = %d credentials, want 1", len(active))
	}

	has, err := s.ReviewerHasActiveWebAuthnCredential(ctx, reviewer)
	if err != nil {
		t.Fatalf("ReviewerHasActiveWebAuthnCredential() error = %v", err)
	}
	if !has {
		t.Error("ReviewerHasActiveWebAuthnCredential() = false, want true")
	}
}

func TestWebAuthnCredential_ListScopedPerReviewer(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	a := seedReviewer(t, s, "device-a")
	b := seedReviewer(t, s, "device-b")

	if _, err := s.CreateWebAuthnCredential(ctx, a, "a-key", []byte("cred-a"), []byte("pub-a"), "none", nil, nil, 0, false, false); err != nil {
		t.Fatalf("CreateWebAuthnCredential() error = %v", err)
	}
	if _, err := s.CreateWebAuthnCredential(ctx, b, "b-key", []byte("cred-b"), []byte("pub-b"), "none", nil, nil, 0, false, false); err != nil {
		t.Fatalf("CreateWebAuthnCredential() error = %v", err)
	}

	aCreds, err := s.ListWebAuthnCredentialsForReviewer(ctx, a)
	if err != nil {
		t.Fatalf("ListWebAuthnCredentialsForReviewer(a) error = %v", err)
	}
	if len(aCreds) != 1 || aCreds[0].Label != "a-key" {
		t.Fatalf("ListWebAuthnCredentialsForReviewer(a) = %+v, want exactly [a-key]", aCreds)
	}
}

func TestWebAuthnCredential_DuplicateCredentialIDRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	reviewer := seedReviewer(t, s, "device-a")

	if _, err := s.CreateWebAuthnCredential(ctx, reviewer, "first", []byte("dup-id"), []byte("pub"), "none", nil, nil, 0, false, false); err != nil {
		t.Fatalf("CreateWebAuthnCredential() error = %v", err)
	}
	_, err := s.CreateWebAuthnCredential(ctx, reviewer, "second", []byte("dup-id"), []byte("pub2"), "none", nil, nil, 0, false, false)
	if err == nil {
		t.Fatal("CreateWebAuthnCredential() with a duplicate credential_id succeeded, want ErrWebAuthnCredentialAlreadyRegistered")
	}
	if err != ErrWebAuthnCredentialAlreadyRegistered {
		t.Fatalf("CreateWebAuthnCredential() error = %v, want ErrWebAuthnCredentialAlreadyRegistered", err)
	}
}

// TestWebAuthnCredential_RevokedCredentialIDIsReusable pins the partial
// unique index's purpose: uniqueness only needs to hold among live rows, so
// re-registering the exact same physical authenticator after revoking its
// old row must succeed — matching reviewer_tokens' token_hash partial index.
func TestWebAuthnCredential_RevokedCredentialIDIsReusable(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	reviewer := seedReviewer(t, s, "device-a")

	first, err := s.CreateWebAuthnCredential(ctx, reviewer, "first", []byte("reusable-id"), []byte("pub"), "none", nil, nil, 0, false, false)
	if err != nil {
		t.Fatalf("CreateWebAuthnCredential() error = %v", err)
	}
	if err := s.RevokeWebAuthnCredential(ctx, first.ID, reviewer); err != nil {
		t.Fatalf("RevokeWebAuthnCredential() error = %v", err)
	}
	if _, err := s.CreateWebAuthnCredential(ctx, reviewer, "second", []byte("reusable-id"), []byte("pub2"), "none", nil, nil, 0, false, false); err != nil {
		t.Fatalf("CreateWebAuthnCredential() after revoking the prior owner of this credential_id: error = %v, want success", err)
	}
}

func TestWebAuthnCredential_RevokeScopedToOwner(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	a := seedReviewer(t, s, "device-a")
	b := seedReviewer(t, s, "device-b")

	cred, err := s.CreateWebAuthnCredential(ctx, a, "a-key", []byte("cred-a"), []byte("pub-a"), "none", nil, nil, 0, false, false)
	if err != nil {
		t.Fatalf("CreateWebAuthnCredential() error = %v", err)
	}

	// b must not be able to revoke a's credential — RevokeWebAuthnCredential is
	// scoped by (id, reviewer_token_id), unlike RevokeReviewerToken.
	if err := s.RevokeWebAuthnCredential(ctx, cred.ID, b); err == nil {
		t.Fatal("RevokeWebAuthnCredential() by a non-owning reviewer succeeded, want an error")
	}

	if err := s.RevokeWebAuthnCredential(ctx, cred.ID, a); err != nil {
		t.Fatalf("RevokeWebAuthnCredential() by the owner: error = %v, want success", err)
	}
	if err := s.RevokeWebAuthnCredential(ctx, cred.ID, a); err == nil {
		t.Fatal("RevokeWebAuthnCredential() on an already-revoked credential succeeded, want an error")
	}
}

func TestWebAuthnCredential_UpdateCounter(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	reviewer := seedReviewer(t, s, "device-a")

	cred, err := s.CreateWebAuthnCredential(ctx, reviewer, "key", []byte("cred"), []byte("pub"), "none", nil, nil, 5, false, false)
	if err != nil {
		t.Fatalf("CreateWebAuthnCredential() error = %v", err)
	}
	if err := s.UpdateWebAuthnCredentialCounter(ctx, cred.ID, 6); err != nil {
		t.Fatalf("UpdateWebAuthnCredentialCounter() error = %v", err)
	}

	all, err := s.ListWebAuthnCredentialsForReviewer(ctx, reviewer)
	if err != nil {
		t.Fatalf("ListWebAuthnCredentialsForReviewer() error = %v", err)
	}
	if len(all) != 1 || all[0].SignCount != 6 {
		t.Fatalf("SignCount after update = %d, want 6", all[0].SignCount)
	}
	if all[0].LastUsedAt == nil {
		t.Error("LastUsedAt not set after UpdateWebAuthnCredentialCounter()")
	}
}

// TestWebAuthnCredential_FlagCloneWarningFailsClosed pins the fail-closed
// tripwire contract: flagging a clone warning must revoke the credential in
// the same call, not just annotate it — a credential merely "warned about"
// but left active would keep passing the next assertion, defeating the point.
func TestWebAuthnCredential_FlagCloneWarningFailsClosed(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	reviewer := seedReviewer(t, s, "device-a")

	cred, err := s.CreateWebAuthnCredential(ctx, reviewer, "key", []byte("cred"), []byte("pub"), "none", nil, nil, 5, false, false)
	if err != nil {
		t.Fatalf("CreateWebAuthnCredential() error = %v", err)
	}
	if err := s.FlagWebAuthnCredentialCloneWarning(ctx, cred.ID); err != nil {
		t.Fatalf("FlagWebAuthnCredentialCloneWarning() error = %v", err)
	}

	all, err := s.ListWebAuthnCredentialsForReviewer(ctx, reviewer)
	if err != nil {
		t.Fatalf("ListWebAuthnCredentialsForReviewer() error = %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("ListWebAuthnCredentialsForReviewer() = %d rows, want 1", len(all))
	}
	if all[0].CloneWarningAt == nil {
		t.Error("CloneWarningAt not set after FlagWebAuthnCredentialCloneWarning()")
	}
	if all[0].RevokedAt == nil {
		t.Error("RevokedAt not set after FlagWebAuthnCredentialCloneWarning() — clone signal must fail closed by revoking, not just warn")
	}

	active, err := s.ActiveWebAuthnCredentialsForReviewer(ctx, reviewer)
	if err != nil {
		t.Fatalf("ActiveWebAuthnCredentialsForReviewer() error = %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("ActiveWebAuthnCredentialsForReviewer() after a clone warning = %d, want 0 (revoked)", len(active))
	}
}

func TestReviewerHasTOTP(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	enrolled, err := s.CreateReviewerToken(ctx, "enrolled", "plaintext-enrolled", "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	unenrolled, err := s.CreateReviewerToken(ctx, "unenrolled", "plaintext-unenrolled", "")
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}

	has, err := s.ReviewerHasTOTP(ctx, enrolled.ID)
	if err != nil {
		t.Fatalf("ReviewerHasTOTP(enrolled) error = %v", err)
	}
	if !has {
		t.Error("ReviewerHasTOTP(enrolled) = false, want true")
	}

	has, err = s.ReviewerHasTOTP(ctx, unenrolled.ID)
	if err != nil {
		t.Fatalf("ReviewerHasTOTP(unenrolled) error = %v", err)
	}
	if has {
		t.Error("ReviewerHasTOTP(unenrolled) = true, want false")
	}
}

func TestWebAuthnChallenge_ConsumeIsSingleUse(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	reviewer := seedReviewer(t, s, "device-a")

	payload := []byte(`{"challenge":"abc"}`)
	if err := s.PutWebAuthnChallenge(ctx, reviewer, WebAuthnPurposeAssertion, payload, time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("PutWebAuthnChallenge() error = %v", err)
	}

	got, ok, err := s.ConsumeWebAuthnChallenge(ctx, reviewer, WebAuthnPurposeAssertion)
	if err != nil {
		t.Fatalf("ConsumeWebAuthnChallenge() error = %v", err)
	}
	if !ok || !jsonEqual(t, got, payload) {
		t.Fatalf("ConsumeWebAuthnChallenge() = (%s, %v), want (%s, true)", got, ok, payload)
	}

	// Second consume must fail — single-use.
	_, ok, err = s.ConsumeWebAuthnChallenge(ctx, reviewer, WebAuthnPurposeAssertion)
	if err != nil {
		t.Fatalf("ConsumeWebAuthnChallenge() (second call) error = %v", err)
	}
	if ok {
		t.Fatal("ConsumeWebAuthnChallenge() succeeded a second time, want it consumed after the first")
	}
}

func TestWebAuthnChallenge_ExpiredIsNotConsumable(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	reviewer := seedReviewer(t, s, "device-a")

	if err := s.PutWebAuthnChallenge(ctx, reviewer, WebAuthnPurposeRegistration, []byte(`{}`), time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("PutWebAuthnChallenge() error = %v", err)
	}

	_, ok, err := s.ConsumeWebAuthnChallenge(ctx, reviewer, WebAuthnPurposeRegistration)
	if err != nil {
		t.Fatalf("ConsumeWebAuthnChallenge() error = %v", err)
	}
	if ok {
		t.Fatal("ConsumeWebAuthnChallenge() succeeded on an expired challenge, want false")
	}
}

// TestWebAuthnChallenge_PutOverwritesPending pins the "one pending challenge
// per (reviewer, purpose)" contract: starting a second ceremony before
// finishing the first must invalidate the first's challenge, not leave both
// consumable — otherwise an abandoned begin call from an earlier page load
// could still be completed later against stale state.
func TestWebAuthnChallenge_PutOverwritesPending(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	reviewer := seedReviewer(t, s, "device-a")

	if err := s.PutWebAuthnChallenge(ctx, reviewer, WebAuthnPurposeAssertion, []byte(`{"n":1}`), time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("PutWebAuthnChallenge() (first) error = %v", err)
	}
	if err := s.PutWebAuthnChallenge(ctx, reviewer, WebAuthnPurposeAssertion, []byte(`{"n":2}`), time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("PutWebAuthnChallenge() (second) error = %v", err)
	}

	got, ok, err := s.ConsumeWebAuthnChallenge(ctx, reviewer, WebAuthnPurposeAssertion)
	if err != nil {
		t.Fatalf("ConsumeWebAuthnChallenge() error = %v", err)
	}
	if !ok {
		t.Fatal("ConsumeWebAuthnChallenge() = false, want true")
	}
	if !jsonEqual(t, got, []byte(`{"n":2}`)) {
		t.Fatalf("ConsumeWebAuthnChallenge() = %s, want the second Put's payload %s", got, `{"n":2}`)
	}
}

func TestWebAuthnChallenge_ConsumeWithNoPendingChallenge(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	reviewer := seedReviewer(t, s, "device-a")

	_, ok, err := s.ConsumeWebAuthnChallenge(ctx, reviewer, WebAuthnPurposeRegistration)
	if err != nil {
		t.Fatalf("ConsumeWebAuthnChallenge() error = %v", err)
	}
	if ok {
		t.Fatal("ConsumeWebAuthnChallenge() with nothing pending succeeded, want false")
	}
}

func TestCreateWebAuthnCredential_EmptyLabelRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	reviewer := seedReviewer(t, s, "device-a")

	if _, err := s.CreateWebAuthnCredential(ctx, reviewer, "", []byte("cred"), []byte("pub"), "none", nil, nil, 0, false, false); err == nil {
		t.Fatal("CreateWebAuthnCredential() with an empty label succeeded, want an error")
	}
}

// TestCountEverEnrolledWebAuthnCredentials_MonotonicUnderRevocation pins the
// property createToken's ever-enrolled gate depends on: revoking a
// credential must not lower the count — same monotonicity contract as
// CountEverEnrolledReviewerTokens (see that query's doc comment for the
// escalation an active-only count enables).
func TestCountEverEnrolledWebAuthnCredentials_MonotonicUnderRevocation(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	reviewer := seedReviewer(t, s, "device-a")

	if n, err := s.CountEverEnrolledWebAuthnCredentials(ctx); err != nil || n != 0 {
		t.Fatalf("CountEverEnrolledWebAuthnCredentials() = %d, %v; want 0, nil", n, err)
	}

	cred, err := s.CreateWebAuthnCredential(ctx, reviewer, "yubikey",
		[]byte("cred-count"), []byte("pub"), "none", nil, nil, 0, false, false)
	if err != nil {
		t.Fatalf("CreateWebAuthnCredential() error = %v", err)
	}
	if n, err := s.CountEverEnrolledWebAuthnCredentials(ctx); err != nil || n != 1 {
		t.Fatalf("CountEverEnrolledWebAuthnCredentials() after enrollment = %d, %v; want 1, nil", n, err)
	}

	if err := s.RevokeWebAuthnCredential(ctx, cred.ID, reviewer); err != nil {
		t.Fatalf("RevokeWebAuthnCredential() error = %v", err)
	}
	if n, err := s.CountEverEnrolledWebAuthnCredentials(ctx); err != nil || n != 1 {
		t.Fatalf("CountEverEnrolledWebAuthnCredentials() after revocation = %d, %v; want it to stay 1 (monotonic), got %d, %v", n, err, n, err)
	}
}
