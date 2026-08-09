package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	"github.com/abradner/chuvar/backend/internal/db"
	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/store"
	"github.com/abradner/chuvar/backend/internal/summarize"
)

// webauthnTestServer is testServer's setup, plus the underlying pool — this
// file's tests verify audit_log rows directly (mirroring
// internal/store/grant_requests_test.go's pattern), which needs a raw
// connection testServer's two-value return doesn't expose.
func webauthnTestServer(t *testing.T) (*httptest.Server, *store.Store, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping api integration tests")
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, reviewer_tokens, webauthn_credentials, webauthn_challenges, grant_requests, data_keys`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := testSealedStore(t, pool)
	if _, err := st.CreateReviewerToken(ctx, "test-reviewer", testAuthToken, testTOTPSecret); err != nil {
		t.Fatalf("seeding reviewer token: %v", err)
	}
	a := New(st, embed.Stub{}, summarize.Stub{}, testOrigin, 10*time.Second, testWebAuthn(t))
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)
	return srv, st, pool
}

// doWebAuthn issues a request with the given bearer token and, if non-empty,
// TOTP code / WebAuthn assertion headers — deliberately not reusing
// doJSON/doJSONWithAuth's "always attach a valid TOTP code" convenience,
// since exactly which factor (if any) is presented is what these tests are
// checking.
func doWebAuthn(t *testing.T, method, url, token, totpCode, assertion string, body []byte) *http.Response {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if totpCode != "" {
		req.Header.Set("X-Chuvar-TOTP-Code", totpCode)
	}
	if assertion != "" {
		req.Header.Set(webauthnAssertionHeader, assertion)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func currentTOTPCode(t *testing.T) string {
	t.Helper()
	code, err := totp.GenerateCode(testTOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode() error = %v", err)
	}
	return code
}

func auditCount(t *testing.T, pool *pgxpool.Pool, eventType, subject string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE event_type = $1 AND subject = $2`, eventType, subject,
	).Scan(&n); err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	return n
}

// --- Registration ---

func TestWebAuthnRegister_RequiresTOTPWhenEnrolled(t *testing.T) {
	srv, _, pool := webauthnTestServer(t)

	// No TOTP code: testAuthToken has one enrolled (webauthnTestServer), so
	// register/begin must refuse — bearer auth alone must never be enough to
	// add a factor once a stronger one already exists (requireExistingSecondFactor).
	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", testAuthToken, "", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("register/begin without TOTP: status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", testAuthToken, currentTOTPCode(t), "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register/begin with a valid TOTP code: status = %d, want 200", resp.StatusCode)
	}
	creation := decodeInto[protocol.CredentialCreation](t, resp)

	va := newVirtualAuthenticator(t, "cred-totp-gated", true)
	body := va.register(t, &creation, testRPID, testOrigin, "yubikey")

	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/finish", testAuthToken, "", "", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register/finish: status = %d, want 201", resp.StatusCode)
	}
	view := decodeInto[webauthnCredentialView](t, resp)
	if view.Label != "yubikey" || !view.Active {
		t.Fatalf("register/finish response = %+v, want label=yubikey active=true", view)
	}

	if n := auditCount(t, pool, "webauthn_credential_enrolled", "test-reviewer"); n != 1 {
		t.Errorf("webauthn_credential_enrolled audit rows = %d, want 1", n)
	}
}

// TestWebAuthnRegister_FactorlessTokenRefused is the regression test for the
// bootstrap-token self-escalation hole found in review: a reviewer token
// with no enrolled factor of either kind (exactly what cmd/apiserver's
// bootstrapReviewerToken creates, and what any pre-reviewer_totp-migration
// token looks like) must never be able to start a passkey registration —
// otherwise whoever holds that bearer token mints themselves a credential
// that passes every requireStrongFactor gate. 403, not a fall-through to
// 200: an earlier version of the gate treated "no factor to demand" as
// "nothing to check" and let exactly this caller straight through.
func TestWebAuthnRegister_FactorlessTokenRefused(t *testing.T) {
	srv, st, _ := webauthnTestServer(t)
	ctx := context.Background()

	if _, err := st.CreateReviewerToken(ctx, "bootstrap", "plaintext-no-factors", ""); err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}

	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", "plaintext-no-factors", "", "", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("register/begin with no enrolled factor at all: status = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestWebAuthnRegister_FactorlessTokenRefusedAfterFullRevocation replays the
// exact recovery-scenario exploit found in review of a sibling attempt:
// every enrolled device token gets revoked (bearer-only, deliberately —
// revocation "only reduces authority"), leaving the factorless bootstrap
// token the only active credential. Registration must still be refused —
// docs/operations.md's "every enrolled device is lost" recovery deliberately
// has no API path, and a registration gate keyed on *active* enrollment
// state (rather than failing closed for factorless callers) would be exactly
// that API path.
func TestWebAuthnRegister_FactorlessTokenRefusedAfterFullRevocation(t *testing.T) {
	srv, st, _ := webauthnTestServer(t)
	ctx := context.Background()

	if _, err := st.CreateReviewerToken(ctx, "bootstrap", "plaintext-bootstrap", ""); err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}

	// Revoke the enrolled test-reviewer device — over the API, with only the
	// bootstrap bearer token, as the attacker in this scenario would.
	tokens, err := st.ListReviewerTokens(ctx)
	if err != nil {
		t.Fatalf("ListReviewerTokens() error = %v", err)
	}
	for _, tok := range tokens {
		if tok.Label != "test-reviewer" {
			continue
		}
		resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/tokens/"+tok.ID+"/revoke", "plaintext-bootstrap", "", "", nil)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("revoking enrolled token: status = %d, want 204", resp.StatusCode)
		}
		resp.Body.Close()
	}

	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", "plaintext-bootstrap", "", "", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("register/begin on the bootstrap token after all enrolled devices are revoked: status = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestWebAuthnRegister_WebAuthnOnlyTokenUsesAssertion covers the one state in
// which a token legitimately has a passkey but no TOTP secret: the
// break-glass TOTP reset (docs/operations.md) clears totp_secret_enc while
// credentials rows survive. Such a token must prove its existing passkey to
// enroll another — bearer-token-alone must not be sufficient just because
// the surviving factor happens to be WebAuthn rather than TOTP. The state is
// constructed through the store directly because no API path can produce it
// (registration always demands an existing factor), matching how the
// break-glass procedure itself is a direct database action.
func TestWebAuthnRegister_WebAuthnOnlyTokenUsesAssertion(t *testing.T) {
	srv, st, _ := webauthnTestServer(t)
	ctx := context.Background()

	tok, err := st.CreateReviewerToken(ctx, "passkey-only", "plaintext-passkey-only", "")
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	first := newVirtualAuthenticator(t, "cred-first", false)
	if _, err := st.CreateWebAuthnCredential(ctx, tok.ID, "first-key",
		first.credentialID, first.coseKeyBytes(t), "none", nil, nil, 0, false, false); err != nil {
		t.Fatalf("CreateWebAuthnCredential() error = %v", err)
	}

	// No factor presented: refused, and as 401 (present your passkey), not
	// the factorless 403 — this token does have a factor to demand.
	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", "plaintext-passkey-only", "", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("register/begin for a second passkey with no assertion: status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Assert the surviving passkey, then registration of a second one succeeds.
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/assert/begin", "plaintext-passkey-only", "", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("assert/begin: status = %d, want 200", resp.StatusCode)
	}
	assertion := decodeInto[protocol.CredentialAssertion](t, resp)
	assertionHeader := first.assert(t, &assertion, testRPID, testOrigin)

	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", "plaintext-passkey-only", "", assertionHeader, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register/begin for a second passkey with a valid assertion of the first: status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestWebAuthnRegister_AssertionSatisfiesGateWhenBothFactorsEnrolled: a
// reviewer enrolled in both TOTP and a passkey may prove either one to add a
// further passkey — the two factors are equally sufficient at every mutation
// gate this enrollment ultimately unlocks (the 2026-08-09 decision), so the
// registration gate accepts the same set, with the assertion header taking
// precedence exactly as requireStrongFactor's does.
func TestWebAuthnRegister_AssertionSatisfiesGateWhenBothFactorsEnrolled(t *testing.T) {
	srv, _, _ := webauthnTestServer(t)

	// Enroll the first passkey the ordinary way, proving TOTP.
	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", testAuthToken, currentTOTPCode(t), "", nil)
	creation := decodeInto[protocol.CredentialCreation](t, resp)
	va := newVirtualAuthenticator(t, "cred-both-factors", false)
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/finish", testAuthToken, "", "",
		va.register(t, &creation, testRPID, testOrigin, "first-key"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register/finish (first passkey): status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	// Begin a second registration proving the passkey instead of TOTP.
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/assert/begin", testAuthToken, "", "", nil)
	assertion := decodeInto[protocol.CredentialAssertion](t, resp)
	assertionHeader := va.assert(t, &assertion, testRPID, testOrigin)

	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", testAuthToken, "", assertionHeader, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register/begin with a valid assertion while TOTP is also enrolled: status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestWebAuthnRegister_DuplicateCredentialConflict(t *testing.T) {
	srv, _, _ := webauthnTestServer(t)

	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", testAuthToken, currentTOTPCode(t), "", nil)
	creation := decodeInto[protocol.CredentialCreation](t, resp)
	va := newVirtualAuthenticator(t, "cred-dup", false)
	body := va.register(t, &creation, testRPID, testOrigin, "device-one")
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/finish", testAuthToken, "", "", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first register/finish: status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	// Re-register the exact same authenticator (credential ID) without
	// revoking the first row — must conflict, not silently duplicate.
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", testAuthToken, currentTOTPCode(t), "", nil)
	creation2 := decodeInto[protocol.CredentialCreation](t, resp)
	body2 := va.register(t, &creation2, testRPID, testOrigin, "device-one-again")
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/finish", testAuthToken, "", "", body2)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("re-registering the same credential: status = %d, want 409", resp.StatusCode)
	}
}

func TestWebAuthnRegisterFinish_MalformedBodyRejected(t *testing.T) {
	srv, _, _ := webauthnTestServer(t)

	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", testAuthToken, currentTOTPCode(t), "", nil)
	resp.Body.Close()

	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/finish", testAuthToken, "", "", []byte("not json at all"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("register/finish with a malformed body: status = %d, want 400", resp.StatusCode)
	}
}

func TestWebAuthnRegisterFinish_ExpiredOrConsumedChallengeRejected(t *testing.T) {
	srv, _, _ := webauthnTestServer(t)

	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", testAuthToken, currentTOTPCode(t), "", nil)
	creation := decodeInto[protocol.CredentialCreation](t, resp)
	va := newVirtualAuthenticator(t, "cred-once", false)
	body := va.register(t, &creation, testRPID, testOrigin, "device")

	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/finish", testAuthToken, "", "", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first register/finish: status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	// Replaying the identical finish body must fail — the challenge was
	// already consumed by the first call.
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/finish", testAuthToken, "", "", body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed register/finish: status = %d, want 401", resp.StatusCode)
	}
}

// --- Assertion, used to satisfy requireStrongFactor on a real mutation ---

func TestWebAuthnAssertion_SatisfiesCreateGrant(t *testing.T) {
	srv, _, pool := webauthnTestServer(t)

	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", testAuthToken, currentTOTPCode(t), "", nil)
	creation := decodeInto[protocol.CredentialCreation](t, resp)
	va := newVirtualAuthenticator(t, "cred-grant", true)
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/finish", testAuthToken, "", "",
		va.register(t, &creation, testRPID, testOrigin, "primary-key"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register/finish: status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/assert/begin", testAuthToken, "", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("assert/begin: status = %d, want 200", resp.StatusCode)
	}
	assertion := decodeInto[protocol.CredentialAssertion](t, resp)
	assertionHeader := va.assert(t, &assertion, testRPID, testOrigin)

	grantBody, err := json.Marshal(createGrantRequest{Subject: "agent-a", Scopes: []string{"identity.basic"}, Depth: "summary"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/grants", testAuthToken, "", assertionHeader, grantBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/grants with a valid WebAuthn assertion: status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	if n := auditCount(t, pool, "webauthn_assertion_used", "test-reviewer"); n != 1 {
		t.Errorf("webauthn_assertion_used audit rows = %d, want 1", n)
	}

	// The challenge is single-use: replaying the identical assertion header
	// against a second mutation must fail.
	grantBody2, err := json.Marshal(createGrantRequest{Subject: "agent-b", Scopes: []string{"identity.basic"}, Depth: "summary"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/grants", testAuthToken, "", assertionHeader, grantBody2)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed WebAuthn assertion: status = %d, want 401", resp.StatusCode)
	}
}

// TestWebAuthnAssertion_WrongCredentialCannotSatisfyAnotherReviewer is the
// cross-reviewer-isolation regression test: a valid assertion for reviewer
// A's own passkey must never satisfy reviewer B's requireStrongFactor gate,
// even though both are otherwise-valid authenticated reviewer tokens.
func TestWebAuthnAssertion_WrongCredentialCannotSatisfyAnotherReviewer(t *testing.T) {
	srv, st, _ := webauthnTestServer(t)
	ctx := context.Background()

	if _, err := st.CreateReviewerToken(ctx, "reviewer-b", "plaintext-reviewer-b", ""); err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}

	// A enrolls a passkey.
	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", testAuthToken, currentTOTPCode(t), "", nil)
	creation := decodeInto[protocol.CredentialCreation](t, resp)
	va := newVirtualAuthenticator(t, "cred-a", false)
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/finish", testAuthToken, "", "",
		va.register(t, &creation, testRPID, testOrigin, "a-key"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register/finish: status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	// B (bearer-authenticated as reviewer-b, no factors of its own) cannot
	// even start an assertion ceremony — it has no enrolled credential.
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/assert/begin", "plaintext-reviewer-b", "", "", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("assert/begin for a reviewer with no enrolled passkey: status = %d, want 409", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestWebAuthnAssertion_WrongKeySignatureRejected checks the core signature
// verification, not just the identity/isolation checks around it: an
// assertion for the right credential ID and the right challenge, but signed
// with a different private key than the one registered, must fail
// ValidateLogin — the scenario an attacker who has learned a credential ID
// (public, sent in every ceremony) but not the private key is in.
func TestWebAuthnAssertion_WrongKeySignatureRejected(t *testing.T) {
	srv, _, _ := webauthnTestServer(t)

	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", testAuthToken, currentTOTPCode(t), "", nil)
	creation := decodeInto[protocol.CredentialCreation](t, resp)
	va := newVirtualAuthenticator(t, "cred-tamper", false)
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/finish", testAuthToken, "", "",
		va.register(t, &creation, testRPID, testOrigin, "tamper-key"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register/finish: status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/assert/begin", testAuthToken, "", "", nil)
	assertion := decodeInto[protocol.CredentialAssertion](t, resp)

	// Same credential ID as the registered one, but a freshly generated
	// private key — a signature over the right challenge/RP/origin with the
	// wrong key.
	impostor := newVirtualAuthenticator(t, "cred-tamper", false)
	assertionHeader := impostor.assert(t, &assertion, testRPID, testOrigin)

	grantBody, _ := json.Marshal(createGrantRequest{Subject: "agent-a", Scopes: []string{"identity.basic"}, Depth: "summary"})
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/grants", testAuthToken, "", assertionHeader, grantBody)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("assertion signed with the wrong private key: status = %d, want 401", resp.StatusCode)
	}
}

// TestWebAuthnAssertion_CloneSignalFailsClosed simulates a cloned
// authenticator by reusing an already-used (non-incrementing) counter value
// on a second assertion — the fail-closed tripwire this package's design
// spec requires.
func TestWebAuthnAssertion_CloneSignalFailsClosed(t *testing.T) {
	srv, _, pool := webauthnTestServer(t)

	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", testAuthToken, currentTOTPCode(t), "", nil)
	creation := decodeInto[protocol.CredentialCreation](t, resp)
	va := newVirtualAuthenticator(t, "cred-clone", false)
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/finish", testAuthToken, "", "",
		va.register(t, &creation, testRPID, testOrigin, "clone-target"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register/finish: status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	// A legitimate first use, counter goes from 0 to 1.
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/assert/begin", testAuthToken, "", "", nil)
	assertion := decodeInto[protocol.CredentialAssertion](t, resp)
	assertionHeader := va.assert(t, &assertion, testRPID, testOrigin)
	grantBody, _ := json.Marshal(createGrantRequest{Subject: "agent-a", Scopes: []string{"identity.basic"}, Depth: "summary"})
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/grants", testAuthToken, "", assertionHeader, grantBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first (legitimate) assertion: status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	// A "cloned" use: same counter value as the last legitimate one (a
	// cloned key that doesn't know the original has already moved past it).
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/assert/begin", testAuthToken, "", "", nil)
	assertion2 := decodeInto[protocol.CredentialAssertion](t, resp)
	cloneHeader := va.assertWithCounter(t, &assertion2, testRPID, testOrigin, 1) // same as before, not incremented
	grantBody2, _ := json.Marshal(createGrantRequest{Subject: "agent-b", Scopes: []string{"identity.basic"}, Depth: "summary"})
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/grants", testAuthToken, "", cloneHeader, grantBody2)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("assertion with a regressed counter (clone signal): status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	if n := auditCount(t, pool, "webauthn_clone_suspected", "test-reviewer"); n != 1 {
		t.Errorf("webauthn_clone_suspected audit rows = %d, want 1", n)
	}

	// The credential must now be revoked — even a fresh, correctly-
	// incrementing assertion from it must be refused.
	resp = doWebAuthn(t, http.MethodGet, srv.URL+"/api/webauthn/credentials", testAuthToken, "", "", nil)
	creds := decodeInto[[]webauthnCredentialView](t, resp)
	var found bool
	for _, c := range creds {
		if c.Label == "clone-target" {
			found = true
			if c.Active {
				t.Error("credential flagged for a clone signal is still Active, want revoked")
			}
			if c.CloneWarningAt == nil {
				t.Error("credential flagged for a clone signal has no CloneWarningAt")
			}
		}
	}
	if !found {
		t.Fatal("clone-target credential not found in listing")
	}
}

func TestWebAuthnAssertion_MissingHeaderStillFallsBackToTOTP(t *testing.T) {
	srv, _, _ := webauthnTestServer(t)

	// requireStrongFactor must still accept a plain TOTP code exactly as
	// before this feature existed — the addition must be additive, never a
	// downgrade or a behavior change on the existing path.
	grantBody, _ := json.Marshal(createGrantRequest{Subject: "agent-a", Scopes: []string{"identity.basic"}, Depth: "summary"})
	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/grants", testAuthToken, currentTOTPCode(t), "", grantBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/grants with a valid TOTP code (no WebAuthn header): status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	// Neither factor present: still refused.
	grantBody2, _ := json.Marshal(createGrantRequest{Subject: "agent-b", Scopes: []string{"identity.basic"}, Depth: "summary"})
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/grants", testAuthToken, "", "", grantBody2)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/grants with neither factor: status = %d, want 401", resp.StatusCode)
	}
}

func TestWebAuthnAssertion_MalformedBase64HeaderRejected(t *testing.T) {
	srv, _, _ := webauthnTestServer(t)

	grantBody, _ := json.Marshal(createGrantRequest{Subject: "agent-a", Scopes: []string{"identity.basic"}, Depth: "summary"})
	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/grants", testAuthToken, "", "not-valid-base64!!!", grantBody)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with a malformed %s header: status = %d, want 400", webauthnAssertionHeader, resp.StatusCode)
	}
}

// --- Listing and revocation ---

func TestWebAuthnCredentials_ListAndRevoke(t *testing.T) {
	srv, st, _ := webauthnTestServer(t)
	ctx := context.Background()

	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", testAuthToken, currentTOTPCode(t), "", nil)
	creation := decodeInto[protocol.CredentialCreation](t, resp)
	va := newVirtualAuthenticator(t, "cred-list", false)
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/finish", testAuthToken, "", "",
		va.register(t, &creation, testRPID, testOrigin, "listed-key"))
	view := decodeInto[webauthnCredentialView](t, resp)

	resp = doWebAuthn(t, http.MethodGet, srv.URL+"/api/webauthn/credentials", testAuthToken, "", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/webauthn/credentials: status = %d, want 200", resp.StatusCode)
	}
	creds := decodeInto[[]webauthnCredentialView](t, resp)
	if len(creds) != 1 || creds[0].ID != view.ID {
		t.Fatalf("GET /api/webauthn/credentials = %+v, want exactly [%s]", creds, view.ID)
	}

	// A different reviewer must not see this credential — scoped listing.
	if _, err := st.CreateReviewerToken(ctx, "other-reviewer", "plaintext-other", ""); err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	resp = doWebAuthn(t, http.MethodGet, srv.URL+"/api/webauthn/credentials", "plaintext-other", "", "", nil)
	otherCreds := decodeInto[[]webauthnCredentialView](t, resp)
	if len(otherCreds) != 0 {
		t.Fatalf("GET /api/webauthn/credentials for a different reviewer = %+v, want empty", otherCreds)
	}

	// Revoking from a different reviewer must fail (scoped ownership).
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/credentials/"+view.ID+"/revoke", "plaintext-other", "", "", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("revoking another reviewer's credential: status = %d, want 409", resp.StatusCode)
	}
	resp.Body.Close()

	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/credentials/"+view.ID+"/revoke", testAuthToken, "", "", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoking own credential: status = %d, want 204", resp.StatusCode)
	}

	resp = doWebAuthn(t, http.MethodGet, srv.URL+"/api/webauthn/credentials", testAuthToken, "", "", nil)
	creds = decodeInto[[]webauthnCredentialView](t, resp)
	if len(creds) != 1 || creds[0].Active {
		t.Fatalf("GET /api/webauthn/credentials after revoke = %+v, want the same row with Active=false", creds)
	}
}

// --- createToken's ever-enrolled gate, WebAuthn half ---

// webauthnBootstrapTestServer mirrors testServerWithBootstrapToken (a single
// factorless bootstrap token, nothing enrolled anywhere) but also returns the
// store, which the gate tests below need to construct enrollment states no
// API path can produce.
func webauthnBootstrapTestServer(t *testing.T) (*httptest.Server, *store.Store, string) {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping api integration tests")
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, reviewer_tokens, webauthn_credentials, webauthn_challenges, grant_requests, data_keys`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := testSealedStore(t, pool)
	const bootstrapToken = "bootstrap-token-do-not-use-in-prod"
	if _, err := st.CreateReviewerToken(ctx, "bootstrap", bootstrapToken, ""); err != nil {
		t.Fatalf("seeding bootstrap token: %v", err)
	}
	a := New(st, embed.Stub{}, summarize.Stub{}, testOrigin, 10*time.Second, testWebAuthn(t))
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)
	return srv, st, bootstrapToken
}

// TestCreateToken_WebAuthnOnlyEnrollmentClosesGate is the regression test for
// the self-mint escalation found in review of a sibling attempt: with a
// passkey the only second factor ever enrolled anywhere (no TOTP — the state
// a break-glass TOTP reset leaves behind), a gate that counted only TOTP
// enrollments read "ever enrolled = 0" and let a bare bearer token mint a
// fresh token, read its otpauth:// URI, and self-enroll — full escalation
// from bearer-token-only to every strong-factor-gated mutation. The gate
// must count WebAuthn credentials too.
func TestCreateToken_WebAuthnOnlyEnrollmentClosesGate(t *testing.T) {
	srv, st, bootstrapToken := webauthnBootstrapTestServer(t)
	ctx := context.Background()

	// A device token whose only surviving factor is a passkey — constructed
	// through the store because no API path produces this state (see
	// TestWebAuthnRegister_WebAuthnOnlyTokenUsesAssertion).
	tok, err := st.CreateReviewerToken(ctx, "passkey-only", "plaintext-passkey-only", "")
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}
	va := newVirtualAuthenticator(t, "cred-gate", false)
	if _, err := st.CreateWebAuthnCredential(ctx, tok.ID, "surviving-key",
		va.credentialID, va.coseKeyBytes(t), "none", nil, nil, 0, false, false); err != nil {
		t.Fatalf("CreateWebAuthnCredential() error = %v", err)
	}

	// The attack: the bare bootstrap bearer token, no factor header at all.
	body, _ := json.Marshal(createTokenRequest{Label: "attacker-device"})
	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/tokens", bootstrapToken, "", "", body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/tokens with only a WebAuthn credential ever enrolled: status = %d, want 401 (the ever-enrolled gate must count passkeys too)", resp.StatusCode)
	}
	resp.Body.Close()

	// The legitimate path through the same closed gate: the passkey-only
	// token proves its passkey and mints a replacement device.
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/assert/begin", "plaintext-passkey-only", "", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("assert/begin: status = %d, want 200", resp.StatusCode)
	}
	assertion := decodeInto[protocol.CredentialAssertion](t, resp)
	assertionHeader := va.assert(t, &assertion, testRPID, testOrigin)

	body2, _ := json.Marshal(createTokenRequest{Label: "replacement-device"})
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/tokens", "plaintext-passkey-only", "", assertionHeader, body2)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/tokens with a valid WebAuthn assertion: status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestCreateToken_AcceptsWebAuthnAssertion: minting a token from an enrolled
// device accepts a WebAuthn assertion in place of a TOTP code — the
// either-factor rule (verifySecondFactor) applies to createToken's
// conditional gate the same as to every requireStrongFactor route.
func TestCreateToken_AcceptsWebAuthnAssertion(t *testing.T) {
	srv, _, _ := webauthnTestServer(t)

	// Enroll a passkey on the (TOTP-enrolled) test reviewer.
	resp := doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/begin", testAuthToken, currentTOTPCode(t), "", nil)
	creation := decodeInto[protocol.CredentialCreation](t, resp)
	va := newVirtualAuthenticator(t, "cred-mint", false)
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/register/finish", testAuthToken, "", "",
		va.register(t, &creation, testRPID, testOrigin, "mint-key"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register/finish: status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/webauthn/assert/begin", testAuthToken, "", "", nil)
	assertion := decodeInto[protocol.CredentialAssertion](t, resp)
	assertionHeader := va.assert(t, &assertion, testRPID, testOrigin)

	body, _ := json.Marshal(createTokenRequest{Label: "new-device"})
	resp = doWebAuthn(t, http.MethodPost, srv.URL+"/api/tokens", testAuthToken, "", assertionHeader, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/tokens with a WebAuthn assertion instead of a TOTP code: status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- CORS ---

func TestCORS_AllowsWebAuthnAssertionHeader(t *testing.T) {
	srv, _, _ := webauthnTestServer(t)

	req, err := http.NewRequest(http.MethodOptions, srv.URL+"/api/grants", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()

	got := resp.Header.Get("Access-Control-Allow-Headers")
	if !strings.Contains(got, webauthnAssertionHeader) {
		t.Errorf("Access-Control-Allow-Headers = %q, want it to include %s", got, webauthnAssertionHeader)
	}
}
