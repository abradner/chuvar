package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/abradner/chuvar/backend/internal/custody"
	"github.com/abradner/chuvar/backend/internal/db"
	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/store"
	"github.com/abradner/chuvar/backend/internal/summarize"
)

// testAuthToken is the plaintext of a reviewer token seeded into the store by
// testServer (see below), reused across most tests as "the" authenticated
// credential — analogous to the shared secret constant this replaced, but now
// backed by a real reviewer_tokens row rather than a value the API trusts blindly.
const testAuthToken = "test-token-do-not-use-in-prod"

// testTOTPSecret is testAuthToken's enrolled TOTP secret — a fixed base32 value
// (not a real credential), not generated per-test, so every test in this
// package can compute a valid current code without coordinating on state.
const testTOTPSecret = "JBSWY3DPEHPK3PXP"

// testRPID/testOrigin are the WebAuthn Relying Party identity every test
// server in this package validates ceremonies against — matching what a real
// deployment's dev default resolves to (cmd/apiserver's newWebAuthn derives
// RP ID "localhost" from the same http://localhost:5173 origin). Fixed
// constants so every virtual-authenticator helper (webauthn_virtual_test.go)
// can build clientDataJSON against a known value rather than threading it
// through every test.
const (
	testRPID   = "localhost"
	testOrigin = "http://localhost:5173"
)

// testWebAuthn builds the *webauthn.WebAuthn every testServer variant needs
// to satisfy api.New's now-required WebAuthn field. User verification is
// required, matching cmd/apiserver's real configuration (newWebAuthn's doc
// comment on why: this factor stands in for a TOTP code, so it must carry
// the same "the human just proved presence right now" weight).
func testWebAuthn(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          testRPID,
		RPDisplayName: "Chuvar Test",
		RPOrigins:     []string{testOrigin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		t.Fatalf("webauthn.New() error = %v", err)
	}
	return wa
}

func testServer(t *testing.T) (*httptest.Server, *store.Store) {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, reviewer_tokens, webauthn_credentials, webauthn_challenges, enrollment_latch, grant_requests, data_keys, signing_policies, capability_grant_identities, capability_grant_tokens`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := testSealedStore(t, pool)
	if _, err := st.CreateReviewerToken(ctx, "test-reviewer", testAuthToken, testTOTPSecret); err != nil {
		t.Fatalf("seeding reviewer token: %v", err)
	}
	a := New(st, embed.Stub{}, summarize.Stub{}, testOrigin, 10*time.Second, testWebAuthn(t))
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)
	return srv, st
}

// testServerWithBootstrapToken is testServer's setup but seeds a single
// unenrolled token (no TOTP secret) instead — the same shape as
// cmd/apiserver's real bootstrapReviewerToken, for tests exercising
// createToken's conditional TOTP gate at the "zero enrolled devices yet"
// state.
func testServerWithBootstrapToken(t *testing.T) (*httptest.Server, string) {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, reviewer_tokens, webauthn_credentials, webauthn_challenges, enrollment_latch, grant_requests, data_keys, signing_policies, capability_grant_identities, capability_grant_tokens`); err != nil {
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
	return srv, bootstrapToken
}

// doJSON sends an authenticated request (the common case for these tests — most
// of them are testing business logic, not the auth gate itself, which has its own
// dedicated tests below).
func doJSON(t *testing.T, method, url string, body any) *http.Response {
	t.Helper()
	return doJSONWithAuth(t, method, url, body, testAuthToken)
}

func doJSONWithAuth(t *testing.T, method, url string, body any, token string) *http.Response {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshaling request body: %v", err)
		}
		reader = bytes.NewReader(b)
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
	// Attach a valid current TOTP code whenever the request is authenticating as
	// the seeded testAuthToken — harmless for routes that don't check it
	// (requireStrongFactor only gates approve/create-grant), and means individual tests
	// don't each have to compute one just to reach a gated handler.
	if token == testAuthToken {
		code, err := totp.GenerateCode(testTOTPSecret, time.Now())
		if err != nil {
			t.Fatalf("totp.GenerateCode() error = %v", err)
		}
		req.Header.Set("X-Chuvar-TOTP-Code", code)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func decodeInto[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding response body: %v", err)
	}
	return out
}

func TestRequireAuth_MissingTokenRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSONWithAuth(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /api/grants with no Authorization header: status = %d, want 401", resp.StatusCode)
	}
}

func TestRequireAuth_WrongTokenRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSONWithAuth(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil, "wrong-token")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /api/grants with wrong token: status = %d, want 401", resp.StatusCode)
	}
}

func TestRequireAuth_CorrectTokenAccepted(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/grants with correct token: status = %d, want 200", resp.StatusCode)
	}
}

func TestRequireAuth_RevokedTokenRejected(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()

	tok, err := st.CreateReviewerToken(ctx, "throwaway-device", "throwaway-plaintext", "")
	if err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}

	resp := doJSONWithAuth(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil, "throwaway-plaintext")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/grants with a freshly created token: status = %d, want 200", resp.StatusCode)
	}

	if err := st.RevokeReviewerToken(ctx, tok.ID); err != nil {
		t.Fatalf("RevokeReviewerToken() error = %v", err)
	}

	resp = doJSONWithAuth(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil, "throwaway-plaintext")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /api/grants with a revoked token: status = %d, want 401", resp.StatusCode)
	}
}

func TestRequireTOTP_MissingHeaderRejected(t *testing.T) {
	srv, _ := testServer(t)

	// Built manually, not via doJSON/doJSONWithAuth: both of those attach a valid
	// TOTP code automatically for testAuthToken (see doJSONWithAuth), which would
	// defeat the point of this test — a valid bearer token alone must not be
	// enough for a mutation that grants authority.
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/grants", bytes.NewReader(mustJSON(t, createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{"identity.basic"},
	})))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/grants with no TOTP header: status = %d, want 401", resp.StatusCode)
	}
}

func TestRequireTOTP_WhitespaceOnlyHeaderTreatedAsMissing(t *testing.T) {
	srv, _ := testServer(t)

	// A whitespace-only header (e.g. an accidental space pasted alongside the
	// code) must be treated the same as an absent one — errTOTPRequired, not
	// errTOTPInvalid, which the pre-fix code would return since " " != "".
	// Found in review.
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/grants", bytes.NewReader(mustJSON(t, createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{"identity.basic"},
	})))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	req.Header.Set("X-Chuvar-TOTP-Code", "   ")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/grants with a whitespace-only TOTP header: status = %d, want 401", resp.StatusCode)
	}
	body := decodeInto[errorResponse](t, resp)
	if body.Error != errTOTPRequired.Error() {
		t.Errorf("error = %q, want %q (whitespace-only should read as \"required\", not \"invalid\")", body.Error, errTOTPRequired.Error())
	}
}

// The two tests below exercise the whitespace-assertion-header fix at the unit
// level, calling the factor-selection helpers directly rather than over the
// wire. That is deliberate: Go's HTTP server trims leading/trailing spaces and
// tabs from header values before any handler sees them, so a whitespace-only
// header sent over a real connection already arrives empty. The branch-selection
// bug this fix closes — choosing the WebAuthn path on a present-but-blank
// assertion header, and thereby ignoring a valid TOTP code with a spurious 401 —
// is only observable when the header reaches the code still carrying whitespace,
// which is exactly what a direct call with httptest.NewRequest reproduces.
func newTestAPIWithReviewer(t *testing.T) (*API, store.AuthenticatedReviewer) {
	t.Helper()
	_, st := testServer(t)
	a := New(st, embed.Stub{}, summarize.Stub{}, testOrigin, 10*time.Second, testWebAuthn(t))
	reviewer, ok, err := st.AuthenticateReviewerToken(context.Background(), testAuthToken)
	if err != nil || !ok {
		t.Fatalf("authenticating seeded reviewer: ok=%v err=%v", ok, err)
	}
	return a, reviewer
}

// reqWithFactor builds an authenticated request carrying a valid TOTP code plus
// whatever assertion-header value the test wants to probe — set directly, so
// (unlike a wire request) whitespace survives to the handler.
func reqWithFactor(t *testing.T, reviewer store.AuthenticatedReviewer, assertion string) *http.Request {
	t.Helper()
	code, err := totp.GenerateCode(testTOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", nil)
	req = req.WithContext(context.WithValue(req.Context(), reviewerContextKey{}, reviewer))
	req.Header.Set("X-Chuvar-TOTP-Code", code)
	req.Header.Set(webauthnAssertionHeader, assertion)
	return req
}

func TestVerifySecondFactor_WhitespaceAssertionHeaderHonoursTOTP(t *testing.T) {
	a, reviewer := newTestAPIWithReviewer(t)
	req := reqWithFactor(t, reviewer, "   ")
	rr := httptest.NewRecorder()
	if !a.verifySecondFactor(rr, req) {
		t.Fatalf("verifySecondFactor with a whitespace-only assertion header and a valid TOTP code = false (status %d), want true (whitespace must not force the WebAuthn path)", rr.Code)
	}
}

func TestRequireExistingSecondFactor_WhitespaceAssertionHeaderHonoursTOTP(t *testing.T) {
	a, reviewer := newTestAPIWithReviewer(t)
	req := reqWithFactor(t, reviewer, "   ")
	rr := httptest.NewRecorder()
	called := false
	a.requireExistingSecondFactor(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})(rr, req)
	if !called {
		t.Fatalf("requireExistingSecondFactor with a whitespace-only assertion header and a valid TOTP code did not reach next (status %d), want the valid TOTP code honoured", rr.Code)
	}
}

func TestRequireTOTP_WrongCodeRejected(t *testing.T) {
	srv, _ := testServer(t)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/grants", bytes.NewReader(mustJSON(t, createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{"identity.basic"},
	})))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	req.Header.Set("X-Chuvar-TOTP-Code", "000000")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/grants with a wrong TOTP code: status = %d, want 401", resp.StatusCode)
	}
}

func TestRequireTOTP_UnenrolledTokenRejected(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()

	// A token created with no TOTP secret (the pre-this-batch default, and the
	// bootstrap token's own shape) authenticates fine but must never pass a
	// requireStrongFactor-gated route — that's the whole point of failing closed.
	if _, err := st.CreateReviewerToken(ctx, "no-totp-device", "no-totp-plaintext", ""); err != nil {
		t.Fatalf("CreateReviewerToken() error = %v", err)
	}

	// A code header is present (any value — there's no enrolled secret to
	// generate a real one against) to isolate "unenrolled" from the separate
	// "missing header" case already covered above.
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/grants", bytes.NewReader(mustJSON(t, createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{"identity.basic"},
	})))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer no-totp-plaintext")
	req.Header.Set("X-Chuvar-TOTP-Code", "000000")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/grants with an unenrolled token: status = %d, want 401", resp.StatusCode)
	}
}

func TestRequireTOTP_DenyRevokeNotGated(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()

	req, err := st.RequestGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "")
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}

	// deny is deliberately not gated by requireStrongFactor (see api.go's Routes doc
	// comment): it only reduces authority, not the self-escalation vector the
	// gate exists for. doJSONWithAuth with no TOTP header must still succeed.
	resp := doJSONWithAuth(t, http.MethodPost, srv.URL+"/api/grant-requests/"+req.ID+"/deny", nil, testAuthToken)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST deny with no TOTP header: status = %d, want 204", resp.StatusCode)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}
	return b
}

func TestCreateAndListGrants(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{"identity.basic"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/grants status = %d, want 201", resp.StatusCode)
	}
	created := decodeInto[grantView](t, resp)
	if !created.Active {
		t.Error("created grant should be Active")
	}

	resp = doJSON(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/grants status = %d, want 200", resp.StatusCode)
	}
	grants := decodeInto[page[grantView]](t, resp).Items
	if len(grants) != 1 {
		t.Fatalf("GET /api/grants returned %d grants, want 1", len(grants))
	}
}

func TestCreateGrant_InvalidScopeRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{"Not A Valid Scope"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with invalid scope: status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateGrant_InvalidDepthRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{"identity.basic"},
		Depth:   "bogus",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with invalid depth: status = %d, want 400", resp.StatusCode)
	}
	body := decodeInto[errorResponse](t, resp)
	if body.Error == "" {
		t.Error("expected a clean validation message, got empty error")
	}
	// This is the regression case from review: an invalid depth used to reach
	// Postgres's CHECK constraint and leak a raw driver error (constraint name,
	// SQLSTATE) as a 500. It must now be caught before ever reaching the store.
	if want := "depth must be one of"; len(body.Error) < len(want) || body.Error[:len(want)] != want {
		t.Errorf("error message = %q, want it to start with %q (a clean validation message, not a raw driver error)", body.Error, want)
	}
}

func TestCreateGrant_NegativeTTLRejected(t *testing.T) {
	srv, _ := testServer(t)

	negative := -60
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		Subject:    "agent-a",
		Scopes:     []string{"identity.basic"},
		TTLSeconds: &negative,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with negative ttl_seconds: status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateGrant_DuplicateScopesRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{"identity.basic", "identity.basic"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with duplicate scopes: status = %d, want 400", resp.StatusCode)
	}
	// This is the regression case from review: a duplicate scope used to reach
	// grant_scopes' (grant_id, scope) primary key and come back as a 500 instead
	// of a clean 400.
	body := decodeInto[errorResponse](t, resp)
	if body.Error == "" {
		t.Error("expected a clean validation message, got empty error")
	}
}

func TestCreateGrant_TTLTooLargeRejected(t *testing.T) {
	srv, _ := testServer(t)

	huge := maxGrantTTLSeconds + 1
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		Subject:    "agent-a",
		Scopes:     []string{"identity.basic"},
		TTLSeconds: &huge,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with ttl_seconds over max: status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateGrant_EmptyScopesRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with no scopes: status = %d, want 400", resp.StatusCode)
	}
}

func TestRevokeGrant(t *testing.T) {
	srv, _ := testServer(t)

	created := decodeInto[grantView](t, doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{"identity.basic"},
	}))

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants/"+created.ID+"/revoke", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST revoke status = %d, want 204", resp.StatusCode)
	}

	grants := decodeInto[page[grantView]](t, doJSON(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil)).Items
	if len(grants) != 1 || grants[0].Active {
		t.Fatalf("grant after revoke = %+v, want present but not Active", grants)
	}

	// Revoking again should fail, not silently succeed.
	resp = doJSON(t, http.MethodPost, srv.URL+"/api/grants/"+created.ID+"/revoke", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST revoke (already revoked) status = %d, want 409", resp.StatusCode)
	}
}

func TestRenewGrant(t *testing.T) {
	srv, _ := testServer(t)

	ttl := 60
	created := decodeInto[grantView](t, doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		Subject:    "agent-a",
		Scopes:     []string{"identity.basic"},
		TTLSeconds: &ttl,
	}))

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants/"+created.ID+"/renew", struct {
		TTLSeconds int `json:"ttl_seconds"`
	}{TTLSeconds: 3600})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST renew status = %d, want 200", resp.StatusCode)
	}
	renewed := decodeInto[grantView](t, resp)
	if !renewed.Active {
		t.Error("renewed grant should still be Active")
	}
	if renewed.ExpiresAt == nil || *renewed.ExpiresAt == *created.ExpiresAt {
		t.Fatalf("renewed grant's ExpiresAt = %v, want it later than the original %v", renewed.ExpiresAt, created.ExpiresAt)
	}
}

func TestRenewGrant_NonPositiveTTLRejected(t *testing.T) {
	srv, _ := testServer(t)

	created := decodeInto[grantView](t, doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{"identity.basic"},
	}))

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants/"+created.ID+"/renew", struct {
		TTLSeconds int `json:"ttl_seconds"`
	}{TTLSeconds: 0})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST renew with ttl_seconds=0: status = %d, want 400 (renewing into \"no expiry\" isn't allowed)", resp.StatusCode)
	}
}

func TestRenewGrant_RevokedGrantRejected(t *testing.T) {
	srv, _ := testServer(t)

	created := decodeInto[grantView](t, doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{"identity.basic"},
	}))
	doJSON(t, http.MethodPost, srv.URL+"/api/grants/"+created.ID+"/revoke", nil)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants/"+created.ID+"/renew", struct {
		TTLSeconds int `json:"ttl_seconds"`
	}{TTLSeconds: 3600})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST renew on a revoked grant: status = %d, want 409 (a lapsed grant needs a fresh CreateGrant, not a renewal)", resp.StatusCode)
	}
}

func TestRenewGrant_RequiresTOTP(t *testing.T) {
	srv, _ := testServer(t)

	created := decodeInto[grantView](t, doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{"identity.basic"},
	}))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/grants/"+created.ID+"/renew", bytes.NewReader(mustJSON(t, struct {
		TTLSeconds int `json:"ttl_seconds"`
	}{TTLSeconds: 3600})))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	req.Header.Set("X-Chuvar-TOTP-Code", "000000")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST renew with a wrong TOTP code: status = %d, want 401", resp.StatusCode)
	}
}

func TestStagedDiffs_ListApproveReject(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()

	vec := []float32{1, 0, 0}
	vec384 := make([]float32, 384)
	copy(vec384, vec)

	approveMe, err := st.ProposeDiff(ctx, "agent-a", "user likes tea", []string{"preferences.tea"}, vec384, nil, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	rejectMe, err := st.ProposeDiff(ctx, "agent-a", "user likes coffee", []string{"preferences.coffee"}, vec384, nil, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}

	pending := decodeInto[page[stagedDiffView]](t, doJSON(t, http.MethodGet, srv.URL+"/api/staged-diffs?status=pending", nil)).Items
	if len(pending) != 2 {
		t.Fatalf("pending diffs = %d, want 2", len(pending))
	}

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/staged-diffs?status=bogus", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET /api/staged-diffs with unknown status: status = %d, want 400", resp.StatusCode)
	}

	resp = doJSON(t, http.MethodPost, srv.URL+"/api/staged-diffs/"+approveMe.ID+"/approve", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST approve status = %d, want 200", resp.StatusCode)
	}

	resp = doJSON(t, http.MethodPost, srv.URL+"/api/staged-diffs/"+rejectMe.ID+"/reject", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST reject status = %d, want 204", resp.StatusCode)
	}

	stillPending := decodeInto[page[stagedDiffView]](t, doJSON(t, http.MethodGet, srv.URL+"/api/staged-diffs?status=pending", nil)).Items
	if len(stillPending) != 0 {
		t.Fatalf("pending diffs after decisions = %d, want 0", len(stillPending))
	}
}

// TestStagedDiffs_Pagination_LimitAndCursor covers the new query-param
// contract for GET /api/staged-diffs: limit defaults, is bounded, and the
// cursor walk returns every pending diff exactly once with no next_cursor
// once the walk is exhausted.
func TestStagedDiffs_Pagination_LimitAndCursor(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()

	vec384 := make([]float32, 384)
	const total = 3
	want := make(map[string]bool, total)
	for i := 0; i < total; i++ {
		d, err := st.ProposeDiff(ctx, "agent-a", fmt.Sprintf("fact %d", i), []string{"preferences.tea"}, vec384, nil, nil)
		if err != nil {
			t.Fatalf("ProposeDiff() error = %v", err)
		}
		want[d.ID] = true
	}

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/staged-diffs?status=pending&limit=2", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/staged-diffs?limit=2 status = %d, want 200", resp.StatusCode)
	}
	first := decodeInto[page[stagedDiffView]](t, resp)
	if len(first.Items) != 2 {
		t.Fatalf("first page items = %d, want 2", len(first.Items))
	}
	if first.NextCursor == nil {
		t.Fatal("first page next_cursor = nil, want a cursor (a third row still exists)")
	}

	resp = doJSON(t, http.MethodGet, srv.URL+"/api/staged-diffs?status=pending&limit=2&cursor="+*first.NextCursor, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/staged-diffs with cursor status = %d, want 200", resp.StatusCode)
	}
	second := decodeInto[page[stagedDiffView]](t, resp)
	if len(second.Items) != 1 {
		t.Fatalf("second page items = %d, want 1", len(second.Items))
	}
	if second.NextCursor != nil {
		t.Fatalf("second page next_cursor = %q, want nil (no rows left)", *second.NextCursor)
	}

	got := map[string]bool{}
	for _, d := range append(first.Items, second.Items...) {
		if got[d.ID] {
			t.Fatalf("id %s returned twice across pages", d.ID)
		}
		got[d.ID] = true
	}
	if len(got) != len(want) {
		t.Fatalf("walked %d distinct diffs, want %d", len(got), len(want))
	}
	for id := range want {
		if !got[id] {
			t.Errorf("diff %s never appeared across either page", id)
		}
	}
}

func TestStagedDiffs_Pagination_InvalidLimitRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/staged-diffs?limit=0", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("GET /api/staged-diffs?limit=0: status = %d, want 400", resp.StatusCode)
	}

	resp = doJSON(t, http.MethodGet, srv.URL+"/api/staged-diffs?limit=abc", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("GET /api/staged-diffs?limit=abc: status = %d, want 400", resp.StatusCode)
	}

	resp = doJSON(t, http.MethodGet, srv.URL+fmt.Sprintf("/api/staged-diffs?limit=%d", maxListLimit+1), nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("GET /api/staged-diffs?limit=%d (over max): status = %d, want 400", maxListLimit+1, resp.StatusCode)
	}
}

func TestStagedDiffs_Pagination_InvalidCursorRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/staged-diffs?cursor=not-a-valid-cursor!!", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("GET /api/staged-diffs with a garbage cursor: status = %d, want 400", resp.StatusCode)
	}

	// A well-formed token whose ID half is not a UUID must also be a 400, not
	// a 500 from the ::uuid cast inside the page query — found in review: the
	// parser validated the timestamp but passed the ID through to Postgres.
	badID := base64.RawURLEncoding.EncodeToString([]byte("2026-01-01T00:00:00Z|not-a-uuid"))
	resp = doJSON(t, http.MethodGet, srv.URL+"/api/staged-diffs?cursor="+badID, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("GET /api/staged-diffs with a non-UUID cursor ID: status = %d, want 400", resp.StatusCode)
	}
}

// TestGrants_Pagination_NextCursorAbsentWhenExhausted is the grants-listing
// counterpart of the staged-diffs pagination test above, confirming
// next_cursor is nil once every one of subject's grants has been returned.
func TestGrants_Pagination_NextCursorAbsentWhenExhausted(t *testing.T) {
	srv, _ := testServer(t)

	doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{"identity.basic"},
	})

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a&limit=50", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/grants status = %d, want 200", resp.StatusCode)
	}
	got := decodeInto[page[grantView]](t, resp)
	if len(got.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(got.Items))
	}
	if got.NextCursor != nil {
		t.Fatalf("next_cursor = %q, want nil (only one grant exists)", *got.NextCursor)
	}
}

func TestGetFact_ViaAPI(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()

	vec := make([]float32, 384)
	vec[0] = 1
	d, err := st.ProposeDiff(ctx, "agent-a", "user's favorite color is teal", []string{"preferences.color"}, vec, nil, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	fact, err := st.CommitDiff(ctx, d.ID, "human-reviewer", vec, "")
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/facts/"+fact.ID, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/facts/{id} status = %d, want 200", resp.StatusCode)
	}
	got := decodeInto[factView](t, resp)
	if got.Content != "user's favorite color is teal" {
		t.Errorf("GET /api/facts/{id} content = %q, want the fact's content", got.Content)
	}

	resp = doJSON(t, http.MethodGet, srv.URL+"/api/facts/00000000-0000-0000-0000-000000000000", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /api/facts/{id} for nonexistent fact: status = %d, want 404", resp.StatusCode)
	}
}

func TestApproveStagedDiff_NotFoundReturnsCleanError(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/staged-diffs/00000000-0000-0000-0000-000000000000/approve", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST approve for nonexistent diff: status = %d, want 404", resp.StatusCode)
	}
	body := decodeInto[errorResponse](t, resp)
	if body.Error != "staged diff not found" {
		t.Errorf("error message = %q, want a clean not-found message, not a raw store/driver error", body.Error)
	}
}

// TestApproveStagedDiff_RealDBErrorIsNotMaskedAs404 is the regression test for
// the same error-masking class already fixed for grant requests in this batch
// (TestGrantRequestActions_RealDBErrorIsNotMaskedAs404): approveStagedDiff used
// to turn every GetStagedDiff failure into a 404, so a real database error would
// come back indistinguishable from a bad ID. A syntactically invalid UUID
// triggers a real Postgres error ("invalid input syntax for type uuid"), not
// pgx.ErrNoRows — a realistic way to exercise the non-404 path through an
// ordinary HTTP request, without needing to fake a connection failure.
func TestApproveStagedDiff_RealDBErrorIsNotMaskedAs404(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/staged-diffs/not-a-valid-uuid/approve", nil)
	if resp.StatusCode == http.StatusNotFound {
		t.Fatal("POST approve with a malformed ID: got 404, want a real database error to surface as 500 (not masked as not-found)")
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("POST approve with a malformed ID: status = %d, want 500", resp.StatusCode)
	}
	body := decodeInto[errorResponse](t, resp)
	if body.Error != "could not look up staged diff" {
		t.Errorf("error message = %q, want a clean generic message, not a raw store/driver error", body.Error)
	}
}

func TestRoutes_CORSReflectsConfiguredOriginOnly(t *testing.T) {
	srv, _ := testServer(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()

	got := resp.Header.Get("Access-Control-Allow-Origin")
	if got != "http://localhost:5173" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the configured origin, not a wildcard", got)
	}
}

func TestRoutes_CORSAllowsTOTPHeader(t *testing.T) {
	srv, _ := testServer(t)

	// Without X-Chuvar-TOTP-Code in Access-Control-Allow-Headers, a browser's
	// preflight for any requireStrongFactor-gated mutation (createGrant, approve*,
	// renewGrant) rejects the real request client-side before it reaches the
	// server — the frontend's TOTP-gated actions would be unreachable
	// cross-origin. Found in review.
	req, err := http.NewRequest(http.MethodOptions, srv.URL+"/api/grants", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type,x-chuvar-totp-code")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()

	got := resp.Header.Get("Access-Control-Allow-Headers")
	if !strings.Contains(got, "X-Chuvar-TOTP-Code") {
		t.Errorf("Access-Control-Allow-Headers = %q, want it to include X-Chuvar-TOTP-Code", got)
	}
}

func TestRoutes_OPTIONSPreflightDoesNotRequireAuth(t *testing.T) {
	srv, _ := testServer(t)

	// Browsers never send Authorization on a CORS preflight OPTIONS request — if
	// the auth check ran before CORS, every real cross-origin request from the
	// frontend would fail at the preflight stage before the browser ever got a
	// chance to attach the real request's Authorization header.
	req, err := http.NewRequest(http.MethodOptions, srv.URL+"/api/grants", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Origin", "http://localhost:5173")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("OPTIONS preflight with no Authorization header: status = %d, want 204", resp.StatusCode)
	}
}

func TestNew_WildcardOriginRejected(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New() with CORS_ALLOWED_ORIGIN=\"*\": want panic, got none")
		}
	}()
	New(nil, nil, nil, "*", 10*time.Second, testWebAuthn(t))
}

func TestNew_NullOriginRejected(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal(`New() with CORS_ALLOWED_ORIGIN="null": want panic, got none`)
		}
	}()
	New(nil, nil, nil, "null", 10*time.Second, testWebAuthn(t))
}

func TestNew_OriginWithPathRejected(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New() with a CORS_ALLOWED_ORIGIN containing a path: want panic, got none")
		}
	}()
	New(nil, nil, nil, "http://localhost:5173/app", 10*time.Second, testWebAuthn(t))
}

func TestNew_NonPositiveRequestTimeoutRejected(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New() with a zero RequestTimeout: want panic, got none")
		}
	}()
	New(nil, nil, nil, "", 0, testWebAuthn(t))
}

func TestNew_NilWebAuthnRejected(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New() with a nil WebAuthn: want panic, got none")
		}
	}()
	New(nil, nil, nil, "", 10*time.Second, nil)
}

// slowThenCheckContextEmbedder sleeps past the request timeout, then reports
// whether the context it was given had already been cancelled by the time it
// woke up — the actual thing under test, not just "did the HTTP call time out."
type slowThenCheckContextEmbedder struct {
	sleep    time.Duration
	canceled chan bool
}

func (e slowThenCheckContextEmbedder) Embed(ctx context.Context, _ string) ([]float32, error) {
	select {
	case <-time.After(e.sleep):
		e.canceled <- false
	case <-ctx.Done():
		e.canceled <- true
	}
	return nil, ctx.Err()
}

func TestWithRequestTimeout_CancelsSlowHandlerContext(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, reviewer_tokens, webauthn_credentials, webauthn_challenges, enrollment_latch, grant_requests, data_keys, signing_policies, capability_grant_identities, capability_grant_tokens`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := testSealedStore(t, pool)
	if _, err := st.CreateReviewerToken(ctx, "test-reviewer", testAuthToken, testTOTPSecret); err != nil {
		t.Fatalf("seeding reviewer token: %v", err)
	}
	canceled := make(chan bool, 1)
	// RequestTimeout much shorter than the embedder's sleep: without
	// withRequestTimeout wiring a.RequestTimeout into the handler's context, the
	// embedder would just sleep out its full duration and report canceled=false.
	a := New(st, slowThenCheckContextEmbedder{sleep: 200 * time.Millisecond, canceled: canceled}, summarize.Stub{}, "", 20*time.Millisecond, testWebAuthn(t))
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)

	diff, err := st.ProposeDiff(ctx, "agent-a", "user likes tea", []string{"preferences.tea"}, nil, nil, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/staged-diffs/"+diff.ID+"/approve", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	code, err := totp.GenerateCode(testTOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode() error = %v", err)
	}
	req.Header.Set("X-Chuvar-TOTP-Code", code)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()

	select {
	case wasCanceled := <-canceled:
		if !wasCanceled {
			t.Fatal("embedder's context was never canceled — a.RequestTimeout is not reaching the handler's context")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("embedder never reported back — handler likely hung")
	}
}

func TestLimitBody_OversizedRequestRejected(t *testing.T) {
	srv, _ := testServer(t)

	// Subject has no length validation of its own anywhere in createGrant — that's
	// deliberate here: a check on Subject's length would give this test the same
	// right-status-wrong-reason problem an oversized Scopes entry has (scope.Validate's
	// own MaxLength would reject it first, never exercising MaxBytesReader at all).
	// Without the body limit, this request would fully decode and succeed (201); the
	// limit has to be what turns it into a body-read failure instead.
	oversized := createGrantRequest{
		Subject: strings.Repeat("a", maxRequestBodyBytes+1),
		Scopes:  []string{"identity.basic"},
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", oversized)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with an oversized body: status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateToken_LifecycleIssueAuthenticateRevoke(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/tokens", createTokenRequest{Label: "pi5-tui"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/tokens status = %d, want 201", resp.StatusCode)
	}
	created := decodeInto[createTokenResponse](t, resp)
	if created.Token == "" {
		t.Fatal("POST /api/tokens response did not include a plaintext token")
	}
	if !created.Active {
		t.Error("newly created token should be Active")
	}

	// The new token authenticates a request on its own.
	resp = doJSONWithAuth(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil, created.Token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/grants with the newly issued token: status = %d, want 200", resp.StatusCode)
	}

	// It shows up in the listing (without the plaintext).
	tokens := decodeInto[[]tokenView](t, doJSON(t, http.MethodGet, srv.URL+"/api/tokens", nil))
	found := false
	for _, tk := range tokens {
		if tk.ID == created.ID {
			found = true
			if tk.Label != "pi5-tui" {
				t.Errorf("listed token label = %q, want %q", tk.Label, "pi5-tui")
			}
		}
	}
	if !found {
		t.Error("newly created token not present in GET /api/tokens")
	}

	// Revoke it, then confirm it can no longer authenticate.
	resp = doJSON(t, http.MethodPost, srv.URL+"/api/tokens/"+created.ID+"/revoke", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /api/tokens/{id}/revoke status = %d, want 204", resp.StatusCode)
	}
	resp = doJSONWithAuth(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil, created.Token)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /api/grants with a revoked token: status = %d, want 401", resp.StatusCode)
	}

	// Revoking again should fail, not silently succeed — same "no-op revoke" stance
	// as RevokeGrant.
	resp = doJSON(t, http.MethodPost, srv.URL+"/api/tokens/"+created.ID+"/revoke", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST /api/tokens/{id}/revoke (already revoked) status = %d, want 409", resp.StatusCode)
	}
}

func TestCreateToken_BootstrapTokenCreatesFirstEnrolledDeviceWithoutTOTP(t *testing.T) {
	srv, bootstrapToken := testServerWithBootstrapToken(t)

	// The bootstrap token has no TOTP secret of its own — this is the one
	// call requireStrongFactor-style gating must not block, or the operator could
	// never mint a first real device via the API at all.
	resp := doJSONWithAuth(t, http.MethodPost, srv.URL+"/api/tokens", createTokenRequest{Label: "first-device"}, bootstrapToken)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/tokens from the bootstrap token with zero enrolled devices: status = %d, want 201", resp.StatusCode)
	}
}

func TestCreateToken_RequiresTOTPOnceAnEnrolledDeviceExists(t *testing.T) {
	srv, _ := testServer(t) // testServer seeds one enrolled token already

	// No TOTP header at all: must be rejected once an enrolled device exists,
	// even though this same call would have succeeded against a fresh
	// install (see the bootstrap test above).
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/tokens", bytes.NewReader(mustJSON(t, createTokenRequest{Label: "second-device"})))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/tokens with no TOTP code once a device is enrolled: status = %d, want 401 (closes the self-enrollment bypass — found in review)", resp.StatusCode)
	}
}

func TestCreateToken_BootstrapTokenCannotCreateFurtherTokensOnceEnrolledDeviceExists(t *testing.T) {
	srv, bootstrapTokenValue := testServerWithBootstrapToken(t)

	// Bootstrap creates the first real device — succeeds, no TOTP required
	// (mirrors the test above).
	first := decodeInto[createTokenResponse](t, doJSONWithAuth(t, http.MethodPost, srv.URL+"/api/tokens", createTokenRequest{Label: "first-device"}, bootstrapTokenValue))
	if first.Token == "" {
		t.Fatal("expected the first device token to be created")
	}

	// The bootstrap token tries again, now that one enrolled device exists.
	// It can never supply a valid TOTP code (it has no secret), so this must
	// be rejected — correctly retiring bootstrap back to break-glass-only
	// status rather than letting it keep minting tokens indefinitely.
	resp := doJSONWithAuth(t, http.MethodPost, srv.URL+"/api/tokens", createTokenRequest{Label: "second-device-via-bootstrap"}, bootstrapTokenValue)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/tokens from the (unenrolled) bootstrap token once a real device is enrolled: status = %d, want 401", resp.StatusCode)
	}
}

// TestCreateToken_RevokingEveryEnrolledDeviceDoesNotReopenTheGate is the
// regression test for the escalation the first version of this gate allowed:
// it counted only *active* enrolled tokens, so revocation — bearer-only by
// design, since it "only reduces authority" — could drop that count to zero
// and reopen enrollment to whoever held the stolen bearer token. Counting
// ever-enrolled tokens (revoked included) makes the signal monotonic. Found
// in review of the fix itself, not of the original PR.
func TestCreateToken_RevokingEveryEnrolledDeviceDoesNotReopenTheGate(t *testing.T) {
	srv, bootstrapTokenValue := testServerWithBootstrapToken(t)

	// Bootstrap mints the operator's first (and only) enrolled device.
	enrolled := decodeInto[createTokenResponse](t, doJSONWithAuth(t, http.MethodPost, srv.URL+"/api/tokens", createTokenRequest{Label: "operator-phone"}, bootstrapTokenValue))
	if enrolled.Token == "" {
		t.Fatal("expected the first device token to be created")
	}

	// The attack: holding only the bootstrap bearer token, revoke the enrolled
	// device. Revocation itself is expected to succeed — it is deliberately
	// not TOTP-gated, and gating it would break the legitimate "revoke a lost
	// device from a working one" flow.
	resp := doJSONWithAuth(t, http.MethodPost, srv.URL+"/api/tokens/"+enrolled.ID+"/revoke", nil, bootstrapTokenValue)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST revoke status = %d, want 204", resp.StatusCode)
	}

	// Zero *active* enrolled devices now exist. The gate must stay shut
	// anyway: the enrolled row is retained, so the ever-enrolled count is
	// still 1 and minting still demands a code the attacker cannot produce.
	resp = doJSONWithAuth(t, http.MethodPost, srv.URL+"/api/tokens", createTokenRequest{Label: "attacker-device"}, bootstrapTokenValue)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/tokens after revoking every enrolled device: status = %d, want 401 (revocation must not reopen enrollment)", resp.StatusCode)
	}
}

// TestCreateToken_FactorResetLeavesGateClosedViaLatch is the durable-latch
// regression test: clearing every factor row (the documented break-glass
// recovery) drops both ever-enrolled counts to zero, but the append-only
// enrollment latch survives it, so createToken's gate ("latch OR counts > 0")
// stays closed and a factorless bootstrap token cannot self-enroll during the
// re-bootstrap window. This is principle 12 applied to the enrollment gate:
// the gate counts ever-enrolled, and recovery must take a separate, deliberate
// latch reset — never reopen the gate as a byproduct of clearing factors.
func TestCreateToken_FactorResetLeavesGateClosedViaLatch(t *testing.T) {
	srv, bootstrapTokenValue := testServerWithBootstrapToken(t)

	// Bootstrap mints the operator's first enrolled device; enrolling its TOTP
	// secret sets the durable latch.
	enrolled := decodeInto[createTokenResponse](t, doJSONWithAuth(t, http.MethodPost, srv.URL+"/api/tokens", createTokenRequest{Label: "operator-phone"}, bootstrapTokenValue))
	if enrolled.Token == "" {
		t.Fatal("expected the first device token to be created")
	}

	// Simulate the break-glass recovery's factor-clearing step directly: null
	// every TOTP secret and delete every passkey. Both ever-enrolled counts go
	// to zero — the latch must not.
	ctx := context.Background()
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

	// The gate stays closed: a factorless bearer token still cannot self-enroll.
	resp := doJSONWithAuth(t, http.MethodPost, srv.URL+"/api/tokens", createTokenRequest{Label: "attacker-device"}, bootstrapTokenValue)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/tokens after a full factor reset: status = %d, want 401 (durable latch must keep the gate closed)", resp.StatusCode)
	}
}

// TestCreateToken_EnrolledCallerCanStillMintAfterRevokingAnotherDevice guards
// the flip side of the test above: making the gate monotonic must not break
// the legitimate lost-device flow, where the operator revokes the lost device
// from a working one and mints its replacement.
func TestCreateToken_EnrolledCallerCanStillMintAfterRevokingAnotherDevice(t *testing.T) {
	srv, _ := testServer(t) // seeds one enrolled token (testAuthToken)

	// Mint a second device from the first, then revoke it as if it were lost.
	lost := decodeInto[createTokenResponse](t, doJSON(t, http.MethodPost, srv.URL+"/api/tokens", createTokenRequest{Label: "lost-laptop"}))
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/tokens/"+lost.ID+"/revoke", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST revoke status = %d, want 204", resp.StatusCode)
	}

	// The still-enrolled operator device mints the replacement — doJSON
	// attaches a valid TOTP code for testAuthToken, so this exercises the
	// gate being satisfied rather than bypassed.
	resp = doJSON(t, http.MethodPost, srv.URL+"/api/tokens", createTokenRequest{Label: "replacement-laptop"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/tokens from an enrolled device after revoking another: status = %d, want 201", resp.StatusCode)
	}
}

func TestCreateToken_MissingLabelRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/tokens", createTokenRequest{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/tokens with no label: status = %d, want 400", resp.StatusCode)
	}
}

func TestGrantRequests_ListApproveDeny(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()

	toApprove, err := st.RequestGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "need to greet the user by name")
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	toDeny, err := st.RequestGrant(ctx, "agent-b", []string{"preferences.food"}, "memory", "facts", nil, "")
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}

	pending := decodeInto[[]grantRequestView](t, doJSON(t, http.MethodGet, srv.URL+"/api/grant-requests?status=pending", nil))
	if len(pending) != 2 {
		t.Fatalf("pending grant requests = %d, want 2", len(pending))
	}

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/grant-requests?status=bogus", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET /api/grant-requests with unknown status: status = %d, want 400", resp.StatusCode)
	}

	resp = doJSON(t, http.MethodPost, srv.URL+"/api/grant-requests/"+toApprove.ID+"/approve", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST approve status = %d, want 200", resp.StatusCode)
	}
	approved := decodeInto[grantView](t, resp)
	if !approved.Active {
		t.Error("approving a grant request should produce an Active grant")
	}

	resp = doJSON(t, http.MethodPost, srv.URL+"/api/grant-requests/"+toDeny.ID+"/deny", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST deny status = %d, want 204", resp.StatusCode)
	}

	stillPending := decodeInto[[]grantRequestView](t, doJSON(t, http.MethodGet, srv.URL+"/api/grant-requests?status=pending", nil))
	if len(stillPending) != 0 {
		t.Fatalf("pending grant requests after decisions = %d, want 0", len(stillPending))
	}

	// The subject that had its request approved now actually holds the grant.
	grants := decodeInto[page[grantView]](t, doJSON(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil)).Items
	if len(grants) != 1 {
		t.Fatalf("GET /api/grants?subject=agent-a returned %d grants, want 1", len(grants))
	}

	// Approving/denying again should fail, not silently succeed.
	resp = doJSON(t, http.MethodPost, srv.URL+"/api/grant-requests/"+toApprove.ID+"/approve", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST approve (already approved) status = %d, want 409", resp.StatusCode)
	}
}

func TestCreateToken_WhitespaceOnlyLabelRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/tokens", createTokenRequest{Label: "   "})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/tokens with a whitespace-only label: status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateToken_LabelIsTrimmed(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/tokens", createTokenRequest{Label: "  pi5-tui  "})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/tokens status = %d, want 201", resp.StatusCode)
	}
	created := decodeInto[createTokenResponse](t, resp)
	if created.Label != "pi5-tui" {
		t.Errorf("Label = %q, want trimmed to %q", created.Label, "pi5-tui")
	}
}

func TestGrantRequestActions_NonexistentIDReturns404(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grant-requests/00000000-0000-0000-0000-000000000000/approve", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST approve for nonexistent grant request: status = %d, want 404", resp.StatusCode)
	}

	resp = doJSON(t, http.MethodPost, srv.URL+"/api/grant-requests/00000000-0000-0000-0000-000000000000/deny", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST deny for nonexistent grant request: status = %d, want 404", resp.StatusCode)
	}
}

func TestGrantRequestActions_AlreadyDecidedReturns409(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()

	req, err := st.RequestGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "")
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	if _, err := st.ApproveGrantRequest(ctx, req.ID, "human-reviewer"); err != nil {
		t.Fatalf("ApproveGrantRequest() error = %v", err)
	}

	// The request genuinely exists (so grantRequestExists must not 404 it) but
	// is no longer pending — this must stay a distinguishable 409, not 404.
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grant-requests/"+req.ID+"/approve", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST approve on an already-approved request: status = %d, want 409", resp.StatusCode)
	}
}

// TestGrantRequestActions_RealDBErrorIsNotMaskedAs404 is the regression test
// for the review finding on this same followup PR: the first version of
// grantRequestExists treated *every* GetGrantRequest error as "not found," so
// a real database failure during approve/deny would come back as a 404
// instead of the 500 it actually is — masking the same class of failure
// AuthenticateReviewerToken's own regression test (in this batch) guards
// against, just one layer up. A syntactically invalid UUID triggers a real
// Postgres error ("invalid input syntax for type uuid"), not
// pgx.ErrNoRows — a realistic way to exercise the non-404 path through an
// ordinary HTTP request, without needing to fake a connection failure.
func TestGrantRequestActions_RealDBErrorIsNotMaskedAs404(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grant-requests/not-a-valid-uuid/approve", nil)
	if resp.StatusCode == http.StatusNotFound {
		t.Fatal("POST approve with a malformed ID: got 404, want a real database error to surface as 500 (not masked as not-found)")
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("POST approve with a malformed ID: status = %d, want 500", resp.StatusCode)
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
