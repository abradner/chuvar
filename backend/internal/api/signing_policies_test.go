package api

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestUpsertAndGetSigningPolicy(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/signing-policies", upsertSigningPolicyRequest{
		Repo:   "github.com/abradner/chuvar",
		Policy: "required",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/signing-policies status = %d, want 200", resp.StatusCode)
	}
	created := decodeInto[signingPolicyView](t, resp)
	if created.Repo != "github.com/abradner/chuvar" || created.Policy != "required" {
		t.Fatalf("POST /api/signing-policies response = %+v, want repo/policy round-tripped", created)
	}
	if created.SetBy != "test-reviewer" {
		t.Fatalf("POST /api/signing-policies set_by = %q, want the authenticated reviewer's label, not a request-body field", created.SetBy)
	}

	resp = doJSON(t, http.MethodGet, srv.URL+"/api/signing-policies/github.com/abradner/chuvar", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/signing-policies/{repo} status = %d, want 200", resp.StatusCode)
	}
	got := decodeInto[signingPolicyView](t, resp)
	if got.Policy != "required" {
		t.Fatalf("GET /api/signing-policies/{repo} = %+v, want policy=required", got)
	}
}

// TestUpsertSigningPolicy_SecondCallReplacesTheFirst exercises the upsert
// through the REST surface end to end: a reviewer changing their mind about a
// repo's policy must see the change on the very next GET.
func TestUpsertSigningPolicy_SecondCallReplacesTheFirst(t *testing.T) {
	srv, _ := testServer(t)

	doJSON(t, http.MethodPost, srv.URL+"/api/signing-policies", upsertSigningPolicyRequest{
		Repo:   "github.com/abradner/chuvar",
		Policy: "preferred",
	})
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/signing-policies", upsertSigningPolicyRequest{
		Repo:   "github.com/abradner/chuvar",
		Policy: "off",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/signing-policies (second) status = %d, want 200", resp.StatusCode)
	}

	got := decodeInto[signingPolicyView](t, doJSON(t, http.MethodGet, srv.URL+"/api/signing-policies/github.com/abradner/chuvar", nil))
	if got.Policy != "off" {
		t.Fatalf("GET /api/signing-policies/{repo} after a second upsert = %+v, want the replaced value \"off\"", got)
	}
}

func TestGetSigningPolicy_UnconfiguredRepoReturns404(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/signing-policies/github.com/never-configured/repo", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /api/signing-policies/{repo} for an unconfigured repo: status = %d, want 404", resp.StatusCode)
	}
}

// TestGetSigningPolicy_RealDBErrorIsNotMaskedAs404 is the signing-policy
// analogue of TestApproveStagedDiff_RealDBErrorIsNotMaskedAs404/
// TestGrantRequestActions_RealDBErrorIsNotMaskedAs404: an embedded NUL byte
// (percent-encoded in the URL, so it survives net/http's own path parsing and
// reaches the handler) is not valid PostgreSQL text and triggers a real
// SQLSTATE 22021 from the database, not pgx.ErrNoRows — this must surface as
// a 500 an operator would investigate, not an indistinguishable 404 that
// reads as "this repo just isn't configured."
func TestGetSigningPolicy_RealDBErrorIsNotMaskedAs404(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/signing-policies/abc%00def", nil)
	if resp.StatusCode == http.StatusNotFound {
		t.Fatal("GET /api/signing-policies/{repo} with an embedded NUL byte: got 404, want a real database error to surface as 500 (not masked as not-found)")
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET /api/signing-policies/{repo} with an embedded NUL byte: status = %d, want 500", resp.StatusCode)
	}
	body := decodeInto[errorResponse](t, resp)
	if body.Error != "could not look up signing policy" {
		t.Errorf("error message = %q, want a clean generic message, not a raw store/driver error", body.Error)
	}
}

func TestUpsertSigningPolicy_InvalidPolicyRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/signing-policies", upsertSigningPolicyRequest{
		Repo:   "github.com/abradner/chuvar",
		Policy: "bogus",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/signing-policies with invalid policy: status = %d, want 400", resp.StatusCode)
	}
}

func TestUpsertSigningPolicy_EmptyRepoRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/signing-policies", upsertSigningPolicyRequest{
		Repo:   "",
		Policy: "required",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/signing-policies with empty repo: status = %d, want 400", resp.StatusCode)
	}
}

func TestUpsertSigningPolicy_WhitespaceInRepoRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/signing-policies", upsertSigningPolicyRequest{
		Repo:   "github.com/abradner/chu var",
		Policy: "required",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/signing-policies with whitespace in repo: status = %d, want 400", resp.StatusCode)
	}
}

func TestUpsertSigningPolicy_OversizedRepoRejected(t *testing.T) {
	srv, _ := testServer(t)

	oversized := make([]byte, maxRepoLength+1)
	for i := range oversized {
		oversized[i] = 'a'
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/signing-policies", upsertSigningPolicyRequest{
		Repo:   string(oversized),
		Policy: "required",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/signing-policies with an oversized repo: status = %d, want 400", resp.StatusCode)
	}
}

// TestUpsertSigningPolicy_RequiresTOTP is the self-escalation guard this
// batch's other requireTOTP-gated mutations already have (see
// TestRenewGrant_RequiresTOTP): a bearer token alone, without a valid TOTP
// code, must not be able to set or downgrade a repo's signing policy.
func TestUpsertSigningPolicy_RequiresTOTP(t *testing.T) {
	srv, _ := testServer(t)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/signing-policies", bytes.NewReader(mustJSON(t, upsertSigningPolicyRequest{
		Repo:   "github.com/abradner/chuvar",
		Policy: "required",
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
		t.Fatalf("POST /api/signing-policies with a wrong TOTP code: status = %d, want 401", resp.StatusCode)
	}
}

// TestGetSigningPolicy_NotGatedByTOTP confirms the read path stays
// bearer-only, matching listGrants/listTokens: this is also issue #94's
// preflight read, which a signing shim needs to call without prompting for a
// second factor on every commit.
func TestGetSigningPolicy_NotGatedByTOTP(t *testing.T) {
	srv, _ := testServer(t)

	doJSON(t, http.MethodPost, srv.URL+"/api/signing-policies", upsertSigningPolicyRequest{
		Repo:   "github.com/abradner/chuvar",
		Policy: "required",
	})

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/signing-policies/github.com/abradner/chuvar", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/signing-policies/{repo} with no TOTP header: status = %d, want 200", resp.StatusCode)
	}
}

// TestValidateRepo unit-tests validateRepo directly rather than only through
// the HTTP round trip TestUpsertSigningPolicy_OversizedRepoRejected/
// TestUpsertSigningPolicy_WhitespaceInRepoRejected exercise. It exists to pin
// down validateRepo's doc comment: unlike the empty-repo case (backed by
// store.UpsertSigningPolicy's own repo == "" guard), the length and
// whitespace checks are NOT backed by the store or any DB constraint —
// validateRepo is their only enforcement. This test (and the two HTTP-level
// tests above) is what would catch a future edit that deletes those branches
// on the mistaken belief that something further down the stack still guards
// them.
func TestValidateRepo(t *testing.T) {
	oversized := strings.Repeat("a", maxRepoLength+1)

	cases := []struct {
		name    string
		repo    string
		wantErr bool
	}{
		{"valid", "github.com/abradner/chuvar", false},
		{"empty", "", true},
		{"oversized", oversized, true},
		{"at max length", strings.Repeat("a", maxRepoLength), false},
		{"space", "github.com/abradner/chu var", true},
		{"tab", "github.com/abradner/chu\tvar", true},
		{"newline", "github.com/abradner/chu\nvar", true},
		{"unicode whitespace (NBSP)", "github.com/abradner/chu var", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRepo(tc.repo)
			if tc.wantErr && err == nil {
				t.Fatalf("validateRepo(%q) = nil, want an error", tc.repo)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateRepo(%q) = %v, want nil", tc.repo, err)
			}
		})
	}
}
