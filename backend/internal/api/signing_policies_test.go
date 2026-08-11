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
//
// The NUL is embedded inside an otherwise-canonical host/owner/repo
// ("github.com/abradner/chu\x00var") on purpose: it must survive validateRepo
// (finding 1's canonical-form check now rejects a bare "abc\x00def" as a 400
// before it reaches the store) yet still reach the database as a value the
// driver rejects, so this assertion exercises the store-error-vs-404 guard, not
// the input validator.
func TestGetSigningPolicy_RealDBErrorIsNotMaskedAs404(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/signing-policies/github.com/abradner/chu%00var", nil)
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

// TestUpsertSigningPolicy_NonCanonicalRepoRejected is finding 1's write-path
// guard: a repo spelled as anything other than the bare canonical target form
// (github.com/owner/repo) is a clean 400 at upsert, so a human can never store
// a `required` policy under a divergent spelling that a later canonical lookup
// would read as absent. Each of these denotes the SAME repository as the
// canonical github.com/abradner/chuvar.
func TestUpsertSigningPolicy_NonCanonicalRepoRejected(t *testing.T) {
	srv, _ := testServer(t)

	for _, repo := range []string{
		"github.com/abradner/chuvar.git",
		"https://github.com/abradner/chuvar",
		"github.com/abradner/chuvar/",
		// Finding 1(b): case divergence in owner/repo — GitHub treats these
		// paths case-insensitively, so this must not key a second row
		// alongside the canonical lowercase spelling.
		"github.com/ABRADNER/CHUVAR",
		// Finding 2: a fourth path segment must not be accepted as a
		// distinct, non-canonical key.
		"github.com/abradner/chuvar/extra",
	} {
		t.Run(repo, func(t *testing.T) {
			resp := doJSON(t, http.MethodPost, srv.URL+"/api/signing-policies", upsertSigningPolicyRequest{
				Repo:   repo,
				Policy: "required",
			})
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("POST /api/signing-policies with non-canonical repo %q: status = %d, want 400", repo, resp.StatusCode)
			}
		})
	}
}

// TestGetSigningPolicy_NonCanonicalRepoRejected is the read-path half: a lookup
// under a non-canonical spelling is a clean 400, never a silent miss that reads
// as "no policy set" (a 404). Without the same validation on the GET path, an
// agent-controlled remote spelling could probe as unconfigured and be treated
// as not-required — the fail-open this table exists to prevent.
func TestGetSigningPolicy_NonCanonicalRepoRejected(t *testing.T) {
	srv, _ := testServer(t)

	// A canonical policy exists; the point is that a divergent spelling of the
	// same repo does not resolve to it AND does not read as unconfigured.
	doJSON(t, http.MethodPost, srv.URL+"/api/signing-policies", upsertSigningPolicyRequest{
		Repo:   "github.com/abradner/chuvar",
		Policy: "required",
	})

	for _, repo := range []string{
		"github.com/abradner/chuvar.git",
		"https://github.com/abradner/chuvar",
		"github.com/abradner/chuvar/",
		// Finding 1(b): case divergence in owner/repo.
		"github.com/ABRADNER/CHUVAR",
		// Finding 2: a fourth path segment.
		"github.com/abradner/chuvar/extra",
	} {
		t.Run(repo, func(t *testing.T) {
			resp := doJSON(t, http.MethodGet, srv.URL+"/api/signing-policies/"+repo, nil)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("GET /api/signing-policies/%s: status = %d, want 400 (a clean rejection, not a 404 that reads as no-policy)", repo, resp.StatusCode)
			}
		})
	}
}

// TestGetSigningPolicy_MuxCleanedPathRejected is finding 3's HTTP round-trip
// closure. net/http.ServeMux cleans a request path containing doubled
// slashes or "."/".." segments and issues its own redirect BEFORE any
// registered handler runs — so TestValidateRepo's direct-call coverage of
// those same spellings (the "doubled slash"/"dot segment"/"dot-dot traversal
// segment" cases) never proves anything about what a real HTTP client
// receives. This test drives the request through a.Routes() with a client
// that does NOT follow redirects (http.ErrUseLastResponse) — the posture a
// signing shim should reasonably take, since following the redirect here
// would mean silently reading whatever policy is stored under a different,
// mux-rewritten key than the one the caller asked for — and asserts the
// reject-not-rewrite promise actually holds: a clean 400, not net/http's own
// redirect.
//
// A canonical policy is seeded first so a regression that silently followed
// the mux's cleaning internally (rather than rejecting before it) would show
// up as a 200 under the wrong key, the sharper failure mode finding 3 warns
// about, not merely a 404.
func TestGetSigningPolicy_MuxCleanedPathRejected(t *testing.T) {
	srv, _ := testServer(t)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	doJSON(t, http.MethodPost, srv.URL+"/api/signing-policies", upsertSigningPolicyRequest{
		Repo:   "github.com/abradner/chuvar",
		Policy: "required",
	})

	for _, path := range []string{
		"/api/signing-policies/github.com//abradner/chuvar",
		"/api/signing-policies/github.com/./abradner/chuvar",
		"/api/signing-policies/github.com/abradner/../chuvar",
	} {
		t.Run(path, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+testAuthToken)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request error: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusMovedPermanently {
				t.Fatalf("GET %s: status = %d (net/http's own mux-cleaning redirect), want a clean 400 — the reject-not-rewrite promise must be reachable over HTTP, not merely true of validateRepo called directly", path, resp.StatusCode)
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("GET %s: status = %d, want 400", path, resp.StatusCode)
			}
		})
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
	// A canonical host/owner/repo padded out to exactly maxRepoLength — the
	// length branch has to be exercisable without tripping the canonical-form
	// branch, so this stays host/owner/repo shaped rather than a bare run of
	// 'a's (which is now rejected as non-canonical, not for length).
	canonicalPrefix := "github.com/abradner/"
	atMaxLength := canonicalPrefix + strings.Repeat("a", maxRepoLength-len(canonicalPrefix))

	cases := []struct {
		name    string
		repo    string
		wantErr bool
	}{
		{"valid", "github.com/abradner/chuvar", false},
		{"empty", "", true},
		{"oversized", oversized, true},
		{"at max length", atMaxLength, false},
		{"space", "github.com/abradner/chu var", true},
		{"tab", "github.com/abradner/chu\tvar", true},
		{"newline", "github.com/abradner/chu\nvar", true},
		{"unicode whitespace (NBSP)", "github.com/abradner/chu var", true},
		// Divergent spellings of github.com/abradner/chuvar that must all be
		// rejected so no two of them can key different signing_policies rows.
		{".git clone suffix", "github.com/abradner/chuvar.git", true},
		{"https URL form", "https://github.com/abradner/chuvar", true},
		{"http URL form", "http://github.com/abradner/chuvar", true},
		{"git URL form", "git://github.com/abradner/chuvar", true},
		{"trailing slash", "github.com/abradner/chuvar/", true},
		{"leading slash", "/github.com/abradner/chuvar", true},
		{"doubled slash", "github.com//abradner/chuvar", true},
		{"dot-dot traversal segment", "github.com/abradner/../chuvar", true},
		{"dot segment", "github.com/./abradner/chuvar", true},
		{"uppercase host", "GitHub.com/abradner/chuvar", true},
		{"missing repo segment", "github.com/abradner", true},
		{"bare string, no slashes", "chuvar", true},
		// Finding 1(a): a trailing DNS root dot on the host names the same
		// host as without it, so it must not key a distinct row.
		{"trailing DNS root dot on host", "github.com./abradner/chuvar", true},
		// Finding 1(b): GitHub treats owner/repo case-insensitively, and the
		// store compares repo byte-for-byte, so any case divergence anywhere
		// in the string (not just the host) must be rejected.
		{"uppercase owner and repo", "github.com/ABRADNER/CHUVAR", true},
		{"uppercase repo only", "github.com/abradner/CHUVAR", true},
		// Finding 2: exactly host/owner/repo — a fourth segment must be
		// rejected, not silently accepted as "at least 3".
		{"extra path segment", "github.com/abradner/chuvar/extra", true},
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
