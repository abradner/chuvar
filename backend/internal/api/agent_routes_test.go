package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abradner/chuvar/backend/internal/bouncer"
	"github.com/abradner/chuvar/backend/internal/db"
	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/store"
	"github.com/abradner/chuvar/backend/internal/summarize"
)

// agentTestPool sets up (migrate + truncate) a real Postgres connection for
// the agent-surface tests below and returns the pool — callers build their
// own *store.Store (testSealedStore) and *bouncer.Bouncer/API on top,
// because several tests here (the race test in particular) need a custom
// Embedder wired through both, which a one-size-fits-all helper can't
// express cleanly.
func agentTestPool(t *testing.T) *pgxpool.Pool {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, `+
		`reviewer_tokens, agent_tokens, grant_requests, data_keys, capability_grant_identities, `+
		`capability_grant_tokens, signing_policies, webauthn_credentials, webauthn_challenges, `+
		`enrollment_latch, propose_write_rate_limits`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}
	return pool
}

// agentTestEnv bundles a real *store.Store and TWO httptest.Servers standing
// in for cmd/apiserver's two separate listeners — agentSrv serves
// AgentRoutes(), reviewerSrv serves Routes(). Deliberately two servers, not
// one shared mux: production never merges them (agent_routes.go's doc
// comment), and the confused-deputy tests below depend on that actually
// being true, not just on separately-registered mux patterns.
type agentTestEnv struct {
	agentSrv, reviewerSrv *httptest.Server
	st                    *store.Store
	emb                   embed.Embedder
	bouncer               *bouncer.Bouncer
	pool                  *pgxpool.Pool
}

// newAgentTestEnvWithEmbedder builds a full environment against emb — used
// directly by the race test, which needs a custom Embedder wired through
// both the API and the Bouncer built on top of the SAME store.
func newAgentTestEnvWithEmbedder(t *testing.T, pool *pgxpool.Pool, emb embed.Embedder) agentTestEnv {
	t.Helper()
	ctx := context.Background()
	stt := testSealedStore(t, pool)
	if _, err := stt.CreateReviewerToken(ctx, "test-reviewer", testAuthToken, testTOTPSecret); err != nil {
		t.Fatalf("seeding reviewer token: %v", err)
	}
	b := bouncer.New(stt, emb, bouncer.PassthroughClassifier{})
	a := New(stt, emb, summarize.Stub{}, b, testOrigin, 10*time.Second, testWebAuthn(t))

	agentSrv := httptest.NewServer(a.AgentRoutes())
	t.Cleanup(agentSrv.Close)
	reviewerSrv := httptest.NewServer(a.Routes())
	t.Cleanup(reviewerSrv.Close)

	return agentTestEnv{agentSrv: agentSrv, reviewerSrv: reviewerSrv, st: stt, emb: emb, bouncer: b, pool: pool}
}

func newAgentTestEnv(t *testing.T) agentTestEnv {
	t.Helper()
	pool := agentTestPool(t)
	return newAgentTestEnvWithEmbedder(t, pool, embed.Stub{})
}

// mintAgentToken creates a real agent_tokens row for subject and returns its
// plaintext bearer credential — the same shape createAgentToken (POST
// /api/agent-tokens) hands an operator, generated directly against the store
// here for test setup.
func mintAgentToken(t *testing.T, st *store.Store, subject string) string {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	plaintext := base64.URLEncoding.EncodeToString(buf)
	if _, err := st.CreateAgentToken(context.Background(), subject, subject+"-device", plaintext); err != nil {
		t.Fatalf("CreateAgentToken() error = %v", err)
	}
	return plaintext
}

// seedFact stages and commits a fact via the real store pipeline
// (ProposeDiff + CommitDiff) — a fact never legitimately exists without
// going through this path (AGENTS.md §3.1). Returns the committed fact's ID.
func seedFact(t *testing.T, st *store.Store, emb embed.Embedder, subject, content, summary string, scopes []string) string {
	t.Helper()
	ctx := context.Background()
	vec, err := emb.Embed(ctx, content)
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	d, err := st.ProposeDiff(ctx, subject, content, scopes, vec, nil, scopes)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	f, err := st.CommitDiff(ctx, d.ID, "human-reviewer", vec, summary)
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}
	return f.ID
}

func doAgentJSON(t *testing.T, method, url, token string, body any) *http.Response {
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

// doAgentRaw sends rawBody verbatim (no json.Marshal) — used by the
// body-supplied-subject tests, which need to inject a "subject" field the
// real request structs don't declare a field for.
func doAgentRaw(t *testing.T, method, url, token, rawBody string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(rawBody))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func agentDecodeInto[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding response body: %v", err)
	}
	return out
}

// ---------------------------------------------------------------------
// The race: revoke-during-embed must be caught by the re-check (step 5).
// ---------------------------------------------------------------------

// revokingEmbedder wraps a real Embedder and revokes a grant as a side
// effect of Embed — simulating a grant being revoked while an embedding
// call is in flight, deterministically rather than relying on real timing.
// Mirrors internal/mcptools/mcptools_test.go's identical helper exactly:
// this is the HTTP-layer proof of the same property the MCP tool already
// proves, not a different one — see agent_search.go's step 5 comment for
// why both surfaces need this test.
type revokingEmbedder struct {
	embed.Embedder
	st      *store.Store
	grantID string
}

func (e revokingEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	if err := e.st.RevokeGrant(ctx, e.grantID, "test-revoker"); err != nil {
		return nil, err
	}
	return e.Embedder.Embed(ctx, text)
}

// TestAgentSearch_RevokedMidEmbedIsRejected is THE regression test for
// agent_search.go's step 5 (the re-check). It proves the gate stays atomic
// across the embed call: a grant that is valid when the request starts (so
// the pre-embed check at step 3 passes) but gets revoked while Embed is in
// flight must produce insufficient_scope, not a stale-scope "ok". See this
// PR's revert-and-confirm notes for the exact failure this test produces
// when the re-check is removed.
func TestAgentSearch_RevokedMidEmbedIsRejected(t *testing.T) {
	pool := agentTestPool(t)
	ctx := context.Background()

	// Build the store first (no bouncer/API yet) so we can create the grant
	// and know its ID before constructing the revoking embedder that needs
	// it.
	stt := testSealedStore(t, pool)
	if _, err := stt.CreateReviewerToken(ctx, "test-reviewer", testAuthToken, testTOTPSecret); err != nil {
		t.Fatalf("seeding reviewer token: %v", err)
	}
	g, err := stt.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "test-setup")
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	emb := revokingEmbedder{Embedder: embed.Stub{}, st: stt, grantID: g.ID}
	b := bouncer.New(stt, emb, bouncer.PassthroughClassifier{})
	a := New(stt, emb, summarize.Stub{}, b, testOrigin, 10*time.Second, testWebAuthn(t))
	agentSrv := httptest.NewServer(a.AgentRoutes())
	t.Cleanup(agentSrv.Close)

	token := mintAgentToken(t, stt, "agent-a")

	resp := doAgentJSON(t, http.MethodPost, agentSrv.URL+"/api/agent/search", token, agentSearchRequest{
		Query:           "anything",
		RequestedScopes: []string{"identity.basic"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/agent/search status = %d, want 200", resp.StatusCode)
	}
	out := agentDecodeInto[agentSearchResponse](t, resp)
	if out.Status != "insufficient_scope" {
		t.Fatalf("status = %q, want insufficient_scope (the grant was revoked mid-embed; a stale pre-embed snapshot would wrongly return ok)", out.Status)
	}
	if len(out.MissingScopes) != 1 || out.MissingScopes[0] != "identity.basic" {
		t.Fatalf("missing_scopes = %v, want [identity.basic]", out.MissingScopes)
	}

	// The insufficient_scope path must still have audited — the re-check
	// takes the exact same audit branch as an ordinary pre-embed miss.
	rows, err := agentAuditRowsForTest(ctx, pool, "agent-a", "insufficient_scope")
	if err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("insufficient_scope audit rows for agent-a = %d, want exactly 1", len(rows))
	}
}

// ---------------------------------------------------------------------
// Scope-before-rank: an ungranted fact must never appear, even as the top
// semantic match.
// ---------------------------------------------------------------------

func TestAgentSearch_ScopeBeforeRank_UngrantedFactNeverAppears(t *testing.T) {
	env := newAgentTestEnv(t)
	ctx := context.Background()

	const secretContent = "user's confidential medical diagnosis is a rare condition"
	secretID := seedFact(t, env.st, env.emb, "agent-a", secretContent, "a stub summary", []string{"identity.medical"})
	seedFact(t, env.st, env.emb, "agent-a", "user's favorite coffee is a flat white", "a stub summary", []string{"preferences.coffee"})

	if _, err := env.st.CreateGrant(ctx, "agent-a", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	token := mintAgentToken(t, env.st, "agent-a")

	// Querying with the secret fact's OWN exact text guarantees it is the
	// single best semantic (and keyword) match — embed.Stub{} maps
	// identical text to an identical, distance-0 vector, and Postgres
	// full-text search matches it exactly too. If scope-before-rank were
	// broken (filtered after ranking, or not filtered by SQL at all), this
	// is exactly the query that would surface it.
	resp := doAgentJSON(t, http.MethodPost, env.agentSrv.URL+"/api/agent/search", token, agentSearchRequest{
		Query:           secretContent,
		RequestedScopes: []string{"preferences.coffee"},
		Limit:           50,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/agent/search status = %d, want 200", resp.StatusCode)
	}
	out := agentDecodeInto[agentSearchResponse](t, resp)
	if out.Status != "ok" {
		t.Fatalf("status = %q, want ok", out.Status)
	}
	for _, f := range out.Facts {
		if f.ID == secretID {
			t.Fatalf("response included the ungranted identity.medical fact (id=%s) as the top semantic match — scope-before-rank is broken", secretID)
		}
	}
}

// ---------------------------------------------------------------------
// Depth redaction: summary vs facts vs full projected correctly.
// ---------------------------------------------------------------------

func TestAgentSearch_DepthRedaction(t *testing.T) {
	env := newAgentTestEnv(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name  string
		depth string
	}{
		{"summary", "summary"},
		{"facts", "facts"},
		{"full", "full"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subject := "agent-depth-" + tc.name
			scopeName := "identity." + tc.name
			content := fmt.Sprintf("user's %s-depth secret is a specific value", tc.name)
			seedFact(t, env.st, env.emb, subject, content, "a stub summary for "+tc.name, []string{scopeName})
			if _, err := env.st.CreateGrant(ctx, subject, []string{scopeName}, "memory", tc.depth, nil, "human-reviewer"); err != nil {
				t.Fatalf("CreateGrant() error = %v", err)
			}
			token := mintAgentToken(t, env.st, subject)

			resp := doAgentJSON(t, http.MethodPost, env.agentSrv.URL+"/api/agent/search", token, agentSearchRequest{
				Query:           content,
				RequestedScopes: []string{scopeName},
			})
			out := agentDecodeInto[agentSearchResponse](t, resp)
			if out.Status != "ok" || len(out.Facts) != 1 {
				t.Fatalf("search at depth %q: status=%q facts=%+v, want ok with 1 fact", tc.depth, out.Status, out.Facts)
			}
			got := out.Facts[0]
			if got.Depth != tc.depth {
				t.Errorf("Depth = %q, want %q", got.Depth, tc.depth)
			}

			switch tc.depth {
			case "summary":
				if got.Content != "" {
					t.Errorf("Content = %q, want empty at summary depth", got.Content)
				}
				if got.Summary == "" {
					t.Error("Summary is empty at summary depth, want the stub summary")
				}
				if got.Provenance != nil {
					t.Error("Provenance set at summary depth, want nil")
				}
			case "facts":
				if got.Content == "" {
					t.Error("Content is empty at facts depth, want the full content")
				}
				if got.Summary != "" {
					t.Errorf("Summary = %q, want empty at facts depth (mutually exclusive with Content)", got.Summary)
				}
				if got.Provenance != nil {
					t.Error("Provenance set at facts depth, want nil (full-depth-only)")
				}
			case "full":
				if got.Content == "" {
					t.Error("Content is empty at full depth, want the full content")
				}
				if got.Provenance == nil {
					t.Fatal("Provenance is nil at full depth, want the approval trail")
				}
				if got.Provenance.DecidedBy == nil || *got.Provenance.DecidedBy != "human-reviewer" {
					t.Errorf("Provenance.DecidedBy = %v, want \"human-reviewer\"", got.Provenance.DecidedBy)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------
// Disclosure audit: one "read" row per call, per-fact detail.
// ---------------------------------------------------------------------

func TestAgentSearch_DisclosureAudit_OneRowPerCallWithPerFactDetail(t *testing.T) {
	env := newAgentTestEnv(t)
	ctx := context.Background()

	factID := seedFact(t, env.st, env.emb, "agent-a", "user's timezone is UTC", "a stub summary", []string{"identity.timezone"})
	if _, err := env.st.CreateGrant(ctx, "agent-a", []string{"identity.timezone"}, "memory", "full", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	token := mintAgentToken(t, env.st, "agent-a")

	resp := doAgentJSON(t, http.MethodPost, env.agentSrv.URL+"/api/agent/search", token, agentSearchRequest{
		Query:           "timezone",
		RequestedScopes: []string{"identity.timezone"},
	})
	out := agentDecodeInto[agentSearchResponse](t, resp)
	if out.Status != "ok" || len(out.Facts) != 1 {
		t.Fatalf("status=%q facts=%+v, want ok with 1 fact", out.Status, out.Facts)
	}

	rows, err := agentAuditRowsForTest(ctx, env.pool, "agent-a", "read")
	if err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("read audit rows for agent-a = %d, want exactly 1", len(rows))
	}
	var detail store.ReadAuditDetail
	if err := json.Unmarshal(rows[0], &detail); err != nil {
		t.Fatalf("unmarshaling read audit detail: %v", err)
	}
	if len(detail.Facts) != 1 {
		t.Fatalf("read audit detail.Facts = %+v, want exactly 1 entry", detail.Facts)
	}
	if detail.Facts[0].FactID != factID {
		t.Errorf("read audit detail FactID = %q, want %q", detail.Facts[0].FactID, factID)
	}
	if detail.Facts[0].Depth != "full" {
		t.Errorf("read audit detail Depth = %q, want %q", detail.Facts[0].Depth, "full")
	}
}

// agentAuditRowsForTest queries audit_log directly for eventType rows
// belonging to subject, returning each row's raw detail JSON — there is no
// store-layer accessor for this (audit_log is append-only and
// intentionally has no general read API outside the reviewer surface), so
// tests that need to assert on what got audited query it directly, same as
// other packages' equivalent test helpers.
func agentAuditRowsForTest(ctx context.Context, pool *pgxpool.Pool, subject, eventType string) ([][]byte, error) {
	rows, err := pool.Query(ctx, `SELECT detail FROM audit_log WHERE subject = $1 AND event_type = $2 ORDER BY created_at`, subject, eventType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var detail []byte
		if err := rows.Scan(&detail); err != nil {
			return nil, err
		}
		out = append(out, detail)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------
// Confused deputy, both directions.
// ---------------------------------------------------------------------

func TestConfusedDeputy_AgentTokenRejectedOnReviewerListener(t *testing.T) {
	env := newAgentTestEnv(t)
	token := mintAgentToken(t, env.st, "agent-a")

	resp := doAgentJSON(t, http.MethodGet, env.reviewerSrv.URL+"/api/grants?subject=agent-a", token, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reviewer listener with an agent token: status = %d, want 401", resp.StatusCode)
	}
}

func TestConfusedDeputy_ReviewerTokenRejectedOnAgentListener(t *testing.T) {
	env := newAgentTestEnv(t)

	resp := doAgentJSON(t, http.MethodGet, env.agentSrv.URL+"/api/agent/whoami", testAuthToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("agent listener with a reviewer token: status = %d, want 401", resp.StatusCode)
	}
}

func TestAgentRoutes_NoTokenRejected(t *testing.T) {
	env := newAgentTestEnv(t)

	resp := doAgentJSON(t, http.MethodGet, env.agentSrv.URL+"/api/agent/whoami", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("agent listener with no token: status = %d, want 401", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------
// whoami
// ---------------------------------------------------------------------

func TestAgentWhoami_ReturnsAuthenticatedSubject(t *testing.T) {
	env := newAgentTestEnv(t)
	token := mintAgentToken(t, env.st, "agent-a")

	resp := doAgentJSON(t, http.MethodGet, env.agentSrv.URL+"/api/agent/whoami", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/agent/whoami status = %d, want 200", resp.StatusCode)
	}
	out := agentDecodeInto[agentWhoamiResponse](t, resp)
	if out.Subject != "agent-a" {
		t.Errorf("Subject = %q, want %q", out.Subject, "agent-a")
	}
}

// ---------------------------------------------------------------------
// Body-supplied subject is ignored, on every agent endpoint.
// ---------------------------------------------------------------------

func TestAgentSearch_BodySuppliedSubjectIsIgnored(t *testing.T) {
	env := newAgentTestEnv(t)
	ctx := context.Background()

	// alice's own grant covers preferences.coffee; "victim" (a subject
	// alice's token has no relation to) is granted a DIFFERENT, disjoint
	// scope. If the body's "subject":"victim" field were honored, this
	// request would act as victim and see victim's grants/facts instead of
	// alice's own.
	if _, err := env.st.CreateGrant(ctx, "alice", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := env.st.CreateGrant(ctx, "victim", []string{"identity.medical"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	token := mintAgentToken(t, env.st, "alice")

	// Ask for a scope only "victim" holds, while claiming to BE victim in
	// the body. If subject were taken from the body, this would succeed
	// (status=ok); since it must come from the token, alice has no such
	// grant and the request must be insufficient_scope.
	raw := `{"query":"anything","requested_scopes":["identity.medical"],"subject":"victim"}`
	resp := doAgentRaw(t, http.MethodPost, env.agentSrv.URL+"/api/agent/search", token, raw)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/agent/search status = %d, want 200", resp.StatusCode)
	}
	out := agentDecodeInto[agentSearchResponse](t, resp)
	if out.Status != "insufficient_scope" {
		t.Fatalf("status = %q, want insufficient_scope (a body-supplied subject=victim must be ignored; alice holds no identity.medical grant)", out.Status)
	}
}

func TestAgentListGrants_ReturnsOwnGrantsOnly(t *testing.T) {
	env := newAgentTestEnv(t)
	ctx := context.Background()

	if _, err := env.st.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := env.st.CreateGrant(ctx, "agent-b", []string{"identity.sensitive"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	token := mintAgentToken(t, env.st, "agent-a")

	resp := doAgentJSON(t, http.MethodGet, env.agentSrv.URL+"/api/agent/grants", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/agent/grants status = %d, want 200", resp.StatusCode)
	}
	out := agentDecodeInto[agentGrantsResponse](t, resp)
	if len(out.Grants) != 1 || out.Grants[0].Scopes[0] != "identity.basic" {
		t.Fatalf("grants = %+v, want only agent-a's own identity.basic grant", out.Grants)
	}
}

func TestAgentRequestGrant_BodySuppliedSubjectIsIgnored(t *testing.T) {
	env := newAgentTestEnv(t)
	token := mintAgentToken(t, env.st, "alice")

	raw := `{"requested_scopes":["identity.basic"],"subject":"victim"}`
	resp := doAgentRaw(t, http.MethodPost, env.agentSrv.URL+"/api/agent/grant-requests", token, raw)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/agent/grant-requests status = %d, want 201", resp.StatusCode)
	}
	_ = agentDecodeInto[agentGrantRequestResponse](t, resp)

	reqs, err := env.st.ListGrantRequests(context.Background(), store.GrantRequestPending)
	if err != nil {
		t.Fatalf("ListGrantRequests() error = %v", err)
	}
	if len(reqs) != 1 || reqs[0].Subject != "alice" {
		t.Fatalf("grant requests = %+v, want exactly 1 with Subject=alice, not the body-supplied \"victim\"", reqs)
	}
}

func TestAgentRequestGrant_NegativeTTLRejected(t *testing.T) {
	env := newAgentTestEnv(t)
	token := mintAgentToken(t, env.st, "agent-a")

	resp := doAgentJSON(t, http.MethodPost, env.agentSrv.URL+"/api/agent/grant-requests", token, agentGrantRequestRequest{
		RequestedScopes: []string{"identity.basic"},
		TTLSeconds:      -5,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/agent/grant-requests with a negative ttl_seconds: status = %d, want 400", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------
// Proposals: the three-way outcome.
// ---------------------------------------------------------------------

func TestAgentPropose_ValidationError_Returns400Verbatim(t *testing.T) {
	env := newAgentTestEnv(t)
	token := mintAgentToken(t, env.st, "agent-a")

	resp := doAgentJSON(t, http.MethodPost, env.agentSrv.URL+"/api/agent/proposals", token, agentProposalRequest{
		Content:        "some fact",
		ProposedScopes: []string{"Not A Valid Scope"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	out := agentDecodeInto[errorResponse](t, resp)
	if strings.Contains(out.Error, "internal error") {
		t.Fatalf("error = %q, want the validation message verbatim, not the generic masked message", out.Error)
	}
	if !strings.Contains(out.Error, "scope") {
		t.Fatalf("error = %q, want it to mention the malformed scope", out.Error)
	}
}

func TestAgentPropose_StoreErrorIsMasked500(t *testing.T) {
	env := newAgentTestEnv(t)
	ctx := context.Background()

	factID := seedFact(t, env.st, env.emb, "alice", "alice's medical condition is confidential", "", []string{"identity.medical"})
	if _, err := env.st.CreateGrant(ctx, "bob", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	token := mintAgentToken(t, env.st, "bob")

	resp := doAgentJSON(t, http.MethodPost, env.agentSrv.URL+"/api/agent/proposals", token, agentProposalRequest{
		Content:        "innocuous-looking replacement content",
		ProposedScopes: []string{"preferences.coffee"},
		TargetFactID:   factID,
	})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("proposal targeting a fact outside the subject's grants: status = %d, want 500 (masked)", resp.StatusCode)
	}
	out := agentDecodeInto[errorResponse](t, resp)
	if strings.Contains(out.Error, factID) {
		t.Fatalf("error = %q leaked the target fact ID, a store-layer detail that must stay masked", out.Error)
	}
}

func TestAgentPropose_RateLimited_AuditsAndReturns429(t *testing.T) {
	pool := agentTestPool(t)
	ctx := context.Background()
	stt := testSealedStore(t, pool)
	if _, err := stt.CreateReviewerToken(ctx, "test-reviewer", testAuthToken, testTOTPSecret); err != nil {
		t.Fatalf("seeding reviewer token: %v", err)
	}
	emb := embed.Stub{}
	b := bouncer.New(stt, emb, bouncer.PassthroughClassifier{})
	b.RateLimit = 1
	b.RateLimitWindow = time.Hour
	a := New(stt, emb, summarize.Stub{}, b, testOrigin, 10*time.Second, testWebAuthn(t))
	agentSrv := httptest.NewServer(a.AgentRoutes())
	t.Cleanup(agentSrv.Close)

	token := mintAgentToken(t, stt, "agent-a")

	first := doAgentJSON(t, http.MethodPost, agentSrv.URL+"/api/agent/proposals", token, agentProposalRequest{
		Content:        "agent-a fact number 1",
		ProposedScopes: []string{"preferences.coffee"},
	})
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first proposal (within limit): status = %d, want 201", first.StatusCode)
	}
	first.Body.Close()

	second := doAgentJSON(t, http.MethodPost, agentSrv.URL+"/api/agent/proposals", token, agentProposalRequest{
		Content:        "agent-a fact number 2",
		ProposedScopes: []string{"preferences.coffee"},
	})
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second proposal (over limit): status = %d, want 429", second.StatusCode)
	}
	out := agentDecodeInto[agentProposalResponse](t, second)
	if out.Status != "RATE_LIMITED" {
		t.Fatalf("status = %q, want RATE_LIMITED", out.Status)
	}
	if out.DiffID != "" {
		t.Errorf("diff_id = %q, want empty on a rate-limited response", out.DiffID)
	}

	rows, err := agentAuditRowsForTest(ctx, pool, "agent-a", "rate_limited")
	if err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rate_limited audit rows for agent-a = %d, want exactly 1", len(rows))
	}
}

func TestAgentPropose_BodySuppliedSubjectIsIgnored(t *testing.T) {
	env := newAgentTestEnv(t)
	token := mintAgentToken(t, env.st, "alice")

	raw := `{"content":"a fact","proposed_scopes":["preferences.coffee"],"subject":"victim"}`
	resp := doAgentRaw(t, http.MethodPost, env.agentSrv.URL+"/api/agent/proposals", token, raw)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	diffs, err := env.st.ListStagedDiffsBounded(context.Background(), store.DiffPending, 10)
	if err != nil {
		t.Fatalf("listing staged diffs: %v", err)
	}
	if len(diffs) != 1 || diffs[0].Subject != "alice" {
		t.Fatalf("staged diffs = %+v, want exactly 1 with Subject=alice, not the body-supplied \"victim\"", diffs)
	}
}
