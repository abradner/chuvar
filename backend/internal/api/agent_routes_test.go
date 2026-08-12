package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abradner/chuvar/backend/internal/bouncer"
	"github.com/abradner/chuvar/backend/internal/db"
	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/store"
	"github.com/abradner/chuvar/backend/internal/summarize"
)

// agentTestServer spins up an httptest.Server serving ONLY AgentRoutes() —
// the same network-level isolation the real deployment gets from a second
// http.Server on CHUVAR_AGENT_ADDR (cmd/apiserver/main.go) — with a single
// agent-class token seeded for subject. emb, when non-nil, overrides the
// Embedder api.New would otherwise default to (embed.Stub{}); used by the
// race test below to inject a revoke-during-embed side effect
// deterministically rather than relying on real timing. Returns the raw pool
// too (mirroring webauthnTestServer's shape in webauthn_test.go), for the
// handful of tests here that verify audit_log rows directly.
func agentTestServer(t *testing.T, subject string, emb embed.Embedder) (srv *httptest.Server, st *store.Store, pool *pgxpool.Pool, token string) {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, reviewer_tokens, agent_tokens, grant_requests, data_keys, propose_write_rate_limits, capability_grant_identities, capability_grant_tokens, signing_policies, webauthn_credentials, webauthn_challenges, enrollment_latch`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st = testSealedStore(t, pool)
	if emb == nil {
		emb = embed.Stub{}
	}
	b := bouncer.New(st, emb, bouncer.PassthroughClassifier{})
	a := New(st, emb, summarize.Stub{}, testOrigin, 10*time.Second, testWebAuthn(t), b)
	srv = httptest.NewServer(a.AgentRoutes())
	t.Cleanup(srv.Close)

	token = "agent-test-token-" + subject
	if _, err := st.CreateAgentToken(ctx, subject, "test agent: "+subject, token); err != nil {
		t.Fatalf("seeding agent token: %v", err)
	}
	return srv, st, pool, token
}

// doAgentJSON sends a request carrying an agent-class bearer token — the
// analogue of doJSONWithAuth (api_test.go), which only ever attaches a
// reviewer token.
func doAgentJSON(t *testing.T, method, url string, body any, token string) *http.Response {
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

// mustCommitAgentFact stages and immediately approves a fact directly
// through the store, bypassing the human-review queue — a test-only
// shortcut (the same one internal/mcptools' own tests use) for getting a
// committed, searchable fact into place without going through
// POST /api/agent/proposals plus a separate reviewer-approval step for
// every fixture.
func mustCommitAgentFact(t *testing.T, st *store.Store, subject, content string, scopes []string, summary string) store.Fact {
	t.Helper()
	ctx := context.Background()
	vec, err := embed.Stub{}.Embed(ctx, content)
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	diff, err := st.ProposeDiff(ctx, subject, content, scopes, vec, nil, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	fact, err := st.CommitDiff(ctx, diff.ID, "human-reviewer", vec, summary)
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}
	return fact
}

// --- /api/agent/search -------------------------------------------------

func TestAgentSearch_InsufficientScope(t *testing.T) {
	srv, _, _, token := agentTestServer(t, "agent-a", nil)

	resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/search", agentSearchRequest{
		Query:           "coffee preference",
		RequestedScopes: []string{"preferences.coffee"},
	}, token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	out := decodeInto[agentSearchResponse](t, resp)
	if out.Status != "insufficient_scope" {
		t.Fatalf("status = %q, want insufficient_scope", out.Status)
	}
	if len(out.MissingScopes) != 1 || out.MissingScopes[0] != "preferences.coffee" {
		t.Fatalf("missing_scopes = %v, want [preferences.coffee]", out.MissingScopes)
	}
}

func TestAgentSearch_TooManyRequestedScopesRejected(t *testing.T) {
	srv, _, _, token := agentTestServer(t, "agent-a", nil)

	scopes := make([]string, agentMaxScopesPerRequest+1)
	for i := range scopes {
		scopes[i] = "identity.basic"
	}
	resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/search", agentSearchRequest{Query: "x", RequestedScopes: scopes}, token)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAgentSearch_QueryTooLongRejected(t *testing.T) {
	srv, _, _, token := agentTestServer(t, "agent-a", nil)

	resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/search", agentSearchRequest{
		Query:           string(make([]byte, agentMaxQueryLength+1)),
		RequestedScopes: []string{"identity.basic"},
	}, token)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAgentSearch_LimitTooLargeRejected(t *testing.T) {
	srv, _, _, token := agentTestServer(t, "agent-a", nil)

	resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/search", agentSearchRequest{
		Query:           "x",
		RequestedScopes: []string{"identity.basic"},
		Limit:           agentMaxSearchLimit + 1,
	}, token)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// agentRevokingEmbedder wraps a real Embedder and revokes a grant as a side
// effect of Embed — simulating a grant being revoked while an embedding call
// is in flight, deterministically rather than relying on real timing. Same
// idiom as mcptools_test.go's revokingEmbedder, reproduced here (not
// imported: it's unexported in that package, and this file must not import
// internal/mcptools at all — see agent_routes.go's package doc comment on
// why the duplication across these two files is deliberate).
type agentRevokingEmbedder struct {
	embed.Embedder
	st      *store.Store
	grantID string
}

func (e agentRevokingEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	if err := e.st.RevokeGrant(ctx, e.grantID, "test-revoker"); err != nil {
		return nil, err
	}
	return e.Embedder.Embed(ctx, text)
}

// TestAgentSearch_RevokedMidEmbedIsRejected is the proof the atomic gate
// survived the move from an MCP tool call to an HTTP handler: the grant is
// active when the request starts (requested_scopes passes the pre-embed
// check) but gets revoked inside Embed, before SearchFacts runs. Without the
// post-embed re-check in agentSearch, this would return status=ok using the
// stale pre-revocation scope snapshot fetched before Embed ran — see this
// package's revert-and-confirm notes (PR report) for the run where that
// re-check was temporarily removed and this test failed exactly that way.
func TestAgentSearch_RevokedMidEmbedIsRejected(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, reviewer_tokens, agent_tokens, grant_requests, data_keys, propose_write_rate_limits, capability_grant_identities, capability_grant_tokens, signing_policies, webauthn_credentials, webauthn_challenges, enrollment_latch`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := testSealedStore(t, pool)
	g, err := st.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "test-setup")
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	emb := agentRevokingEmbedder{Embedder: embed.Stub{}, st: st, grantID: g.ID}
	b := bouncer.New(st, emb, bouncer.PassthroughClassifier{})
	a := New(st, emb, summarize.Stub{}, testOrigin, 10*time.Second, testWebAuthn(t), b)
	srv := httptest.NewServer(a.AgentRoutes())
	t.Cleanup(srv.Close)

	const token = "agent-race-token"
	if _, err := st.CreateAgentToken(ctx, "agent-a", "race test", token); err != nil {
		t.Fatalf("seeding agent token: %v", err)
	}

	resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/search", agentSearchRequest{
		Query:           "anything",
		RequestedScopes: []string{"identity.basic"},
	}, token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	out := decodeInto[agentSearchResponse](t, resp)
	if out.Status != "insufficient_scope" {
		t.Fatalf("status = %q, want insufficient_scope (the grant was revoked mid-Embed)", out.Status)
	}
}

// TestAgentSearch_ScopeBeforeRank is the proof a fact outside the caller's
// granted scopes never enters the result set, even when it is at least as
// good a keyword match for the query as the fact that IS granted (both
// share the same distinctive phrase, so nothing but the scope filter can be
// keeping the ungranted one out — content strings are deliberately distinct,
// not identical, so CommitDiff's own exact-duplicate-content guard
// (staged_diffs.go) doesn't stand in for the property actually under test
// here). SearchFacts' own candidate_facts CTE is what actually enforces this
// (facts.go's doc comment, AGENTS.md §3.2) — this test's job is proving
// agentSearch doesn't undermine that guarantee by passing SearchFacts a
// broader granted-scope list than the subject actually holds. See this
// package's revert-and-confirm notes (PR report) for the run where
// agentSearch was temporarily modified to append an extra, ungranted scope
// before calling SearchFacts, and this test failed by observing the
// ungranted fact leak through.
func TestAgentSearch_ScopeBeforeRank(t *testing.T) {
	srv, st, _, token := agentTestServer(t, "agent-a", nil)
	ctx := context.Background()

	granted := mustCommitAgentFact(t, st, "agent-a", "the user's favorite coffee order is a flat white, every single morning", []string{"preferences.coffee"}, "coffee summary")
	ungranted := mustCommitAgentFact(t, st, "agent-a", "the user's favorite coffee order is a flat white, no exceptions ever", []string{"preferences.secret"}, "secret summary")

	if _, err := st.CreateGrant(ctx, "agent-a", []string{"preferences.coffee"}, "memory", "full", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/search", agentSearchRequest{
		Query:           "flat white",
		RequestedScopes: []string{"preferences.coffee"},
		Limit:           10,
	}, token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	out := decodeInto[agentSearchResponse](t, resp)
	if out.Status != "ok" {
		t.Fatalf("status = %q, want ok", out.Status)
	}
	found := false
	for _, f := range out.Facts {
		if f.ID == ungranted.ID {
			t.Fatalf("search results include fact %s, tagged with an ungranted scope — scope filter did not run before ranking", ungranted.ID)
		}
		if f.ID == granted.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("search results = %+v, want the granted fact %s present", out.Facts, granted.ID)
	}
}

// TestAgentSearch_DepthRedaction is the HTTP-layer proof of
// mcptools_test.go's summary/facts/full projection tests: Content vs Summary
// are mutually exclusive by depth, and Provenance is present ONLY at "full"
// — over the actual wire JSON, not just the Go struct, so a forgotten
// omitempty or nil-check would show up here exactly as it would to a real
// caller.
func TestAgentSearch_DepthRedaction(t *testing.T) {
	srv, st, _, token := agentTestServer(t, "agent-a", nil)
	ctx := context.Background()

	const content = "user's favorite editor is neovim"
	fact := mustCommitAgentFact(t, st, "agent-a", content, []string{"preferences.tools"}, "editor summary")

	t.Run("summary depth", func(t *testing.T) {
		g, err := st.CreateGrant(ctx, "agent-a", []string{"preferences.tools"}, "memory", "summary", nil, "human-reviewer")
		if err != nil {
			t.Fatalf("CreateGrant() error = %v", err)
		}
		t.Cleanup(func() {
			if err := st.RevokeGrant(ctx, g.ID, "test-cleanup"); err != nil {
				t.Fatalf("RevokeGrant() error = %v", err)
			}
		})

		out := decodeInto[agentSearchResponse](t, doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/search", agentSearchRequest{
			Query: "editor", RequestedScopes: []string{"preferences.tools"},
		}, token))
		if out.Status != "ok" || len(out.Facts) != 1 {
			t.Fatalf("search = %+v, want status ok with 1 fact", out)
		}
		got := out.Facts[0]
		if got.Depth != "summary" {
			t.Errorf("Depth = %q, want summary", got.Depth)
		}
		if got.Content != "" {
			t.Errorf("Content = %q, want empty at summary depth", got.Content)
		}
		if got.Summary != "editor summary" {
			t.Errorf("Summary = %q, want the committed summary", got.Summary)
		}
		if got.Provenance != nil {
			t.Errorf("Provenance at summary depth = %+v, want nil", got.Provenance)
		}
	})

	t.Run("facts depth", func(t *testing.T) {
		g, err := st.CreateGrant(ctx, "agent-a", []string{"preferences.tools"}, "memory", "facts", nil, "human-reviewer")
		if err != nil {
			t.Fatalf("CreateGrant() error = %v", err)
		}
		t.Cleanup(func() {
			if err := st.RevokeGrant(ctx, g.ID, "test-cleanup"); err != nil {
				t.Fatalf("RevokeGrant() error = %v", err)
			}
		})

		out := decodeInto[agentSearchResponse](t, doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/search", agentSearchRequest{
			Query: "editor", RequestedScopes: []string{"preferences.tools"},
		}, token))
		if out.Status != "ok" || len(out.Facts) != 1 {
			t.Fatalf("search = %+v, want status ok with 1 fact", out)
		}
		got := out.Facts[0]
		if got.Depth != "facts" {
			t.Errorf("Depth = %q, want facts", got.Depth)
		}
		if got.Content != content {
			t.Errorf("Content = %q, want %q", got.Content, content)
		}
		if got.Provenance != nil {
			t.Errorf("Provenance at facts depth = %+v, want nil — decided_by must not reach a facts-depth caller", got.Provenance)
		}
	})

	t.Run("full depth", func(t *testing.T) {
		if _, err := st.CreateGrant(ctx, "agent-a", []string{"preferences.tools"}, "memory", "full", nil, "human-reviewer"); err != nil {
			t.Fatalf("CreateGrant() error = %v", err)
		}

		out := decodeInto[agentSearchResponse](t, doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/search", agentSearchRequest{
			Query: "editor", RequestedScopes: []string{"preferences.tools"},
		}, token))
		if out.Status != "ok" || len(out.Facts) != 1 {
			t.Fatalf("search = %+v, want status ok with 1 fact", out)
		}
		got := out.Facts[0]
		if got.Depth != "full" {
			t.Errorf("Depth = %q, want full", got.Depth)
		}
		if got.Provenance == nil {
			t.Fatalf("Provenance at full depth = nil, want the approval trail")
		}
		if got.Provenance.DecidedBy == nil || *got.Provenance.DecidedBy != "human-reviewer" {
			t.Errorf("Provenance.DecidedBy = %v, want human-reviewer", got.Provenance.DecidedBy)
		}
		if got.ID != fact.ID {
			t.Errorf("fact ID = %q, want %q", got.ID, fact.ID)
		}
	})
}

// TestAgentSearch_AuditsPerFactDepth is the HTTP-layer proof of
// mcptools_test.go's identical audit test: one "read" row per call, carrying
// a per-fact disclosure depth (not a single value for the whole call), for
// two facts granted at different depths in the same search.
func TestAgentSearch_AuditsPerFactDepth(t *testing.T) {
	srv, st, pool, token := agentTestServer(t, "agent-a", nil)
	ctx := context.Background()

	coffee := mustCommitAgentFact(t, st, "agent-a", "user's favorite coffee order is a flat white", []string{"preferences.coffee"}, "coffee summary")
	tea := mustCommitAgentFact(t, st, "agent-a", "user's favorite tea order is earl grey", []string{"preferences.tea"}, "tea summary")

	if _, err := st.CreateGrant(ctx, "agent-a", []string{"preferences.coffee"}, "memory", "full", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := st.CreateGrant(ctx, "agent-a", []string{"preferences.tea"}, "memory", "summary", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	out := decodeInto[agentSearchResponse](t, doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/search", agentSearchRequest{
		Query:           "favorite",
		RequestedScopes: []string{"preferences.coffee", "preferences.tea"},
		Limit:           10,
	}, token))
	if out.Status != "ok" || len(out.Facts) != 2 {
		t.Fatalf("search = %+v, want status ok with 2 facts", out)
	}

	wantDepth := map[string]string{coffee.ID: "full", tea.ID: "summary"}
	for _, f := range out.Facts {
		if f.Depth != wantDepth[f.ID] {
			t.Errorf("fact %s Depth = %q, want %q", f.ID, f.Depth, wantDepth[f.ID])
		}
	}

	var detailJSON []byte
	if err := pool.QueryRow(ctx,
		`SELECT detail FROM audit_log WHERE event_type = 'read' AND subject = 'agent-a' ORDER BY created_at DESC LIMIT 1`,
	).Scan(&detailJSON); err != nil {
		t.Fatalf("querying audit_log.detail: %v", err)
	}
	var detail store.ReadAuditDetail
	if err := json.Unmarshal(detailJSON, &detail); err != nil {
		t.Fatalf("unmarshaling audit_log.detail %s: %v", detailJSON, err)
	}
	if len(detail.Facts) != 2 {
		t.Fatalf("audit detail facts = %+v, want 2", detail.Facts)
	}
	gotDepth := make(map[string]string, len(detail.Facts))
	for _, f := range detail.Facts {
		gotDepth[f.FactID] = f.Depth
	}
	for factID, want := range wantDepth {
		if got := gotDepth[factID]; got != want {
			t.Errorf("audit detail depth for fact %s = %q, want %q", factID, got, want)
		}
	}
}

// TestAgentSearch_InsufficientScopeIsAudited proves the insufficient_scope
// branch writes its own audit row (not just the happy path) — the same
// tripwire-must-self-report property propose_write's rate-limit audit
// documents.
func TestAgentSearch_InsufficientScopeIsAudited(t *testing.T) {
	srv, _, pool, token := agentTestServer(t, "agent-a", nil)
	ctx := context.Background()

	resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/search", agentSearchRequest{
		Query:           "coffee",
		RequestedScopes: []string{"preferences.coffee"},
	}, token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	out := decodeInto[agentSearchResponse](t, resp)
	if out.Status != "insufficient_scope" {
		t.Fatalf("status = %q, want insufficient_scope", out.Status)
	}

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE event_type = 'insufficient_scope' AND subject = 'agent-a'`,
	).Scan(&n); err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if n != 1 {
		t.Fatalf("insufficient_scope audit rows = %d, want 1", n)
	}
}

// --- confused deputy, both directions -----------------------------------

// TestAgentListenerRejectsReviewerToken and
// TestReviewerListenerRejectsAgentToken are the confused-deputy proof named
// explicitly in the brief: an agent token must never authenticate on the
// reviewer surface, and a reviewer token must never authenticate on the
// agent surface — even though, in this test process, both muxes are backed
// by the same *API and the same *store.Store (the real defense-in-depth is
// that a deployed agent process can't even reach cfg.HTTPAddr over the
// network — see cmd/apiserver/main.go's runServers — but the auth rejection
// underneath that must hold on its own regardless).
func TestAgentListenerRejectsReviewerToken(t *testing.T) {
	srv, st, _, _ := agentTestServer(t, "agent-a", nil)
	ctx := context.Background()

	const reviewerPlaintext = "a-reviewer-token"
	if _, err := st.CreateReviewerToken(ctx, "some-reviewer", reviewerPlaintext, ""); err != nil {
		t.Fatalf("seeding reviewer token: %v", err)
	}

	resp := doAgentJSON(t, http.MethodGet, srv.URL+"/api/agent/whoami", nil, reviewerPlaintext)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /api/agent/whoami with a reviewer token: status = %d, want 401", resp.StatusCode)
	}
}

func TestReviewerListenerRejectsAgentToken(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()

	const agentPlaintext = "an-agent-token"
	if _, err := st.CreateAgentToken(ctx, "agent-a", "some agent", agentPlaintext); err != nil {
		t.Fatalf("seeding agent token: %v", err)
	}

	resp := doJSONWithAuth(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil, agentPlaintext)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /api/grants with an agent token: status = %d, want 401", resp.StatusCode)
	}
}

// --- body-supplied subject is ignored ------------------------------------

// TestAgentRequestGrant_BodySuppliedSubjectIgnored proves a raw JSON body
// containing an unrecognized "subject" field (none of the agent* request
// structs in agent_routes.go declare one — see that file's package doc
// comment) cannot spoof a different actor: the resulting grant request is
// always attributed to the authenticated agent token's subject.
func TestAgentRequestGrant_BodySuppliedSubjectIgnored(t *testing.T) {
	srv, st, _, token := agentTestServer(t, "agent-a", nil)
	ctx := context.Background()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/agent/grant-requests",
		bytes.NewReader([]byte(`{"subject":"someone-else","requested_scopes":["identity.basic"],"justification":"spoofing attempt"}`)))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	out := decodeInto[agentGrantRequestResponse](t, resp)

	gr, err := st.GetGrantRequest(ctx, out.RequestID)
	if err != nil {
		t.Fatalf("GetGrantRequest() error = %v", err)
	}
	if gr.Subject != "agent-a" {
		t.Fatalf("grant request Subject = %q, want the authenticated agent's subject %q (body-supplied \"subject\" must be ignored)", gr.Subject, "agent-a")
	}
}

// --- /api/agent/proposals ------------------------------------------------

func TestAgentProposals_HappyPath(t *testing.T) {
	srv, _, _, token := agentTestServer(t, "agent-a", nil)

	resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/proposals", agentProposalRequest{
		Content:        "user's favorite coffee order is a flat white",
		ProposedScopes: []string{"preferences.coffee"},
	}, token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	out := decodeInto[agentProposalResponse](t, resp)
	if out.Status != "pending" {
		t.Fatalf("status = %q, want pending", out.Status)
	}
	if out.DedupeVerdict != "novel" {
		t.Fatalf("dedupe_verdict = %q, want novel", out.DedupeVerdict)
	}
	if out.DiffID == "" {
		t.Fatal("diff_id is empty")
	}
}

// TestAgentProposals_ValidationErrorVerbatim is the regression test for the
// bouncer.ValidationError taxonomy at the HTTP boundary: a malformed
// caller-supplied scope is safe and useful to show verbatim (400), unlike
// any other proposals failure, which stays masked behind a generic 500 —
// same distinction propose_write.go's own doc comment draws.
func TestAgentProposals_ValidationErrorVerbatim(t *testing.T) {
	srv, _, _, token := agentTestServer(t, "agent-a", nil)

	resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/proposals", agentProposalRequest{
		Content:        "some fact",
		ProposedScopes: []string{"Not A Valid Scope"},
	}, token)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body := decodeInto[errorResponse](t, resp)
	if body.Error == "" || body.Error == "could not process proposal" {
		t.Fatalf("error = %q, want the validation message verbatim, not the generic masked message", body.Error)
	}
}

// TestAgentProposals_StoreErrorMasked is the negative counterpart: an error
// originating in the store layer (here, targeting a fact outside the
// proposer's grants) must never be shown verbatim, even though its message
// happens to be informative in this particular case — only errors positively
// constructed as bouncer.ValidationError are safe to return as-is.
func TestAgentProposals_StoreErrorMasked(t *testing.T) {
	srv, st, _, aliceToken := agentTestServer(t, "alice", nil)
	ctx := context.Background()

	proposed := decodeInto[agentProposalResponse](t, doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/proposals", agentProposalRequest{
		Content:        "alice's medical condition is confidential",
		ProposedScopes: []string{"identity.medical"},
	}, aliceToken))

	commitVec, err := embed.Stub{}.Embed(ctx, "alice's medical condition is confidential")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	fact, err := st.CommitDiff(ctx, proposed.DiffID, "human-reviewer", commitVec, "")
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	// bob has a real, active grant, just not one covering identity.medical.
	if _, err := st.CreateGrant(ctx, "bob", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	const bobToken = "bob-agent-token"
	if _, err := st.CreateAgentToken(ctx, "bob", "bob's agent", bobToken); err != nil {
		t.Fatalf("seeding agent token: %v", err)
	}

	resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/proposals", agentProposalRequest{
		Content:        "innocuous-looking replacement content",
		ProposedScopes: []string{"preferences.coffee"},
		TargetFactID:   fact.ID,
	}, bobToken)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (masked store error)", resp.StatusCode)
	}
	body := decodeInto[errorResponse](t, resp)
	if body.Error != "could not process proposal" {
		t.Fatalf("error = %q, want the generic masked message", body.Error)
	}
	if bytes.Contains([]byte(body.Error), []byte(fact.ID)) {
		t.Fatalf("error = %q leaked the target fact ID, a store-layer detail that must stay masked", body.Error)
	}
}

// TestAgentProposals_RateLimited is the HTTP-layer proof of
// mcptools_test.go's TestProposeWrite_RateLimited: hitting a low configured
// limit surfaces as a structured 429 with status=RATE_LIMITED, and it is
// audited.
func TestAgentProposals_RateLimited(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, reviewer_tokens, agent_tokens, grant_requests, data_keys, propose_write_rate_limits, capability_grant_identities, capability_grant_tokens, signing_policies, webauthn_credentials, webauthn_challenges, enrollment_latch`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := testSealedStore(t, pool)
	emb := embed.Stub{}
	b := bouncer.New(st, emb, bouncer.PassthroughClassifier{})
	b.RateLimit = 2
	b.RateLimitWindow = time.Hour
	a := New(st, emb, summarize.Stub{}, testOrigin, 10*time.Second, testWebAuthn(t), b)
	srv := httptest.NewServer(a.AgentRoutes())
	t.Cleanup(srv.Close)

	const token = "agent-rate-limit-token"
	if _, err := st.CreateAgentToken(ctx, "agent-a", "rate limit test", token); err != nil {
		t.Fatalf("seeding agent token: %v", err)
	}

	for i := 0; i < 2; i++ {
		resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/proposals", agentProposalRequest{
			Content:        "fact number",
			ProposedScopes: []string{"preferences.coffee"},
		}, token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("proposal %d: status = %d, want 200", i, resp.StatusCode)
		}
	}

	resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/proposals", agentProposalRequest{
		Content:        "one too many",
		ProposedScopes: []string{"preferences.coffee"},
	}, token)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	out := decodeInto[agentProposalResponse](t, resp)
	if out.Status != "RATE_LIMITED" {
		t.Fatalf("status = %q, want RATE_LIMITED", out.Status)
	}
	if out.DiffID != "" {
		t.Fatalf("diff_id = %q, want empty — nothing should be staged once rate-limited", out.DiffID)
	}

	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE event_type = 'rate_limited' AND subject = 'agent-a'`).Scan(&n); err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if n != 1 {
		t.Fatalf("rate_limited audit rows = %d, want 1", n)
	}
}

// --- /api/agent/grants ------------------------------------------------------

func TestAgentListGrants_OwnGrantsOnly(t *testing.T) {
	srv, st, _, aliceToken := agentTestServer(t, "alice", nil)
	ctx := context.Background()

	if _, err := st.CreateGrant(ctx, "alice", []string{"identity.sensitive"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := st.CreateGrant(ctx, "bob", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	out := decodeInto[agentGrantsResponse](t, doAgentJSON(t, http.MethodGet, srv.URL+"/api/agent/grants", nil, aliceToken))
	if len(out.Grants) != 1 || out.Grants[0].Scopes[0] != "identity.sensitive" {
		t.Fatalf("agent/grants = %+v, want only alice's own identity.sensitive grant", out.Grants)
	}
	if !out.Grants[0].Active {
		t.Error("grant should be Active")
	}
}

// --- /api/agent/grant-requests -----------------------------------------

func TestAgentRequestGrant_HappyPath(t *testing.T) {
	srv, st, _, token := agentTestServer(t, "agent-a", nil)
	ctx := context.Background()

	out := decodeInto[agentGrantRequestResponse](t, doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/grant-requests", agentGrantRequestRequest{
		RequestedScopes: []string{"identity.basic"},
		Justification:   "need this to answer a question",
	}, token))
	if out.Status != "pending" {
		t.Fatalf("status = %q, want pending", out.Status)
	}
	if out.RequestID == "" {
		t.Fatal("request_id is empty")
	}

	granted, err := st.GrantedScopes(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopes() error = %v", err)
	}
	if len(granted) != 0 {
		t.Fatalf("GrantedScopes() after grant-requests = %v, want empty (no auto-approval)", granted)
	}
}

// TestAgentRequestGrant_NegativeTTLRejected is the HTTP-layer regression
// test for request_grant.go's fix: a negative ttl_seconds must not silently
// collapse into "no expiry requested," the same outcome an omitted one
// produces.
func TestAgentRequestGrant_NegativeTTLRejected(t *testing.T) {
	srv, _, _, token := agentTestServer(t, "agent-a", nil)

	resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/grant-requests", agentGrantRequestRequest{
		RequestedScopes: []string{"identity.basic"},
		TTLSeconds:      -60,
	}, token)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAgentRequestGrant_EmptyScopesRejected(t *testing.T) {
	srv, _, _, token := agentTestServer(t, "agent-a", nil)

	resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/grant-requests", agentGrantRequestRequest{}, token)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAgentRequestGrant_InvalidScopeRejected(t *testing.T) {
	srv, _, _, token := agentTestServer(t, "agent-a", nil)

	resp := doAgentJSON(t, http.MethodPost, srv.URL+"/api/agent/grant-requests", agentGrantRequestRequest{
		RequestedScopes: []string{"Not A Valid Scope"},
	}, token)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// --- /api/agent/whoami -------------------------------------------------

func TestAgentWhoami_ReturnsAuthenticatedSubject(t *testing.T) {
	srv, _, _, token := agentTestServer(t, "agent-whoami-subject", nil)

	out := decodeInto[agentWhoamiResponse](t, doAgentJSON(t, http.MethodGet, srv.URL+"/api/agent/whoami", nil, token))
	if out.Subject != "agent-whoami-subject" {
		t.Fatalf("subject = %q, want %q", out.Subject, "agent-whoami-subject")
	}
}

func TestAgentWhoami_NoTokenRejected(t *testing.T) {
	srv, _, _, _ := agentTestServer(t, "agent-a", nil)

	resp := doAgentJSON(t, http.MethodGet, srv.URL+"/api/agent/whoami", nil, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAgentWhoami_RevokedTokenRejected(t *testing.T) {
	srv, st, _, token := agentTestServer(t, "agent-a", nil)
	ctx := context.Background()

	tokens, err := st.ListAgentTokens(ctx)
	if err != nil {
		t.Fatalf("ListAgentTokens() error = %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("ListAgentTokens() = %d tokens, want 1", len(tokens))
	}
	if err := st.RevokeAgentToken(ctx, tokens[0].ID); err != nil {
		t.Fatalf("RevokeAgentToken() error = %v", err)
	}

	resp := doAgentJSON(t, http.MethodGet, srv.URL+"/api/agent/whoami", nil, token)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (revoked token)", resp.StatusCode)
	}
}
