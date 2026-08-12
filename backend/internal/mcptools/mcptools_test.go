package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/agentclient"
	"github.com/abradner/chuvar/backend/internal/api"
	"github.com/abradner/chuvar/backend/internal/bouncer"
	"github.com/abradner/chuvar/backend/internal/db"
	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/store"
	"github.com/abradner/chuvar/backend/internal/summarize"
)

// Post-cutover (ticket E3, #82/#86 PR 4), this package no longer touches
// Postgres, an Embedder, or a Bouncer directly — every tool is a thin HTTP
// client of internal/api's agent-facing surface. These tests therefore drive
// the full real path: a genuine *api.API serving AgentRoutes() over
// httptest, an agent-class token minted directly through the store (the same
// shortcut a human reviewer's mint action stands in for, since minting over
// HTTP needs a second factor by design), and an *agentclient.Client built
// against that server. This is deliberately the same shape as
// internal/api/agent_routes_test.go's own agentTestServer helper —
// reproduced here rather than imported, because that package (a branch below
// this PR) is off-limits to modify, and importing its unexported test
// helpers isn't possible from another package anyway.

const (
	testRPID   = "localhost"
	testOrigin = "http://localhost:5173"
)

func testWebAuthn(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          testRPID,
		RPDisplayName: "Chuvar mcptools test",
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

// testPool opens a migrated, truncated connection to DATABASE_URL, skipping
// the test entirely if it isn't set — matching every other integration test
// in this codebase (AGENTS.md §4).
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping mcptools integration tests")
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, agent_tokens, grant_requests, data_keys, propose_write_rate_limits, capability_grant_identities, capability_grant_tokens`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}
	return pool
}

// testHarness bundles a real store, bouncer and api.API serving AgentRoutes()
// over httptest — everything a test needs both to drive tools through a real
// HTTP+MCP round trip (session) and to reach into the store directly for
// fixtures a human reviewer would normally provide (grants, committed facts).
type testHarness struct {
	pool *pgxpool.Pool
	st   *store.Store
	b    *bouncer.Bouncer
	srv  *httptest.Server
}

func newTestHarness(t *testing.T, emb embed.Embedder) *testHarness {
	t.Helper()
	pool := testPool(t)
	st := store.New(pool)
	if emb == nil {
		emb = embed.Stub{}
	}
	b := bouncer.New(st, emb, bouncer.PassthroughClassifier{})
	a := api.New(st, emb, summarize.Stub{}, testOrigin, 10*time.Second, testWebAuthn(t), b)
	srv := httptest.NewServer(a.AgentRoutes())
	t.Cleanup(srv.Close)
	return &testHarness{pool: pool, st: st, b: b, srv: srv}
}

// tokenSeq guarantees a unique plaintext per minted agent token across a
// single test binary run — agent_tokens' active-token index is unique on
// token_hash (20260812120000_agent_tokens.up.sql), so two active tokens
// must never hash the same, even for the same subject minted twice in one
// test.
var tokenSeq atomic.Int64

// session mints a fresh agent-class token for subject, builds an
// *agentclient.Client authenticated with it against h.srv, registers the
// v0 tool surface with that client, and returns a live in-memory MCP client
// session — the same shape cmd/mcpserver constructs at boot (agentclient.Client
// + mcptools.Register), minus the process boundary and stdio transport.
func (h *testHarness) session(t *testing.T, subject string) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	plaintext := fmt.Sprintf("test-agent-token-%s-%d", subject, tokenSeq.Add(1))
	if _, err := h.st.CreateAgentToken(ctx, subject, "test agent: "+subject, plaintext); err != nil {
		t.Fatalf("CreateAgentToken() error = %v", err)
	}
	client := &agentclient.Client{BaseURL: h.srv.URL, Token: plaintext, HTTP: h.srv.Client()}

	server := mcp.NewServer(&mcp.Implementation{Name: "chuvar-test", Version: "test"}, nil)
	Register(server, client)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := mcpClient.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// testSession is the common-case entry point: a harness with the stub
// embedder plus one session bound to subject, for tests that don't need to
// tune the bouncer or mint a second session.
func testSession(t *testing.T, subject string) (*mcp.ClientSession, *testHarness) {
	t.Helper()
	h := newTestHarness(t, nil)
	return h.session(t, subject), h
}

func callTool[T any](t *testing.T, session *mcp.ClientSession, name string, args any) T {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s) transport error = %v", name, err)
	}
	if res.IsError {
		t.Fatalf("CallTool(%s) tool error: %+v", name, res.Content)
	}

	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshaling StructuredContent: %v", err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshaling StructuredContent into %T: %v", out, err)
	}
	return out
}

// toolErrorText extracts the text of a tool-error result, the same value an
// MCP client actually sees, so tests can assert on what's shown to the calling
// agent rather than on internal error types.
func toolErrorText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("tool error result has no content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("tool error content[0] = %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

func TestListGrants_ViaMCP(t *testing.T) {
	session, h := testSession(t, "agent-a")
	ctx := context.Background()

	if _, err := h.st.CreateGrant(ctx, "agent-a", []string{"identity.basic", "preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	out := callTool[listGrantsOutput](t, session, "list_grants", listGrantsArgs{})
	if len(out.Grants) != 1 {
		t.Fatalf("list_grants returned %d grants, want 1", len(out.Grants))
	}
	if !out.Grants[0].Active {
		t.Error("grant should be Active")
	}
	if len(out.Grants[0].Scopes) != 2 {
		t.Errorf("grant scopes = %v, want 2 entries", out.Grants[0].Scopes)
	}
}

// TestSubjectIsBoundToTheAuthenticatedToken is the cutover's regression test
// for the pre-cutover MCP_SUBJECT trust model: subject used to be an
// environment variable the launching agent host set — trusted, but not a
// credential. Now it's resolved server-side from whichever agent-class
// token client.Token carries (store.AuthenticateAgentToken). Two independent
// tokens for two different subjects, run through two independent sessions,
// must each only ever see their own subject's grants — there is still no
// tool argument anywhere in this package that can cross that boundary (the
// args structs have no Subject field), but this proves the token-derived
// binding holds end to end over the real HTTP path, not just at the Go type
// level.
func TestSubjectIsBoundToTheAuthenticatedToken(t *testing.T) {
	h := newTestHarness(t, nil)
	ctx := context.Background()

	if _, err := h.st.CreateGrant(ctx, "alice", []string{"identity.sensitive"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := h.st.CreateGrant(ctx, "bob", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	aliceSession := h.session(t, "alice")
	bobSession := h.session(t, "bob")

	aliceGrants := callTool[listGrantsOutput](t, aliceSession, "list_grants", listGrantsArgs{})
	if len(aliceGrants.Grants) != 1 || aliceGrants.Grants[0].Scopes[0] != "identity.sensitive" {
		t.Fatalf("alice's session list_grants = %+v, want only her own identity.sensitive grant", aliceGrants.Grants)
	}

	bobGrants := callTool[listGrantsOutput](t, bobSession, "list_grants", listGrantsArgs{})
	if len(bobGrants.Grants) != 1 || bobGrants.Grants[0].Scopes[0] != "preferences.coffee" {
		t.Fatalf("bob's session list_grants = %+v, want only his own preferences.coffee grant", bobGrants.Grants)
	}
}

func TestReadWithScopeCheck_InsufficientScope_ViaMCP(t *testing.T) {
	session, _ := testSession(t, "agent-a")

	out := callTool[readOutput](t, session, "read_with_scope_check", readArgs{
		Query:           "coffee preference",
		RequestedScopes: []string{"preferences.coffee"},
	})
	if out.Status != "insufficient_scope" {
		t.Fatalf("status = %q, want insufficient_scope", out.Status)
	}
	if len(out.MissingScopes) != 1 || out.MissingScopes[0] != "preferences.coffee" {
		t.Fatalf("missing_scopes = %v, want [preferences.coffee]", out.MissingScopes)
	}
}

func TestReadWithScopeCheck_TooManyRequestedScopesIsError(t *testing.T) {
	session, _ := testSession(t, "agent-a")

	scopes := make([]string, maxScopesPerRequest+1)
	for i := range scopes {
		scopes[i] = "identity.basic"
	}

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "read_with_scope_check",
		Arguments: readArgs{Query: "x", RequestedScopes: scopes},
	})
	if err != nil {
		t.Fatalf("CallTool() transport error = %v", err)
	}
	if !res.IsError {
		t.Fatal("read_with_scope_check with more than maxScopesPerRequest scopes: want a tool error, got success")
	}
}

func TestReadWithScopeCheck_QueryTooLongIsError(t *testing.T) {
	session, _ := testSession(t, "agent-a")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "read_with_scope_check",
		Arguments: readArgs{
			Query:           string(make([]byte, maxQueryLength+1)),
			RequestedScopes: []string{"identity.basic"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool() transport error = %v", err)
	}
	if !res.IsError {
		t.Fatal("read_with_scope_check with a query over maxQueryLength: want a tool error, got success")
	}
}

func TestReadWithScopeCheck_LimitTooLargeIsError(t *testing.T) {
	session, _ := testSession(t, "agent-a")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "read_with_scope_check",
		Arguments: readArgs{
			Query:           "x",
			RequestedScopes: []string{"identity.basic"},
			Limit:           maxSearchLimit + 1,
		},
	})
	if err != nil {
		t.Fatalf("CallTool() transport error = %v", err)
	}
	if !res.IsError {
		t.Fatal("read_with_scope_check with limit over maxSearchLimit: want a tool error, got success")
	}
}

// The revoke-during-embed race (a grant revoked while an embedding call for
// the same request is in flight) is no longer reproducible from this
// package: the embed call, and the re-check that closes the race, both now
// run inside agentSearch (internal/api/agent_routes.go), a single server-side
// handler this package has no way to inject a side-effecting Embedder into.
// That test now lives there, as TestAgentSearch_RevokedMidEmbedIsRejected —
// this comment exists so "the race test disappeared" reads as "moved with
// the code it exercises," not as a dropped assertion.

func TestProposeWriteThenRead_EndToEnd_ViaMCP(t *testing.T) {
	session, h := testSession(t, "agent-a")
	ctx := context.Background()

	proposed := callTool[proposeWriteOutput](t, session, "propose_write", proposeWriteArgs{
		Content:        "user's favorite coffee order is a flat white",
		ProposedScopes: []string{"preferences.coffee"},
	})
	if proposed.Status != "pending" {
		t.Fatalf("propose_write status = %q, want pending", proposed.Status)
	}
	if proposed.DedupeVerdict != "novel" {
		t.Fatalf("propose_write dedupe_verdict = %q, want novel", proposed.DedupeVerdict)
	}

	// propose_write must never have created a readable fact — approval is a
	// separate, human-triggered action (AGENTS.md §3.1), not exposed as an MCP
	// tool in v0. Commit it directly via the store, standing in for that human
	// approval step.
	if _, err := h.st.CreateGrant(ctx, "agent-a", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	beforeCommit := callTool[readOutput](t, session, "read_with_scope_check", readArgs{
		Query:           "coffee",
		RequestedScopes: []string{"preferences.coffee"},
	})
	if len(beforeCommit.Facts) != 0 {
		t.Fatalf("read before commit returned facts = %+v, want none (still only staged)", beforeCommit.Facts)
	}

	commitVec, err := embed.Stub{}.Embed(ctx, "user's favorite coffee order is a flat white")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	if _, err := h.st.CommitDiff(ctx, proposed.DiffID, "human-reviewer", commitVec, ""); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	afterCommit := callTool[readOutput](t, session, "read_with_scope_check", readArgs{
		Query:           "coffee",
		RequestedScopes: []string{"preferences.coffee"},
	})
	if afterCommit.Status != "ok" {
		t.Fatalf("read after commit status = %q, want ok", afterCommit.Status)
	}
	if len(afterCommit.Facts) != 1 {
		t.Fatalf("read after commit facts = %+v, want 1", afterCommit.Facts)
	}

	// audit_log.subject is the authenticated agent's subject, end to end
	// through the real HTTP path — the cutover's central claim.
	var auditedSubject string
	if err := h.pool.QueryRow(ctx,
		`SELECT subject FROM audit_log WHERE event_type = 'read' ORDER BY created_at DESC LIMIT 1`,
	).Scan(&auditedSubject); err != nil {
		t.Fatalf("querying audit_log.subject: %v", err)
	}
	if auditedSubject != "agent-a" {
		t.Errorf("audit_log.subject = %q, want %q", auditedSubject, "agent-a")
	}
}

// TestProposeWrite_InvalidScopeReturnsVerbatimValidationError_ViaMCP is the
// regression test for the ValidationError taxonomy across the cutover: a
// malformed caller-supplied scope now fails agentRequestGrant/agentProposeWrite's
// own scope.Validate call server-side and comes back as an HTTP 400, which
// agentclient.decodeValidationError turns into a *agentclient.ValidationError
// carrying the server's message verbatim — mapClientError passes that through
// unmasked, the same "safe and useful to show, self-correct and retry"
// treatment bouncer.ValidationError got before the cutover.
func TestProposeWrite_InvalidScopeReturnsVerbatimValidationError_ViaMCP(t *testing.T) {
	session, _ := testSession(t, "agent-a")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "propose_write",
		Arguments: proposeWriteArgs{
			Content:        "some fact",
			ProposedScopes: []string{"Not A Valid Scope"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool() transport error = %v", err)
	}
	if !res.IsError {
		t.Fatal("propose_write with a malformed scope succeeded, want a tool error")
	}
	text := toolErrorText(t, res)
	if strings.Contains(text, "internal error") {
		t.Fatalf("propose_write error text = %q, want the validation message verbatim, not the generic masked message", text)
	}
	if !strings.Contains(text, "scope") {
		t.Fatalf("propose_write error text = %q, want it to mention the malformed scope", text)
	}
}

// TestProposeWrite_ServerErrorIsMasked_ViaMCP is the negative counterpart: an
// error that originates inside the server's store layer (here, targeting a
// fact the proposer's grants don't cover) must NOT be shown verbatim to the
// calling agent, even though its message happens to be informative and
// non-sensitive in this particular case. mapClientError's allowlist only
// passes through *agentclient.ValidationError; a masked 500 comes back as
// agentclient's own serverError, which mapClientError routes through
// toolError — proving the masking survives the extra HTTP hop the cutover
// introduced, not just the original in-process errors.As check.
func TestProposeWrite_ServerErrorIsMasked_ViaMCP(t *testing.T) {
	h := newTestHarness(t, nil)
	ctx := context.Background()

	aliceSession := h.session(t, "alice")
	proposed := callTool[proposeWriteOutput](t, aliceSession, "propose_write", proposeWriteArgs{
		Content:        "alice's medical condition is confidential",
		ProposedScopes: []string{"identity.medical"},
	})
	commitVec, err := embed.Stub{}.Embed(ctx, "alice's medical condition is confidential")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	fact, err := h.st.CommitDiff(ctx, proposed.DiffID, "human-reviewer", commitVec, "")
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	// bob has a real, active grant, just not one covering identity.medical — this
	// proves the store's rejection is scope-specific.
	if _, err := h.st.CreateGrant(ctx, "bob", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	bobSession := h.session(t, "bob")

	res, err := bobSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "propose_write",
		Arguments: proposeWriteArgs{
			Content:        "innocuous-looking replacement content",
			ProposedScopes: []string{"preferences.coffee"},
			TargetFactID:   fact.ID,
		},
	})
	if err != nil {
		t.Fatalf("CallTool() transport error = %v", err)
	}
	if !res.IsError {
		t.Fatal("propose_write targeting a fact outside the subject's grants succeeded, want a tool error")
	}
	text := toolErrorText(t, res)
	if !strings.Contains(text, "internal error") {
		t.Fatalf("propose_write error text = %q, want the generic masked message, not the store's internal-detail message", text)
	}
	if strings.Contains(text, fact.ID) {
		t.Fatalf("propose_write error text = %q leaked the target fact ID, a store-layer detail that must stay masked", text)
	}
}

func TestReadWithScopeCheck_SummaryDepthRedactsContent_ViaMCP(t *testing.T) {
	session, h := testSession(t, "agent-a")
	ctx := context.Background()

	proposed := callTool[proposeWriteOutput](t, session, "propose_write", proposeWriteArgs{
		Content:        "user's favorite coffee order is a flat white",
		ProposedScopes: []string{"preferences.coffee"},
	})

	if _, err := h.st.CreateGrant(ctx, "agent-a", []string{"preferences.coffee"}, "memory", "summary", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	commitVec, err := embed.Stub{}.Embed(ctx, "user's favorite coffee order is a flat white")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	if _, err := h.st.CommitDiff(ctx, proposed.DiffID, "human-reviewer", commitVec, "a stub summary of the coffee fact"); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	out := callTool[readOutput](t, session, "read_with_scope_check", readArgs{
		Query:           "coffee",
		RequestedScopes: []string{"preferences.coffee"},
	})
	if out.Status != "ok" {
		t.Fatalf("read status = %q, want ok", out.Status)
	}
	if len(out.Facts) != 1 {
		t.Fatalf("read facts = %+v, want 1", out.Facts)
	}
	got := out.Facts[0]
	if got.Depth != "summary" {
		t.Errorf("Depth = %q, want %q", got.Depth, "summary")
	}
	if got.Content != "" {
		t.Errorf("Content = %q, want empty at summary depth (via the actual MCP wire format, not just the Go struct)", got.Content)
	}
	if got.Summary != "a stub summary of the coffee fact" {
		t.Errorf("Summary = %q, want the committed summary", got.Summary)
	}
}

// A caller granted only "facts" depth must never see provenance over the
// wire, even though "full" depth (a different grant, same subject/scope)
// does. Exercised through callTool's real JSON marshal/unmarshal end to end
// over the HTTP hop this cutover introduced, not just the Go struct.
func TestReadWithScopeCheck_FullDepthAddsProvenance_FactsDepthDoesNot_ViaMCP(t *testing.T) {
	session, h := testSession(t, "agent-a")
	ctx := context.Background()

	proposed := callTool[proposeWriteOutput](t, session, "propose_write", proposeWriteArgs{
		Content:        "user's favorite editor is neovim",
		ProposedScopes: []string{"preferences.tools"},
	})

	commitVec, err := embed.Stub{}.Embed(ctx, "user's favorite editor is neovim")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	if _, err := h.st.CommitDiff(ctx, proposed.DiffID, "human-reviewer", commitVec, "editor preference summary"); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	t.Run("facts depth", func(t *testing.T) {
		if _, err := h.st.CreateGrant(ctx, "agent-a", []string{"preferences.tools"}, "memory", "facts", nil, "human-reviewer"); err != nil {
			t.Fatalf("CreateGrant() error = %v", err)
		}
		out := callTool[readOutput](t, session, "read_with_scope_check", readArgs{
			Query:           "editor",
			RequestedScopes: []string{"preferences.tools"},
		})
		if out.Status != "ok" || len(out.Facts) != 1 {
			t.Fatalf("read = %+v, want status ok with 1 fact", out)
		}
		if out.Facts[0].Depth != "facts" {
			t.Fatalf("Depth = %q, want %q", out.Facts[0].Depth, "facts")
		}
		if out.Facts[0].Provenance != nil {
			t.Errorf("Provenance at facts depth = %+v, want nil — decided_by must not reach a facts-depth caller", out.Facts[0].Provenance)
		}
	})

	t.Run("full depth", func(t *testing.T) {
		if _, err := h.st.CreateGrant(ctx, "agent-a", []string{"preferences.tools"}, "memory", "full", nil, "human-reviewer"); err != nil {
			t.Fatalf("CreateGrant() error = %v", err)
		}
		out := callTool[readOutput](t, session, "read_with_scope_check", readArgs{
			Query:           "editor",
			RequestedScopes: []string{"preferences.tools"},
		})
		if out.Status != "ok" || len(out.Facts) != 1 {
			t.Fatalf("read = %+v, want status ok with 1 fact", out)
		}
		got := out.Facts[0]
		if got.Depth != "full" {
			t.Fatalf("Depth = %q, want %q", got.Depth, "full")
		}
		if got.Provenance == nil {
			t.Fatalf("Provenance at full depth = nil, want the approval trail")
		}
		if got.Provenance.DecidedBy == nil || *got.Provenance.DecidedBy != "human-reviewer" {
			t.Errorf("Provenance.DecidedBy = %v, want \"human-reviewer\"", got.Provenance.DecidedBy)
		}
		if got.Provenance.SourceStagedDiffID != proposed.DiffID {
			t.Errorf("Provenance.SourceStagedDiffID = %q, want %q", got.Provenance.SourceStagedDiffID, proposed.DiffID)
		}
		if got.Provenance.CreatedAt == "" {
			t.Error("Provenance.CreatedAt is empty, want the fact's system-time start (RFC3339)")
		}
		if got.Provenance.ValidAt == "" {
			t.Error("Provenance.ValidAt is empty, want the fact's real-world validity start (RFC3339)")
		}
	})
}

// TestReadWithScopeCheck_AuditsPerFactDepth_ViaMCP is the regression test for
// the audit gap this ticket closes: a "read" audit row records a per-fact
// depth (not one depth for the whole call), since effectiveDepth can vary
// fact-to-fact within a single call. This logic lives entirely server-side
// now (agentSearch), so this test drives it through the real HTTP path and
// reads audit_log directly, same as before the cutover.
func TestReadWithScopeCheck_AuditsPerFactDepth_ViaMCP(t *testing.T) {
	session, h := testSession(t, "agent-a")
	ctx := context.Background()

	coffee := callTool[proposeWriteOutput](t, session, "propose_write", proposeWriteArgs{
		Content:        "user's favorite coffee order is a flat white",
		ProposedScopes: []string{"preferences.coffee"},
	})
	tea := callTool[proposeWriteOutput](t, session, "propose_write", proposeWriteArgs{
		Content:        "user's favorite tea order is earl grey",
		ProposedScopes: []string{"preferences.tea"},
	})

	if _, err := h.st.CreateGrant(ctx, "agent-a", []string{"preferences.coffee"}, "memory", "full", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := h.st.CreateGrant(ctx, "agent-a", []string{"preferences.tea"}, "memory", "summary", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	coffeeVec, err := embed.Stub{}.Embed(ctx, "user's favorite coffee order is a flat white")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	coffeeFact, err := h.st.CommitDiff(ctx, coffee.DiffID, "human-reviewer", coffeeVec, "coffee summary")
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}
	teaVec, err := embed.Stub{}.Embed(ctx, "user's favorite tea order is earl grey")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	teaFact, err := h.st.CommitDiff(ctx, tea.DiffID, "human-reviewer", teaVec, "tea summary")
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	out := callTool[readOutput](t, session, "read_with_scope_check", readArgs{
		Query:           "favorite",
		RequestedScopes: []string{"preferences.coffee", "preferences.tea"},
		Limit:           10,
	})
	if out.Status != "ok" {
		t.Fatalf("read status = %q, want ok", out.Status)
	}
	if len(out.Facts) != 2 {
		t.Fatalf("read facts = %+v, want 2", out.Facts)
	}

	wantDepth := map[string]string{coffeeFact.ID: "full", teaFact.ID: "summary"}
	for _, f := range out.Facts {
		if f.Depth != wantDepth[f.ID] {
			t.Errorf("fact %s Depth = %q, want %q", f.ID, f.Depth, wantDepth[f.ID])
		}
	}

	var detailJSON []byte
	if err := h.pool.QueryRow(ctx,
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

func TestRequestGrant_ViaMCP(t *testing.T) {
	session, h := testSession(t, "agent-a")
	ctx := context.Background()

	out := callTool[requestGrantOutput](t, session, "request_grant", requestGrantArgs{
		RequestedScopes: []string{"identity.basic"},
		Justification:   "need this to answer a question about the user",
	})
	if out.Status != "pending" {
		t.Fatalf("request_grant status = %q, want pending", out.Status)
	}
	if out.RequestID == "" {
		t.Fatal("request_grant did not return a request_id")
	}

	// It never creates a real grant directly — the whole point of this tool is
	// that it stages a request for human review (AGENTS.md §3.1 shape).
	granted, err := h.st.GrantedScopes(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopes() error = %v", err)
	}
	if len(granted) != 0 {
		t.Fatalf("GrantedScopes() after request_grant = %v, want empty (no auto-approval)", granted)
	}

	// The request is bound to the session's authenticated subject, same as
	// every other tool — not client-suppliable (there is no Subject field in
	// requestGrantArgs).
	reqs, err := h.st.ListGrantRequests(ctx, store.GrantRequestPending)
	if err != nil {
		t.Fatalf("ListGrantRequests() error = %v", err)
	}
	if len(reqs) != 1 || reqs[0].Subject != "agent-a" {
		t.Fatalf("ListGrantRequests() = %+v, want one request from agent-a", reqs)
	}
}

func TestRequestGrant_InvalidScopeIsError(t *testing.T) {
	session, _ := testSession(t, "agent-a")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "request_grant",
		Arguments: requestGrantArgs{RequestedScopes: []string{"Not A Valid Scope"}},
	})
	if err != nil {
		t.Fatalf("CallTool() transport error = %v", err)
	}
	if !res.IsError {
		t.Fatal("request_grant with an invalid scope succeeded, want a tool error")
	}
}

func TestRequestGrant_EmptyScopesIsError(t *testing.T) {
	session, _ := testSession(t, "agent-a")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "request_grant",
		Arguments: requestGrantArgs{},
	})
	if err != nil {
		t.Fatalf("CallTool() transport error = %v", err)
	}
	if !res.IsError {
		t.Fatal("request_grant with no scopes succeeded, want a tool error")
	}
}

// TestRequestGrant_NegativeTTLIsError proves the negative-ttl_seconds
// rejection still holds after the cutover, even though this package no
// longer performs the check itself — agentRequestGrant
// (internal/api/agent_routes.go) reproduces it server-side, and this test
// only has HTTP-shaped visibility into that now.
func TestRequestGrant_NegativeTTLIsError(t *testing.T) {
	session, _ := testSession(t, "agent-a")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "request_grant",
		Arguments: requestGrantArgs{
			RequestedScopes: []string{"identity.basic"},
			TTLSeconds:      -60,
		},
	})
	if err != nil {
		t.Fatalf("CallTool() transport error = %v", err)
	}
	if !res.IsError {
		t.Fatal("request_grant with a negative ttl_seconds succeeded, want a tool error")
	}
}

// TestProposeWrite_RateLimited is the trap regression test called out in the
// cutover brief: agentclient.ProposeResult uses ONE struct for both the 200
// and the 429 outcome, discriminated only by Status. This proves the tool
// still reports RATE_LIMITED as a structured status (res.IsError stays
// false, matching insufficient_scope's shape) with no diff_id, that nothing
// gets staged once limited, that the denial is audited, and that a different
// subject's own limit is untouched — end to end through the real HTTP hop
// the cutover introduced.
func TestProposeWrite_RateLimited(t *testing.T) {
	h := newTestHarness(t, nil)
	h.b.RateLimit = 2
	h.b.RateLimitWindow = time.Hour

	agentA := h.session(t, "agent-a")
	agentB := h.session(t, "agent-b")

	// The first two proposals for agent-a fit within its configured limit of 2.
	for i := 0; i < 2; i++ {
		out := callTool[proposeWriteOutput](t, agentA, "propose_write", proposeWriteArgs{
			Content:        fmt.Sprintf("agent-a fact number %d", i),
			ProposedScopes: []string{"preferences.coffee"},
		})
		if out.Status == agentclient.StatusRateLimited {
			t.Fatalf("proposal %d for agent-a: status = RATE_LIMITED, want it to succeed (still within limit)", i)
		}
	}

	// The third trips the limit.
	third := callTool[proposeWriteOutput](t, agentA, "propose_write", proposeWriteArgs{
		Content:        "agent-a fact number 3",
		ProposedScopes: []string{"preferences.coffee"},
	})
	if third.Status != agentclient.StatusRateLimited {
		t.Fatalf("propose_write status = %q after exceeding the limit, want RATE_LIMITED", third.Status)
	}
	if third.DiffID != "" {
		t.Fatalf("RATE_LIMITED response carried a diff_id (%q); nothing should have been staged", third.DiffID)
	}
	if third.DedupeVerdict != "" || third.CandidateFactID != nil {
		t.Fatalf("RATE_LIMITED response carried other 200-only fields = %+v, want them zero", third)
	}

	ctx := context.Background()
	var audited int
	if err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE event_type = 'rate_limited' AND subject = 'agent-a'`,
	).Scan(&audited); err != nil {
		t.Fatalf("querying audit_log for rate_limited rows: %v", err)
	}
	if audited != 1 {
		t.Errorf("audit_log rate_limited rows for agent-a = %d, want exactly 1 (one per denial)", audited)
	}

	// agent-b's own limit must be untouched by agent-a's activity.
	bOut := callTool[proposeWriteOutput](t, agentB, "propose_write", proposeWriteArgs{
		Content:        "agent-b's own, unrelated fact",
		ProposedScopes: []string{"preferences.tea"},
	})
	if bOut.Status == agentclient.StatusRateLimited {
		t.Fatal("agent-b's first proposal was rate limited by agent-a's activity — the limit is not correctly keyed per subject")
	}
}
