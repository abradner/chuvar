package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/agentclient"
	"github.com/abradner/chuvar/backend/internal/api"
	"github.com/abradner/chuvar/backend/internal/bouncer"
	"github.com/abradner/chuvar/backend/internal/custody"
	"github.com/abradner/chuvar/backend/internal/db"
	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/store"
	"github.com/abradner/chuvar/backend/internal/summarize"
)

// This file is the proof the PR 4 cutover actually happened: mcptools no
// longer touches Postgres directly (no *store.Store, no *pgxpool.Pool, no
// embed.Embedder, no *bouncer.Bouncer anywhere in this package's non-test
// code any more — see mcptools.go's package doc comment). Every test below
// drives the four MCP tools through a real *agentclient.Client talking HTTP
// to a real internal/api.API serving AgentRoutes(), backed by a real,
// migrated Postgres — the same production wiring cmd/mcpserver and
// cmd/apiserver assemble, just built here from exported pieces (api.New,
// store.NewSealed, custody.Ephemeral, webauthn.New, bouncer.New) since this
// package must not import internal/api's own unexported test helpers (nor
// modify that package to add any — out of scope for this PR).
//
// TestCutover_AllToolsEndToEnd is the single most load-bearing test here: it
// unsets DATABASE_URL from the process environment before registering any
// tool, then drives all four tools end to end — proving mcpserver's actual
// runtime path (agentclient.Client -> mcptools.Register) needs no database
// credential at all, not just that this test file happens not to pass one
// in.

// agentBackend is a real internal/api.API, serving only AgentRoutes(), over
// httptest — the same network-level shape a deployed mcpserver talks to
// (cmd/apiserver/main.go's second http.Server on CHUVAR_AGENT_ADDR). Returns
// the underlying store and pool too, for tests that need to seed grants,
// commit facts, or assert on audit_log directly — none of which mcpserver's
// own process is allowed to do any more, but the test setup legitimately
// still needs a human-review stand-in for that.
type agentBackend struct {
	srv  *httptest.Server
	st   *store.Store
	pool *pgxpool.Pool
}

// newAgentBackend spins up agentBackend against a real, migrated Postgres.
// b, when non-nil, overrides the *bouncer.Bouncer api.New would otherwise
// build (embed.Stub{} + PassthroughClassifier{} + default rate limit) — used
// by the rate-limit test below to configure a low limit deterministically.
func newAgentBackend(t *testing.T, b *bouncer.Bouncer) *agentBackend {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, reviewer_tokens, agent_tokens, grant_requests, data_keys, propose_write_rate_limits, capability_grant_identities, capability_grant_tokens, signing_policies, webauthn_credentials, webauthn_challenges, enrollment_latch`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := testSealedStore(t, pool)
	emb := embed.Stub{}
	if b == nil {
		b = bouncer.New(st, emb, bouncer.PassthroughClassifier{})
	}
	wa := testWebAuthn(t)
	a := api.New(st, emb, summarize.Stub{}, testOrigin, 10*time.Second, wa, b)
	srv := httptest.NewServer(a.AgentRoutes())
	t.Cleanup(srv.Close)

	return &agentBackend{srv: srv, st: st, pool: pool}
}

// testOrigin/testWebAuthn/testSealedStore reproduce internal/api's own
// api_test.go helpers of the same name field-for-field (same RP ID, same
// UserVerification stance, same custody.Ephemeral-backed sealed store). This
// is deliberate duplication, not an oversight: those helpers are unexported
// test-only code in a package this PR must not modify, and every piece they
// use (webauthn.New, custody.Ephemeral, custody.NewKey, store.NewSealed) is
// exported, so reproducing the ~15 lines here is safer than either exporting
// test helpers from internal/api or importing its _test.go file (which Go
// doesn't allow across packages anyway).
const (
	testRPID   = "localhost"
	testOrigin = "http://localhost:5173"
)

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

// mintAgentSession mints an agent-class token DIRECTLY via the store — never
// over HTTP, matching the brief: minting requires a human second factor by
// design (internal/api/agent_tokens.go's createAgentToken doc comment), so a
// test standing in for "an operator already minted this and handed it to an
// agent host" goes straight to the store the way a real mint ultimately
// would, not through the reviewer-authenticated POST /api/agent-tokens route
// this package has no business calling anyway. Builds an *agentclient.Client
// against ab's server with that token, registers all four MCP tools with it
// (mcptools.Register — this package's real entrypoint), and connects a real
// MCP client/server pair over an in-memory transport, so these tests
// exercise the actual protocol marshaling/unmarshaling on top of the actual
// HTTP round trip, not just Go function calls.
func mintAgentSession(t *testing.T, ab *agentBackend, subject string) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	plaintext := "agent-test-token-" + subject
	if _, err := ab.st.CreateAgentToken(ctx, subject, "test agent: "+subject, plaintext); err != nil {
		t.Fatalf("seeding agent token: %v", err)
	}

	client := &agentclient.Client{BaseURL: ab.srv.URL, Token: plaintext, HTTP: &http.Client{}}

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
// MCP client actually sees, so tests can assert on what's shown to the
// calling agent rather than on internal error types.
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

// mustCommitFact stages and immediately approves a fact directly through the
// store, bypassing the human-review queue and (necessarily) propose_write
// itself — a test-only shortcut for getting a committed, searchable fact
// into place without a separate reviewer-approval step for every fixture.
func mustCommitFact(t *testing.T, st *store.Store, subject, content string, scopes []string, summary string) store.Fact {
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

// --- TestCutover_AllToolsEndToEnd ----------------------------------------

// TestCutover_AllToolsEndToEnd is "Done means" for this PR: it proves
// mcpserver's actual runtime path — build an *agentclient.Client, hand it to
// mcptools.Register, drive real MCP tool calls — works with DATABASE_URL
// absent from the process environment, and exercises every documented
// outcome of every one of the four tools in one place:
//   - list_grants: returns only the authenticated agent's own grants.
//   - request_grant: stages a request, never a real grant.
//   - read_with_scope_check: both status=ok and status=insufficient_scope.
//   - propose_write: both a normal "pending" outcome and status=RATE_LIMITED
//     (the TRAP case propose_write.go's doc comment names — DiffID must come
//     back empty and Status must be checked, not inferred from that).
//
// It also asserts audit_log.subject on the resulting rows is the
// AUTHENTICATED agent's subject — resolved server-side from the bearer
// token (agent_routes.go's agentFromContext) — not anything this test's MCP
// client ever had a chance to supply, since none of the tool arg structs in
// this package carry a subject field any more than agent_routes.go's request
// structs do.
func TestCutover_AllToolsEndToEnd(t *testing.T) {
	// The DB is still needed to build the real backend (apiserver's job,
	// same as production) — but that setup happens BEFORE the env var is
	// unset, and nothing reachable from mcptools.Register or an MCP tool
	// call below ever consults DATABASE_URL again after this point. envVal
	// is read directly (not through the process environment) precisely so
	// this test doesn't depend on the var it's about to remove.
	envVal := os.Getenv("DATABASE_URL")
	if envVal == "" {
		t.Skip("DATABASE_URL not set; skipping mcptools integration tests")
	}

	ab := newAgentBackend(t, nil)

	if err := os.Unsetenv("DATABASE_URL"); err != nil {
		t.Fatalf("os.Unsetenv(DATABASE_URL) error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.Setenv("DATABASE_URL", envVal); err != nil {
			t.Fatalf("restoring DATABASE_URL: %v", err)
		}
	})
	if _, ok := os.LookupEnv("DATABASE_URL"); ok {
		t.Fatal("DATABASE_URL still set after Unsetenv — test setup bug")
	}

	session := mintAgentSession(t, ab, "cutover-agent")
	ctx := context.Background()

	// --- list_grants: starts empty, then reflects a grant seeded via the
	// store (standing in for a human's REST-API approval — never anything
	// this MCP session could create itself). ---
	empty := callTool[listGrantsOutput](t, session, "list_grants", listGrantsArgs{})
	if len(empty.Grants) != 0 {
		t.Fatalf("list_grants before any grant exists = %+v, want none", empty.Grants)
	}

	// --- read_with_scope_check: insufficient_scope before any grant. ---
	insufficient := callTool[readOutput](t, session, "read_with_scope_check", readArgs{
		Query:           "coffee preference",
		RequestedScopes: []string{"preferences.coffee"},
	})
	if insufficient.Status != "insufficient_scope" {
		t.Fatalf("read_with_scope_check status = %q, want insufficient_scope", insufficient.Status)
	}
	if len(insufficient.MissingScopes) != 1 || insufficient.MissingScopes[0] != "preferences.coffee" {
		t.Fatalf("missing_scopes = %v, want [preferences.coffee]", insufficient.MissingScopes)
	}

	// --- request_grant: stages a request, never a real grant. ---
	reqOut := callTool[requestGrantOutput](t, session, "request_grant", requestGrantArgs{
		RequestedScopes: []string{"preferences.coffee"},
		Justification:   "need this to answer a question about coffee",
	})
	if reqOut.Status != "pending" {
		t.Fatalf("request_grant status = %q, want pending", reqOut.Status)
	}
	granted, err := ab.st.GrantedScopes(ctx, "cutover-agent")
	if err != nil {
		t.Fatalf("GrantedScopes() error = %v", err)
	}
	if len(granted) != 0 {
		t.Fatalf("GrantedScopes() after request_grant = %v, want empty (no auto-approval)", granted)
	}

	// A human approves out of band (store-level stand-in for the REST API).
	if _, err := ab.st.CreateGrant(ctx, "cutover-agent", []string{"preferences.coffee"}, "memory", "full", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	// --- list_grants again: now reflects the human-approved grant. ---
	withGrant := callTool[listGrantsOutput](t, session, "list_grants", listGrantsArgs{})
	if len(withGrant.Grants) != 1 || withGrant.Grants[0].Scopes[0] != "preferences.coffee" {
		t.Fatalf("list_grants after grant = %+v, want one preferences.coffee grant", withGrant.Grants)
	}
	if !withGrant.Grants[0].Active {
		t.Error("grant should be Active")
	}

	// --- propose_write: normal outcome, then read it back. ---
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
	if proposed.DiffID == "" {
		t.Fatal("propose_write diff_id is empty")
	}

	// Still only staged — propose_write must never make a fact readable on
	// its own (AGENTS.md §3.1).
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
	if _, err := ab.st.CommitDiff(ctx, proposed.DiffID, "human-reviewer", commitVec, "coffee summary"); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	// --- read_with_scope_check: status=ok now that the fact is committed
	// and the grant is held. ---
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

	// --- audit_log.subject is the AUTHENTICATED agent's subject, for both
	// the read and the insufficient_scope rows produced above — never
	// anything this MCP client could have supplied itself (mcptools has no
	// Subject-shaped tool argument anywhere in this package's args structs). ---
	var readSubject string
	if err := ab.pool.QueryRow(ctx,
		`SELECT subject FROM audit_log WHERE event_type = 'read' ORDER BY created_at DESC LIMIT 1`,
	).Scan(&readSubject); err != nil {
		t.Fatalf("querying audit_log for read: %v", err)
	}
	if readSubject != "cutover-agent" {
		t.Fatalf("audit_log.subject (read) = %q, want %q", readSubject, "cutover-agent")
	}
	var insufficientSubject string
	if err := ab.pool.QueryRow(ctx,
		`SELECT subject FROM audit_log WHERE event_type = 'insufficient_scope' ORDER BY created_at DESC LIMIT 1`,
	).Scan(&insufficientSubject); err != nil {
		t.Fatalf("querying audit_log for insufficient_scope: %v", err)
	}
	if insufficientSubject != "cutover-agent" {
		t.Fatalf("audit_log.subject (insufficient_scope) = %q, want %q", insufficientSubject, "cutover-agent")
	}

	// --- propose_write: RATE_LIMITED outcome, on a second backend
	// configured with a low limit (rebuilding the whole session, since the
	// first backend's default limit of 20/minute would take 20 calls to
	// trip). This is the TRAP case: DiffID must come back empty and Status
	// must read RATE_LIMITED, not a masked tool error and not a
	// falsely-successful diff_id. ---
	limitedBouncerStore := testSealedStore(t, ab.pool)
	limitedBouncer := bouncer.New(limitedBouncerStore, embed.Stub{}, bouncer.PassthroughClassifier{})
	limitedBouncer.RateLimit = 1
	limitedBouncer.RateLimitWindow = time.Hour
	limitedAB := newAgentBackendWithBouncer(t, ab.pool, limitedBouncer)
	limitedSession := mintAgentSession(t, limitedAB, "rate-limited-agent")

	first := callTool[proposeWriteOutput](t, limitedSession, "propose_write", proposeWriteArgs{
		Content:        "first fact fits within the limit",
		ProposedScopes: []string{"preferences.tea"},
	})
	if first.Status == "RATE_LIMITED" {
		t.Fatal("first propose_write: status = RATE_LIMITED, want it to succeed (still within the limit of 1)")
	}

	second := callTool[proposeWriteOutput](t, limitedSession, "propose_write", proposeWriteArgs{
		Content:        "second fact trips the limit",
		ProposedScopes: []string{"preferences.tea"},
	})
	if second.Status != "RATE_LIMITED" {
		t.Fatalf("second propose_write: status = %q, want RATE_LIMITED", second.Status)
	}
	if second.DiffID != "" {
		t.Fatalf("RATE_LIMITED propose_write carried diff_id = %q, want empty — nothing should be staged", second.DiffID)
	}
	if second.DedupeVerdict != "" {
		t.Fatalf("RATE_LIMITED propose_write carried dedupe_verdict = %q, want empty", second.DedupeVerdict)
	}

	var rateLimitedSubject string
	if err := ab.pool.QueryRow(ctx,
		`SELECT subject FROM audit_log WHERE event_type = 'rate_limited' ORDER BY created_at DESC LIMIT 1`,
	).Scan(&rateLimitedSubject); err != nil {
		t.Fatalf("querying audit_log for rate_limited: %v", err)
	}
	if rateLimitedSubject != "rate-limited-agent" {
		t.Fatalf("audit_log.subject (rate_limited) = %q, want %q", rateLimitedSubject, "rate-limited-agent")
	}
}

// newAgentBackendWithBouncer is newAgentBackend without the DATABASE_URL
// skip/migrate/truncate ceremony (already done by the caller against the
// same pool) — used by TestCutover_AllToolsEndToEnd to stand up a second
// AgentRoutes() server sharing the first's already-migrated database but
// with its own, differently-configured *bouncer.Bouncer.
func newAgentBackendWithBouncer(t *testing.T, pool *pgxpool.Pool, b *bouncer.Bouncer) *agentBackend {
	t.Helper()
	st := testSealedStore(t, pool)
	wa := testWebAuthn(t)
	a := api.New(st, embed.Stub{}, summarize.Stub{}, testOrigin, 10*time.Second, wa, b)
	srv := httptest.NewServer(a.AgentRoutes())
	t.Cleanup(srv.Close)
	return &agentBackend{srv: srv, st: st, pool: pool}
}

// --- list_grants ----------------------------------------------------------

func TestListGrants_ViaMCP(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")
	ctx := context.Background()

	if _, err := ab.st.CreateGrant(ctx, "agent-a", []string{"identity.basic", "preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
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

// TestSubjectComesFromToken_NotClientSuppliable is this package's version of
// the pre-cutover subject-spoofing regression test, adapted: subject is no
// longer bound at mcptools.Register time at all (Register's signature
// carries no subject parameter any more — see mcptools.go's doc comment on
// why that responsibility moved one hop further out). It's now resolved
// exactly once, server-side, from whichever agent-class bearer token the
// *agentclient.Client happens to hold (agentFromContext, agent_routes.go).
// Two independently-minted tokens, two independent MCP sessions: this proves
// each only ever sees its own token's grants, with literally no tool
// argument in this package's args structs able to name a different subject.
func TestSubjectComesFromToken_NotClientSuppliable(t *testing.T) {
	ab := newAgentBackend(t, nil)
	ctx := context.Background()

	if _, err := ab.st.CreateGrant(ctx, "alice", []string{"identity.sensitive"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := ab.st.CreateGrant(ctx, "bob", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	aliceSession := mintAgentSession(t, ab, "alice")
	bobSession := mintAgentSession(t, ab, "bob")

	aliceGrants := callTool[listGrantsOutput](t, aliceSession, "list_grants", listGrantsArgs{})
	if len(aliceGrants.Grants) != 1 || aliceGrants.Grants[0].Scopes[0] != "identity.sensitive" {
		t.Fatalf("alice's session list_grants = %+v, want only her own identity.sensitive grant", aliceGrants.Grants)
	}

	bobGrants := callTool[listGrantsOutput](t, bobSession, "list_grants", listGrantsArgs{})
	if len(bobGrants.Grants) != 1 || bobGrants.Grants[0].Scopes[0] != "preferences.coffee" {
		t.Fatalf("bob's session list_grants = %+v, want only his own preferences.coffee grant", bobGrants.Grants)
	}
}

// --- read_with_scope_check -------------------------------------------------

func TestReadWithScopeCheck_InsufficientScope_ViaMCP(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")

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
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")

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
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")

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
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")

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

// TestReadWithScopeCheck_InvalidScopeIsValidationErrorVerbatim is the
// regression test for the moved-not-deleted property: per-scope format
// validation (scope.Validate) no longer runs in this package at all — it now
// runs exactly once, server-side, in agentSearch. A malformed scope must
// still surface as a tool error carrying the real validation message
// verbatim (via *agentclient.ValidationError), not a generic masked one.
func TestReadWithScopeCheck_InvalidScopeIsValidationErrorVerbatim(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "read_with_scope_check",
		Arguments: readArgs{
			Query:           "x",
			RequestedScopes: []string{"Not A Valid Scope"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool() transport error = %v", err)
	}
	if !res.IsError {
		t.Fatal("read_with_scope_check with a malformed scope succeeded, want a tool error")
	}
	text := toolErrorText(t, res)
	if strings.Contains(text, "internal error") {
		t.Fatalf("error text = %q, want the validation message verbatim, not the generic masked message", text)
	}
}

func TestReadWithScopeCheck_SummaryDepthRedactsContent_ViaMCP(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")
	ctx := context.Background()

	fact := mustCommitFact(t, ab.st, "agent-a", "user's favorite coffee order is a flat white", []string{"preferences.coffee"}, "a stub summary of the coffee fact")
	_ = fact

	if _, err := ab.st.CreateGrant(ctx, "agent-a", []string{"preferences.coffee"}, "memory", "summary", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
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
	if got.Provenance != nil {
		t.Errorf("Provenance at summary depth = %+v, want nil", got.Provenance)
	}
}

func TestReadWithScopeCheck_FullDepthAddsProvenance_FactsDepthDoesNot_ViaMCP(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")
	ctx := context.Background()

	const content = "user's favorite editor is neovim"
	vec, err := embed.Stub{}.Embed(ctx, content)
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	diff, err := ab.st.ProposeDiff(ctx, "agent-a", content, []string{"preferences.tools"}, vec, nil, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	fact, err := ab.st.CommitDiff(ctx, diff.ID, "human-reviewer", vec, "editor preference summary")
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	t.Run("facts depth", func(t *testing.T) {
		if _, err := ab.st.CreateGrant(ctx, "agent-a", []string{"preferences.tools"}, "memory", "facts", nil, "human-reviewer"); err != nil {
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
		if _, err := ab.st.CreateGrant(ctx, "agent-a", []string{"preferences.tools"}, "memory", "full", nil, "human-reviewer"); err != nil {
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
		if got.Provenance.SourceStagedDiffID != diff.ID {
			t.Errorf("Provenance.SourceStagedDiffID = %q, want %q", got.Provenance.SourceStagedDiffID, diff.ID)
		}
		if got.Provenance.CreatedAt == "" {
			t.Error("Provenance.CreatedAt is empty, want the fact's system-time start (RFC3339)")
		}
		if got.Provenance.ValidAt == "" {
			t.Error("Provenance.ValidAt is empty, want the fact's real-world validity start (RFC3339)")
		}
		if got.ID != fact.ID {
			t.Errorf("fact ID = %q, want %q", got.ID, fact.ID)
		}
	})
}

// TestReadWithScopeCheck_AuditsPerFactDepth_ViaMCP proves the per-fact
// disclosure-depth audit detail (store.ReadAuditDetail) still reaches
// audit_log correctly now that agentSearch, not this package, is the one
// writing it — the same property mcptools used to guarantee itself pre-
// cutover, now proven end-to-end over the HTTP boundary instead.
func TestReadWithScopeCheck_AuditsPerFactDepth_ViaMCP(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")
	ctx := context.Background()

	coffee := mustCommitFact(t, ab.st, "agent-a", "user's favorite coffee order is a flat white", []string{"preferences.coffee"}, "coffee summary")
	tea := mustCommitFact(t, ab.st, "agent-a", "user's favorite tea order is earl grey", []string{"preferences.tea"}, "tea summary")

	if _, err := ab.st.CreateGrant(ctx, "agent-a", []string{"preferences.coffee"}, "memory", "full", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := ab.st.CreateGrant(ctx, "agent-a", []string{"preferences.tea"}, "memory", "summary", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	out := callTool[readOutput](t, session, "read_with_scope_check", readArgs{
		Query:           "favorite",
		RequestedScopes: []string{"preferences.coffee", "preferences.tea"},
		Limit:           10,
	})
	if out.Status != "ok" || len(out.Facts) != 2 {
		t.Fatalf("read = %+v, want status ok with 2 facts", out)
	}

	wantDepth := map[string]string{coffee.ID: "full", tea.ID: "summary"}
	for _, f := range out.Facts {
		if f.Depth != wantDepth[f.ID] {
			t.Errorf("fact %s Depth = %q, want %q", f.ID, f.Depth, wantDepth[f.ID])
		}
	}

	var detailJSON []byte
	if err := ab.pool.QueryRow(ctx,
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

// --- propose_write ----------------------------------------------------------

func TestProposeWriteThenRead_EndToEnd_ViaMCP(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")
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
	if _, err := ab.st.CreateGrant(ctx, "agent-a", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
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
	if _, err := ab.st.CommitDiff(ctx, proposed.DiffID, "human-reviewer", commitVec, ""); err != nil {
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
}

// TestProposeWrite_InvalidScopeReturnsVerbatimValidationError_ViaMCP is the
// regression test for the same moved-not-deleted property
// TestReadWithScopeCheck_InvalidScopeIsValidationErrorVerbatim proves for the
// sibling tool: propose_write no longer validates proposed_scopes' format
// itself, agentProposeWrite does, and the resulting 400 must still surface
// to the calling agent verbatim.
func TestProposeWrite_InvalidScopeReturnsVerbatimValidationError_ViaMCP(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")

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

// TestProposeWrite_StoreErrorIsMasked_ViaMCP is the negative counterpart: an
// error that originates in the store layer (here, targeting a fact outside
// the proposer's grants) must NOT be shown verbatim, even though its message
// happens to be informative and non-sensitive in this particular case — only
// a *agentclient.ValidationError (mirroring only bouncer.ValidationError
// server-side) is safe to return as-is; everything else stays masked by
// toolError.
func TestProposeWrite_StoreErrorIsMasked_ViaMCP(t *testing.T) {
	ab := newAgentBackend(t, nil)
	aliceSession := mintAgentSession(t, ab, "alice")
	ctx := context.Background()

	proposed := callTool[proposeWriteOutput](t, aliceSession, "propose_write", proposeWriteArgs{
		Content:        "alice's medical condition is confidential",
		ProposedScopes: []string{"identity.medical"},
	})
	commitVec, err := embed.Stub{}.Embed(ctx, "alice's medical condition is confidential")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	fact, err := ab.st.CommitDiff(ctx, proposed.DiffID, "human-reviewer", commitVec, "")
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	// bob has a real, active grant, just not one covering identity.medical —
	// proves the store's rejection is scope-specific.
	if _, err := ab.st.CreateGrant(ctx, "bob", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	bobSession := mintAgentSession(t, ab, "bob")

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

func TestProposeWrite_TooManyScopesIsError(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")

	scopes := make([]string, maxScopesPerRequest+1)
	for i := range scopes {
		scopes[i] = "preferences.coffee"
	}
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "propose_write",
		Arguments: proposeWriteArgs{Content: "x", ProposedScopes: scopes},
	})
	if err != nil {
		t.Fatalf("CallTool() transport error = %v", err)
	}
	if !res.IsError {
		t.Fatal("propose_write with more than maxScopesPerRequest scopes: want a tool error, got success")
	}
}

func TestProposeWrite_ContentTooLongIsError(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "propose_write",
		Arguments: proposeWriteArgs{
			Content:        string(make([]byte, maxContentLength+1)),
			ProposedScopes: []string{"preferences.coffee"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool() transport error = %v", err)
	}
	if !res.IsError {
		t.Fatal("propose_write with content over maxContentLength: want a tool error, got success")
	}
}

// TestProposeWrite_RateLimited exercises the ticket this rate limit exists
// for, over the HTTP boundary: hitting a low configured limit surfaces as a
// structured status=RATE_LIMITED (not a generic tool error — res.IsError
// stays false, same as insufficient_scope), nothing gets staged once
// limited, and a different subject's own calls are completely unaffected by
// the first subject's activity.
func TestProposeWrite_RateLimited(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, reviewer_tokens, agent_tokens, grant_requests, data_keys, propose_write_rate_limits, capability_grant_identities, capability_grant_tokens, signing_policies, webauthn_credentials, webauthn_challenges, enrollment_latch`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := testSealedStore(t, pool)
	b := bouncer.New(st, embed.Stub{}, bouncer.PassthroughClassifier{})
	b.RateLimit = 2
	b.RateLimitWindow = time.Hour
	wa := testWebAuthn(t)
	a := api.New(st, embed.Stub{}, summarize.Stub{}, testOrigin, 10*time.Second, wa, b)
	srv := httptest.NewServer(a.AgentRoutes())
	t.Cleanup(srv.Close)
	ab := &agentBackend{srv: srv, st: st, pool: pool}

	agentA := mintAgentSession(t, ab, "agent-a")
	agentB := mintAgentSession(t, ab, "agent-b")

	for i := 0; i < 2; i++ {
		out := callTool[proposeWriteOutput](t, agentA, "propose_write", proposeWriteArgs{
			Content:        fmt.Sprintf("agent-a fact number %d", i),
			ProposedScopes: []string{"preferences.coffee"},
		})
		if out.Status == "RATE_LIMITED" {
			t.Fatalf("proposal %d for agent-a: status = RATE_LIMITED, want it to succeed (still within limit)", i)
		}
	}

	third := callTool[proposeWriteOutput](t, agentA, "propose_write", proposeWriteArgs{
		Content:        "agent-a fact number 3",
		ProposedScopes: []string{"preferences.coffee"},
	})
	if third.Status != "RATE_LIMITED" {
		t.Fatalf("propose_write status = %q after exceeding the limit, want RATE_LIMITED", third.Status)
	}
	if third.DiffID != "" {
		t.Fatalf("RATE_LIMITED response carried a diff_id (%q); nothing should have been staged", third.DiffID)
	}

	var audited int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE event_type = 'rate_limited' AND subject = 'agent-a'`,
	).Scan(&audited); err != nil {
		t.Fatalf("querying audit_log for rate_limited rows: %v", err)
	}
	if audited != 1 {
		t.Errorf("audit_log rate_limited rows for agent-a = %d, want exactly 1 (one per denial)", audited)
	}

	bOut := callTool[proposeWriteOutput](t, agentB, "propose_write", proposeWriteArgs{
		Content:        "agent-b's own, unrelated fact",
		ProposedScopes: []string{"preferences.tea"},
	})
	if bOut.Status == "RATE_LIMITED" {
		t.Fatal("agent-b's first proposal was rate limited by agent-a's activity — the limit is not correctly keyed per subject")
	}
}

// --- request_grant ----------------------------------------------------------

func TestRequestGrant_ViaMCP(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")
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
	granted, err := ab.st.GrantedScopes(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopes() error = %v", err)
	}
	if len(granted) != 0 {
		t.Fatalf("GrantedScopes() after request_grant = %v, want empty (no auto-approval)", granted)
	}

	reqs, err := ab.st.ListGrantRequests(ctx, store.GrantRequestPending)
	if err != nil {
		t.Fatalf("ListGrantRequests() error = %v", err)
	}
	if len(reqs) != 1 || reqs[0].Subject != "agent-a" {
		t.Fatalf("ListGrantRequests() = %+v, want one request from agent-a", reqs)
	}
}

// TestRequestGrant_InvalidScopeIsValidationErrorVerbatim, TestRequestGrant_EmptyScopesIsValidationErrorVerbatim,
// and TestRequestGrant_NegativeTTLIsValidationErrorVerbatim are the
// moved-not-deleted regression tests for request_grant.go: none of these
// three checks (per-scope format, non-empty requested_scopes, non-negative
// ttl_seconds) run client-side any more — agentRequestGrant
// (agent_routes.go) reproduces every one of them, and the resulting 400 must
// still surface to the calling agent verbatim, not as a masked tool error.

func TestRequestGrant_InvalidScopeIsValidationErrorVerbatim(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")

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
	if text := toolErrorText(t, res); strings.Contains(text, "internal error") {
		t.Fatalf("error text = %q, want the validation message verbatim", text)
	}
}

func TestRequestGrant_EmptyScopesIsValidationErrorVerbatim(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")

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
	if text := toolErrorText(t, res); strings.Contains(text, "internal error") {
		t.Fatalf("error text = %q, want the validation message verbatim", text)
	}
}

func TestRequestGrant_NegativeTTLIsValidationErrorVerbatim(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")

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
	if text := toolErrorText(t, res); strings.Contains(text, "internal error") {
		t.Fatalf("error text = %q, want the validation message verbatim", text)
	}
}

func TestRequestGrant_TooManyScopesIsError(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")

	scopes := make([]string, maxScopesPerRequest+1)
	for i := range scopes {
		scopes[i] = "identity.basic"
	}
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "request_grant",
		Arguments: requestGrantArgs{RequestedScopes: scopes},
	})
	if err != nil {
		t.Fatalf("CallTool() transport error = %v", err)
	}
	if !res.IsError {
		t.Fatal("request_grant with more than maxScopesPerRequest scopes: want a tool error, got success")
	}
}

func TestRequestGrant_JustificationTooLongIsError(t *testing.T) {
	ab := newAgentBackend(t, nil)
	session := mintAgentSession(t, ab, "agent-a")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "request_grant",
		Arguments: requestGrantArgs{
			RequestedScopes: []string{"identity.basic"},
			Justification:   string(make([]byte, maxJustificationLength+1)),
		},
	})
	if err != nil {
		t.Fatalf("CallTool() transport error = %v", err)
	}
	if !res.IsError {
		t.Fatal("request_grant with justification over maxJustificationLength: want a tool error, got success")
	}
}
