package mcptools

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/bouncer"
	"github.com/abradner/chuvar/backend/internal/db"
	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/store"
)

// testSession spins up a real MCP server bound to subject (with all v0 tools
// registered) and a real client connected over an in-memory transport, so these
// tests exercise the actual protocol marshaling/unmarshaling, not just the Go
// function calls underneath it.
func testSession(t *testing.T, subject string) (*mcp.ClientSession, *store.Store) {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, grant_requests`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := store.New(pool)
	emb := embed.Stub{}
	b := bouncer.New(st, emb, bouncer.PassthroughClassifier{})

	server := mcp.NewServer(&mcp.Implementation{Name: "chuvar-test", Version: "test"}, nil)
	Register(server, subject, st, emb, b)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	return session, st
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

func TestListGrants_ViaMCP(t *testing.T) {
	session, st := testSession(t, "agent-a")
	ctx := context.Background()

	if _, err := st.CreateGrant(ctx, "agent-a", []string{"identity.basic", "preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
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

// TestSubjectIsBoundNotClientSupplied is the regression test for the review
// finding that `subject` used to be a client-supplied, unauthenticated tool
// argument: any caller could pass any subject string and act on their behalf
// (enumerate their grants, read everything they're granted, forge writes
// attributed to them). Now subject is bound once at server construction — this
// proves two independently-bound sessions each only ever see their own subject's
// grants, with no tool argument able to cross that boundary (the args structs
// literally have no Subject field anymore, so this is also enforced at compile
// time, but this test proves the runtime behavior end to end).
func TestSubjectIsBoundNotClientSupplied(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, grant_requests`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}
	st := store.New(pool)

	if _, err := st.CreateGrant(ctx, "alice", []string{"identity.sensitive"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := st.CreateGrant(ctx, "bob", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	emb := embed.Stub{}
	b := bouncer.New(st, emb, bouncer.PassthroughClassifier{})

	newSession := func(subject string) *mcp.ClientSession {
		server := mcp.NewServer(&mcp.Implementation{Name: "chuvar-test", Version: "test"}, nil)
		Register(server, subject, st, emb, b)
		clientTransport, serverTransport := mcp.NewInMemoryTransports()
		if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
			t.Fatalf("server.Connect() error = %v", err)
		}
		client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
		session, err := client.Connect(ctx, clientTransport, nil)
		if err != nil {
			t.Fatalf("client.Connect() error = %v", err)
		}
		t.Cleanup(func() { _ = session.Close() })
		return session
	}

	aliceSession := newSession("alice")
	bobSession := newSession("bob")

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

// revokingEmbedder wraps a real Embedder and revokes a grant as a side effect of
// Embed — simulating a grant being revoked while an embedding call is in flight,
// deterministically rather than relying on real timing. See
// TestReadWithScopeCheck_RevokedMidEmbedIsRejected.
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

func TestReadWithScopeCheck_RevokedMidEmbedIsRejected(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping mcptools integration test")
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, grant_requests`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := store.New(pool)
	g, err := st.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "test-setup")
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	emb := revokingEmbedder{Embedder: embed.Stub{}, st: st, grantID: g.ID}
	b := bouncer.New(st, emb, bouncer.PassthroughClassifier{})

	server := mcp.NewServer(&mcp.Implementation{Name: "chuvar-test", Version: "test"}, nil)
	Register(server, "agent-a", st, emb, b)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	// The grant is active when the tool call starts (requested_scopes passes the
	// pre-embed check) but gets revoked inside Embed, before SearchFacts runs.
	// Without the re-fetch, this would return status=ok using the stale
	// pre-revocation scope snapshot.
	out := callTool[readOutput](t, session, "read_with_scope_check", readArgs{
		Query:           "anything",
		RequestedScopes: []string{"identity.basic"},
	})
	if out.Status != "insufficient_scope" {
		t.Fatalf("read_with_scope_check after mid-request revocation: status = %q, want insufficient_scope", out.Status)
	}
}

func TestProposeWriteThenRead_EndToEnd_ViaMCP(t *testing.T) {
	session, st := testSession(t, "agent-a")
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
	if _, err := st.CreateGrant(ctx, "agent-a", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	beforeCommit := callTool[readOutput](t, session, "read_with_scope_check", readArgs{
		Query:           "coffee",
		RequestedScopes: []string{"preferences.coffee"},
	})
	if len(beforeCommit.Facts) != 0 {
		t.Fatalf("read before commit returned facts = %+v, want none (still only staged)", beforeCommit.Facts)
	}

	// CommitDiff takes its own embedding rather than reusing the one ProposeDiff
	// computed for the dedupe check (that one isn't persisted on the diff row) —
	// re-embedding at commit time is what a real approval-UI backend would do.
	// embed.Stub is deterministic, so this matches what propose_write used.
	commitVec, err := embed.Stub{}.Embed(ctx, "user's favorite coffee order is a flat white")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	if _, err := st.CommitDiff(ctx, proposed.DiffID, "human-reviewer", commitVec, ""); err != nil {
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

func TestReadWithScopeCheck_SummaryDepthRedactsContent_ViaMCP(t *testing.T) {
	session, st := testSession(t, "agent-a")
	ctx := context.Background()

	proposed := callTool[proposeWriteOutput](t, session, "propose_write", proposeWriteArgs{
		Content:        "user's favorite coffee order is a flat white",
		ProposedScopes: []string{"preferences.coffee"},
	})

	if _, err := st.CreateGrant(ctx, "agent-a", []string{"preferences.coffee"}, "memory", "summary", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	commitVec, err := embed.Stub{}.Embed(ctx, "user's favorite coffee order is a flat white")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	if _, err := st.CommitDiff(ctx, proposed.DiffID, "human-reviewer", commitVec, "a stub summary of the coffee fact"); err != nil {
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

func TestRequestGrant_ViaMCP(t *testing.T) {
	session, st := testSession(t, "agent-a")
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
	granted, err := st.GrantedScopes(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopes() error = %v", err)
	}
	if len(granted) != 0 {
		t.Fatalf("GrantedScopes() after request_grant = %v, want empty (no auto-approval)", granted)
	}

	// The request is bound to the session's subject, same as every other tool —
	// not client-suppliable.
	reqs, err := st.ListGrantRequests(ctx, store.GrantRequestPending)
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

// TestRequestGrant_NegativeTTLIsError is the regression test for the review
// finding: a negative ttl_seconds used to fall through the same branch as an
// omitted one, silently becoming "no expiry" instead of a rejected value.
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
