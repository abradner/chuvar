package mcptools

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"memoryvault/internal/bouncer"
	"memoryvault/internal/db"
	"memoryvault/internal/embed"
	"memoryvault/internal/store"
)

// testSession spins up a real MCP server (with all v0 tools registered) and a real
// client connected over an in-memory transport, so these tests exercise the actual
// protocol marshaling/unmarshaling, not just the Go function calls underneath it.
func testSession(t *testing.T) (*mcp.ClientSession, *store.Store) {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := store.New(pool)
	emb := embed.Stub{}
	b := bouncer.New(st, emb, bouncer.PassthroughClassifier{})

	server := mcp.NewServer(&mcp.Implementation{Name: "memoryvault-test", Version: "test"}, nil)
	Register(server, st, emb, b)

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
	session, st := testSession(t)
	ctx := context.Background()

	if _, err := st.CreateGrant(ctx, "agent-a", []string{"identity.basic", "preferences.coffee"}, "facts", nil); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	out := callTool[listGrantsOutput](t, session, "list_grants", listGrantsArgs{Subject: "agent-a"})
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

func TestReadWithScopeCheck_InsufficientScope_ViaMCP(t *testing.T) {
	session, _ := testSession(t)

	out := callTool[readOutput](t, session, "read_with_scope_check", readArgs{
		Subject:         "agent-a",
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

func TestProposeWriteThenRead_EndToEnd_ViaMCP(t *testing.T) {
	session, st := testSession(t)
	ctx := context.Background()

	proposed := callTool[proposeWriteOutput](t, session, "propose_write", proposeWriteArgs{
		Subject:        "agent-a",
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
	if _, err := st.CreateGrant(ctx, "agent-a", []string{"preferences.coffee"}, "facts", nil); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	beforeCommit := callTool[readOutput](t, session, "read_with_scope_check", readArgs{
		Subject:         "agent-a",
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
	if _, err := st.CommitDiff(ctx, proposed.DiffID, "human-reviewer", commitVec); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	afterCommit := callTool[readOutput](t, session, "read_with_scope_check", readArgs{
		Subject:         "agent-a",
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
