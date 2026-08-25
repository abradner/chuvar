package main

// This file is the evidence for the cutover (ticket E3, #82/#86 PR 4):
// mcpserver no longer needs DATABASE_URL, anywhere in its process
// environment, to serve any of the four v0 tools. It boots a real
// *api.API serving AgentRoutes() over httptest (the same surface
// cmd/apiserver's second http.Server, CHUVAR_AGENT_ADDR, exposes in
// production), mints an agent-class token directly through the store
// (standing in for a human reviewer's POST /api/agent-tokens mint action —
// minting over HTTP needs a second factor by design, so a test can't do
// that itself), unsets DATABASE_URL, and drives every tool end to end
// through the exact same agentclient.Client + mcptools.Register wiring
// run() constructs at real boot.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
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
	"github.com/abradner/chuvar/backend/internal/db"
	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/mcptools"
	"github.com/abradner/chuvar/backend/internal/store"
	"github.com/abradner/chuvar/backend/internal/summarize"
)

const (
	testRPID   = "localhost"
	testOrigin = "http://localhost:5173"
)

func testWebAuthn(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          testRPID,
		RPDisplayName: "Chuvar mcpserver cutover test",
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

// backend bundles a real store + api.API serving AgentRoutes() over
// httptest, and a raw *pgxpool.Pool for fixture setup and audit assertions —
// standing in for a real apiserver deployment. Reproduced from
// internal/api/agent_routes_test.go's agentTestServer shape rather than
// imported: internal/api is a branch below this PR and off-limits to modify,
// and its test helpers are unexported anyway.
type backend struct {
	pool *pgxpool.Pool
	st   *store.Store
	b    *bouncer.Bouncer
	srv  *httptest.Server
}

// newBackend reads DATABASE_URL once, before any test in this file unsets it
// from the process environment, and captures it as a plain Go string so the
// pool this function opens keeps working regardless of what happens to the
// environment afterward (pgxpool.Pool parses its connection string once at
// Open time — it never re-reads the environment per query).
func newBackend(t *testing.T) *backend {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping mcpserver cutover integration test")
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

	st := store.New(pool)
	emb := embed.Stub{}
	b := bouncer.New(st, emb, bouncer.PassthroughClassifier{})
	a := api.New(st, emb, summarize.Stub{}, testOrigin, 10*time.Second, testWebAuthn(t), b)
	srv := httptest.NewServer(a.AgentRoutes())
	t.Cleanup(srv.Close)

	return &backend{pool: pool, st: st, b: b, srv: srv}
}

// mintToken mints a fresh agent-class token for subject directly through the
// store — the test-only equivalent of a human reviewer's
// POST /api/agent-tokens action (createAgentToken, internal/api/agent_tokens.go).
// Minting over HTTP is deliberately not exercised here: that endpoint sits
// behind requireStrongFactor (a TOTP/WebAuthn second factor), by design —
// see CLAUDE.md principle 10 ("presence is precious") — and a test standing
// that up would just be exercising webauthn_test.go's own virtual-authenticator
// machinery for no benefit to this test's actual claim.
func (bk *backend) mintToken(t *testing.T, subject string) string {
	t.Helper()
	plaintext := "cutover-test-token-" + subject + "-" + t.Name()
	if _, err := bk.st.CreateAgentToken(context.Background(), subject, "cutover test: "+subject, plaintext); err != nil {
		t.Fatalf("CreateAgentToken() error = %v", err)
	}
	return plaintext
}

// unsetenvRestoring removes key from the process environment for the
// duration of t, restoring whatever value (or absence) key had beforehand
// once t completes — the same LookupEnv-then-Cleanup shape
// TestCutover_MCPServerNeedsNoDatabaseCredential already uses for
// DATABASE_URL above, factored out here because TestBoot_FailsFastOnMissingToken
// needs it for two variables. t.Setenv can't express "unset" on its own
// (t.Setenv(key, "") sets an empty value, which is not the same thing:
// config.Secret would still see the key as present), so this wraps the
// plain os.Unsetenv this test needs while still guaranteeing the ambient
// environment this test binary runs in is never left mutated for whichever
// test runs next.
func unsetenvRestoring(t *testing.T, key string) {
	t.Helper()
	if v, ok := os.LookupEnv(key); ok {
		t.Cleanup(func() { os.Setenv(key, v) })
		os.Unsetenv(key)
	}
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

// newMCPSession registers the v0 tool surface against client and returns a
// live in-memory MCP client session — the exact wiring run() performs
// (mcptools.Register(server, client)) after boot() succeeds, minus the
// process boundary and stdio transport.
func newMCPSession(t *testing.T, client *agentclient.Client) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	server := mcp.NewServer(&mcp.Implementation{Name: "chuvar-test", Version: "test"}, nil)
	mcptools.Register(server, client)
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

// TestCutover_MCPServerNeedsNoDatabaseCredential is the proof this PR's brief
// asks for: with DATABASE_URL absent from the process environment (removed,
// not merely empty, via os.Unsetenv — matching what a real launcher that
// simply never sets it looks like), boot()'s config.Secret("CHUVAR_AGENT_TOKEN")
// + client.Whoami() health check succeeds, mcptools.Register wires up the
// same four tools against nothing but that client, and every tool works end
// to end over the real HTTP path: list_grants, request_grant,
// read_with_scope_check (both ok and insufficient_scope), and propose_write
// (both a normal accept and RATE_LIMITED). audit_log.subject is asserted to
// be the authenticated agent's own subject throughout — never anything a
// tool argument could have supplied, since none of the four tools' arg
// structs carry a Subject field at all.
func TestCutover_MCPServerNeedsNoDatabaseCredential(t *testing.T) {
	bk := newBackend(t)
	ctx := context.Background()

	// Set once, up front, and never changed again: CheckProposeWriteRateLimit
	// keys its per-window counter row on time.Now().UTC().Truncate(window)
	// (internal/store/rate_limit.go), so changing RateLimitWindow between two
	// calls in the same test would silently move the second call into a
	// fresh bucket — the two propose_write calls below must share the exact
	// same window for the second one to actually observe the first one's
	// count and trip RATE_LIMITED. A limit of 1 admits the first ("ok" path)
	// proposal and rejects the second (the RATE_LIMITED path).
	bk.b.RateLimit = 1
	bk.b.RateLimitWindow = time.Hour

	// The proof itself: no DATABASE_URL anywhere in this process's
	// environment from this point on. bk's pool was already opened above
	// (pgxpool.Pool doesn't re-consult the environment per query), so the
	// backend keeps working — only mcpserver's own path is being asserted as
	// DB-credential-free here, not the test's own fixture plumbing.
	if v, ok := os.LookupEnv("DATABASE_URL"); ok {
		os.Unsetenv("DATABASE_URL")
		t.Cleanup(func() { os.Setenv("DATABASE_URL", v) })
	}
	if _, ok := os.LookupEnv("DATABASE_URL"); ok {
		t.Fatal("DATABASE_URL still set after Unsetenv; test setup is broken")
	}

	token := bk.mintToken(t, "agent-cutover")

	// boot() reads CHUVAR_AGENT_API_URL/CHUVAR_AGENT_TOKEN from the process
	// environment — point both at this test's server/token, then call it
	// exactly as run() does, with DATABASE_URL absent throughout.
	t.Setenv("CHUVAR_AGENT_API_URL", bk.srv.URL)
	t.Setenv("CHUVAR_AGENT_TOKEN", token)
	bootedClient, subject, err := boot(ctx)
	if err != nil {
		t.Fatalf("boot() error = %v, want success with no DATABASE_URL set", err)
	}
	if subject != "agent-cutover" {
		t.Fatalf("boot() subject = %q, want %q", subject, "agent-cutover")
	}

	session := newMCPSession(t, bootedClient)

	// list_grants: empty to start.
	grants := callTool[grantsOutputShim](t, session, "list_grants", struct{}{})
	if len(grants.Grants) != 0 {
		t.Fatalf("list_grants before any grant = %+v, want empty", grants.Grants)
	}

	// read_with_scope_check: insufficient_scope before any grant exists.
	insufficient := callTool[readOutputShim](t, session, "read_with_scope_check", map[string]any{
		"query":            "anything",
		"requested_scopes": []string{"preferences.coffee"},
	})
	if insufficient.Status != "insufficient_scope" {
		t.Fatalf("read_with_scope_check status = %q, want insufficient_scope", insufficient.Status)
	}
	if len(insufficient.MissingScopes) != 1 || insufficient.MissingScopes[0] != "preferences.coffee" {
		t.Fatalf("missing_scopes = %v, want [preferences.coffee]", insufficient.MissingScopes)
	}

	// request_grant: stages a request, creates no real grant.
	reqOut := callTool[requestGrantOutputShim](t, session, "request_grant", map[string]any{
		"requested_scopes": []string{"preferences.coffee"},
		"justification":    "cutover integration test",
	})
	if reqOut.Status != "pending" || reqOut.RequestID == "" {
		t.Fatalf("request_grant = %+v, want status=pending with a request_id", reqOut)
	}
	granted, err := bk.st.GrantedScopes(ctx, "agent-cutover")
	if err != nil {
		t.Fatalf("GrantedScopes() error = %v", err)
	}
	if len(granted) != 0 {
		t.Fatalf("GrantedScopes() after request_grant = %v, want empty (no auto-approval)", granted)
	}

	// A human reviewer approves the grant directly (store-level, standing in
	// for the reviewer REST surface) so read_with_scope_check has something
	// to find. propose_write + commit puts a fact behind that scope.
	if _, err := bk.st.CreateGrant(ctx, "agent-cutover", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	proposed := callTool[proposeOutputShim](t, session, "propose_write", map[string]any{
		"content":         "user's favorite coffee order is a flat white",
		"proposed_scopes": []string{"preferences.coffee"},
	})
	if proposed.Status != "pending" || proposed.DiffID == "" {
		t.Fatalf("propose_write = %+v, want status=pending with a diff_id", proposed)
	}
	commitVec, err := embed.Stub{}.Embed(ctx, "user's favorite coffee order is a flat white")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	if _, err := bk.st.CommitDiff(ctx, proposed.DiffID, "human-reviewer", commitVec, ""); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	ok := callTool[readOutputShim](t, session, "read_with_scope_check", map[string]any{
		"query":            "coffee",
		"requested_scopes": []string{"preferences.coffee"},
	})
	if ok.Status != "ok" || len(ok.Facts) != 1 {
		t.Fatalf("read_with_scope_check after commit = %+v, want status=ok with 1 fact", ok)
	}

	// propose_write RATE_LIMITED: the one proposal above already consumed
	// this subject's entire budget under a limit of 1, so the next one trips
	// it. Confirms the trap-flagged status discrimination holds over the
	// real transport (ProposeResult's Status field, not a truthy DiffID).
	limited := callTool[proposeOutputShim](t, session, "propose_write", map[string]any{
		"content":         "this should be rejected",
		"proposed_scopes": []string{"preferences.coffee"},
	})
	if limited.Status != agentclient.StatusRateLimited {
		t.Fatalf("propose_write status = %q, want RATE_LIMITED", limited.Status)
	}
	if limited.DiffID != "" {
		t.Fatalf("RATE_LIMITED propose_write carried a diff_id (%q), want none", limited.DiffID)
	}

	// audit_log.subject is the authenticated agent's own subject on every
	// row this session produced — never anything a tool argument could have
	// supplied (none of the four tools' args have a Subject field).
	// "human-reviewer" rows (grant_created, diff_committed) are this test's
	// own stand-ins for a human's out-of-band approval action — store.CreateGrant/
	// CommitDiff calls made directly against bk.st, never through the MCP
	// tool surface this test is actually asserting about. Every row produced
	// by a tool call this session made (insufficient_scope, read,
	// rate_limited, and request_grant's own audit trail via grant_requests)
	// must carry the authenticated agent's subject and nothing else — the
	// cutover's central claim: identity comes from the bearer token, never a
	// tool argument (none of the four tools' arg structs have a Subject
	// field to spoof in the first place).
	var offBySubject int
	if err := bk.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE subject NOT IN ('agent-cutover', 'human-reviewer')`,
	).Scan(&offBySubject); err != nil {
		t.Fatalf("querying audit_log subjects: %v", err)
	}
	if offBySubject != 0 {
		t.Fatalf("audit_log has %d rows attributed to neither agent-cutover nor human-reviewer", offBySubject)
	}
	var toolCallRows int
	if err := bk.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE event_type IN ('insufficient_scope', 'read', 'rate_limited') AND subject = 'agent-cutover'`,
	).Scan(&toolCallRows); err != nil {
		t.Fatalf("querying audit_log tool-call rows: %v", err)
	}
	if toolCallRows != 3 {
		t.Fatalf("audit_log has %d insufficient_scope/read/rate_limited rows attributed to agent-cutover, want 3 (one per tool call that audits)", toolCallRows)
	}
	var subj string
	if err := bk.pool.QueryRow(ctx, `SELECT subject FROM audit_log LIMIT 1`).Scan(&subj); err != nil {
		t.Fatalf("querying audit_log.subject: %v", err)
	}
	if subj != "agent-cutover" {
		t.Fatalf("audit_log.subject = %q, want %q", subj, "agent-cutover")
	}
}

// grantsOutputShim/readOutputShim/requestGrantOutputShim/proposeOutputShim
// re-declare the JSON shape of mcptools' own (unexported) output types.
// mcptools is a separate package and these fields are the tools' actual
// wire contract (readOutput, listGrantsOutput, requestGrantOutput,
// proposeWriteOutput in internal/mcptools) — duplicated here only because
// this test lives in package main and can't import unexported types from
// another package; every field name matches its mcptools counterpart
// exactly, so a drift between the two would show up as this test failing to
// unmarshal, not as silently passing on stale field names.
type grantsOutputShim struct {
	Grants []struct {
		ID     string   `json:"id"`
		Scopes []string `json:"scopes"`
	} `json:"grants"`
}

type readOutputShim struct {
	Status        string   `json:"status"`
	MissingScopes []string `json:"missing_scopes,omitempty"`
	Facts         []struct {
		ID string `json:"id"`
	} `json:"facts,omitempty"`
}

type requestGrantOutputShim struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

type proposeOutputShim struct {
	DiffID string `json:"diff_id"`
	Status string `json:"status"`
}

// TestBoot_FailsFastOnBadToken proves the boot health check aborts before
// ever registering a tool when CHUVAR_AGENT_TOKEN doesn't authenticate against
// a live backend (a typo, a revoked token, a token minted for a different
// deployment) — and that the message names this as a credential problem,
// distinct from an unreachable backend (TestBoot_FailsFastOnUnreachableBaseURL
// below).
func TestBoot_FailsFastOnBadToken(t *testing.T) {
	bk := newBackend(t)

	t.Setenv("CHUVAR_AGENT_API_URL", bk.srv.URL)
	t.Setenv("CHUVAR_AGENT_TOKEN", "this-token-was-never-minted")

	_, _, err := boot(context.Background())
	if err == nil {
		t.Fatal("boot() with a bad token succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "bad or revoked agent token") {
		t.Errorf("boot() error = %q, want it to name the bad/revoked-token case explicitly", err.Error())
	}
}

// TestBoot_FailsFastOnRevokedToken is the same claim, but for a token that
// authenticated successfully once and was later revoked — the more likely
// real-world trigger for this path than a token that was simply never
// minted.
func TestBoot_FailsFastOnRevokedToken(t *testing.T) {
	bk := newBackend(t)
	token := bk.mintToken(t, "agent-to-revoke")

	agent, ok, err := bk.st.AuthenticateAgentToken(context.Background(), token)
	if err != nil || !ok {
		t.Fatalf("AuthenticateAgentToken() before revoke: ok=%v err=%v", ok, err)
	}
	if err := bk.st.RevokeAgentToken(context.Background(), agent.ID); err != nil {
		t.Fatalf("RevokeAgentToken() error = %v", err)
	}

	t.Setenv("CHUVAR_AGENT_API_URL", bk.srv.URL)
	t.Setenv("CHUVAR_AGENT_TOKEN", token)

	_, _, err = boot(context.Background())
	if err == nil {
		t.Fatal("boot() with a revoked token succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "bad or revoked agent token") {
		t.Errorf("boot() error = %q, want it to name the bad/revoked-token case explicitly", err.Error())
	}
}

// TestBoot_FailsFastOnUnreachableBaseURL proves the other half of the
// distinct-error-message requirement: an unreachable CHUVAR_AGENT_API_URL
// (wrong port, apiserver not started yet, network partition) must not be
// reported the same way a bad token is — this is a "the backend isn't there"
// problem, an operator would look in a different place to fix it.
func TestBoot_FailsFastOnUnreachableBaseURL(t *testing.T) {
	// A closed listener: guaranteed connection-refused, no live server to
	// accidentally answer.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	unreachable := "http://" + l.Addr().String()
	l.Close()

	t.Setenv("CHUVAR_AGENT_API_URL", unreachable)
	t.Setenv("CHUVAR_AGENT_TOKEN", "irrelevant-token")

	_, _, err = boot(context.Background())
	if err == nil {
		t.Fatal("boot() against an unreachable base URL succeeded, want an error")
	}
	if strings.Contains(err.Error(), "bad or revoked agent token") {
		t.Errorf("boot() error = %q, an unreachable base URL must not be reported as a credential problem", err.Error())
	}
	if errors.Is(err, agentclient.ErrUnauthorized) {
		t.Errorf("boot() error = %v, wrapped ErrUnauthorized for an unreachable base URL — the two failure modes must stay distinguishable", err)
	}
}

// TestBoot_FailsFastOnMissingToken proves the CHUVAR_AGENT_TOKEN-absent case —
// the config.Secret/config.ErrNotSet path, never reached in the two tests
// above — also fails loudly rather than proceeding with an empty token.
func TestBoot_FailsFastOnMissingToken(t *testing.T) {
	t.Setenv("CHUVAR_AGENT_API_URL", "http://127.0.0.1:1") // never dialed; token check runs first
	// t.Setenv can't express "unset", and a bare os.Unsetenv here would
	// leak into every later test in this binary if CHUVAR_AGENT_TOKEN(_FILE)
	// happened to be set in the ambient environment (found in review, #119
	// Copilot) — unsetenvRestoring below is this file's own
	// LookupEnv-then-restore idiom (see newBackend's DATABASE_URL handling
	// above), factored out since this test needs it for two variables.
	unsetenvRestoring(t, "CHUVAR_AGENT_TOKEN")
	unsetenvRestoring(t, "CHUVAR_AGENT_TOKEN_FILE")

	_, _, err := boot(context.Background())
	if err == nil {
		t.Fatal("boot() with no CHUVAR_AGENT_TOKEN succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "CHUVAR_AGENT_TOKEN") {
		t.Errorf("boot() error = %q, want it to name the missing variable", err.Error())
	}
}

// TestBoot_TimesOutOnStalledBackend is the regression test for #119 (Codex
// P2 + Copilot, the round's most important finding): the http.Client boot()
// constructed used to have no Timeout at all, so a backend that accepts the
// TCP connection but never writes a response — a stalled proxy, a wedged
// apiserver — would block the Whoami health check forever. That health
// check exists specifically to fail fast (CLAUDE.md principle 5: fail
// closed, loudly, in bounded time); a hang defeats its entire purpose.
//
// The handler below accepts the connection and then blocks on an unbuffered
// channel until this test explicitly releases it in cleanup — simulating a
// backend that never returns headers, not one that's merely slow. boot()
// must still return within a bounded wall-clock time governed by
// apiClientTimeout, not by whatever this handler eventually does.
func TestBoot_TimesOutOnStalledBackend(t *testing.T) {
	unblock := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-unblock
	}))
	// Registered in this order so t.Cleanup's LIFO order runs
	// close(unblock) BEFORE srv.Close(): srv.Close() waits for every
	// in-flight handler to return, and the handler above only returns once
	// unblock is closed — Close() first would deadlock this test's cleanup
	// forever.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(unblock) })

	t.Setenv("CHUVAR_AGENT_API_URL", srv.URL)
	t.Setenv("CHUVAR_AGENT_TOKEN", "irrelevant-token")

	start := time.Now()
	_, _, err := boot(context.Background())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("boot() against a stalled backend succeeded, want a timeout error")
	}
	// Comfortably above apiClientTimeout so a loaded CI box can't flake
	// this on scheduling jitter alone, but nowhere near "the handler
	// eventually responded" territory (the handler here never responds at
	// all until cleanup) — this bound only passes if the *client's* own
	// Timeout is what stopped the call.
	if want := apiClientTimeout + 20*time.Second; elapsed > want {
		t.Fatalf("boot() against a stalled backend took %v, want well under %v (apiClientTimeout=%v) — did the http.Client.Timeout get dropped?", elapsed, want, apiClientTimeout)
	}
	if elapsed < apiClientTimeout {
		t.Fatalf("boot() against a stalled backend returned after %v, before apiClientTimeout (%v) even elapsed — that shouldn't be possible against a handler that never responds", elapsed, apiClientTimeout)
	}
}
