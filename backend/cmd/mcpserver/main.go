// Command mcpserver runs the Chuvar MCP server: the read-with-scope-check,
// propose-write, list-grants and request-grant tools.
//
// Cutover (ticket E3, #82/#86 PR 4): this process no longer holds a database
// credential. Every prior direct dependency — db.Open, the pgx pool,
// store.New, bouncer.New, embed.Stub, db.CheckSchema, db.WarnIfOverprivileged,
// and the MCP_SUBJECT environment variable that used to bind identity at
// launch — is gone. mcpserver is now a pure HTTP client of internal/api's
// agent-facing surface (AgentRoutes(), CHUVAR_AGENT_ADDR), authenticated with
// a single revocable agent-class token. This closes AGENTS.md §3.0/§3.6's
// last documented "residual gap": mcpserver runs inside an agent's own
// process tree, so it is the one process that must hold least, and it now
// holds nothing that reaches Postgres directly.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/agentclient"
	"github.com/abradner/chuvar/backend/internal/config"
	"github.com/abradner/chuvar/backend/internal/mcptools"
)

// defaultAPIBaseURL matches config.AgentAddr's own default
// (internal/config/config.go, CHUVAR_AGENT_ADDR) — mcpserver talks to the
// agent-facing listener, never the reviewer-facing one (HTTPAddr/8080): the
// two are served on entirely separate net/http.Servers specifically so a
// process holding only an agent token can't reach reviewer routes even at
// the network layer (agent_routes.go's package doc comment).
const defaultAPIBaseURL = "http://127.0.0.1:8081"

func main() {
	if err := run(); err != nil {
		slog.Error("mcpserver: fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	client, subject, err := boot(context.Background())
	if err != nil {
		return err
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "chuvar", Version: "v0"}, nil)
	mcptools.Register(server, client)

	slog.Info("mcpserver: authenticated, serving on stdio", "subject", subject, "api_base_url", client.BaseURL)
	return server.Run(context.Background(), &mcp.StdioTransport{})
}

// boot resolves this process's configuration and proves it can authenticate
// against the agent API before anything starts serving MCP tool calls,
// returning the client every tool then shares and the subject it resolved
// to (for the boot log line, matching what MCP_SUBJECT used to log
// pre-cutover). Factored out of run() so the config-and-health-check path —
// the part of this file with actual decisions in it — is testable without
// also invoking the blocking stdio transport.
func boot(ctx context.Context) (*agentclient.Client, string, error) {
	baseURL := os.Getenv("CHUVAR_API_BASE_URL")
	if baseURL == "" {
		baseURL = defaultAPIBaseURL
	}

	// CHUVAR_API_TOKEN required, fail-fast — same stance as every other
	// required credential in this codebase (AGENTS.md §6, CLAUDE.md principle
	// 5): a server that silently started with no way to authenticate would
	// just fail every tool call one at a time instead of explaining the
	// problem once, up front. config.Secret (not a bare os.Getenv) so
	// CHUVAR_API_TOKEN_FILE indirection works here too, exactly as it does
	// for cmd/approver's own CHUVAR_API_TOKEN — see config.requireSecret's
	// doc comment on why a file beats an environment variable for a
	// credential (AGENTS.md §3.7).
	token, err := config.Secret("CHUVAR_API_TOKEN")
	if err != nil {
		if errors.Is(err, config.ErrNotSet) {
			return nil, "", fmt.Errorf("mcpserver: required environment variable CHUVAR_API_TOKEN is not set (or CHUVAR_API_TOKEN_FILE); " +
				"mint one via POST /api/agent-tokens as an authenticated reviewer (see internal/api/agent_tokens.go)")
		}
		return nil, "", fmt.Errorf("mcpserver: %w", err)
	}

	client := &agentclient.Client{BaseURL: baseURL, Token: token, HTTP: &http.Client{}}

	// Boot health check replaces db.CheckSchema: mcpserver has no database
	// connection left to check a schema version against. Calling
	// GET /api/agent/whoami here and failing fast on any error delegates "is
	// the backend healthy and schema-current" to apiserver, transitively —
	// apiserver runs its own db.CheckSchema at its own boot and refuses to
	// serve at all if the schema is stale (AGENTS.md §3.6's launch-topology
	// table), so a successful Whoami response already proves apiserver is up
	// and passed that gate. This process never re-implements that check
	// itself; it just refuses to proceed until proof it's talking to a live,
	// authenticated backend.
	//
	// ErrUnauthorized gets its own distinct, actionable message (a bad or
	// revoked agent token — an operator problem to fix by minting/rotating a
	// token) rather than folding into the generic "couldn't reach the API"
	// case (an unreachable base URL, wrong port, apiserver down) — the two
	// have different remedies, and CLAUDE.md principle 11 ("failure is
	// legible") means the message should say which kind of no this is.
	who, err := client.Whoami(ctx)
	if err != nil {
		if errors.Is(err, agentclient.ErrUnauthorized) {
			return nil, "", fmt.Errorf("mcpserver: CHUVAR_API_TOKEN did not authenticate against %s (bad or revoked agent token)", baseURL)
		}
		return nil, "", fmt.Errorf("mcpserver: could not reach the agent API at %s: %w", baseURL, err)
	}

	return client, who.Subject, nil
}
