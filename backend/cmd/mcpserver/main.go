// Command mcpserver runs the Chuvar MCP server: the read-with-scope-check,
// propose-write, list-grants, and request-grant tools, backed by chuvar's
// agent-facing HTTP API (internal/api/agent_routes.go), never a direct
// database connection.
//
// This is the cutover ticket E3 names (AGENTS.md §3.6): mcpserver runs inside
// an agent host's own process tree, so it is the process that must hold
// least. It used to hold a raw DATABASE_URL — the chuvar_agent role
// constrained what that credential could do, but the connection itself was
// still a root of trust reachable from agent context, the last live
// violation of CLAUDE.md principle 3 (zero ambient authority). This binary
// now holds exactly one credential, a revocable agent-class bearer token
// (store.AuthenticateAgentToken, minted by a human via POST /api/agent-tokens
// and never by an agent-reachable path — principle 4), and speaks nothing but
// HTTP to reach the backend. There is no db.Open, no pgxpool.Pool, no
// store.Store, no embed.Embedder, no bouncer.Bouncer anywhere in this
// process — every one of those now lives exactly once, server-side, behind
// internal/api/agent_routes.go.
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

func main() {
	if err := run(); err != nil {
		slog.Error("mcpserver: fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	baseURL, err := requiredSecret("CHUVAR_API_BASE_URL")
	if err != nil {
		return err
	}
	token, err := requiredSecret("CHUVAR_API_TOKEN")
	if err != nil {
		return err
	}

	client := &agentclient.Client{BaseURL: baseURL, Token: token, HTTP: &http.Client{}}

	ctx := context.Background()

	// mcpserver has no database of its own any more (see the package doc
	// comment), so it cannot run db.CheckSchema the way it used to on boot —
	// there is no schema for this process to check. That verification isn't
	// gone, it moved: apiserver (cmd/apiserver/main.go) still runs its own
	// db.CheckSchema at ITS boot, before it ever starts serving AgentRoutes()
	// at all, so "is the backend up and its schema current" is exactly the
	// question a successful whoami call below already answers by construction
	// — if the schema were stale, apiserver would have refused to start, and
	// this call would be hitting nothing. Calling whoami here is mcpserver's
	// substitute boot health check: fail fast and loudly (CLAUDE.md principle
	// 5) if the configured token doesn't authenticate, or if the backend
	// can't be reached at all, rather than starting up cleanly and failing
	// every subsequent MCP tool call one at a time with no clear diagnosis.
	who, err := checkHealth(ctx, client)
	if err != nil {
		return err
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "chuvar", Version: "v0"}, nil)
	mcptools.Register(server, client)

	slog.Info("mcpserver: authenticated, serving on stdio", "subject", who)
	return server.Run(ctx, &mcp.StdioTransport{})
}

// checkHealth calls GET /api/agent/whoami and returns the authenticated
// subject on success. Split out from run() so a test can drive it directly
// against a fake or real backend without going through process env vars or
// serving stdio.
//
// errors.Is(err, agentclient.ErrUnauthorized) gets its own, more actionable
// message ("bad or revoked token") than every other failure mode (backend
// unreachable, a 5xx, a transport error) — those stay generic per
// agentclient's own masking stance (see its doc comments), since there's
// nothing this process can usefully add beyond "could not reach the API."
func checkHealth(ctx context.Context, client *agentclient.Client) (subject string, err error) {
	who, err := client.Whoami(ctx)
	if err != nil {
		if errors.Is(err, agentclient.ErrUnauthorized) {
			return "", fmt.Errorf("mcpserver: agent token rejected by %s — it may be missing, malformed, or revoked: %w", client.BaseURL, err)
		}
		return "", fmt.Errorf("mcpserver: could not reach chuvar API at %s: %w", client.BaseURL, err)
	}
	return who.Subject, nil
}

// requiredSecret reads key via config.Secret (so <KEY>_FILE indirection
// works, AGENTS.md §3.7) and fails fast with a clear message if it's absent
// — the same two-branch shape cmd/approver/main.go uses for CHUVAR_API_TOKEN:
// a hard error from config.Secret itself (e.g. a credential file with bad
// permissions) is reported as-is, while a plain "nothing was set"
// (config.ErrNotSet) gets mcpserver's own explanatory message naming the
// variable. Both CHUVAR_API_BASE_URL and CHUVAR_API_TOKEN are required here,
// unlike cmd/approver's optional base URL (which falls back to
// http://localhost:8080): mcpserver runs unattended inside an agent host, so
// a silent default pointing at the wrong backend is a worse failure mode
// than refusing to start.
func requiredSecret(key string) (string, error) {
	v, err := config.Secret(key)
	if err != nil && !errors.Is(err, config.ErrNotSet) {
		return "", fmt.Errorf("mcpserver: %w", err)
	}
	if err != nil || v == "" {
		return "", fmt.Errorf("mcpserver: required environment variable %s is not set (or %s_FILE)", key, key)
	}
	return v, nil
}
