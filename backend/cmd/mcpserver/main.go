// Command mcpserver runs the Chuvar MCP server: the read-with-scope-check,
// propose-write, and list-grants tools, backed by Postgres+pgvector.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/bouncer"
	"github.com/abradner/chuvar/backend/internal/config"
	"github.com/abradner/chuvar/backend/internal/db"
	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/mcptools"
	"github.com/abradner/chuvar/backend/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error("mcpserver: fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// MCP_SUBJECT identifies who this server process is authorized to act as.
	// Required, fail-fast — see mcptools.Register's doc comment for why this can't
	// be a client-supplied tool argument: with the stdio transport, whoever
	// launches this process (an agent host spawning one server per session) IS the
	// trust boundary, and the host is expected to set this to the identity of the
	// agent session it's spawning the server for.
	subject, ok := os.LookupEnv("MCP_SUBJECT")
	if !ok || subject == "" {
		return fmt.Errorf("mcpserver: required environment variable MCP_SUBJECT is not set")
	}

	ctx := context.Background()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	// Checks the schema; does not change it. This process is spawned by an agent
	// host and runs inside the agent's own process tree, so it must not assert
	// DDL authority on boot — see db.CheckSchema and AGENTS.md §3.0. Migrating
	// is cmd/migrate's job, or cmd/apiserver's.
	//
	// Runs on the pool rather than opening its own handle, so the check issues
	// exactly one SELECT and no DDL — going through golang-migrate would create
	// the schema_migrations table just by looking.
	//
	// This narrows what mcpserver does with the credentials it holds; it does
	// not remove them. mcpserver still receives DATABASE_URL, and anything
	// holding that can run DDL through SQL regardless. Closing that is ticket
	// E3 (mcpserver becomes an API client with an agent-class token), and this
	// is a step toward it, not a substitute for it.
	if err := db.CheckSchema(ctx, pool); err != nil {
		return err
	}
	// Loudest here of anywhere: this is the process an agent host spawns, so an
	// over-privileged connection is the one that matters most (ticket E8).
	db.WarnIfOverprivileged(ctx, pool, "mcpserver")

	st := store.New(pool)
	emb := embed.Stub{} // TODO: swap for a real Embedder once the Research track lands one
	b := bouncer.New(st, emb, bouncer.PassthroughClassifier{})
	// bouncer.New already defaults these; override from config so an operator
	// can tune propose_write's per-subject rate limit (PROPOSE_WRITE_RATE_LIMIT*)
	// without a code change — see that migration's doc comment for why this
	// exists at all.
	b.RateLimit = cfg.ProposeWriteRateLimit
	b.RateLimitWindow = cfg.ProposeWriteRateLimitWindow

	server := mcp.NewServer(&mcp.Implementation{Name: "chuvar", Version: "v0"}, nil)
	mcptools.Register(server, subject, st, emb, b)

	slog.Info("mcpserver: connected, schema verified, serving on stdio", "subject", subject)
	return server.Run(ctx, &mcp.StdioTransport{})
}
