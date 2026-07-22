// Command mcpserver runs the Chuvar MCP server: the read-with-scope-check,
// propose-write, and list-grants tools, backed by Postgres+pgvector.
package main

import (
	"context"
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

	if err := db.Migrate(cfg.DatabaseURL); err != nil {
		return err
	}

	ctx := context.Background()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	st := store.New(pool)
	emb := embed.Stub{} // TODO: swap for a real Embedder once the Research track lands one
	b := bouncer.New(st, emb, bouncer.PassthroughClassifier{})

	server := mcp.NewServer(&mcp.Implementation{Name: "chuvar", Version: "v0"}, nil)
	mcptools.Register(server, st, emb, b)

	slog.Info("mcpserver: connected and migrated, serving on stdio")
	return server.Run(ctx, &mcp.StdioTransport{})
}
