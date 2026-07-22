// Command mcpserver runs the Memory Vault MCP server: the read-with-scope-check,
// propose-write, and list-grants tools, backed by Postgres+pgvector.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"memoryvault/internal/bouncer"
	"memoryvault/internal/config"
	"memoryvault/internal/db"
	"memoryvault/internal/embed"
	"memoryvault/internal/mcptools"
	"memoryvault/internal/store"
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

	server := mcp.NewServer(&mcp.Implementation{Name: "memoryvault", Version: "v0"}, nil)
	mcptools.Register(server, st, emb, b)

	slog.Info("mcpserver: connected and migrated, serving on stdio")
	return server.Run(ctx, &mcp.StdioTransport{})
}
