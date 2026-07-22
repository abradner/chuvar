// Command mcpserver runs the Memory Vault MCP server: the read-with-scope-check,
// propose-write, and list-grants tools, backed by Postgres+pgvector.
package main

import (
	"context"
	"log/slog"
	"os"

	"memoryvault/internal/config"
	"memoryvault/internal/db"
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

	slog.Info("mcpserver: connected and migrated, tools not yet wired up")
	return nil
}
