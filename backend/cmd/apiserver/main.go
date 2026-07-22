// Command apiserver runs the REST API behind the approval UI. Separate process
// from cmd/mcpserver (which speaks MCP over stdio to agents) — this one speaks
// HTTP to the frontend, on a normal listening port.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"memoryvault/internal/api"
	"memoryvault/internal/config"
	"memoryvault/internal/db"
	"memoryvault/internal/embed"
	"memoryvault/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error("apiserver: fatal", "error", err)
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

	a := api.New(store.New(pool), embed.Stub{})

	slog.Info("apiserver: listening", "addr", cfg.HTTPAddr)
	return http.ListenAndServe(cfg.HTTPAddr, a.Routes())
}
