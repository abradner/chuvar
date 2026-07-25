// Command apiserver runs the REST API behind the approval UI. Separate process
// from cmd/mcpserver (which speaks MCP over stdio to agents) — this one speaks
// HTTP to the frontend, on a normal listening port.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/abradner/chuvar/backend/internal/api"
	"github.com/abradner/chuvar/backend/internal/config"
	"github.com/abradner/chuvar/backend/internal/db"
	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/store"
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

	// API_AUTH_TOKEN gates every route (see internal/api's package comment).
	// Required, fail-fast — same stance as MCP_SUBJECT in cmd/mcpserver: an API
	// server that silently started with no way to check who's calling is worse
	// than one that refuses to start at all, given approveStagedDiff is the one
	// endpoint that turns a staged diff into a permanent fact.
	authToken, ok := os.LookupEnv("API_AUTH_TOKEN")
	if !ok || authToken == "" {
		return fmt.Errorf("apiserver: required environment variable API_AUTH_TOKEN is not set")
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

	// CORS_ALLOWED_ORIGIN is optional — the Vite dev server's default port is a
	// reasonable default for local dev, but this is deliberately not baked into
	// config.Config: it's specific to this binary, not shared with cmd/mcpserver.
	allowedOrigin := os.Getenv("CORS_ALLOWED_ORIGIN")
	if allowedOrigin == "" {
		allowedOrigin = "http://localhost:5173"
	}

	a := api.New(store.New(pool), embed.Stub{}, allowedOrigin, authToken, cfg.RequestTimeout)

	// Read/Write/IdleTimeout and ReadHeaderTimeout all come from cfg.RequestTimeout
	// rather than being left at the zero-value http.Server default (no timeout at
	// all) — an unbounded server is a slowloris/hung-connection risk, and there's
	// no reason to accept that when the config knob for it already existed.
	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           a.Routes(),
		ReadTimeout:       cfg.RequestTimeout,
		WriteTimeout:      cfg.RequestTimeout,
		IdleTimeout:       cfg.RequestTimeout,
		ReadHeaderTimeout: cfg.RequestTimeout,
	}

	slog.Info("apiserver: listening", "addr", cfg.HTTPAddr, "allowedOrigin", allowedOrigin)
	return server.ListenAndServe()
}
