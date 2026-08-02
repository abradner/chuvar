// Command migrate applies pending schema migrations and exits.
//
// It exists so migrating is something an operator does on purpose, rather than
// a side effect of whichever process happened to start first. cmd/apiserver
// still migrates on boot (it runs inside the trust boundary and its startup is
// an operator action anyway); cmd/mcpserver deliberately does not, because an
// agent host spawns it — see db.CheckSchema.
//
// Separating it also unblocks the operational cases where starting the API is
// the wrong move: migrating before a deploy switches over, or migrating a
// database whose apiserver cannot start yet because its custody key is not in
// place.
package main

import (
	"log/slog"
	"os"

	"github.com/abradner/chuvar/backend/internal/config"
	"github.com/abradner/chuvar/backend/internal/db"
)

func main() {
	if err := run(); err != nil {
		slog.Error("migrate: fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	// config.Load rather than reading DATABASE_URL directly, so this binary
	// fails the same way as every other one when it is unset.
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if err := db.Migrate(cfg.DatabaseURL); err != nil {
		return err
	}

	slog.Info("migrate: schema is current")
	return nil
}
