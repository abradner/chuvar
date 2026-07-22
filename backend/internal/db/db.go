// Package db owns the Postgres connection pool and schema migrations. Postgres+pgvector
// is the sole canonical store (AGENTS.md §3.2) — every other package talks to Postgres
// through here rather than opening its own connection.
package db

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5" // registers the "pgx5" driver scheme
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Open connects to Postgres and returns a ready-to-use pool. It does not run
// migrations — call Migrate separately so callers can control when schema changes
// happen (e.g. skip it in tests that manage their own schema state).
func Open(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("db: creating connection pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: pinging database: %w", err)
	}
	return pool, nil
}

// Migrate applies all pending up-migrations embedded in this package. Safe to call
// on every process start: a no-op if the schema is already current.
func Migrate(databaseURL string) error {
	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("db: loading embedded migrations: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", source, toPgx5URL(databaseURL))
	if err != nil {
		return fmt.Errorf("db: initializing migrator: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("db: applying migrations: %w", err)
	}
	return nil
}

// toPgx5URL rewrites a standard postgres:// URL to the pgx5:// scheme that the
// golang-migrate pgx/v5 driver (imported for its side-effecting init/registration
// below) expects.
func toPgx5URL(databaseURL string) string {
	return "pgx5://" + trimScheme(databaseURL)
}

func trimScheme(url string) string {
	for _, prefix := range []string{"postgres://", "postgresql://"} {
		if len(url) > len(prefix) && url[:len(prefix)] == prefix {
			return url[len(prefix):]
		}
	}
	return url
}
