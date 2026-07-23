// Package db owns the Postgres connection pool and schema migrations. Postgres+pgvector
// is the sole canonical store (AGENTS.md §3.2) — every other package talks to Postgres
// through here rather than opening its own connection.
package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net/url"

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

	pgx5URL, err := toPgx5URL(databaseURL)
	if err != nil {
		return err
	}

	m, err := migrate.NewWithSourceInstance("iofs", source, pgx5URL)
	if err != nil {
		return fmt.Errorf("db: initializing migrator: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("db: applying migrations: %w", err)
	}
	return nil
}

// toPgx5URL rewrites a postgres:// or postgresql:// URL to the pgx5:// scheme that
// the golang-migrate pgx/v5 driver (imported for its side-effecting init/
// registration above) expects. Parses with net/url rather than a raw string-prefix
// check, so it doesn't silently mishandle query params, IPv6 hosts, or an
// unrecognized scheme — a garbled connection string that fails downstream with a
// confusing driver error is worse than failing here with a clear one.
func toPgx5URL(databaseURL string) (string, error) {
	u, err := url.Parse(databaseURL)
	if err != nil {
		return "", fmt.Errorf("db: parsing DATABASE_URL: %w", err)
	}
	switch u.Scheme {
	case "postgres", "postgresql":
		u.Scheme = "pgx5"
	default:
		return "", fmt.Errorf("db: unsupported DATABASE_URL scheme %q (expected postgres:// or postgresql://)", u.Scheme)
	}
	return u.String(), nil
}
