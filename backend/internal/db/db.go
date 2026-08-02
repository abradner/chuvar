// Package db owns the Postgres connection pool and schema migrations. Postgres+pgvector
// is the sole canonical store (AGENTS.md §3.2) — every other package talks to Postgres
// through here rather than opening its own connection.
package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strconv"
	"strings"

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

// ErrSchemaNotCurrent reports a database whose schema is behind the migrations
// embedded in this binary, or has never been migrated at all.
var ErrSchemaNotCurrent = errors.New("db: schema is not current")

// CheckSchema verifies the database is migrated up to the latest embedded
// migration, applying nothing.
//
// This exists so a process can depend on the schema without holding the
// authority to change it. cmd/mcpserver is spawned by an agent host, inside
// the agent's own process tree; a process in that position asserting DDL
// authority on every boot is exactly the ambient authority the trust boundary
// forbids (AGENTS.md §3.0). It reads the schema version and refuses to start if
// the answer is wrong, rather than fixing it.
//
// Failing to start is the point. A stale schema is an operator problem, and an
// agent-side process silently repairing it is how a migration ends up applied
// by whoever happened to launch a tool first.
func CheckSchema(databaseURL string) error {
	m, closeFn, err := migrator(databaseURL)
	if err != nil {
		return err
	}
	defer closeFn()

	latest, err := latestEmbeddedVersion()
	if err != nil {
		return err
	}

	current, dirty, err := m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return fmt.Errorf("%w: database has no migrations applied (latest is %d); "+
			"run `go run ./cmd/migrate` or start cmd/apiserver", ErrSchemaNotCurrent, latest)
	}
	if err != nil {
		return fmt.Errorf("db: reading schema version: %w", err)
	}
	if dirty {
		return fmt.Errorf("%w: schema is marked dirty at version %d — a previous migration "+
			"failed part-way and needs manual resolution (see docs/operations.md)", ErrSchemaNotCurrent, current)
	}
	if current < latest {
		return fmt.Errorf("%w: database is at version %d, this binary expects %d; "+
			"run `go run ./cmd/migrate`", ErrSchemaNotCurrent, current, latest)
	}
	// current > latest is deliberately allowed: that's an older binary against a
	// newer schema, which happens mid-rollout and is not this check's call to
	// veto. Migrations are additive by convention (AGENTS.md §6), so the older
	// binary's queries still work.
	return nil
}

// latestEmbeddedVersion returns the highest migration version compiled into this
// binary, read from the embedded filenames rather than the migrate source
// driver — the driver's cursor is owned by the migrator instance, and borrowing
// it to enumerate would mean opening a second connection just to count files.
func latestEmbeddedVersion() (uint, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return 0, fmt.Errorf("db: reading embedded migrations: %w", err)
	}
	var latest uint
	for _, e := range entries {
		name := e.Name()
		idx := strings.IndexByte(name, '_')
		if idx <= 0 {
			continue
		}
		v, err := strconv.ParseUint(name[:idx], 10, 64)
		if err != nil {
			continue
		}
		if uint(v) > latest {
			latest = uint(v)
		}
	}
	if latest == 0 {
		return 0, errors.New("db: no embedded migrations found")
	}
	return latest, nil
}

// migrator builds a migrate instance over the embedded migrations. The returned
// close function releases both the source and the database handle.
func migrator(databaseURL string) (*migrate.Migrate, func(), error) {
	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return nil, nil, fmt.Errorf("db: loading embedded migrations: %w", err)
	}

	pgx5URL, err := toPgx5URL(databaseURL)
	if err != nil {
		return nil, nil, err
	}

	m, err := migrate.NewWithSourceInstance("iofs", source, pgx5URL)
	if err != nil {
		return nil, nil, fmt.Errorf("db: initializing migrator: %w", err)
	}
	return m, func() { m.Close() }, nil
}

// Migrate applies all pending up-migrations embedded in this package. Safe to call
// on every process start: a no-op if the schema is already current.
//
// Callers hold DDL authority by calling this. That is appropriate for
// cmd/apiserver and cmd/migrate, which run inside the trust boundary; it is not
// appropriate for cmd/mcpserver — see CheckSchema.
func Migrate(databaseURL string) error {
	m, closeFn, err := migrator(databaseURL)
	if err != nil {
		return err
	}
	defer closeFn()

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
