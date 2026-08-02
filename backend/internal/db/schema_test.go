package db

import (
	"context"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	// Not named url: that would shadow the net/url package this file imports.
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping schema integration tests (see docker-compose.yml)")
	}
	return dsn
}

func TestLatestEmbeddedVersion(t *testing.T) {
	v, err := latestEmbeddedVersion()
	require.NoError(t, err)
	// The init migration's timestamp is the floor; anything lower means the
	// filename parse silently matched something it shouldn't have.
	require.GreaterOrEqual(t, v, uint(20260722234814))
}

func TestCheckSchema_PassesOnAMigratedDatabase(t *testing.T) {
	url := testDatabaseURL(t)
	require.NoError(t, Migrate(url))

	ctx := context.Background()
	pool, err := Open(ctx, url)
	require.NoError(t, err)
	defer pool.Close()

	require.NoError(t, CheckSchema(ctx, pool), "CheckSchema rejected a freshly migrated database")
}

// The whole point of the split: CheckSchema must not change anything. Steps the
// schema back, confirms CheckSchema neither advances it nor clears the shortfall,
// then restores — an assertion the earlier version of this test claimed to make
// but didn't, because it only ever ran against an already-current database.
func TestCheckSchema_DoesNotMigrate(t *testing.T) {
	url := testDatabaseURL(t)
	require.NoError(t, Migrate(url))

	m, closeFn, err := migrator(url)
	require.NoError(t, err)
	require.NoError(t, m.Steps(-1))
	behind, _, err := m.Version()
	closeFn()
	require.NoError(t, err)

	ctx := context.Background()
	pool, err := Open(ctx, url)
	require.NoError(t, err)
	defer pool.Close()

	err = CheckSchema(ctx, pool)
	require.ErrorIs(t, err, ErrSchemaNotCurrent, "a behind database should not pass")
	require.ErrorContains(t, err, "cmd/migrate", "the refusal should say how to fix it")

	m2, closeFn2, err := migrator(url)
	require.NoError(t, err)
	after, _, err := m2.Version()
	closeFn2()
	require.NoError(t, err)
	require.Equal(t, behind, after, "CheckSchema advanced the schema version")

	require.NoError(t, Migrate(url), "restoring the schema after the test")
}

// CheckSchema must issue no DDL. Going through golang-migrate would create
// schema_migrations just by constructing the migrator, which is why this reads
// the table directly — this test is the regression guard for that.
func TestCheckSchema_CreatesNoTablesOnAVirginDatabase(t *testing.T) {
	adminURL := testDatabaseURL(t)
	ctx := context.Background()

	admin, err := Open(ctx, adminURL)
	require.NoError(t, err)
	defer admin.Close()

	const scratch = "chuvar_checkschema_probe"
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+scratch)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Skipf("cannot create a scratch database (%v); skipping DDL probe", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+scratch)
	})

	// Swap the database name by parsing, not by replacing a hard-coded substring:
	// a DATABASE_URL pointing at any other database name would make the replace a
	// no-op, and this probe would run against the migrated admin database instead
	// of a virgin one — gutting the invariant it exists to guard.
	u, err := url.Parse(adminURL)
	require.NoError(t, err)
	u.Path = "/" + scratch
	probeURL := u.String()
	probe, err := Open(ctx, probeURL)
	require.NoError(t, err)
	defer probe.Close()

	err = CheckSchema(ctx, probe)
	require.ErrorIs(t, err, ErrSchemaNotCurrent)
	require.ErrorContains(t, err, "never been migrated")

	var tables int
	require.NoError(t, probe.QueryRow(ctx,
		"SELECT count(*) FROM pg_tables WHERE schemaname = 'public'").Scan(&tables))
	require.Zero(t, tables, "CheckSchema created %d table(s); it must issue no DDL", tables)
}
