package db

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping schema integration tests (see docker-compose.yml)")
	}
	return url
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
	require.NoError(t, CheckSchema(url), "CheckSchema rejected a freshly migrated database")
}

// The whole point of the split: CheckSchema must not change anything. Running
// it against a database that is behind has to leave it behind.
func TestCheckSchema_DoesNotMigrate(t *testing.T) {
	url := testDatabaseURL(t)
	require.NoError(t, Migrate(url))

	m, closeFn, err := migrator(url)
	require.NoError(t, err)
	before, dirtyBefore, err := m.Version()
	closeFn()
	require.NoError(t, err)
	require.False(t, dirtyBefore)

	require.NoError(t, CheckSchema(url))

	m2, closeFn2, err := migrator(url)
	require.NoError(t, err)
	after, dirtyAfter, err := m2.Version()
	closeFn2()
	require.NoError(t, err)
	require.Equal(t, before, after, "CheckSchema changed the schema version")
	require.False(t, dirtyAfter)
}

func TestCheckSchema_RejectsUnmigratedDatabase(t *testing.T) {
	url := testDatabaseURL(t)
	require.NoError(t, Migrate(url))

	// Step down one migration, verify the check refuses, then restore. Done
	// against the real database rather than a fake because the failure this
	// guards is precisely "the version table says something unexpected", which
	// a fake would only ever tell us what we told it.
	m, closeFn, err := migrator(url)
	require.NoError(t, err)
	require.NoError(t, m.Steps(-1))
	closeFn()

	err = CheckSchema(url)
	require.ErrorIs(t, err, ErrSchemaNotCurrent)
	require.ErrorContains(t, err, "cmd/migrate", "the refusal should say how to fix it")

	require.NoError(t, Migrate(url), "restoring the schema after the test")
	require.NoError(t, CheckSchema(url))
}
