package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeSecret(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte(content), mode))
	return path
}

func TestRequireSecret_PrefersFileOverEnv(t *testing.T) {
	path := writeSecret(t, "postgres://from-file/db", 0o600)
	t.Setenv("TEST_SECRET", "postgres://from-env/db")
	t.Setenv("TEST_SECRET_FILE", path)

	// The file wins: a deployment that went to the trouble of providing one has
	// made the more deliberate choice, and silently preferring the environment
	// would mean a stale env var quietly overriding the credential someone
	// installed on purpose.
	got, err := requireSecret("TEST_SECRET")
	require.NoError(t, err)
	require.Equal(t, "postgres://from-file/db", got)
}

func TestRequireSecret_FallsBackToEnv(t *testing.T) {
	t.Setenv("TEST_SECRET", "postgres://from-env/db")
	t.Setenv("TEST_SECRET_FILE", "")

	got, err := requireSecret("TEST_SECRET")
	require.NoError(t, err)
	require.Equal(t, "postgres://from-env/db", got)
}

func TestRequireSecret_ErrorsWhenNeitherIsSet(t *testing.T) {
	t.Setenv("TEST_SECRET", "")
	t.Setenv("TEST_SECRET_FILE", "")

	_, err := requireSecret("TEST_SECRET")
	require.ErrorContains(t, err, "TEST_SECRET is not set")
}

// A world-readable credential file is worse than an environment variable: it
// grants every user on the host rather than only the one running the process.
// Refusing beats silently accepting it.
func TestRequireSecret_RejectsLoosePermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o666} {
		t.Run(mode.String(), func(t *testing.T) {
			path := writeSecret(t, "postgres://x/db", 0o600)
			require.NoError(t, os.Chmod(path, mode))
			t.Setenv("TEST_SECRET_FILE", path)

			_, err := requireSecret("TEST_SECRET")
			require.ErrorContains(t, err, "chmod 600")
		})
	}
}

func TestRequireSecret_RejectsMissingOrEmptyFile(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		t.Setenv("TEST_SECRET_FILE", filepath.Join(t.TempDir(), "absent"))
		_, err := requireSecret("TEST_SECRET")
		require.Error(t, err)
	})

	t.Run("empty", func(t *testing.T) {
		t.Setenv("TEST_SECRET_FILE", writeSecret(t, "   \n", 0o600))
		_, err := requireSecret("TEST_SECRET")
		require.ErrorContains(t, err, "is empty")
	})

	// A directory or FIFO named as a credential file would otherwise reach
	// ReadFile and either fail confusingly or block forever.
	t.Run("not a regular file", func(t *testing.T) {
		t.Setenv("TEST_SECRET_FILE", t.TempDir())
		_, err := requireSecret("TEST_SECRET")
		require.ErrorContains(t, err, "not a regular file")
	})
}

// Trailing newlines are what every editor and `echo > file` leave behind, and a
// connection string with one appended fails later with a confusing parse error.
func TestRequireSecret_TrimsTrailingWhitespace(t *testing.T) {
	t.Setenv("TEST_SECRET_FILE", writeSecret(t, "postgres://x/db\n\n  ", 0o600))

	got, err := requireSecret("TEST_SECRET")
	require.NoError(t, err)
	require.Equal(t, "postgres://x/db", got)
}

// The credential must not remain in the process environment when it came from a
// file — otherwise the file adds ceremony without removing the exposure it
// exists to remove.
func TestRequireSecret_FileValueIsNotPlacedInTheEnvironment(t *testing.T) {
	t.Setenv("TEST_SECRET", "")
	t.Setenv("TEST_SECRET_FILE", writeSecret(t, "postgres://from-file/db", 0o600))

	_, err := requireSecret("TEST_SECRET")
	require.NoError(t, err)
	require.Empty(t, os.Getenv("TEST_SECRET"), "the secret was copied into the environment")
}
