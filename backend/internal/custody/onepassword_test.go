package custody

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// requireOpCLI skips with a clear message unless a real, signed-in `op`
// session is available. A found-but-unauthenticated binary is treated the
// same as an absent one: either way this package cannot honestly claim to
// have exercised real 1Password integration, and faking that would be
// exactly the "fake a pass" AGENTS.md warns against.
func requireOpCLI(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("op")
	if err != nil {
		t.Skip("custody: `op` CLI not found on PATH; skipping real 1Password integration test " +
			"(see OnePasswordBackend's doc comment for setup)")
	}
	// `op whoami` is read-only and fails fast (no prompt) when the session
	// isn't signed in, so it's a safe probe to run unconditionally in tests.
	if err := exec.Command(path, "whoami").Run(); err != nil {
		t.Skip("custody: `op` CLI is present but not signed in; run `op signin` to exercise " +
			"this test (see OnePasswordBackend's doc comment for setup)")
	}
	return path
}

// writeStubOp writes a fake `op` executable that runs the given shell
// script body, and returns its path. This is not a substitute for real
// 1Password coverage (see TestOnePasswordBackendAgainstRealCLI below) — it
// exists to exercise OnePasswordBackend's own argument-building, decoding,
// and error-wrapping logic without requiring a signed-in account, the same
// way an HTTP client's tests stub the server rather than requiring a live
// one.
func writeStubOp(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "op")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o700))
	return path
}

func TestOnePasswordBackendUnseal(t *testing.T) {
	raw, err := GenerateKey()
	require.NoError(t, err)
	validB64 := base64.StdEncoding.EncodeToString(raw)

	tests := []struct {
		name    string
		script  string
		wantKey []byte
		wantErr string
	}{
		{
			name:    "success",
			script:  fmt.Sprintf("printf %%s %q\n", validB64),
			wantKey: raw,
		},
		{
			// The realistic failure mode on this very host: `op` installed
			// but the session isn't signed in.
			name:    "not signed in",
			script:  "echo '[ERROR] 2026/08/09 12:00:00 you are not currently signed in' 1>&2\nexit 1\n",
			wantErr: "not currently signed in",
		},
		{
			name:    "item not found",
			script:  "echo '[ERROR] 2026/08/09 12:00:00 could not find item' 1>&2\nexit 1\n",
			wantErr: "could not find item",
		},
		{
			name:    "not base64",
			script:  "printf 'not-valid-base64!!'\n",
			wantErr: "decode 1Password field",
		},
		{
			name:    "wrong length: too short",
			script:  fmt.Sprintf("printf %%s %q\n", base64.StdEncoding.EncodeToString(make([]byte, KeyLen-1))),
			wantErr: "want 32",
		},
		{
			name:    "wrong length: empty field",
			script:  "printf ''\n",
			wantErr: "want 32",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli := writeStubOp(t, tt.script)
			b := &OnePasswordBackend{Reference: "op://Private/chuvar-master-key/password", CLIPath: cli}
			key, err := b.Unseal(context.Background())
			if tt.wantErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantKey, key)
		})
	}
}

// A failing op invocation's stderr is truncated before it reaches the
// wrapped error, since this package doesn't control the shape of `op`'s
// own diagnostic output and shouldn't let an oversized message propagate.
func TestOnePasswordBackendTruncatesLongErrorOutput(t *testing.T) {
	long := strings.Repeat("x", 500)
	cli := writeStubOp(t, fmt.Sprintf("printf %%s %q 1>&2\nexit 1\n", long))
	b := &OnePasswordBackend{Reference: "op://Private/chuvar-master-key/password", CLIPath: cli}

	_, err := b.Unseal(context.Background())
	require.Error(t, err)
	require.Less(t, len(err.Error()), len(long), "long op stderr was not truncated")
}

// Unseal must refuse rather than silently succeed when the calling
// environment carries a designed-for-automation credential that would let
// `op` authenticate with zero human interaction — see ambientOpAuthVar's
// doc comment and OnePasswordBackend's package doc for the adversary this
// defends against. The stub script would return a valid key if reached;
// asserting the specific error (rather than merely "some error") also
// confirms Unseal never even shells out to `op` in this case.
func TestOnePasswordBackendRefusesAmbientServiceAccountToken(t *testing.T) {
	raw, err := GenerateKey()
	require.NoError(t, err)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "ops_fake_automation_token")

	cli := writeStubOp(t, fmt.Sprintf("printf %%s %q\n", base64.StdEncoding.EncodeToString(raw)))
	b := &OnePasswordBackend{Reference: "op://Private/chuvar-master-key/password", CLIPath: cli}

	_, err = b.Unseal(context.Background())
	require.ErrorContains(t, err, "OP_SERVICE_ACCOUNT_TOKEN")
	require.ErrorContains(t, err, "no human interaction")
}

// A cached interactive `op signin` session (OP_SESSION_<account>) is the
// other non-interactive path — present in the environment, it authenticates
// `op` for the remainder of its TTL without re-prompting.
func TestOnePasswordBackendRefusesAmbientSessionToken(t *testing.T) {
	raw, err := GenerateKey()
	require.NoError(t, err)
	t.Setenv("OP_SESSION_my_account", "cached_session_token")

	cli := writeStubOp(t, fmt.Sprintf("printf %%s %q\n", base64.StdEncoding.EncodeToString(raw)))
	b := &OnePasswordBackend{Reference: "op://Private/chuvar-master-key/password", CLIPath: cli}

	_, err = b.Unseal(context.Background())
	require.ErrorContains(t, err, "OP_SESSION_my_account")
}

// A normal environment (no ambient 1Password auth vars) must be unaffected
// by the new check — this is the control for the two tests above.
func TestOnePasswordBackendSucceedsWithoutAmbientAuthVars(t *testing.T) {
	raw, err := GenerateKey()
	require.NoError(t, err)

	cli := writeStubOp(t, fmt.Sprintf("printf %%s %q\n", base64.StdEncoding.EncodeToString(raw)))
	b := &OnePasswordBackend{Reference: "op://Private/chuvar-master-key/password", CLIPath: cli}

	key, err := b.Unseal(context.Background())
	require.NoError(t, err)
	require.Equal(t, raw, key)
}

func TestAmbientOpAuthVarDetection(t *testing.T) {
	tests := []struct {
		name    string
		environ []string
		want    string
	}{
		{"empty", nil, ""},
		{"unrelated vars only", []string{"PATH=/usr/bin", "HOME=/home/x"}, ""},
		{"service account token", []string{"OP_SERVICE_ACCOUNT_TOKEN=abc"}, "OP_SERVICE_ACCOUNT_TOKEN"},
		{"session token", []string{"OP_SESSION_myaccount=abc"}, "OP_SESSION_myaccount"},
		{"prefix collision only, not a match", []string{"OP_SERVICE_ACCOUNT_TOKEN_BUT_NOT=abc"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ambientOpAuthVar(tt.environ))
		})
	}
}

// The `op` subprocess must run in a sanitised, allow-listed environment — it
// must NOT inherit the apiserver's wider environment (DATABASE_URL, bootstrap
// tokens, unrelated secrets). The stub dumps its own environment to a file so
// the test can assert exactly what crossed the process boundary.
func TestOnePasswordBackendSanitizesSubprocessEnv(t *testing.T) {
	raw, err := GenerateKey()
	require.NoError(t, err)

	// Secrets that live in the apiserver's environment and must not reach `op`.
	t.Setenv("DATABASE_URL", "postgres://user:secret@localhost:5432/chuvar")
	t.Setenv("CHUVAR_UNRELATED_SECRET", "bootstrap-token-value")

	envDump := filepath.Join(t.TempDir(), "env.dump")
	cli := writeStubOp(t, fmt.Sprintf("env > %q\nprintf %%s %q\n",
		envDump, base64.StdEncoding.EncodeToString(raw)))
	b := &OnePasswordBackend{Reference: "op://Private/chuvar-master-key/password", CLIPath: cli}

	key, err := b.Unseal(context.Background())
	require.NoError(t, err)
	require.Equal(t, raw, key)

	dump, err := os.ReadFile(envDump)
	require.NoError(t, err)
	got := string(dump)
	require.NotContains(t, got, "DATABASE_URL", "op subprocess inherited DATABASE_URL from the apiserver env")
	require.NotContains(t, got, "CHUVAR_UNRELATED_SECRET", "op subprocess inherited an unrelated apiserver secret")
	require.Contains(t, got, "PATH=", "op subprocess is missing PATH from the allow-list")
}

func TestOnePasswordBackendRejectsEmptyReference(t *testing.T) {
	b := &OnePasswordBackend{CLIPath: writeStubOp(t, "printf 'unused'\n")}
	_, err := b.Unseal(context.Background())
	require.ErrorContains(t, err, "Reference is empty")
}

func TestOnePasswordBackendRejectsNonOpReference(t *testing.T) {
	b := &OnePasswordBackend{
		Reference: "not-a-secret-reference",
		CLIPath:   writeStubOp(t, "printf 'unused'\n"),
	}
	_, err := b.Unseal(context.Background())
	require.ErrorContains(t, err, "not an op:// secret reference")
}

// TestOnePasswordBackendMissingCLI exercises the real, un-stubbed lookup
// path: no CLIPath override, and PATH deliberately cleared so `op` cannot be
// found, regardless of whether the host actually has it installed. This is
// the "op is absent" case AGENTS.md asks for — and it must fail loudly, not
// hang or silently succeed.
func TestOnePasswordBackendMissingCLI(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // an empty directory: guaranteed no `op`
	b := &OnePasswordBackend{Reference: "op://Private/chuvar-master-key/password"}
	_, err := b.Unseal(context.Background())
	require.Error(t, err)
}

// TestOnePasswordBackendAgainstRealCLI is the actual integration path: it
// runs the real `op` binary end to end rather than the stub above. It needs
// both a signed-in `op` session (requireOpCLI) and a provisioned item
// (CHUVAR_TEST_OP_REFERENCE, set to that item's op:// reference per this
// backend's doc comment) — neither of which this development host has
// (`op` is installed but not signed in), so it skips cleanly here. Nothing
// about the skip should be read as this backend being unverified: the
// stub-based table above verifies every branch of OnePasswordBackend's own
// logic; this test's job is solely to confirm those assumptions about `op`
// read --no-newline's real output shape hold, whenever it can actually run.
func TestOnePasswordBackendAgainstRealCLI(t *testing.T) {
	requireOpCLI(t)
	ref := os.Getenv("CHUVAR_TEST_OP_REFERENCE")
	if ref == "" {
		t.Skip("custody: CHUVAR_TEST_OP_REFERENCE not set; skipping real 1Password integration " +
			"test (see OnePasswordBackend's doc comment for setup)")
	}
	b := &OnePasswordBackend{Reference: ref}
	key, err := b.Unseal(context.Background())
	require.NoError(t, err)
	require.Len(t, key, KeyLen)
}
