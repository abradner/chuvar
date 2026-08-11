package custody

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// captureSlog redirects the default slog logger to a buffer for the
// duration of the test, so a test can assert on what was logged (e.g. the
// unsealed-backend warning) without depending on stderr capture.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestBackendFromEnv_NoConfigRefusesToBoot(t *testing.T) {
	// Deliberately not calling t.Setenv for the _BACKEND var — this is the
	// "operator hasn't configured anything" case (CLAUDE.md principle 5:
	// missing config means no boot, never a silent default).
	_, err := BackendFromEnv("TESTPFX_NOCFG", "TESTPFX_NOCFG_ALLOW_UNSEALED", "consequence", "")
	require.Error(t, err)
	require.ErrorContains(t, err, "TESTPFX_NOCFG_BACKEND")
	require.ErrorContains(t, err, "is not set")
}

func TestBackendFromEnv_UnknownBackendRefused(t *testing.T) {
	t.Setenv("TESTPFX_BAD_BACKEND", "carrier-pigeon")
	_, err := BackendFromEnv("TESTPFX_BAD", "TESTPFX_BAD_ALLOW_UNSEALED", "consequence", "")
	require.Error(t, err)
	require.ErrorContains(t, err, "unknown backend")
}

func TestBackendFromEnv_UnsealedFileBackendRefusedWithoutEscapeHatch(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")
	t.Setenv("TESTPFX_FILE_BACKEND", "file")
	t.Setenv("TESTPFX_FILE_FILE", keyPath)
	t.Setenv("TESTPFX_FILE_CREATE", "1")
	// Deliberately not setting the allow-unsealed var.

	_, err := BackendFromEnv("TESTPFX_FILE", "TESTPFX_FILE_ALLOW_UNSEALED", "an attacker could forge signatures", "")
	require.Error(t, err)
	require.ErrorContains(t, err, "NOT sealed")
	require.ErrorContains(t, err, "an attacker could forge signatures")
	require.ErrorContains(t, err, "TESTPFX_FILE_ALLOW_UNSEALED")

	// And the refusal must be at selection time, before ever touching disk —
	// no key file should have been minted.
	_, statErr := os.Stat(keyPath)
	require.Error(t, statErr, "BackendFromEnv should refuse before Unseal is ever called")
}

func TestBackendFromEnv_UnsealedFileBackendBootsAndWarnsWithEscapeHatch(t *testing.T) {
	buf := captureSlog(t)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")
	t.Setenv("TESTPFX_FILE2_BACKEND", "file")
	t.Setenv("TESTPFX_FILE2_FILE", keyPath)
	t.Setenv("TESTPFX_FILE2_CREATE", "1")
	t.Setenv("TESTPFX_FILE2_ALLOW_UNSEALED", "1")

	backend, err := BackendFromEnv("TESTPFX_FILE2", "TESTPFX_FILE2_ALLOW_UNSEALED",
		"an attacker could forge signatures", "")
	require.NoError(t, err)
	require.False(t, backend.Sealed())
	require.Equal(t, "file", backend.Name())

	raw, err := backend.Unseal(context.Background())
	require.NoError(t, err)
	require.Len(t, raw, KeyLen)

	logged := buf.String()
	require.Contains(t, logged, "UNSEALED")
	require.Contains(t, logged, "an attacker could forge signatures")
	require.Contains(t, logged, "TESTPFX_FILE2_ALLOW_UNSEALED")
}

func TestBackendFromEnv_DefaultFileUsedWhenFileVarUnset(t *testing.T) {
	dir := t.TempDir()
	defaultPath := filepath.Join(dir, "default-signing.key")
	t.Setenv("TESTPFX_DEF_BACKEND", "file")
	t.Setenv("TESTPFX_DEF_CREATE", "1")
	t.Setenv("TESTPFX_DEF_ALLOW_UNSEALED", "1")
	// TESTPFX_DEF_FILE deliberately unset — defaultFile should be used
	// instead of FileBackend's own DefaultKeyPath (which would point at
	// master.key, the wrong file for a caller with its own default).

	backend, err := BackendFromEnv("TESTPFX_DEF", "TESTPFX_DEF_ALLOW_UNSEALED", "consequence", defaultPath)
	require.NoError(t, err)
	fb, ok := backend.(*FileBackend)
	require.True(t, ok)
	require.Equal(t, defaultPath, fb.Path)
}

func TestBackendFromEnv_AgeRequiresFileVar(t *testing.T) {
	t.Setenv("TESTPFX_AGENOFILE_BACKEND", "age")
	_, err := BackendFromEnv("TESTPFX_AGENOFILE", "TESTPFX_AGENOFILE_ALLOW_UNSEALED", "consequence", "")
	require.Error(t, err)
	require.ErrorContains(t, err, "requires TESTPFX_AGENOFILE_FILE")
}

func TestBackendFromEnv_AgeWithPassphraseFileIsUnsealedButUsable(t *testing.T) {
	dir := t.TempDir()
	agePath := filepath.Join(dir, "signing.age")
	passphrasePath := filepath.Join(dir, "passphrase")
	require.NoError(t, os.WriteFile(passphrasePath, []byte("a-test-passphrase\n"), 0o600))

	t.Setenv("TESTPFX_AGEPP_BACKEND", "age")
	t.Setenv("TESTPFX_AGEPP_FILE", agePath)
	t.Setenv("TESTPFX_AGEPP_CREATE", "1")
	t.Setenv("TESTPFX_AGEPP_PASSPHRASE_FILE", passphrasePath)
	t.Setenv("TESTPFX_AGEPP_ALLOW_UNSEALED", "1")

	backend, err := BackendFromEnv("TESTPFX_AGEPP", "TESTPFX_AGEPP_ALLOW_UNSEALED", "consequence", "")
	require.NoError(t, err)
	require.False(t, backend.Sealed(), "AgeBackend configured via PassphrasePath must report Sealed() == false")

	raw, err := backend.Unseal(context.Background())
	require.NoError(t, err)
	require.Len(t, raw, KeyLen)
}

func TestBackendFromEnv_AgeWithPassphraseFileRefusedWithoutEscapeHatch(t *testing.T) {
	dir := t.TempDir()
	agePath := filepath.Join(dir, "signing.age")
	passphrasePath := filepath.Join(dir, "passphrase")
	require.NoError(t, os.WriteFile(passphrasePath, []byte("a-test-passphrase\n"), 0o600))

	t.Setenv("TESTPFX_AGEPP2_BACKEND", "age")
	t.Setenv("TESTPFX_AGEPP2_FILE", agePath)
	t.Setenv("TESTPFX_AGEPP2_PASSPHRASE_FILE", passphrasePath)
	// No escape hatch set.

	_, err := BackendFromEnv("TESTPFX_AGEPP2", "TESTPFX_AGEPP2_ALLOW_UNSEALED", "consequence", "")
	require.Error(t, err)
	require.ErrorContains(t, err, "NOT sealed")
}

func TestBackendFromEnv_OnePasswordRequiresReference(t *testing.T) {
	t.Setenv("TESTPFX_1PNOREF_BACKEND", "1password")
	_, err := BackendFromEnv("TESTPFX_1PNOREF", "TESTPFX_1PNOREF_ALLOW_UNSEALED", "consequence", "")
	require.Error(t, err)
	require.ErrorContains(t, err, "requires TESTPFX_1PNOREF_1PASSWORD_REFERENCE")
}

// TestBackendFromEnv_SealedOnePasswordBackendBootsWithoutEscapeHatch is the
// "a sealed backend boots" case: OnePasswordBackend.Sealed() is always
// true, so selection must succeed with no escape-hatch var set at all, and
// no unsealed-backend warning logged. Exercises a full Unseal too (via a
// stub `op` on PATH — see writeStubOp in onepassword_test.go, same
// package), not just selection, to prove the constructed backend actually
// works end to end.
func TestBackendFromEnv_SealedOnePasswordBackendBootsWithoutEscapeHatch(t *testing.T) {
	buf := captureSlog(t)

	raw, err := GenerateKey()
	require.NoError(t, err)
	validB64 := base64.StdEncoding.EncodeToString(raw)

	stubDir := t.TempDir()
	stubPath := filepath.Join(stubDir, "op")
	require.NoError(t, os.WriteFile(stubPath, []byte(fmt.Sprintf("#!/bin/sh\nprintf %%s %q\n", validB64)), 0o700))
	t.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	t.Setenv("TESTPFX_1PSEALED_BACKEND", "1password")
	t.Setenv("TESTPFX_1PSEALED_1PASSWORD_REFERENCE", "op://Private/chuvar-broker-signing-key/password")
	// No TESTPFX_1PSEALED_ALLOW_UNSEALED set — sealed backends must not need it.

	backend, err := BackendFromEnv("TESTPFX_1PSEALED", "TESTPFX_1PSEALED_ALLOW_UNSEALED", "consequence", "")
	require.NoError(t, err)
	require.True(t, backend.Sealed())
	require.Equal(t, "1password", backend.Name())

	got, err := backend.Unseal(context.Background())
	require.NoError(t, err)
	require.Equal(t, raw, got)

	require.False(t, strings.Contains(buf.String(), "UNSEALED"),
		"a sealed backend must not trigger the unsealed-backend warning")
}
