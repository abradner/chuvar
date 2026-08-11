package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/abradner/chuvar/backend/internal/custody"
)

// clearBrokerSigningKeyEnv unsets every var loadSigningKey or
// custody.BackendFromEnv might read, so each test starts from "operator
// configured nothing" regardless of what's in the real environment this
// test binary happens to run in.
func clearBrokerSigningKeyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"CHUVAR_BROKER_SIGNING_KEY_BACKEND",
		"CHUVAR_BROKER_SIGNING_KEY_FILE",
		"CHUVAR_BROKER_SIGNING_KEY_CREATE",
		"CHUVAR_BROKER_SIGNING_KEY_PASSPHRASE_FILE",
		"CHUVAR_BROKER_SIGNING_KEY_1PASSWORD_REFERENCE",
		"CHUVAR_BROKER_ALLOW_UNSEALED_KEY",
		"XDG_STATE_HOME",
	} {
		v, ok := os.LookupEnv(k)
		t.Cleanup(func() {
			if ok {
				os.Setenv(k, v) //nolint:errcheck
			} else {
				os.Unsetenv(k) //nolint:errcheck
			}
		})
		os.Unsetenv(k) //nolint:errcheck
	}
}

// These four cases are round-2 review's explicit test list for the
// signing-key custody fix (TASK 1): no config refuses to boot; an unsealed
// backend without the escape hatch refuses; an unsealed backend WITH the
// escape hatch boots and warns; a sealed backend boots. internal/custody's
// select_test.go already covers this matrix at the BackendFromEnv level in
// more depth (including the warning text and the age-backend variants);
// these exercise the same gate through brokerd's actual entrypoint,
// loadSigningKey, including the real keyring.Load step the selector-level
// tests don't reach.

func TestLoadSigningKey_NoConfigRefusesToBoot(t *testing.T) {
	clearBrokerSigningKeyEnv(t)
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	_, err := loadSigningKey(context.Background())
	require.Error(t, err)
	require.ErrorContains(t, err, "CHUVAR_BROKER_SIGNING_KEY_BACKEND")
	require.ErrorContains(t, err, "is not set")
}

func TestLoadSigningKey_UnsealedFileBackendRefusedWithoutEscapeHatch(t *testing.T) {
	clearBrokerSigningKeyEnv(t)
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	t.Setenv("CHUVAR_BROKER_SIGNING_KEY_BACKEND", "file")
	t.Setenv("CHUVAR_BROKER_SIGNING_KEY_FILE", filepath.Join(dir, "signing.key"))
	t.Setenv("CHUVAR_BROKER_SIGNING_KEY_CREATE", "1")

	_, err := loadSigningKey(context.Background())
	require.Error(t, err)
	require.ErrorContains(t, err, "NOT sealed")
	require.ErrorContains(t, err, "forge arbitrary git commit signatures")
	require.ErrorContains(t, err, "CHUVAR_BROKER_ALLOW_UNSEALED_KEY")
}

func TestLoadSigningKey_UnsealedFileBackendBootsAndWarnsWithEscapeHatch(t *testing.T) {
	clearBrokerSigningKeyEnv(t)
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	t.Setenv("CHUVAR_BROKER_SIGNING_KEY_BACKEND", "file")
	t.Setenv("CHUVAR_BROKER_SIGNING_KEY_FILE", filepath.Join(dir, "signing.key"))
	t.Setenv("CHUVAR_BROKER_SIGNING_KEY_CREATE", "1")
	t.Setenv("CHUVAR_BROKER_ALLOW_UNSEALED_KEY", "1")

	key, err := loadSigningKey(context.Background())
	require.NoError(t, err)
	require.NotNil(t, key)
	key.Destroy()
}

// TestLoadSigningKey_SealedOnePasswordBackendBoots exercises the "a sealed
// backend boots" case through the real entrypoint, using a stub `op` on
// PATH (same technique as internal/custody's onepassword_test.go and
// select_test.go) rather than a live 1Password session.
func TestLoadSigningKey_SealedOnePasswordBackendBoots(t *testing.T) {
	clearBrokerSigningKeyEnv(t)
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)

	raw, err := custody.GenerateKey()
	require.NoError(t, err)
	validB64 := base64.StdEncoding.EncodeToString(raw)

	stubDir := t.TempDir()
	stubPath := filepath.Join(stubDir, "op")
	require.NoError(t, os.WriteFile(stubPath, []byte("#!/bin/sh\nprintf %s '"+validB64+"'\n"), 0o700))
	t.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	t.Setenv("CHUVAR_BROKER_SIGNING_KEY_BACKEND", "1password")
	t.Setenv("CHUVAR_BROKER_SIGNING_KEY_1PASSWORD_REFERENCE", "op://Private/chuvar-broker-signing-key/password")
	// Deliberately no CHUVAR_BROKER_ALLOW_UNSEALED_KEY — a sealed backend
	// must not need it.

	key, err := loadSigningKey(context.Background())
	require.NoError(t, err)
	require.NotNil(t, key)
	key.Destroy()
}
