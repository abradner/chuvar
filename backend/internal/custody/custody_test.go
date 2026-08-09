package custody

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestKey(t *testing.T) *Key {
	t.Helper()
	raw, err := GenerateKey()
	require.NoError(t, err)
	k, err := NewKey(raw)
	require.NoError(t, err)
	return k
}

func TestNewKeyRejectsWrongLength(t *testing.T) {
	tests := []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"short", KeyLen - 1},
		{"long", KeyLen + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewKey(make([]byte, tt.n))
			require.ErrorIs(t, err, ErrKeyLen)
		})
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := newTestKey(t)
	tests := []struct {
		name string
		pt   []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("JBSWY3DPEHPK3PXP")},
		{"binary", []byte{0x00, 0xff, 0x00, 0xff}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blob, err := k.Seal(tt.pt)
			require.NoError(t, err)
			require.NotEqual(t, tt.pt, blob, "Seal returned the plaintext unchanged")

			got, err := k.Open(blob)
			require.NoError(t, err)
			// bytes.Equal rather than require.Equal: GCM returns nil, not an
			// empty slice, for empty plaintext, and require.Equal distinguishes
			// the two. This package promises the contents round-trip, not the
			// nil-ness of the header.
			require.True(t, bytes.Equal(tt.pt, got), "Open(Seal(%q)) = %q", tt.pt, got)
		})
	}
}

// Sealing the same plaintext twice must produce different blobs. If this fails,
// the nonce is being reused, which collapses GCM's confidentiality — the whole
// reason Seal draws a fresh nonce per call.
func TestSealIsNonDeterministic(t *testing.T) {
	k := newTestKey(t)
	pt := []byte("JBSWY3DPEHPK3PXP")

	first, err := k.Seal(pt)
	require.NoError(t, err)
	second, err := k.Seal(pt)
	require.NoError(t, err)

	require.NotEqual(t, first, second, "sealing the same plaintext twice reused the nonce")
}

func TestOpenRejectsWrongKey(t *testing.T) {
	blob, err := newTestKey(t).Seal([]byte("secret"))
	require.NoError(t, err)

	_, err = newTestKey(t).Open(blob)
	require.Error(t, err, "a blob sealed under one key opened under another")
}

func TestOpenRejectsTamperedBlob(t *testing.T) {
	k := newTestKey(t)
	blob, err := k.Seal([]byte("secret"))
	require.NoError(t, err)

	t.Run("flipped ciphertext bit", func(t *testing.T) {
		tampered := bytes.Clone(blob)
		tampered[len(tampered)-1] ^= 0x01
		_, err := k.Open(tampered)
		require.Error(t, err)
	})

	t.Run("flipped nonce bit", func(t *testing.T) {
		tampered := bytes.Clone(blob)
		tampered[0] ^= 0x01
		_, err := k.Open(tampered)
		require.Error(t, err)
	})

	t.Run("truncated below nonce length", func(t *testing.T) {
		_, err := k.Open(blob[:4])
		require.ErrorContains(t, err, "shorter than its nonce")
	})

	t.Run("empty", func(t *testing.T) {
		_, err := k.Open(nil)
		require.ErrorContains(t, err, "shorter than its nonce")
	})
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	master := newTestKey(t)
	dekRaw, err := GenerateKey()
	require.NoError(t, err)

	wrapped, err := master.Wrap(dekRaw)
	require.NoError(t, err)
	require.False(t, bytes.Contains(wrapped, dekRaw), "wrapped DEK contains the raw key bytes")

	dek, err := master.Unwrap(wrapped)
	require.NoError(t, err)

	// The unwrapped DEK must be the same key, not merely a valid one: seal with
	// the original and open with the recovered copy.
	original, err := NewKey(dekRaw)
	require.NoError(t, err)
	blob, err := original.Seal([]byte("payload"))
	require.NoError(t, err)

	got, err := dek.Open(blob)
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), got)
}

func TestWrapRejectsWrongLength(t *testing.T) {
	_, err := newTestKey(t).Wrap(make([]byte, KeyLen-1))
	require.ErrorIs(t, err, ErrKeyLen)
}

func TestUnwrapRejectsWrongMasterKey(t *testing.T) {
	dekRaw, err := GenerateKey()
	require.NoError(t, err)
	wrapped, err := newTestKey(t).Wrap(dekRaw)
	require.NoError(t, err)

	_, err = newTestKey(t).Unwrap(wrapped)
	require.Error(t, err)
}

func TestUnwrapRejectsCorruptWrappedKey(t *testing.T) {
	master := newTestKey(t)
	dekRaw, err := GenerateKey()
	require.NoError(t, err)
	wrapped, err := master.Wrap(dekRaw)
	require.NoError(t, err)

	corrupt := bytes.Clone(wrapped)
	corrupt[len(corrupt)-1] ^= 0xff
	_, err = master.Unwrap(corrupt)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrKeyLen, "corruption reported as a length problem; it is an AEAD failure")
}

// Rotating the master key must rewrap the DEK without re-encrypting the data —
// the property the envelope exists for. Data sealed before the rotation must
// still open afterwards.
func TestMasterKeyRotationPreservesSealedData(t *testing.T) {
	oldMaster := newTestKey(t)
	dekRaw, err := GenerateKey()
	require.NoError(t, err)
	dek, err := NewKey(dekRaw)
	require.NoError(t, err)

	sealed, err := dek.Seal([]byte("enrolled secret"))
	require.NoError(t, err)
	wrapped, err := oldMaster.Wrap(dekRaw)
	require.NoError(t, err)

	// Rotate: recover the DEK under the old master, rewrap under the new one.
	// The sealed payload is never touched.
	recovered, err := oldMaster.Unwrap(wrapped)
	require.NoError(t, err)
	_, err = recovered.Open(sealed)
	require.NoError(t, err, "recovered DEK could not open its own data")

	newMaster := newTestKey(t)
	rewrapped, err := newMaster.Wrap(dekRaw)
	require.NoError(t, err)
	_, err = oldMaster.Unwrap(rewrapped)
	require.Error(t, err, "the retired master key still unwraps the rewrapped DEK")

	dekAfter, err := newMaster.Unwrap(rewrapped)
	require.NoError(t, err)
	got, err := dekAfter.Open(sealed)
	require.NoError(t, err, "data sealed before rotation did not survive it")
	require.Equal(t, []byte("enrolled secret"), got)
}

func TestFileBackendCreatesKeyWhenAllowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "master.key")
	b := &FileBackend{Path: path, AllowCreate: true}

	key, err := b.Unseal(context.Background())
	require.NoError(t, err)
	require.Len(t, key, KeyLen)

	info, err := os.Stat(path)
	require.NoError(t, err)
	// The contract is "not readable or writable by group or other", not exactly
	// 0600 — the open mode is masked by umask, so an unusual umask can legally
	// yield 0400. Asserting equality would fail on a file the code accepts.
	require.Zero(t, info.Mode().Perm()&0o077, "minted key file is accessible beyond its owner (mode %04o)", info.Mode().Perm())

	// A second Unseal must return the same key, or every restart would orphan
	// everything sealed before it.
	again, err := b.Unseal(context.Background())
	require.NoError(t, err)
	require.Equal(t, key, again)
}

func TestFileBackendRefusesToCreateByDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")

	_, err := (&FileBackend{Path: path}).Unseal(context.Background())
	require.ErrorContains(t, err, "no key file")
	require.NoFileExists(t, path, "a refusal left a key file behind")
}

func TestFileBackendRejectsLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	raw, err := GenerateKey()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(raw)), 0o600))

	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		t.Run(mode.String(), func(t *testing.T) {
			require.NoError(t, os.Chmod(path, mode))
			_, err := (&FileBackend{Path: path}).Unseal(context.Background())
			require.ErrorContains(t, err, "chmod 600")
		})
	}
}

func TestFileBackendRejectsMalformedKeyFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{"not base64", "!!!! not base64 !!!!", "decode key file"},
		{"too short", base64.StdEncoding.EncodeToString(make([]byte, KeyLen-1)), "want 32"},
		{"too long", base64.StdEncoding.EncodeToString(make([]byte, KeyLen+1)), "want 32"},
		{"empty", "", "want 32"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "master.key")
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))

			_, err := (&FileBackend{Path: path}).Unseal(context.Background())
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// Trailing whitespace is what any editor or `echo` leaves behind, and a key
// file is exactly the sort of thing someone edits by hand during recovery.
func TestFileBackendToleratesTrailingWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	raw, err := GenerateKey()
	require.NoError(t, err)
	content := base64.StdEncoding.EncodeToString(raw) + "\n\n  "
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	key, err := (&FileBackend{Path: path}).Unseal(context.Background())
	require.NoError(t, err)
	require.Equal(t, raw, key)
}

func TestDefaultKeyPathHonoursXDGStateHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/tmp/example-state")
	path, err := DefaultKeyPath()
	require.NoError(t, err)
	require.Equal(t, "/tmp/example-state/chuvar/master.key", path)
}

func TestDefaultKeyPathFallsBackToXDGConvention(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	path, err := DefaultKeyPath()
	require.NoError(t, err)
	require.Contains(t, path, filepath.Join(".local", "state", "chuvar"))
}

func TestEphemeralIsStableWithinAnInstance(t *testing.T) {
	e := &Ephemeral{}
	first, err := e.Unseal(context.Background())
	require.NoError(t, err)
	second, err := e.Unseal(context.Background())
	require.NoError(t, err)
	require.Equal(t, first, second)

	otherKey, err := (&Ephemeral{}).Unseal(context.Background())
	require.NoError(t, err)
	require.NotEqual(t, first, otherKey, "separate Ephemeral instances share a key")
}

// Both shipped backends are honest about being unsealed. When a backend that
// genuinely seals at rest lands (E7), it reports true and this test grows a
// case rather than being edited to fit.
func TestShippedBackendsReportUnsealed(t *testing.T) {
	for _, b := range []Backend{&FileBackend{}, &Ephemeral{}} {
		t.Run(b.Name(), func(t *testing.T) {
			require.False(t, b.Sealed(), "backend claims to seal at rest; none does yet (see package doc)")
		})
	}
}

// OnePasswordBackend and AgeBackend (configured with an in-memory,
// interactively-sourced Passphrase — see TestAgeBackendSealedReflectsPassphraseDelivery
// for the PassphrasePath case, which must NOT report sealed) are the case
// the comment above anticipated growing: both genuinely seal the master key
// at rest, so both must report Sealed() == true.
func TestSealedBackendsReportSealed(t *testing.T) {
	for _, b := range []Backend{
		&OnePasswordBackend{},
		&AgeBackend{Passphrase: "sourced from a human-present prompt at boot"},
	} {
		t.Run(b.Name(), func(t *testing.T) {
			require.True(t, b.Sealed(), "backend seals the key at rest but reports otherwise")
		})
	}
}
