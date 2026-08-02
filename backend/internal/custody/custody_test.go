package custody

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestKey(t *testing.T) *Key {
	t.Helper()
	raw, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	k, err := NewKey(raw)
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}
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
			if _, err := NewKey(make([]byte, tt.n)); !errors.Is(err, ErrKeyLen) {
				t.Fatalf("NewKey(%d bytes) error = %v, want ErrKeyLen", tt.n, err)
			}
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
			if err != nil {
				t.Fatalf("Seal() error = %v", err)
			}
			if bytes.Equal(blob, tt.pt) {
				t.Fatal("Seal() returned the plaintext unchanged")
			}
			got, err := k.Open(blob)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			// bytes.Equal, not reflect.DeepEqual: GCM returns nil rather than an
			// empty slice for empty plaintext, and that distinction is not one
			// this package promises to preserve.
			if !bytes.Equal(got, tt.pt) {
				t.Fatalf("Open(Seal(%q)) = %q, want round trip", tt.pt, got)
			}
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
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	second, err := k.Seal(pt)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("sealing the same plaintext twice produced identical blobs; nonce is being reused")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	blob, err := newTestKey(t).Seal([]byte("secret"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if _, err := newTestKey(t).Open(blob); err == nil {
		t.Fatal("Open() with an unrelated key succeeded, want error")
	}
}

func TestOpenRejectsTamperedBlob(t *testing.T) {
	k := newTestKey(t)
	blob, err := k.Seal([]byte("secret"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	t.Run("flipped ciphertext bit", func(t *testing.T) {
		tampered := bytes.Clone(blob)
		tampered[len(tampered)-1] ^= 0x01
		if _, err := k.Open(tampered); err == nil {
			t.Fatal("Open() accepted a tampered ciphertext")
		}
	})

	t.Run("flipped nonce bit", func(t *testing.T) {
		tampered := bytes.Clone(blob)
		tampered[0] ^= 0x01
		if _, err := k.Open(tampered); err == nil {
			t.Fatal("Open() accepted a tampered nonce")
		}
	})

	t.Run("truncated below nonce length", func(t *testing.T) {
		_, err := k.Open(blob[:4])
		if err == nil || !strings.Contains(err.Error(), "shorter than its nonce") {
			t.Fatalf("Open(truncated) error = %v, want a nonce-length complaint", err)
		}
	})

	t.Run("empty", func(t *testing.T) {
		_, err := k.Open(nil)
		if err == nil || !strings.Contains(err.Error(), "shorter than its nonce") {
			t.Fatalf("Open(nil) error = %v, want a nonce-length complaint", err)
		}
	})
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	master := newTestKey(t)
	dekRaw, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	wrapped, err := master.Wrap(dekRaw)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}
	if bytes.Contains(wrapped, dekRaw) {
		t.Fatal("wrapped DEK contains the raw key bytes")
	}

	dek, err := master.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap() error = %v", err)
	}

	// The unwrapped DEK must be the same key, not merely a valid one: seal with
	// the original and open with the recovered copy.
	original, err := NewKey(dekRaw)
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}
	blob, err := original.Seal([]byte("payload"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	got, err := dek.Open(blob)
	if err != nil {
		t.Fatalf("Open() with unwrapped DEK error = %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("Open() = %q, want %q", got, "payload")
	}
}

func TestWrapRejectsWrongLength(t *testing.T) {
	if _, err := newTestKey(t).Wrap(make([]byte, KeyLen-1)); !errors.Is(err, ErrKeyLen) {
		t.Fatalf("Wrap(short) error = %v, want ErrKeyLen", err)
	}
}

func TestUnwrapRejectsWrongMasterKey(t *testing.T) {
	dekRaw, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	wrapped, err := newTestKey(t).Wrap(dekRaw)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}
	if _, err := newTestKey(t).Unwrap(wrapped); err == nil {
		t.Fatal("Unwrap() with an unrelated master key succeeded, want error")
	}
}

func TestUnwrapRejectsCorruptWrappedKey(t *testing.T) {
	master := newTestKey(t)
	dekRaw, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	wrapped, err := master.Wrap(dekRaw)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	corrupt := bytes.Clone(wrapped)
	corrupt[len(corrupt)-1] ^= 0xff
	_, err = master.Unwrap(corrupt)
	if err == nil {
		t.Fatal("Unwrap() accepted a corrupt blob")
	}
	if errors.Is(err, ErrKeyLen) {
		t.Fatal("corruption reported as a length problem; it is an AEAD failure")
	}
}

// Rotating the master key must rewrap the DEK without re-encrypting the data —
// the property the envelope exists for. Data sealed before the rotation must
// still open afterwards.
func TestMasterKeyRotationPreservesSealedData(t *testing.T) {
	oldMaster := newTestKey(t)
	dekRaw, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	dek, err := NewKey(dekRaw)
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}

	sealed, err := dek.Seal([]byte("enrolled secret"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	wrapped, err := oldMaster.Wrap(dekRaw)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	// Rotate: recover the DEK under the old master, rewrap under the new one.
	// The sealed payload is never touched.
	recovered, err := oldMaster.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap() error = %v", err)
	}
	if _, err := recovered.Open(sealed); err != nil {
		t.Fatalf("recovered DEK could not open its own data: %v", err)
	}

	newMaster := newTestKey(t)
	rewrapped, err := newMaster.Wrap(dekRaw)
	if err != nil {
		t.Fatalf("Wrap() under new master error = %v", err)
	}
	if _, err := oldMaster.Unwrap(rewrapped); err == nil {
		t.Fatal("the retired master key still unwraps the rewrapped DEK")
	}

	dekAfter, err := newMaster.Unwrap(rewrapped)
	if err != nil {
		t.Fatalf("Unwrap() under new master error = %v", err)
	}
	got, err := dekAfter.Open(sealed)
	if err != nil {
		t.Fatalf("data sealed before rotation did not survive it: %v", err)
	}
	if string(got) != "enrolled secret" {
		t.Fatalf("Open() = %q, want %q", got, "enrolled secret")
	}
}

func TestFileBackendCreatesKeyWhenAllowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "master.key")
	b := &FileBackend{Path: path, AllowCreate: true}

	key, err := b.Unseal(context.Background())
	if err != nil {
		t.Fatalf("Unseal() error = %v", err)
	}
	if len(key) != KeyLen {
		t.Fatalf("Unseal() returned %d bytes, want %d", len(key), KeyLen)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("minted key file mode = %04o, want 0600", perm)
	}

	// A second Unseal must return the same key, or every restart would orphan
	// everything sealed before it.
	again, err := b.Unseal(context.Background())
	if err != nil {
		t.Fatalf("second Unseal() error = %v", err)
	}
	if !bytes.Equal(key, again) {
		t.Fatal("Unseal() returned a different key on the second call")
	}
}

func TestFileBackendRefusesToCreateByDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")

	_, err := (&FileBackend{Path: path}).Unseal(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no key file") {
		t.Fatalf("Unseal() error = %v, want a missing-key-file refusal", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("a refusal left a key file behind")
	}
}

func TestFileBackendRejectsLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	raw, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(raw)), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		t.Run(mode.String(), func(t *testing.T) {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("Chmod() error = %v", err)
			}
			_, err := (&FileBackend{Path: path}).Unseal(context.Background())
			if err == nil || !strings.Contains(err.Error(), "chmod 600") {
				t.Fatalf("Unseal() with mode %04o error = %v, want a permissions refusal", mode, err)
			}
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
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			_, err := (&FileBackend{Path: path}).Unseal(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Unseal() error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

// Trailing whitespace is what any editor or `echo` leaves behind, and a key
// file is exactly the sort of thing someone edits by hand during recovery.
func TestFileBackendToleratesTrailingWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	raw, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	content := base64.StdEncoding.EncodeToString(raw) + "\n\n  "
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	key, err := (&FileBackend{Path: path}).Unseal(context.Background())
	if err != nil {
		t.Fatalf("Unseal() error = %v", err)
	}
	if !bytes.Equal(key, raw) {
		t.Fatal("Unseal() did not recover the written key")
	}
}

func TestDefaultKeyPathHonoursXDGStateHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/tmp/example-state")
	path, err := DefaultKeyPath()
	if err != nil {
		t.Fatalf("DefaultKeyPath() error = %v", err)
	}
	if want := "/tmp/example-state/chuvar/master.key"; path != want {
		t.Fatalf("DefaultKeyPath() = %q, want %q", path, want)
	}
}

func TestDefaultKeyPathFallsBackToXDGConvention(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	path, err := DefaultKeyPath()
	if err != nil {
		t.Fatalf("DefaultKeyPath() error = %v", err)
	}
	if want := filepath.Join(".local", "state", "chuvar"); !strings.Contains(path, want) {
		t.Fatalf("DefaultKeyPath() = %q, want it under %q", path, want)
	}
}

func TestEphemeralIsStableWithinAnInstance(t *testing.T) {
	e := &Ephemeral{}
	first, err := e.Unseal(context.Background())
	if err != nil {
		t.Fatalf("Unseal() error = %v", err)
	}
	second, err := e.Unseal(context.Background())
	if err != nil {
		t.Fatalf("second Unseal() error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("Ephemeral returned a different key on the second call")
	}

	otherKey, err := (&Ephemeral{}).Unseal(context.Background())
	if err != nil {
		t.Fatalf("Unseal() on second instance error = %v", err)
	}
	if bytes.Equal(first, otherKey) {
		t.Fatal("separate Ephemeral instances share a key")
	}
}

// Both shipped backends are honest about being unsealed. When a backend that
// genuinely seals at rest lands (E7), it reports true and this test grows a
// case rather than being edited to fit.
func TestShippedBackendsReportUnsealed(t *testing.T) {
	for _, b := range []Backend{&FileBackend{}, &Ephemeral{}} {
		t.Run(b.Name(), func(t *testing.T) {
			if b.Sealed() {
				t.Fatal("backend claims to seal at rest; no shipped backend does yet (see package doc)")
			}
		})
	}
}
