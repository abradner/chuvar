package custody

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
)

// sealAgeFile writes an age-encrypted file at path holding plaintext under
// passphrase, mirroring what AgeBackend.create does — used by tests that
// need to construct a fixture without exercising create() itself, so a
// create() regression doesn't mask an Unseal() regression or vice versa.
func sealAgeFile(t *testing.T, path, passphrase string, plaintext []byte, mode os.FileMode) {
	t.Helper()
	recipient, err := age.NewScryptRecipient(passphrase)
	require.NoError(t, err)
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	require.NoError(t, err)
	_, err = w.Write(plaintext)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, os.WriteFile(path, buf.Bytes(), mode))
}

func TestAgeBackendCreatesKeyWhenAllowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "master.key.age")
	b := &AgeBackend{Path: path, Passphrase: "correct horse battery staple", AllowCreate: true}

	key, err := b.Unseal(context.Background())
	require.NoError(t, err)
	require.Len(t, key, KeyLen)

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Zero(t, info.Mode().Perm()&0o077, "minted age key file is accessible beyond its owner (mode %04o)", info.Mode().Perm())

	// A second Unseal must return the same key, or every restart would
	// orphan everything sealed before it.
	again, err := b.Unseal(context.Background())
	require.NoError(t, err)
	require.Equal(t, key, again)
}

func TestAgeBackendRefusesToCreateByDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key.age")
	b := &AgeBackend{Path: path, Passphrase: "correct horse battery staple"}

	_, err := b.Unseal(context.Background())
	require.ErrorContains(t, err, "no age key file")
	require.NoFileExists(t, path, "a refusal left a key file behind")
}

func TestAgeBackendRoundTripsWithPassphraseFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key.age")
	passPath := filepath.Join(dir, "passphrase")
	require.NoError(t, os.WriteFile(passPath, []byte("correct horse battery staple\n"), 0o600))

	raw, err := GenerateKey()
	require.NoError(t, err)
	sealAgeFile(t, keyPath, "correct horse battery staple", raw, 0o600)

	b := &AgeBackend{Path: keyPath, PassphrasePath: passPath}
	key, err := b.Unseal(context.Background())
	require.NoError(t, err)
	require.Equal(t, raw, key)
}

func TestAgeBackendRejectsLoosePermissionsOnKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key.age")
	raw, err := GenerateKey()
	require.NoError(t, err)
	sealAgeFile(t, path, "a passphrase", raw, 0o600)

	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		t.Run(mode.String(), func(t *testing.T) {
			require.NoError(t, os.Chmod(path, mode))
			b := &AgeBackend{Path: path, Passphrase: "a passphrase"}
			_, err := b.Unseal(context.Background())
			require.ErrorContains(t, err, "chmod 600")
		})
	}
}

func TestAgeBackendRejectsLoosePermissionsOnPassphraseFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key.age")
	passPath := filepath.Join(dir, "passphrase")
	raw, err := GenerateKey()
	require.NoError(t, err)
	sealAgeFile(t, keyPath, "a passphrase", raw, 0o600)
	require.NoError(t, os.WriteFile(passPath, []byte("a passphrase"), 0o644))

	b := &AgeBackend{Path: keyPath, PassphrasePath: passPath}
	_, err = b.Unseal(context.Background())
	require.ErrorContains(t, err, "chmod 600")
}

func TestAgeBackendRejectsWrongPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key.age")
	raw, err := GenerateKey()
	require.NoError(t, err)
	sealAgeFile(t, path, "the right passphrase", raw, 0o600)

	b := &AgeBackend{Path: path, Passphrase: "the wrong passphrase"}
	_, err = b.Unseal(context.Background())
	require.Error(t, err)
}

// Corrupt ciphertext must be reported as a failure, not silently produce
// wrong key bytes — the same non-negotiable Key.Open enforces via GCM's
// authentication tag, exercised here at the AgeBackend layer.
func TestAgeBackendRejectsCorruptCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key.age")
	raw, err := GenerateKey()
	require.NoError(t, err)
	sealAgeFile(t, path, "a passphrase", raw, 0o600)

	ciphertext, err := os.ReadFile(path)
	require.NoError(t, err)
	corrupt := bytes.Clone(ciphertext)
	// Flip a byte well past the header, in the body most likely to hold the
	// symmetric payload's authentication tag.
	corrupt[len(corrupt)-1] ^= 0xff
	require.NoError(t, os.WriteFile(path, corrupt, 0o600))

	b := &AgeBackend{Path: path, Passphrase: "a passphrase"}
	_, err = b.Unseal(context.Background())
	require.Error(t, err)
}

func TestAgeBackendRejectsTruncatedCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key.age")
	raw, err := GenerateKey()
	require.NoError(t, err)
	sealAgeFile(t, path, "a passphrase", raw, 0o600)

	ciphertext, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, ciphertext[:len(ciphertext)/2], 0o600))

	b := &AgeBackend{Path: path, Passphrase: "a passphrase"}
	_, err = b.Unseal(context.Background())
	require.Error(t, err)
}

func TestAgeBackendRejectsWrongLengthPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key.age")
	sealAgeFile(t, path, "a passphrase", []byte("too short"), 0o600)

	b := &AgeBackend{Path: path, Passphrase: "a passphrase"}
	_, err := b.Unseal(context.Background())
	require.ErrorContains(t, err, "want 32")
}

func TestAgeBackendRequiresPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key.age")
	b := &AgeBackend{Path: path, AllowCreate: true}
	_, err := b.Unseal(context.Background())
	require.ErrorContains(t, err, "needs PassphrasePath or Passphrase")
}

func TestAgeBackendRequiresPath(t *testing.T) {
	b := &AgeBackend{Passphrase: "a passphrase"}
	_, err := b.Unseal(context.Background())
	require.ErrorContains(t, err, "Path is empty")
}

// checkPrivateFileMode's "not a regular file" branch — shared by
// FileBackend, and by both files AgeBackend reads — is exercised here via a
// FIFO: reading one would otherwise turn Unseal into an unbounded blocking
// read on a misconfigured or attacker-influenced path, exactly the failure
// mode the comment on that check describes.
func TestAgeBackendRejectsNonRegularKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key.age")
	require.NoError(t, syscall.Mkfifo(path, 0o600))

	b := &AgeBackend{Path: path, Passphrase: "a passphrase"}
	_, err := b.Unseal(context.Background())
	require.ErrorContains(t, err, "not a regular file")
}

// os.Stat can fail for reasons other than "does not exist" — e.g. a path
// component that isn't a directory — and that must not be folded into the
// AllowCreate branch, which would otherwise attempt to create a key file
// underneath what is actually a regular file.
func TestAgeBackendReportsStatErrorsOtherThanNotExist(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "not-a-directory")
	require.NoError(t, os.WriteFile(notADir, []byte("x"), 0o600))
	path := filepath.Join(notADir, "master.key.age")

	b := &AgeBackend{Path: path, Passphrase: "a passphrase", AllowCreate: true}
	_, err := b.Unseal(context.Background())
	require.Error(t, err)
	require.NotErrorIs(t, err, os.ErrNotExist, "a non-ENOENT stat error was treated as a missing file")
}

func TestAgeBackendRejectsMissingPassphraseFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key.age")
	raw, err := GenerateKey()
	require.NoError(t, err)
	sealAgeFile(t, keyPath, "a passphrase", raw, 0o600)

	b := &AgeBackend{Path: keyPath, PassphrasePath: filepath.Join(dir, "does-not-exist")}
	_, err = b.Unseal(context.Background())
	require.Error(t, err)
}

// Sealed() must distinguish the two ways a passphrase can be delivered: a
// PassphrasePath file sits right next to the key file, readable by the same
// same-OS-user adversary with zero human interaction (no more protection
// than FileBackend's plaintext key), while an in-memory Passphrase implies
// it was sourced from a human-present prompt and never touches disk. See
// AgeBackend.Sealed's doc comment for the full statement.
func TestAgeBackendSealedReflectsPassphraseDelivery(t *testing.T) {
	t.Run("interactive passphrase reports sealed", func(t *testing.T) {
		b := &AgeBackend{Path: "irrelevant.age", Passphrase: "correct horse battery staple"}
		require.True(t, b.Sealed())
	})

	t.Run("co-located passphrase file reports NOT sealed", func(t *testing.T) {
		b := &AgeBackend{Path: "irrelevant.age", PassphrasePath: "/some/co-located/passphrase"}
		require.False(t, b.Sealed(),
			"PassphrasePath is a same-OS-user-readable file, same exposure as FileBackend's "+
				"plaintext key; Sealed() must not claim otherwise")
	})

	t.Run("both set: PassphrasePath takes precedence and reports NOT sealed", func(t *testing.T) {
		b := &AgeBackend{
			Path:           "irrelevant.age",
			PassphrasePath: "/some/co-located/passphrase",
			Passphrase:     "correct horse battery staple",
		}
		require.False(t, b.Sealed())
	})

	// Neither delivery mode configured: the backend cannot unseal at all, so it
	// must not claim to be sealed — that would assert an at-rest guarantee for a
	// config that opens no key (CLAUDE.md principle 8).
	t.Run("neither set reports NOT sealed", func(t *testing.T) {
		b := &AgeBackend{Path: "irrelevant.age"}
		require.False(t, b.Sealed(),
			"an unconfigured AgeBackend protects nothing; Sealed() must not report true")
	})
}

// readPrivateFile must strip only the trailing line ending an editor or `echo`
// leaves behind, never intentional leading/trailing spaces or tabs — a
// passphrase is arbitrary text and those bytes may be part of the secret. An
// all-whitespace file still carries no secret and is rejected.
func TestReadPrivateFilePreservesIntentionalWhitespace(t *testing.T) {
	dir := t.TempDir()

	t.Run("preserves surrounding spaces, strips only the newline", func(t *testing.T) {
		p := filepath.Join(dir, "spaced")
		require.NoError(t, os.WriteFile(p, []byte("  pass phrase with edges  \n"), 0o600))
		v, err := readPrivateFile(p)
		require.NoError(t, err)
		require.Equal(t, "  pass phrase with edges  ", v)
	})

	t.Run("strips a CRLF ending", func(t *testing.T) {
		p := filepath.Join(dir, "crlf")
		require.NoError(t, os.WriteFile(p, []byte("secret\r\n"), 0o600))
		v, err := readPrivateFile(p)
		require.NoError(t, err)
		require.Equal(t, "secret", v)
	})

	t.Run("rejects an all-whitespace file", func(t *testing.T) {
		p := filepath.Join(dir, "blank")
		require.NoError(t, os.WriteFile(p, []byte("   \t\n"), 0o600))
		_, err := readPrivateFile(p)
		require.ErrorContains(t, err, "is empty")
	})
}

func TestAgeBackendRejectsEmptyPassphraseFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key.age")
	passPath := filepath.Join(dir, "passphrase")
	raw, err := GenerateKey()
	require.NoError(t, err)
	sealAgeFile(t, keyPath, "a passphrase", raw, 0o600)
	require.NoError(t, os.WriteFile(passPath, []byte("   \n"), 0o600))

	b := &AgeBackend{Path: keyPath, PassphrasePath: passPath}
	_, err = b.Unseal(context.Background())
	require.ErrorContains(t, err, "is empty")
}
