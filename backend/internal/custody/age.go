package custody

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"filippo.io/age"
)

// AgeBackend decrypts a master key sealed as an age-encrypted file under a
// passphrase — age's scrypt recipient/identity pair, a symmetric,
// KDF-stretched secret rather than an asymmetric keypair, since there is no
// second party here to hand a public key to: the principal who sealed the
// key and the principal unsealing it are the same operator. Pure Go (the
// filippo.io/age library, no CGo, no shelled-out binary), so this backend
// works anywhere the Go toolchain does, unlike OnePasswordBackend's
// dependency on the `op` CLI being installed and signed in.
//
// Two files matter here, and they carry different sensitivity:
//   - Path: the age ciphertext. A strong passphrase makes this safe to leave
//     world-readable in principle, but this backend enforces the same 0600
//     posture as everything else in this package anyway — cheap
//     defense-in-depth against offline brute-forcing of a weak passphrase,
//     and it keeps "every key-bearing file on disk is 0600" a single
//     invariant an operator can check once rather than a per-backend
//     exception to remember.
//   - PassphrasePath: the actual secret. Read the same way config.Secret
//     reads a required credential's <KEY>_FILE (see readPrivateFile) —
//     refused if the file is regular but readable beyond its owner. Note
//     that "readable only by this file's owner" is not the same guarantee
//     as "readable only by a human" — see Sealed's doc comment for which
//     adversary each delivery mode (PassphrasePath vs. Passphrase) actually
//     defends against.
//
// The plaintext key is stored as the raw KeyLen bytes inside the age
// envelope, not base64 the way FileBackend's plaintext file is: FileBackend
// is base64 because its file is meant to be read and hand-edited during
// recovery; an age file is opaque ciphertext nobody edits by hand, so the
// extra encoding layer buys nothing.
type AgeBackend struct {
	// Path is the age-encrypted key file's location.
	Path string

	// PassphrasePath points to a file holding the decryption passphrase.
	// Takes precedence over Passphrase when set.
	//
	// CAVEAT — read before using this in a real deployment (see Sealed's doc
	// comment for the full statement): a passphrase co-located on disk next
	// to Path is readable, with zero human interaction, by exactly the same
	// same-OS-user adversary who can already read Path — the primary
	// adversary AGENTS.md §3.0 puts in scope for at-rest protection (an
	// instruction-following agent, or commodity exfiltration malware,
	// running as the operator's own OS user). Against that adversary this
	// mode buys nothing over FileBackend's plaintext key: the attacker
	// reads two 0600 files instead of one, still fully offline, still no
	// prompt. It only helps against a narrower adversary — one who reaches
	// the database or a backup but not the general filesystem. Use it only
	// when that narrower guarantee (plus restart-without-a-human) is the
	// accepted trade, not as a default "preferred for real deployments."
	PassphrasePath string

	// Passphrase is the decryption passphrase already resident in memory,
	// sourced from a human-present prompt at boot (see Backend.Unseal's doc
	// comment on why that ceremony is the one point chuvar requires operator
	// presence). Because the passphrase never touches disk, this — not
	// PassphrasePath — is the configuration that actually delivers the
	// guarantee Sealed() reports: protection against the same-OS-user
	// adversary named on PassphrasePath's doc, not just the narrower
	// database-only one.
	Passphrase string

	// AllowCreate permits sealing a fresh key under the passphrase when Path
	// does not exist yet, mirroring FileBackend.AllowCreate — and for the
	// same reason: silently minting a replacement key would present
	// unrecoverable data loss (everything sealed under the previous key) as
	// a successful boot.
	AllowCreate bool
}

func (b *AgeBackend) Name() string { return "age" }

// Sealed reports whether this configuration protects the key against the
// primary adversary AGENTS.md §3.0 puts in scope for at-rest protection: an
// instruction-following agent, or commodity exfiltration malware, reading
// the filesystem as the operator's own OS user. The age ciphertext and its
// scrypt KDF buy nothing against that adversary if the passphrase needed to
// open it sits in a second file the same attacker can also read — so
// Sealed() is keyed on *how the passphrase was delivered*, not merely on
// whether the key file is ciphertext:
//
//   - PassphrasePath set: false. The passphrase is a co-located 0600 file;
//     Unseal reads both files automatically with no human interaction, which
//     is exactly FileBackend's plaintext-key exposure with extra steps. See
//     PassphrasePath's doc comment for the full statement.
//   - Passphrase set (PassphrasePath empty): true. The passphrase was
//     sourced from a human-present prompt at boot and never reaches disk, so
//     this configuration genuinely denies the same-OS-user adversary the key
//     — modulo the passphrase's strength, which this package does not
//     enforce a minimum entropy for (an honest gap, not a claim overstated
//     here).
//
// Neither mode defends against an attacker who can read this process's own
// memory while it holds the passphrase or the unsealed key (see the package
// doc's stated runtime residual) — Sealed() is an at-rest claim only.
func (b *AgeBackend) Sealed() bool { return b.PassphrasePath == "" }

func (b *AgeBackend) passphrase() (string, error) {
	if b.PassphrasePath != "" {
		// Deliberately noisy, mirroring FileBackend.warnUnsealed: this mode
		// reports Sealed() == false (see its doc comment) for a real reason,
		// and the moment that becomes background noise nobody notices is the
		// moment a PoC deployment quietly becomes the real one.
		slog.Warn("custody: age backend configured with PassphrasePath — the decryption "+
			"passphrase is a co-located file, readable with no human interaction by anyone who "+
			"can read the master key file itself; this is NOT sealed against that adversary, "+
			"only against one who reaches the database but not the filesystem (see "+
			"AgeBackend.PassphrasePath's doc comment)", "backend", b.Name(), "path", b.PassphrasePath)
		return readPrivateFile(b.PassphrasePath)
	}
	if b.Passphrase != "" {
		return b.Passphrase, nil
	}
	return "", errors.New("custody: AgeBackend needs PassphrasePath or Passphrase set")
}

// Unseal reads and decrypts the age key file, or creates one when
// AllowCreate is set and no file exists yet.
func (b *AgeBackend) Unseal(ctx context.Context) ([]byte, error) {
	if b.Path == "" {
		return nil, errors.New("custody: AgeBackend.Path is empty")
	}
	passphrase, err := b.passphrase()
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(b.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !b.AllowCreate {
			// Deliberately does not suggest minting one, for the same reason
			// FileBackend's equivalent message doesn't: a replacement key opens
			// nothing sealed under the original.
			return nil, fmt.Errorf("custody: no age key file at %s", b.Path)
		}
		return b.create(b.Path, passphrase)
	case err != nil:
		return nil, fmt.Errorf("custody: stat age key file: %w", err)
	}
	if err := checkPrivateFileMode(info, b.Path); err != nil {
		return nil, err
	}

	f, err := os.Open(b.Path)
	if err != nil {
		return nil, fmt.Errorf("custody: open age key file: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only handle; nothing left to flush

	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("custody: build scrypt identity: %w", err)
	}
	r, err := age.Decrypt(f, identity)
	if err != nil {
		// age deliberately returns the same error for "wrong passphrase" and
		// "corrupt or tampered ciphertext" — like custody.Key.Open, the two
		// are indistinguishable by design and both fatal to the caller. The
		// error itself is age's own diagnostic text, never key material: no
		// bytes have been decrypted at the point this can fire.
		return nil, fmt.Errorf("custody: decrypt age key file %s: %w", b.Path, err)
	}
	// LimitReader bounds how much attacker-influenced plaintext this reads
	// into memory before checking length: cheap defense in depth in case
	// something one day writes an oversized payload behind Path (already
	// gated by checkPrivateFileMode above — this is belt-and-suspenders, not
	// the primary control).
	raw, err := io.ReadAll(io.LimitReader(r, KeyLen+1))
	if err != nil {
		return nil, fmt.Errorf("custody: read decrypted age key file %s: %w", b.Path, err)
	}
	if len(raw) != KeyLen {
		return nil, fmt.Errorf("custody: age key file %s holds %d bytes, want %d: %w",
			b.Path, len(raw), KeyLen, ErrKeyLen)
	}
	return raw, nil
}

func (b *AgeBackend) create(path, passphrase string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("custody: create age key directory: %w", err)
	}
	key, err := GenerateKey()
	if err != nil {
		return nil, err
	}

	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, fmt.Errorf("custody: build scrypt recipient: %w", err)
	}
	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return nil, fmt.Errorf("custody: begin age encryption: %w", err)
	}
	if _, err := w.Write(key); err != nil {
		return nil, fmt.Errorf("custody: encrypt age key file: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("custody: finish age encryption: %w", err)
	}

	// O_EXCL so a concurrent boot can't have two processes each mint a key
	// and race to overwrite — the loser would silently hold a key that opens
	// nothing, same reasoning as FileBackend.create.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("custody: create age key file: %w", err)
	}
	if _, err := f.Write(ciphertext.Bytes()); err != nil {
		f.Close() //nolint:errcheck // the write error is the one worth reporting
		return nil, fmt.Errorf("custody: write age key file: %w", err)
	}
	// fsync before reporting success — see FileBackend.create's identical
	// comment: without it a crash between write and OS flush leaves a
	// truncated key file after the caller has already been told sealing can
	// proceed.
	if err := f.Sync(); err != nil {
		f.Close() //nolint:errcheck // the sync error is the one worth reporting
		return nil, fmt.Errorf("custody: syncing age key file to disk: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("custody: close age key file: %w", err)
	}
	// Sync the parent directory too, for the same reason FileBackend.create
	// does: the directory entry that names the file is a separate write from
	// the file's own contents.
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("custody: opening age key directory to sync: %w", err)
	}
	if err := dir.Sync(); err != nil {
		dir.Close() //nolint:errcheck // the sync error is the one worth reporting
		return nil, fmt.Errorf("custody: syncing age key directory: %w", err)
	}
	if err := dir.Close(); err != nil {
		return nil, fmt.Errorf("custody: closing age key directory: %w", err)
	}

	slog.Warn("custody: minted a new age-sealed master key — back up both the key file and "+
		"its passphrase before sealing anything; losing either means losing every secret "+
		"sealed under it", "path", path)
	return key, nil
}
