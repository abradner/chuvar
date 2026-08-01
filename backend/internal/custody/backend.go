package custody

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Backend supplies the master key at service boot.
//
// Three implementations are decided rather than speculative, which is what
// justifies an interface here under AGENTS.md §3.3: the file backend below
// (headless Linux — the Pi), an OS keychain backend (macOS, where keychain
// ACLs bind to the requesting application), and a password-manager backend
// (1Password, with biometric release). Only the file backend exists today.
type Backend interface {
	// Unseal returns raw master key material of length KeyLen. Implementations
	// that require a human-present ceremony block here, which is the one point
	// in chuvar's lifecycle where operator presence is required by design.
	Unseal(ctx context.Context) ([]byte, error)

	// Name identifies the backend in logs and operational output.
	Name() string

	// Sealed reports whether this backend actually protects the key at rest.
	//
	// False means the door is wedged open: the key is recoverable by anyone who
	// can read the host's filesystem as this user, so the at-rest guarantee in
	// package doc does not hold. Callers should surface this, not swallow it —
	// a deployment that believes it is sealed when it is not is worse than one
	// that knows it isn't (CLAUDE.md principle 8).
	Sealed() bool
}

// FileBackend reads the master key from a file on local disk.
//
// DOOR WEDGED OPEN: the file is plaintext today, so this backend reports
// Sealed() == false. It exists in this form deliberately — it establishes the
// envelope, the key's storage location, and every call site, so that adding
// the real ceremony (age encryption under a passphrase, prompted at boot) is a
// change to this one type rather than a change to the system. Until that lands,
// anything that can read the key file can unseal chuvar's secrets, and the
// protection this provides is limited to attackers who reach the database
// without reaching the filesystem — a stolen backup, a `pgdata` scrape, or a
// process holding DB credentials and nothing else. That is a real adversary
// (it is precisely the one that could otherwise read a TOTP secret and approve
// its own grant request) but it is not the whole threat model.
type FileBackend struct {
	// Path is the key file's location. Empty means DefaultKeyPath.
	Path string

	// AllowCreate permits generating a new key when Path does not exist. A
	// fresh key cannot decrypt anything sealed under a previous one, so this
	// is deliberately opt-in: silently minting a replacement would present
	// unrecoverable data loss as a successful boot.
	AllowCreate bool
}

// DefaultKeyPath returns the conventional key location, honouring
// XDG_STATE_HOME and falling back to ~/.local/state per the XDG basedir spec.
// Deliberately outside the repository — a key under a working tree is one
// `git add -A` away from being published.
func DefaultKeyPath() (string, error) {
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		return filepath.Join(dir, "chuvar", "master.key"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("custody: locating home directory: %w", err)
	}
	return filepath.Join(home, ".local", "state", "chuvar", "master.key"), nil
}

func (b *FileBackend) Name() string { return "file" }

// Sealed is false for as long as the key file is plaintext. See the type's doc
// comment; this is the honest answer, not a placeholder.
func (b *FileBackend) Sealed() bool { return false }

func (b *FileBackend) path() (string, error) {
	if b.Path != "" {
		return b.Path, nil
	}
	return DefaultKeyPath()
}

// Unseal reads the key file, or creates one when AllowCreate is set and no file
// exists. It refuses a file that is readable beyond its owner: a 0644 key is a
// key every process on the box already has, and continuing would mean claiming
// a protection that isn't there.
func (b *FileBackend) Unseal(ctx context.Context) ([]byte, error) {
	path, err := b.path()
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !b.AllowCreate {
			// Deliberately does not suggest minting one: a replacement key opens
			// nothing sealed under the original, so "just create it" is the wrong
			// instinct when the real cause is a key that went missing. Callers
			// that know minting is safe (a first run) say so in their own message.
			return nil, fmt.Errorf("custody: no key file at %s", path)
		}
		return b.create(path)
	case err != nil:
		return nil, fmt.Errorf("custody: stat key file: %w", err)
	}

	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("custody: key file %s has mode %04o; it must not be readable "+
			"or writable by group or other (chmod 600)", path, perm)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("custody: read key file: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("custody: decode key file %s: %w", path, err)
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf("custody: key file %s holds %d bytes, want %d: %w",
			path, len(key), KeyLen, ErrKeyLen)
	}

	b.warnUnsealed(path)
	return key, nil
}

func (b *FileBackend) create(path string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("custody: create key directory: %w", err)
	}
	key, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	encoded := append([]byte(base64.StdEncoding.EncodeToString(key)), '\n')
	// O_EXCL so a concurrent boot can't have two processes each mint a key and
	// race to overwrite — the loser would silently hold a key that opens
	// nothing.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("custody: create key file: %w", err)
	}
	if _, err := f.Write(encoded); err != nil {
		f.Close()
		return nil, fmt.Errorf("custody: write key file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("custody: close key file: %w", err)
	}

	slog.Warn("custody: minted a new master key — back this file up before sealing anything, "+
		"losing it means losing every secret sealed under it", "path", path)
	b.warnUnsealed(path)
	return key, nil
}

// warnUnsealed states the wedged-open posture on every boot. It is deliberately
// noisy: the moment this becomes background noise nobody notices is the moment
// a PoC deployment quietly becomes the real one.
func (b *FileBackend) warnUnsealed(path string) {
	slog.Warn("custody: DOOR WEDGED OPEN — master key is stored in plaintext and this "+
		"deployment is NOT sealed at rest against anyone who can read the filesystem as this "+
		"user; suitable for development and low-value PoC secrets only",
		"backend", b.Name(), "path", path, "ticket", "E7")
}

// Ephemeral is an in-memory backend that mints a fresh key per instance. For
// tests and for any run whose data is expected not to outlive the process —
// nothing sealed under it can be opened again once it goes away.
type Ephemeral struct {
	key []byte
}

func (e *Ephemeral) Name() string { return "ephemeral" }

// Sealed is false: the key never reaches disk, but it isn't protected from the
// process holding it either, and claiming otherwise would overstate it.
func (e *Ephemeral) Sealed() bool { return false }

func (e *Ephemeral) Unseal(ctx context.Context) ([]byte, error) {
	if e.key == nil {
		key := make([]byte, KeyLen)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("custody: ephemeral key: %w", err)
		}
		e.key = key
	}
	return e.key, nil
}
