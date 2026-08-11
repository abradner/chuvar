package custody

import (
	"bytes"
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
// (1Password, with biometric release — OnePasswordBackend, below).
//
// The macOS keychain backend is a design note, not code yet: it would shell
// out to (or cgo-bind) `security find-generic-password`, storing the key
// under a service/account pair with an access-control-list entry scoped to
// the calling binary's code-signature — the same "human-present unlock"
// shape as the other two backends, satisfied by the OS prompting Touch
// ID/password the first time a *newly signed* binary asks for the item.
// Sealed() would report true. Not implemented because this fleet is
// Linux-only today (AGENTS.md §2); the interface is already
// implementation-compatible with it, which is the point of deciding the
// interface now rather than when the second platform actually lands.
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

	// Regular files only, not group/other readable. A path pointing at a FIFO
	// or a character device turns os.ReadFile into an unbounded blocking read,
	// so a misconfigured path (or one an attacker can influence) becomes a
	// boot that never completes rather than one that fails; refusing is both
	// safer and far easier to diagnose. checkPrivateFileMode is shared with
	// AgeBackend below — see its doc comment for why the same check applies
	// to every key-bearing file this package reads, not just this one.
	if err := checkPrivateFileMode(info, path); err != nil {
		return nil, err
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
		f.Close() //nolint:errcheck // the write error is the one worth reporting
		return nil, fmt.Errorf("custody: write key file: %w", err)
	}
	// fsync before reporting success. Without it a crash or power loss between
	// the write and the OS flush leaves a truncated or empty key file — and the
	// caller has already been told it has a key, so it will happily seal
	// secrets that nothing can ever open again. On a Pi with no UPS this is not
	// a theoretical window.
	if err := f.Sync(); err != nil {
		f.Close() //nolint:errcheck // the sync error is the one worth reporting
		return nil, fmt.Errorf("custody: syncing key file to disk: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("custody: close key file: %w", err)
	}
	// Sync the parent directory as well. f.Sync() makes the file's *contents*
	// durable, but the directory entry that gives those bytes a name is a
	// separate write — so without this the file can vanish entirely after a
	// power loss, while the database already holds a DEK wrapped under it. That
	// is the unrecoverable case, in the one window where it is silent.
	//
	// This covers the key file's own entry. If MkdirAll had to create the
	// directory too, that entry lives in *its* parent and is not synced here —
	// bounded honesty rather than a durability guarantee: the common case is a
	// pre-existing state directory.
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("custody: opening key directory to sync: %w", err)
	}
	if err := dir.Sync(); err != nil {
		dir.Close() //nolint:errcheck // the sync error is the one worth reporting
		return nil, fmt.Errorf("custody: syncing key directory: %w", err)
	}
	if err := dir.Close(); err != nil {
		return nil, fmt.Errorf("custody: closing key directory: %w", err)
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
	// A copy, not the backing slice. NewKey's doc invites callers to clear their
	// buffer once it has derived the cipher, and a caller taking that invitation
	// would zero this backend's only copy — after which every later Unseal hands
	// out 32 zero bytes and decryption silently fails against data sealed
	// earlier in the same process. FileBackend is unaffected because it returns
	// a freshly decoded slice per call.
	return bytes.Clone(e.key), nil
}

// checkPrivateFileMode enforces "not readable or writable by group or other"
// on every key-bearing file this package reads from disk — FileBackend's key
// file, AgeBackend's ciphertext file, and AgeBackend's passphrase file all
// share this exact check, deliberately: a secret (or, for AgeBackend's
// ciphertext, low-entropy material an attacker could otherwise attack
// offline) readable by another local user is the same failure mode no matter
// which backend produced it, and config.Secret's <KEY>_FILE reads apply the
// identical rule at the config layer — one posture, checked the same way
// everywhere it appears.
func checkPrivateFileMode(info fs.FileInfo, path string) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("custody: %s is not a regular file (mode %s); refusing to read it",
			path, info.Mode().Type())
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("custody: %s has mode %04o; it must not be readable or writable by "+
			"group or other (chmod 600)", path, perm)
	}
	return nil
}

// readPrivateFile reads a secret from disk, refusing loose permissions first
// via checkPrivateFileMode — the same shape config.Secret uses to read a
// required credential's <KEY>_FILE, reproduced here rather than imported so
// this package stays free of a dependency on internal/config's env-var
// lookup semantics, which don't apply to an explicit file path.
//
// It trims only the trailing line ending (`\n` or `\r\n`) an editor or `echo`
// leaves behind — NOT spaces or tabs, which may be intentional characters of
// the secret (an age passphrase is arbitrary text, unlike the connection
// strings and tokens config.Secret trims with TrimSpace, so the trimming
// deliberately differs there). An all-whitespace or empty file carries no
// secret and is still rejected.
func readPrivateFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("custody: stat %s: %w", path, err)
	}
	if err := checkPrivateFileMode(info, path); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("custody: read %s: %w", path, err)
	}
	v := strings.TrimRight(string(raw), "\r\n")
	if strings.TrimSpace(v) == "" {
		return "", fmt.Errorf("custody: %s is empty", path)
	}
	return v, nil
}
