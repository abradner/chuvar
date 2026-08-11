// Package custody holds chuvar's root key material and the AEAD primitive that
// seals secrets under it.
//
// The shape is an envelope: a Backend supplies the master key (KEK) at service
// boot; that key wraps a data-encryption key (DEK) stored alongside the data it
// protects. Rotating the master key rewraps the DEK — it does not re-encrypt
// the data. That property is why the envelope exists at all, and it's what
// makes the eventual multi-factor story (passphrase, cold-stored recovery
// phrase, hardware token — each wrapping the same DEK independently) additive
// rather than a migration.
//
// Threat model: this package defends the at-rest case — an attacker who reads
// `pgdata` bytes, a stolen backup, or a process holding DB credentials but not
// the master key. See CLAUDE.md principles 3 and 9, and the Agent Capability
// Broker decision log (2026-08-01 entries) in docs/capability-broker.md for
// the full statement.
//
// What this package does NOT do, stated plainly because an aspirational
// security claim is a bug (CLAUDE.md principle 8): key material here lives on
// the ordinary Go heap. It is not held in a guarded enclave, not mlocked, and
// not protected from a same-user process that can ptrace this one or read a
// core dump. Those mitigations belong to the sealed-vault pass (ticket E7),
// which is also where the multi-factor wrapping and the real unlock ceremony
// land. Until then the runtime residual is exactly as the threat model
// describes it: narrowed at rest, unmitigated in memory.
package custody

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeyLen is the length of every key this package handles — master keys and
// DEKs alike — in bytes. 32 bytes selects AES-256 in NewKey below.
const KeyLen = 32

// ErrKeyLen is returned when key material is the wrong size. Callers reading
// keys from storage should treat this as corruption, not as a retryable error.
var ErrKeyLen = fmt.Errorf("custody: key must be exactly %d bytes", KeyLen)

// Key is symmetric key material plus the AEAD built over it. The same type
// serves as both master key and DEK: wrapping a DEK is just sealing its bytes
// under the master key, so one primitive covers both jobs.
type Key struct {
	aead cipher.AEAD
}

// NewKey builds a Key from raw material. The slice is not retained — the
// derived cipher state is what lives on, so callers may reuse or clear their
// buffer afterwards.
func NewKey(raw []byte) (*Key, error) {
	if len(raw) != KeyLen {
		return nil, ErrKeyLen
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, fmt.Errorf("custody: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("custody: new gcm: %w", err)
	}
	return &Key{aead: aead}, nil
}

// GenerateKey returns fresh random key material suitable for NewKey.
func GenerateKey() ([]byte, error) {
	raw := make([]byte, KeyLen)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("custody: generate key: %w", err)
	}
	return raw, nil
}

// Seal encrypts plaintext, returning nonce||ciphertext||tag as one blob.
//
// The nonce is random per call rather than a counter: a counter would have to
// survive process restarts and be coordinated across whoever holds the key,
// and getting that wrong silently destroys GCM's security. Random 96-bit
// nonces are safe well past any volume chuvar will see for a single key.
func (k *Key) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("custody: nonce: %w", err)
	}
	// Seal appends to its first argument, so passing the nonce itself both
	// prefixes the output and avoids a second allocation.
	return k.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open reverses Seal. A failure here means the blob was produced under a
// different key or has been tampered with; both are fatal to the caller, and
// neither is distinguishable from the other by design.
func (k *Key) Open(blob []byte) ([]byte, error) {
	ns := k.aead.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("custody: sealed blob is shorter than its nonce")
	}
	plaintext, err := k.aead.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("custody: open: %w", err)
	}
	return plaintext, nil
}

// Wrap seals a DEK's raw bytes under this key. Named separately from Seal
// because the distinction is load-bearing when reading call sites: wrapped
// DEKs are safe to store next to the data, sealed values are the data.
func (k *Key) Wrap(dek []byte) ([]byte, error) {
	if len(dek) != KeyLen {
		return nil, ErrKeyLen
	}
	return k.Seal(dek)
}

// Unwrap recovers a DEK wrapped by Wrap and returns it ready to use.
func (k *Key) Unwrap(wrapped []byte) (*Key, error) {
	raw, err := k.Open(wrapped)
	if err != nil {
		return nil, err
	}
	return NewKey(raw)
}
