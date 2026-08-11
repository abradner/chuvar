// Package keyring holds brokerd's decrypted git-signing key in guarded
// process memory for the process's lifetime, and derives an ssh.Signer from
// it on demand.
//
// # Scope, honestly stated
//
// capability-broker.md's custody model describes fetching and holding key
// material "in process memory for the grant duration" — implying a fetch
// per grant. This package does something narrower: brokerd's core (issues
// #95, #79) has no grant-*creation* surface yet (that's #96, explicitly
// out of scope here), so there is no interactive moment at which a per-grant
// fetch could even happen. What exists instead is ONE signing key, unsealed
// once at process boot via a custody.Backend (the same interface, same
// human-present-unlock posture the doc describes — just invoked at boot
// rather than at grant time), held here for the process's lifetime, and
// destroyed on shutdown or an operator-initiated reseal.
//
// "Revocation becomes destruction" (capability-broker.md, Custody model)
// therefore holds at the *authorization* layer in this build — a revoked
// grant is removed from the broker's in-memory index and can no longer
// authorize a request (internal/broker/cache.go) — but not at the *key
// material* layer, since the key isn't per-grant to begin with. That's a
// real, stated scope reduction, not a silent one: true per-grant custody
// isolation is deferred to whenever #96 gives grant creation an interactive
// moment to fetch into. Until then, every capability grant that authorizes
// git.sign shares this one broker-wide key, distinguished from each other
// only by the (committer email, scope, token, expiry) content the grant
// itself carries — see capability-broker.md's "Agent identity is grant
// content" decision, configuration 2 (dedicated key + distinct committer
// email), which is exactly what a shared key plus per-grant committer
// identity gives you.
//
// # Memory hygiene
//
// Uses github.com/awnumar/memguard, per the #74 custody spike's
// recommendation, with the three caveats that spike found the library
// itself does not handle:
//
//  1. NewBuffer+Copy, never NewBufferFromBytes — the latter silently
//     Freeze()s the buffer, and Wipe() on a frozen buffer SIGSEGVs the whole
//     process instead of returning an error (spike finding, reproduced live).
//  2. Every allocation is wrapped in recover(): exceeding memguard's
//     mlock-derived ceiling calls core.Panic, which is a normal recoverable
//     Go panic but has the side effect of destroying every other
//     currently-held memguard buffer in the process (Purge()), not just the
//     failing one — this package has exactly one buffer, so that blast
//     radius is contained to itself, but the recover() still matters:
//     without it, an allocation failure here would be a fatal crash instead
//     of a reported error.
//  3. PR_SET_DUMPABLE(0) is NOT something memguard calls for you (confirmed
//     by source inspection in the spike) — cmd/brokerd's main.go calls it
//     once at boot, before this package's Load ever runs, so this package
//     doesn't need to and doesn't duplicate that call.
//
// What this narrows but does not close, stated per AGENTS.md §6 ("an
// aspirational security comment is a bug"): deriving an ssh.Signer from the
// guarded seed necessarily copies key material onto the ordinary Go heap
// (crypto/ed25519's internal state has no exposed Zero()/Destroy() hook,
// confirmed in the #74 spike for the AES case and structurally identical
// here) for as long as that Signer is held. Signer() is therefore called
// once, at Load time, and the resulting ssh.Signer is what's reused for
// every signing operation — not re-derived per request — which bounds the
// heap-copy count to one rather than one per signature, but does not zero
// it. Re-deriving just-in-time per signature would shrink the window
// further at the cost of doing so on every hot-path sign call; not taken,
// consistent with the 2026-08-09 "sign call consults only in-process state"
// decision not wanting extra per-signature cost on that path either.
package keyring

import (
	"crypto/ed25519"
	"fmt"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/ssh"
)

// SeedLen is the length of an ed25519 private key seed — chosen as brokerd's
// one supported key type because it is small, modern, and (not
// coincidentally) exactly custody.KeyLen, so the existing custody.Backend
// interface ("Unseal returns raw key material of length KeyLen") can supply
// it with no changes to that interface or its contract.
const SeedLen = ed25519.SeedSize // 32

// SigningKey holds a guarded ed25519 seed and the ssh.Signer derived from it.
type SigningKey struct {
	buf    *memguard.LockedBuffer
	signer ssh.Signer
}

// Load guards seed's bytes (mlock'd, MADV_DONTDUMP'd, guard-paged — see
// memguard's own documentation for the mechanism) and derives the ssh.Signer
// used for every subsequent Sign call. seed is not retained by the caller's
// slice after this returns — Load copies it into the guarded buffer and the
// caller should discard (ideally zero) its own copy.
func Load(seed []byte) (key *SigningKey, err error) {
	if len(seed) != SeedLen {
		return nil, fmt.Errorf("keyring: seed must be %d bytes, got %d", SeedLen, len(seed))
	}

	// See the package doc's point 2: a recover() here turns an
	// mlock-ceiling panic into a reported error instead of a fatal crash.
	// This package holds exactly one buffer, so Purge()'s "destroys every
	// other currently-held buffer" side effect has no other victims in this
	// process — but it's still worth naming: a caller retrying Load in a
	// loop after a failure here should not assume any previous SigningKey
	// this process might somehow still be holding survived the panic.
	defer func() {
		if r := recover(); r != nil {
			key = nil
			err = fmt.Errorf("keyring: allocating guarded memory panicked (likely RLIMIT_MEMLOCK exhaustion): %v", r)
		}
	}()

	buf := memguard.NewBuffer(SeedLen) // mutable — required for Destroy/Wipe to work, see point 1
	if buf == nil || buf.Size() == 0 {
		return nil, fmt.Errorf("keyring: memguard.NewBuffer returned no usable buffer")
	}
	buf.Copy(seed)

	priv := ed25519.NewKeyFromSeed(buf.Bytes())
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		buf.Destroy()
		return nil, fmt.Errorf("keyring: deriving ssh signer: %w", err)
	}

	return &SigningKey{buf: buf, signer: signer}, nil
}

// Signer returns the ssh.Signer derived at Load time. Returns an error
// rather than a possibly-nil Signer once Destroy has run — see Destroyed.
func (k *SigningKey) Signer() (ssh.Signer, error) {
	if k.Destroyed() {
		return nil, fmt.Errorf("keyring: signing key has been destroyed")
	}
	return k.signer, nil
}

// Destroyed reports whether Destroy has already run — memguard's own
// IsAlive, inverted, so callers don't have to know memguard's vocabulary.
func (k *SigningKey) Destroyed() bool {
	return !k.buf.IsAlive()
}

// Destroy wipes and unmaps the guarded seed. Idempotent: memguard's own
// Destroy is safe to call more than once. Called on process shutdown
// (cmd/brokerd's signal handler) — the point at which this build's
// process-lifetime key custody actually ends; see the package doc's "Scope,
// honestly stated" for what this does and doesn't mean for an individual
// grant's revocation.
func (k *SigningKey) Destroy() {
	k.buf.Destroy()
}
