// Package broker implements brokerd's core: preflight and payload-
// constrained signing over capability grants (issues #95, #79). It never
// imports or queries facts/staged_diffs — see store.go's doc comment — and
// it never blind-signs (capability-broker.md, "The broker must not
// blind-sign"): the only thing Sign can produce a signature over is a
// payload that parses as a well-formed git commit object whose committer
// email matches the invoking grant, under the "git" SSHSIG namespace and no
// other.
package broker

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abradner/chuvar/backend/internal/broker/commit"
	"github.com/abradner/chuvar/backend/internal/broker/keyring"
	"github.com/abradner/chuvar/backend/internal/broker/sshsig"
	"github.com/abradner/chuvar/backend/internal/scope"
)

// gitNamespace is the only SSHSIG namespace brokerd will ever sign under —
// see the package doc and capability-broker.md's "The broker must not
// blind-sign". Not a config knob: making this configurable would be handing
// back exactly the general-purpose signing surface this design exists to
// refuse.
const gitNamespace = "git"

// gitSignOperation is the one capability operation this binary implements.
// Every request's scope must name exactly this operation (any target is
// fine — that half is checked against the grant via scope.Covers); anything
// else is refused before the grant's own scopes are even consulted. See
// checkScope for who this defends against.
const gitSignOperation = scope.Scope("git.sign")

// Broker wires together the grant cache, the signing key, and the audit
// trail to answer preflight and sign requests. Safe for concurrent use —
// every field is itself concurrency-safe (Cache and rateLimiter hold their
// own locks; SigningKey's underlying memguard buffer supports concurrent
// reads) and Handle allocates no shared mutable state of its own.
type Broker struct {
	pool  *pgxpool.Pool
	cache *Cache
	key   *keyring.SigningKey
	rate  *rateLimiter
}

// New builds a Broker. rateLimit <= 0 or rateWindow <= 0 disables the
// per-grant sign-rate tripwire (see newRateLimiter).
func New(pool *pgxpool.Pool, cache *Cache, key *keyring.SigningKey, rateLimit int, rateWindow time.Duration) *Broker {
	return &Broker{pool: pool, cache: cache, key: key, rate: newRateLimiter(rateLimit, rateWindow)}
}

// Handle dispatches one request to Preflight or Sign, matching the socket
// protocol's Op field. Unknown ops are refused rather than ignored — see
// AGENTS.md §5 "fail closed, loudly."
func (b *Broker) Handle(ctx context.Context, req Request) Result {
	switch req.Op {
	case "preflight":
		return b.Preflight(req)
	case "sign":
		return b.Sign(ctx, req)
	default:
		return Result{Code: ScopeDenied, Message: fmt.Sprintf("unknown op %q", req.Op)}
	}
}

// Preflight answers "authorized, and for how long?" with no side effects —
// capability-broker.md's requirement that availability be queryable before
// an agent commits to a long-running operation. Consults only the
// in-memory cache: no database round trip, no audit write.
func (b *Broker) Preflight(req Request) Result {
	entry, ok := b.cache.Lookup(req.Token)
	if !ok {
		return Result{Code: NoGrant, Message: "no active capability grant matches this token"}
	}

	if res, ok := checkScope(entry, req.Scope); !ok {
		return res
	}

	res := Result{Code: OK}
	if entry.ExpiresAt != nil {
		s := entry.ExpiresAt.UTC().Format(time.RFC3339)
		res.ExpiresAt = &s
	}
	return res
}

// Sign validates req.Payload as a well-formed, not-yet-signed git commit
// object whose committer matches the invoking grant's authorized identity,
// signs it under the "git" SSHSIG namespace, durably records the exercise
// of authority, and returns the armored signature.
//
// The audit write (insertSignAuditLog) is the one part of this call that
// touches Postgres — everything before it (token lookup, scope check,
// payload validation, the signature itself) is in-process only, matching
// the 2026-08-09 "the sign call consults only in-process state" decision
// for the *authorization* question. The audit write is this build's
// deliberate, stated exception to that decision for a different property:
// AGENTS.md principle 6, "every exercise of authority is audited," and the
// package doc's "never blind-signs" extended one step further — a
// signature this process cannot attest to having produced is treated the
// same as one it should never have produced at all. If the audit write
// fails, the computed signature is discarded and BACKEND_UNREACHABLE is
// returned rather than OK: the caller gets nothing usable, not an
// unaudited signature with a confusing error alongside it.
func (b *Broker) Sign(ctx context.Context, req Request) Result {
	entry, ok := b.cache.Lookup(req.Token)
	if !ok {
		return Result{Code: NoGrant, Message: "no active capability grant matches this token"}
	}

	if !b.rate.Allow(entry.GrantID) {
		return Result{Code: RateLimited, Message: "sign-rate anomaly tripwire fired for this grant"}
	}

	if res, ok := checkScope(entry, req.Scope); !ok {
		return res
	}

	// "Never blind-signs": payload must parse as a well-formed git commit
	// object, and its committer must be the identity this specific grant
	// authorizes — see codes.go's ScopeDenied doc comment for why both
	// failure shapes land on that code rather than a new one.
	c, err := commit.Parse(req.Payload)
	if err != nil {
		return Result{Code: ScopeDenied, Message: "refusing to sign: " + err.Error()}
	}
	if c.CommitterEmail != entry.CommitterEmail {
		return Result{Code: ScopeDenied, Message: fmt.Sprintf(
			"refusing to sign: committer %q does not match this grant's authorized identity", c.CommitterEmail)}
	}

	signer, err := b.key.Signer()
	if err != nil {
		// Only reachable once the signing key has been destroyed (process
		// shutdown in progress) — see keyring.SigningKey.Signer's doc
		// comment. Not a semantic fit for "custody backend down" in the
		// literal sense the taxonomy's table describes, but the closest
		// available code: the thing that would make this request succeed
		// (a live signing key) is unavailable, and BACKEND_UNREACHABLE's
		// prescribed response ("escalate; distinct from LOCKED") is the
		// right guidance regardless of exactly which backing store is the
		// one that's gone.
		return Result{Code: BackendUnreachable, Message: "signing key unavailable: " + err.Error()}
	}

	armored, err := sshsig.Sign(signer, gitNamespace, req.Payload)
	if err != nil {
		// Not expected to be reachable in practice (see sshsig.Sign's
		// callers here: namespace is always the non-empty constant above,
		// and the only other failure mode is the underlying crypto
		// signer's Sign call itself failing, which for ed25519 requires a
		// broken rand.Reader). Handled defensively rather than treated as
		// impossible — same BACKEND_UNREACHABLE reasoning as the Signer()
		// error above.
		return Result{Code: BackendUnreachable, Message: "signing failed: " + err.Error()}
	}

	if err := insertSignAuditLog(ctx, b.pool, entry.Subject, entry.GrantID, req.Scope); err != nil {
		return Result{Code: BackendUnreachable, Message: "signature computed but could not be audited; refusing to return it: " + err.Error()}
	}

	return Result{Code: OK, Signature: armored}
}

// checkScope is the one scope gate both Preflight and Sign run — shared
// deliberately, so preflight can never say OK to a request Sign would then
// refuse (an agent doing exactly what the design asks, "ask before
// starting," must never get a false positive from the cheap call).
//
// Two checks, in order:
//
//  1. The requested scope's operation must be exactly gitSignOperation.
//     Adversary: a mis-provisioned grant row. No grant-creation surface
//     exists yet (#96), so nothing upstream enforces that a capability
//     grant carrying identity+token rows also carries a git.sign-shaped
//     scope — and coverage alone (check 2) would happily authorize a grant
//     seeded with "totally.unrelated.operation" to mint a real git-commit
//     signature, an operation its human approver never named. The only
//     artifact Sign can ever produce is an SSHSIG in the "git" namespace,
//     so a request naming any other operation is refused outright rather
//     than resolved against the grant. Exact match, not Covers-descent: a
//     request for a sub-operation ("git.sign.something") names an operation
//     this binary doesn't implement either.
//  2. The grant's scopes must cover the request (scope.AnyCovers) — the
//     operation hierarchy and exact-match target semantics both live in
//     internal/scope, checked against the grant the *token* authenticated,
//     never a grant the request merely named.
func checkScope(entry Entry, reqScope string) (Result, bool) {
	requested := scope.Scope(reqScope)
	if err := scope.Validate(requested); err != nil {
		return Result{Code: ScopeDenied, Message: "invalid scope: " + err.Error()}, false
	}
	if requested.Operation() != gitSignOperation {
		return Result{Code: ScopeDenied, Message: fmt.Sprintf(
			"this broker implements only the %q operation; refusing scope %q", gitSignOperation, reqScope)}, false
	}
	if !scope.AnyCovers(entry.Scopes, requested) {
		return Result{Code: ScopeDenied, Message: "grant does not cover the requested scope"}, false
	}
	return Result{}, true
}
