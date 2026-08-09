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
	"crypto/sha256"
	"encoding/hex"
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
// Every request's scope must name exactly this operation; anything else is
// refused before the grant's own scopes are even consulted. See checkScope
// for who this defends against.
//
// The target half is NOT "fine either way" — brokerd always knows which
// repository it is signing for (it parsed the commit payload's tree/parent
// context or was invoked for a specific worktree), so every request scope
// it builds or accepts must carry a target, and checkScope enforces that via
// scope.ValidateCapability before ever consulting the grant. This reflects
// the 2026-08-09 fail-closed resolution (docs/capability-broker.md decision
// log, "Capability scope Covers is fail-closed on target..."): an
// untargeted grant does not cover a targeted request and vice versa, so a
// request with no target could never be legitimately authorized by any
// grant this broker is willing to cache in the first place (see cache.go's
// parseScopes) — accepting an untargeted request at all would just be a
// slower way to reach the same SCOPE_DENIED/NO_GRANT outcome, with a less
// useful error message along the way.
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
	// commit.Parse's ErrMalformed is deliberately structural and carries no
	// payload-derived bytes (see commit.go's malformed doc) — so surfacing
	// err.Error() to the socket client here leaks nothing attacker-controlled
	// and cannot be amplified into an oversized response by a giant header
	// value. Do NOT interpolate parsed payload fields into a client-facing
	// message for the same reason: the committer-mismatch case below reports
	// the structural fact ("does not match this grant's authorized identity")
	// without echoing the attacker-supplied, unbounded committer string.
	c, err := commit.Parse(req.Payload)
	if err != nil {
		return Result{Code: ScopeDenied, Message: "refusing to sign: " + err.Error()}
	}
	if c.CommitterEmail != entry.CommitterEmail {
		return Result{Code: ScopeDenied, Message: "refusing to sign: committer does not match this grant's authorized identity"}
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

	// Attribute this row to the specific object signed: the sha256 of the
	// unsigned payload plus the committer identity, both non-sensitive (see
	// signAuditDetail). Digest the exact bytes that were signed (req.Payload,
	// which is also what sshsig.Sign consumed above), so the trail identifies
	// the signed object, not a reserialization of it.
	digest := sha256.Sum256(req.Payload)
	detail := signAuditDetail{
		PayloadSHA256:  hex.EncodeToString(digest[:]),
		CommitterEmail: c.CommitterEmail,
	}
	if err := insertSignAuditLog(ctx, b.pool, entry.Subject, entry.GrantID, req.Scope, detail); err != nil {
		return Result{Code: BackendUnreachable, Message: "signature computed but could not be audited; refusing to return it: " + err.Error()}
	}

	return Result{Code: OK, Signature: armored}
}

// checkScope is the one scope gate both Preflight and Sign run — shared
// deliberately, so preflight can never say OK to a request Sign would then
// refuse (an agent doing exactly what the design asks, "ask before
// starting," must never get a false positive from the cheap call).
//
// What this broker enforces today, stated exactly (principle 8, "claims name
// their adversary — and must hold"): the grant's authorized committer
// identity (broker.go's Sign, the CommitterEmail match), a well-formed,
// not-already-signed git commit payload (commit.Parse), and the
// operation:target scope STRING the caller presents (checkScope below:
// operation == git.sign, a target is present, and the grant covers it).
//
// What it does NOT enforce — the residual, stated plainly rather than
// aspirationally claimed: the signature is NOT bound to the repository the
// scope target names. A git commit object carries no repository identity (only
// tree/parent object ids), and checkScope validates only the caller-supplied
// req.Scope, never the payload's tree/parents against the repo the target
// names. The adversary is our own user's confused/injected agent (principle 2)
// holding a legitimate git.sign:<repoA> grant: it can label the request with
// repoA's scope (passing every check here) while submitting a well-formed
// commit destined for repoB with the permitted committer email, and receive a
// valid "git" SSHSIG usable in repoB — an object the human approver authorized
// for repoA only. This is architectural (the payload has no repo identity to
// check against), deliberately shipped documented-and-ticketed rather than
// enforced in this PR; real binding is designed in issue #106. Do not read
// this as "repo binding is stated but not enforced" cover for adding a weaker
// check: until #106 lands there is NO repository binding at all.
//
// Three checks, in order:
//
//  1. The requested scope must be well-formed AND carry a target
//     (scope.ValidateCapability, not the weaker scope.Validate that memory
//     scopes use). Adversary: a caller sending an untargeted "git.sign"
//     hoping it resolves against some ambient default repository. Per the
//     2026-08-09 fail-closed decision, no grant this broker will ever cache
//     can cover an untargeted request anyway (cache.go's parseScopes
//     refuses to load an untargeted capability grant at all — see its doc
//     comment) — rejecting here first just gives a precise "must specify a
//     target" message instead of a generic scope-mismatch one for what
//     would otherwise still end in denial.
//  2. The requested scope's operation must be exactly gitSignOperation.
//     Adversary: a mis-provisioned grant row. No grant-creation surface
//     exists yet (#96), so nothing upstream enforces that a capability
//     grant carrying identity+token rows also carries a git.sign-shaped
//     scope — and coverage alone (check 3) would happily authorize a grant
//     seeded with "totally.unrelated.operation" to mint a real git-commit
//     signature, an operation its human approver never named. The only
//     artifact Sign can ever produce is an SSHSIG in the "git" namespace,
//     so a request naming any other operation is refused outright rather
//     than resolved against the grant. Exact match, not Covers-descent: a
//     request for a sub-operation ("git.sign.something") names an operation
//     this binary doesn't implement either.
//  3. The grant's scopes must cover the request (scope.AnyCovers) — the
//     operation hierarchy and fail-closed exact-match target semantics both
//     live in internal/scope, checked against the grant the *token*
//     authenticated, never a grant the request merely named.
func checkScope(entry Entry, reqScope string) (Result, bool) {
	requested := scope.Scope(reqScope)
	if err := scope.ValidateCapability(requested); err != nil {
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
