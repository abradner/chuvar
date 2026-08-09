package broker

// Code is brokerd's typed failure taxonomy, exactly as capability-broker.md's
// table specifies — replacing a single undifferentiated error string with a
// vocabulary an agent can branch on without parsing prose.
type Code string

const (
	// OK: signature (or, for preflight, authorization) returned. Proceed.
	OK Code = "OK"

	// NoGrant: never granted, expired, or revoked. Correct agent response
	// per the doc: request a grant; consult repo signing policy.
	//
	// Reserved strictly for "no active grant matches the presented token at
	// all" — the cache.Lookup miss at the top of Preflight/Sign. A payload
	// that fails to parse as a well-formed git commit object, or that already
	// carries a gpgsig header, does NOT land here: the token matched a live
	// grant, so those are SCOPE_DENIED (see that code's own doc comment for
	// why the whole content-shaped question of what a signing grant authorizes
	// folds into SCOPE_DENIED rather than a new code).
	NoGrant Code = "NO_GRANT"

	// ScopeDenied: an active grant was found (the token matched), but it
	// does not cover this request. capability-broker.md's table defines
	// this as "grant exists but does not cover this scope"; this build
	// extends that to cover the whole content-shaped question of what a
	// signing grant authorizes, not only the operation:target scope string:
	//
	//   - the requested scope isn't covered by the grant's granted scopes
	//     (wrong operation or wrong target — internal/scope's Covers)
	//   - the payload's committer email doesn't match the grant's
	//     authorized committer_email (internal/broker/commit)
	//   - the payload doesn't parse as a well-formed git commit object, or
	//     carries a gpgsig header already (internal/broker/commit)
	//
	// The taxonomy in the doc has no separate code for "malformed payload"
	// or "wrong identity," and both are, at heart, the same shape of
	// answer as scope denial: the grant that exists does not authorize
	// *this*. Choosing to fold them into SCOPE_DENIED rather than invent a
	// new code is this build's own judgment call, stated here rather than
	// left implicit — a caller in any of these cases gets the same
	// "do not retry; escalate" guidance the doc already prescribes for
	// SCOPE_DENIED, which is the right guidance for all three: retrying an
	// unfixed payload or an uncovered scope can't succeed.
	ScopeDenied Code = "SCOPE_DENIED"

	// Locked: custody backend needs a human unlock. Defined for taxonomy
	// completeness but NOT reachable in this build — stated, not enforced,
	// per AGENTS.md §8. This build's custody backend unseals once at
	// process boot (internal/broker/keyring's package doc, "Scope,
	// honestly stated") and brokerd fails to *start* if that fails, rather
	// than surfacing a runtime LOCKED response — there is no code path
	// today where a request arrives while the backend is mid-unlock. A
	// future interactive backend capable of re-locking mid-session (a
	// real password manager requiring biometric release per request, say)
	// would need this at the per-request layer; none exists yet.
	Locked Code = "LOCKED"

	// Contended: held by another session, includes retry_after. Defined
	// for taxonomy completeness but NOT reachable in this build — stated,
	// not enforced. This build's signing key is shared, in-memory, and
	// stateless to use (Sign is not exclusive-holder-shaped; concurrent
	// requests each derive their own signature from the same loaded key
	// with no serialization), so there is no "held elsewhere" state for a
	// request to collide with. A single-holder custody backend (a hardware
	// token that can only have one session open, say) would need this;
	// none exists yet.
	Contended Code = "CONTENDED"

	// BackendUnreachable: custody backend down. Reachable in exactly one
	// place in this build: the synchronous audit_log write that must
	// succeed before a computed signature is returned to the caller (see
	// broker.go's Sign) — "never blind-signs" extended to "never hands out
	// an unaudited signature." A cache load/refresh failure against an
	// unreachable database also surfaces here.
	BackendUnreachable Code = "BACKEND_UNREACHABLE"

	// RateLimited: anomaly tripwire fired. Reachable: internal/broker's
	// per-grant sliding-window sign-rate limiter, operationalizing
	// capability-broker.md's open question 5 ("TTL is the control, count
	// is an anomaly tripwire").
	RateLimited Code = "RATE_LIMITED"
)

// Result is brokerd's socket protocol response for both preflight and sign.
type Result struct {
	Code    Code   `json:"code"`
	Message string `json:"message,omitempty"`

	// ExpiresAt is set on an OK preflight response — capability-broker.md
	// requirement "introspectable before use": an agent can ask "do I have
	// authority, and for how long?"
	ExpiresAt *string `json:"expires_at,omitempty"`

	// Signature is set on an OK sign response: the armored SSHSIG text.
	Signature string `json:"signature,omitempty"`
}
