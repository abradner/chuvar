// Package api is the REST API behind the approval UI: reviewing/approving/
// rejecting staged diffs, and creating/listing/revoking grants. This is the human
// side of the consent model — nothing here is reachable from an MCP tool, and
// nothing in mcptools calls into this package.
//
// Every route requires a named, individually-revocable reviewer/device token (see
// requireAuth and store.AuthenticateReviewerToken) — this replaces the original v0
// answer of a single shared secret. Every mutation's decided_by/approved_by/
// revoked_by is now derived from the authenticated token's label (reviewerFromContext),
// never read from the request body: a client-supplied identity field is exactly
// the "self-reported, not authenticated" gap flagged after v0 shipped (Notion tasks
// tracker), since nothing stopped one reviewer's browser session from attributing an
// approval to a different name. This still isn't real multi-user auth with roles —
// every active token can do everything any other active token can, matching "one
// trusted operator, multiple devices" rather than a permissions model — but who
// performed an action is now provably the token holder, not a string they typed.
// The server also binds 127.0.0.1 by default (internal/config) and CORS reflects
// one specific configured origin rather than a wildcard (see Routes/cors below) as
// defense in depth on top of token auth, not instead of it.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/store"
	"github.com/abradner/chuvar/backend/internal/summarize"
)

// maxRequestBodyBytes bounds every request body this API accepts. Every body here
// is a handful of JSON fields (a grant or decision request) — nothing legitimate
// approaches this. Without it, semantic limits (maxScopesPerGrant etc.) only run
// after json.Decoder has already read and allocated the entire body, so a fast
// authenticated request with an arbitrarily large body can still consume memory
// before any of those checks get a chance to reject it.
const maxRequestBodyBytes = 1 << 16 // 64KiB

type API struct {
	Store      *store.Store
	Embedder   embed.Embedder
	Summarizer summarize.Summarizer

	// AllowedOrigin is the single origin the CORS policy permits (e.g.
	// "http://localhost:5173" for the Vite dev server). Empty disables CORS
	// headers entirely rather than falling back to a wildcard.
	AllowedOrigin string

	// RequestTimeout bounds how long a single request's context stays alive —
	// see withRequestTimeout. Required (New panics if <= 0): the zero value would
	// mean "no timeout," silently undoing the whole point of this field.
	RequestTimeout time.Duration

	// WebAuthn holds the Relying Party configuration (RP ID, RP origins) that
	// every registration/assertion ceremony validates against — see webauthn.go.
	// Required (New panics if nil): a nil value would mean every ceremony
	// endpoint panics on first use instead of failing at boot, and RP ID/origin
	// validation is exactly the property that must never be silently absent
	// (AGENTS.md §6, "every network-facing default must be secure by default").
	WebAuthn *webauthn.WebAuthn
}

func New(st *store.Store, emb embed.Embedder, summ summarize.Summarizer, allowedOrigin string, requestTimeout time.Duration, wa *webauthn.WebAuthn) *API {
	if requestTimeout <= 0 {
		panic("api: RequestTimeout must be positive — a zero or negative value disables request cancellation entirely")
	}
	if err := validateAllowedOrigin(allowedOrigin); err != nil {
		panic("api: " + err.Error())
	}
	if wa == nil {
		panic("api: WebAuthn must not be nil — construct it with webauthn.New and the deployment's RP ID/origins")
	}
	return &API{Store: st, Embedder: emb, Summarizer: summ, AllowedOrigin: allowedOrigin, RequestTimeout: requestTimeout, WebAuthn: wa}
}

// validateAllowedOrigin rejects anything that isn't either empty (CORS disabled)
// or a single, concrete http(s) origin with no path. Found in review: this
// package's whole design intent is "never a wildcard" (see the package comment),
// but nothing actually enforced that — CORS_ALLOWED_ORIGIN=* would have been
// accepted verbatim and reflected back on every request. "null" is rejected too:
// browsers send the literal Origin: null header for sandboxed contexts (a
// sandboxed iframe, a file:// page), so accepting the string "null" as a
// configured origin is a known way to let exactly those untrusted contexts pass
// the check.
func validateAllowedOrigin(origin string) error {
	if origin == "" {
		return nil
	}
	if origin == "*" {
		return fmt.Errorf("CORS_ALLOWED_ORIGIN must not be a wildcard")
	}
	if origin == "null" {
		return fmt.Errorf("CORS_ALLOWED_ORIGIN must not be \"null\" (the sandboxed-origin value browsers send for untrusted contexts)")
	}
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid CORS_ALLOWED_ORIGIN %q: %w", origin, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("CORS_ALLOWED_ORIGIN %q must use http or https", origin)
	}
	if u.Host == "" {
		return fmt.Errorf("CORS_ALLOWED_ORIGIN %q must include a host", origin)
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("CORS_ALLOWED_ORIGIN %q must not include a path", origin)
	}
	return nil
}

// Routes builds the mux. Uses Go's stdlib method+path routing (net/http as of
// 1.22) rather than a router framework — see AGENTS.md §6, not enough surface
// here to justify the dependency. cors wraps requireAuth, not the other way
// around: a CORS preflight (OPTIONS) request never carries the Authorization
// header, so it has to be answered before auth is checked, not after.
func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/staged-diffs", a.listStagedDiffs)
	mux.HandleFunc("POST /api/staged-diffs/{id}/approve", a.requireStrongFactor(a.approveStagedDiff))
	mux.HandleFunc("POST /api/staged-diffs/{id}/reject", a.rejectStagedDiff)
	mux.HandleFunc("GET /api/facts/{id}", a.getFact)
	mux.HandleFunc("GET /api/grants", a.listGrants)
	mux.HandleFunc("POST /api/grants", a.requireStrongFactor(a.createGrant))
	mux.HandleFunc("POST /api/grants/{id}/revoke", a.revokeGrant)
	mux.HandleFunc("POST /api/grants/{id}/renew", a.requireStrongFactor(a.renewGrant))
	mux.HandleFunc("GET /api/grant-requests", a.listGrantRequests)
	mux.HandleFunc("POST /api/grant-requests/{id}/approve", a.requireStrongFactor(a.approveGrantRequest))
	mux.HandleFunc("POST /api/grant-requests/{id}/deny", a.denyGrantRequest)
	mux.HandleFunc("GET /api/tokens", a.listTokens)
	mux.HandleFunc("POST /api/tokens", a.createToken)
	mux.HandleFunc("POST /api/tokens/{id}/revoke", a.revokeToken)
	// WebAuthn (passkey) ceremonies — see webauthn.go's package-level doc
	// comment for the two-endpoint-per-ceremony shape and why the strong-
	// factor gate sits on *begin*, not finish.
	mux.HandleFunc("POST /api/webauthn/register/begin", a.requireExistingSecondFactor(a.webauthnRegisterBegin))
	mux.HandleFunc("POST /api/webauthn/register/finish", a.webauthnRegisterFinish)
	mux.HandleFunc("POST /api/webauthn/assert/begin", a.webauthnAssertBegin)
	mux.HandleFunc("GET /api/webauthn/credentials", a.listWebAuthnCredentials)
	mux.HandleFunc("POST /api/webauthn/credentials/{id}/revoke", a.revokeWebAuthnCredential)
	// {repo...} (not {repo}): a repo identifier like
	// "github.com/abradner/chuvar" contains slashes, so this wildcard-suffix
	// pattern is the only one of the two that can capture it whole — see
	// getSigningPolicy's doc comment. Registration order is irrelevant here:
	// Go 1.22+ ServeMux resolves overlapping patterns by specificity, not by
	// the order they were added, so a more specific fixed-segment route would
	// win over this wildcard regardless of which was registered first.
	mux.HandleFunc("GET /api/signing-policies/{repo...}", a.getSigningPolicy)
	mux.HandleFunc("POST /api/signing-policies", a.requireStrongFactor(a.upsertSigningPolicy))

	// /api/events (events.go) is mounted outside withRequestTimeout deliberately:
	// every other route is a quick request/response and benefits from a bounded
	// context, but streamEvents is meant to stay open indefinitely — wrapping it
	// in the same ~10s context would cancel the stream itself, not just bound a
	// slow store call. Its own doc comment covers the matching socket-level
	// WriteTimeout concern.
	top := http.NewServeMux()
	top.HandleFunc("GET /api/events", a.streamEvents)
	top.Handle("/", a.withRequestTimeout(mux))

	return a.cors(a.requireAuth(a.limitBody(top)))
}

// withRequestTimeout bounds the context every handler receives at a.RequestTimeout.
// This is distinct from (and doesn't replace) the http.Server socket-level
// Read/Write/IdleTimeout fields set in cmd/apiserver/main.go: those bound reading
// the request and writing the response, not how long a handler already in
// progress keeps running. Without this, a slow store/embedder call could keep
// mutating state well after those socket timeouts had already given up on the
// connection — e.g. committing an approval after the response write had timed
// out. Every handler in this package threads r.Context() through to its
// store/embedder calls already, so wrapping it here is enough to make them
// observe cancellation; found in review.
func (a *API) withRequestTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), a.RequestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// limitBody caps every request body at maxRequestBodyBytes before any handler (or
// json.Decoder) reads it.
func (a *API) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("api: encoding response", "error", err)
	}
}

type errorResponse struct {
	Error string `json:"error"`
}

// writeError reports a client-input problem. Only for messages this package
// constructed itself (e.g. "subject is required") — never pass a raw error from
// the store layer here, see writeStoreError.
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, errorResponse{Error: err.Error()})
}

// writeStoreError reports a failure that originated below this package (Postgres,
// the embedder, etc.). The real error is logged server-side; the client gets a
// generic message. Returning err.Error() verbatim here would put raw driver text —
// query fragments, column/constraint names — directly into an HTTP response body.
func writeStoreError(w http.ResponseWriter, status int, op, clientMessage string, err error) {
	slog.Error("api: internal error", "op", op, "error", err)
	writeJSON(w, status, errorResponse{Error: clientMessage})
}

// requireAuth authenticates the bearer token against store.AuthenticateReviewerToken
// and, on success, attaches the token's label to the request context via
// reviewerFromContext — every handler that mutates state (approve/reject a diff,
// create/revoke a grant, issue/revoke a token) reads the acting reviewer from there,
// never from the request body. See the package comment for why.
func (a *API) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) {
			writeError(w, http.StatusUnauthorized, errUnauthorized)
			return
		}
		reviewer, ok, err := a.Store.AuthenticateReviewerToken(r.Context(), strings.TrimPrefix(auth, prefix))
		if err != nil {
			writeStoreError(w, http.StatusInternalServerError, "requireAuth", "could not authenticate", err)
			return
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, errUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), reviewerContextKey{}, reviewer)))
	})
}

// requireStrongFactor gates a handler behind a device-local second factor —
// TOTP or WebAuthn, whichever the caller presents — on top of (never instead
// of) requireAuth. Applied only to mutations that grant or extend authority
// (approve grant request, direct grant create, approve staged diff, grant
// renewal) — the confused-deputy hole this closes is self-escalation, not
// denial/revocation, so those paths stay bearer-only. See the reviewer_totp
// migration's doc comment for why a second factor is needed at all: the
// bearer token alone is readable by anything with shell access to the
// reviewer's environment.
//
// Renamed from requireTOTP (2026-08-09, WebAuthn addition): TOTP keeps
// working unmodified — see verifyTOTPCode — and a WebAuthn assertion is now
// an equally-accepted alternative, never a downgrade of what this gate
// requires. Priority: X-Chuvar-WebAuthn-Assertion is checked first, so a
// request carrying both headers succeeds only if the (more phishing-
// resistant) assertion is itself valid, not merely the TOTP code.
func (a *API) requireStrongFactor(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.verifySecondFactor(w, r) {
			return
		}
		next(w, r)
	}
}

// verifySecondFactor checks whichever second factor the request presents —
// the WebAuthn assertion header when present, the TOTP code header otherwise
// — writing the appropriate error response and returning false on any
// failure. Factored out of requireStrongFactor so createToken (tokens.go)
// can apply the identical either-factor check conditionally rather than as
// an unconditional route wrapper; both factors must be accepted everywhere
// one is (the 2026-08-09 decision, docs/decisions.md), including there.
func (a *API) verifySecondFactor(w http.ResponseWriter, r *http.Request) bool {
	// TrimSpace before the emptiness check, matching verifyTOTPCode: a
	// whitespace-only assertion header (a stray space pasted alongside — or in
	// place of — a code) is non-empty as sent, so without trimming it forces
	// the WebAuthn branch and a caller presenting a perfectly valid TOTP code
	// gets a spurious 401 instead of having their code checked. The factor a
	// request presents is which header carries real content, not which one is
	// merely present. Found in review.
	if strings.TrimSpace(r.Header.Get(webauthnAssertionHeader)) != "" {
		return a.verifyWebAuthnAssertionHeader(w, r)
	}
	return a.verifyTOTPCode(w, r)
}

// requireExistingSecondFactor gates WebAuthn credential *registration*
// (webauthnRegisterBegin) — adding a passkey is itself a capability-widening
// act (the new credential passes requireStrongFactor forever after), so it
// must be proven by a second factor the calling reviewer token has already
// enrolled: a valid TOTP code, or an assertion of an already-enrolled
// passkey. A gate a stolen bearer token can pass equally well would not be a
// second factor at all (the same reasoning the reviewer_totp migration's doc
// comment gives for gating mutations, applied one step earlier: to gating
// the enrollment of the factor itself).
//
// A caller with NO enrolled factor of either kind is refused outright — 403,
// never a fall-through to bearer-only. There is deliberately no bootstrap
// carve-out here, per-token or deployment-wide, because none is needed:
// createToken enrolls a TOTP secret on every token it mints, so every
// legitimately-minted reviewer token already holds a factor to prove. The
// only tokens without one are the break-glass bootstrap token
// (cmd/apiserver's bootstrapReviewerToken, created with no secret precisely
// so requireStrongFactor-gated mutations stay unreachable on it) and tokens
// predating the reviewer_totp migration — exactly the credentials that must
// not be able to mint themselves a passkey. The first version of this gate
// fell through to bearer-only when the caller had no factor, "bootstrap
// parity with createToken"; that parity claim was false (createToken's
// carve-out closes permanently via a deployment-wide monotonic count, the
// per-token check never closes for a factorless token) and it let whoever
// held the bootstrap bearer token self-enroll a passkey and pass every
// strong-factor gate. Found in review.
//
// Which factor: the assertion header, when present, wins — same precedence
// as requireStrongFactor, and for the same reason. This also means a
// reviewer enrolled in both factors may prove either one; the two are
// equally sufficient at every other gate (the 2026-08-09 decision,
// docs/decisions.md), so demanding specifically TOTP here would be a
// stricter rule than the mutations this enrollment ultimately unlocks.
func (a *API) requireExistingSecondFactor(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reviewer := reviewerFromContext(r.Context())
		hasTOTP, err := a.Store.ReviewerHasTOTP(r.Context(), reviewer.ID)
		if err != nil {
			writeStoreError(w, http.StatusInternalServerError, "requireExistingSecondFactor", "could not check enrollment status", err)
			return
		}
		hasWebAuthn, err := a.Store.ReviewerHasActiveWebAuthnCredential(r.Context(), reviewer.ID)
		if err != nil {
			writeStoreError(w, http.StatusInternalServerError, "requireExistingSecondFactor", "could not check enrollment status", err)
			return
		}
		if !hasTOTP && !hasWebAuthn {
			// 403, not 401: no header this caller could send would change the
			// answer — the token itself has no factor to prove. The message
			// names the way out (principle: every denial says which kind of
			// no it is) without weakening anything: minting an enrolled token
			// is itself gated by createToken's ever-enrolled check.
			writeError(w, http.StatusForbidden, errNoEnrolledFactor)
			return
		}
		// TrimSpace before the emptiness check, same reason as verifySecondFactor:
		// a whitespace-only assertion header must not force the WebAuthn branch
		// and deny a caller who presented a valid TOTP code. Found in review.
		if strings.TrimSpace(r.Header.Get(webauthnAssertionHeader)) != "" {
			if !a.verifyWebAuthnAssertionHeader(w, r) {
				return
			}
			next(w, r)
			return
		}
		if hasTOTP {
			if !a.verifyTOTPCode(w, r) {
				return
			}
			next(w, r)
			return
		}
		// WebAuthn is the caller's only enrolled factor and no assertion was
		// presented. Reachable for real: the break-glass TOTP reset
		// (docs/operations.md) clears totp_secret_enc while passkeys may
		// remain enrolled.
		writeError(w, http.StatusUnauthorized, errWebAuthnRequired)
	}
}

// verifyTOTPCode checks the X-Chuvar-TOTP-Code header against the authenticated
// reviewer's enrolled secret, writing the appropriate error response and
// returning false on any failure. Factored out of requireStrongFactor so
// createToken (tokens.go) and requireExistingSecondFactor (webauthn
// enrollment gating) can each apply the same check conditionally rather than
// as an unconditional route wrapper — see createToken's own doc comment for why.
func (a *API) verifyTOTPCode(w http.ResponseWriter, r *http.Request) bool {
	// TrimSpace before the empty check, not after: a whitespace-only header
	// (e.g. an accidental space pasted alongside the code) is non-empty as
	// typed, so without this it reaches VerifyReviewerTOTP and comes back
	// "invalid" instead of the more accurate "required" — a confusing
	// distinction to debug from the caller's side for no real benefit. Found
	// in review.
	code := strings.TrimSpace(r.Header.Get("X-Chuvar-TOTP-Code"))
	if code == "" {
		writeError(w, http.StatusUnauthorized, errTOTPRequired)
		return false
	}
	reviewer := reviewerFromContext(r.Context())
	ok, err := a.Store.VerifyReviewerTOTP(r.Context(), reviewer.ID, code)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "verifyTOTPCode", "could not verify code", err)
		return false
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, errTOTPInvalid)
		return false
	}
	return true
}

var (
	errUnauthorized = unauthorizedError{}
	errTOTPRequired = totpError{"X-Chuvar-TOTP-Code header is required for this action"}
	errTOTPInvalid  = totpError{"invalid or expired TOTP code"}
	// errNoEnrolledFactor is requireExistingSecondFactor's refusal for a
	// token with no second factor of its own (the bootstrap token, or one
	// predating the reviewer_totp migration): registration is not reachable
	// for it at all, and the fix is a properly-minted token, not a different
	// header.
	errNoEnrolledFactor = totpError{"this reviewer token has no second factor enrolled, so it cannot enroll a passkey; " +
		"mint an enrolled device token (POST /api/tokens) and register the passkey from that device instead"}
)

type unauthorizedError struct{}

func (unauthorizedError) Error() string { return "unauthorized" }

type totpError struct{ msg string }

func (e totpError) Error() string { return e.msg }

// reviewerContextKey is an unexported type so this package's context value can
// never collide with a key set by another package — the standard Go idiom for
// context keys (see context.WithValue's doc comment).
type reviewerContextKey struct{}

// reviewerFromContext returns the authenticated reviewer's identity (token ID
// and label), set by requireAuth on every request that reaches a handler.
// Panics if called on a request that didn't go through requireAuth — every
// route in Routes() does, so this is a programmer error (a new route added
// outside the auth chain), not a runtime condition to handle gracefully.
func reviewerFromContext(ctx context.Context) store.AuthenticatedReviewer {
	reviewer, ok := ctx.Value(reviewerContextKey{}).(store.AuthenticatedReviewer)
	if !ok {
		panic("api: reviewerFromContext called on a request that bypassed requireAuth")
	}
	return reviewer
}

// cors applies a single, explicitly-configured allowed origin — never a wildcard.
// AllowedOrigin empty means no CORS headers are sent at all (browsers then enforce
// same-origin by default, which is the safe failure mode, not "allow everything").
func (a *API) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.AllowedOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", a.AllowedOrigin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			// X-Chuvar-TOTP-Code: without it here, a browser's CORS preflight
			// for any requireStrongFactor-gated mutation (createGrant, approve*,
			// renewGrant) rejects the real request client-side before it ever
			// reaches the server — the frontend's TOTP-gated actions would be
			// unreachable cross-origin. Found in review. X-Chuvar-WebAuthn-
			// Assertion is the same story for the WebAuthn alternative added
			// alongside it.
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Chuvar-TOTP-Code, "+webauthnAssertionHeader)
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
