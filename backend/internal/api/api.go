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

	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/store"
)

// maxRequestBodyBytes bounds every request body this API accepts. Every body here
// is a handful of JSON fields (a grant or decision request) — nothing legitimate
// approaches this. Without it, semantic limits (maxScopesPerGrant etc.) only run
// after json.Decoder has already read and allocated the entire body, so a fast
// authenticated request with an arbitrarily large body can still consume memory
// before any of those checks get a chance to reject it.
const maxRequestBodyBytes = 1 << 16 // 64KiB

type API struct {
	Store    *store.Store
	Embedder embed.Embedder

	// AllowedOrigin is the single origin the CORS policy permits (e.g.
	// "http://localhost:5173" for the Vite dev server). Empty disables CORS
	// headers entirely rather than falling back to a wildcard.
	AllowedOrigin string

	// RequestTimeout bounds how long a single request's context stays alive —
	// see withRequestTimeout. Required (New panics if <= 0): the zero value would
	// mean "no timeout," silently undoing the whole point of this field.
	RequestTimeout time.Duration
}

func New(st *store.Store, emb embed.Embedder, allowedOrigin string, requestTimeout time.Duration) *API {
	if requestTimeout <= 0 {
		panic("api: RequestTimeout must be positive — a zero or negative value disables request cancellation entirely")
	}
	if err := validateAllowedOrigin(allowedOrigin); err != nil {
		panic("api: " + err.Error())
	}
	return &API{Store: st, Embedder: emb, AllowedOrigin: allowedOrigin, RequestTimeout: requestTimeout}
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
	mux.HandleFunc("POST /api/staged-diffs/{id}/approve", a.approveStagedDiff)
	mux.HandleFunc("POST /api/staged-diffs/{id}/reject", a.rejectStagedDiff)
	mux.HandleFunc("GET /api/facts/{id}", a.getFact)
	mux.HandleFunc("GET /api/grants", a.listGrants)
	mux.HandleFunc("POST /api/grants", a.createGrant)
	mux.HandleFunc("POST /api/grants/{id}/revoke", a.revokeGrant)
	mux.HandleFunc("GET /api/grant-requests", a.listGrantRequests)
	mux.HandleFunc("POST /api/grant-requests/{id}/approve", a.approveGrantRequest)
	mux.HandleFunc("POST /api/grant-requests/{id}/deny", a.denyGrantRequest)
	mux.HandleFunc("GET /api/tokens", a.listTokens)
	mux.HandleFunc("POST /api/tokens", a.createToken)
	mux.HandleFunc("POST /api/tokens/{id}/revoke", a.revokeToken)

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
		label, ok, err := a.Store.AuthenticateReviewerToken(r.Context(), strings.TrimPrefix(auth, prefix))
		if err != nil {
			writeStoreError(w, http.StatusInternalServerError, "requireAuth", "could not authenticate", err)
			return
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, errUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), reviewerContextKey{}, label)))
	})
}

var errUnauthorized = unauthorizedError{}

type unauthorizedError struct{}

func (unauthorizedError) Error() string { return "unauthorized" }

// reviewerContextKey is an unexported type so this package's context value can
// never collide with a key set by another package — the standard Go idiom for
// context keys (see context.WithValue's doc comment).
type reviewerContextKey struct{}

// reviewerFromContext returns the authenticated reviewer's token label, set by
// requireAuth on every request that reaches a handler. Panics if called on a
// request that didn't go through requireAuth — every route in Routes() does, so
// this is a programmer error (a new route added outside the auth chain), not a
// runtime condition to handle gracefully.
func reviewerFromContext(ctx context.Context) string {
	label, ok := ctx.Value(reviewerContextKey{}).(string)
	if !ok {
		panic("api: reviewerFromContext called on a request that bypassed requireAuth")
	}
	return label
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
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
