// Package api is the REST API behind the approval UI: reviewing/approving/
// rejecting staged diffs, and creating/listing/revoking grants. This is the human
// side of the consent model — nothing here is reachable from an MCP tool, and
// nothing in mcptools calls into this package.
//
// Every route requires a shared-secret bearer token (see requireAuth) — this is a
// deliberately minimal v0 answer, not a real multi-user auth system: there's one
// secret, checked on every request, standing in for "only the one trusted operator
// can reach this." A real system (per-reviewer identity, roles, audit trail of who
// approved what) is a genuine product decision this project hasn't made yet, and
// this doesn't presume to make it. What it does close is the gap review found: this
// package used to have literally no check on who could call approveStagedDiff — the
// one endpoint that turns a staged diff into a permanent fact (AGENTS.md §3.1) — so
// "no auth yet" was a real, not theoretical, hole. The server also binds
// 127.0.0.1 by default (internal/config) and CORS reflects one specific configured
// origin rather than a wildcard (see Routes/cors below) as defense in depth on top
// of the token, not instead of it.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
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

	// AuthToken gates every route via requireAuth. Required — New panics if it's
	// empty, the same "fail fast on missing required config" stance as
	// config.Load (AGENTS.md §6), applied here because an API server with an
	// empty/unset auth token is worse than one that refuses to start: it would
	// silently accept every request as authenticated.
	AuthToken string

	// RequestTimeout bounds how long a single request's context stays alive —
	// see withRequestTimeout. Required (New panics if <= 0): the zero value would
	// mean "no timeout," silently undoing the whole point of this field.
	RequestTimeout time.Duration
}

func New(st *store.Store, emb embed.Embedder, allowedOrigin, authToken string, requestTimeout time.Duration) *API {
	if authToken == "" {
		panic("api: AuthToken must not be empty — see the package comment")
	}
	if requestTimeout <= 0 {
		panic("api: RequestTimeout must be positive — a zero or negative value disables request cancellation entirely")
	}
	if err := validateAllowedOrigin(allowedOrigin); err != nil {
		panic("api: " + err.Error())
	}
	return &API{Store: st, Embedder: emb, AllowedOrigin: allowedOrigin, AuthToken: authToken, RequestTimeout: requestTimeout}
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
	return a.cors(a.requireAuth(a.limitBody(a.withRequestTimeout(mux))))
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

// requireAuth checks a shared-secret bearer token on every request. Constant-time
// comparison (crypto/subtle) so a timing side-channel can't help an attacker guess
// the token byte by byte — cheap to get right, so there's no reason not to.
func (a *API) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if len(auth) != len(prefix)+len(a.AuthToken) ||
			auth[:len(prefix)] != prefix ||
			subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(a.AuthToken)) != 1 {
			writeError(w, http.StatusUnauthorized, errUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var errUnauthorized = unauthorizedError{}

type unauthorizedError struct{}

func (unauthorizedError) Error() string { return "unauthorized" }

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
