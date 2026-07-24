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
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/store"
)

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
}

func New(st *store.Store, emb embed.Embedder, allowedOrigin, authToken string) *API {
	if authToken == "" {
		panic("api: AuthToken must not be empty — see the package comment")
	}
	return &API{Store: st, Embedder: emb, AllowedOrigin: allowedOrigin, AuthToken: authToken}
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
	mux.HandleFunc("GET /api/grants", a.listGrants)
	mux.HandleFunc("POST /api/grants", a.createGrant)
	mux.HandleFunc("POST /api/grants/{id}/revoke", a.revokeGrant)
	return a.cors(a.requireAuth(mux))
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
