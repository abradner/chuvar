// Package api is the REST API behind the approval UI: reviewing/approving/
// rejecting staged diffs, and creating/listing/revoking grants. This is the human
// side of the consent model — nothing here is reachable from an MCP tool, and
// nothing in mcptools calls into this package.
//
// No authentication yet — this is a known, deliberate gap for v0 local-dev use
// only (AGENTS.md doesn't have an answer for this yet either). Don't deploy this
// past localhost without addressing it first.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"memoryvault/internal/embed"
	"memoryvault/internal/store"
)

type API struct {
	Store    *store.Store
	Embedder embed.Embedder
}

func New(st *store.Store, emb embed.Embedder) *API {
	return &API{Store: st, Embedder: emb}
}

// Routes builds the mux. Uses Go's stdlib method+path routing (net/http as of
// 1.22) rather than a router framework — see AGENTS.md §6, not enough surface
// here to justify the dependency.
func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/staged-diffs", a.listStagedDiffs)
	mux.HandleFunc("POST /api/staged-diffs/{id}/approve", a.approveStagedDiff)
	mux.HandleFunc("POST /api/staged-diffs/{id}/reject", a.rejectStagedDiff)
	mux.HandleFunc("GET /api/grants", a.listGrants)
	mux.HandleFunc("POST /api/grants", a.createGrant)
	mux.HandleFunc("POST /api/grants/{id}/revoke", a.revokeGrant)
	return devCORS(mux)
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

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, errorResponse{Error: err.Error()})
}

// devCORS is a permissive CORS wrapper for local development, where the Bun/Vite
// frontend runs on a different port than this API. Not meant to survive contact
// with a real deployment target — see the package-level auth note; CORS policy is
// the same open question wearing a different hat.
func devCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
