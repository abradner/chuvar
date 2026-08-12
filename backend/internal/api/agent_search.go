package api

// agentSearch (POST /api/agent/search) is the HTTP twin of
// internal/mcptools/read_with_scope_check.go's read_with_scope_check tool.
// It is the highest-risk handler in this package: a bug here is a silent
// scope bypass — an agent reading facts it was never granted. It reproduces
// that tool's sequence EXACTLY, inside this one handler:
//
//  1. input caps (requested_scopes/query/limit)
//  2. st.GrantedScopeDepths (pre-embed snapshot)
//  3. scope.Missing gate — on a miss: audit "insufficient_scope" and return
//     WITHOUT searching
//  4. emb.Embed, server-side — never accepted from the client
//  5. RE-FETCH GrantedScopeDepths and RE-CHECK scope.Missing — closes the
//     revoke-during-embed race (see the comment on that block below, which
//     is deliberately close to verbatim from the mcptools original: the
//     reasoning doesn't change just because the transport did)
//  6. st.SearchFacts — scope-before-rank is enforced in SQL inside
//     SearchFacts' candidate_facts CTE, and is NOT reimplemented here
//  7. project to the fact view (provenance only at full depth)
//  8. per-fact "read" disclosure audit, written before the response
//
// The whole sequence stays inside this one handler on purpose: if the HTTP
// client did the embedding, or checked scope itself, the race step 5 closes
// would reopen and the gate would become advisory rather than enforced.
// Never use store.GetFact here — it is a single-ID reviewer lookup with no
// scope filtering at all (see its own doc comment).
//
// This is a deliberate, temporary duplicate of the mcptools implementation
// (see agent_routes.go's package comment) — a later PR deletes mcptools'
// copy once mcpserver becomes a pure HTTP client of this endpoint. Do not
// import internal/mcptools from here, or vice versa; keep the two in
// lockstep by hand until that deletion PR lands.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/abradner/chuvar/backend/internal/scope"
	"github.com/abradner/chuvar/backend/internal/store"
)

// agentFactView mirrors mcptools.factView field-for-field — see that type's
// doc comment for why Content/Summary are mutually exclusive by Depth, and
// why Provenance is "full" depth's own addition rather than folded into
// "facts" (it discloses a human's identity, which content alone never does).
type agentFactView struct {
	ID         string                   `json:"id"`
	Content    string                   `json:"content,omitempty"`
	Summary    string                   `json:"summary,omitempty"`
	Depth      string                   `json:"depth"`
	Scopes     []string                 `json:"scopes"`
	Provenance *agentFactProvenanceView `json:"provenance,omitempty"`
}

// agentFactProvenanceView mirrors mcptools.factProvenanceView field-for-field.
type agentFactProvenanceView struct {
	SourceStagedDiffID string  `json:"source_staged_diff_id"`
	DecidedBy          *string `json:"decided_by,omitempty"`
	DecidedAt          *string `json:"decided_at,omitempty"`
	SupersededBy       *string `json:"superseded_by,omitempty"`
	CreatedAt          string  `json:"created_at"`
	ValidAt            string  `json:"valid_at"`
	InvalidAt          *string `json:"invalid_at,omitempty"`
	ExpiredAt          *string `json:"expired_at,omitempty"`
}

// agentSearchRequest deliberately has NO subject field — the authenticated
// subject always comes from the agent token (agentFromContext), never the
// request body. A body carrying one is silently ignored (there is nothing
// in this struct for json.Decoder to bind it to).
type agentSearchRequest struct {
	Query           string   `json:"query"`
	RequestedScopes []string `json:"requested_scopes"`
	Limit           int      `json:"limit,omitempty"`
}

// agentSearchResponse mirrors mcptools.readOutput: Status is "ok" or
// "insufficient_scope" — a structured, expected outcome the caller acts on
// (request the missing grant), not an HTTP error status.
type agentSearchResponse struct {
	Status        string          `json:"status"`
	Facts         []agentFactView `json:"facts,omitempty"`
	MissingScopes []string        `json:"missing_scopes,omitempty"`
}

func (a *API) agentSearch(w http.ResponseWriter, r *http.Request) {
	subject := agentFromContext(r.Context()).Subject
	ctx := r.Context()

	var req agentSearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request body: %w", err))
		return
	}

	// 1. Input caps — before any store call, so a malformed/hostile request
	// pays nothing for scope.Missing's O(requested×granted) comparison or an
	// unbounded query reaching the embedder/Postgres full-text search.
	if len(req.RequestedScopes) > agentMaxScopesPerRequest {
		writeError(w, http.StatusBadRequest, fmt.Errorf("requested_scopes exceeds max of %d", agentMaxScopesPerRequest))
		return
	}
	if len(req.Query) > agentMaxQueryLength {
		writeError(w, http.StatusBadRequest, fmt.Errorf("query exceeds max length of %d", agentMaxQueryLength))
		return
	}
	if req.Limit > agentMaxSearchLimit {
		writeError(w, http.StatusBadRequest, fmt.Errorf("limit exceeds max of %d", agentMaxSearchLimit))
		return
	}
	requested := agentToScopes(req.RequestedScopes)
	for _, sc := range requested {
		if err := scope.Validate(sc); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	// 2. Pre-embed granted-scope snapshot.
	grantedDepths, err := a.Store.GrantedScopeDepths(ctx, subject)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not check grants", err)
		return
	}
	grantedStrs := agentGrantedScopeStrs(grantedDepths)

	// 3. Scope gate: on a miss, audit and return WITHOUT searching.
	if missing := scope.Missing(requested, agentToScopes(grantedStrs)); len(missing) > 0 {
		missingStrs := agentFromScopes(missing)
		if err := a.Store.LogAudit(ctx, "insufficient_scope", subject, nil, nil, nil, nil, missingStrs, nil); err != nil {
			writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not log audit event", err)
			return
		}
		writeJSON(w, http.StatusOK, agentSearchResponse{Status: "insufficient_scope", MissingScopes: missingStrs})
		return
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 20
	}

	// 4. Server-side embedding. Never accept a client-supplied vector here —
	// that would let a caller control (or skip) the latency step 5's
	// re-check exists to close a window around, or bypass the check
	// entirely by claiming an embedding was already computed.
	var queryVec []float32
	if a.Embedder != nil {
		queryVec, err = a.Embedder.Embed(ctx, req.Query)
		if err != nil {
			writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not embed query", err)
			return
		}
	}

	// 5. THE re-check — the single most important block in this file.
	//
	// Re-fetch granted scope depths here rather than reusing the snapshot
	// from before Embed ran: a grant expiring, being revoked, or changing
	// depth while Embed is in flight would otherwise let SearchFacts run
	// against a stale, wider/deeper scope list than the subject currently
	// holds — content disclosed after revocation or a depth downgrade.
	// Embed is synchronous/instant against the v0 Stub embedder, so this
	// window is nil today, but the real embedder this is meant to be
	// swapped for (Research track) is an external, non-trivial-latency
	// call, which is exactly when this race becomes real. This closes the
	// window between "embed" and "search"; it doesn't make the whole
	// request atomic against a grant change — full atomicity would mean
	// pushing grant membership into the retrieval SQL itself (keyed by
	// subject, joined at query time), a larger restructure of SearchFacts'
	// signature and every caller, not justified for a race this narrow
	// today. (Reproduced from mcptools/read_with_scope_check.go verbatim —
	// see that file's identical comment; the reasoning is transport-
	// independent, so the words shouldn't drift even though the code
	// housing them does.)
	grantedDepths, err = a.Store.GrantedScopeDepths(ctx, subject)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not check grants", err)
		return
	}
	grantedStrs = agentGrantedScopeStrs(grantedDepths)
	if missing := scope.Missing(requested, agentToScopes(grantedStrs)); len(missing) > 0 {
		missingStrs := agentFromScopes(missing)
		if err := a.Store.LogAudit(ctx, "insufficient_scope", subject, nil, nil, nil, nil, missingStrs, nil); err != nil {
			writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not log audit event", err)
			return
		}
		writeJSON(w, http.StatusOK, agentSearchResponse{Status: "insufficient_scope", MissingScopes: missingStrs})
		return
	}

	// 6. Scope-before-rank is enforced in SQL inside SearchFacts' own
	// candidate_facts CTE, so it travels with SearchFacts regardless of
	// caller — not reimplemented here. An empty granted list returns no
	// results (SearchFacts' own doc comment): no grant means no access, not
	// "search everything and filter later."
	facts, err := a.Store.SearchFacts(ctx, req.Query, queryVec, grantedDepths, limit)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not search facts", err)
		return
	}

	// 7. Project to the fact view.
	out := agentSearchResponse{Status: "ok"}
	for _, f := range facts {
		fv := agentFactView{ID: f.ID, Content: f.Content, Summary: f.Summary, Depth: f.Depth, Scopes: f.Scopes}
		if f.Provenance != nil {
			p := f.Provenance
			fv.Provenance = &agentFactProvenanceView{
				SourceStagedDiffID: p.SourceStagedDiffID,
				DecidedBy:          p.DecidedBy,
				DecidedAt:          agentFormatTimePtr(p.DecidedAt),
				SupersededBy:       p.SupersededBy,
				CreatedAt:          f.CreatedAt.Format(time.RFC3339),
				ValidAt:            f.ValidAt.Format(time.RFC3339),
				InvalidAt:          agentFormatTimePtr(p.InvalidAt),
				ExpiredAt:          agentFormatTimePtr(p.ExpiredAt),
			}
		}
		out.Facts = append(out.Facts, fv)
	}

	// 8. Disclosure audit: what was actually disclosed and at what depth,
	// per fact — not just which scopes the subject held. Written BEFORE the
	// response so a client that never sees the response (a dropped
	// connection) still leaves an audit trail of what the server actually
	// returned.
	detail := store.ReadAuditDetail{Facts: make([]store.ReadFactDisclosure, 0, len(out.Facts))}
	for _, f := range out.Facts {
		detail.Facts = append(detail.Facts, store.ReadFactDisclosure{FactID: f.ID, Depth: f.Depth})
	}
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not record audit detail", err)
		return
	}
	if err := a.Store.LogAudit(ctx, "read", subject, nil, nil, nil, nil, grantedStrs, detailJSON); err != nil {
		writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not log audit event", err)
		return
	}

	writeJSON(w, http.StatusOK, out)
}

// agentGrantedScopeStrs discards the depth half of each pair and dedupes —
// mirrors mcptools.grantedScopeStrs exactly, including its doc comment's
// reasoning: GrantedScopeDepths is DISTINCT on (scope, depth), not scope
// alone, so a subject holding two active grants over the same scope at
// different depths produces two rows with an identical Scope, which would
// otherwise duplicate that scope in the audit log's recorded scopes list.
func agentGrantedScopeStrs(granted []store.GrantedScope) []string {
	seen := make(map[string]struct{}, len(granted))
	out := make([]string, 0, len(granted))
	for _, g := range granted {
		if _, ok := seen[g.Scope]; ok {
			continue
		}
		seen[g.Scope] = struct{}{}
		out = append(out, g.Scope)
	}
	return out
}

func agentToScopes(ss []string) []scope.Scope {
	out := make([]scope.Scope, len(ss))
	for i, s := range ss {
		out[i] = scope.Scope(s)
	}
	return out
}

func agentFromScopes(ss []scope.Scope) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = string(s)
	}
	return out
}

// agentFormatTimePtr mirrors mcptools.formatTimePtr.
func agentFormatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339)
	return &s
}
