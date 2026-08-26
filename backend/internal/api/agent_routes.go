// agent_routes.go is the agent-facing HTTP surface: the network endpoint
// mcpserver calls instead of holding a raw database credential itself
// (AGENTS.md §3.0/§3.6, ticket E3 — the cutover landed in #82/#86 PR 4).
// Every route here authenticates via requireAgentAuth (agent_auth.go) — an
// agent-class token, store.AuthenticateAgentToken — and is served on its own
// listener (AgentRoutes(), bound by cmd/apiserver/main.go to
// CHUVAR_AGENT_ADDR), never mounted alongside Routes()'s reviewer surface.
// See agent_auth.go's doc comment for why that's two independent layers,
// not one.
//
// This file is the single, current home of the agent read/propose
// orchestration sequence — not a copy of it. agentSearch's body (below) is
// where the pre-embed scope gate, the server-side Embed call, the
// POST-embed re-check (the line that closes the revoke-during-embed race),
// SearchFacts, the per-fact projection, and the disclosure audit all
// actually run; internal/mcptools/read_with_scope_check.go
// (registerReadWithScopeCheck) is a thin adapter that marshals MCP tool
// arguments into an agentclient.SearchRequest, calls POST
// /api/agent/search, and maps the response back onto its own output shape —
// nothing security-relevant happens on that side of the wire. This is the
// single chokepoint CLAUDE.md principle 7 asks for: scope-before-rank stays
// atomic against a grant changing mid-request because the embed call and
// both scope checks run once, in this one handler, in this one process —
// splitting any piece of it out to the HTTP client (having the client
// embed, or having it pass down a pre-fetched scope snapshot) would reopen
// exactly that race and turn the gate into something advisory rather than
// enforced. Never use store.GetFact for this path: it is a single-ID,
// unscoped reviewer lookup (see its own doc comment), not a search endpoint,
// and calling it here would bypass every scope/depth check this file exists
// to enforce.
//
// The types and helpers below (agentFactView, agentSearchResponse,
// agentToScopes/agentFromScopes, agentGrantedScopeStrs, the size caps) do
// still exist as separate declarations from mcptools' own factView/
// readOutput/toScopes/fromScopes/grantedScopeStrs — see each type's doc
// comment for the field-for-field mirror. That is a wire-contract mirror
// (this package's JSON shape vs. the tool's own output shape), not the
// security-logic duplication this file used to carry pre-cutover: the two
// sets of types stay independently declared because internal/mcptools
// imports agentclient's wire types (not this package's unexported ones) and
// re-projects them onto its own MCP-facing output structs, but there is
// only one place — here — where a grant is actually checked or a fact is
// actually read from storage.
//
// The authenticated subject always comes from agentFromContext (the agent
// token), never from a request body field — none of the request structs
// below even have a Subject field, so there is nothing for a client to
// spoof; this mirrors how reviewer routes derive the actor from
// reviewerFromContext(...).Label rather than trusting anything the caller
// typed.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/abradner/chuvar/backend/internal/bouncer"
	"github.com/abradner/chuvar/backend/internal/scope"
	"github.com/abradner/chuvar/backend/internal/store"
)

// agentMaxScopesPerRequest, agentMaxQueryLength, agentMaxSearchLimit,
// agentMaxContentLength, and agentMaxJustificationLength mirror
// mcptools.maxScopesPerRequest/maxQueryLength/maxSearchLimit/
// maxContentLength/maxJustificationLength exactly (same values, same
// reasoning: a malformed or hostile request must not turn scope.Missing's
// comparison, an embedding call, a content insert, or a review-queue entry
// into a cheap resource-exhaustion lever) — prefixed agent* rather than
// imported because mcptools' constants are unexported, and because this
// package's own callers (createAgentToken etc.) already use unprefixed
// max* names for unrelated bounds.
const (
	agentMaxScopesPerRequest    = 50
	agentMaxQueryLength         = 1024
	agentMaxSearchLimit         = 200
	agentMaxContentLength       = 16384
	agentMaxJustificationLength = 2048
)

// AgentRoutes builds the mux served on the agent listener
// (cmd/apiserver/main.go's second http.Server, CHUVAR_AGENT_ADDR) — entirely
// separate from Routes()'s reviewer mux and its http.Server. Middleware
// order matches every gated mutation on the reviewer side: cors has to sit
// outermost (a CORS preflight carries no Authorization header, so it must be
// answered before auth runs — same reasoning as Routes()'s own comment),
// then requireAgentAuth, then limitBody, then withRequestTimeout innermost.
func (a *API) AgentRoutes() http.Handler {
	agentMux := http.NewServeMux()
	agentMux.HandleFunc("POST /api/agent/search", a.agentSearch)
	agentMux.HandleFunc("POST /api/agent/proposals", a.agentProposeWrite)
	agentMux.HandleFunc("GET /api/agent/grants", a.agentListGrants)
	agentMux.HandleFunc("POST /api/agent/grant-requests", a.agentRequestGrant)
	agentMux.HandleFunc("GET /api/agent/whoami", a.agentWhoami)

	return a.cors(a.requireAgentAuth(a.limitBody(a.withRequestTimeout(agentMux))))
}

// --- /api/agent/search ---------------------------------------------------

// agentFactProvenanceView mirrors mcptools.factProvenanceView field-for-field
// — see that type's doc comment for why "full" depth adds provenance rather
// than more content, and why Provenance being nil already means "not full
// depth" with no separate check needed here either.
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

// agentFactView mirrors mcptools.factView field-for-field — see that type's
// doc comment for the Content/Summary mutual exclusivity and why Provenance
// is only ever present at "full" depth.
type agentFactView struct {
	ID         string                   `json:"id"`
	Content    string                   `json:"content,omitempty"`
	Summary    string                   `json:"summary,omitempty"`
	Depth      string                   `json:"depth"`
	Scopes     []string                 `json:"scopes"`
	Provenance *agentFactProvenanceView `json:"provenance,omitempty"`
}

// agentSearchRequest is POST /api/agent/search's body. Deliberately has no
// Subject field — see the package doc comment.
type agentSearchRequest struct {
	Query           string   `json:"query"`
	RequestedScopes []string `json:"requested_scopes"`
	Limit           int      `json:"limit,omitempty"`
}

// agentSearchResponse mirrors mcptools.readOutput field-for-field, including
// its Status contract: "ok" or "insufficient_scope", both returned as
// 200 OK — insufficient_scope is an expected, structured outcome the agent
// is meant to act on (request the missing grant), not an HTTP error status.
type agentSearchResponse struct {
	Status        string          `json:"status"`
	Facts         []agentFactView `json:"facts,omitempty"`
	MissingScopes []string        `json:"missing_scopes,omitempty"`
}

// agentSearch handles POST /api/agent/search. See the package doc comment:
// this handler is the sole place the read/scope-check sequence runs — kept
// inside one handler so the pre-embed check, the server-side Embed call, and
// the post-embed re-check all happen atomically from the caller's
// perspective. mcptools.registerReadWithScopeCheck (the MCP tool client-side
// callers actually invoke) only ever reaches this sequence over HTTP via
// agentclient.Client.Search; do not let a future edit move any piece of it
// — the embedding call especially — to that client side, and do not
// refactor any piece of it out to a helper a client-side caller could also
// invoke without going through the HTTP boundary: either would reopen the
// race the second GrantedScopeDepths/scope.Missing pair below exists to
// close.
func (a *API) agentSearch(w http.ResponseWriter, r *http.Request) {
	subject := agentFromContext(r.Context()).Subject
	ctx := r.Context()

	var req agentSearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request body: %w", err))
		return
	}

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

	grantedDepths, err := a.Store.GrantedScopeDepths(ctx, subject)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not check grants", err)
		return
	}
	grantedStrs := agentGrantedScopeStrs(grantedDepths)

	if missing := scope.Missing(requested, agentToScopes(grantedStrs)); len(missing) > 0 {
		missingStrs := agentFromScopes(missing)
		if err := a.Store.LogAudit(ctx, "insufficient_scope", subject, nil, nil, nil, nil, missingStrs, nil); err != nil {
			writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not audit", err)
			return
		}
		writeJSON(w, http.StatusOK, agentSearchResponse{Status: "insufficient_scope", MissingScopes: missingStrs})
		return
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 20
	}

	var queryVec []float32
	if a.Embedder != nil {
		queryVec, err = a.Embedder.Embed(ctx, req.Query)
		if err != nil {
			writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not embed query", err)
			return
		}
	}

	// Re-fetch granted scope depths here rather than reusing the snapshot
	// from before Embed ran: a grant expiring, being revoked, or changing
	// depth while Embed is in flight would otherwise let SearchFacts run
	// against a stale, wider/deeper scope list than the subject currently
	// holds — content disclosed after revocation or a depth downgrade. This
	// closes the window between "embed" and "search"; see
	// read_with_scope_check.go's identical comment for the full reasoning
	// (including why full atomicity against a grant change would need a
	// larger restructure this narrow race doesn't justify). This re-check is
	// the single most important pair of lines in this file — do not remove
	// it or reorder it to before Embed.
	grantedDepths, err = a.Store.GrantedScopeDepths(ctx, subject)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not check grants", err)
		return
	}
	grantedStrs = agentGrantedScopeStrs(grantedDepths)
	if missing := scope.Missing(requested, agentToScopes(grantedStrs)); len(missing) > 0 {
		missingStrs := agentFromScopes(missing)
		if err := a.Store.LogAudit(ctx, "insufficient_scope", subject, nil, nil, nil, nil, missingStrs, nil); err != nil {
			writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not audit", err)
			return
		}
		writeJSON(w, http.StatusOK, agentSearchResponse{Status: "insufficient_scope", MissingScopes: missingStrs})
		return
	}

	facts, err := a.Store.SearchFacts(ctx, req.Query, queryVec, grantedDepths, limit)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not search facts", err)
		return
	}

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

	// Record what was actually disclosed (fact ID + the depth it was
	// disclosed at) — see store.ReadAuditDetail's doc comment and
	// read_with_scope_check.go's identical block for why this is a per-fact
	// list, not a single value for the whole call.
	detail := store.ReadAuditDetail{Facts: make([]store.ReadFactDisclosure, 0, len(out.Facts))}
	for _, f := range out.Facts {
		detail.Facts = append(detail.Facts, store.ReadFactDisclosure{FactID: f.ID, Depth: f.Depth})
	}
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not audit", err)
		return
	}
	if err := a.Store.LogAudit(ctx, "read", subject, nil, nil, nil, nil, grantedStrs, detailJSON); err != nil {
		writeStoreError(w, http.StatusInternalServerError, "agentSearch", "could not audit", err)
		return
	}

	writeJSON(w, http.StatusOK, out)
}

// agentGrantedScopeStrs mirrors mcptools.grantedScopeStrs — see that
// function's doc comment for why deduping matters (GrantedScopeDepths is
// DISTINCT on (scope, depth), so the same scope at two depths would
// otherwise duplicate in the audit log's recorded scopes list).
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

func agentFormatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339)
	return &s
}

// --- /api/agent/proposals --------------------------------------------------

// agentProposalRequest is POST /api/agent/proposals' body. Deliberately has
// no Subject field — see the package doc comment.
type agentProposalRequest struct {
	Content        string   `json:"content"`
	ProposedScopes []string `json:"proposed_scopes"`
	TargetFactID   string   `json:"target_fact_id,omitempty"`
}

// agentProposalResponse mirrors mcptools.proposeWriteOutput field-for-field
// — see that type's doc comment for the RATE_LIMITED status contract.
type agentProposalResponse struct {
	DiffID          string  `json:"diff_id"`
	Status          string  `json:"status"`
	DedupeVerdict   string  `json:"dedupe_verdict"`
	CandidateFactID *string `json:"candidate_fact_id,omitempty"`
}

// agentProposeWrite handles POST /api/agent/proposals, wrapping
// bouncer.ProposeWrite and preserving propose_write.go's exact three-way
// outcome: store.ErrRateLimited becomes an audited 429 with
// status=RATE_LIMITED (never a plain error — the caller is meant to back off
// and retry, same structured-outcome shape as insufficient_scope);
// bouncer.ValidationError (detected with errors.As, the same allowlist —
// not denylist — stance propose_write.go documents) becomes a 400 with the
// message verbatim, since it's the agent's own malformed input and safe to
// show; anything else is a masked 500 via writeStoreError, since it may
// carry raw store/driver text.
func (a *API) agentProposeWrite(w http.ResponseWriter, r *http.Request) {
	subject := agentFromContext(r.Context()).Subject
	ctx := r.Context()

	var req agentProposalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request body: %w", err))
		return
	}
	if len(req.ProposedScopes) > agentMaxScopesPerRequest {
		writeError(w, http.StatusBadRequest, fmt.Errorf("proposed_scopes exceeds max of %d", agentMaxScopesPerRequest))
		return
	}
	if len(req.Content) > agentMaxContentLength {
		writeError(w, http.StatusBadRequest, fmt.Errorf("content exceeds max length of %d", agentMaxContentLength))
		return
	}

	scopes := agentToScopes(req.ProposedScopes)
	var target *string
	if req.TargetFactID != "" {
		target = &req.TargetFactID
	}

	diff, disclosure, err := a.Bouncer.ProposeWrite(ctx, subject, req.Content, scopes, target)
	if err != nil {
		if errors.Is(err, store.ErrRateLimited) {
			// Audited before responding, same as insufficient_scope in
			// agentSearch and rate_limited in propose_write.go: a tripwire
			// that reports only to the adversary who tripped it is not a
			// tripwire. A failed audit write fails the response rather than
			// being dropped.
			if auditErr := a.Store.LogAudit(ctx, "rate_limited", subject, nil, nil, nil, nil, nil, nil); auditErr != nil {
				writeStoreError(w, http.StatusInternalServerError, "agentProposeWrite", "could not audit", auditErr)
				return
			}
			writeJSON(w, http.StatusTooManyRequests, agentProposalResponse{Status: "RATE_LIMITED"})
			return
		}
		var verr *bouncer.ValidationError
		if errors.As(err, &verr) {
			writeError(w, http.StatusBadRequest, verr)
			return
		}
		writeStoreError(w, http.StatusInternalServerError, "agentProposeWrite", "could not process proposal", err)
		return
	}

	// Built from disclosure, NOT diff.DedupeVerdict/diff.DedupeCandidateFactID:
	// those carry the true, unredacted dedupe result for the human reviewer
	// (the reviewer-facing staged-diff endpoints read diff's fields directly),
	// while disclosure is what store.ProposeDiff already redacted to this
	// agent's actual granted depth over the matched fact. This is the agent
	// surface's copy of the exact rule mcptools/propose_write.go follows —
	// using diff's fields here would reopen issue #83 through the agent API.
	out := agentProposalResponse{
		DiffID:          diff.ID,
		Status:          string(diff.Status),
		DedupeVerdict:   string(disclosure.Verdict),
		CandidateFactID: disclosure.CandidateFactID,
	}
	writeJSON(w, http.StatusOK, out)
}

// --- /api/agent/grants ------------------------------------------------------

// agentGrantView mirrors mcptools.grantView field-for-field.
type agentGrantView struct {
	ID        string   `json:"id"`
	Scopes    []string `json:"scopes"`
	Depth     string   `json:"depth"`
	Active    bool     `json:"active"`
	ExpiresAt *string  `json:"expires_at,omitempty"`
	RevokedAt *string  `json:"revoked_at,omitempty"`
}

// agentGrantsResponse mirrors mcptools.listGrantsOutput field-for-field.
type agentGrantsResponse struct {
	Grants []agentGrantView `json:"grants"`
}

// agentListGrants handles GET /api/agent/grants — the calling agent's OWN
// grants (via agentFromContext's subject), not the reviewer-facing
// cursor-paginated shape listGrants (grants.go) serves for an operator
// browsing any subject's grants.
func (a *API) agentListGrants(w http.ResponseWriter, r *http.Request) {
	subject := agentFromContext(r.Context()).Subject

	grants, err := a.Store.ListGrants(r.Context(), subject)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "agentListGrants", "could not list grants", err)
		return
	}

	now := time.Now()
	out := agentGrantsResponse{}
	for _, g := range grants {
		out.Grants = append(out.Grants, agentGrantView{
			ID:        g.ID,
			Scopes:    g.Scopes,
			Depth:     g.Depth,
			Active:    g.Active(now),
			ExpiresAt: agentFormatTimePtr(g.ExpiresAt),
			RevokedAt: agentFormatTimePtr(g.RevokedAt),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// --- /api/agent/grant-requests ----------------------------------------------

// agentGrantRequestRequest is POST /api/agent/grant-requests' body.
// Deliberately has no Subject field — see the package doc comment.
type agentGrantRequestRequest struct {
	RequestedScopes []string `json:"requested_scopes"`
	Depth           string   `json:"depth,omitempty"`
	TTLSeconds      int      `json:"ttl_seconds,omitempty"`
	Justification   string   `json:"justification,omitempty"`
}

// agentGrantRequestResponse mirrors mcptools.requestGrantOutput
// field-for-field.
type agentGrantRequestResponse struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

// agentRequestGrant handles POST /api/agent/grant-requests, reproducing
// request_grant.go's validation (including the negative-ttl_seconds
// rejection — see that file's doc comment for why an omitted ttl_seconds and
// an explicit negative one must not collapse to the same "no expiry"
// outcome) before staging the request. Like request_grant.go, this NEVER
// creates a real grant — store.RequestGrant only stages one for a human to
// approve or deny via the reviewer REST surface.
func (a *API) agentRequestGrant(w http.ResponseWriter, r *http.Request) {
	subject := agentFromContext(r.Context()).Subject
	ctx := r.Context()

	var req agentGrantRequestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request body: %w", err))
		return
	}
	if len(req.RequestedScopes) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("requested_scopes must not be empty"))
		return
	}
	if len(req.RequestedScopes) > agentMaxScopesPerRequest {
		writeError(w, http.StatusBadRequest, fmt.Errorf("requested_scopes exceeds max of %d", agentMaxScopesPerRequest))
		return
	}
	if len(req.Justification) > agentMaxJustificationLength {
		writeError(w, http.StatusBadRequest, fmt.Errorf("justification exceeds max length of %d", agentMaxJustificationLength))
		return
	}
	for _, sc := range req.RequestedScopes {
		if err := scope.Validate(scope.Scope(sc)); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	depth := req.Depth
	if depth == "" {
		depth = "facts"
	}
	if !store.ValidDepth(depth) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("depth must be one of summary, facts, full (got %q)", depth))
		return
	}

	// A negative ttl_seconds must be rejected explicitly rather than falling
	// through to "no expiry requested" the way an omitted one does — see
	// request_grant.go's identical check and doc comment (found in review
	// there; reproduced here for the same reason).
	if req.TTLSeconds < 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("ttl_seconds must be positive if provided (got %d)", req.TTLSeconds))
		return
	}
	var ttl *int
	if req.TTLSeconds > 0 {
		ttl = &req.TTLSeconds
	}

	gr, err := a.Store.RequestGrant(ctx, subject, req.RequestedScopes, string(store.GrantKindMemory), depth, ttl, req.Justification)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "agentRequestGrant", "could not create grant request", err)
		return
	}
	writeJSON(w, http.StatusOK, agentGrantRequestResponse{RequestID: gr.ID, Status: string(gr.Status)})
}

// --- /api/agent/whoami -------------------------------------------------------

type agentWhoamiResponse struct {
	Subject string `json:"subject"`
}

// agentWhoami handles GET /api/agent/whoami. A later PR uses this as
// mcpserver's boot health check (confirming its configured agent token
// authenticates and reporting which subject it resolves to) before it
// starts serving MCP tool calls.
func (a *API) agentWhoami(w http.ResponseWriter, r *http.Request) {
	subject := agentFromContext(r.Context()).Subject
	writeJSON(w, http.StatusOK, agentWhoamiResponse{Subject: subject})
}
