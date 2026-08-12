package api

// agentPropose (POST /api/agent/proposals) is the HTTP twin of
// internal/mcptools/propose_write.go's propose_write tool — see
// agent_routes.go's package comment for why this is a deliberate, temporary
// duplicate. It preserves that tool's three-way outcome exactly:
//
//   - store.ErrRateLimited: audit "rate_limited", then HTTP 429 with
//     {status:"RATE_LIMITED"} (no diff_id) — a structured, expected outcome
//     the caller acts on (back off), not a masked failure.
//   - bouncer.ValidationError (detected with errors.As, not errors.Is — see
//     that type's own doc comment on why this is an allowlist, not a
//     denylist): 400 with the message verbatim. Safe because ValidationError
//     is only ever positively constructed from the caller's own malformed
//     input (an invalid scope, empty content), never wraps a store/driver
//     error.
//   - anything else: masked 500 — never leak internals (raw pgx/driver
//     text) into the response.
//
// This NEVER writes memory directly — b.ProposeWrite only ever stages a
// diff (AGENTS.md §3.1); only a human approval (the reviewer REST API)
// commits it.
import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/abradner/chuvar/backend/internal/bouncer"
	"github.com/abradner/chuvar/backend/internal/store"
)

// agentProposalRequest deliberately has NO subject field — see
// agentSearchRequest's identical doc comment.
type agentProposalRequest struct {
	Content        string   `json:"content"`
	ProposedScopes []string `json:"proposed_scopes"`
	TargetFactID   string   `json:"target_fact_id,omitempty"`
}

// agentProposalResponse mirrors mcptools.proposeWriteOutput.
type agentProposalResponse struct {
	DiffID          string  `json:"diff_id,omitempty"`
	Status          string  `json:"status"`
	DedupeVerdict   string  `json:"dedupe_verdict,omitempty"`
	CandidateFactID *string `json:"candidate_fact_id,omitempty"`
}

func (a *API) agentPropose(w http.ResponseWriter, r *http.Request) {
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

	diff, err := a.Bouncer.ProposeWrite(ctx, subject, req.Content, scopes, target)
	if err != nil {
		if errors.Is(err, store.ErrRateLimited) {
			// Audited before responding — same discipline as
			// insufficient_scope in agent_search.go: a tripwire that
			// reports only to the adversary who tripped it is not a
			// tripwire. A failed audit write fails the response rather
			// than being silently dropped.
			if auditErr := a.Bouncer.Store.LogAudit(ctx, "rate_limited", subject, nil, nil, nil, nil, nil, nil); auditErr != nil {
				writeStoreError(w, http.StatusInternalServerError, "agentPropose", "could not log audit event", auditErr)
				return
			}
			writeJSON(w, http.StatusTooManyRequests, agentProposalResponse{Status: "RATE_LIMITED"})
			return
		}
		// errors.As, not a type switch or errors.Is: only errors
		// bouncer.ProposeWrite positively constructed as *bouncer.ValidationError
		// are shown verbatim — everything else, including anything
		// unrecognized, stays masked. Fail closed: this is an allowlist,
		// not a denylist (mirrors mcptools.propose_write's identical
		// reasoning).
		var verr *bouncer.ValidationError
		if errors.As(err, &verr) {
			writeError(w, http.StatusBadRequest, verr)
			return
		}
		writeStoreError(w, http.StatusInternalServerError, "agentPropose", "could not stage proposal", err)
		return
	}

	out := agentProposalResponse{
		DiffID:          diff.ID,
		Status:          string(diff.Status),
		CandidateFactID: diff.DedupeCandidateFactID,
	}
	if diff.DedupeVerdict != nil {
		out.DedupeVerdict = string(*diff.DedupeVerdict)
	}
	writeJSON(w, http.StatusCreated, out)
}
