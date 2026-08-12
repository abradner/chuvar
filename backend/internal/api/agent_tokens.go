package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/abradner/chuvar/backend/internal/store"
)

// maxAgentTokenFieldLength bounds the free-text subject/label an operator
// gives a new agent-class token. Mirrors maxTokenLabelLength (tokens.go) —
// nothing about a real value needs anywhere near this many characters; exists
// so a malformed request can't stuff an oversized string into agent_tokens.
const maxAgentTokenFieldLength = 128

type agentTokenView struct {
	ID         string  `json:"id"`
	Subject    string  `json:"subject"`
	Label      string  `json:"label"`
	Active     bool    `json:"active"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at,omitempty"`
	RevokedAt  *string `json:"revoked_at,omitempty"`
}

func toAgentTokenView(t store.AgentToken) agentTokenView {
	v := agentTokenView{
		ID:        t.ID,
		Subject:   t.Subject,
		Label:     t.Label,
		Active:    t.RevokedAt == nil,
		CreatedAt: t.CreatedAt.Format(timeFormat),
	}
	if t.LastUsedAt != nil {
		s := t.LastUsedAt.Format(timeFormat)
		v.LastUsedAt = &s
	}
	if t.RevokedAt != nil {
		s := t.RevokedAt.Format(timeFormat)
		v.RevokedAt = &s
	}
	return v
}

// listAgentTokens handles GET /api/agent-tokens. Bearer-only: listing never
// returns a hash or plaintext, so there is no authority-widening act to gate
// behind a second factor — same stance as listTokens (tokens.go).
func (a *API) listAgentTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := a.Store.ListAgentTokens(r.Context())
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "listAgentTokens", "could not list agent tokens", err)
		return
	}
	views := make([]agentTokenView, len(tokens))
	for i, t := range tokens {
		views[i] = toAgentTokenView(t)
	}
	writeJSON(w, http.StatusOK, views)
}

type createAgentTokenRequest struct {
	Subject string `json:"subject"`
	Label   string `json:"label"`
}

type createAgentTokenResponse struct {
	agentTokenView
	// Token is the plaintext bearer credential — returned exactly once, in
	// this response, and never again. The server only ever persists its hash
	// (store.HashToken); losing this value means the token can only be
	// revoked and replaced with a new one, never recovered. Same discipline
	// as createTokenResponse.Token (tokens.go).
	Token string `json:"token"`
}

// createAgentToken handles POST /api/agent-tokens. Mints a new agent-class
// token — a credential structurally distinct from a reviewer token (its own
// table, its own hash space; see the agent_tokens migration) — for
// cmd/mcpserver to eventually hold in place of a raw database credential
// (ticket E3; this PR builds only the credential itself, mcpserver is
// unchanged).
//
// Gated by requireStrongFactor UNCONDITIONALLY, in Routes() (api.go) — unlike
// createToken (tokens.go), there is NO bootstrap carve-out here. createToken's
// conditional gate exists only because a reviewer device token's own first
// mint has to be reachable by the factorless bootstrap token before any real
// factor has ever been enrolled anywhere on the deployment; an agent-class
// token has no equivalent chicken-and-egg problem; minting one is always an
// act of extending standing authority to a new principal, never a one-time
// deployment bootstrap step, so it always demands a present human second
// factor (CLAUDE.md principles 4 and 10: "no agent-reachable path mints ...
// authority" and "require the human exactly once, at grant time"). Concretely:
// the factorless bootstrap reviewer token (cmd/apiserver's
// bootstrapReviewerToken) passes requireAuth but can never pass
// requireStrongFactor, so it cannot reach this handler at all — it can create
// its own replacement reviewer device but never an agent credential.
//
// The actor for any future audit trail this token's use produces is the
// authenticated reviewer's label (reviewerFromContext), never a request body
// field — subject/label here name the AGENT principal being credentialed,
// not who is doing the crediting.
func (a *API) createAgentToken(w http.ResponseWriter, r *http.Request) {
	var req createAgentTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request body: %w", err))
		return
	}
	// Trimmed before the empty/length checks, matching createToken's label
	// handling: a value of "   " is non-empty and under the length limit as
	// typed, but meaningless as an identifier.
	req.Subject = strings.TrimSpace(req.Subject)
	req.Label = strings.TrimSpace(req.Label)
	if req.Subject == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("subject is required"))
		return
	}
	if req.Label == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("label is required"))
		return
	}
	if len(req.Subject) > maxAgentTokenFieldLength {
		writeError(w, http.StatusBadRequest, fmt.Errorf("subject exceeds max length of %d", maxAgentTokenFieldLength))
		return
	}
	if len(req.Label) > maxAgentTokenFieldLength {
		writeError(w, http.StatusBadRequest, fmt.Errorf("label exceeds max length of %d", maxAgentTokenFieldLength))
		return
	}

	plaintext, err := generateToken()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "createAgentToken.generateToken", "could not create token", err)
		return
	}
	t, err := a.Store.CreateAgentToken(r.Context(), req.Subject, req.Label, plaintext)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "createAgentToken", "could not create token", err)
		return
	}
	writeJSON(w, http.StatusCreated, createAgentTokenResponse{agentTokenView: toAgentTokenView(t), Token: plaintext})
}

// revokeAgentToken handles POST /api/agent-tokens/{id}/revoke. Bearer-only
// (no requireStrongFactor) on the same stance as revokeToken: revocation only
// ever reduces authority, so it needs no second-factor gate.
func (a *API) revokeAgentToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.Store.RevokeAgentToken(r.Context(), id); err != nil {
		writeStoreError(w, http.StatusConflict, "revokeAgentToken", "could not revoke token — it may not exist or already be revoked", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
