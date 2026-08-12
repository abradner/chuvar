package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/abradner/chuvar/backend/internal/store"
)

// maxAgentTokenFieldLength bounds the free-text subject/label an operator
// gives a new agent-class token, matching maxTokenLabelLength's reasoning
// (tokens.go) — nothing legitimate needs anywhere near this many characters,
// this just keeps a malformed request from stuffing an oversized string into
// agent_tokens.
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

// listAgentTokens handles GET /api/agent-tokens. Bearer-only (any active
// reviewer token can list) — this is a read, and matches listTokens'
// "one trusted operator" stance for the reviewer surface. Never returns
// token_hash or plaintext.
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
	// this response, and never again. The server only ever persists its
	// hash (store.HashToken via CreateAgentToken); losing this value means
	// the token can only be revoked and replaced with a new one (rotation:
	// mint a fresh token with the same Subject), never recovered.
	Token string `json:"token"`
}

// createAgentToken handles POST /api/agent-tokens. Mints a new agent-class
// token — a credential structurally distinct from every reviewer token (its
// own table, its own hash namespace; see the agent_tokens migration's doc
// comment) that a later PR will hand to mcpserver in place of a raw database
// credential.
//
// Gated by requireStrongFactor UNCONDITIONALLY in Routes() — unlike
// createToken (tokens.go), there is NO bootstrap carve-out here. createToken
// needs one because the very first reviewer token on a fresh deployment has
// no enrolled factor to present yet, and without a carve-out the operator
// could never mint their first enrolled device. No equivalent bootstrap
// problem exists for agent tokens: minting one always happens from an
// already-authenticated, already-enrolled reviewer session — an operator
// who can reach this endpoint at all already holds a reviewer token capable
// of enrolling and proving a second factor. An agent-class token is pure
// standing authority with no ongoing human presence check of its own (it's
// a bearer credential handed to a long-running agent process), so the
// moment of minting it is the one point a human factor can be demanded —
// principles 4 ("humans approve; agents request") and 10 ("presence is
// precious... at grant time"). A confused or injected agent holding only
// the factorless bootstrap reviewer token must not be able to mint itself
// (or another agent) a standing credential.
func (a *API) createAgentToken(w http.ResponseWriter, r *http.Request) {
	var req createAgentTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request body: %w", err))
		return
	}
	// Trimmed before the empty/length checks, same reasoning as createToken's
	// label handling: a whitespace-only value is non-empty as typed but
	// meaningless as an identifier, and subject in particular becomes the
	// actor every grant/audit row this token's holder produces is attributed
	// to.
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

	// generateToken (tokens.go) — not reimplemented here: same 32-byte
	// crypto/rand, base64url-encoded plaintext shape as a reviewer token.
	// Structural distinctness comes from the table/hash namespace this
	// value is persisted into (agent_tokens, via CreateAgentToken), not
	// from the plaintext's own format.
	plaintext, err := generateToken()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "createAgentToken.generateToken", "could not create agent token", err)
		return
	}
	t, err := a.Store.CreateAgentToken(r.Context(), req.Subject, req.Label, plaintext)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "createAgentToken", "could not create agent token", err)
		return
	}
	writeJSON(w, http.StatusCreated, createAgentTokenResponse{agentTokenView: toAgentTokenView(t), Token: plaintext})
}

// revokeAgentToken handles POST /api/agent-tokens/{id}/revoke. Bearer-only
// (no requireStrongFactor), matching revokeToken's stance: revocation only
// ever reduces authority, so it doesn't need the same human-presence proof
// that minting does.
func (a *API) revokeAgentToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.Store.RevokeAgentToken(r.Context(), id); err != nil {
		writeStoreError(w, http.StatusConflict, "revokeAgentToken", "could not revoke agent token — it may not exist or already be revoked", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
