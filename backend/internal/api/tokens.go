package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/abradner/chuvar/backend/internal/store"
)

// maxTokenLabelLength bounds the free-text label an operator gives a new device
// token (e.g. "alex-laptop"). Nothing about a real label needs anywhere near this
// many characters — exists so a malformed request can't stuff an oversized string
// into the reviewer_tokens table.
const maxTokenLabelLength = 128

type tokenView struct {
	ID         string  `json:"id"`
	Label      string  `json:"label"`
	Active     bool    `json:"active"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at,omitempty"`
	RevokedAt  *string `json:"revoked_at,omitempty"`
}

func toTokenView(t store.ReviewerToken) tokenView {
	v := tokenView{
		ID:        t.ID,
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

// listTokens handles GET /api/tokens. Any active token can list every token —
// see the package comment on this being "one trusted operator, multiple devices,"
// not a permissions model.
func (a *API) listTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := a.Store.ListReviewerTokens(r.Context())
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "listTokens", "could not list tokens", err)
		return
	}
	views := make([]tokenView, len(tokens))
	for i, t := range tokens {
		views[i] = toTokenView(t)
	}
	writeJSON(w, http.StatusOK, views)
}

type createTokenRequest struct {
	Label string `json:"label"`
}

type createTokenResponse struct {
	tokenView
	// Token is the plaintext bearer credential — returned exactly once, in this
	// response, and never again. The server only ever persists its hash (see
	// store.HashToken); losing this value means the token can only be revoked and
	// replaced with a new one, never recovered.
	Token string `json:"token"`
}

// generateToken produces a new random plaintext bearer credential: 32 bytes from
// crypto/rand, base64url-encoded (no padding, URL/header-safe as-is). 256 bits of
// entropy is comfortably enough that guessing is not a viable attack — the actual
// security property here is the same as any bearer-token scheme, unchanged from
// the shared secret this replaces.
func generateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("api: generating token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// createToken handles POST /api/tokens. Issues a new device/reviewer token —
// the plaintext is generated server-side (never client-supplied, so there's no
// way to request a weak or predictable token) and returned once in the response.
func (a *API) createToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request body: %w", err))
		return
	}
	if req.Label == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("label is required"))
		return
	}
	if len(req.Label) > maxTokenLabelLength {
		writeError(w, http.StatusBadRequest, fmt.Errorf("label exceeds max length of %d", maxTokenLabelLength))
		return
	}

	plaintext, err := generateToken()
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "createToken.generateToken", "could not create token", err)
		return
	}
	t, err := a.Store.CreateReviewerToken(r.Context(), req.Label, plaintext)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "createToken", "could not create token", err)
		return
	}
	writeJSON(w, http.StatusCreated, createTokenResponse{tokenView: toTokenView(t), Token: plaintext})
}

// revokeToken handles POST /api/tokens/{id}/revoke. A token can revoke itself or
// any other active token — deliberately unrestricted for the same "one operator,
// multiple devices, no role model yet" reason as every other route (package
// comment); the operator is expected not to hand device tokens to anyone else.
func (a *API) revokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.Store.RevokeReviewerToken(r.Context(), id); err != nil {
		writeStoreError(w, http.StatusConflict, "revokeToken", "could not revoke token — it may not exist or already be revoked", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
