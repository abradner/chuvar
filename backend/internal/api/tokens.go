package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/pquerna/otp/totp"

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
	// TOTPEnrollURI is an otpauth:// URI for scanning into an authenticator app —
	// same "shown exactly once" discipline as Token. This is the device-local
	// second factor requireTOTP checks on approval mutations; a token minted
	// without ever seeing this value can authenticate for reads but can never
	// pass that gate; see the reviewer_totp migration's doc comment for why.
	TOTPEnrollURI string `json:"totp_enroll_uri"`
}

// generateTOTPSecret mints a new device TOTP secret and its otpauth:// enrollment
// URI. label becomes the account name shown in the authenticator app, so the
// operator can tell devices apart the same way they already do by token label.
func generateTOTPSecret(label string) (secret, uri string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Chuvar", AccountName: label})
	if err != nil {
		return "", "", fmt.Errorf("api: generating totp secret: %w", err)
	}
	return key.Secret(), key.URL(), nil
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
// way to request a weak or predictable token) and returned once in the
// response, alongside a fresh TOTP enrollment URI.
//
// Gated by TOTP conditionally, not via requireTOTP's unconditional wrap like
// createGrant/approveGrantRequest/approveStagedDiff/renewGrant: once any
// device has ever been enrolled (CountEverEnrolledReviewerTokens > 0), a valid
// code is required from the caller, same as those routes. Below that — a fresh
// install, or a deployment still carrying only pre-TOTP-migration tokens — no
// code is required, because the bootstrap token this endpoint's first real
// call authenticates with (cmd/apiserver's bootstrapReviewerToken) is
// deliberately created with no TOTP secret of its own; an unconditional
// requireTOTP wrap would make it impossible to ever mint the operator's first
// enrolled device. Once that first device is enrolled the gate is permanently
// closed — including against the bootstrap token itself, which (having no
// secret) can never pass it again, correctly retiring it to break-glass
// status. Closes the gap where a stolen bearer token alone could mint a fresh
// token, read its otpauth:// URI from the response, and self-enroll,
// defeating every other requireTOTP gate. Found in review.
//
// The count deliberately includes revoked tokens. An active-only count made
// this gate re-openable by the very credential it defends against: revocation
// is bearer-only (it "only reduces authority" — revokeToken's doc comment), so
// a stolen bearer token could revoke every enrolled device, drop the count to
// zero, and self-enroll a replacement through the reopened gate. Counting
// ever-enrolled instead makes the signal monotonic — revoked rows are retained,
// never deleted, so nothing reachable over this API can lower it — which also
// restores revokeToken's "only reduces authority" property, since revocation
// no longer widens what any other endpoint permits. Found in review of the
// first version of this fix.
//
// The tradeoff: losing every enrolled device is not self-service recoverable
// over the API. Minting a replacement needs a code the operator no longer has,
// and REVIEWER_BOOTSTRAP_TOKEN can't help — a fresh bootstrap token still
// faces a nonzero ever-enrolled count. That is deliberate: an API-reachable
// recovery path is indistinguishable from the attack above. Recovery is a
// direct database action (clear totp_secret_enc on a token row, or delete the
// enrolled rows), which suits this deployment's single operator with DB
// access; see docs/operations.md.
func (a *API) createToken(w http.ResponseWriter, r *http.Request) {
	everEnrolled, err := a.Store.CountEverEnrolledReviewerTokens(r.Context())
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "createToken", "could not check enrollment status", err)
		return
	}
	if everEnrolled > 0 && !a.verifyTOTPCode(w, r) {
		return
	}

	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request body: %w", err))
		return
	}
	// Trimmed before the empty/length checks, not after: a label of "   " is
	// non-empty and under the length limit as typed, but it's meaningless as
	// an identifier and would still end up recorded as the actor in every
	// audit event this token's holder produces (decided_by/approved_by/
	// revoked_by, per this package's comment). Found in review.
	req.Label = strings.TrimSpace(req.Label)
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
	secret, enrollURI, err := generateTOTPSecret(req.Label)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "createToken.generateTOTPSecret", "could not create token", err)
		return
	}
	t, err := a.Store.CreateReviewerToken(r.Context(), req.Label, plaintext, secret)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "createToken", "could not create token", err)
		return
	}
	writeJSON(w, http.StatusCreated, createTokenResponse{tokenView: toTokenView(t), Token: plaintext, TOTPEnrollURI: enrollURI})
}

// revokeToken handles POST /api/tokens/{id}/revoke. A token can revoke itself or
// any other active token — deliberately unrestricted for the same "one operator,
// multiple devices, no role model yet" reason as every other route (package
// comment); the operator is expected not to hand device tokens to anyone else.
//
// Left bearer-only (no requireTOTP) on the stance that revocation only ever
// reduces authority. That stance is a real invariant, not just a convention:
// createToken's enrollment gate is keyed on a count this endpoint must not be
// able to lower, which is why that count includes revoked tokens. Before
// widening what revocation can do — hard-deleting rows, clearing totp_secret_enc,
// anything that shrinks the ever-enrolled population — re-check createToken's
// doc comment first; the two are coupled.
func (a *API) revokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.Store.RevokeReviewerToken(r.Context(), id); err != nil {
		writeStoreError(w, http.StatusConflict, "revokeToken", "could not revoke token — it may not exist or already be revoked", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
