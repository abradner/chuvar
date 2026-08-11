// Passkey (WebAuthn) reviewer authentication — additive alongside TOTP
// (decided 2026-08-09, docs/decisions.md; see the webauthn_credentials
// migration's doc comment for the full rationale). Two ceremonies, each
// split into a begin/finish pair the way the WebAuthn browser API itself is
// two calls (navigator.credentials.create()/.get()):
//
//   - Registration (enrollment): POST /api/webauthn/register/begin, gated by
//     requireExistingSecondFactor — adding a factor must never be reachable
//     with strictly less proof than the reviewer's existing factors already
//     demand, or "add a passkey" becomes a downgrade path around TOTP.
//     POST /api/webauthn/register/finish is NOT re-gated: the single-use
//     challenge row only register/begin's gate could have created is the
//     proof finish consumes (see that handler's own doc comment on the
//     deletion test).
//   - Assertion: POST /api/webauthn/assert/begin (requireAuth only — you need
//     a challenge before you can prove anything against it) hands back a
//     CredentialAssertion; the resulting signed response travels in the
//     X-Chuvar-WebAuthn-Assertion header on the actual gated mutation
//     (createGrant, approveGrantRequest, approveStagedDiff, renewGrant — see
//     requireStrongFactor in api.go), verified and single-use-consumed inline
//     there, exactly where X-Chuvar-TOTP-Code is checked today.
//
// Every ceremony is scoped to the authenticated reviewer token
// (reviewerFromContext) end to end: the challenge is stored keyed by that
// reviewer's ID, and the credential set offered to go-webauthn at both begin
// and finish is that reviewer's own (store.ActiveWebAuthnCredentialsForReviewer)
// — a signature over one reviewer's credential can never satisfy another
// reviewer's gate, because the "user" go-webauthn validates against is never
// built from anything wider than the caller's own authenticated identity.
package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/abradner/chuvar/backend/internal/store"
)

// webauthnAssertionHeader carries a base64-encoded JSON WebAuthn assertion
// response (the browser's navigator.credentials.get() result, unmodified) —
// the WebAuthn analogue of X-Chuvar-TOTP-Code. The base64 layer keeps the
// whole blob a single opaque header token rather than raising a "does this
// JSON need header-value quoting" question; RFC 7230 restricts header field
// values to visible ASCII, and base64 is the standard way to satisfy that
// for an arbitrary byte/JSON payload.
const webauthnAssertionHeader = "X-Chuvar-WebAuthn-Assertion"

// webauthnChallengeTTL bounds how long a registration or assertion challenge
// stays consumable — short-lived per the design spec. Five minutes covers a
// human noticing and completing a platform-authenticator prompt (including a
// biometric retry) without leaving a long-lived nonce sitting in the database.
const webauthnChallengeTTL = 5 * time.Minute

var (
	errWebAuthnRequired  = webauthnError{fmt.Sprintf("%s header is required for this action", webauthnAssertionHeader)}
	errWebAuthnChallenge = webauthnError{"no pending WebAuthn challenge for this reviewer, or it expired — call the begin endpoint again"}
	errWebAuthnClone     = webauthnError{"this passkey's signature counter went backwards, which this server treats as a possible cloned authenticator; the credential has been revoked — enroll a new one"}
)

type webauthnError struct{ msg string }

func (e webauthnError) Error() string { return e.msg }

// webauthnUser adapts one reviewer token's enrolled credentials to
// webauthn.User for a single ceremony. Built fresh per request from the
// authenticated reviewer's own store rows — never from anything the request
// body supplies — so the credential set go-webauthn validates against can
// never be widened by a caller.
type webauthnUser struct {
	id          string
	label       string
	credentials []webauthn.Credential
	// byCredentialID maps a raw WebAuthn credential ID (as go-webauthn hands
	// it back after a successful ceremony) to this reviewer's store row for
	// it — the only way verifyWebAuthnAssertionHeader can turn "which
	// credential just asserted" back into "which database row to update the
	// counter on", since the library's own Credential type carries no
	// concept of our row ID.
	byCredentialID map[string]store.WebAuthnCredential
}

func (u webauthnUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u webauthnUser) WebAuthnName() string                       { return u.label }
func (u webauthnUser) WebAuthnDisplayName() string                { return u.label }
func (u webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func toLibraryCredential(c store.WebAuthnCredential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, len(c.Transports))
	for i, t := range c.Transports {
		transports[i] = protocol.AuthenticatorTransport(t)
	}
	return webauthn.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
		Flags: webauthn.CredentialFlags{
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    c.AAGUID,
			SignCount: c.SignCount,
		},
	}
}

// loadWebAuthnUser fetches reviewer's active credentials and adapts them for
// a ceremony. Active only (never revoked ones): a revoked credential must
// neither be offered as something a fresh registration should exclude nor as
// something an assertion could still satisfy.
func (a *API) loadWebAuthnUser(r *http.Request, reviewer store.AuthenticatedReviewer) (webauthnUser, error) {
	creds, err := a.Store.ActiveWebAuthnCredentialsForReviewer(r.Context(), reviewer.ID)
	if err != nil {
		return webauthnUser{}, err
	}
	u := webauthnUser{
		id:             reviewer.ID,
		label:          reviewer.Label,
		credentials:    make([]webauthn.Credential, len(creds)),
		byCredentialID: make(map[string]store.WebAuthnCredential, len(creds)),
	}
	for i, c := range creds {
		u.credentials[i] = toLibraryCredential(c)
		u.byCredentialID[string(c.CredentialID)] = c
	}
	return u, nil
}

// putWebAuthnSession JSON-encodes go-webauthn's own SessionData and stores it
// as the single pending challenge for this reviewer/purpose — see
// store.PutWebAuthnChallenge's doc comment for the single-use/short-expiry
// guarantee this relies on.
func (a *API) putWebAuthnSession(r *http.Request, reviewerID, purpose string, session *webauthn.SessionData) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("api: marshal webauthn session: %w", err)
	}
	return a.Store.PutWebAuthnChallenge(r.Context(), reviewerID, purpose, data, time.Now().Add(webauthnChallengeTTL))
}

// webauthnRegisterBegin handles POST /api/webauthn/register/begin. Gated by
// requireExistingSecondFactor (Routes) — see that function and this
// file's package doc comment for why enrollment itself needs a factor gate.
func (a *API) webauthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	reviewer := reviewerFromContext(r.Context())
	user, err := a.loadWebAuthnUser(r, reviewer)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "webauthnRegisterBegin", "could not load enrolled credentials", err)
		return
	}

	exclude := make([]protocol.CredentialDescriptor, len(user.credentials))
	for i, c := range user.credentials {
		exclude[i] = c.Descriptor()
	}

	creation, session, err := a.WebAuthn.BeginRegistration(user, webauthn.WithExclusions(exclude))
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "webauthnRegisterBegin", "could not start registration", err)
		return
	}
	if err := a.putWebAuthnSession(r, reviewer.ID, store.WebAuthnPurposeRegistration, session); err != nil {
		writeStoreError(w, http.StatusInternalServerError, "webauthnRegisterBegin", "could not save registration challenge", err)
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

// registerFinishRequest lets the same JSON body the browser's
// navigator.credentials.create() response is decoded from also carry a
// caller-chosen label — protocol.ParseCredentialCreationResponseBytes
// ignores fields it doesn't recognize (standard encoding/json behaviour), so
// this is a second, narrow decode of the identical bytes rather than a
// competing body schema.
type registerFinishRequest struct {
	Label string `json:"label"`
}

// webauthnRegisterFinish handles POST /api/webauthn/register/finish.
// Deliberately NOT wrapped in requireExistingSecondFactor again: that
// gate already ran at register/begin (Routes), and its output — a single-use
// challenge row keyed to this reviewer, which only a caller who passed that
// gate could have caused to exist — is exactly the proof this handler
// consumes via ConsumeWebAuthnChallenge. Re-checking the factor here would be
// a second lock whose only key is the first lock's own output: decoration,
// not enforcement, and fails the deletion test (AGENTS.md §6) — removing it
// would change nothing about what's possible, only add a redundant TOTP/
// assertion prompt mid-ceremony.
func (a *API) webauthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	reviewer := reviewerFromContext(r.Context())

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("reading request body: %w", err))
		return
	}

	sessionData, ok, err := a.Store.ConsumeWebAuthnChallenge(r.Context(), reviewer.ID, store.WebAuthnPurposeRegistration)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "webauthnRegisterFinish", "could not verify registration challenge", err)
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, errWebAuthnChallenge)
		return
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(sessionData, &session); err != nil {
		writeStoreError(w, http.StatusInternalServerError, "webauthnRegisterFinish", "could not read registration challenge", err)
		return
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid registration response: %w", err))
		return
	}

	user, err := a.loadWebAuthnUser(r, reviewer)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "webauthnRegisterFinish", "could not load enrolled credentials", err)
		return
	}

	cred, err := a.WebAuthn.CreateCredential(user, session, parsed)
	if err != nil {
		// A registration ceremony failure (bad RP ID/origin, challenge
		// mismatch, malformed attestation) is the caller's ceremony being
		// wrong, not a server fault — 400, not 500. The underlying error text
		// comes from the protocol package, not raw driver output, so
		// returning it (unlike writeStoreError's stance) doesn't leak
		// anything the operator debugging their own browser doesn't already
		// see in devtools.
		writeError(w, http.StatusBadRequest, fmt.Errorf("registration failed: %w", err))
		return
	}

	var reqBody registerFinishRequest
	_ = json.Unmarshal(body, &reqBody) // best-effort: an absent/malformed label just falls back below.
	label := strings.TrimSpace(reqBody.Label)
	if label == "" {
		label = "passkey"
	}
	if len(label) > maxTokenLabelLength {
		writeError(w, http.StatusBadRequest, fmt.Errorf("label exceeds max length of %d", maxTokenLabelLength))
		return
	}

	transports := make([]string, len(cred.Transport))
	for i, t := range cred.Transport {
		transports[i] = string(t)
	}

	// actor (reviewer.Label) makes the enrollment audit row atomic with the
	// credential insert and the latch set — all three commit or roll back as
	// one transaction inside CreateWebAuthnCredential now, closing the P1
	// finding that a LogAudit failure after this call used to leave a live,
	// unaudited passkey with the endpoint returning 500 (a retry could then
	// only 409 on the unique credential_id constraint). See that method's doc
	// comment.
	stored, err := a.Store.CreateWebAuthnCredential(r.Context(), reviewer.ID, label,
		cred.ID, cred.PublicKey, cred.AttestationType, transports, cred.Authenticator.AAGUID,
		cred.Authenticator.SignCount, cred.Flags.BackupEligible, cred.Flags.BackupState, reviewer.Label)
	if err != nil {
		if errors.Is(err, store.ErrWebAuthnCredentialAlreadyRegistered) {
			writeError(w, http.StatusConflict, err)
			return
		}
		writeStoreError(w, http.StatusInternalServerError, "webauthnRegisterFinish", "could not save credential", err)
		return
	}

	writeJSON(w, http.StatusCreated, toWebAuthnCredentialView(stored))
}

// webauthnAssertBegin handles POST /api/webauthn/assert/begin. Bearer-auth
// only (no strong-factor gate): obtaining a challenge proves nothing by
// itself, and the request that eventually presents the resulting signed
// assertion is checked at the mutation it's gating (requireStrongFactor).
func (a *API) webauthnAssertBegin(w http.ResponseWriter, r *http.Request) {
	reviewer := reviewerFromContext(r.Context())
	user, err := a.loadWebAuthnUser(r, reviewer)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "webauthnAssertBegin", "could not load enrolled credentials", err)
		return
	}
	if len(user.credentials) == 0 {
		writeError(w, http.StatusConflict, fmt.Errorf("no passkey enrolled for this reviewer token"))
		return
	}

	assertion, session, err := a.WebAuthn.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "webauthnAssertBegin", "could not start assertion", err)
		return
	}
	if err := a.putWebAuthnSession(r, reviewer.ID, store.WebAuthnPurposeAssertion, session); err != nil {
		writeStoreError(w, http.StatusInternalServerError, "webauthnAssertBegin", "could not save assertion challenge", err)
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

// verifyWebAuthnAssertionHeader is requireStrongFactor's/
// requireExistingSecondFactor's WebAuthn branch: consumes the single-use
// assertion challenge, validates the signed response against this reviewer's
// own credentials, persists the new sign counter, and audits the use. Every
// failure mode writes its own response and returns false; success returns
// true having already logged the "webauthn_assertion_used" audit row, so
// callers need no further bookkeeping.
func (a *API) verifyWebAuthnAssertionHeader(w http.ResponseWriter, r *http.Request) bool {
	reviewer := reviewerFromContext(r.Context())

	raw := strings.TrimSpace(r.Header.Get(webauthnAssertionHeader))
	if raw == "" {
		writeError(w, http.StatusUnauthorized, errWebAuthnRequired)
		return false
	}
	body, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("%s header is not valid base64: %w", webauthnAssertionHeader, err))
		return false
	}

	sessionData, ok, err := a.Store.ConsumeWebAuthnChallenge(r.Context(), reviewer.ID, store.WebAuthnPurposeAssertion)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "verifyWebAuthnAssertionHeader", "could not verify assertion challenge", err)
		return false
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, errWebAuthnChallenge)
		return false
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(sessionData, &session); err != nil {
		writeStoreError(w, http.StatusInternalServerError, "verifyWebAuthnAssertionHeader", "could not read assertion challenge", err)
		return false
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid webauthn assertion: %w", err))
		return false
	}

	user, err := a.loadWebAuthnUser(r, reviewer)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "verifyWebAuthnAssertionHeader", "could not load enrolled credentials", err)
		return false
	}

	cred, err := a.WebAuthn.ValidateLogin(user, session, parsed)
	if err != nil {
		// Scoping user to this reviewer's own active credentials (loadWebAuthnUser)
		// is what makes this the actor-identity check, not just a signature
		// check: ValidateLogin can only succeed against a credential this
		// specific reviewer token owns (protocol.Verify's Step 3 search over
		// user.WebAuthnCredentials()), so a valid signature over a different
		// reviewer's passkey fails here too.
		//
		// The client-facing message is deliberately generic — same "don't
		// distinguish the reason a factor failed" stance as
		// verifyTOTPCode's errTOTPInvalid. go-webauthn's error text
		// (origin/challenge mismatch vs. bad signature vs. unknown
		// credential ID) is exactly the kind of detail that helps an
		// attacker iterating on a forged assertion learn which part to fix
		// next; the full error still reaches the server log via
		// writeStoreError for real debugging. Found in review.
		writeStoreError(w, http.StatusUnauthorized, "verifyWebAuthnAssertionHeader", "invalid or expired webauthn assertion", err)
		return false
	}

	stored, known := user.byCredentialID[string(cred.ID)]
	if !known {
		// Can't happen given the above (ValidateLogin only returns a
		// credential drawn from user.WebAuthnCredentials(), which
		// byCredentialID was built from the same slice to cover) — guarded
		// rather than indexed unchecked, because a silent map-miss here would
		// mean skipping the counter update below instead of erroring loudly.
		writeStoreError(w, http.StatusInternalServerError, "verifyWebAuthnAssertionHeader", "could not resolve matched credential", fmt.Errorf("no stored row for asserted credential"))
		return false
	}

	action := r.Method + " " + r.URL.Path

	// Both branches below pair a real state mutation (revoke+flag on a clone
	// signal; the sign counter otherwise) with the audit event describing it,
	// via the atomic Store methods (RecordWebAuthnAssertionUse,
	// FlagWebAuthnCredentialCloneWarningAudited) rather than a mutation call
	// followed by a separate pool-level Store.LogAudit. Found in the same
	// review pass as CreateWebAuthnCredential's atomicity fix: a sign-counter
	// update or a clone-triggered revocation is exactly the kind of mutation
	// audit.go's doc comment says belongs inside its own transaction (this
	// package's mutations are supposed to log atomically; LogAudit-via-pool is
	// documented as being for read-path events with no mutation to fail
	// together with — a counter update and a fail-closed revocation are both
	// real mutations, not that). Left as two mutations rather than one because
	// they're mutually exclusive outcomes of the same assertion (a clone
	// signal short-circuits before any counter update happens at all), each
	// with a different audit event type describing what actually happened.
	if cred.Authenticator.CloneWarning {
		detail := mustAuditJSON(map[string]string{"credential_id": base64.RawURLEncoding.EncodeToString(stored.CredentialID), "action": action})
		if err := a.Store.FlagWebAuthnCredentialCloneWarningAudited(r.Context(), stored.ID, reviewer.Label, detail); err != nil {
			writeStoreError(w, http.StatusInternalServerError, "verifyWebAuthnAssertionHeader", "could not record clone warning", err)
			return false
		}
		writeError(w, http.StatusUnauthorized, errWebAuthnClone)
		return false
	}

	detail := mustAuditJSON(map[string]string{"credential_id": base64.RawURLEncoding.EncodeToString(stored.CredentialID), "action": action})
	if err := a.Store.RecordWebAuthnAssertionUse(r.Context(), stored.ID, cred.Authenticator.SignCount, reviewer.Label, detail); err != nil {
		writeStoreError(w, http.StatusInternalServerError, "verifyWebAuthnAssertionHeader", "could not update credential counter", err)
		return false
	}

	return true
}

type webauthnCredentialView struct {
	ID              string  `json:"id"`
	Label           string  `json:"label"`
	Active          bool    `json:"active"`
	AttestationType string  `json:"attestation_type"`
	CreatedAt       string  `json:"created_at"`
	LastUsedAt      *string `json:"last_used_at,omitempty"`
	CloneWarningAt  *string `json:"clone_warning_at,omitempty"`
	RevokedAt       *string `json:"revoked_at,omitempty"`
}

func toWebAuthnCredentialView(c store.WebAuthnCredential) webauthnCredentialView {
	v := webauthnCredentialView{
		ID:              c.ID,
		Label:           c.Label,
		Active:          c.RevokedAt == nil,
		AttestationType: c.AttestationType,
		CreatedAt:       c.CreatedAt.Format(timeFormat),
	}
	if c.LastUsedAt != nil {
		s := c.LastUsedAt.Format(timeFormat)
		v.LastUsedAt = &s
	}
	if c.CloneWarningAt != nil {
		s := c.CloneWarningAt.Format(timeFormat)
		v.CloneWarningAt = &s
	}
	if c.RevokedAt != nil {
		s := c.RevokedAt.Format(timeFormat)
		v.RevokedAt = &s
	}
	return v
}

// listWebAuthnCredentials handles GET /api/webauthn/credentials. Scoped to
// the calling reviewer token's own credentials — see the store method's doc
// comment for why this, unlike listTokens, isn't "every active token sees
// everything."
func (a *API) listWebAuthnCredentials(w http.ResponseWriter, r *http.Request) {
	reviewer := reviewerFromContext(r.Context())
	creds, err := a.Store.ListWebAuthnCredentialsForReviewer(r.Context(), reviewer.ID)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "listWebAuthnCredentials", "could not list credentials", err)
		return
	}
	views := make([]webauthnCredentialView, len(creds))
	for i, c := range creds {
		views[i] = toWebAuthnCredentialView(c)
	}
	writeJSON(w, http.StatusOK, views)
}

// revokeWebAuthnCredential handles POST /api/webauthn/credentials/{id}/revoke.
// Bearer-only, no strong-factor gate — revocation only reduces authority,
// same stance as revokeToken (see that handler's doc comment). Scoped to the
// caller's own credentials by store.RevokeWebAuthnCredential.
func (a *API) revokeWebAuthnCredential(w http.ResponseWriter, r *http.Request) {
	reviewer := reviewerFromContext(r.Context())
	id := r.PathValue("id")
	if err := a.Store.RevokeWebAuthnCredential(r.Context(), id, reviewer.ID); err != nil {
		writeStoreError(w, http.StatusConflict, "revokeWebAuthnCredential", "could not revoke credential — it may not exist, already be revoked, or not belong to this reviewer", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// mustAuditJSON marshals an audit detail value that this package constructed
// itself from known-good fields (never user-controlled shapes that could
// fail to marshal) — panicking here would only mean a programmer error in
// this file, the same bar api.go's other invariants (RequestTimeout, RP
// config) hold at construction time.
func mustAuditJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("api: marshal audit detail: %v", err))
	}
	return b
}
