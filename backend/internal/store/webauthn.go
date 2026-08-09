package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/abradner/chuvar/backend/internal/store/sqlcgen"
)

// ErrWebAuthnCredentialAlreadyRegistered means the authenticator presented at
// registration is already enrolled (and still active) — surfaced as a
// distinguishable sentinel so internal/api can answer 409, not a generic 500,
// when the operator re-registers a passkey they (or a shared physical key)
// already hold.
var ErrWebAuthnCredentialAlreadyRegistered = errors.New("store: this authenticator is already registered")

// WebAuthnCredential is the store-facing view of one registered authenticator,
// bound to the reviewer token that enrolled it (ReviewerTokenID) — never to a
// caller-supplied identity, matching every other actor-identity rule in this
// package (see AGENTS.md §6). PublicKey and SignCount are plaintext by design:
// AGENTS.md §3.5's sealing rule covers plaintext-*secret* surfaces, and a
// WebAuthn public key is exactly that — public — while the sign counter is a
// monotonic integer, neither of which is a bearer credential the way
// totp_secret_enc is.
type WebAuthnCredential struct {
	ID              string
	ReviewerTokenID string
	Label           string
	CredentialID    []byte
	PublicKey       []byte
	AttestationType string
	Transports      []string
	AAGUID          []byte
	SignCount       uint32
	// BackupEligible/BackupState round-trip go-webauthn's CredentialFlags —
	// see the migration's doc comment on why BackupEligible in particular
	// must survive storage unchanged rather than being re-derived per call
	// (the library hard-fails an assertion whose BackupEligible flag doesn't
	// match what was recorded at registration).
	BackupEligible bool
	BackupState    bool
	CreatedAt      time.Time
	LastUsedAt     *time.Time
	CloneWarningAt *time.Time
	RevokedAt      *time.Time
}

func toWebAuthnCredential(row sqlcgen.WebauthnCredential) WebAuthnCredential {
	return WebAuthnCredential{
		ID:              row.ID,
		ReviewerTokenID: row.ReviewerTokenID,
		Label:           row.Label,
		CredentialID:    row.CredentialID,
		PublicKey:       row.PublicKey,
		AttestationType: row.AttestationType,
		Transports:      row.Transports,
		AAGUID:          row.Aaguid,
		// sign_count is BIGINT in Postgres (sqlc has no unsigned integer
		// mapping) but is always a uint32 in practice — go-webauthn's own
		// Authenticator.SignCount is uint32, per the WebAuthn spec's 32-bit
		// counter field. Truncating here rather than carrying int64 through
		// this package keeps every caller working in the type the protocol
		// actually uses.
		SignCount:      uint32(row.SignCount),
		BackupEligible: row.BackupEligible,
		BackupState:    row.BackupState,
		CreatedAt:      row.CreatedAt,
		LastUsedAt:     row.LastUsedAt,
		CloneWarningAt: row.CloneWarningAt,
		RevokedAt:      row.RevokedAt,
	}
}

// CreateWebAuthnCredential persists a newly registered authenticator. Bound to
// reviewerTokenID, which every caller (internal/api's registerFinish) derives
// from the authenticated request context, never from the request body —
// accepting a caller-supplied owner here would let one reviewer token enroll
// a credential it doesn't hold against another's identity.
func (s *Store) CreateWebAuthnCredential(
	ctx context.Context,
	reviewerTokenID, label string,
	credentialID, publicKey []byte,
	attestationType string,
	transports []string,
	aaguid []byte,
	signCount uint32,
	backupEligible, backupState bool,
) (WebAuthnCredential, error) {
	if label == "" {
		return WebAuthnCredential{}, fmt.Errorf("store: webauthn credential label must not be empty")
	}
	if transports == nil {
		transports = []string{}
	}
	if aaguid == nil {
		// pgx sends a nil []byte as SQL NULL, not an empty BYTEA, which
		// violates the column's NOT NULL constraint — an authenticator that
		// doesn't report an AAGUID (or a caller that doesn't have one to
		// hand) means "no AAGUID," which the schema represents as '' rather
		// than NULL (see the migration's default), not "value unknown."
		aaguid = []byte{}
	}
	row, err := s.q.InsertWebAuthnCredential(ctx, sqlcgen.InsertWebAuthnCredentialParams{
		ReviewerTokenID: reviewerTokenID,
		Label:           label,
		CredentialID:    credentialID,
		PublicKey:       publicKey,
		AttestationType: attestationType,
		Transports:      transports,
		Aaguid:          aaguid,
		SignCount:       int64(signCount),
		BackupEligible:  backupEligible,
		BackupState:     backupState,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return WebAuthnCredential{}, ErrWebAuthnCredentialAlreadyRegistered
		}
		return WebAuthnCredential{}, fmt.Errorf("store: insert webauthn credential: %w", err)
	}
	return toWebAuthnCredential(row), nil
}

// ListWebAuthnCredentialsForReviewer returns every credential — active and
// revoked — owned by one reviewer token, oldest first. Scoped to a single
// reviewer rather than every reviewer system-wide: unlike reviewer_tokens'
// "any active token lists every token" stance (there is no per-owner
// permission model there), a WebAuthn credential's metadata is tied to a
// specific physical authenticator, and there's no legibility reason for one
// device's browser session to enumerate another device's registered keys.
func (s *Store) ListWebAuthnCredentialsForReviewer(ctx context.Context, reviewerTokenID string) ([]WebAuthnCredential, error) {
	rows, err := s.q.ListWebAuthnCredentialsForReviewer(ctx, reviewerTokenID)
	if err != nil {
		return nil, fmt.Errorf("store: list webauthn credentials: %w", err)
	}
	creds := make([]WebAuthnCredential, len(rows))
	for i, r := range rows {
		creds[i] = toWebAuthnCredential(r)
	}
	return creds, nil
}

// ActiveWebAuthnCredentialsForReviewer is ListWebAuthnCredentialsForReviewer
// filtered to non-revoked rows — what a registration or assertion ceremony
// should ever present to the authenticator (a revoked credential must not be
// offered as an exclude-list entry to silently block re-registering the same
// physical key, nor as an allow-list entry an assertion could still satisfy).
func (s *Store) ActiveWebAuthnCredentialsForReviewer(ctx context.Context, reviewerTokenID string) ([]WebAuthnCredential, error) {
	all, err := s.ListWebAuthnCredentialsForReviewer(ctx, reviewerTokenID)
	if err != nil {
		return nil, err
	}
	active := make([]WebAuthnCredential, 0, len(all))
	for _, c := range all {
		if c.RevokedAt == nil {
			active = append(active, c)
		}
	}
	return active, nil
}

// CountEverEnrolledWebAuthnCredentials reports how many WebAuthn credentials
// have ever been enrolled on this deployment, revoked ones included — the
// WebAuthn half of createToken's (internal/api/tokens.go) "has any second
// factor ever been enrolled" bootstrap gate, alongside
// CountEverEnrolledReviewerTokens' TOTP half. Same monotonicity argument as
// that method's doc comment: rows are retained on revocation, never deleted,
// so nothing reachable over the API can lower this count.
//
// Strictly speaking this half is redundant today: a passkey can only be
// enrolled by proving an existing factor on a TOTP-enrolled token
// (requireExistingSecondFactor has no factorless carve-out), so a nonzero
// WebAuthn count implies a nonzero TOTP count. It is counted anyway so the
// gate enforces its property ("any second factor, ever, of any kind")
// directly rather than depending on that cross-endpoint invariant staying
// true — if a future change ever lets a passkey exist without a TOTP-enrolled
// ancestor, this gate stays closed instead of silently reopening.
func (s *Store) CountEverEnrolledWebAuthnCredentials(ctx context.Context) (int64, error) {
	n, err := s.q.CountEverEnrolledWebAuthnCredentials(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: count ever-enrolled webauthn credentials: %w", err)
	}
	return n, nil
}

// ReviewerHasActiveWebAuthnCredential reports whether this reviewer token has
// at least one live (non-revoked) passkey enrolled — used by
// requireExistingSecondFactor (internal/api) to decide whether enrolling a
// further credential must itself be proven against an existing one.
func (s *Store) ReviewerHasActiveWebAuthnCredential(ctx context.Context, reviewerTokenID string) (bool, error) {
	ok, err := s.q.ReviewerHasActiveWebAuthnCredential(ctx, reviewerTokenID)
	if err != nil {
		return false, fmt.Errorf("store: check reviewer webauthn enrollment: %w", err)
	}
	return ok, nil
}

// ReviewerHasTOTP reports whether this specific reviewer token has a TOTP
// secret enrolled. Deliberately per-reviewer, unlike
// CountEverEnrolledReviewerTokens' deployment-wide count: that count exists
// only to keep the bootstrap token's very first enrollment reachable, while
// this answers "does *this* token have a factor to demand" for
// requireExistingSecondFactor's enrollment gate — a reviewer with no TOTP
// enrolled has nothing to demand a code against, regardless of what any other
// device on the deployment has done.
func (s *Store) ReviewerHasTOTP(ctx context.Context, reviewerTokenID string) (bool, error) {
	v, err := s.q.ReviewerHasTOTP(ctx, reviewerTokenID)
	if err != nil {
		return false, fmt.Errorf("store: check reviewer totp enrollment: %w", err)
	}
	// v is pgtype.Bool because sqlc can't prove the boolean expression is
	// never NULL from static analysis alone; it always is not-NULL for a row
	// that exists (totp_secret_enc IS NOT NULL never evaluates to NULL). The
	// query already returned ErrNoRows above if reviewerTokenID didn't match
	// any row, so reaching here with Valid == false would be a genuine
	// anomaly, not an expected "no" — surfaced as an error rather than
	// silently read as false.
	if !v.Valid {
		return false, fmt.Errorf("store: reviewer totp enrollment check returned no value for token %s", reviewerTokenID)
	}
	return v.Bool, nil
}

// UpdateWebAuthnCredentialCounter persists a new sign counter after a
// successful assertion — the "greater than before" case. Callers must have
// already established authDataCount > the stored value (or both are zero, the
// standard reading for authenticators that never increment — see
// go-webauthn's Authenticator.UpdateCounter); the clone-signal case is
// FlagWebAuthnCredentialCloneWarning instead, never this method.
func (s *Store) UpdateWebAuthnCredentialCounter(ctx context.Context, credentialID string, signCount uint32) error {
	if err := s.q.UpdateWebAuthnCredentialCounter(ctx, sqlcgen.UpdateWebAuthnCredentialCounterParams{
		ID:        credentialID,
		SignCount: int64(signCount),
	}); err != nil {
		return fmt.Errorf("store: update webauthn credential counter: %w", err)
	}
	return nil
}

// FlagWebAuthnCredentialCloneWarning records a detected sign-counter
// regression and revokes the credential in the same statement — fail-closed,
// per the migration's doc comment: a possibly-cloned authenticator must not
// keep passing this gate on a later call just because this one was refused.
// The adversary this defends against is a physically or logically duplicated
// authenticator private key (a cloned security key, or an extracted platform
// key) whose two copies both produce valid signatures but diverge on the
// counter — the one signal a bearer-token-holding attacker cannot forge
// without the key material itself.
func (s *Store) FlagWebAuthnCredentialCloneWarning(ctx context.Context, credentialID string) error {
	if err := s.q.FlagWebAuthnCredentialCloneWarning(ctx, credentialID); err != nil {
		return fmt.Errorf("store: flag webauthn credential clone warning: %w", err)
	}
	return nil
}

// RevokeWebAuthnCredential marks a credential revoked. Scoped to
// reviewerTokenID — a reviewer can only revoke its own credentials, matching
// ListWebAuthnCredentialsForReviewer's per-owner scoping rather than
// reviewer_tokens' unrestricted "any token revokes any token" stance,
// because unlike device tokens (all equally the one operator's own devices,
// per that package's comment), nothing here establishes that two different
// reviewer tokens belong to the same operator. Errors (rather than silently
// no-opping) on an already-revoked, nonexistent, or not-owned id, matching
// RevokeReviewerToken's stance.
func (s *Store) RevokeWebAuthnCredential(ctx context.Context, id, reviewerTokenID string) error {
	rows, err := s.q.RevokeWebAuthnCredential(ctx, sqlcgen.RevokeWebAuthnCredentialParams{
		ID:              id,
		ReviewerTokenID: reviewerTokenID,
	})
	if err != nil {
		return fmt.Errorf("store: revoke webauthn credential: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("store: webauthn credential %s not found, already revoked, or not owned by this reviewer", id)
	}
	return nil
}

// WebAuthn ceremony purposes — the two kinds of server-side challenge state
// this package tracks. Matches the CHECK constraint on webauthn_challenges.purpose.
const (
	WebAuthnPurposeRegistration = "registration"
	WebAuthnPurposeAssertion    = "assertion"
)

// PutWebAuthnChallenge stores (or overwrites) the single pending challenge for
// a reviewer/purpose pair. sessionData is the go-webauthn library's own
// SessionData, opaque to this package — it round-trips through JSONB
// unexamined, since none of it is secret (see the migration's doc comment).
func (s *Store) PutWebAuthnChallenge(ctx context.Context, reviewerTokenID, purpose string, sessionData []byte, expiresAt time.Time) error {
	if err := s.q.UpsertWebAuthnChallenge(ctx, sqlcgen.UpsertWebAuthnChallengeParams{
		ReviewerTokenID: reviewerTokenID,
		Purpose:         purpose,
		SessionData:     sessionData,
		ExpiresAt:       pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}); err != nil {
		return fmt.Errorf("store: put webauthn challenge: %w", err)
	}
	return nil
}

// ConsumeWebAuthnChallenge atomically retrieves and deletes the pending
// challenge for a reviewer/purpose pair, enforcing single-use and expiry in
// one statement (see ConsumeWebAuthnChallenge in queries/webauthn.sql). ok is
// false — not an error — for "no such challenge, or it already expired,
// or it was already consumed": these are ordinary ceremony-abuse or
// stale-request outcomes a caller should reject with 401, not evidence of a
// server failure.
func (s *Store) ConsumeWebAuthnChallenge(ctx context.Context, reviewerTokenID, purpose string) (sessionData []byte, ok bool, err error) {
	data, err := s.q.ConsumeWebAuthnChallenge(ctx, sqlcgen.ConsumeWebAuthnChallengeParams{
		ReviewerTokenID: reviewerTokenID,
		Purpose:         purpose,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("store: consume webauthn challenge: %w", err)
	}
	return data, true, nil
}
