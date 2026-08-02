package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"

	"github.com/abradner/chuvar/backend/internal/store/sqlcgen"
)

// ReviewerToken is the store-facing view of an authenticated reviewer credential.
// The plaintext token itself is never stored or returned after creation — see
// CreateReviewerToken.
type ReviewerToken struct {
	ID         string
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// HashToken derives the lookup key for a plaintext bearer token. SHA-256 rather
// than a fast non-cryptographic hash for the same reason embed.Stub switched to
// it (internal/embed's doc comment): this value is compared against untrusted
// input on every request, so it should resist adversarial construction, not just
// accidental collision.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// CreateReviewerToken records a new device/reviewer token identified by label and
// returns its store-side record. The caller already generated the plaintext
// token and is responsible for showing it to the operator exactly once — this
// method only ever persists the hash. totpSecret is the device's enrolled TOTP
// secret (base32, empty if the caller chose not to enroll one) — see
// api.createToken. A token with no secret simply cannot pass requireTOTP later;
// it isn't a distinct error here.
//
// The secret is sealed before it reaches Postgres. Enrolling one therefore
// requires a Store built by NewSealed: without a key the only way to satisfy
// the caller would be to write the secret in the clear, and that is the exact
// failure this column was changed to close.
func (s *Store) CreateReviewerToken(ctx context.Context, label, plaintext, totpSecret string) (ReviewerToken, error) {
	if label == "" {
		return ReviewerToken{}, fmt.Errorf("store: reviewer token label must not be empty")
	}
	var sealed []byte
	if totpSecret != "" {
		if s.secrets == nil {
			return ReviewerToken{}, errors.New("store: cannot enroll a TOTP secret without a sealing key " +
				"(build the Store with NewSealed) — refusing to store it in the clear")
		}
		var err error
		if sealed, err = s.secrets.Seal([]byte(totpSecret)); err != nil {
			return ReviewerToken{}, fmt.Errorf("store: seal totp secret: %w", err)
		}
	}
	row, err := s.q.InsertReviewerToken(ctx, sqlcgen.InsertReviewerTokenParams{
		Label:         label,
		TokenHash:     HashToken(plaintext),
		TotpSecretEnc: sealed,
	})
	if err != nil {
		return ReviewerToken{}, fmt.Errorf("store: insert reviewer token: %w", err)
	}
	return ReviewerToken{ID: row.ID, Label: row.Label, CreatedAt: row.CreatedAt}, nil
}

// AuthenticatedReviewer identifies the token that authenticated a request: Label
// is what every decided_by/approved_by/revoked_by field records, ID is what
// requireTOTP uses to look up that specific device's enrolled secret. Two
// different tokens can share a label (nothing enforces uniqueness there), so
// TOTP verification is always keyed by ID, never by label.
type AuthenticatedReviewer struct {
	ID    string
	Label string
}

// AuthenticateReviewerToken looks up the active (non-revoked) token matching
// plaintext and reports its identity, updating last_used_at as a side effect. The
// second return value is false for "no such active token" — including a revoked
// one — never a distinguishable error, so callers can't use response shape to
// probe which tokens exist versus are merely revoked.
//
// The lookup itself is an exact-match query keyed by a full SHA-256 hash, not a
// byte-by-byte comparison against attacker-controlled input — unlike the shared
// bearer token requireAuth used to compare directly (internal/api's package
// comment), there's no comparable timing side channel here to guard with
// subtle.ConstantTimeCompare: a B-tree equality lookup's timing is a function of
// index depth, not of how many leading bytes of the hash matched.
func (s *Store) AuthenticateReviewerToken(ctx context.Context, plaintext string) (reviewer AuthenticatedReviewer, ok bool, err error) {
	row, err := s.q.LookupActiveReviewerToken(ctx, HashToken(plaintext))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AuthenticatedReviewer{}, false, nil
		}
		// A real DB failure (connection lost, pool exhausted, a migration
		// that hasn't run) used to be swallowed into the same "not
		// authenticated" result as a merely-unknown token — every request
		// during an outage would come back as an unlogged 401, making the
		// outage itself invisible instead of surfacing as the 500 it
		// actually is. Only "no matching row" means unauthenticated; every
		// other error is a real failure the caller (requireAuth) should log
		// and report as one. Found in review.
		return AuthenticatedReviewer{}, false, fmt.Errorf("store: authenticate reviewer token: %w", err)
	}
	if err := s.q.TouchReviewerToken(ctx, row.ID); err != nil {
		return AuthenticatedReviewer{}, false, fmt.Errorf("store: touch reviewer token: %w", err)
	}
	return AuthenticatedReviewer{ID: row.ID, Label: row.Label}, true, nil
}

// VerifyReviewerTOTP validates a one-time code against the given token's
// enrolled secret. Returns false, not an error, both when no code matches and
// when the token has no secret enrolled — an unenrolled device fails the gate
// the same way a wrong code does, it isn't a distinguishable server error.
//
// A missing sealing key IS an error rather than a false, unlike the cases
// above: those are ordinary "this request doesn't pass" outcomes, whereas a
// keyless Store gating an approval endpoint is a misconfigured deployment. It
// should surface as a 500 the operator investigates, not as a wrong code the
// operator retries.
func (s *Store) VerifyReviewerTOTP(ctx context.Context, tokenID, code string) (bool, error) {
	sealed, err := s.q.GetReviewerTOTPSecret(ctx, tokenID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("store: get reviewer totp secret: %w", err)
	}
	if len(sealed) == 0 {
		return false, nil
	}
	if s.secrets == nil {
		return false, errors.New("store: cannot verify TOTP without a sealing key " +
			"(build the Store with NewSealed)")
	}
	secret, err := s.secrets.Open(sealed)
	if err != nil {
		// The row exists but this key can't open it — a replaced key file, or a
		// database restored beside the wrong one. Never a wrong code, so don't
		// report it as one.
		return false, fmt.Errorf("store: opening the enrolled totp secret failed; the sealing key "+
			"does not match the one it was enrolled under: %w", err)
	}
	return totp.Validate(code, string(secret)), nil
}

// ListReviewerTokens returns every token, active or revoked, oldest first.
func (s *Store) ListReviewerTokens(ctx context.Context) ([]ReviewerToken, error) {
	rows, err := s.q.ListReviewerTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: list reviewer tokens: %w", err)
	}
	tokens := make([]ReviewerToken, len(rows))
	for i, r := range rows {
		tokens[i] = ReviewerToken{ID: r.ID, Label: r.Label, CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt, RevokedAt: r.RevokedAt}
	}
	return tokens, nil
}

// RevokeReviewerToken marks a token revoked. Errors (rather than silently
// no-opping) on an already-revoked or nonexistent ID, matching RevokeGrant's
// stance in grants.go — the consent/audit path doesn't paper over a bad request.
func (s *Store) RevokeReviewerToken(ctx context.Context, id string) error {
	rows, err := s.q.RevokeReviewerToken(ctx, id)
	if err != nil {
		return fmt.Errorf("store: revoke reviewer token: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("store: reviewer token %s not found or already revoked", id)
	}
	return nil
}

// CountActiveReviewerTokens reports how many non-revoked tokens currently exist —
// used by the bootstrap flow (cmd/apiserver) to decide whether to mint a first
// token from REVIEWER_BOOTSTRAP_TOKEN.
func (s *Store) CountActiveReviewerTokens(ctx context.Context) (int64, error) {
	n, err := s.q.CountActiveReviewerTokens(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: count active reviewer tokens: %w", err)
	}
	return n, nil
}

// CountEverEnrolledReviewerTokens reports how many tokens have a TOTP secret,
// counting revoked ones too — used by createToken (internal/api/tokens.go) to
// decide whether minting a new token requires a TOTP code from the caller.
// Zero means no device has ever been enrolled on this deployment: a fresh
// install, or one still carrying only pre-TOTP-migration tokens. Either way
// the operator has no enrolled device to prove possession of, so token
// creation can't require one without becoming unbootstrappable.
//
// "Ever", not "currently active", is load-bearing: revocation is bearer-only
// by design (it "only reduces authority"), so an active-only count would let
// anyone holding a stolen bearer token revoke every enrolled device, reopen
// this gate, and self-enroll a replacement. Because revoked rows are retained
// rather than deleted, this count is monotonic and nothing reachable over the
// API can lower it.
func (s *Store) CountEverEnrolledReviewerTokens(ctx context.Context) (int64, error) {
	n, err := s.q.CountEverEnrolledReviewerTokens(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: count ever-enrolled reviewer tokens: %w", err)
	}
	return n, nil
}
