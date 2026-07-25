package store

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

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
// method only ever persists the hash.
func (s *Store) CreateReviewerToken(ctx context.Context, label, plaintext string) (ReviewerToken, error) {
	if label == "" {
		return ReviewerToken{}, fmt.Errorf("store: reviewer token label must not be empty")
	}
	row, err := s.q.InsertReviewerToken(ctx, sqlcgen.InsertReviewerTokenParams{
		Label:     label,
		TokenHash: HashToken(plaintext),
	})
	if err != nil {
		return ReviewerToken{}, fmt.Errorf("store: insert reviewer token: %w", err)
	}
	return ReviewerToken{ID: row.ID, Label: row.Label, CreatedAt: row.CreatedAt}, nil
}

// AuthenticateReviewerToken looks up the active (non-revoked) token matching
// plaintext and reports its label, updating last_used_at as a side effect. The
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
func (s *Store) AuthenticateReviewerToken(ctx context.Context, plaintext string) (label string, ok bool, err error) {
	row, err := s.q.LookupActiveReviewerToken(ctx, HashToken(plaintext))
	if err != nil {
		return "", false, nil //nolint:nilerr // sqlc pgx.ErrNoRows and genuine DB errors are both "not authenticated" here; see doc comment
	}
	if err := s.q.TouchReviewerToken(ctx, row.ID); err != nil {
		return "", false, fmt.Errorf("store: touch reviewer token: %w", err)
	}
	return row.Label, true, nil
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
