package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/abradner/chuvar/backend/internal/store/sqlcgen"
)

// AgentToken is the store-facing view of an agent-class credential. The
// plaintext token itself is never stored or returned after creation — see
// CreateAgentToken. This is a structurally distinct row from ReviewerToken:
// it lives in its own table (agent_tokens), so it can never satisfy
// AuthenticateReviewerToken's lookup, and vice versa — see the migration's
// doc comment (20260812120000_agent_tokens.up.sql) for the reasoning.
type AgentToken struct {
	ID         string
	Subject    string
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// CreateAgentToken records a new agent-class token identified by subject and
// label, and returns its store-side record. The caller already generated the
// plaintext token (api.generateToken) and is responsible for showing it to
// the operator exactly once — this method only ever persists its hash, via
// the same store.HashToken reviewer tokens use, not a separate hashing
// scheme: this table exists to be a *structurally* distinct credential
// (its own table, its own unique index), not a cryptographically distinct
// one — both use SHA-256 for the same reason (resisting adversarial lookup
// construction, not just accidental collision).
//
// subject and label are kept separate deliberately (see the migration's
// comment): subject is the grant/audit identity a token's holder acts as,
// label is pure operator-facing description. Both are required — an empty
// subject would mean audit rows and grants end up attributed to "", and an
// empty label leaves the operator with no way to tell tokens apart in the
// list view.
func (s *Store) CreateAgentToken(ctx context.Context, subject, label, plaintext string) (AgentToken, error) {
	if subject == "" {
		return AgentToken{}, fmt.Errorf("store: agent token subject must not be empty")
	}
	if label == "" {
		return AgentToken{}, fmt.Errorf("store: agent token label must not be empty")
	}
	row, err := s.q.InsertAgentToken(ctx, sqlcgen.InsertAgentTokenParams{
		Subject:   subject,
		Label:     label,
		TokenHash: HashToken(plaintext),
	})
	if err != nil {
		return AgentToken{}, fmt.Errorf("store: insert agent token: %w", err)
	}
	return AgentToken{ID: row.ID, Subject: row.Subject, Label: row.Label, CreatedAt: row.CreatedAt}, nil
}

// AuthenticatedAgent identifies the agent-class token that authenticated a
// request: Subject is the grant/audit identity that request should act as,
// Label is the operator-facing description (for logging/diagnostics, not
// for attribution — Subject is what audit rows and grant checks use).
type AuthenticatedAgent struct {
	ID      string
	Subject string
	Label   string
}

// AuthenticateAgentToken looks up the active (non-revoked) agent token
// matching plaintext and reports its identity, updating last_used_at as a
// side effect. The second return value is false for "no such active token"
// — including a revoked one — never a distinguishable error, mirroring
// AuthenticateReviewerToken's discipline exactly.
//
// Only pgx.ErrNoRows maps to (_, false, nil). Every other error — a lost
// connection, an exhausted pool, a migration that hasn't run — is returned
// as a real error, never folded into "not authenticated." An auth check
// that treats a transient DB failure as "no match" fails OPEN during an
// outage in the sense that matters here: every legitimate caller gets
// rejected and the rejection looks identical to an unknown token, so the
// outage itself goes uninvestigated instead of surfacing as the 500 it
// actually is (principle 5, fail closed, loudly — silence is the enemy of
// consent). This is the security-critical method on this type; see
// AuthenticateReviewerToken's identical doc comment and the regression test
// this mirrors, TestAuthenticateAgentToken_RealDBErrorIsReturnedNotMaskedAsUnauthenticated.
func (s *Store) AuthenticateAgentToken(ctx context.Context, plaintext string) (agent AuthenticatedAgent, ok bool, err error) {
	row, err := s.q.LookupActiveAgentToken(ctx, HashToken(plaintext))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AuthenticatedAgent{}, false, nil
		}
		return AuthenticatedAgent{}, false, fmt.Errorf("store: authenticate agent token: %w", err)
	}
	if err := s.q.TouchAgentToken(ctx, row.ID); err != nil {
		return AuthenticatedAgent{}, false, fmt.Errorf("store: touch agent token: %w", err)
	}
	return AuthenticatedAgent{ID: row.ID, Subject: row.Subject, Label: row.Label}, true, nil
}

// ListAgentTokens returns every agent token, active or revoked, oldest
// first. Never returns token_hash or plaintext — this is the list surface
// an operator uses to see what exists and revoke what shouldn't.
func (s *Store) ListAgentTokens(ctx context.Context) ([]AgentToken, error) {
	rows, err := s.q.ListAgentTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: list agent tokens: %w", err)
	}
	tokens := make([]AgentToken, len(rows))
	for i, r := range rows {
		tokens[i] = AgentToken{ID: r.ID, Subject: r.Subject, Label: r.Label, CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt, RevokedAt: r.RevokedAt}
	}
	return tokens, nil
}

// RevokeAgentToken marks an agent token revoked. Errors (rather than
// silently no-opping) on an already-revoked or nonexistent ID, matching
// RevokeReviewerToken's stance — revocation only ever reduces authority, but
// a request to revoke something that doesn't exist or is already gone is
// still a bad request the caller should learn about, not a silent success.
func (s *Store) RevokeAgentToken(ctx context.Context, id string) error {
	rows, err := s.q.RevokeAgentToken(ctx, id)
	if err != nil {
		return fmt.Errorf("store: revoke agent token: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("store: agent token %s not found or already revoked", id)
	}
	return nil
}
