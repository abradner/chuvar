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
// CreateAgentToken. Structurally distinct from ReviewerToken: this type lives
// in its own table (agent_tokens), so a value read here can never satisfy
// AuthenticateReviewerToken's query, and vice versa — see the migration's
// doc comment (20260812090000_agent_tokens.up.sql).
type AgentToken struct {
	ID         string
	Subject    string
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// CreateAgentToken records a new agent-class token identified by subject and
// label and returns its store-side record. The caller already generated the
// plaintext token (internal/api's generateToken) and is responsible for
// showing it to the operator exactly once — this method only ever persists
// the hash, via the same store.HashToken reviewer tokens use: hashing itself
// isn't a property distinct per credential kind, so there's no reason for a
// second implementation.
//
// subject and label are both required and kept separate: subject is the
// identity CreateGrant/audit_log key authority to, label is purely the
// operator-facing description shown in the list UI. Rotating a token
// (RevokeAgentToken the old row, CreateAgentToken a fresh one with the SAME
// subject) must not orphan any grant already issued to that subject — which
// is exactly why the two are different columns instead of one.
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

// AuthenticatedAgent identifies the token that authenticated an agent
// request: Subject is what any resulting grant/audit action is keyed to,
// Label is the operator-facing description, ID is the token row's own
// identity. Distinct from store.AuthenticatedReviewer — this type can only
// ever come from AuthenticateAgentToken, and callers gating reviewer-only
// behavior should never accept one in its place.
type AuthenticatedAgent struct {
	ID      string
	Subject string
	Label   string
}

// AuthenticateAgentToken looks up the active (non-revoked) agent token
// matching plaintext and reports its identity, updating last_used_at as a
// side effect. The second return value is false for "no such active token" —
// including a revoked one — never a distinguishable error, so callers can't
// use response shape to probe which tokens exist versus are merely revoked.
//
// Error discipline copied exactly from AuthenticateReviewerToken (the
// security-critical property both share): ONLY pgx.ErrNoRows collapses to
// (_, false, nil). Every other error — a lost connection, an exhausted pool,
// a migration that hasn't run — is returned as a real error, never silently
// folded into "not authenticated." An auth check that reports "no match" on
// a transient DB failure is a fail-open bug: it turns a real outage into an
// unlogged 401 nobody investigates, exactly the failure mode CLAUDE.md
// principle 5 ("fail closed, loudly") rules out.
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

// ListAgentTokens returns every agent token, active or revoked, oldest first.
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
// RevokeReviewerToken's stance — the consent/audit path doesn't paper over a
// bad request.
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
