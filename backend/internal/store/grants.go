package store

import (
	"context"
	"fmt"
	"time"

	"github.com/abradner/chuvar/backend/internal/store/sqlcgen"
)

// validDepths mirrors the CHECK constraint on grants.depth in the schema — kept in
// sync by hand, not queried from the DB, since it changes about as often as the
// migration itself. Validating here means a bad value comes back as a clear "store:
// invalid depth" error instead of a raw Postgres check-constraint violation leaking
// out of this package.
var validDepths = map[string]bool{"summary": true, "facts": true, "full": true}

// CreateGrant records a new time-boxed grant. ttl of nil means no expiry. actor is
// who's creating the grant — required, logged to audit_log in the same transaction
// as the insert (see logAudit's doc comment). Under the current shared-bearer-token
// REST auth (internal/api's package comment), actor is self-reported by the
// caller, not cryptographically authenticated identity — the audit trail is honest
// about who *claimed* to approve something, not a guarantee against a token holder
// misattributing it. Closing that gap needs real per-reviewer auth, a product
// decision this project hasn't made yet (same caveat as decided_by on diffs).
func (s *Store) CreateGrant(ctx context.Context, subject string, scopes []string, depth string, ttl *time.Duration, actor string) (Grant, error) {
	if len(scopes) == 0 {
		return Grant{}, fmt.Errorf("store: grant must include at least one scope")
	}
	if !validDepths[depth] {
		return Grant{}, fmt.Errorf("store: invalid depth %q (want summary, facts, or full)", depth)
	}
	if actor == "" {
		return Grant{}, fmt.Errorf("store: actor must not be empty")
	}

	var expiresAt *time.Time
	if ttl != nil {
		t := time.Now().Add(*ttl)
		expiresAt = &t
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Grant{}, fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op if already committed
	qtx := s.q.WithTx(tx)

	row, err := qtx.InsertGrant(ctx, sqlcgen.InsertGrantParams{
		Subject:   subject,
		Depth:     depth,
		ExpiresAt: toTimestamptz(expiresAt),
	})
	if err != nil {
		return Grant{}, fmt.Errorf("store: insert grant: %w", err)
	}

	for _, sc := range scopes {
		if err := qtx.InsertGrantScope(ctx, sqlcgen.InsertGrantScopeParams{GrantID: row.ID, Scope: sc}); err != nil {
			return Grant{}, fmt.Errorf("store: insert grant scope %q: %w", sc, err)
		}
	}

	if err := logAudit(ctx, qtx, "grant_created", actor, nil, &row.ID, nil, scopes); err != nil {
		return Grant{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Grant{}, fmt.Errorf("store: commit grant: %w", err)
	}

	return Grant{
		ID:        row.ID,
		Subject:   row.Subject,
		Scopes:    scopes,
		Depth:     row.Depth,
		CreatedAt: row.CreatedAt,
		ExpiresAt: row.ExpiresAt,
		RevokedAt: row.RevokedAt,
	}, nil
}

// ListGrants returns every grant (active or not) for subject, most recent first.
func (s *Store) ListGrants(ctx context.Context, subject string) ([]Grant, error) {
	rows, err := s.q.ListGrants(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("store: list grants: %w", err)
	}

	var grants []Grant
	for _, r := range rows {
		scopes, err := s.q.ListGrantScopes(ctx, r.ID)
		if err != nil {
			return nil, fmt.Errorf("store: list grant scopes: %w", err)
		}
		grants = append(grants, Grant{
			ID:        r.ID,
			Subject:   r.Subject,
			Scopes:    scopes,
			Depth:     r.Depth,
			CreatedAt: r.CreatedAt,
			ExpiresAt: r.ExpiresAt,
			RevokedAt: r.RevokedAt,
		})
	}
	return grants, nil
}

// GrantedScopes returns the union of scopes granted to subject across all currently
// active (non-revoked, unexpired) grants. This is what read-with-scope-check checks
// requested scopes against.
func (s *Store) GrantedScopes(ctx context.Context, subject string) ([]string, error) {
	scopes, err := s.q.GrantedScopes(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("store: granted scopes: %w", err)
	}
	return scopes, nil
}

// RevokeGrant marks a grant revoked. Idempotent calls (revoking an already-revoked
// grant) return an error rather than silently succeeding — see AGENTS.md §6 on not
// swallowing errors in the consent/audit path. actor is who's revoking it —
// required, logged to audit_log atomically with the revoke; see CreateGrant's doc
// comment for the same self-reported-identity caveat.
func (s *Store) RevokeGrant(ctx context.Context, grantID, actor string) error {
	if actor == "" {
		return fmt.Errorf("store: actor must not be empty")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op if already committed
	qtx := s.q.WithTx(tx)

	rows, err := qtx.RevokeGrant(ctx, grantID)
	if err != nil {
		return fmt.Errorf("store: revoke grant: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("store: grant %s not found or already revoked", grantID)
	}

	if err := logAudit(ctx, qtx, "grant_revoked", actor, nil, &grantID, nil, nil); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit grant revocation: %w", err)
	}
	return nil
}
