package store

import (
	"context"
	"fmt"
	"time"
)

// validDepths mirrors the CHECK constraint on grants.depth in the schema — kept in
// sync by hand, not queried from the DB, since it changes about as often as the
// migration itself. Validating here means a bad value comes back as a clear "store:
// invalid depth" error instead of a raw Postgres check-constraint violation leaking
// out of this package.
var validDepths = map[string]bool{"summary": true, "facts": true, "full": true}

// CreateGrant records a new time-boxed grant. ttl of nil means no expiry.
func (s *Store) CreateGrant(ctx context.Context, subject string, scopes []string, depth string, ttl *time.Duration) (Grant, error) {
	if len(scopes) == 0 {
		return Grant{}, fmt.Errorf("store: grant must include at least one scope")
	}
	if !validDepths[depth] {
		return Grant{}, fmt.Errorf("store: invalid depth %q (want summary, facts, or full)", depth)
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

	var g Grant
	err = tx.QueryRow(ctx,
		`INSERT INTO grants (subject, depth, expires_at)
		 VALUES ($1, $2, $3)
		 RETURNING id, subject, depth, created_at, expires_at, revoked_at`,
		subject, depth, expiresAt,
	).Scan(&g.ID, &g.Subject, &g.Depth, &g.CreatedAt, &g.ExpiresAt, &g.RevokedAt)
	if err != nil {
		return Grant{}, fmt.Errorf("store: insert grant: %w", err)
	}

	for _, sc := range scopes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO grant_scopes (grant_id, scope) VALUES ($1, $2)`,
			g.ID, sc,
		); err != nil {
			return Grant{}, fmt.Errorf("store: insert grant scope %q: %w", sc, err)
		}
	}
	g.Scopes = scopes

	if err := tx.Commit(ctx); err != nil {
		return Grant{}, fmt.Errorf("store: commit grant: %w", err)
	}
	return g, nil
}

// ListGrants returns every grant (active or not) for subject, most recent first.
func (s *Store) ListGrants(ctx context.Context, subject string) ([]Grant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, subject, depth, created_at, expires_at, revoked_at
		 FROM grants WHERE subject = $1 ORDER BY created_at DESC`,
		subject,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list grants: %w", err)
	}
	defer rows.Close()

	var grants []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.ID, &g.Subject, &g.Depth, &g.CreatedAt, &g.ExpiresAt, &g.RevokedAt); err != nil {
			return nil, fmt.Errorf("store: scan grant: %w", err)
		}
		grants = append(grants, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list grants: %w", err)
	}

	for i := range grants {
		scopes, err := s.grantScopes(ctx, grants[i].ID)
		if err != nil {
			return nil, err
		}
		grants[i].Scopes = scopes
	}
	return grants, nil
}

func (s *Store) grantScopes(ctx context.Context, grantID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT scope FROM grant_scopes WHERE grant_id = $1`, grantID)
	if err != nil {
		return nil, fmt.Errorf("store: list grant scopes: %w", err)
	}
	defer rows.Close()

	var scopes []string
	for rows.Next() {
		var sc string
		if err := rows.Scan(&sc); err != nil {
			return nil, fmt.Errorf("store: scan grant scope: %w", err)
		}
		scopes = append(scopes, sc)
	}
	return scopes, rows.Err()
}

// GrantedScopes returns the union of scopes granted to subject across all currently
// active (non-revoked, unexpired) grants. This is what read-with-scope-check checks
// requested scopes against.
func (s *Store) GrantedScopes(ctx context.Context, subject string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT gs.scope
		 FROM grant_scopes gs
		 JOIN grants g ON g.id = gs.grant_id
		 WHERE g.subject = $1
		   AND g.revoked_at IS NULL
		   AND (g.expires_at IS NULL OR g.expires_at > now())`,
		subject,
	)
	if err != nil {
		return nil, fmt.Errorf("store: granted scopes: %w", err)
	}
	defer rows.Close()

	var scopes []string
	for rows.Next() {
		var sc string
		if err := rows.Scan(&sc); err != nil {
			return nil, fmt.Errorf("store: scan granted scope: %w", err)
		}
		scopes = append(scopes, sc)
	}
	return scopes, rows.Err()
}

// RevokeGrant marks a grant revoked. Idempotent calls (revoking an already-revoked
// grant) return an error rather than silently succeeding — see AGENTS.md §6 on not
// swallowing errors in the consent/audit path.
func (s *Store) RevokeGrant(ctx context.Context, grantID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE grants SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`,
		grantID,
	)
	if err != nil {
		return fmt.Errorf("store: revoke grant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: grant %s not found or already revoked", grantID)
	}
	return nil
}
