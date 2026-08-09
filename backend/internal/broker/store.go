package broker

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// grantRow is one capability grant, joined with the signing-specific content
// added by 20260809140000_capability_grant_signing.up.sql. Deliberately its
// own minimal query layer rather than a dependency on internal/store: this
// package's whole point is a narrower trust boundary than apiserver/mcpserver
// hold (its own chuvar_broker DB role, its own explicit query set touching
// exactly grants/grant_scopes/capability_grant_identities/
// capability_grant_tokens/audit_log — see the migration's own comment) —
// importing internal/store would pull in a package whose facts.go/
// staged_diffs.go exist to serve a role this binary never runs as, even
// though no code path here would call those methods. "Never imports/touches
// facts" is easiest to keep true by construction, not by discipline, and a
// separate small query layer is what makes that true rather than merely
// intended.
type grantRow struct {
	ID             string
	Subject        string
	CommitterEmail string
	TokenHash      []byte
	Scopes         []string
	ExpiresAt      *time.Time
}

// loadCapabilityGrants returns every currently-active (not revoked, not
// expired), fully-provisioned (has both an identity and a token row —
// see the migration comment on capability_grant_identities) capability
// grant. The inner joins are the enforcement: a capability grant missing
// either row is structurally unusable rather than usable-with-a-nil-check,
// matching this package's stance that a git.sign grant with no identity is
// simply not a thing brokerd can act on.
func loadCapabilityGrants(ctx context.Context, pool *pgxpool.Pool) ([]grantRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT g.id, g.subject, g.expires_at,
		       ci.committer_email,
		       ct.token_hash,
		       (SELECT array_agg(gs.scope) FROM grant_scopes gs WHERE gs.grant_id = g.id)::text[] AS scopes
		FROM grants g
		JOIN capability_grant_identities ci ON ci.grant_id = g.id
		JOIN capability_grant_tokens ct ON ct.grant_id = g.id
		WHERE g.kind = 'capability'
		  AND g.revoked_at IS NULL
		  AND (g.expires_at IS NULL OR g.expires_at > now())
	`)
	if err != nil {
		return nil, fmt.Errorf("broker: loading capability grants: %w", err)
	}
	defer rows.Close()

	var out []grantRow
	for rows.Next() {
		var r grantRow
		var expiresAt *time.Time
		if err := rows.Scan(&r.ID, &r.Subject, &expiresAt, &r.CommitterEmail, &r.TokenHash, &r.Scopes); err != nil {
			return nil, fmt.Errorf("broker: scanning capability grant row: %w", err)
		}
		r.ExpiresAt = expiresAt
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("broker: reading capability grant rows: %w", err)
	}
	return out, nil
}

// insertSignAuditLog records one successful signing operation. Synchronous
// on the sign path, deliberately — see internal/broker/broker.go's doc
// comment on why the audit write, unlike the grant-authorization check that
// precedes it, is not purely in-process state.
func insertSignAuditLog(ctx context.Context, pool *pgxpool.Pool, subject, grantID, scope string) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO audit_log (event_type, subject, grant_id, scopes, detail)
		VALUES ('capability_signed', $1, $2, $3, '{}'::jsonb)
	`, subject, grantID, []string{scope})
	if err != nil {
		return fmt.Errorf("broker: inserting sign audit log: %w", err)
	}
	return nil
}
