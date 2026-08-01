package store

import (
	"context"
	"fmt"
	"time"

	"github.com/abradner/chuvar/backend/internal/store/sqlcgen"
)

// ValidDepth mirrors the CHECK constraint on grants.depth/grant_requests.depth in
// the schema — kept in sync by hand, not queried from the DB, since it changes
// about as often as the migration itself. The single copy every layer that
// accepts external input (this package, internal/api, internal/mcptools) now
// calls, replacing three independently hand-synced maps that carried the
// identical drift risk. Checking here means a bad value comes back as a clear
// validation error instead of a raw Postgres check-constraint violation leaking
// out.
func ValidDepth(depth string) bool {
	switch depth {
	case "summary", "facts", "full":
		return true
	default:
		return false
	}
}

// ValidKind mirrors the CHECK constraint on grants.kind/grant_requests.kind.
func ValidKind(kind string) bool {
	switch GrantKind(kind) {
	case GrantKindMemory, GrantKindCapability:
		return true
	default:
		return false
	}
}

// validateKindAndDepth enforces the same pairing invariant as the DB's
// grants_kind_depth_pairing / grant_requests_kind_depth_pairing CHECK
// constraints, at the Go boundary rather than as a raw constraint-violation
// error: kind defaults to memory when omitted (every caller before this type
// existed only ever created memory grants), a memory kind requires a valid
// depth, and any other kind must not carry one — there's no equivalent concept
// for a capability grant yet.
func validateKindAndDepth(kind, depth string) (GrantKind, string, error) {
	if kind == "" {
		kind = string(GrantKindMemory)
	}
	if !ValidKind(kind) {
		return "", "", fmt.Errorf("store: invalid kind %q (want memory or capability)", kind)
	}
	if GrantKind(kind) == GrantKindMemory {
		if !ValidDepth(depth) {
			return "", "", fmt.Errorf("store: invalid depth %q (want summary, facts, or full)", depth)
		}
	} else if depth != "" {
		return "", "", fmt.Errorf("store: depth must not be set for kind %q", kind)
	}
	return GrantKind(kind), depth, nil
}

// nullableDepth converts the empty-string "no depth" sentinel to NULL for
// storage — depth is empty exactly when kind isn't memory (validateKindAndDepth
// already enforced that pairing).
func nullableDepth(depth string) *string {
	if depth == "" {
		return nil
	}
	return &depth
}

// depthOrEmpty is nullableDepth's inverse, reading a row back out.
func depthOrEmpty(depth *string) string {
	if depth == nil {
		return ""
	}
	return *depth
}

// CreateGrant records a new time-boxed grant. ttl of nil means no expiry. actor is
// who's creating the grant — required, logged to audit_log in the same transaction
// as the insert (see logAudit's doc comment). decided_by/approved_by/revoked_by
// are derived from the authenticated reviewer token (internal/api's requireAuth),
// never read from the request body — actor here is that already-authenticated
// identity, not client-supplied.
func (s *Store) CreateGrant(ctx context.Context, subject string, scopes []string, kind, depth string, ttl *time.Duration, actor string) (Grant, error) {
	if len(scopes) == 0 {
		return Grant{}, fmt.Errorf("store: grant must include at least one scope")
	}
	validKind, depth, err := validateKindAndDepth(kind, depth)
	if err != nil {
		return Grant{}, err
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
		Kind:      string(validKind),
		Depth:     nullableDepth(depth),
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

	if err := logAudit(ctx, qtx, "grant_created", actor, nil, &row.ID, nil, nil, scopes); err != nil {
		return Grant{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Grant{}, fmt.Errorf("store: commit grant: %w", err)
	}

	return Grant{
		ID:        row.ID,
		Subject:   row.Subject,
		Scopes:    scopes,
		Kind:      GrantKind(row.Kind),
		Depth:     depthOrEmpty(row.Depth),
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
			Kind:      GrantKind(r.Kind),
			Depth:     depthOrEmpty(r.Depth),
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

	if err := logAudit(ctx, qtx, "grant_revoked", actor, nil, &grantID, nil, nil, nil); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit grant revocation: %w", err)
	}
	return nil
}
