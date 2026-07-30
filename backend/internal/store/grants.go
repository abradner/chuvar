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

// depthRank orders depths by permissiveness, for computing an effective depth
// across multiple covering grants (facts.go's effectiveDepth) — not derivable
// by sorting the strings themselves, since "facts" < "full" < "summary"
// alphabetically is not the permissiveness order. Panics on an invalid depth:
// every caller is expected to have already passed depth through ValidDepth
// (at write time) or to be reading it back from a column the DB CHECK
// constraint already restricts to these three values.
func depthRank(depth string) int {
	switch depth {
	case "summary":
		return 0
	case "facts":
		return 1
	case "full":
		return 2
	default:
		panic(fmt.Sprintf("store: depthRank: invalid depth %q", depth))
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
// as the insert (see logAudit's doc comment). This store method itself only
// requires actor to be non-empty; it does not authenticate it. The guarantee that
// decided_by/approved_by/revoked_by is the authenticated reviewer token's identity
// (internal/api's requireAuth), never client-supplied, holds for the REST API call
// path specifically — internal/api/grants.go passes reviewerFromContext(...).Label,
// not a request-body field. Other callers of this store method (tests, any future
// non-HTTP caller) can pass any string. Found in review.
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
// active (non-revoked, unexpired) memory-kind grants. This is what read-with-scope-
// check checks requested scopes against, and what the bouncer's dedupe/target-fact
// visibility checks gate on. kind = memory is enforced in the query itself: before
// that filter existed, a capability-only grant (e.g. git.sign:...) silently also
// authorized memory reads/writes over the same scope string — a confused-deputy gap
// introduced when the kind discriminator landed, closed here rather than left for
// GrantedScopeDepths (below) to be the only place that gets it right.
func (s *Store) GrantedScopes(ctx context.Context, subject string) ([]string, error) {
	scopes, err := s.q.GrantedScopes(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("store: granted scopes: %w", err)
	}
	return scopes, nil
}

// GrantedScopeDepths returns each of subject's currently active memory-kind scope
// grants paired with that grant's depth, for depth-aware reads (SearchFacts).
// Unlike GrantedScopes this doesn't collapse to a deduped flat list: a subject can
// hold more than one active grant covering the same or overlapping scope at
// different depths (e.g. a broad long-lived grant and a narrower recent one), and
// the caller needs every covering grant's depth to compute an effective depth per
// fact — see facts.go's effectiveDepth for the composition rule.
func (s *Store) GrantedScopeDepths(ctx context.Context, subject string) ([]GrantedScope, error) {
	rows, err := s.q.GrantedScopeDepths(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("store: granted scope depths: %w", err)
	}
	out := make([]GrantedScope, len(rows))
	for i, r := range rows {
		out[i] = GrantedScope{Scope: r.Scope, Depth: depthOrEmpty(r.Depth)}
	}
	return out, nil
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

// RenewGrant extends grantID's expiry to time.Now().Add(ttl), symmetric to
// RevokeGrant. ttl is required — unlike CreateGrant's optional ttl, renewing
// into "no expiry" would defeat the whole TTL-bounded security property
// renewal exists to preserve (renewal cost is what determines viable TTL
// length; see the batch's own framing of this as a security property, not a
// convenience). Only a currently-active grant (not revoked, not already past
// its expiry) can be renewed: renewal is meant to be a lightweight
// continuation of an already-live authorization, not a way to reinstate one
// that already lapsed unnoticed — a lapsed grant needs a fresh CreateGrant
// decision instead. actor is who's renewing it — required, logged to
// audit_log atomically with the renewal; see CreateGrant's doc comment for
// the same self-reported-identity caveat.
func (s *Store) RenewGrant(ctx context.Context, grantID string, ttl time.Duration, actor string) (Grant, error) {
	if actor == "" {
		return Grant{}, fmt.Errorf("store: actor must not be empty")
	}
	if ttl <= 0 {
		return Grant{}, fmt.Errorf("store: ttl must be positive")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Grant{}, fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op if already committed
	qtx := s.q.WithTx(tx)

	newExpiry := time.Now().Add(ttl)
	row, err := qtx.RenewGrant(ctx, sqlcgen.RenewGrantParams{ID: grantID, ExpiresAt: toTimestamptz(&newExpiry)})
	if err != nil {
		return Grant{}, fmt.Errorf("store: grant %s not found, revoked, or already expired: %w", grantID, err)
	}

	scopes, err := qtx.ListGrantScopes(ctx, grantID)
	if err != nil {
		return Grant{}, fmt.Errorf("store: list grant scopes: %w", err)
	}

	if err := logAudit(ctx, qtx, "grant_renewed", actor, nil, &grantID, nil, nil, scopes); err != nil {
		return Grant{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Grant{}, fmt.Errorf("store: commit grant renewal: %w", err)
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

// ListGrantsNearingExpiry returns every currently-active grant (not revoked,
// not already expired) whose expiry falls at or before before — the backing
// query for the SSE stream's grant_expiring event (internal/api/events.go).
// Subject-agnostic like ListStagedDiffs/ListGrantRequests, matching v0's
// single-operator scope.
func (s *Store) ListGrantsNearingExpiry(ctx context.Context, before time.Time) ([]Grant, error) {
	rows, err := s.q.ListGrantsNearingExpiry(ctx, toTimestamptz(&before))
	if err != nil {
		return nil, fmt.Errorf("store: list grants nearing expiry: %w", err)
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
