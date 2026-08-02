package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/abradner/chuvar/backend/internal/store/sqlcgen"
)

type GrantRequestStatus string

const (
	GrantRequestPending  GrantRequestStatus = "pending"
	GrantRequestApproved GrantRequestStatus = "approved"
	GrantRequestDenied   GrantRequestStatus = "denied"
)

type GrantRequest struct {
	ID                  string
	Subject             string
	RequestedScopes     []string
	Kind                GrantKind
	Depth               string // empty for anything other than GrantKindMemory — see Grant.Depth
	RequestedTTLSeconds *int
	Justification       string
	Status              GrantRequestStatus
	CreatedAt           time.Time
	DecidedAt           *time.Time
	DecidedBy           *string
	ResultingGrantID    *string
}

func toInt4(v *int) pgtype.Int4 {
	if v == nil {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: int32(*v), Valid: true}
}

func fromInt4(v pgtype.Int4) *int {
	if !v.Valid {
		return nil
	}
	n := int(v.Int32)
	return &n
}

func toGrantRequest(row sqlcgen.GrantRequest) GrantRequest {
	return GrantRequest{
		ID:                  row.ID,
		Subject:             row.Subject,
		RequestedScopes:     row.RequestedScopes,
		Kind:                GrantKind(row.Kind),
		Depth:               depthOrEmpty(row.Depth),
		RequestedTTLSeconds: fromInt4(row.RequestedTtlSeconds),
		Justification:       row.Justification,
		Status:              GrantRequestStatus(row.Status),
		CreatedAt:           row.CreatedAt,
		DecidedAt:           row.DecidedAt,
		DecidedBy:           row.DecidedBy,
		ResultingGrantID:    row.ResultingGrantID,
	}
}

// RequestGrant stages a grant request for human review — the agent-initiated
// counterpart to CreateGrant, mirroring ProposeDiff's "propose, never write
// directly" shape (AGENTS.md §3.1): nothing here ever creates a real grant. Only
// ApproveGrantRequest does that, and only for a pending request a human decided on.
func (s *Store) RequestGrant(ctx context.Context, subject string, scopes []string, kind, depth string, ttlSeconds *int, justification string) (GrantRequest, error) {
	if len(scopes) == 0 {
		return GrantRequest{}, fmt.Errorf("store: grant request must include at least one scope")
	}
	validKind, depth, err := validateKindAndDepth(kind, depth)
	if err != nil {
		return GrantRequest{}, err
	}
	if subject == "" {
		return GrantRequest{}, fmt.Errorf("store: subject must not be empty")
	}
	// Deduped, not rejected: an agent listing the same scope twice isn't a
	// malformed request worth bouncing back with an error (the same call
	// bouncer.ProposeWrite already makes for a staged diff's proposed scopes,
	// via scope.Dedupe — this mirrors it for the analogous agent-initiated
	// path). Without this, a duplicate here would stage successfully but
	// ApproveGrantRequest's per-scope grant_scopes insert would fail on the
	// (grant_id, scope) primary key, leaving a request that looks valid but
	// can never be approved. Found in review.
	scopes = dedupeStrings(scopes)

	row, err := s.q.InsertGrantRequest(ctx, sqlcgen.InsertGrantRequestParams{
		Subject:             subject,
		RequestedScopes:     scopes,
		Kind:                string(validKind),
		Depth:               nullableDepth(depth),
		RequestedTtlSeconds: toInt4(ttlSeconds),
		Justification:       justification,
	})
	if err != nil {
		return GrantRequest{}, fmt.Errorf("store: insert grant request: %w", err)
	}
	// Built from inputs plus the three generated columns, for the same reason as
	// ProposeDiff: a wide RETURNING would require the agent role to hold SELECT
	// over every subject's justification.
	return GrantRequest{
		ID:                  row.ID,
		Subject:             subject,
		RequestedScopes:     scopes,
		Kind:                validKind,
		Depth:               depth,
		RequestedTTLSeconds: ttlSeconds,
		Justification:       justification,
		Status:              GrantRequestStatus(row.Status),
		CreatedAt:           row.CreatedAt,
	}, nil
}

// ListGrantRequests returns requests in the given status, oldest first (review
// queue order) — same convention as ListStagedDiffs.
func (s *Store) ListGrantRequests(ctx context.Context, status GrantRequestStatus) ([]GrantRequest, error) {
	rows, err := s.q.ListGrantRequests(ctx, string(status))
	if err != nil {
		return nil, fmt.Errorf("store: list grant requests: %w", err)
	}
	out := make([]GrantRequest, len(rows))
	for i, r := range rows {
		out[i] = toGrantRequest(r)
	}
	return out, nil
}

// GetGrantRequest fetches a single request by ID.
func (s *Store) GetGrantRequest(ctx context.Context, id string) (GrantRequest, error) {
	row, err := s.q.GetGrantRequest(ctx, id)
	if err != nil {
		return GrantRequest{}, fmt.Errorf("store: get grant request %s: %w", id, err)
	}
	return toGrantRequest(row), nil
}

// ApproveGrantRequest approves a pending request and atomically creates the real
// grant it describes — the only path, alongside CreateGrant itself, that ever
// inserts into `grants`. decidedBy is the authenticated reviewer approving it.
func (s *Store) ApproveGrantRequest(ctx context.Context, id, decidedBy string) (Grant, error) {
	if decidedBy == "" {
		return Grant{}, fmt.Errorf("store: decidedBy must not be empty")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Grant{}, fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op if already committed
	qtx := s.q.WithTx(tx)

	req, err := qtx.LoadGrantRequestForUpdate(ctx, id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Grant{}, fmt.Errorf("store: grant request %s not found", id)
		}
		return Grant{}, fmt.Errorf("store: load grant request %s: %w", id, err)
	}
	if req.Status != string(GrantRequestPending) {
		return Grant{}, fmt.Errorf("store: grant request %s is not pending (status=%s)", id, req.Status)
	}

	var expiresAt *time.Time
	if ttl := fromInt4(req.RequestedTtlSeconds); ttl != nil {
		t := time.Now().Add(time.Duration(*ttl) * time.Second)
		expiresAt = &t
	}

	grantRow, err := qtx.InsertGrant(ctx, sqlcgen.InsertGrantParams{
		Subject:   req.Subject,
		Kind:      req.Kind,
		Depth:     req.Depth,
		ExpiresAt: toTimestamptz(expiresAt),
	})
	if err != nil {
		return Grant{}, fmt.Errorf("store: insert grant from request: %w", err)
	}
	for _, sc := range req.RequestedScopes {
		if err := qtx.InsertGrantScope(ctx, sqlcgen.InsertGrantScopeParams{GrantID: grantRow.ID, Scope: sc}); err != nil {
			return Grant{}, fmt.Errorf("store: insert grant scope %q: %w", sc, err)
		}
	}

	db := decidedBy
	rows, err := qtx.ApproveGrantRequest(ctx, sqlcgen.ApproveGrantRequestParams{
		ID:               id,
		DecidedBy:        &db,
		ResultingGrantID: &grantRow.ID,
	})
	if err != nil {
		return Grant{}, fmt.Errorf("store: mark grant request approved: %w", err)
	}
	if rows == 0 {
		// Narrows the same concurrent-decision race CommitDiff's re-check
		// narrows (see that function's doc comment): the FOR UPDATE above
		// already serializes concurrent approvals of this row, so this can only
		// fire if the row's status changed between the lock and this UPDATE by
		// a path that doesn't take the same lock — treated as a bug, not a
		// normal race, since none exists in this package today.
		return Grant{}, fmt.Errorf("store: grant request %s was not pending at approval time", id)
	}

	if err := logAudit(ctx, qtx, "grant_request_approved", decidedBy, nil, &grantRow.ID, nil, &id, req.RequestedScopes); err != nil {
		return Grant{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Grant{}, fmt.Errorf("store: commit grant request approval: %w", err)
	}

	return Grant{
		ID:        grantRow.ID,
		Subject:   grantRow.Subject,
		Scopes:    req.RequestedScopes,
		Kind:      GrantKind(grantRow.Kind),
		Depth:     depthOrEmpty(grantRow.Depth),
		CreatedAt: grantRow.CreatedAt,
		ExpiresAt: grantRow.ExpiresAt,
		RevokedAt: grantRow.RevokedAt,
	}, nil
}

// DenyGrantRequest marks a pending request denied. Never touches `grants`.
func (s *Store) DenyGrantRequest(ctx context.Context, id, decidedBy string) error {
	if decidedBy == "" {
		return fmt.Errorf("store: decidedBy must not be empty")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op if already committed
	qtx := s.q.WithTx(tx)

	db := decidedBy
	rows, err := qtx.DenyGrantRequest(ctx, sqlcgen.DenyGrantRequestParams{ID: id, DecidedBy: &db})
	if err != nil {
		return fmt.Errorf("store: deny grant request: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("store: grant request %s is not pending", id)
	}

	if err := logAudit(ctx, qtx, "grant_request_denied", decidedBy, nil, nil, nil, &id, nil); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit grant request denial: %w", err)
	}
	return nil
}

// dedupeStrings returns s with exact duplicates removed, preserving
// first-appearance order. A package-local equivalent of internal/scope's
// Dedupe rather than importing that package here: store treats scopes as
// plain strings throughout (CreateGrant, InsertGrantScope) — validating their
// shape is the API/mcptools boundary's job, not this layer's.
func dedupeStrings(s []string) []string {
	seen := make(map[string]bool, len(s))
	out := make([]string, 0, len(s))
	for _, v := range s {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
