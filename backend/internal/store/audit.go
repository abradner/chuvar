package store

import (
	"context"
	"fmt"
	"time"
)

type AuditEvent struct {
	ID           string
	EventType    string
	Subject      string
	FactID       *string
	GrantID      *string
	StagedDiffID *string
	Scopes       []string
	CreatedAt    time.Time
}

// LogAudit appends an entry to the audit log. Append-only: this package has no
// function that updates or deletes an audit_log row, matching mem0's and Letta's
// separation of audit history from mutable state (Notion §7) — the log records both
// writes and grants being exercised to read, not just mutations.
//
// This runs against the pool directly, so it's for callers with nothing to make it
// atomic with (mcptools' read-path events: "read", "insufficient_scope" — there's
// no mutation to fail-together-with here). Every mutation in this package
// (CommitDiff, CreateGrant, RevokeGrant, RejectDiff) logs its own event through
// logAudit inside its own transaction instead, so the audit row and the mutation
// it describes commit or roll back as one unit — seeing the mutation without a
// corresponding audit row (or vice versa) should never be possible.
func (s *Store) LogAudit(ctx context.Context, eventType, subject string, factID, grantID, stagedDiffID *string, scopes []string) error {
	return logAudit(ctx, s.pool, eventType, subject, factID, grantID, stagedDiffID, scopes)
}

func logAudit(ctx context.Context, q queryer, eventType, subject string, factID, grantID, stagedDiffID *string, scopes []string) error {
	// scopes is NOT NULL DEFAULT '{}' — that default only applies when the column
	// is omitted from the INSERT, not when an explicit NULL is bound, and pgx
	// sends a nil Go slice as SQL NULL rather than an empty array literal. Callers
	// with nothing scope-relevant to log (e.g. a revoke, or a rejection) pass nil
	// for readability; normalize here instead of asking every call site to
	// remember []string{}.
	if scopes == nil {
		scopes = []string{}
	}
	_, err := q.Exec(ctx,
		`INSERT INTO audit_log (event_type, subject, fact_id, grant_id, staged_diff_id, scopes)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		eventType, subject, factID, grantID, stagedDiffID, scopes,
	)
	if err != nil {
		return fmt.Errorf("store: log audit event %q: %w", eventType, err)
	}
	return nil
}
