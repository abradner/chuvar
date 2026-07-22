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
func (s *Store) LogAudit(ctx context.Context, eventType, subject string, factID, grantID, stagedDiffID *string, scopes []string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_log (event_type, subject, fact_id, grant_id, staged_diff_id, scopes)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		eventType, subject, factID, grantID, stagedDiffID, scopes,
	)
	if err != nil {
		return fmt.Errorf("store: log audit event %q: %w", eventType, err)
	}
	return nil
}
