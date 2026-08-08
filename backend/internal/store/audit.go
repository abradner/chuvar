package store

import (
	"context"
	"fmt"
	"time"

	"github.com/abradner/chuvar/backend/internal/store/sqlcgen"
)

type AuditEvent struct {
	ID             string
	EventType      string
	Subject        string
	FactID         *string
	GrantID        *string
	StagedDiffID   *string
	GrantRequestID *string
	Scopes         []string
	Detail         []byte
	CreatedAt      time.Time
}

// ReadFactDisclosure is one fact's audit-relevant disclosure detail for a "read"
// event: the fact returned, and the depth it was actually disclosed at.
//
// This is per-fact, not per-call, because depth is: effectiveDepth (facts.go) is
// computed per fact against that fact's own scope tags intersected with the
// caller's grants, so a single read_with_scope_check call can return some facts
// at "full" and others at "summary" in the same response. Recording one depth
// for the whole call would silently claim uniform disclosure that never
// happened.
type ReadFactDisclosure struct {
	FactID string `json:"fact_id"`
	Depth  string `json:"depth"`
}

// ReadAuditDetail is the JSON shape written to audit_log.detail for "read"
// events. Before this existed, a "read" row recorded only the subject's granted
// scopes at read time — it could answer "what was this agent allowed to see,"
// but not "what did it actually see, and at what fidelity" — the question that
// matters after a suspected compromise. One row per read call (not one row per
// fact) to keep audit volume proportional to read volume, which is already the
// highest-frequency audited event.
type ReadAuditDetail struct {
	Facts []ReadFactDisclosure `json:"facts"`
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
// logAudit inside its own transaction instead (via q.WithTx), so the audit row and
// the mutation it describes commit or roll back as one unit — seeing the mutation
// without a corresponding audit row (or vice versa) should never be possible.
//
// detail is raw JSON (nil for events with nothing structured to record — most of
// them); see ReadAuditDetail for the one event type that currently uses it.
func (s *Store) LogAudit(ctx context.Context, eventType, subject string, factID, grantID, stagedDiffID, grantRequestID *string, scopes []string, detail []byte) error {
	return logAudit(ctx, s.q, eventType, subject, factID, grantID, stagedDiffID, grantRequestID, scopes, detail)
}

// logAudit's grantRequestID makes a grant_request_denied row attributable to
// which request was denied — before this column existed, a denial audit row
// carried event_type and the actor and nothing else, so multiple denials by
// the same reviewer were indistinguishable without cross-referencing the
// mutable grant_requests table by timestamp (flagged in review on #21).
// grant_request_approved rows already linked forward via grantID (the newly
// created grant); this adds the matching backward link for both outcomes.
func logAudit(ctx context.Context, q *sqlcgen.Queries, eventType, subject string, factID, grantID, stagedDiffID, grantRequestID *string, scopes []string, detail []byte) error {
	// scopes is NOT NULL DEFAULT '{}' — that default only applies when the column
	// is omitted from the INSERT, not when an explicit NULL is bound, and pgx
	// sends a nil Go slice as SQL NULL rather than an empty array literal. Callers
	// with nothing scope-relevant to log (e.g. a revoke, or a rejection) pass nil
	// for readability; normalize here instead of asking every call site to
	// remember []string{}.
	if scopes == nil {
		scopes = []string{}
	}
	// detail is NOT NULL DEFAULT '{}'::jsonb — same story as scopes above: an
	// explicit NULL bind would override that default, so callers with nothing
	// structured to record (nearly all of them) pass nil for readability and get
	// the column's own empty-object default instead.
	if detail == nil {
		detail = []byte("{}")
	}
	err := q.InsertAuditLog(ctx, sqlcgen.InsertAuditLogParams{
		EventType:      eventType,
		Subject:        subject,
		FactID:         factID,
		GrantID:        grantID,
		StagedDiffID:   stagedDiffID,
		GrantRequestID: grantRequestID,
		Scopes:         scopes,
		Detail:         detail,
	})
	if err != nil {
		return fmt.Errorf("store: log audit event %q: %w", eventType, err)
	}
	return nil
}
