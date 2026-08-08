package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/abradner/chuvar/backend/internal/store/sqlcgen"
)

// ErrRateLimited signals that a subject has exceeded propose_write's per-subject
// rate limit within the current window. It's a distinguishable, expected outcome
// — mcptools/propose_write.go surfaces it as status=RATE_LIMITED rather than
// masking it behind the generic "internal error" every other bouncer/store error
// gets, the same shape read_with_scope_check already uses for insufficient_scope
// (a caller-actionable signal, not an opaque failure).
var ErrRateLimited = errors.New("store: propose_write rate limit exceeded")

// CheckProposeWriteRateLimit increments subject's proposal counter for the
// current fixed window and returns ErrRateLimited if the incremented count
// exceeds limit. subject must be the authenticated MCP_SUBJECT bound at server
// construction (see mcptools.Register's doc comment) — never a client-supplied
// value — since keying this on anything the caller controls would let a subject
// dodge its own limit by lying about who it is.
//
// Fixed-window, not sliding: the counter resets at each window boundary rather
// than tracking a rolling N-per-window across boundaries, so a caller that times
// requests to straddle a boundary can in the worst case get up to ~2x limit
// through in a short span (limit requests just before window N ends, limit more
// just after N+1 starts). That's an accepted looseness for what CLAUDE.md's
// ticket calls a tripwire, not an admission-control guarantee — a sliding
// window would need either a per-request log with a COUNT(*) WHERE
// created_at > now()-window query (unbounded row growth needing its own
// cleanup) or a more complex bucketed approximation, and neither is justified
// as the first defence against queue-flooding.
//
// The increment and the limit check happen as a single atomic UPSERT
// (IncrementProposeWriteRateLimit: INSERT ... ON CONFLICT ... DO UPDATE ...
// RETURNING count), not a separate SELECT-then-write: two concurrent proposals
// from the same subject racing a read-modify-write could otherwise both read
// the pre-increment count, both pass the limit check, and both get admitted —
// exactly the race this function exists to close. Postgres serializes
// concurrent upserts against the same (subject, window_start) row via that
// row's own lock (the second waits for the first to commit, then sees its
// incremented value), so the race closes at the database, not with an
// application-level lock — and it only ever serializes a subject against
// itself: concurrent proposals from different subjects touch different rows
// and never contend, so one subject's burst cannot throttle another's.
//
// Fails closed: a database error here is returned as-is, not swallowed into
// "allow" — CLAUDE.md's fail-closed principle is explicit that an ambiguous
// state (here, "can't determine the current count") must block the proposal,
// not silently let it through. A non-positive limit or window is likewise
// rejected rather than reinterpreted as "unlimited," which matters because
// Bouncer's zero-value RateLimit/RateLimitWindow (e.g. a struct literal built
// without bouncer.New) would otherwise mean "no rate limiting" instead of "the
// caller forgot to configure this."
func (s *Store) CheckProposeWriteRateLimit(ctx context.Context, subject string, limit int, window time.Duration) error {
	if limit <= 0 {
		return fmt.Errorf("store: rate limit must be positive, got %d", limit)
	}
	if window <= 0 {
		return fmt.Errorf("store: rate limit window must be positive, got %s", window)
	}

	windowStart := time.Now().UTC().Truncate(window)
	count, err := s.q.IncrementProposeWriteRateLimit(ctx, sqlcgen.IncrementProposeWriteRateLimitParams{
		Subject:     subject,
		WindowStart: pgtype.Timestamptz{Time: windowStart, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("store: propose_write rate limit: %w", err)
	}
	if int(count) > limit {
		return ErrRateLimited
	}
	return nil
}
