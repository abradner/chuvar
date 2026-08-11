package broker

import (
	"sync"
	"time"
)

// rateLimiter is a per-key sliding-window sign-rate tripwire, operationalizing
// capability-broker.md's open question 5: "TTL is the control, count is an
// anomaly tripwire — hundreds of signatures in a minute is a signal; a dozen
// over a night is normal." Keyed by grant id (not by subject or token) so
// each grant's own burst doesn't consume another grant's budget.
//
// In-process only, by design — matching the 2026-08-09 "sign call consults
// only in-process state" decision: this is a signal about request pattern,
// not a durable record, and restarting brokerd resetting it is an accepted
// cost, not a gap (a restart is already a discontinuity in what the process
// remembers).
type rateLimiter struct {
	limit  int
	window time.Duration

	mu     sync.Mutex
	events map[string][]time.Time
}

// newRateLimiter builds a limiter allowing at most limit events per window,
// per key. limit <= 0 or window <= 0 disables the limiter (every call to
// Allow returns true) — a deployment that hasn't tuned this shouldn't be
// silently blocked by an arbitrary default; cmd/brokerd's own default is
// chosen deliberately (see its doc comment), this constructor just doesn't
// invent one on a caller's behalf.
func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, events: make(map[string][]time.Time)}
}

// Allow reports whether one more event for key is within budget, and records
// it if so. Events outside the current window are pruned on every call —
// this keeps memory bounded to (active grants) x (limit), not to total
// lifetime signing volume.
func (r *rateLimiter) Allow(key string) bool {
	if r.limit <= 0 || r.window <= 0 {
		return true
	}

	now := time.Now()
	cutoff := now.Add(-r.window)

	r.mu.Lock()
	defer r.mu.Unlock()

	kept := r.events[key][:0]
	for _, t := range r.events[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.limit {
		r.events[key] = kept
		return false
	}
	r.events[key] = append(kept, now)
	return true
}
