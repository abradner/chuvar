package store

import (
	"context"
	"fmt"
)

// EnrollmentLatchSet reports whether this deployment has ever had a second
// factor enrolled, as recorded by the durable append-only latch (see the
// enrollment_latch migration). createToken (internal/api/tokens.go) ORs this
// with the live ever-enrolled counts: the counts read mutable factor rows and
// the documented break-glass recovery clears them, but the latch is not touched
// by that recovery, so the token self-mint gate stays closed across a factor
// reset. That is the whole point — principle 12, "the enrollment gate counts
// ever-enrolled" — and it is why nothing here exposes a way to clear the latch:
// resetting it is a deliberate, separately-documented operator action
// (docs/operations.md), never a store method an API path could reach.
func (s *Store) EnrollmentLatchSet(ctx context.Context) (bool, error) {
	latched, err := s.q.EnrollmentLatchSet(ctx)
	if err != nil {
		return false, fmt.Errorf("store: check enrollment latch: %w", err)
	}
	return latched, nil
}
