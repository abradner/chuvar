package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCheckProposeWriteRateLimit_AllowsUpToLimit(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := s.CheckProposeWriteRateLimit(ctx, "agent-a", 3, time.Minute); err != nil {
			t.Fatalf("call %d within limit: unexpected error = %v", i, err)
		}
	}
}

func TestCheckProposeWriteRateLimit_BlocksOverLimit(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := s.CheckProposeWriteRateLimit(ctx, "agent-a", 3, time.Minute); err != nil {
			t.Fatalf("call %d within limit: unexpected error = %v", i, err)
		}
	}
	if err := s.CheckProposeWriteRateLimit(ctx, "agent-a", 3, time.Minute); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("call past the limit: err = %v, want ErrRateLimited", err)
	}
}

// A shared limit keyed wrong (ignoring subject, or keyed on something a caller
// controls) would let one subject's activity throttle another's — its own
// denial-of-service against a legitimate agent. This proves the limit is
// tracked independently per subject.
func TestCheckProposeWriteRateLimit_IsolatedPerSubject(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if err := s.CheckProposeWriteRateLimit(ctx, "agent-a", 1, time.Minute); err != nil {
		t.Fatalf("agent-a first call: unexpected error = %v", err)
	}
	if err := s.CheckProposeWriteRateLimit(ctx, "agent-a", 1, time.Minute); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("agent-a second call: err = %v, want ErrRateLimited", err)
	}

	// agent-b has never called before; its own limit of 1 must still be fresh.
	if err := s.CheckProposeWriteRateLimit(ctx, "agent-b", 1, time.Minute); err != nil {
		t.Fatalf("agent-b first call: unexpected error = %v (agent-a's limit leaked across subjects)", err)
	}
}

// A non-positive limit or window has no sane interpretation as "the caller
// wants this" — it's far more likely a construction bug (e.g. a Bouncer built
// as a struct literal without going through bouncer.New, leaving
// RateLimit/RateLimitWindow at their zero values). CLAUDE.md's fail-closed
// principle says an ambiguous configuration state must block the proposal, not
// be silently reinterpreted as "no limit."
func TestCheckProposeWriteRateLimit_NonPositiveConfigFailsClosed(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if err := s.CheckProposeWriteRateLimit(ctx, "agent-a", 0, time.Minute); err == nil {
		t.Fatal("limit=0: want an error (fail closed), got nil")
	}
	if err := s.CheckProposeWriteRateLimit(ctx, "agent-a", -1, time.Minute); err == nil {
		t.Fatal("limit=-1: want an error (fail closed), got nil")
	}
	if err := s.CheckProposeWriteRateLimit(ctx, "agent-a", 5, 0); err == nil {
		t.Fatal("window=0: want an error (fail closed), got nil")
	}
	if err := s.CheckProposeWriteRateLimit(ctx, "agent-a", 5, -time.Minute); err == nil {
		t.Fatal("negative window: want an error (fail closed), got nil")
	}
}

// The whole point of the atomic UPSERT (INSERT ... ON CONFLICT ... DO UPDATE
// ... RETURNING count) rather than a separate SELECT-then-write: two
// concurrent proposals from the same subject racing a read-modify-write could
// otherwise both read the pre-increment count, both pass the limit check, and
// both get admitted — a burst let through right at the boundary this function
// exists to guard. This pins that closed: of N goroutines racing against a
// limit of 1, exactly one may succeed.
func TestCheckProposeWriteRateLimit_ConcurrentCallsAreSerialized(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	const attempts = 10
	const limit = 1

	var wg sync.WaitGroup
	results := make([]error, attempts)
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			results[i] = s.CheckProposeWriteRateLimit(ctx, "agent-a", limit, time.Minute)
		}(i)
	}
	wg.Wait()

	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrRateLimited) {
			t.Fatalf("unexpected error (not ErrRateLimited): %v", err)
		}
	}
	if successes != limit {
		t.Fatalf("%d of %d concurrent calls against a limit of %d succeeded, want exactly %d — the race the atomic upsert exists to close let a burst through",
			successes, attempts, limit, limit)
	}
}
