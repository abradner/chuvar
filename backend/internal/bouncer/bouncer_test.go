package bouncer

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/abradner/chuvar/backend/internal/db"
	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/scope"
	"github.com/abradner/chuvar/backend/internal/store"
)

// fakeClassifier lets tests control what Classify returns without depending on
// PassthroughClassifier's always-nil behavior.
type fakeClassifier struct {
	scopes []scope.Scope
	err    error
}

func (f fakeClassifier) Classify(context.Context, string) ([]scope.Scope, error) {
	return f.scopes, f.err
}

type fakeEmbedder struct {
	vec []float32
	err error
}

func (f fakeEmbedder) Embed(context.Context, string) ([]float32, error) {
	return f.vec, f.err
}

// wantValidationError fails the test unless err is non-nil and satisfies
// errors.As against *ValidationError — the taxonomy propose_write (mcptools)
// relies on to decide what's safe to show an agent verbatim.
func wantValidationError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("want a *ValidationError, got nil")
	}
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("err = %v (%T), want it to satisfy errors.As(err, &ValidationError{})", err, err)
	}
}

// wantNotValidationError fails the test unless err is non-nil and does NOT
// satisfy errors.As against *ValidationError — these are the failure paths
// (misconfiguration, Classifier/Embedder/Store failures) that must stay masked
// by mcptools' generic toolError, since they can carry internal details a
// ValidationError is allowed to skip masking for.
func wantNotValidationError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("want an error, got nil")
	}
	var verr *ValidationError
	if errors.As(err, &verr) {
		t.Fatalf("err = %v: satisfies errors.As(err, &ValidationError{}), want it to stay masked (not a caller-input failure)", err)
	}
}

func TestProposeWrite_NoScopesIsError(t *testing.T) {
	b := New(nil, embed.Stub{}, PassthroughClassifier{})
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", nil, nil)
	wantValidationError(t, err)
}

func TestProposeWrite_InvalidScopeIsError(t *testing.T) {
	b := New(nil, embed.Stub{}, PassthroughClassifier{})
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", []scope.Scope{"Not Valid"}, nil)
	wantValidationError(t, err)
}

func TestProposeWrite_EmptyContentIsError(t *testing.T) {
	b := New(nil, embed.Stub{}, PassthroughClassifier{})
	_, err := b.ProposeWrite(context.Background(), "agent-a", "", []scope.Scope{"identity.basic"}, nil)
	wantValidationError(t, err)
}

func TestProposeWrite_NilClassifierReturnsErrorNotPanic(t *testing.T) {
	b := &Bouncer{Store: nil, Embedder: embed.Stub{}, Classifier: nil}
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", []scope.Scope{"identity.basic"}, nil)
	// Misconfiguration, not a caller mistake — must stay masked.
	wantNotValidationError(t, err)
}

func TestProposeWrite_NilEmbedderReturnsErrorNotPanic(t *testing.T) {
	b := &Bouncer{Store: nil, Embedder: nil, Classifier: PassthroughClassifier{}}
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", []scope.Scope{"identity.basic"}, nil)
	wantNotValidationError(t, err)
}

func TestProposeWrite_NilStoreReturnsErrorNotPanic(t *testing.T) {
	b := &Bouncer{Store: nil, Embedder: embed.Stub{}, Classifier: PassthroughClassifier{}}
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", []scope.Scope{"identity.basic"}, nil)
	wantNotValidationError(t, err)
}

type emptySliceClassifier struct{}

func (emptySliceClassifier) Classify(context.Context, string) ([]scope.Scope, error) {
	return []scope.Scope{}, nil
}

func TestProposeWrite_ClassifierNonNilEmptySliceOverridesCaller(t *testing.T) {
	// A non-nil empty slice is a real classification ("no scopes apply"), distinct
	// from nil ("defer to caller") — see Classifier's doc comment. It must override
	// the caller's proposed scopes down to nothing, not be treated as "no opinion."
	b := New(nil, embed.Stub{}, emptySliceClassifier{})
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", []scope.Scope{"identity.basic"}, nil)
	// "No scopes proposed or classified" is still safe/actionable even though the
	// classifier (not the caller) drove it here — see the ValidationError call
	// site's comment in bouncer.go.
	wantValidationError(t, err)
}

func TestProposeWrite_ClassifierErrorIsWrapped(t *testing.T) {
	b := New(nil, embed.Stub{}, fakeClassifier{err: errors.New("classifier unavailable")})
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", []scope.Scope{"identity.basic"}, nil)
	// A Classifier failure isn't caller input — could wrap an external service's
	// error text — so it must stay masked.
	wantNotValidationError(t, err)
}

type invalidScopeClassifier struct{}

func (invalidScopeClassifier) Classify(context.Context, string) ([]scope.Scope, error) {
	return []scope.Scope{"Not Valid"}, nil
}

func TestProposeWrite_ClassifierProducedInvalidScopeIsNotValidationError(t *testing.T) {
	// A malformed scope from the CLASSIFIER (as opposed to one the caller
	// proposed directly) is this service's own component misbehaving, not
	// something the calling agent can fix by resubmitting — so, unlike the
	// caller-supplied-scope case, it must stay masked rather than shown verbatim.
	b := New(nil, embed.Stub{}, invalidScopeClassifier{})
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", []scope.Scope{"identity.basic"}, nil)
	wantNotValidationError(t, err)
}

func TestProposeWrite_EmbedderErrorIsWrapped(t *testing.T) {
	// Store is nil and must never be reached: the embed error should short-circuit
	// before ProposeWrite touches the store, or this panics instead of failing
	// cleanly.
	b := New(nil, fakeEmbedder{err: errors.New("embedding provider unavailable")}, PassthroughClassifier{})
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", []scope.Scope{"identity.basic"}, nil)
	// An Embedder failure isn't caller input either — same reasoning as the
	// Classifier failure case above.
	wantNotValidationError(t, err)
}

func TestProposeWrite_ClassifierOverridesProposedScopes(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping bouncer integration test")
	}
	if err := db.Migrate(url); err != nil {
		t.Fatalf("db.Migrate() error = %v", err)
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatalf("db.Open() error = %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, grant_requests, data_keys, propose_write_rate_limits`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	// This is the one piece of real logic ProposeWrite adds beyond validation and
	// plumbing — the classifier, when it has an opinion, wins over whatever the
	// caller proposed. PassthroughClassifier always returns nil, so this branch
	// (bouncer.go's `if len(classified) > 0 { scopes = classified }`) was
	// previously never exercised by any test.
	classifierScopes := []scope.Scope{"identity.professional"}
	b := New(store.New(pool), embed.Stub{}, fakeClassifier{scopes: classifierScopes})

	diff, err := b.ProposeWrite(ctx, "agent-a", "user works as a software engineer",
		[]scope.Scope{"preferences.coffee"}, nil) // caller proposes the "wrong" scope
	if err != nil {
		t.Fatalf("ProposeWrite() error = %v", err)
	}

	want := []string{"identity.professional"}
	if !reflect.DeepEqual(diff.ProposedScopes, want) {
		t.Fatalf("ProposeWrite() staged scopes = %v, want the classifier's %v (not the caller-proposed %v)",
			diff.ProposedScopes, want, []scope.Scope{"preferences.coffee"})
	}
}

func TestProposeWrite_DuplicateScopesDedupedSoCommitSucceeds(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping bouncer integration test")
	}
	if err := db.Migrate(url); err != nil {
		t.Fatalf("db.Migrate() error = %v", err)
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatalf("db.Open() error = %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, grant_requests, data_keys, propose_write_rate_limits`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := store.New(pool)
	b := New(st, embed.Stub{}, PassthroughClassifier{})

	diff, err := b.ProposeWrite(ctx, "agent-a", "user's favorite tea is earl grey",
		[]scope.Scope{"preferences.tea", "preferences.tea"}, nil)
	if err != nil {
		t.Fatalf("ProposeWrite() error = %v", err)
	}
	if len(diff.ProposedScopes) != 1 {
		t.Fatalf("ProposeWrite() staged scopes = %v, want deduped to 1", diff.ProposedScopes)
	}

	// Without deduping in ProposeWrite, this would fail here instead: CommitDiff
	// inserts one fact_scopes row per proposed scope, and (fact_id, scope) is that
	// table's primary key.
	if _, err := st.CommitDiff(ctx, diff.ID, "human-reviewer", nil, ""); err != nil {
		t.Fatalf("CommitDiff() error = %v (duplicate scopes not deduped before staging?)", err)
	}
}

func TestProposeWrite_TargetOutsideSubjectGrantsRejected(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping bouncer integration test")
	}
	if err := db.Migrate(url); err != nil {
		t.Fatalf("db.Migrate() error = %v", err)
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatalf("db.Open() error = %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, grant_requests, data_keys, propose_write_rate_limits`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := store.New(pool)
	b := New(st, embed.Stub{}, PassthroughClassifier{})

	// agent-a proposes and commits a fact under a scope agent-b has no grant for.
	first, err := b.ProposeWrite(ctx, "agent-a", "user's medical condition is confidential",
		[]scope.Scope{"identity.medical"}, nil)
	if err != nil {
		t.Fatalf("ProposeWrite() (first) error = %v", err)
	}
	fact, err := st.CommitDiff(ctx, first.ID, "human-reviewer", nil, "")
	if err != nil {
		t.Fatalf("CommitDiff() (first) error = %v", err)
	}

	// agent-b has an active grant, just not one covering identity.medical — this
	// proves the rejection is scope-specific, not "agent-b has zero grants."
	if _, err := st.CreateGrant(ctx, "agent-b", []string{"preferences.coffee"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	// This is the actual wiring under test: ProposeWrite must fetch agent-b's real
	// granted scopes (via Store.GrantedScopes) and pass them through to
	// Store.ProposeDiff, which is what rejects the out-of-grant target. A unit
	// test with a fake/hardcoded scopes list wouldn't catch a wiring mistake here
	// (wrong subject, wrong variable, argument left out) the way this does.
	_, err = b.ProposeWrite(ctx, "agent-b", "innocuous-looking replacement content",
		[]scope.Scope{"preferences.coffee"}, &fact.ID)
	if err == nil {
		t.Fatal("ProposeWrite() targeting a fact outside the subject's actual grants: want error, got nil")
	}
	// This rejection comes back from store.ProposeDiff, wrapped by ProposeWrite's
	// generic "bouncer: stage diff: %w" — it must NOT satisfy errors.As against
	// ValidationError, or mcptools.propose_write would show a store-originated
	// error verbatim, the exact leak the taxonomy exists to prevent.
	wantNotValidationError(t, err)
}

func TestProposeWrite_EndToEnd(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping bouncer integration test")
	}
	if err := db.Migrate(url); err != nil {
		t.Fatalf("db.Migrate() error = %v", err)
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatalf("db.Open() error = %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, grant_requests, data_keys, propose_write_rate_limits`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	b := New(store.New(pool), embed.Stub{}, PassthroughClassifier{})

	diff, err := b.ProposeWrite(ctx, "agent-a", "user prefers dark roast coffee", []scope.Scope{"preferences.coffee"}, nil)
	if err != nil {
		t.Fatalf("ProposeWrite() error = %v", err)
	}
	if diff.Status != store.DiffPending {
		t.Errorf("diff.Status = %v, want pending", diff.Status)
	}
	if diff.DedupeVerdict == nil || *diff.DedupeVerdict != store.DedupeNovel {
		t.Errorf("diff.DedupeVerdict = %v, want novel", diff.DedupeVerdict)
	}
}

// New must leave RateLimit/RateLimitWindow at a working, non-zero default —
// store.CheckProposeWriteRateLimit treats a non-positive limit or window as a
// misconfiguration and fails closed (rejects the proposal), so a caller that
// doesn't explicitly wire config.Config's PROPOSE_WRITE_RATE_LIMIT* values
// through must still get a Bouncer that actually works, not one that silently
// rejects every proposal.
func TestNew_DefaultsRateLimitToAWorkingValue(t *testing.T) {
	b := New(nil, embed.Stub{}, PassthroughClassifier{})
	if b.RateLimit <= 0 {
		t.Errorf("New() RateLimit = %d, want a positive default", b.RateLimit)
	}
	if b.RateLimitWindow <= 0 {
		t.Errorf("New() RateLimitWindow = %v, want a positive default", b.RateLimitWindow)
	}
}

// TestProposeWrite_RateLimitExceededIsDistinguishable pins the ticket's core
// requirement: ProposeWrite requires no grant at all (deliberately — a
// brand-new agent has to propose before it holds anything to be granted), so
// without a rate limit any configured MCP_SUBJECT can stage unlimited diffs
// against the human review queue. Once the configured limit is hit, the error
// must be errors.Is-distinguishable as store.ErrRateLimited (not just "some
// error"), because mcptools/propose_write.go depends on that to surface it as
// a structured RATE_LIMITED status rather than masking it like every other
// failure.
func TestProposeWrite_RateLimitExceededIsDistinguishable(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping bouncer integration test")
	}
	if err := db.Migrate(url); err != nil {
		t.Fatalf("db.Migrate() error = %v", err)
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatalf("db.Open() error = %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, grant_requests, data_keys, propose_write_rate_limits`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	b := New(store.New(pool), embed.Stub{}, PassthroughClassifier{})
	b.RateLimit = 1
	b.RateLimitWindow = time.Hour

	if _, err := b.ProposeWrite(ctx, "agent-a", "first fact, within the limit", []scope.Scope{"preferences.coffee"}, nil); err != nil {
		t.Fatalf("ProposeWrite() (first, within limit) error = %v", err)
	}

	_, err = b.ProposeWrite(ctx, "agent-a", "second fact, over the limit", []scope.Scope{"preferences.coffee"}, nil)
	if !errors.Is(err, store.ErrRateLimited) {
		t.Fatalf("ProposeWrite() over the limit: err = %v, want errors.Is(err, store.ErrRateLimited)", err)
	}

	// A subject with no rate-limit history of its own must not be affected by
	// agent-a's — otherwise the control keyed wrong and throttles an
	// uninvolved subject, which is its own denial-of-service.
	if _, err := b.ProposeWrite(ctx, "agent-b", "agent-b's own, unrelated fact", []scope.Scope{"preferences.tea"}, nil); err != nil {
		t.Fatalf("ProposeWrite() for a different subject: unexpected error = %v (agent-a's limit leaked across subjects)", err)
	}
}
