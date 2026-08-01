package bouncer

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

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

func TestProposeWrite_NoScopesIsError(t *testing.T) {
	b := New(nil, embed.Stub{}, PassthroughClassifier{})
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", nil, nil)
	if err == nil {
		t.Fatal("ProposeWrite() with no proposed/classified scopes: want error, got nil")
	}
}

func TestProposeWrite_InvalidScopeIsError(t *testing.T) {
	b := New(nil, embed.Stub{}, PassthroughClassifier{})
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", []scope.Scope{"Not Valid"}, nil)
	if err == nil {
		t.Fatal("ProposeWrite() with malformed scope: want error, got nil")
	}
}

func TestProposeWrite_EmptyContentIsError(t *testing.T) {
	b := New(nil, embed.Stub{}, PassthroughClassifier{})
	_, err := b.ProposeWrite(context.Background(), "agent-a", "", []scope.Scope{"identity.basic"}, nil)
	if err == nil {
		t.Fatal("ProposeWrite() with empty content: want error, got nil")
	}
}

func TestProposeWrite_NilClassifierReturnsErrorNotPanic(t *testing.T) {
	b := &Bouncer{Store: nil, Embedder: embed.Stub{}, Classifier: nil}
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", []scope.Scope{"identity.basic"}, nil)
	if err == nil {
		t.Fatal("ProposeWrite() with nil Classifier: want error, got nil")
	}
}

func TestProposeWrite_NilEmbedderReturnsErrorNotPanic(t *testing.T) {
	b := &Bouncer{Store: nil, Embedder: nil, Classifier: PassthroughClassifier{}}
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", []scope.Scope{"identity.basic"}, nil)
	if err == nil {
		t.Fatal("ProposeWrite() with nil Embedder: want error, got nil")
	}
}

func TestProposeWrite_NilStoreReturnsErrorNotPanic(t *testing.T) {
	b := &Bouncer{Store: nil, Embedder: embed.Stub{}, Classifier: PassthroughClassifier{}}
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", []scope.Scope{"identity.basic"}, nil)
	if err == nil {
		t.Fatal("ProposeWrite() with nil Store: want error, got nil")
	}
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
	if err == nil {
		t.Fatal("ProposeWrite() with classifier returning non-nil empty scopes: want error (overridden to no scopes), got nil")
	}
}

func TestProposeWrite_ClassifierErrorIsWrapped(t *testing.T) {
	b := New(nil, embed.Stub{}, fakeClassifier{err: errors.New("classifier unavailable")})
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", []scope.Scope{"identity.basic"}, nil)
	if err == nil {
		t.Fatal("ProposeWrite() with a failing classifier: want error, got nil")
	}
}

func TestProposeWrite_EmbedderErrorIsWrapped(t *testing.T) {
	// Store is nil and must never be reached: the embed error should short-circuit
	// before ProposeWrite touches the store, or this panics instead of failing
	// cleanly.
	b := New(nil, fakeEmbedder{err: errors.New("embedding provider unavailable")}, PassthroughClassifier{})
	_, err := b.ProposeWrite(context.Background(), "agent-a", "some fact", []scope.Scope{"identity.basic"}, nil)
	if err == nil {
		t.Fatal("ProposeWrite() with a failing embedder: want error, got nil")
	}
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, grant_requests, data_keys`); err != nil {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, grant_requests, data_keys`); err != nil {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, grant_requests, data_keys`); err != nil {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, grant_requests, data_keys`); err != nil {
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
