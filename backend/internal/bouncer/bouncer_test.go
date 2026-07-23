package bouncer

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"chuvar/internal/db"
	"chuvar/internal/embed"
	"chuvar/internal/scope"
	"chuvar/internal/store"
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log`); err != nil {
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
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log`); err != nil {
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
