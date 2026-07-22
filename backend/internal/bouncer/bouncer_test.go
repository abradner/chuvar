package bouncer

import (
	"context"
	"os"
	"testing"

	"memoryvault/internal/db"
	"memoryvault/internal/embed"
	"memoryvault/internal/scope"
	"memoryvault/internal/store"
)

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
