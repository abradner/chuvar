package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"memoryvault/internal/db"
)

// These are integration tests against a real Postgres+pgvector instance (the raw
// SQL — especially the scope-filtering CTEs in facts.go — is exactly the kind of
// thing that looks right and silently isn't; a mock wouldn't catch that). They run
// against docker-compose's local instance and are skipped if DATABASE_URL isn't
// set, per AGENTS.md's testing note preferring integration-level coverage.
func testStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping store integration tests (see docker-compose.yml)")
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

	// Isolate each test: truncate everything before it runs rather than after, so a
	// failed run leaves data behind to inspect.
	_, err = pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log`)
	if err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	return New(pool), pool
}

func TestGrants_CreateListRevoke(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	g, err := s.CreateGrant(ctx, "agent-a", []string{"projects.spritz.read", "identity.basic"}, "facts", nil)
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if g.ID == "" {
		t.Fatal("CreateGrant() returned empty ID")
	}

	grants, err := s.ListGrants(ctx, "agent-a")
	if err != nil {
		t.Fatalf("ListGrants() error = %v", err)
	}
	if len(grants) != 1 || len(grants[0].Scopes) != 2 {
		t.Fatalf("ListGrants() = %+v, want 1 grant with 2 scopes", grants)
	}

	granted, err := s.GrantedScopes(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopes() error = %v", err)
	}
	if len(granted) != 2 {
		t.Fatalf("GrantedScopes() = %v, want 2 scopes", granted)
	}

	if err := s.RevokeGrant(ctx, g.ID); err != nil {
		t.Fatalf("RevokeGrant() error = %v", err)
	}
	granted, err = s.GrantedScopes(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopes() after revoke error = %v", err)
	}
	if len(granted) != 0 {
		t.Fatalf("GrantedScopes() after revoke = %v, want none", granted)
	}

	// Revoking again should error, not silently succeed.
	if err := s.RevokeGrant(ctx, g.ID); err == nil {
		t.Fatal("RevokeGrant() on already-revoked grant: want error, got nil")
	}
}

func TestGrants_ExpiredExcludedFromGrantedScopes(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	past := -time.Hour
	if _, err := s.CreateGrant(ctx, "agent-b", []string{"identity.basic"}, "facts", &past); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	granted, err := s.GrantedScopes(ctx, "agent-b")
	if err != nil {
		t.Fatalf("GrantedScopes() error = %v", err)
	}
	if len(granted) != 0 {
		t.Fatalf("GrantedScopes() with expired grant = %v, want none", granted)
	}
}

func TestStagedDiffs_ProposeCommitAndSupersede(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	vecA := unitVector(0)
	d, err := s.ProposeDiff(ctx, "agent-a", "user's favorite coffee is a flat white", []string{"preferences.coffee"}, vecA, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if d.Status != DiffPending {
		t.Fatalf("ProposeDiff() status = %v, want pending", d.Status)
	}
	if d.DedupeVerdict == nil || *d.DedupeVerdict != DedupeNovel {
		t.Fatalf("ProposeDiff() first proposal verdict = %v, want novel", d.DedupeVerdict)
	}

	fact, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vecA)
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}
	if len(fact.Scopes) != 1 || fact.Scopes[0] != "preferences.coffee" {
		t.Fatalf("CommitDiff() fact.Scopes = %v, want [preferences.coffee]", fact.Scopes)
	}

	// Committing an already-committed diff should error.
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vecA); err == nil {
		t.Fatal("CommitDiff() on already-committed diff: want error, got nil")
	}

	// Propose an update that supersedes the fact.
	d2, err := s.ProposeDiff(ctx, "agent-a", "user's favorite coffee is a long black", []string{"preferences.coffee"}, unitVector(1), &fact.ID)
	if err != nil {
		t.Fatalf("ProposeDiff() (supersede) error = %v", err)
	}
	newFact, err := s.CommitDiff(ctx, d2.ID, "human-reviewer", unitVector(1))
	if err != nil {
		t.Fatalf("CommitDiff() (supersede) error = %v", err)
	}

	granted := []string{"preferences.coffee"}
	results, err := s.SearchFacts(ctx, "coffee", unitVector(1), granted, 10)
	if err != nil {
		t.Fatalf("SearchFacts() error = %v", err)
	}
	for _, r := range results {
		if r.ID == fact.ID {
			t.Errorf("SearchFacts() returned superseded fact %s", fact.ID)
		}
	}
	found := false
	for _, r := range results {
		if r.ID == newFact.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("SearchFacts() did not return the superseding fact %s among %+v", newFact.ID, results)
	}
}

func TestStagedDiffs_DedupeExactDuplicate(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	content := "user was born in Melbourne"
	vec := unitVector(2)

	d1, err := s.ProposeDiff(ctx, "agent-a", content, []string{"identity.basic"}, vec, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d1.ID, "human-reviewer", vec); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	d2, err := s.ProposeDiff(ctx, "agent-a", content, []string{"identity.basic"}, vec, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() (duplicate) error = %v", err)
	}
	if d2.DedupeVerdict == nil || *d2.DedupeVerdict != DedupeDuplicate {
		t.Fatalf("ProposeDiff() duplicate verdict = %v, want duplicate", d2.DedupeVerdict)
	}
	if d2.DedupeCandidateFactID == nil {
		t.Fatal("ProposeDiff() duplicate verdict but no candidate fact ID set")
	}
}

func TestStagedDiffs_DedupeNearMatchFlaggedAsContradiction(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	base := unitVector(3)
	near := nudge(base, 0.01) // small perturbation: close in cosine distance, different text

	d1, err := s.ProposeDiff(ctx, "agent-a", "user works as a software engineer", []string{"identity.professional"}, base, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d1.ID, "human-reviewer", base); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	d2, err := s.ProposeDiff(ctx, "agent-a", "user works as a senior engineer", []string{"identity.professional"}, near, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() (near match) error = %v", err)
	}
	if d2.DedupeVerdict == nil || *d2.DedupeVerdict != DedupeContradiction {
		t.Fatalf("ProposeDiff() near-match verdict = %v, want contradiction (flagged for review, not auto-merged)", d2.DedupeVerdict)
	}
}

func TestSearchFacts_ScopeIntersectionRequiresAllTags(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	vec := unitVector(4)
	d, err := s.ProposeDiff(ctx, "agent-a", "planning a wedding in March with partner", []string{"relationships.partner", "finances.budget"}, vec, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	// Only one of the two required scopes granted: must NOT be returned.
	partial, err := s.SearchFacts(ctx, "wedding", vec, []string{"relationships.partner"}, 10)
	if err != nil {
		t.Fatalf("SearchFacts() (partial grant) error = %v", err)
	}
	if len(partial) != 0 {
		t.Fatalf("SearchFacts() with only one of two required scopes granted = %+v, want none (intersection semantics)", partial)
	}

	// Both scopes granted: must be returned.
	full, err := s.SearchFacts(ctx, "wedding", vec, []string{"relationships.partner", "finances.budget"}, 10)
	if err != nil {
		t.Fatalf("SearchFacts() (full grant) error = %v", err)
	}
	if len(full) != 1 {
		t.Fatalf("SearchFacts() with both required scopes granted = %+v, want 1 result", full)
	}

	// A broader ancestor grant covering both dotted children: must also be returned.
	ancestor, err := s.SearchFacts(ctx, "wedding", vec, []string{"relationships", "finances"}, 10)
	if err != nil {
		t.Fatalf("SearchFacts() (ancestor grant) error = %v", err)
	}
	if len(ancestor) != 1 {
		t.Fatalf("SearchFacts() with ancestor grants = %+v, want 1 result", ancestor)
	}
}

func TestSearchFacts_NoGrantsReturnsNothing(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	results, err := s.SearchFacts(ctx, "anything", unitVector(5), nil, 10)
	if err != nil {
		t.Fatalf("SearchFacts() error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("SearchFacts() with no granted scopes = %+v, want none", results)
	}
}

func TestAuditLog_Insert(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	if err := s.LogAudit(ctx, "read", "agent-a", nil, nil, nil, []string{"identity.basic"}); err != nil {
		t.Fatalf("LogAudit() error = %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE event_type = 'read' AND subject = 'agent-a'`).Scan(&count); err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if count != 1 {
		t.Fatalf("audit_log rows = %d, want 1", count)
	}
}

// unitVector returns a deterministic unit vector distinct per seed, for tests that
// need precise control over embedding distances rather than the Stub embedder's
// text-derived (and only loosely controllable) output.
func unitVector(seed int) []float32 {
	vec := make([]float32, 384)
	vec[seed%384] = 1.0
	return vec
}

// nudge perturbs a unit vector slightly and re-normalizes, producing a vector with
// small (but nonzero) cosine distance from base.
func nudge(base []float32, amount float32) []float32 {
	out := make([]float32, len(base))
	var sumSquares float32
	for i, v := range base {
		nv := v
		if i == (len(base)+1)%len(base) {
			nv += amount
		}
		out[i] = nv
		sumSquares += nv * nv
	}
	norm := float32(1.0)
	if sumSquares > 0 {
		norm = sqrt32(sumSquares)
	}
	for i := range out {
		out[i] /= norm
	}
	return out
}

func sqrt32(v float32) float32 {
	// avoid importing math just for one call site here at test scope
	x := v
	for range 20 {
		x = 0.5 * (x + v/x)
	}
	return x
}
