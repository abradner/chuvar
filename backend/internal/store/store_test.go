package store

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pgvector/pgvector-go"

	"github.com/abradner/chuvar/backend/internal/db"
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

	g, err := s.CreateGrant(ctx, "agent-a", []string{"projects.spritz.read", "identity.basic"}, "facts", nil, "human-reviewer")
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

	if err := s.RevokeGrant(ctx, g.ID, "human-reviewer"); err != nil {
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
	if err := s.RevokeGrant(ctx, g.ID, "human-reviewer"); err == nil {
		t.Fatal("RevokeGrant() on already-revoked grant: want error, got nil")
	}
}

func TestGrants_ExpiredExcludedFromGrantedScopes(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	past := -time.Hour
	if _, err := s.CreateGrant(ctx, "agent-b", []string{"identity.basic"}, "facts", &past, "human-reviewer"); err != nil {
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

func TestCreateGrant_InvalidDepthRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "bogus", nil, "human-reviewer"); err == nil {
		t.Fatal("CreateGrant() with invalid depth: want error, got nil")
	}
}

func TestStagedDiffs_ProposeCommitAndSupersede(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	vecA := unitVector(0)
	d, err := s.ProposeDiff(ctx, "agent-a", "user's favorite coffee is a flat white", []string{"preferences.coffee"}, vecA, nil, []string{"preferences.coffee"})
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
	d2, err := s.ProposeDiff(ctx, "agent-a", "user's favorite coffee is a long black", []string{"preferences.coffee"}, unitVector(1), &fact.ID, []string{"preferences.coffee"})
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

func TestCommitDiff_ConcurrentSupersessionIsSerialized(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	vec := unitVector(7)
	original, err := s.ProposeDiff(ctx, "agent-a", "user's preferred name is Alex", []string{"identity.basic"}, vec, nil, []string{"identity.basic"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	targetFact, err := s.CommitDiff(ctx, original.ID, "human-reviewer", vec)
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	// Two diffs race to supersede the same fact.
	diffA, err := s.ProposeDiff(ctx, "agent-a", "user's preferred name is Alexander", []string{"identity.basic"}, unitVector(8), &targetFact.ID, []string{"identity.basic"})
	if err != nil {
		t.Fatalf("ProposeDiff() (A) error = %v", err)
	}
	diffB, err := s.ProposeDiff(ctx, "agent-a", "user's preferred name is Al", []string{"identity.basic"}, unitVector(9), &targetFact.ID, []string{"identity.basic"})
	if err != nil {
		t.Fatalf("ProposeDiff() (B) error = %v", err)
	}

	var wg sync.WaitGroup
	results := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, results[0] = s.CommitDiff(ctx, diffA.ID, "reviewer-a", unitVector(8))
	}()
	go func() {
		defer wg.Done()
		_, results[1] = s.CommitDiff(ctx, diffB.ID, "reviewer-b", unitVector(9))
	}()
	wg.Wait()

	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		}
	}
	// This must hold regardless of goroutine scheduling: FOR UPDATE on the target
	// fact row serializes the two transactions, so exactly one supersedes it and
	// the other gets a clear "already superseded" error — never both silently
	// succeeding (which would lose one supersession link with no error raised).
	if successes != 1 {
		t.Fatalf("concurrent CommitDiff racing to supersede the same fact: got %d successes, want exactly 1 (results: %v)", successes, results)
	}

	var supersededBy *string
	if err := pool.QueryRow(ctx, `SELECT superseded_by FROM facts WHERE id = $1`, targetFact.ID).Scan(&supersededBy); err != nil {
		t.Fatalf("querying superseded_by: %v", err)
	}
	if supersededBy == nil {
		t.Fatal("target fact was not marked superseded by either concurrent commit")
	}
}

func TestSearchFacts_ScopeWithUnderscoreDoesNotWildcardMatch(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	vec := unitVector(10)
	// Postgres LIKE treats an unescaped `_` as "match any one character." Without
	// escaping the granted scope before building the LIKE pattern, a grant on
	// "projects_alpha" would produce the pattern "projects_alpha.%", which would
	// ALSO match a fact scoped to "projectsXalpha.secret" for any character X in
	// that position — an unrelated, never-granted scope leaking through.
	d, err := s.ProposeDiff(ctx, "agent-a", "a fact scoped to an unrelated underscore-adjacent scope",
		[]string{"projectsXalpha.secret"}, vec, nil, []string{"projectsXalpha.secret"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	results, err := s.SearchFacts(ctx, "fact", vec, []string{"projects_alpha"}, 10)
	if err != nil {
		t.Fatalf("SearchFacts() error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf(`SearchFacts() granted "projects_alpha" leaked a fact scoped to "projectsXalpha.secret": %+v`, results)
	}
}

func TestSearchFacts_FactWithNoScopesExcluded(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	// Inserted directly, bypassing CommitDiff's normal fact_scopes insert, specifically
	// to exercise the candidate_facts CTE's EXISTS(fact_scopes) clause against a fact
	// that has zero scope rows — every fact reaching this point through CommitDiff has
	// at least one, but the query shouldn't rely on that being the only way a row can
	// exist. Still goes through a real staged_diffs row for source_staged_diff_id: that
	// FK is NOT NULL (facts always trace back to the diff that produced them — AGENTS.md
	// §3.1), and this fixture shouldn't need to violate that invariant just to test an
	// unrelated code path.
	var diffID string
	err := pool.QueryRow(ctx,
		`INSERT INTO staged_diffs (subject, content, proposed_scopes, status) VALUES ($1, $2, $3, 'committed') RETURNING id`,
		"agent-a", "a fact with no scope tags at all", []string{"identity.basic"},
	).Scan(&diffID)
	if err != nil {
		t.Fatalf("inserting staged diff fixture: %v", err)
	}

	var factID string
	err = pool.QueryRow(ctx,
		`INSERT INTO facts (content, embedding, source_staged_diff_id) VALUES ($1, $2, $3) RETURNING id`,
		"a fact with no scope tags at all", pgvector.NewVector(unitVector(11)), diffID,
	).Scan(&factID)
	if err != nil {
		t.Fatalf("inserting scopeless fact: %v", err)
	}

	results, err := s.SearchFacts(ctx, "fact", unitVector(11), []string{"identity", "projects", "finances"}, 10)
	if err != nil {
		t.Fatalf("SearchFacts() error = %v", err)
	}
	for _, r := range results {
		if r.ID == factID {
			t.Fatalf("SearchFacts() returned a fact with zero fact_scopes rows: %+v", r)
		}
	}
}

func TestGrantedScopesToSearchFacts_MultiGrantPipelineWithRevocation(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	// Exercises the real GrantedScopes -> SearchFacts pipeline end to end, rather
	// than hand-building the granted-scope slice like the other intersection test
	// does — this is closer to what mcptools.read_with_scope_check actually does.
	vec := unitVector(12)
	d, err := s.ProposeDiff(ctx, "agent-a", "a fact needing two different grants worth of scope",
		[]string{"identity.basic", "projects.spritz.read"}, vec, nil, []string{"identity.basic", "projects.spritz.read"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	g1, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "facts", nil, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := s.CreateGrant(ctx, "agent-a", []string{"projects.spritz.read"}, "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	granted, err := s.GrantedScopes(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopes() error = %v", err)
	}
	results, err := s.SearchFacts(ctx, "fact", vec, granted, 10)
	if err != nil {
		t.Fatalf("SearchFacts() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("SearchFacts() via real 2-grant pipeline = %+v, want 1 result", results)
	}

	// Revoke one of the two grants that together satisfy the fact's required
	// scopes — even though the other grant is still active, the fact needs both,
	// so it must disappear from results.
	if err := s.RevokeGrant(ctx, g1.ID, "human-reviewer"); err != nil {
		t.Fatalf("RevokeGrant() error = %v", err)
	}
	granted, err = s.GrantedScopes(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopes() after revoke error = %v", err)
	}
	results, err = s.SearchFacts(ctx, "fact", vec, granted, 10)
	if err != nil {
		t.Fatalf("SearchFacts() error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("SearchFacts() after revoking one of two required-scope grants = %+v, want none", results)
	}
}

func TestStagedDiffs_Get(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	vec := unitVector(6)
	d, err := s.ProposeDiff(ctx, "agent-a", "user's timezone is Australia/Melbourne", []string{"identity.basic"}, vec, nil, []string{"identity.basic"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}

	got, err := s.GetStagedDiff(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetStagedDiff() error = %v", err)
	}
	if got.Content != d.Content {
		t.Errorf("GetStagedDiff().Content = %q, want %q", got.Content, d.Content)
	}

	if _, err := s.GetStagedDiff(ctx, "00000000-0000-0000-0000-000000000000"); err == nil {
		t.Fatal("GetStagedDiff() for nonexistent ID: want error, got nil")
	}
}

func TestStagedDiffs_DedupeExactDuplicate(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	content := "user was born in Melbourne"
	vec := unitVector(2)

	d1, err := s.ProposeDiff(ctx, "agent-a", content, []string{"identity.basic"}, vec, nil, []string{"identity.basic"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d1.ID, "human-reviewer", vec); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	d2, err := s.ProposeDiff(ctx, "agent-a", content, []string{"identity.basic"}, vec, nil, []string{"identity.basic"})
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

	d1, err := s.ProposeDiff(ctx, "agent-a", "user works as a software engineer", []string{"identity.professional"}, base, nil, []string{"identity.professional"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d1.ID, "human-reviewer", base); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	d2, err := s.ProposeDiff(ctx, "agent-a", "user works as a senior engineer", []string{"identity.professional"}, near, nil, []string{"identity.professional"})
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
	d, err := s.ProposeDiff(ctx, "agent-a", "planning a wedding in March with partner", []string{"relationships.partner", "finances.budget"}, vec, nil, []string{"relationships.partner", "finances.budget"})
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

func TestSearchFacts_EmptyQueryEmbeddingFallsBackToKeywordOnly(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	vec := unitVector(6)
	d, err := s.ProposeDiff(ctx, "agent-a", "user's favorite hiking trail is Overland Track", []string{"preferences.hiking"}, vec, nil, []string{"preferences.hiking"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	// No query embedding — this is the degraded no-Embedder-configured mode. Must not
	// error (a bare $4 IS NOT NULL check without the ::vector cast previously failed
	// at prepare time with "could not determine data type of parameter"), and must
	// still find the fact via the keyword ranking alone.
	results, err := s.SearchFacts(ctx, "hiking", nil, []string{"preferences.hiking"}, 10)
	if err != nil {
		t.Fatalf("SearchFacts() with no query embedding: unexpected error = %v", err)
	}
	found := false
	for _, r := range results {
		if r.Content == "user's favorite hiking trail is Overland Track" {
			found = true
		}
	}
	if !found {
		t.Fatalf("SearchFacts() with no query embedding = %+v, want the keyword-matched fact", results)
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

func TestGetFact(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	vec := unitVector(26)
	d, err := s.ProposeDiff(ctx, "agent-a", "user's favorite season is autumn", []string{"preferences.season"}, vec, nil, []string{"preferences.season"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	fact, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec)
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	got, err := s.GetFact(ctx, fact.ID)
	if err != nil {
		t.Fatalf("GetFact() error = %v", err)
	}
	if got.Content != fact.Content {
		t.Errorf("GetFact().Content = %q, want %q", got.Content, fact.Content)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "preferences.season" {
		t.Errorf("GetFact().Scopes = %v, want [preferences.season]", got.Scopes)
	}

	if _, err := s.GetFact(ctx, "00000000-0000-0000-0000-000000000000"); err == nil {
		t.Fatal("GetFact() for nonexistent ID: want error, got nil")
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

func TestProposeDiff_DedupeCandidateSearchScopedToProposerGrants(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	// A fact committed under a scope the second proposer has no grant for.
	vec := unitVector(20)
	content := "user's medical condition is confidential"
	d, err := s.ProposeDiff(ctx, "agent-a", content, []string{"identity.medical"}, vec, nil, []string{"identity.medical"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	// A second proposer submits byte-identical content, but is only granted an
	// unrelated scope. Without scope-filtering the dedupe search, this would come
	// back as "duplicate" with the first fact's ID attached — telling an
	// ungranted caller that a fact with this exact content exists, and handing it
	// a fact ID it could then try to use as a supersession target. Found in review.
	d2, err := s.ProposeDiff(ctx, "agent-b", content, []string{"preferences.coffee"}, vec, nil, []string{"preferences.coffee"})
	if err != nil {
		t.Fatalf("ProposeDiff() (ungranted proposer) error = %v", err)
	}
	if d2.DedupeVerdict == nil || *d2.DedupeVerdict != DedupeNovel {
		t.Fatalf("ProposeDiff() dedupe verdict for an ungranted proposer = %v, want novel (candidate outside their grants must not leak)", d2.DedupeVerdict)
	}
	if d2.DedupeCandidateFactID != nil {
		t.Fatalf("ProposeDiff() leaked candidate fact ID %s to an ungranted proposer", *d2.DedupeCandidateFactID)
	}
}

func TestProposeDiff_TargetFactOutsideProposerGrantsRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	vec := unitVector(21)
	d, err := s.ProposeDiff(ctx, "agent-a", "a fact agent-b has no grant for", []string{"identity.medical"}, vec, nil, []string{"identity.medical"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	fact, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec)
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	// agent-b tries to target that fact for supersession despite having no grant
	// covering its scope — e.g. an ID it guessed, brute-forced, or obtained via
	// the dedupe candidate leak this test's sibling guards against. Must be
	// rejected before ever staging: an approval UI that doesn't show the
	// replacement target (a separate, real gap of its own) would otherwise let a
	// human unknowingly approve superseding a fact they never meant to touch.
	_, err = s.ProposeDiff(ctx, "agent-b", "innocuous-looking replacement content",
		[]string{"preferences.coffee"}, unitVector(22), &fact.ID, []string{"preferences.coffee"})
	if err == nil {
		t.Fatal("ProposeDiff() targeting a fact outside the proposer's grants: want error, got nil")
	}
}

func TestCommitDiff_RejectsIfIdenticalContentCommittedSinceStaging(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	content := "user prefers window seats"
	vec := unitVector(23)

	// Both proposals are staged while neither has committed yet, so both
	// legitimately see "novel" at stage time — the dedupe verdict computed once
	// at staging can't catch this. Only a re-check at commit time can.
	d1, err := s.ProposeDiff(ctx, "agent-a", content, []string{"preferences.seating"}, vec, nil, []string{"preferences.seating"})
	if err != nil {
		t.Fatalf("ProposeDiff() (d1) error = %v", err)
	}
	d2, err := s.ProposeDiff(ctx, "agent-a", content, []string{"preferences.seating"}, vec, nil, []string{"preferences.seating"})
	if err != nil {
		t.Fatalf("ProposeDiff() (d2) error = %v", err)
	}
	if d1.DedupeVerdict == nil || *d1.DedupeVerdict != DedupeNovel {
		t.Fatalf("d1 verdict = %v, want novel", d1.DedupeVerdict)
	}
	if d2.DedupeVerdict == nil || *d2.DedupeVerdict != DedupeNovel {
		t.Fatalf("d2 verdict = %v, want novel (neither has committed yet)", d2.DedupeVerdict)
	}

	if _, err := s.CommitDiff(ctx, d1.ID, "human-reviewer", vec); err != nil {
		t.Fatalf("CommitDiff() (d1) error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d2.ID, "human-reviewer", vec); err == nil {
		t.Fatal("CommitDiff() (d2) committing identical content after d1 already committed it: want error, got nil")
	}
}

func TestCommitDiff_LogsAuditEventAtomically(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	vec := unitVector(24)
	d, err := s.ProposeDiff(ctx, "agent-a", "user's preferred airline is Qantas", []string{"preferences.travel"}, vec, nil, []string{"preferences.travel"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	fact, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec)
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE event_type = 'diff_committed' AND fact_id = $1 AND subject = 'human-reviewer'`,
		fact.ID,
	).Scan(&count); err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if count != 1 {
		t.Fatalf("audit_log rows for diff_committed = %d, want 1 (mutation and audit row must commit atomically)", count)
	}
}

func TestCreateGrant_LogsAuditEventAtomically(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	g, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "facts", nil, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE event_type = 'grant_created' AND grant_id = $1 AND subject = 'human-reviewer'`,
		g.ID,
	).Scan(&count); err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if count != 1 {
		t.Fatalf("audit_log rows for grant_created = %d, want 1", count)
	}
}

func TestRejectDiff_LogsAuditEventAtomically(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	vec := unitVector(25)
	d, err := s.ProposeDiff(ctx, "agent-a", "a proposal that will be rejected", []string{"identity.basic"}, vec, nil, []string{"identity.basic"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if err := s.RejectDiff(ctx, d.ID, "human-reviewer"); err != nil {
		t.Fatalf("RejectDiff() error = %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE event_type = 'diff_rejected' AND staged_diff_id = $1 AND subject = 'human-reviewer'`,
		d.ID,
	).Scan(&count); err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if count != 1 {
		t.Fatalf("audit_log rows for diff_rejected = %d, want 1", count)
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
// small (but nonzero) cosine distance from base. The perturbed index is computed
// relative to base's own nonzero entry (unitVector's seed%384), not a fixed index —
// a fixed index only nudges the intended component by coincidence when the base
// vector happens to peak elsewhere, and silently stops perturbing anything
// meaningful if a caller ever passes a base with its peak at that fixed index.
func nudge(base []float32, amount float32) []float32 {
	peak := 0
	for i, v := range base {
		if v != 0 {
			peak = i
			break
		}
	}
	perturbIdx := (peak + 1) % len(base)

	out := make([]float32, len(base))
	var sumSquares float32
	for i, v := range base {
		nv := v
		if i == perturbIdx {
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
