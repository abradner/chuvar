package store

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pgvector/pgvector-go"

	"github.com/abradner/chuvar/backend/internal/custody"
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
	_, err = pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log, reviewer_tokens, webauthn_credentials, webauthn_challenges, grant_requests, data_keys, propose_write_rate_limits`)
	if err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	// Sealed by default: enrolling a TOTP secret needs a key, and a test Store
	// that couldn't do it would just be a different Store from the real one.
	// The unsealed case has its own coverage in data_keys_test.go.
	return NewSealed(pool, testSecretKey(t)), pool
}

// testSecretKey mints a data-encryption key scoped to a single test.
func testSecretKey(t *testing.T) *custody.Key {
	t.Helper()
	raw, err := custody.GenerateKey()
	if err != nil {
		t.Fatalf("custody.GenerateKey() error = %v", err)
	}
	key, err := custody.NewKey(raw)
	if err != nil {
		t.Fatalf("custody.NewKey() error = %v", err)
	}
	return key
}

func TestGrants_CreateListRevoke(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	g, err := s.CreateGrant(ctx, "agent-a", []string{"projects.spritz.read", "identity.basic"}, "memory", "facts", nil, "human-reviewer")
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

// TestListGrants_ScopesPerGrant guards the array_agg subquery that replaced
// ListGrants' per-grant ListGrantScopes N+1 call (mirroring
// ListGrantsNearingExpiry's identical fix): with several grants for the same
// subject carrying different scope counts, a join gone wrong (e.g. a plain
// JOIN instead of a scalar subquery cross-multiplying rows, or scopes
// attached to the wrong grant) would either change the returned grant count,
// duplicate/drop scopes, or mix scopes across grants — none of which the
// single-grant assertion in TestGrants_CreateListRevoke would catch.
func TestListGrants_ScopesPerGrant(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	single, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() (single-scope) error = %v", err)
	}
	triple, err := s.CreateGrant(ctx, "agent-a",
		[]string{"projects.spritz.read", "projects.spritz.write", "identity.basic"},
		"memory", "facts", nil, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() (triple-scope) error = %v", err)
	}

	grants, err := s.ListGrants(ctx, "agent-a")
	if err != nil {
		t.Fatalf("ListGrants() error = %v", err)
	}
	if len(grants) != 2 {
		t.Fatalf("ListGrants() = %+v, want 2 grants", grants)
	}

	byID := make(map[string][]string, len(grants))
	for _, g := range grants {
		byID[g.ID] = g.Scopes
	}

	wantSingle := []string{"identity.basic"}
	if got := byID[single.ID]; !scopeSetsEqual(got, wantSingle) {
		t.Fatalf("ListGrants() scopes for single-scope grant %s = %v, want %v", single.ID, got, wantSingle)
	}
	wantTriple := []string{"projects.spritz.read", "projects.spritz.write", "identity.basic"}
	if got := byID[triple.ID]; !scopeSetsEqual(got, wantTriple) {
		t.Fatalf("ListGrants() scopes for triple-scope grant %s = %v, want %v", triple.ID, got, wantTriple)
	}
}

// scopeSetsEqual compares two scope slices as sets, since array_agg over
// grant_scopes (a table with no secondary ordering column) makes no promise
// about element order — only about which scopes belong to which grant.
func scopeSetsEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	counts := make(map[string]int, len(want))
	for _, s := range want {
		counts[s]++
	}
	for _, s := range got {
		counts[s]--
	}
	for _, c := range counts {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestRenewGrant_ExtendsExpiry(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	shortTTL := time.Minute
	g, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", &shortTTL, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	renewed, err := s.RenewGrant(ctx, g.ID, time.Hour, "human-reviewer")
	if err != nil {
		t.Fatalf("RenewGrant() error = %v", err)
	}
	if renewed.ExpiresAt == nil || !renewed.ExpiresAt.After(*g.ExpiresAt) {
		t.Fatalf("RenewGrant() ExpiresAt = %v, want later than the original %v", renewed.ExpiresAt, g.ExpiresAt)
	}
	if !renewed.Active(time.Now()) {
		t.Error("renewed grant should be Active")
	}
}

func TestRenewGrant_RevokedGrantRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	g, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if err := s.RevokeGrant(ctx, g.ID, "human-reviewer"); err != nil {
		t.Fatalf("RevokeGrant() error = %v", err)
	}

	if _, err := s.RenewGrant(ctx, g.ID, time.Hour, "human-reviewer"); err == nil {
		t.Fatal("RenewGrant() on a revoked grant: want error, got nil")
	}
}

// A capability grant must not be renewable through the memory-grant path. No
// surface can create one yet (both API and MCP hardcode kind='memory'), so this
// inserts one directly — the only way to exercise a latch closed ahead of the
// door it guards. When the capability broker gains a real creation path, this test keeps
// renewal from silently inheriting memory semantics on the way through.
func TestRenewGrant_CapabilityGrantRejected(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	// depth must be NULL for kind='capability' — the grants_kind_depth_pairing
	// CHECK enforces the pairing, so this insert also asserts that constraint
	// still says what it did when it was written.
	var id string
	err := pool.QueryRow(ctx,
		`INSERT INTO grants (subject, kind, depth, expires_at)
		 VALUES ($1, 'capability', NULL, now() + interval '1 hour') RETURNING id`,
		"agent-capability",
	).Scan(&id)
	if err != nil {
		t.Fatalf("seeding a capability grant: %v", err)
	}

	if _, err := s.RenewGrant(ctx, id, time.Hour, "human-reviewer"); err == nil {
		t.Fatal("RenewGrant() renewed a capability grant: want error, got nil")
	}

	// And the memory path is unaffected — the filter must not be so broad it
	// breaks the case renewal was actually built for.
	g, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := s.RenewGrant(ctx, g.ID, time.Hour, "human-reviewer"); err != nil {
		t.Fatalf("RenewGrant() on a memory grant error = %v", err)
	}
}

func TestRenewGrant_AlreadyExpiredGrantRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	past := -time.Hour
	g, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", &past, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	// A lapsed grant needs a fresh CreateGrant decision, not a renewal — see
	// RenewGrant's doc comment.
	if _, err := s.RenewGrant(ctx, g.ID, time.Hour, "human-reviewer"); err == nil {
		t.Fatal("RenewGrant() on an already-expired grant: want error, got nil")
	}
}

func TestRenewGrant_NonPositiveTTLRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	g, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	if _, err := s.RenewGrant(ctx, g.ID, 0, "human-reviewer"); err == nil {
		t.Fatal("RenewGrant() with ttl=0: want error, got nil (renewing into \"no expiry\" isn't allowed)")
	}
}

func TestRenewGrant_LogsAuditEventAtomically(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	g, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := s.RenewGrant(ctx, g.ID, time.Hour, "human-reviewer"); err != nil {
		t.Fatalf("RenewGrant() error = %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE event_type = 'grant_renewed' AND grant_id = $1 AND subject = 'human-reviewer'`,
		g.ID,
	).Scan(&count); err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if count != 1 {
		t.Fatalf("audit_log rows for grant_renewed = %d, want 1", count)
	}
}

func TestListGrantsNearingExpiry(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	soonTTL := 30 * time.Minute
	soon, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", &soonTTL, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() (soon) error = %v", err)
	}
	laterTTL := 7 * 24 * time.Hour
	if _, err := s.CreateGrant(ctx, "agent-b", []string{"identity.basic"}, "memory", "facts", &laterTTL, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() (later) error = %v", err)
	}
	if _, err := s.CreateGrant(ctx, "agent-c", []string{"identity.basic"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() (no expiry) error = %v", err)
	}
	revokedTTL := 30 * time.Minute
	revoked, err := s.CreateGrant(ctx, "agent-d", []string{"identity.basic"}, "memory", "facts", &revokedTTL, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() (revoked) error = %v", err)
	}
	if err := s.RevokeGrant(ctx, revoked.ID, "human-reviewer"); err != nil {
		t.Fatalf("RevokeGrant() error = %v", err)
	}

	expiring, err := s.ListGrantsNearingExpiry(ctx, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("ListGrantsNearingExpiry() error = %v", err)
	}
	if len(expiring) != 1 || expiring[0].ID != soon.ID {
		t.Fatalf("ListGrantsNearingExpiry() = %+v, want exactly the soon-to-expire grant %s (not the far-out, no-expiry, or revoked ones)", expiring, soon.ID)
	}
	// Scopes come from the query's array_agg subquery, not a separate
	// ListGrantScopes call — assert they actually round-trip, not just that
	// the field exists.
	if len(expiring[0].Scopes) != 1 || expiring[0].Scopes[0] != "identity.basic" {
		t.Fatalf("ListGrantsNearingExpiry() Scopes = %v, want [identity.basic]", expiring[0].Scopes)
	}
}

func TestGrantedScopeDepths_RoundTripsDepthPerScope(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "summary", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := s.CreateGrant(ctx, "agent-a", []string{"projects.spritz.read"}, "memory", "full", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	depths, err := s.GrantedScopeDepths(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopeDepths() error = %v", err)
	}
	got := map[string]string{}
	for _, g := range depths {
		got[g.Scope] = g.Depth
	}
	want := map[string]string{"identity.basic": "summary", "projects.spritz.read": "full"}
	if len(got) != len(want) || got["identity.basic"] != want["identity.basic"] || got["projects.spritz.read"] != want["projects.spritz.read"] {
		t.Fatalf("GrantedScopeDepths() = %v, want %v", got, want)
	}
}

func TestGrants_ExpiredExcludedFromGrantedScopes(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	past := -time.Hour
	if _, err := s.CreateGrant(ctx, "agent-b", []string{"identity.basic"}, "memory", "facts", &past, "human-reviewer"); err != nil {
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

	if _, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "bogus", nil, "human-reviewer"); err == nil {
		t.Fatal("CreateGrant() with invalid depth: want error, got nil")
	}
}

func TestCreateGrant_EmptyKindDefaultsToMemory(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	g, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "", "facts", nil, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() with empty kind error = %v", err)
	}
	if g.Kind != GrantKindMemory {
		t.Errorf("Kind = %q, want %q (empty kind should default to memory)", g.Kind, GrantKindMemory)
	}
}

func TestCreateGrant_InvalidKindRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "bogus-kind", "facts", nil, "human-reviewer"); err == nil {
		t.Fatal("CreateGrant() with invalid kind: want error, got nil")
	}
}

func TestCreateGrant_CapabilityKindRequiresNoDepth(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "capability", "facts", nil, "human-reviewer"); err == nil {
		t.Fatal("CreateGrant() with kind=capability and a depth set: want error, got nil (there's no equivalent concept for a capability grant)")
	}
}

func TestCreateGrant_CapabilityKindWithNoDepthSucceeds(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	g, err := s.CreateGrant(ctx, "agent-a", []string{"git.sign:github.com/abradner/chuvar"}, "capability", "", nil, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() with kind=capability, no depth: error = %v", err)
	}
	if g.Kind != GrantKindCapability {
		t.Errorf("Kind = %q, want %q", g.Kind, GrantKindCapability)
	}
	if g.Depth != "" {
		t.Errorf("Depth = %q, want empty for a capability grant", g.Depth)
	}

	// Round-trips through ListGrants the same way.
	grants, err := s.ListGrants(ctx, "agent-a")
	if err != nil {
		t.Fatalf("ListGrants() error = %v", err)
	}
	if len(grants) != 1 || grants[0].Kind != GrantKindCapability || grants[0].Depth != "" {
		t.Fatalf("ListGrants() = %+v, want one capability grant with empty depth", grants)
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

	fact, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vecA, "")
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}
	if len(fact.Scopes) != 1 || fact.Scopes[0] != "preferences.coffee" {
		t.Fatalf("CommitDiff() fact.Scopes = %v, want [preferences.coffee]", fact.Scopes)
	}

	// Committing an already-committed diff should error.
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vecA, ""); err == nil {
		t.Fatal("CommitDiff() on already-committed diff: want error, got nil")
	}

	// Propose an update that supersedes the fact.
	d2, err := s.ProposeDiff(ctx, "agent-a", "user's favorite coffee is a long black", []string{"preferences.coffee"}, unitVector(1), &fact.ID, []string{"preferences.coffee"})
	if err != nil {
		t.Fatalf("ProposeDiff() (supersede) error = %v", err)
	}
	newFact, err := s.CommitDiff(ctx, d2.ID, "human-reviewer", unitVector(1), "")
	if err != nil {
		t.Fatalf("CommitDiff() (supersede) error = %v", err)
	}

	granted := []string{"preferences.coffee"}
	results, err := s.SearchFacts(ctx, "coffee", unitVector(1), fullDepth(granted), 10)
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
	targetFact, err := s.CommitDiff(ctx, original.ID, "human-reviewer", vec, "")
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
		_, results[0] = s.CommitDiff(ctx, diffA.ID, "reviewer-a", unitVector(8), "")
	}()
	go func() {
		defer wg.Done()
		_, results[1] = s.CommitDiff(ctx, diffB.ID, "reviewer-b", unitVector(9), "")
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
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec, ""); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	results, err := s.SearchFacts(ctx, "fact", vec, fullDepth([]string{"projects_alpha"}), 10)
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

	results, err := s.SearchFacts(ctx, "fact", unitVector(11), fullDepth([]string{"identity", "projects", "finances"}), 10)
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
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec, ""); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	g1, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "human-reviewer")
	if err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := s.CreateGrant(ctx, "agent-a", []string{"projects.spritz.read"}, "memory", "facts", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}

	granted, err := s.GrantedScopes(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopes() error = %v", err)
	}
	results, err := s.SearchFacts(ctx, "fact", vec, fullDepth(granted), 10)
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
	results, err = s.SearchFacts(ctx, "fact", vec, fullDepth(granted), 10)
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

// TestStagedDiffs_ListPage_WalksEveryRowExactlyOnce is the boundary-case test
// the pagination ticket's self-review calls out explicitly: walk a full
// keyset-paginated listing with a page size smaller than the total row
// count, and confirm every row is seen exactly once — no skips (which an
// offset-based scheme would show if a row were removed from an earlier page
// mid-walk) and no duplicates (which a naive "created_at only" cursor could
// show for same-timestamp rows). It also exercises the "a row arrives
// between two poll ticks, right at the cursor" case: a new diff is proposed
// after the first page is fetched but before the walk finishes, and must
// show up only once — after every row that already existed when its own
// cursor position was captured, never skipped, never duplicated into an
// earlier page.
func TestStagedDiffs_ListPage_WalksEveryRowExactlyOnce(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	vec := unitVector(0)
	const total = 5
	ids := make([]string, 0, total+1)
	for i := 0; i < total; i++ {
		d, err := s.ProposeDiff(ctx, "agent-a", fmt.Sprintf("fact number %d", i), []string{"identity.basic"}, vec, nil, nil)
		if err != nil {
			t.Fatalf("ProposeDiff() error = %v", err)
		}
		ids = append(ids, d.ID)
	}

	seen := map[string]bool{}
	var cursor *ListCursor
	insertedMidWalk := false
	for page := 0; ; page++ {
		diffs, hasMore, err := s.ListStagedDiffsPage(ctx, DiffPending, 2, cursor)
		if err != nil {
			t.Fatalf("ListStagedDiffsPage() page %d error = %v", page, err)
		}
		for _, d := range diffs {
			if seen[d.ID] {
				t.Fatalf("ListStagedDiffsPage() returned id %s twice across pages", d.ID)
			}
			seen[d.ID] = true
		}

		// Simulate a diff proposed concurrently with the walk, right after the
		// first page was captured — it must not retroactively appear in a page
		// already returned, and must not be skipped once the walk reaches it.
		if page == 0 && !insertedMidWalk {
			nd, err := s.ProposeDiff(ctx, "agent-a", "fact proposed mid-walk", []string{"identity.basic"}, vec, nil, nil)
			if err != nil {
				t.Fatalf("ProposeDiff() (mid-walk) error = %v", err)
			}
			ids = append(ids, nd.ID)
			insertedMidWalk = true
		}

		if !hasMore {
			break
		}
		last := diffs[len(diffs)-1]
		cursor = &ListCursor{CreatedAt: last.CreatedAt, ID: last.ID}

		if page > total+2 {
			t.Fatal("ListStagedDiffsPage() walk did not terminate — hasMore stuck true")
		}
	}

	if len(seen) != len(ids) {
		t.Fatalf("ListStagedDiffsPage() walk saw %d distinct rows, want %d (ids=%v, seen=%v)", len(seen), len(ids), ids, seen)
	}
	for _, id := range ids {
		if !seen[id] {
			t.Errorf("ListStagedDiffsPage() walk never returned id %s", id)
		}
	}
}

// TestStagedDiffs_ListPage_LimitZeroOrNegativeRejected guards the same input
// contract internal/api's parseListLimit already enforces at the HTTP
// boundary — checked again here since ListStagedDiffsPage is a public Store
// method any future caller could reach directly with a bad limit.
func TestStagedDiffs_ListPage_LimitZeroOrNegativeRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, _, err := s.ListStagedDiffsPage(ctx, DiffPending, 0, nil); err == nil {
		t.Error("ListStagedDiffsPage() with limit=0: want error, got nil")
	}
	if _, _, err := s.ListStagedDiffsPage(ctx, DiffPending, -1, nil); err == nil {
		t.Error("ListStagedDiffsPage() with limit=-1: want error, got nil")
	}
}

// TestGrants_ListPage_WalksEveryRowExactlyOnce is ListStagedDiffsPage's
// sibling test for the newest-first, subject-scoped grants listing —
// confirming the same no-skip/no-duplicate property holds when the cursor
// comparison runs the opposite direction (created_at DESC).
func TestGrants_ListPage_WalksEveryRowExactlyOnce(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	const total = 5
	ids := make([]string, 0, total)
	for i := 0; i < total; i++ {
		g, err := s.CreateGrant(ctx, "agent-a", []string{fmt.Sprintf("scope.%d", i)}, "memory", "facts", nil, "human-reviewer")
		if err != nil {
			t.Fatalf("CreateGrant() error = %v", err)
		}
		ids = append(ids, g.ID)
	}

	seen := map[string]bool{}
	var cursor *ListCursor
	for page := 0; ; page++ {
		grants, hasMore, err := s.ListGrantsPage(ctx, "agent-a", 2, cursor)
		if err != nil {
			t.Fatalf("ListGrantsPage() page %d error = %v", page, err)
		}
		for _, g := range grants {
			if seen[g.ID] {
				t.Fatalf("ListGrantsPage() returned id %s twice across pages", g.ID)
			}
			seen[g.ID] = true
		}
		if !hasMore {
			break
		}
		last := grants[len(grants)-1]
		cursor = &ListCursor{CreatedAt: last.CreatedAt, ID: last.ID}

		if page > total+2 {
			t.Fatal("ListGrantsPage() walk did not terminate — hasMore stuck true")
		}
	}

	if len(seen) != total {
		t.Fatalf("ListGrantsPage() walk saw %d distinct rows, want %d", len(seen), total)
	}
	for _, id := range ids {
		if !seen[id] {
			t.Errorf("ListGrantsPage() walk never returned id %s", id)
		}
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
	if _, err := s.CommitDiff(ctx, d1.ID, "human-reviewer", vec, ""); err != nil {
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
	if _, err := s.CommitDiff(ctx, d1.ID, "human-reviewer", base, ""); err != nil {
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
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec, ""); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	// Only one of the two required scopes granted: must NOT be returned.
	partial, err := s.SearchFacts(ctx, "wedding", vec, fullDepth([]string{"relationships.partner"}), 10)
	if err != nil {
		t.Fatalf("SearchFacts() (partial grant) error = %v", err)
	}
	if len(partial) != 0 {
		t.Fatalf("SearchFacts() with only one of two required scopes granted = %+v, want none (intersection semantics)", partial)
	}

	// Both scopes granted: must be returned.
	full, err := s.SearchFacts(ctx, "wedding", vec, fullDepth([]string{"relationships.partner", "finances.budget"}), 10)
	if err != nil {
		t.Fatalf("SearchFacts() (full grant) error = %v", err)
	}
	if len(full) != 1 {
		t.Fatalf("SearchFacts() with both required scopes granted = %+v, want 1 result", full)
	}

	// A broader ancestor grant covering both dotted children: must also be returned.
	ancestor, err := s.SearchFacts(ctx, "wedding", vec, fullDepth([]string{"relationships", "finances"}), 10)
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
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec, ""); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	// No query embedding — this is the degraded no-Embedder-configured mode. Must not
	// error (a bare $4 IS NOT NULL check without the ::vector cast previously failed
	// at prepare time with "could not determine data type of parameter"), and must
	// still find the fact via the keyword ranking alone.
	results, err := s.SearchFacts(ctx, "hiking", nil, fullDepth([]string{"preferences.hiking"}), 10)
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

	results, err := s.SearchFacts(ctx, "anything", unitVector(5), fullDepth(nil), 10)
	if err != nil {
		t.Fatalf("SearchFacts() error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("SearchFacts() with no granted scopes = %+v, want none", results)
	}
}

func TestSearchFacts_SummaryDepthRedactsContent(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	vec := unitVector(30)
	d, err := s.ProposeDiff(ctx, "agent-a", "user's favorite coffee is a flat white", []string{"preferences.coffee"}, vec, nil, []string{"preferences.coffee"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec, "a stub summary of the coffee fact"); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	granted := []GrantedScope{{Scope: "preferences.coffee", Depth: "summary"}}
	results, err := s.SearchFacts(ctx, "coffee", vec, granted, 10)
	if err != nil {
		t.Fatalf("SearchFacts() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("SearchFacts() = %+v, want 1 result", results)
	}
	got := results[0]
	if got.Depth != "summary" {
		t.Errorf("Depth = %q, want %q", got.Depth, "summary")
	}
	if got.Content != "" {
		t.Errorf("Content = %q, want empty at summary depth", got.Content)
	}
	if got.Summary != "a stub summary of the coffee fact" {
		t.Errorf("Summary = %q, want the committed summary", got.Summary)
	}
}

func TestSearchFacts_SummaryDepthWithNoSummaryFailsClosed(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	// Committed with summary = "" (stored as NULL) — simulates a pre-migration
	// fact or a Summarizer that returned nothing. A summary-depth read of it
	// must never fall back to Content; that would silently un-enforce the
	// redaction this depth exists to apply.
	vec := unitVector(31)
	d, err := s.ProposeDiff(ctx, "agent-a", "user's least favorite vegetable is celery", []string{"preferences.food"}, vec, nil, []string{"preferences.food"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec, ""); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	granted := []GrantedScope{{Scope: "preferences.food", Depth: "summary"}}
	results, err := s.SearchFacts(ctx, "vegetable", vec, granted, 10)
	if err != nil {
		t.Fatalf("SearchFacts() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("SearchFacts() = %+v, want 1 result", results)
	}
	got := results[0]
	if got.Content != "" {
		t.Errorf("Content = %q, want empty (must never fall back to full content when summary is NULL)", got.Content)
	}
	if got.Summary != "" {
		t.Errorf("Summary = %q, want empty (no summary was ever generated)", got.Summary)
	}
}

func TestSearchFacts_FactsAndFullDepthReturnContent(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	vec := unitVector(32)
	d, err := s.ProposeDiff(ctx, "agent-a", "user's timezone is Australia/Melbourne", []string{"identity.timezone"}, vec, nil, []string{"identity.timezone"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec, "a stub summary"); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	for _, depth := range []string{"facts", "full"} {
		granted := []GrantedScope{{Scope: "identity.timezone", Depth: depth}}
		results, err := s.SearchFacts(ctx, "timezone", vec, granted, 10)
		if err != nil {
			t.Fatalf("SearchFacts() at depth %q error = %v", depth, err)
		}
		if len(results) != 1 {
			t.Fatalf("SearchFacts() at depth %q = %+v, want 1 result", depth, results)
		}
		got := results[0]
		if got.Depth != depth {
			t.Errorf("Depth = %q, want %q", got.Depth, depth)
		}
		if got.Content != "user's timezone is Australia/Melbourne" {
			t.Errorf("at depth %q, Content = %q, want the full fact content", depth, got.Content)
		}
		if got.Summary != "" {
			t.Errorf("at depth %q, Summary = %q, want empty (Content and Summary are mutually exclusive)", depth, got.Summary)
		}
	}
}

// The ticket this implements: "full" depth is supposed to add a fact's
// *provenance* on top of its content, not just be a synonym for "facts". This
// asserts that split end to end through the real SearchFacts pipeline, not
// just effectiveDepth's rank arithmetic.
func TestSearchFacts_FullDepthAddsProvenance_FactsDepthDoesNot(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	vec := unitVector(35)
	d, err := s.ProposeDiff(ctx, "agent-a", "user's favorite editor is neovim", []string{"preferences.tools"}, vec, nil, []string{"preferences.tools"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	fact, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec, "editor preference summary")
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	factsResults, err := s.SearchFacts(ctx, "editor", vec, []GrantedScope{{Scope: "preferences.tools", Depth: "facts"}}, 10)
	if err != nil {
		t.Fatalf("SearchFacts() at facts depth error = %v", err)
	}
	if len(factsResults) != 1 {
		t.Fatalf("SearchFacts() at facts depth = %+v, want 1 result", factsResults)
	}
	if factsResults[0].Provenance != nil {
		t.Errorf("Provenance at facts depth = %+v, want nil (provenance is a full-depth-only projection)", factsResults[0].Provenance)
	}

	fullResults, err := s.SearchFacts(ctx, "editor", vec, []GrantedScope{{Scope: "preferences.tools", Depth: "full"}}, 10)
	if err != nil {
		t.Fatalf("SearchFacts() at full depth error = %v", err)
	}
	if len(fullResults) != 1 {
		t.Fatalf("SearchFacts() at full depth = %+v, want 1 result", fullResults)
	}
	prov := fullResults[0].Provenance
	if prov == nil {
		t.Fatalf("Provenance at full depth = nil, want the approval trail")
	}
	if prov.SourceStagedDiffID != d.ID {
		t.Errorf("Provenance.SourceStagedDiffID = %q, want %q", prov.SourceStagedDiffID, d.ID)
	}
	if prov.DecidedBy == nil || *prov.DecidedBy != "human-reviewer" {
		t.Errorf("Provenance.DecidedBy = %v, want \"human-reviewer\"", prov.DecidedBy)
	}
	if prov.DecidedAt == nil {
		t.Error("Provenance.DecidedAt = nil, want the commit time")
	}
	if prov.SupersededBy != nil {
		t.Errorf("Provenance.SupersededBy = %v, want nil (fact is still current)", prov.SupersededBy)
	}
	if prov.InvalidAt != nil || prov.ExpiredAt != nil {
		t.Errorf("Provenance.{InvalidAt,ExpiredAt} = %v, %v, want both nil (fact is still current)", prov.InvalidAt, prov.ExpiredAt)
	}
	if fact.ID == "" {
		t.Fatal("CommitDiff() returned an empty fact ID")
	}
}

func TestSearchFacts_EffectiveDepthIntersectsAcrossFactTags(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	// A fact tagged with two scopes, each covered by exactly one grant, at
	// different depths. The fact is one indivisible blob: the LEAST
	// permissive per-tag result governs (intersection), so "summary" must
	// win overall even though the other tag alone was granted at "full".
	vec := unitVector(33)
	d, err := s.ProposeDiff(ctx, "agent-a", "planning a wedding in March with partner",
		[]string{"relationships.partner", "finances.budget"}, vec, nil, []string{"relationships.partner", "finances.budget"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec, "wedding planning summary"); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	granted := []GrantedScope{
		{Scope: "relationships.partner", Depth: "summary"},
		{Scope: "finances.budget", Depth: "full"},
	}
	results, err := s.SearchFacts(ctx, "wedding", vec, granted, 10)
	if err != nil {
		t.Fatalf("SearchFacts() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("SearchFacts() = %+v, want 1 result", results)
	}
	if got := results[0].Depth; got != "summary" {
		t.Errorf("Depth = %q, want %q (least permissive across the fact's two tags)", got, "summary")
	}
	if results[0].Content != "" {
		t.Errorf("Content = %q, want empty at the computed summary depth", results[0].Content)
	}
}

func TestSearchFacts_EffectiveDepthUnionsAcrossGrantsForOneTag(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	// A single-tag fact, covered by two active grants over that same tag at
	// different depths — e.g. an old broad grant and a newer narrower one.
	// Union across grants means the MORE permissive of the two wins: a stale
	// broad-depth grant already confers read access at all (strictly worse
	// than conferring it at greater depth), so it's not silently overridden
	// by a narrower grant existing alongside it — see effectiveDepth's doc
	// comment.
	vec := unitVector(34)
	d, err := s.ProposeDiff(ctx, "agent-a", "user's favorite coffee is a flat white", []string{"preferences.coffee"}, vec, nil, []string{"preferences.coffee"})
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec, "coffee summary"); err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	granted := []GrantedScope{
		{Scope: "preferences.coffee", Depth: "summary"},
		{Scope: "preferences.coffee", Depth: "full"},
	}
	results, err := s.SearchFacts(ctx, "coffee", vec, granted, 10)
	if err != nil {
		t.Fatalf("SearchFacts() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("SearchFacts() = %+v, want 1 result", results)
	}
	if got := results[0].Depth; got != "full" {
		t.Errorf("Depth = %q, want %q (most permissive across the two grants covering this tag)", got, "full")
	}
	if results[0].Content != "user's favorite coffee is a flat white" {
		t.Errorf("Content = %q, want the full fact content", results[0].Content)
	}
}

func TestGrantedScopes_CapabilityGrantDoesNotAuthorizeMemoryRead(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	// A capability-kind grant (no depth concept, governs something like git
	// commit signing — see store.GrantKind) must not also authorize memory
	// reads/writes over the same scope string. Before the kind = 'memory'
	// filter, GrantedScopes unioned across every grant regardless of kind.
	if _, err := s.CreateGrant(ctx, "agent-a", []string{"git.sign:github.com/abradner/chuvar"}, "capability", "", nil, "human-reviewer"); err != nil {
		t.Fatalf("CreateGrant() (capability) error = %v", err)
	}

	granted, err := s.GrantedScopes(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopes() error = %v", err)
	}
	if len(granted) != 0 {
		t.Fatalf("GrantedScopes() with only a capability-kind grant = %v, want none (capability grants must not authorize memory reads)", granted)
	}

	depths, err := s.GrantedScopeDepths(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopeDepths() error = %v", err)
	}
	if len(depths) != 0 {
		t.Fatalf("GrantedScopeDepths() with only a capability-kind grant = %+v, want none", depths)
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
	fact, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec, "")
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

	if err := s.LogAudit(ctx, "read", "agent-a", nil, nil, nil, nil, []string{"identity.basic"}, nil); err != nil {
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
	if _, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec, ""); err != nil {
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
	fact, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec, "")
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

	if _, err := s.CommitDiff(ctx, d1.ID, "human-reviewer", vec, ""); err != nil {
		t.Fatalf("CommitDiff() (d1) error = %v", err)
	}
	if _, err := s.CommitDiff(ctx, d2.ID, "human-reviewer", vec, ""); err == nil {
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
	fact, err := s.CommitDiff(ctx, d.ID, "human-reviewer", vec, "")
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

	g, err := s.CreateGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "human-reviewer")
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

// fullDepth wraps a flat scope list as GrantedScope pairs all at "full" depth —
// the pre-PR-4 behavior every test above this line was written against before
// depth enforcement existed. Tests that care about depth itself build
// []GrantedScope directly instead of going through this helper.
func fullDepth(scopes []string) []GrantedScope {
	out := make([]GrantedScope, len(scopes))
	for i, s := range scopes {
		out[i] = GrantedScope{Scope: s, Depth: "full"}
	}
	return out
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
