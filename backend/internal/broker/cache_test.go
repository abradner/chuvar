package broker

import (
	"context"
	"testing"
	"time"
)

func TestCache_LoadAndLookup(t *testing.T) {
	pool := testPool(t)
	fx := insertCapabilityGrant(t, pool, "agent-a", "agent@example.com",
		[]string{"git.sign:github.com/abradner/chuvar"}, nil)

	c := NewCache(pool)
	if err := c.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}

	e, ok := c.Lookup(fx.Token)
	if !ok {
		t.Fatal("Lookup(valid token): ok = false, want true")
	}
	if e.GrantID != fx.GrantID {
		t.Errorf("GrantID = %q, want %q", e.GrantID, fx.GrantID)
	}
	if e.CommitterEmail != "agent@example.com" {
		t.Errorf("CommitterEmail = %q", e.CommitterEmail)
	}
	if len(e.Scopes) != 1 || e.Scopes[0] != "git.sign:github.com/abradner/chuvar" {
		t.Errorf("Scopes = %v", e.Scopes)
	}
}

// TestCache_Load_SkipsGrantWithInvalidStoredScope exercises Load's
// scope.Validate error branch: grant_scopes has no CHECK constraint
// enforcing scope.Validate's grammar (scope is plain TEXT, per AGENTS.md
// §3.4 — "don't hardcode the taxonomy"), so a row that somehow bypassed
// application-level validation is a real, if unlikely, state the cache must
// not crash or refuse everything else over. One bad grant is logged and
// skipped; every other grant still loads.
func TestCache_Load_SkipsGrantWithInvalidStoredScope(t *testing.T) {
	pool := testPool(t)
	bad := insertCapabilityGrant(t, pool, "agent-bad", "bad@example.com", nil, nil)
	// grant_scopes has no format constraint at the DB level — insert an
	// invalid scope directly, bypassing scope.Validate entirely, the way a
	// hypothetical future writer with a bug could.
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO grant_scopes (grant_id, scope) VALUES ($1, $2)`, bad.GrantID, "Not A Valid Scope!"); err != nil {
		t.Fatalf("inserting invalid scope fixture: %v", err)
	}
	good := insertCapabilityGrant(t, pool, "agent-good", "good@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)

	c := NewCache(pool)
	if err := c.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v (must not fail the whole load over one bad row)", err)
	}

	if _, ok := c.Lookup(bad.Token); ok {
		t.Error("Lookup(token for the invalid-scope grant): ok = true, want false (skipped)")
	}
	if _, ok := c.Lookup(good.Token); !ok {
		t.Error("Lookup(token for the unrelated valid grant): ok = false, want true (unaffected by the bad row)")
	}
}

// TestCache_Load_SkipsUntargetedCapabilityScope exercises the require-target
// half of parseScopes specifically — distinct from
// TestCache_Load_SkipsGrantWithInvalidStoredScope above, which covers a
// scope that fails even the base scope.Validate grammar check. "git.sign"
// alone is syntactically well-formed (scope.Validate accepts it — it's
// exactly what a memory scope looks like) but is not a valid *capability*
// scope per the 2026-08-09 require-target decision
// (docs/capability-broker.md): scope.ValidateCapability rejects it, and
// parseScopes must too. No capability-grant creation surface exists yet
// (#96) to have refused this at write time, so a grant row seeded directly
// (a fixture, or an operator's psql — exactly the scenario
// scope.ValidateCapability's doc comment names) is the realistic way this
// state reaches the cache. The grant must be refused loudly (logged) and
// treated as absent — the resulting Cache.Lookup miss is what makes the
// broker answer NO_GRANT rather than caching a grant that could never
// legitimately match any request checkScope would accept (checkScope
// itself requires every *request* scope to carry a target too — see
// TestBroker_Sign_UntargetedCapabilityGrantNeverCached for the same
// scenario proven at the Broker level, and that test's doc comment for why
// NO_GRANT, not SCOPE_DENIED, is the correct code here).
func TestCache_Load_SkipsUntargetedCapabilityScope(t *testing.T) {
	pool := testPool(t)
	bad := insertCapabilityGrant(t, pool, "agent-bad", "bad@example.com", []string{"git.sign"}, nil)
	good := insertCapabilityGrant(t, pool, "agent-good", "good@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)

	c := NewCache(pool)
	if err := c.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v (must not fail the whole load over one untargeted grant)", err)
	}

	if _, ok := c.Lookup(bad.Token); ok {
		t.Error("Lookup(token for the untargeted-scope grant): ok = true, want false (skipped)")
	}
	if _, ok := c.Lookup(good.Token); !ok {
		t.Error("Lookup(token for the unrelated targeted grant): ok = false, want true (unaffected by the untargeted row)")
	}
}

func TestCache_Lookup_UnknownTokenRejected(t *testing.T) {
	pool := testPool(t)
	insertCapabilityGrant(t, pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)

	c := NewCache(pool)
	if err := c.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if _, ok := c.Lookup("not-a-real-token"); ok {
		t.Fatal("Lookup(unknown token): ok = true, want false")
	}
}

func TestCache_Lookup_ExpiredGrantExcluded(t *testing.T) {
	pool := testPool(t)
	past := -time.Hour
	fx := insertCapabilityGrant(t, pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, &past)

	c := NewCache(pool)
	if err := c.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Excluded at Load time by the query itself (expires_at > now()).
	if _, ok := c.Lookup(fx.Token); ok {
		t.Fatal("Lookup(token for an already-expired grant): ok = true, want false")
	}
}

// TestCache_Lookup_ExpiresBetweenRefreshes is the case Entry.expired's doc
// comment describes: a grant that was active when Load ran, but whose
// expiry has since passed, before any refresh has happened. Lookup must
// still deny it — expiry is enforced live, not merely at load time.
func TestCache_Lookup_ExpiresBetweenRefreshes(t *testing.T) {
	pool := testPool(t)
	soon := 50 * time.Millisecond
	fx := insertCapabilityGrant(t, pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, &soon)

	c := NewCache(pool)
	if err := c.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := c.Lookup(fx.Token); !ok {
		t.Fatal("Lookup immediately after Load: ok = false, want true (grant hasn't expired yet)")
	}

	time.Sleep(100 * time.Millisecond)

	if _, ok := c.Lookup(fx.Token); ok {
		t.Fatal("Lookup after the grant's expiry elapsed (no reload in between): ok = true, want false")
	}
}

func TestCache_Lookup_RevokedGrantExcludedAfterReload(t *testing.T) {
	pool := testPool(t)
	fx := insertCapabilityGrant(t, pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)

	c := NewCache(pool)
	if err := c.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := c.Lookup(fx.Token); !ok {
		t.Fatal("Lookup before revocation: ok = false, want true")
	}

	revokeGrant(t, pool, fx.GrantID)
	if err := c.Load(context.Background()); err != nil {
		t.Fatalf("Load (reload after revoke): %v", err)
	}

	if _, ok := c.Lookup(fx.Token); ok {
		t.Fatal("Lookup after revoke+reload: ok = true, want false")
	}
}

func TestCache_Remove_DropsEntryWithoutReload(t *testing.T) {
	pool := testPool(t)
	fx := insertCapabilityGrant(t, pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)

	c := NewCache(pool)
	if err := c.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}

	c.Remove(fx.GrantID)

	if _, ok := c.Lookup(fx.Token); ok {
		t.Fatal("Lookup after Remove: ok = true, want false")
	}
}

func TestCache_Remove_UnknownGrantIDIsNoOp(t *testing.T) {
	c := NewCache(nil)
	c.Remove("00000000-0000-0000-0000-000000000000") // must not panic
}

// TestCache_StaleReloadCannotResurrectRevokedGrant reproduces, step by
// deterministic step, the interleaving Watch makes possible: a periodic
// reload's query snapshot is taken *before* a revocation commits, but its
// map swap lands *after* the LISTEN/NOTIFY path's Remove already evicted
// the grant. Without the tombstone pass in apply, the stale swap silently
// reinstates the revoked grant's signing token until the next reload —
// violating success criterion 4 ("afterwards the agent holds nothing that
// still works") for up to a full reconcile interval. Uses the real
// loadCapabilityGrants/Remove/apply code paths, sequenced by hand.
func TestCache_StaleReloadCannotResurrectRevokedGrant(t *testing.T) {
	pool := testPool(t)
	fx := insertCapabilityGrant(t, pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)

	c := NewCache(pool)
	if err := c.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// 1. A concurrent reload's query snapshot, taken while the grant is
	// still active — exactly what loadCapabilityGrants inside Load reads.
	staleRows, err := loadCapabilityGrants(context.Background(), pool)
	if err != nil {
		t.Fatalf("loadCapabilityGrants: %v", err)
	}

	// 2. The revocation commits, and the NOTIFY-triggered path evicts it.
	revokeGrant(t, pool, fx.GrantID)
	c.Remove(fx.GrantID)
	if _, ok := c.Lookup(fx.Token); ok {
		t.Fatal("Lookup after Remove: ok = true, want false")
	}

	// 3. The stale snapshot's map-build-and-swap lands — the same apply
	// step Load runs on the snapshot it read.
	c.apply(staleRows)

	if _, ok := c.Lookup(fx.Token); ok {
		t.Fatal("a stale reload resurrected a revoked grant's signing token")
	}
}

// TestCache_Remove_TombstonesGrantTheCacheNeverHeld covers Remove's
// unconditional-tombstone branch: a revocation NOTIFY can arrive for a
// grant this cache has never loaded (created and revoked while a reload's
// query was in flight), and the in-flight snapshot — which does contain it
// — must still not introduce it.
func TestCache_Remove_TombstonesGrantTheCacheNeverHeld(t *testing.T) {
	c := NewCache(nil) // no database: apply/Remove/Lookup are pure map operations
	const grantID = "11111111-1111-1111-1111-111111111111"
	const token = "some-plaintext-token"

	c.Remove(grantID) // NOTIFY beat the first load that would have contained this grant

	c.apply([]grantRow{{
		ID:             grantID,
		Subject:        "agent-a",
		CommitterEmail: "agent@example.com",
		TokenHash:      hashToken(token),
		Scopes:         []string{"git.sign:github.com/abradner/chuvar"},
	}})

	if _, ok := c.Lookup(token); ok {
		t.Fatal("apply introduced a grant that was revoked before the cache ever held it")
	}
}

// TestCache_TombstonesPrunedAfterTTL pins the memory bound apply claims:
// tombstones exist only to cover the snapshot-to-swap window (seconds), and
// entries older than tombstoneTTL are dropped on the next apply rather than
// accumulating for the process's lifetime.
func TestCache_TombstonesPrunedAfterTTL(t *testing.T) {
	c := NewCache(nil)
	c.Remove("11111111-1111-1111-1111-111111111111")

	c.mu.Lock()
	c.tombstones["11111111-1111-1111-1111-111111111111"] = time.Now().Add(-tombstoneTTL - time.Minute)
	c.mu.Unlock()

	c.apply(nil)

	c.mu.Lock()
	n := len(c.tombstones)
	c.mu.Unlock()
	if n != 0 {
		t.Fatalf("tombstones after applying past the TTL = %d entries, want 0 (pruned)", n)
	}
}

// TestCache_Watch_RevocationPropagatesViaNotify is the end-to-end proof of
// the design decision Watch's own doc comment justifies: revoking a grant
// through an ordinary SQL UPDATE (standing in for whatever future path
// actually performs a revocation — apiserver's today) reaches a running
// Cache.Watch loop via LISTEN/NOTIFY, with no explicit Load call from the
// test at all.
func TestCache_Watch_RevocationPropagatesViaNotify(t *testing.T) {
	pool := testPool(t)
	fx := insertCapabilityGrant(t, pool, "agent-a", "agent@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)

	c := NewCache(pool)
	if err := c.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := c.Lookup(fx.Token); !ok {
		t.Fatal("Lookup before revocation: ok = false, want true")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Watch(ctx, time.Hour) // long reconcile interval: this test is about the NOTIFY path, not the poll fallback

	// Give the watch loop time to establish its LISTEN before revoking —
	// otherwise the notification could fire before anyone's listening for
	// it (NOTIFY has no delivery guarantee to a not-yet-subscribed
	// session).
	time.Sleep(200 * time.Millisecond)

	revokeGrant(t, pool, fx.GrantID)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := c.Lookup(fx.Token); !ok {
			return // propagated
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("revocation did not propagate to the cache via LISTEN/NOTIFY within 5s")
}
