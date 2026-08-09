package broker

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abradner/chuvar/backend/internal/scope"
)

// hashToken derives the lookup key for a plaintext bearer token, the same
// way store.HashToken does for reviewer tokens (crypto/sha256 — this value
// is compared against untrusted socket input on every request, so it must
// resist adversarial construction, not just accidental collision). Not
// reused from internal/store directly: this package deliberately holds no
// dependency on that package at all (see store.go's doc comment) — three
// lines of sha256 is a smaller cost than the dependency it would avoid.
func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// Entry is one authorized capability grant, as held in the live cache.
type Entry struct {
	GrantID        string
	Subject        string
	CommitterEmail string
	Scopes         []scope.Scope
	ExpiresAt      *time.Time
}

// expired reports whether e's grant has passed its expiry, checked against
// wall-clock time at the moment of the call — not against cache freshness.
// This is what lets expiry be enforced correctly even between cache
// refreshes: a stale-but-not-yet-refreshed cache entry for an expired grant
// still answers NO_GRANT correctly, because every Lookup re-checks this
// rather than trusting the cache's mere presence of the entry.
func (e Entry) expired() bool {
	return e.ExpiresAt != nil && !time.Now().Before(*e.ExpiresAt)
}

// Cache is brokerd's in-memory index of active capability grants, keyed by
// hashed socket-auth token. Built once from the database at boot and kept
// current by a combination of a push (LISTEN/NOTIFY on revocation, see
// Watch) and a periodic pull (a full reload, the fallback for a missed or
// dropped notification) — see Watch's doc comment for the full reasoning.
//
// This is what makes the 2026-08-09 "the sign call consults only in-process
// state" decision true for the *authorization* question: Lookup never
// touches the database. Sign's own audit write is the one part of a sign
// call that still does (see broker.go).
type Cache struct {
	pool *pgxpool.Pool

	// loadMu serializes Load end to end (query included), so two concurrent
	// reloads (the periodic reconcile tick and watchNotify's post-reconnect
	// reload) can never apply their snapshots out of order — without it, an
	// older query's snapshot could land after a newer one's and briefly
	// reintroduce whatever the newer one had already dropped.
	loadMu sync.Mutex

	mu      sync.RWMutex
	byToken map[string]Entry  // key: hashToken(plaintext), as a string for map-key use
	tokenOf map[string]string // grantID -> byToken key, so Remove(grantID) doesn't need the plaintext token

	// tombstones records grants evicted by Remove, so a reload whose
	// database snapshot was taken *before* a revocation committed cannot
	// resurrect the revoked grant when its map swap lands *after* the
	// NOTIFY-triggered Remove already evicted it (Load runs concurrently
	// with watchNotify's Remove by design; without this, that interleaving
	// silently reinstates a revoked grant's signing token until the next
	// reload — exactly the window success criterion 4 says must not exist).
	// Safe because a revocation is permanent (revoked_at is set, never
	// cleared, anywhere in this codebase — history is append-only), so
	// suppressing a tombstoned grant id can never suppress a legitimately
	// active grant. Entries are pruned after tombstoneTTL purely to bound
	// memory; see apply.
	tombstones map[string]time.Time
}

// tombstoneTTL bounds how long a Remove'd grant id keeps suppressing
// reloads. It only needs to outlive the longest plausible gap between a
// reload's database snapshot and its map swap (a single query's duration —
// seconds at worst); minutes is comfortably past that while keeping the
// tombstone map bounded by "revocations in the last few minutes," which at
// human revocation rates is a handful of entries.
const tombstoneTTL = 5 * time.Minute

// NewCache returns an empty Cache. Callers must call Load before serving any
// request — an empty-but-never-loaded cache and an empty-because-no-grants-
// exist cache are indistinguishable by design (both correctly answer
// NO_GRANT to everything), so there is no separate "not ready" state to
// plumb through the socket protocol; an operator relying on this should
// confirm via logs that the initial Load succeeded, which cmd/brokerd's
// boot sequence treats as fatal if it doesn't (fail closed, not "start
// serving NO_GRANT to everyone and hope someone notices").
func NewCache(pool *pgxpool.Pool) *Cache {
	return &Cache{
		pool:       pool,
		byToken:    make(map[string]Entry),
		tokenOf:    make(map[string]string),
		tombstones: make(map[string]time.Time),
	}
}

// Load replaces the cache's contents wholesale with the current set of
// active capability grants read from the database. Safe to call
// concurrently with Lookup and Remove — see apply for how the swap
// interacts with a Remove that raced the query, and the loadMu field for
// how concurrent Loads are ordered.
func (c *Cache) Load(ctx context.Context) error {
	c.loadMu.Lock()
	defer c.loadMu.Unlock()
	rows, err := loadCapabilityGrants(ctx, c.pool)
	if err != nil {
		return fmt.Errorf("broker: cache load: %w", err)
	}
	c.apply(rows)
	return nil
}

// apply builds and swaps in the cache maps from a query snapshot. The swap
// is atomic under the write lock, so a concurrent Lookup sees either the old
// or the new snapshot, never a partially-rebuilt one.
//
// The tombstone pass is the ordering guard between a reload and a
// concurrent Remove (see the tombstones field's doc comment for the exact
// interleaving it closes): rows is a database snapshot that may predate a
// revocation the NOTIFY path has already acted on, so any grant Remove has
// evicted is deleted from the snapshot before it goes live. Remove and
// apply both run under c.mu, so a Remove lands either before the swap (its
// tombstone filters the snapshot here) or after it (it deletes from the
// newly-swapped maps directly) — there is no third interleaving.
func (c *Cache) apply(rows []grantRow) {
	byToken := make(map[string]Entry, len(rows))
	tokenOf := make(map[string]string, len(rows))
	for _, r := range rows {
		scopes, err := parseScopes(r.Scopes)
		if err != nil {
			// A grant with an unparseable stored scope is an operator/data
			// problem (scope.Validate already runs wherever a scope is
			// meant to be written), not a reason to fail the whole cache
			// load — every other grant should still work. Logged loudly,
			// skipped individually.
			slog.Error("broker: cache load: skipping grant with invalid stored scope",
				"grant_id", r.ID, "error", err)
			continue
		}
		key := string(r.TokenHash)
		byToken[key] = Entry{
			GrantID:        r.ID,
			Subject:        r.Subject,
			CommitterEmail: r.CommitterEmail,
			Scopes:         scopes,
			ExpiresAt:      r.ExpiresAt,
		}
		tokenOf[r.ID] = key
	}

	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, at := range c.tombstones {
		if now.Sub(at) > tombstoneTTL {
			delete(c.tombstones, id)
			continue
		}
		if key, ok := tokenOf[id]; ok {
			delete(byToken, key)
			delete(tokenOf, id)
		}
	}
	c.byToken = byToken
	c.tokenOf = tokenOf
}

func parseScopes(raw []string) ([]scope.Scope, error) {
	out := make([]scope.Scope, len(raw))
	for i, s := range raw {
		sc := scope.Scope(s)
		if err := scope.Validate(sc); err != nil {
			return nil, err
		}
		out[i] = sc
	}
	return out, nil
}

// Lookup finds the active grant authorized by plaintext, if any. The second
// return value is false both when no grant matches the token at all and
// when a matching grant has since expired — deliberately indistinguishable
// to the caller (see Entry.expired's doc comment on why expiry is
// re-checked here rather than trusted from cache freshness), matching
// AuthenticateReviewerToken's stance in internal/store: "no such active
// token" and "revoked/expired token" collapse to the same false, so a
// caller can't use response shape to probe which tokens exist versus are
// merely expired.
func (c *Cache) Lookup(plaintext string) (Entry, bool) {
	// A Go map lookup, not a byte-by-byte comparison against attacker-
	// controlled input — same reasoning as AuthenticateReviewerToken's own
	// doc comment: this is an exact-match hash-table lookup keyed by a full
	// SHA-256 hash, whose timing is a function of hash-table bucket depth,
	// not of how many leading bytes of the presented token happened to
	// match some stored value. No subtle.ConstantTimeCompare needed here
	// for the same reason none is needed there.
	key := string(hashToken(plaintext))
	c.mu.RLock()
	e, ok := c.byToken[key]
	c.mu.RUnlock()
	if !ok || e.expired() {
		return Entry{}, false
	}
	return e, true
}

// Remove drops grantID from the cache immediately, with no database round
// trip — this is what makes revocation propagate at in-process speed (the
// "revoking stops signing within seconds" success criterion) even under
// Watch's push path, and what keeps the push path from needing to touch the
// database at all: the revocation trigger's NOTIFY payload is the grant id,
// nothing more is needed to answer "is this grant still good."
func (c *Cache) Remove(grantID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Tombstone unconditionally — even when the grant isn't currently in the
	// maps. An in-flight reload's snapshot can contain a grant this cache
	// has never held (loaded-then-revoked before this process's first sight
	// of it, mid-query), and the tombstone is what keeps that snapshot from
	// introducing it. See the tombstones field's doc comment.
	c.tombstones[grantID] = time.Now()
	if key, ok := c.tokenOf[grantID]; ok {
		delete(c.byToken, key)
		delete(c.tokenOf, grantID)
	}
}

// Watch runs until ctx is cancelled, keeping the cache current via two
// independent mechanisms — chosen and justified here rather than only in
// the commit message, since this is the load-bearing design decision
// issue #95 left open ("pick LISTEN/NOTIFY or the existing SSE stream"):
//
//  1. LISTEN on the chuvar_grant_revoked channel (see the
//     20260809140000_capability_grant_signing migration's trigger): a
//     revocation notifies with the grant id as payload, and this loop
//     calls Cache.Remove directly — no query, so a revocation reaches the
//     cache even if, at that exact moment, the rest of the database is
//     under load. LISTEN/NOTIFY was chosen over reusing the existing SSE
//     stream (internal/api/events.go) because that stream is an
//     apiserver-owned HTTP surface built for the browser approval UI —
//     coupling brokerd to it would mean brokerd depending on apiserver
//     being up (a second process, a second failure mode) purely to learn
//     about a database change both processes can already see directly.
//     LISTEN/NOTIFY is native to the one thing brokerd already depends on
//     (Postgres), needs no new schema surface beyond the trigger, and
//     needs no HTTP client, timeout, or retry policy of its own.
//  2. A periodic full Load, independent of (1). LISTEN connections can
//     drop (network blip, pool churn) without an application-visible
//     error until the next attempted read — a dropped LISTEN silently
//     stops delivering notifications rather than failing loudly. The
//     periodic reload is the fallback that bounds how long that gap can
//     last, and it is also what picks up newly-provisioned grants (no
//     capability-grant creation surface exists yet — issue #96 — so this
//     matters more for future-proofing than for anything reachable today).
//
// A dropped LISTEN connection reconnects with a fixed backoff and forces an
// immediate reload on reconnect, to close the gap the drop opened rather
// than waiting out the rest of the current reconcile interval.
func (c *Cache) Watch(ctx context.Context, reconcileInterval time.Duration) {
	go c.watchNotify(ctx)

	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Load(ctx); err != nil {
				slog.Error("broker: periodic cache reload failed", "error", err)
			}
		}
	}
}

// listenReconnectDelay bounds how fast watchNotify retries a dropped LISTEN
// connection — fast enough that a transient blip barely matters, slow
// enough not to hammer a database that's down for a real reason.
const listenReconnectDelay = 2 * time.Second

func (c *Cache) watchNotify(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := c.listenOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("broker: revocation-watch LISTEN connection failed, reconnecting",
				"error", err, "retry_in", listenReconnectDelay)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(listenReconnectDelay):
		}
		if ctx.Err() != nil {
			return
		}
		// Close the gap the drop opened rather than waiting out the rest
		// of the periodic reconcile interval — see Watch's doc comment,
		// point 2.
		if err := c.Load(ctx); err != nil {
			slog.Error("broker: post-reconnect cache reload failed", "error", err)
		}
	}
}

func (c *Cache) listenOnce(ctx context.Context) error {
	conn, err := c.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("broker: acquiring LISTEN connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN chuvar_grant_revoked"); err != nil {
		return fmt.Errorf("broker: LISTEN chuvar_grant_revoked: %w", err)
	}

	for {
		notif, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return fmt.Errorf("broker: waiting for notification: %w", err)
		}
		c.Remove(notif.Payload)
	}
}
