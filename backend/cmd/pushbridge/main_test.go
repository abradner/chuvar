package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abradner/chuvar/backend/internal/sseclient"
)

func TestHandleEvent_NotifiesOnAddedNotResolved(t *testing.T) {
	var calls int32
	var lastTitle string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		lastTitle = r.Header.Get("Title")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	n := &ntfyNotifier{baseURL: srv.URL, topic: "t", http: srv.Client()}
	ctx := context.Background()
	notified := map[string]struct{}{}
	grantNotified := map[string]time.Time{}

	handleEvent(ctx, n, "http://localhost:5173", notified, grantNotified, sseclient.Event{
		Type: "staged_diff_added",
		Diff: &sseclient.StagedDiff{ID: "d1", Subject: "agent-a", Content: "user likes tea"},
	})
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("calls after staged_diff_added = %d, want 1", calls)
	}
	if lastTitle != "New staged diff from agent-a" {
		t.Errorf("title = %q", lastTitle)
	}

	// "_resolved" events are deliberately not notified — nothing left to act on.
	handleEvent(ctx, n, "http://localhost:5173", notified, grantNotified, sseclient.Event{
		Type: "staged_diff_resolved",
		Diff: &sseclient.StagedDiff{ID: "d1"},
	})
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("calls after staged_diff_resolved = %d, want still 1 (no notification)", calls)
	}

	// "ready"/other server events also aren't notifications.
	handleEvent(ctx, n, "http://localhost:5173", notified, grantNotified, sseclient.Event{Type: "ready"})
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("calls after ready = %d, want still 1", calls)
	}
}

// TestHandleEvent_GrantExpiringDedupsOnGrantIDAndExpiresAt is the regression
// test for the notification-fatigue ticket: grant_expiring used to bypass
// dedup entirely, so a flapping SSE connection (streamEvents re-announces
// from an empty baseline on every reconnect, and pushbridge's own reconnect
// loop retries every 2s) produced one push per expiring grant per reconnect,
// unbounded. It now dedups on (grant ID, expires_at) — mirroring events.go's
// own warnedGrantKey — so a reconnect for the same still-expiring grant is
// suppressed, but a renewal (which changes expires_at) still re-warns.
func TestHandleEvent_GrantExpiringDedupsOnGrantIDAndExpiresAt(t *testing.T) {
	var calls int32
	var lastTitle string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		lastTitle = r.Header.Get("Title")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	n := &ntfyNotifier{baseURL: srv.URL, topic: "t", http: srv.Client()}
	ctx := context.Background()
	notified := map[string]struct{}{}
	grantNotified := map[string]time.Time{}

	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	ev := sseclient.Event{
		Type:  "grant_expiring",
		Grant: &sseclient.Grant{ID: "g1", Subject: "agent-a", Scopes: []string{"identity.basic"}, ExpiresAt: &expiresAt},
	}

	handleEvent(ctx, n, "http://localhost:5173", notified, grantNotified, ev)
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("calls after first grant_expiring = %d, want 1", calls)
	}
	if lastTitle != "Grant expiring soon: agent-a" {
		t.Errorf("title = %q", lastTitle)
	}

	// A reconnect re-announcing the same still-expiring grant (same ID, same
	// expires_at) must not re-notify.
	handleEvent(ctx, n, "http://localhost:5173", notified, grantNotified, ev)
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("calls after reconnect re-announce of the same grant = %d, want still 1 (suppressed)", calls)
	}

	// A renewal changes expires_at on the same grant ID — this must still
	// warn, since it's a legitimate second, later expiry warning, not a
	// duplicate of the first.
	renewedExpiresAt := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	renewedEv := sseclient.Event{
		Type:  "grant_expiring",
		Grant: &sseclient.Grant{ID: "g1", Subject: "agent-a", Scopes: []string{"identity.basic"}, ExpiresAt: &renewedExpiresAt},
	}
	handleEvent(ctx, n, "http://localhost:5173", notified, grantNotified, renewedEv)
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("calls after renewal (new expires_at) = %d, want 2 (renewal re-warns)", calls)
	}

	if len(notified) != 0 {
		t.Errorf("notified = %v, want grant_expiring to never populate the ID-only dedup map", notified)
	}
	if len(grantNotified) != 2 {
		t.Errorf("grantNotified = %v, want 2 entries (one per distinct expires_at seen)", grantNotified)
	}
}

// TestEvictExpiredGrantKeys_DropsOnlyPastExpiries confirms grantExpiryNotified
// doesn't grow unbounded over a long-running process: once a grant's
// expires_at is in the past, ListGrantsNearingExpiry can never re-emit that
// exact (grant ID, expires_at) pair again (store/grants.go excludes
// already-expired grants), so it's safe to drop. Still-future expiries, and
// the zero-value "couldn't parse it" fallback, must be left alone.
func TestEvictExpiredGrantKeys_DropsOnlyPastExpiries(t *testing.T) {
	m := map[string]time.Time{
		"past":    time.Now().Add(-time.Hour),
		"future":  time.Now().Add(time.Hour),
		"unknown": {}, // zero value, as handleEvent leaves it on a parse failure
	}

	evictExpiredGrantKeys(m)

	if _, ok := m["past"]; ok {
		t.Error("evictExpiredGrantKeys left a past-expiry key in place")
	}
	if _, ok := m["future"]; !ok {
		t.Error("evictExpiredGrantKeys dropped a still-future key")
	}
	if _, ok := m["unknown"]; !ok {
		t.Error("evictExpiredGrantKeys dropped a zero-value (unparseable) key")
	}
}

func TestHandleEvent_GrantRequestAddedIncludesJustification(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// io.ReadAll, not a single Read() call — see ntfy_test.go's matching fix.
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	n := &ntfyNotifier{baseURL: srv.URL, topic: "t", http: srv.Client()}

	handleEvent(context.Background(), n, "http://localhost:5173", map[string]struct{}{}, map[string]time.Time{}, sseclient.Event{
		Type: "grant_request_added",
		Req: &sseclient.GrantRequest{
			ID: "r1", Subject: "agent-a",
			RequestedScopes: []string{"identity.basic"},
			Justification:   "need this to greet the user by name",
		},
	})

	if !strings.Contains(gotBody, "need this to greet the user by name") {
		t.Errorf("notification body = %q, want it to include the justification", gotBody)
	}
}

// TestHandleEvent_DoesNotRenotifyAlreadyNotifiedID is the regression test for
// the review finding: a reconnect re-announces every still-pending item as
// "added" (events.go's own documented behavior), so without tracking what's
// already been notified, a flapping connection would spam the operator with
// repeat notifications for the same unresolved item.
func TestHandleEvent_DoesNotRenotifyAlreadyNotifiedID(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	n := &ntfyNotifier{baseURL: srv.URL, topic: "t", http: srv.Client()}
	ctx := context.Background()
	notified := map[string]struct{}{}
	grantNotified := map[string]time.Time{}
	ev := sseclient.Event{Type: "staged_diff_added", Diff: &sseclient.StagedDiff{ID: "d1", Subject: "agent-a"}}

	// Simulates the same item being re-announced "added" across two
	// reconnects of the underlying SSE stream, before it's ever resolved.
	handleEvent(ctx, n, "http://localhost:5173", notified, grantNotified, ev)
	handleEvent(ctx, n, "http://localhost:5173", notified, grantNotified, ev)
	handleEvent(ctx, n, "http://localhost:5173", notified, grantNotified, ev)

	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("notify calls = %d, want 1 (repeat re-announces of the same still-pending item must not re-notify)", calls)
	}
}

// TestHandleEvent_ResolutionAllowsRenotifyOfAFutureAddWithTheSameID confirms
// resolving an item clears it from the dedup set, so notified doesn't grow
// unbounded over a long-running process and a later, genuinely new item
// reusing an old ID (impossible with real UUIDs, but this is testing the
// bookkeeping logic itself) isn't permanently suppressed.
func TestHandleEvent_ResolutionClearsFromDedupSet(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	n := &ntfyNotifier{baseURL: srv.URL, topic: "t", http: srv.Client()}
	ctx := context.Background()
	notified := map[string]struct{}{}
	grantNotified := map[string]time.Time{}

	handleEvent(ctx, n, "http://localhost:5173", notified, grantNotified, sseclient.Event{
		Type: "staged_diff_added", Diff: &sseclient.StagedDiff{ID: "d1", Subject: "agent-a"},
	})
	if len(notified) != 1 {
		t.Fatalf("notified = %v, want d1 tracked", notified)
	}

	handleEvent(ctx, n, "http://localhost:5173", notified, grantNotified, sseclient.Event{
		Type: "staged_diff_resolved", Diff: &sseclient.StagedDiff{ID: "d1"},
	})
	if len(notified) != 0 {
		t.Fatalf("notified after resolution = %v, want empty", notified)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("notify calls after resolution = %d, want still 1 (resolutions don't notify)", calls)
	}
}

// TestHandleEvent_FailedNotifyIsNotMarkedNotified confirms a failed notify
// attempt isn't permanently suppressed — the next re-announce (e.g. after an
// ntfy outage recovers) should retry it, not silently give up forever.
func TestHandleEvent_FailedNotifyIsNotMarkedNotified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	n := &ntfyNotifier{baseURL: srv.URL, topic: "t", http: srv.Client()}
	ctx := context.Background()
	notified := map[string]struct{}{}
	grantNotified := map[string]time.Time{}

	handleEvent(ctx, n, "http://localhost:5173", notified, grantNotified, sseclient.Event{
		Type: "staged_diff_added", Diff: &sseclient.StagedDiff{ID: "d1", Subject: "agent-a"},
	})

	if _, ok := notified["d1"]; ok {
		t.Fatal("a failed notify was marked as notified — a later retry would be silently suppressed")
	}
}
