package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

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

	handleEvent(ctx, n, "http://localhost:5173", notified, sseclient.Event{
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
	handleEvent(ctx, n, "http://localhost:5173", notified, sseclient.Event{
		Type: "staged_diff_resolved",
		Diff: &sseclient.StagedDiff{ID: "d1"},
	})
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("calls after staged_diff_resolved = %d, want still 1 (no notification)", calls)
	}

	// "ready"/other server events also aren't notifications.
	handleEvent(ctx, n, "http://localhost:5173", notified, sseclient.Event{Type: "ready"})
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("calls after ready = %d, want still 1", calls)
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

	handleEvent(context.Background(), n, "http://localhost:5173", map[string]struct{}{}, sseclient.Event{
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
	ev := sseclient.Event{Type: "staged_diff_added", Diff: &sseclient.StagedDiff{ID: "d1", Subject: "agent-a"}}

	// Simulates the same item being re-announced "added" across two
	// reconnects of the underlying SSE stream, before it's ever resolved.
	handleEvent(ctx, n, "http://localhost:5173", notified, ev)
	handleEvent(ctx, n, "http://localhost:5173", notified, ev)
	handleEvent(ctx, n, "http://localhost:5173", notified, ev)

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

	handleEvent(ctx, n, "http://localhost:5173", notified, sseclient.Event{
		Type: "staged_diff_added", Diff: &sseclient.StagedDiff{ID: "d1", Subject: "agent-a"},
	})
	if len(notified) != 1 {
		t.Fatalf("notified = %v, want d1 tracked", notified)
	}

	handleEvent(ctx, n, "http://localhost:5173", notified, sseclient.Event{
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

	handleEvent(ctx, n, "http://localhost:5173", notified, sseclient.Event{
		Type: "staged_diff_added", Diff: &sseclient.StagedDiff{ID: "d1", Subject: "agent-a"},
	})

	if _, ok := notified["d1"]; ok {
		t.Fatal("a failed notify was marked as notified — a later retry would be silently suppressed")
	}
}
