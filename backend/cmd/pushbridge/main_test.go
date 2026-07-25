package main

import (
	"context"
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

	handleEvent(ctx, n, "http://localhost:5173", sseclient.Event{
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
	handleEvent(ctx, n, "http://localhost:5173", sseclient.Event{
		Type: "staged_diff_resolved",
		Diff: &sseclient.StagedDiff{ID: "d1"},
	})
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("calls after staged_diff_resolved = %d, want still 1 (no notification)", calls)
	}

	// "ready"/other server events also aren't notifications.
	handleEvent(ctx, n, "http://localhost:5173", sseclient.Event{Type: "ready"})
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("calls after ready = %d, want still 1", calls)
	}
}

func TestHandleEvent_GrantRequestAddedIncludesJustification(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	n := &ntfyNotifier{baseURL: srv.URL, topic: "t", http: srv.Client()}

	handleEvent(context.Background(), n, "http://localhost:5173", sseclient.Event{
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
