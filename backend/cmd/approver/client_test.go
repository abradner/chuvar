package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseEvent_StagedDiff(t *testing.T) {
	ev := parseEvent("staged_diff_added", `{"id":"d1","subject":"agent-a","content":"user likes tea"}`)
	if ev.Type != "staged_diff_added" {
		t.Fatalf("Type = %q, want staged_diff_added", ev.Type)
	}
	if ev.Diff == nil || ev.Diff.ID != "d1" || ev.Diff.Content != "user likes tea" {
		t.Fatalf("Diff = %+v, want a parsed stagedDiff with id=d1", ev.Diff)
	}
}

func TestParseEvent_GrantRequest(t *testing.T) {
	ev := parseEvent("grant_request_resolved", `{"id":"r1","status":"approved"}`)
	if ev.Req == nil || ev.Req.ID != "r1" || ev.Req.Status != "approved" {
		t.Fatalf("Req = %+v, want a parsed grantRequest with id=r1 status=approved", ev.Req)
	}
}

func TestParseEvent_MalformedJSONReportsParseError(t *testing.T) {
	ev := parseEvent("staged_diff_added", `{not valid json`)
	if ev.Type != "parse_error" {
		t.Fatalf("Type = %q, want parse_error for malformed JSON", ev.Type)
	}
}

func TestParseEvent_ReadyHasNoPayload(t *testing.T) {
	ev := parseEvent("ready", `{"ok":true}`)
	if ev.Type != "ready" || ev.Diff != nil || ev.Req != nil {
		t.Fatalf("parseEvent(ready) = %+v, want Type=ready with no Diff/Req", ev)
	}
}

// TestStreamEvents_ParsesRealSSEResponse exercises the actual HTTP + SSE parsing
// path (not just parseEvent in isolation) against a real server, the same way
// internal/api/events_test.go tests the producing side.
func TestStreamEvents_ParsesRealSSEResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "event: ready\ndata: {\"ok\":true}\n\n")
		fmt.Fprintf(w, "event: staged_diff_added\ndata: {\"id\":\"d1\",\"subject\":\"agent-a\"}\n\n")
		w.(http.Flusher).Flush()
	}))
	defer srv.Close()

	c := &apiClient{baseURL: srv.URL, token: "test-token", http: &http.Client{}}
	out := make(chan sseEvent, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := c.streamEvents(ctx, out)
	// The handler closes its response after writing two events (no keep-open
	// loop), so streamEvents should return cleanly once it hits EOF — not an
	// error a caller needs to treat as a real failure. streamEventsWithReconnect
	// (main.go) already handles both cases identically (retry either way).
	if err != nil {
		t.Logf("streamEvents returned %v (expected: server closed the connection)", err)
	}

	close(out)
	var events []sseEvent
	for e := range out {
		events = append(events, e)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(events), events)
	}
	if events[0].Type != "ready" {
		t.Errorf("events[0].Type = %q, want ready", events[0].Type)
	}
	if events[1].Type != "staged_diff_added" || events[1].Diff.ID != "d1" {
		t.Errorf("events[1] = %+v, want staged_diff_added for d1", events[1])
	}
}

func TestStreamEvents_UnauthorizedReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := &apiClient{baseURL: srv.URL, token: "wrong", http: &http.Client{}}
	out := make(chan sseEvent, 1)
	if err := c.streamEvents(context.Background(), out); err == nil {
		t.Fatal("streamEvents() with a 401 response: want an error, got nil")
	}
}
