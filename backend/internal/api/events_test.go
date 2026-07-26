package api

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// sseEvent is one parsed "event: ...\ndata: ...\n\n" frame.
type sseEvent struct {
	Event string
	Data  string
}

// sseReader wraps a single background goroutine scanning an SSE response body —
// exactly one per connection, started once. A test that calls readSSE multiple
// times on the same response (the common case: read "ready", trigger a mutation,
// read the resulting event) must reuse this same reader; starting a fresh
// bufio.Scanner over body.Body on every call would race two goroutines against
// the same underlying io.Reader.
type sseReader struct {
	events chan sseEvent
}

func newSSEReader(body *http.Response) *sseReader {
	r := &sseReader{events: make(chan sseEvent, 16)}
	go func() {
		scanner := bufio.NewScanner(body.Body)
		var cur sseEvent
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				cur.Event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				cur.Data = strings.TrimPrefix(line, "data: ")
			case line == "":
				if cur.Event != "" {
					r.events <- cur
					cur = sseEvent{}
				}
			}
		}
		close(r.events)
	}()
	return r
}

// readSSE reads frames until it has collected want of them or the deadline
// elapses. Test-only: a real consumer (the TUI, the push bridge) would keep
// reading indefinitely instead of stopping at a count.
func (r *sseReader) readSSE(t *testing.T, want int, deadline time.Duration) []sseEvent {
	t.Helper()
	var got []sseEvent
	timeout := time.After(deadline)
	for len(got) < want {
		select {
		case e, ok := <-r.events:
			if !ok {
				t.Fatalf("readSSE: stream closed after %d events, want %d: %+v", len(got), want, got)
			}
			got = append(got, e)
		case <-timeout:
			t.Fatalf("readSSE: got %d events in %v, want %d: %+v", len(got), deadline, want, got)
		}
	}
	return got
}

func TestStreamEvents_AnnouncesNewStagedDiffAndItsResolution(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()

	// Shorten the poll interval for a fast test; restore it so other tests (and
	// other runs of this one under -count) aren't affected.
	orig := eventPollInterval
	eventPollInterval = 20 * time.Millisecond
	t.Cleanup(func() { eventPollInterval = orig })

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/events", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // closed via t.Cleanup below
	if err != nil {
		t.Fatalf("GET /api/events: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/events status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	sse := newSSEReader(resp)

	// The initial poll (before any diff exists) plus the "ready" marker.
	initial := sse.readSSE(t, 1, 2*time.Second)
	if initial[0].Event != "ready" {
		t.Fatalf("first event = %q, want %q (no pending diffs yet)", initial[0].Event, "ready")
	}

	diff, err := st.ProposeDiff(ctx, "agent-a", "user likes tea", []string{"preferences.tea"}, nil, nil, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}

	added := sse.readSSE(t, 1, 2*time.Second)
	if added[0].Event != "staged_diff_added" {
		t.Fatalf("event = %q, want %q", added[0].Event, "staged_diff_added")
	}
	if !strings.Contains(added[0].Data, diff.ID) {
		t.Errorf("staged_diff_added data = %q, want it to contain the diff ID %q", added[0].Data, diff.ID)
	}

	if err := st.RejectDiff(ctx, diff.ID, "human-reviewer"); err != nil {
		t.Fatalf("RejectDiff() error = %v", err)
	}

	resolved := sse.readSSE(t, 1, 2*time.Second)
	if resolved[0].Event != "staged_diff_resolved" {
		t.Fatalf("event = %q, want %q", resolved[0].Event, "staged_diff_resolved")
	}
	if !strings.Contains(resolved[0].Data, `"status":"rejected"`) {
		t.Errorf("staged_diff_resolved data = %q, want it to report status=rejected", resolved[0].Data)
	}
}

func TestStreamEvents_AnnouncesNewGrantRequestAndItsResolution(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()

	orig := eventPollInterval
	eventPollInterval = 20 * time.Millisecond
	t.Cleanup(func() { eventPollInterval = orig })

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/events", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // closed via t.Cleanup below
	if err != nil {
		t.Fatalf("GET /api/events: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	sse := newSSEReader(resp)

	sse.readSSE(t, 1, 2*time.Second) // "ready"

	greq, err := st.RequestGrant(ctx, "agent-a", []string{"identity.basic"}, "facts", nil, "")
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}

	added := sse.readSSE(t, 1, 2*time.Second)
	if added[0].Event != "grant_request_added" {
		t.Fatalf("event = %q, want %q", added[0].Event, "grant_request_added")
	}

	if _, err := st.ApproveGrantRequest(ctx, greq.ID, "human-reviewer"); err != nil {
		t.Fatalf("ApproveGrantRequest() error = %v", err)
	}

	resolved := sse.readSSE(t, 1, 2*time.Second)
	if resolved[0].Event != "grant_request_resolved" {
		t.Fatalf("event = %q, want %q", resolved[0].Event, "grant_request_resolved")
	}
	if !strings.Contains(resolved[0].Data, `"status":"approved"`) {
		t.Errorf("grant_request_resolved data = %q, want it to report status=approved", resolved[0].Data)
	}
}

func TestStreamEvents_RequiresAuth(t *testing.T) {
	srv, _ := testServer(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/events", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/events: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /api/events with no Authorization header: status = %d, want 401", resp.StatusCode)
	}
}
