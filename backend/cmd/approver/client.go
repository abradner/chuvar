package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// stagedDiff and grantRequest mirror the JSON shapes internal/api's
// stagedDiffView / grantRequestView produce — redefined here rather than
// imported because this is a separate binary talking to the REST API over
// HTTP, the same relationship the frontend's api/client.ts has to the backend
// (its own independently-defined TypeScript interfaces, not a shared package).
type stagedDiff struct {
	ID                    string   `json:"id"`
	Subject               string   `json:"subject"`
	Content               string   `json:"content"`
	ProposedScopes        []string `json:"proposed_scopes"`
	TargetFactID          *string  `json:"target_fact_id,omitempty"`
	Status                string   `json:"status"`
	DedupeVerdict         *string  `json:"dedupe_verdict,omitempty"`
	DedupeCandidateFactID *string  `json:"dedupe_candidate_fact_id,omitempty"`
	CreatedAt             string   `json:"created_at"`
}

type grantRequest struct {
	ID                  string   `json:"id"`
	Subject             string   `json:"subject"`
	RequestedScopes     []string `json:"requested_scopes"`
	Depth               string   `json:"depth"`
	RequestedTTLSeconds *int     `json:"requested_ttl_seconds,omitempty"`
	Justification       string   `json:"justification"`
	Status              string   `json:"status"`
	CreatedAt           string   `json:"created_at"`
}

// sseEvent is one parsed "event: ...\ndata: ...\n\n" frame from the stream, with
// its data payload already unmarshaled into whichever of the two shapes matches
// Type. "connection_error" is synthesized locally (main.go) when the stream
// drops, not something the server ever sends.
type sseEvent struct {
	Type   string
	Diff   *stagedDiff
	Req    *grantRequest
	Detail string // only set for connection_error / unrecognized-event cases
}

type apiClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func (c *apiClient) newRequest(ctx context.Context, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	return req, nil
}

// streamEvents connects to GET /api/events and pushes parsed frames to out until
// ctx is canceled or the connection drops. Blocking; callers loop it (see
// streamEventsWithReconnect in main.go).
func (c *apiClient) streamEvents(ctx context.Context, out chan<- sseEvent) error {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/events")
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /api/events: status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	// Staged-diff and grant-request payloads (especially the justification /
	// content free-text fields) can comfortably exceed bufio.Scanner's 64KiB
	// default token buffer on a single "data: ..." line; grow the limit rather
	// than have a long fact silently truncate the stream.
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var eventName, data string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			eventName = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		case line == "":
			if eventName == "" {
				continue
			}
			ev := parseEvent(eventName, data)
			eventName, data = "", ""
			select {
			case out <- ev:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return io.EOF
}

func parseEvent(eventName, data string) sseEvent {
	switch eventName {
	case "staged_diff_added", "staged_diff_resolved":
		var d stagedDiff
		if err := json.Unmarshal([]byte(data), &d); err != nil {
			return sseEvent{Type: "parse_error", Detail: err.Error()}
		}
		return sseEvent{Type: eventName, Diff: &d}
	case "grant_request_added", "grant_request_resolved":
		var r grantRequest
		if err := json.Unmarshal([]byte(data), &r); err != nil {
			return sseEvent{Type: "parse_error", Detail: err.Error()}
		}
		return sseEvent{Type: eventName, Req: &r}
	case "ready":
		return sseEvent{Type: "ready"}
	default:
		return sseEvent{Type: eventName, Detail: data}
	}
}

func (c *apiClient) postAction(ctx context.Context, path string) error {
	req, err := c.newRequest(ctx, http.MethodPost, path)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: status %d", http.MethodPost, path, resp.StatusCode)
	}
	return nil
}

func (c *apiClient) approveStagedDiff(ctx context.Context, id string) error {
	return c.postAction(ctx, "/api/staged-diffs/"+id+"/approve")
}

func (c *apiClient) rejectStagedDiff(ctx context.Context, id string) error {
	return c.postAction(ctx, "/api/staged-diffs/"+id+"/reject")
}

func (c *apiClient) approveGrantRequest(ctx context.Context, id string) error {
	return c.postAction(ctx, "/api/grant-requests/"+id+"/approve")
}

func (c *apiClient) denyGrantRequest(ctx context.Context, id string) error {
	return c.postAction(ctx, "/api/grant-requests/"+id+"/deny")
}
