// Package sseclient is a small client for internal/api's GET /api/events stream
// (events.go), shared by every terminal-side consumer of it — cmd/approver and
// cmd/pushbridge as of this package's introduction. Factored out specifically
// because a second real caller now exists (cmd/pushbridge), the same bar
// embed.Embedder was held to when it became an interface (AGENTS.md §3.3's "the
// second caller is already decided," not speculative abstraction) — before
// pushbridge, this lived only in cmd/approver and wasn't worth extracting.
package sseclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// StagedDiff and GrantRequest mirror the JSON shapes internal/api's
// stagedDiffView / grantRequestView produce. Redefined here rather than
// importing internal/api directly: that package also pulls in the store and
// embedder layers, none of which a terminal client needs, and its view types
// are unexported besides — the same relationship the frontend's api/client.ts
// has to the backend (its own independently-defined TypeScript interfaces).
type StagedDiff struct {
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

type GrantRequest struct {
	ID                  string   `json:"id"`
	Subject             string   `json:"subject"`
	RequestedScopes     []string `json:"requested_scopes"`
	Depth               string   `json:"depth"`
	RequestedTTLSeconds *int     `json:"requested_ttl_seconds,omitempty"`
	Justification       string   `json:"justification"`
	Status              string   `json:"status"`
	CreatedAt           string   `json:"created_at"`
}

// Event is one parsed "event: ...\ndata: ...\n\n" frame, with its payload
// already unmarshaled into whichever of the two shapes Type implies.
// "connection_error" is a caller-synthesized type (see cmd/approver/main.go and
// cmd/pushbridge/main.go's own reconnect loops), never something the server
// sends — Stream itself never produces one.
type Event struct {
	Type   string
	Diff   *StagedDiff
	Req    *GrantRequest
	Detail string // only set for parse_error / unrecognized-event cases
}

// Client talks to one apiserver's GET /api/events endpoint and REST actions.
// The REST action methods live here (not just streaming) because both known
// consumers (approver, pushbridge — the latter only for a future "snooze"/ack
// action, not yet) need the same bearer-token-authenticated HTTP plumbing;
// Stream and the actions share nothing but that plumbing today.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func (c *Client) newRequest(ctx context.Context, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	return req, nil
}

// Stream connects to GET /api/events and pushes parsed frames to out until ctx
// is canceled or the connection drops (returning a non-nil error in the latter
// case, including io.EOF for a server-initiated close — both are "the
// connection ended," not necessarily failures; callers loop this with their own
// backoff, matching AGENTS.md's stance that a network blip isn't code to chase
// as a bug).
func (c *Client) Stream(ctx context.Context, out chan<- Event) error {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/events")
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
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

func parseEvent(eventName, data string) Event {
	switch eventName {
	case "staged_diff_added", "staged_diff_resolved":
		var d StagedDiff
		if err := json.Unmarshal([]byte(data), &d); err != nil {
			return Event{Type: "parse_error", Detail: err.Error()}
		}
		return Event{Type: eventName, Diff: &d}
	case "grant_request_added", "grant_request_resolved":
		var r GrantRequest
		if err := json.Unmarshal([]byte(data), &r); err != nil {
			return Event{Type: "parse_error", Detail: err.Error()}
		}
		return Event{Type: eventName, Req: &r}
	case "ready":
		return Event{Type: "ready"}
	default:
		return Event{Type: eventName, Detail: data}
	}
}

// actionTimeout bounds a single approve/reject/approve/deny REST call. Callers
// (cmd/approver's runAction, in particular) pass this program's own top-level
// ctx — cancelled on SIGINT/SIGTERM, otherwise long-lived for as long as the
// process runs — not something scoped to one HTTP request. Without a bound
// here, a stalled server or network would hang that call indefinitely,
// leaking the goroutine it runs in and leaving the TUI's status line never
// updated for that action. Found in review.
const actionTimeout = 10 * time.Second

// postAction issues the POST and, when totpCode is non-empty, attaches it as
// the device-local second factor requireTOTP checks on mutations that grant or
// extend authority (see internal/api/api.go). Empty for actions that aren't
// gated (reject/deny) — the header is simply omitted, not sent empty.
func (c *Client) postAction(ctx context.Context, path, totpCode string) error {
	ctx, cancel := context.WithTimeout(ctx, actionTimeout)
	defer cancel()

	req, err := c.newRequest(ctx, http.MethodPost, path)
	if err != nil {
		return err
	}
	if totpCode != "" {
		req.Header.Set("X-Chuvar-TOTP-Code", totpCode)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: status %d", http.MethodPost, path, resp.StatusCode)
	}
	return nil
}

// ApproveStagedDiff requires totpCode — see requireTOTP on
// POST /api/staged-diffs/{id}/approve.
func (c *Client) ApproveStagedDiff(ctx context.Context, id, totpCode string) error {
	return c.postAction(ctx, "/api/staged-diffs/"+id+"/approve", totpCode)
}

func (c *Client) RejectStagedDiff(ctx context.Context, id string) error {
	return c.postAction(ctx, "/api/staged-diffs/"+id+"/reject", "")
}

// ApproveGrantRequest requires totpCode — see requireTOTP on
// POST /api/grant-requests/{id}/approve.
func (c *Client) ApproveGrantRequest(ctx context.Context, id, totpCode string) error {
	return c.postAction(ctx, "/api/grant-requests/"+id+"/approve", totpCode)
}

func (c *Client) DenyGrantRequest(ctx context.Context, id string) error {
	return c.postAction(ctx, "/api/grant-requests/"+id+"/deny", "")
}
