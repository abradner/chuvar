// Command pushbridge is a notify-only phone-coverage bridge: it connects to
// apiserver's GET /api/events stream (internal/api/events.go) and posts an
// ntfy (https://ntfy.sh) notification for every newly-pending staged diff or
// grant request, with a deep link back to the web dashboard for the actual
// decision. See the Consent Surfaces workshop (Notion project
// 3a876cbe0b1281d5bf4dc28222e18310) — this is deliberately the cheapest
// possible phone-reach surface (no app, no push infrastructure of our own),
// meant to be superseded by PWA web push once that lands.
//
// Deliberately one-way: unlike cmd/approver, this never calls back into the
// REST API to act on an item — it only reads the event stream and posts
// outbound notifications. Adding approve/deny actions here would mean parsing
// ntfy's own action-button callback scheme and re-authenticating that path,
// real added complexity with no concrete need for it yet (the TUI and web
// dashboard already cover "act on it"); this stays a thin, low-risk notifier.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/abradner/chuvar/backend/internal/sseclient"
)

func main() {
	baseURL := os.Getenv("CHUVAR_API_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	token, ok := os.LookupEnv("CHUVAR_API_TOKEN")
	if !ok || token == "" {
		fmt.Fprintln(os.Stderr, "pushbridge: required environment variable CHUVAR_API_TOKEN is not set")
		os.Exit(1)
	}

	// NTFY_TOPIC is required, fail-fast (AGENTS.md §6): an ntfy topic is
	// effectively a public, unauthenticated broadcast channel (anyone who knows
	// the topic name can subscribe), so there's no sane default to fall back to
	// — a default would either notify nobody (a made-up topic name) or leak
	// notifications to whoever else guessed the same default.
	topic, ok := os.LookupEnv("NTFY_TOPIC")
	if !ok || topic == "" {
		fmt.Fprintln(os.Stderr, "pushbridge: required environment variable NTFY_TOPIC is not set")
		os.Exit(1)
	}
	ntfyURL := os.Getenv("NTFY_URL")
	if ntfyURL == "" {
		ntfyURL = "https://ntfy.sh"
	}
	// webBaseURL is only used to build the deep link in each notification body
	// — best-effort, not required: a notification with no link is still useful
	// (the operator can open the dashboard manually), so this doesn't fail boot
	// the way a genuinely required credential does.
	webBaseURL := os.Getenv("CHUVAR_WEB_BASE_URL")
	if webBaseURL == "" {
		webBaseURL = "http://localhost:5173"
	}

	apiClient := &sseclient.Client{BaseURL: baseURL, Token: token, HTTP: &http.Client{}}
	notifier := &ntfyNotifier{baseURL: ntfyURL, topic: topic, http: &http.Client{Timeout: 10 * time.Second}}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	slog.Info("pushbridge: starting", "api", baseURL, "ntfy", ntfyURL, "topic", topic)
	run(ctx, apiClient, notifier, webBaseURL)
}

// run streams events with reconnect-with-backoff (same shape as
// cmd/approver's streamEventsWithReconnect — this program just has one
// consumer of the stream instead of two) and notifies on every "_added" event.
// "_resolved" events are deliberately not notified: nothing for the operator to
// act on there, and a notification about something no longer needing attention
// would just be noise on the one channel meant to interrupt them.
func run(ctx context.Context, c *sseclient.Client, n *ntfyNotifier, webBaseURL string) {
	const retryDelay = 2 * time.Second
	// notified tracks IDs this process has already sent a notification for,
	// across reconnects — see handleEvent's doc comment for why this exists.
	notified := map[string]struct{}{}
	for {
		if ctx.Err() != nil {
			return
		}
		events := make(chan sseclient.Event, 16)
		done := make(chan error, 1)
		go func() { done <- c.Stream(ctx, events) }()

	consume:
		for {
			select {
			case ev := <-events:
				handleEvent(ctx, n, webBaseURL, notified, ev)
			case err := <-done:
				if ctx.Err() == nil {
					slog.Warn("pushbridge: stream disconnected, reconnecting", "error", err)
				}
				// Stream returning on `done` and events still holding
				// buffered frames aren't mutually exclusive: select above can
				// pick done while events has unread items in it, and moving
				// straight to the retry delay would silently drop them —
				// including a resolution for something that got added and
				// then resolved in the brief window before the disconnect,
				// which this process would then never learn about. Drain
				// whatever's already buffered before reconnecting. Found in
				// review.
			drain:
				for {
					select {
					case ev := <-events:
						handleEvent(ctx, n, webBaseURL, notified, ev)
					default:
						break drain
					}
				}
				break consume
			case <-ctx.Done():
				return
			}
		}

		select {
		case <-time.After(retryDelay):
		case <-ctx.Done():
			return
		}
	}
}

// handleEvent notifies on a newly-seen "_added" event and clears an item from
// notified on its "_resolved" counterpart.
//
// The notified deduplication exists because of how streamEvents (internal/api)
// behaves on reconnect: a fresh connection starts from an empty baseline and
// re-announces every still-pending item as "added" (events.go's own doc
// comment on this — it's deliberate, so a client reconnecting after a drop
// gets a full snapshot rather than a gap). Without tracking what's already
// been notified, a flapping network connection would re-notify the operator
// for the same unresolved item every reconnect, potentially every couple of
// seconds. A failed notify() is deliberately NOT marked as notified — so a
// transient ntfy outage gets retried on the next re-announce instead of the
// item being silently and permanently suppressed. Found in review.
func handleEvent(ctx context.Context, n *ntfyNotifier, webBaseURL string, notified map[string]struct{}, ev sseclient.Event) {
	var id, title, message, link string
	switch ev.Type {
	case "staged_diff_added":
		d := ev.Diff
		id = d.ID
		title = "New staged diff from " + d.Subject
		message = d.Content
		if d.DedupeVerdict != nil && *d.DedupeVerdict == "contradiction" {
			title = "⚠ " + title + " (contradiction)"
		}
		link = webBaseURL
	case "grant_request_added":
		r := ev.Req
		id = r.ID
		title = "Grant request from " + r.Subject
		message = fmt.Sprintf("scopes: %v", r.RequestedScopes)
		if r.Justification != "" {
			message += " — " + r.Justification
		}
		link = webBaseURL
	case "staged_diff_resolved":
		delete(notified, ev.Diff.ID)
		return
	case "grant_request_resolved":
		delete(notified, ev.Req.ID)
		return
	case "grant_expiring":
		// Bypasses the shared notified map entirely rather than participating
		// in the generic id/notified flow below: unlike a diff or grant
		// request, grant_expiring has no "resolved" counterpart to ever clear
		// an entry from notified — a grant's ID is permanent (renewal updates
		// expires_at on the same row, it doesn't create a new grant), so
		// adding it to notified would permanently suppress every notification
		// after the first, including a legitimate second warning if the
		// grant is renewed and later approaches expiry again. The tradeoff:
		// a reconnect re-notifies for a still-expiring grant (the server's
		// own per-connection dedup in events.go only prevents duplicates
		// within one connection) — a minor, occasional nuisance, and a far
		// smaller cost than silently going quiet on a real future expiry.
		g := ev.Grant
		expiry := "unknown"
		if g.ExpiresAt != nil {
			expiry = *g.ExpiresAt
		}
		title := "Grant expiring soon: " + g.Subject
		message := fmt.Sprintf("scopes: %v, expires %s", g.Scopes, expiry)
		if err := n.notify(ctx, title, message, webBaseURL); err != nil {
			slog.Error("pushbridge: sending notification", "error", err)
		}
		return
	default:
		return
	}
	if _, already := notified[id]; already {
		return
	}
	if err := n.notify(ctx, title, message, link); err != nil {
		slog.Error("pushbridge: sending notification", "error", err)
		return
	}
	notified[id] = struct{}{}
}
