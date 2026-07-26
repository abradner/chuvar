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
				handleEvent(ctx, n, webBaseURL, ev)
			case err := <-done:
				if ctx.Err() == nil {
					slog.Warn("pushbridge: stream disconnected, reconnecting", "error", err)
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

func handleEvent(ctx context.Context, n *ntfyNotifier, webBaseURL string, ev sseclient.Event) {
	var title, message, link string
	switch ev.Type {
	case "staged_diff_added":
		d := ev.Diff
		title = "New staged diff from " + d.Subject
		message = d.Content
		if d.DedupeVerdict != nil && *d.DedupeVerdict == "contradiction" {
			title = "⚠ " + title + " (contradiction)"
		}
		link = webBaseURL
	case "grant_request_added":
		r := ev.Req
		title = "Grant request from " + r.Subject
		message = fmt.Sprintf("scopes: %v", r.RequestedScopes)
		if r.Justification != "" {
			message += " — " + r.Justification
		}
		link = webBaseURL
	default:
		return
	}
	if err := n.notify(ctx, title, message, link); err != nil {
		slog.Error("pushbridge: sending notification", "error", err)
	}
}
