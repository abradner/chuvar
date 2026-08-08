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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/abradner/chuvar/backend/internal/config"
	"github.com/abradner/chuvar/backend/internal/sseclient"
)

func main() {
	baseURL := os.Getenv("CHUVAR_API_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	// config.Secret so CHUVAR_API_TOKEN_FILE works here too — see
	// config.requireSecret on why a file beats an environment variable.
	token, secretErr := config.Secret("CHUVAR_API_TOKEN")
	if secretErr != nil && !errors.Is(secretErr, config.ErrNotSet) {
		fmt.Fprintf(os.Stderr, "%s: %v\n", "pushbridge", secretErr)
		os.Exit(1)
	}
	ok := secretErr == nil
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
	// grantExpiryNotified is notified's counterpart for grant_expiring: keyed
	// on (grant ID, expires_at) rather than ID alone, and holding each key's
	// parsed expiry rather than an empty struct{} — see handleEvent's doc
	// comment on why grant_expiring can't share notified outright, and
	// evictExpiredGrantKeys on why the value needs to be the expiry.
	grantExpiryNotified := map[string]time.Time{}
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
				handleEvent(ctx, n, webBaseURL, notified, grantExpiryNotified, ev)
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
						handleEvent(ctx, n, webBaseURL, notified, grantExpiryNotified, ev)
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
func handleEvent(ctx context.Context, n *ntfyNotifier, webBaseURL string, notified map[string]struct{}, grantExpiryNotified map[string]time.Time, ev sseclient.Event) {
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
		// Deliberately does not participate in the generic id/notified flow
		// below (notified is keyed on ID alone): unlike a diff or grant
		// request, grant_expiring has no "resolved" counterpart to ever
		// clear an entry, and a grant's ID is permanent (renewal updates
		// expires_at on the same row, it doesn't create a new grant) — so
		// keying on ID alone would permanently suppress every notification
		// after the first, including a legitimate second warning after the
		// grant is renewed and later approaches expiry again.
		//
		// Instead it has its own dedup, grantExpiryNotified, keyed on
		// (grant ID, expires_at) together — the same composite events.go's
		// own warnedGrantKey uses for its per-connection dedup, kept here
		// across reconnects instead of just within one. A renewal changes
		// expires_at on the same row, so it still gets a fresh key and can
		// warn again; a reconnect re-announcing the same still-expiring
		// grant (streamEvents starts every new connection from an empty
		// baseline, and pushbridge's own reconnect loop retries on a fixed
		// 2s delay) now hits the same key and is suppressed, instead of
		// producing one push per expiring grant per reconnect — the
		// notification-fatigue risk that made the original "just don't
		// dedup this one" tradeoff bigger than it looked. As with notified
		// below, a failed notify() is deliberately not marked as notified.
		g := ev.Grant
		expiry := "unknown"
		var expiresAt time.Time
		if g.ExpiresAt != nil {
			expiry = *g.ExpiresAt
			// A parse failure just leaves expiresAt at its zero value, which
			// evictExpiredGrantKeys treats as "never evict" — strictly more
			// conservative (an extra long-lived entry) than wrong, and
			// ExpiresAt is server-formatted (grantView's timeFormat, which is
			// time.RFC3339) so a real failure here isn't expected in
			// practice.
			if t, err := time.Parse(time.RFC3339, *g.ExpiresAt); err == nil {
				expiresAt = t
			}
		}
		grantKey := g.ID + "@" + expiry
		evictExpiredGrantKeys(grantExpiryNotified)
		if _, already := grantExpiryNotified[grantKey]; already {
			return
		}
		title := "Grant expiring soon: " + g.Subject
		message := fmt.Sprintf("scopes: %v, expires %s", g.Scopes, expiry)
		if err := n.notify(ctx, title, message, webBaseURL); err != nil {
			slog.Error("pushbridge: sending notification", "error", err)
			return
		}
		grantExpiryNotified[grantKey] = expiresAt
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

// evictExpiredGrantKeys drops entries from grantExpiryNotified whose expiry
// has already passed. Without this, the map would grow by one entry per
// (grant, expires_at) pair pushbridge has ever warned about, for the entire
// life of the process — unlike notified (bounded by however many diffs/
// requests are simultaneously pending, since resolution clears an entry),
// grant_expiring has no event that ever clears a key, so nothing else bounds
// it. Dropping a key once its expiry is in the past is safe, not just
// convenient: ListGrantsNearingExpiry (store/grants.go), the query backing
// grant_expiring, excludes already-expired grants, so the server can never
// re-emit that exact (grant ID, expires_at) pair again — a subsequent
// renewal produces a new expires_at and therefore a new key, not this one.
// A zero-value expiresAt (the "couldn't parse it" fallback in handleEvent)
// is never evicted, trading a rare, small leak for never evicting a key that
// might still be live.
func evictExpiredGrantKeys(m map[string]time.Time) {
	now := time.Now()
	for key, expiresAt := range m {
		if !expiresAt.IsZero() && expiresAt.Before(now) {
			delete(m, key)
		}
	}
}
