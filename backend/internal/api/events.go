// Approvals event stream: GET /api/events, a Server-Sent Events feed of pending
// staged diffs and grant requests appearing/resolving, so an approval surface
// (the TUI, a push bridge — see the Consent Surfaces workshop) doesn't have to
// poll the REST endpoints itself.
//
// This is poll-based internally, not Postgres LISTEN/NOTIFY or an in-process
// pub/sub, for one specific reason: staged diffs and grant requests are created
// from cmd/mcpserver (a separate OS process — see that command's package
// comment), not from cmd/apiserver. An in-process Go channel broadcaster in this
// package would never see an MCP-created item; only the shared Postgres database
// is common to both processes. Polling is the simplest correct thing given that
// constraint. LISTEN/NOTIFY (a dedicated pgx connection issuing pg_notify from
// the store layer) would cut latency and DB load and is the natural upgrade if
// polling ever proves insufficient — not adding that complexity now without a
// concrete need for it.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/abradner/chuvar/backend/internal/store"
)

// eventPollInterval is how often streamEvents re-checks for pending items. A var,
// not a const, only so events_test.go can shorten it for a fast test — no public
// way to configure it exists or is needed; no real use case has asked for a
// different cadence in production.
var eventPollInterval = 2 * time.Second

// grantExpiryWarningWindow is how far ahead of a grant's expiry
// grant_expiring starts firing for it. A var for the same test-shortening
// reason as eventPollInterval. A single fixed window rather than one scaled
// to each grant's own original TTL (e.g. "20% of TTL remaining"): grants here
// span wildly different TTLs (a short-lived capability grant vs. a long-lived
// memory grant), and a fixed, predictable window is easier for a reviewer to
// reason about than one that silently varies per grant.
var grantExpiryWarningWindow = 24 * time.Hour

// streamEvents handles GET /api/events. Sends an "added" event for each staged
// diff / grant request that's newly pending, and a "resolved" event (carrying its
// final status) for each that's no longer pending — all relative to what this
// specific connection has already seen, starting from an empty baseline on
// connect (so every currently-pending item is announced as "added" at the start
// of every new connection; a client reconnecting after a drop just sees a fresh
// full snapshot, not a gap in history).
//
// EventSource (the browser SSE client) can't set an Authorization header without
// a polyfill, so this route isn't reachable from a plain browser tab today —
// requireAuth still gates it the same as every other route, and the two v0
// consumers (a Go TUI, a Go push bridge) are plain HTTP clients that set headers
// freely. A browser-based consumer is a later-surfaces problem (PWA push,
// per the workshop), not this route's.
func (a *API) streamEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rc := http.NewResponseController(w)

	// Every other route in this package is bounded by withRequestTimeout
	// (api.go) at ~10s — exactly wrong for a connection meant to stay open
	// indefinitely. streamEvents is deliberately mounted outside that
	// middleware (see Routes()), but the underlying http.Server's own
	// WriteTimeout (cmd/apiserver, set from the same RequestTimeout) still
	// applies at the socket level and would silently kill this stream after
	// the same ~10s regardless — clearing it here (not just once, see send()
	// below) is exactly what ResponseController.SetWriteDeadline exists for;
	// no other route's timeout is weakened by this. Probing it up front, once,
	// still catches "this connection doesn't support deadlines at all" early
	// rather than only on the first real write.
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		// writeStoreError, not writeError: this is an internal-failure case
		// (the connection's transport doesn't support write deadlines at
		// all, not something the client did wrong) and err itself is real
		// diagnostic information worth logging, not just a discarded value.
		// writeError is for client-input problems this package constructed
		// itself; using it here would both mislabel the failure and drop the
		// real error. Found in review.
		writeStoreError(w, http.StatusInternalServerError, "streamEvents.SetWriteDeadline", "streaming not supported by this connection", err)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	send := func(event string, data any) bool {
		b, err := json.Marshal(data)
		if err != nil {
			slog.Error("api: streamEvents: encoding event", "event", event, "error", err)
			return false
		}
		// A finite deadline scoped to just this one write, not the connection
		// clearing done above at connect time: a stalled reader (client
		// stopped reading but kept the TCP connection open) could otherwise
		// block this Fprintf/Flush forever, pinning the handler goroutine —
		// with enough stalled clients, that's a resource-exhaustion path.
		// Resetting it before every write keeps the *stream* unbounded (each
		// successful write earns the next frame a fresh window) while
		// bounding any single stuck one. Found in review.
		_ = rc.SetWriteDeadline(time.Now().Add(a.RequestTimeout))
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b); err != nil {
			return false
		}
		return rc.Flush() == nil
	}

	// logPollError skips context.Canceled: a client disconnecting mid-poll (the
	// common, expected way this loop ends — see the ctx.Done() case below) isn't
	// a server-side failure worth an ERROR-level log line on every disconnect.
	// Anything else — a real DB error — still logs.
	logPollError := func(op string, err error, kv ...any) {
		if errors.Is(err, context.Canceled) {
			return
		}
		slog.Error(op, append([]any{"error", err}, kv...)...)
	}

	seenDiffs := map[string]struct{}{}
	seenRequests := map[string]struct{}{}
	// warnedGrants is keyed by (grant ID, expires_at) together, not grant ID
	// alone — a renewal changes expires_at on the same row, so the new
	// key naturally lets a renewed grant that later re-approaches expiry
	// warn again, without needing a reconnect to reset anything. It still
	// has no "resolved" counterpart to actively clear an entry (a grant
	// doesn't "un-expire"), so a revoked or long-since-renewed grant's old
	// key just sits unused in the map for the life of the connection —
	// harmless, bounded by how many distinct (grant, expiry) pairs one
	// connection ever sees. Found in review (originally keyed by grant ID
	// only, which meant a renewal could never re-trigger a warning on the
	// same connection).
	warnedGrants := map[string]struct{}{}

	poll := func() bool {
		// Every Store call below shares one bounded child context, not the
		// stream's own deadline-free ctx: without this, a hung DB (network
		// partition, a stuck query) leaves this call blocked indefinitely,
		// pinning both this goroutine and the pool connection it holds for as
		// long as the client stays connected — across enough stalled
		// connections, that starves the pool the approval endpoints need.
		// a.RequestTimeout is the same bound every other route already uses
		// for "how long should one unit of work take" (withRequestTimeout,
		// api.go); reusing it here rather than inventing a second knob.
		// Scoped to just one poll cycle, not the whole connection, so the
		// *stream* itself still runs indefinitely. Found in review.
		pollCtx, cancel := context.WithTimeout(ctx, a.RequestTimeout)
		defer cancel()

		diffs, err := a.Store.ListStagedDiffs(pollCtx, store.DiffPending)
		if err != nil {
			logPollError("api: streamEvents: listing staged diffs", err)
			return false
		}
		currentDiffs := make(map[string]struct{}, len(diffs))
		for _, d := range diffs {
			currentDiffs[d.ID] = struct{}{}
			if _, ok := seenDiffs[d.ID]; !ok {
				if !send("staged_diff_added", toStagedDiffView(d)) {
					return false
				}
			}
		}
		for id := range seenDiffs {
			if _, ok := currentDiffs[id]; ok {
				continue
			}
			resolved, err := a.Store.GetStagedDiff(pollCtx, id)
			if err != nil {
				// Keep tracking this ID rather than letting the
				// seenDiffs = currentDiffs assignment below silently forget
				// it: a transient fetch failure here must not mean the
				// client never learns this diff resolved. The next poll
				// retries the fetch — and since it's a real content lookup
				// (not "poll again to see if it's still pending," which
				// currentDiffs already answered "no" to), retrying, not
				// giving up after one failure, is what actually recovers
				// from a blip instead of just deferring the same loss.
				// Found in review.
				logPollError("api: streamEvents: fetching resolved staged diff", err, "id", id)
				currentDiffs[id] = struct{}{}
				continue
			}
			if !send("staged_diff_resolved", toStagedDiffView(resolved)) {
				return false
			}
		}
		seenDiffs = currentDiffs

		reqs, err := a.Store.ListGrantRequests(pollCtx, store.GrantRequestPending)
		if err != nil {
			logPollError("api: streamEvents: listing grant requests", err)
			return false
		}
		currentRequests := make(map[string]struct{}, len(reqs))
		for _, req := range reqs {
			currentRequests[req.ID] = struct{}{}
			if _, ok := seenRequests[req.ID]; !ok {
				if !send("grant_request_added", toGrantRequestView(req)) {
					return false
				}
			}
		}
		for id := range seenRequests {
			if _, ok := currentRequests[id]; ok {
				continue
			}
			resolved, err := a.Store.GetGrantRequest(pollCtx, id)
			if err != nil {
				// See the matching comment in the staged-diffs loop above.
				logPollError("api: streamEvents: fetching resolved grant request", err, "id", id)
				currentRequests[id] = struct{}{}
				continue
			}
			if !send("grant_request_resolved", toGrantRequestView(resolved)) {
				return false
			}
		}
		seenRequests = currentRequests

		expiring, err := a.Store.ListGrantsNearingExpiry(pollCtx, time.Now().Add(grantExpiryWarningWindow))
		if err != nil {
			logPollError("api: streamEvents: listing grants nearing expiry", err)
			return false
		}
		for _, g := range expiring {
			key := warnedGrantKey(g)
			if _, ok := warnedGrants[key]; ok {
				continue
			}
			warnedGrants[key] = struct{}{}
			if !send("grant_expiring", toGrantView(g)) {
				return false
			}
		}
		return true
	}

	if !poll() {
		return
	}
	if !send("ready", map[string]bool{"ok": true}) {
		return
	}

	ticker := time.NewTicker(eventPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !poll() {
				return
			}
		}
	}
}

// warnedGrantKey is warnedGrants' map key: grant ID plus expiry together, so
// a renewal (which changes ExpiresAt on the same row) gets a fresh key and
// can warn again — see warnedGrants' own doc comment above. ExpiresAt is
// never nil for anything ListGrantsNearingExpiry returns (its query filters
// expires_at IS NOT NULL).
func warnedGrantKey(g store.Grant) string {
	return fmt.Sprintf("%s@%s", g.ID, g.ExpiresAt.Format(time.RFC3339Nano))
}
