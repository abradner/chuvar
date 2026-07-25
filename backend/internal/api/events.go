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
	// the same ~10s regardless — clearing it here, for this response only,
	// is exactly what ResponseController.SetWriteDeadline exists for; no
	// other route's timeout is weakened by this.
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("streaming not supported by this connection"))
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	send := func(event string, data any) bool {
		b, err := json.Marshal(data)
		if err != nil {
			slog.Error("api: streamEvents: encoding event", "event", event, "error", err)
			return false
		}
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

	poll := func() bool {
		diffs, err := a.Store.ListStagedDiffs(ctx, store.DiffPending)
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
			resolved, err := a.Store.GetStagedDiff(ctx, id)
			if err != nil {
				logPollError("api: streamEvents: fetching resolved staged diff", err, "id", id)
				continue
			}
			if !send("staged_diff_resolved", toStagedDiffView(resolved)) {
				return false
			}
		}
		seenDiffs = currentDiffs

		reqs, err := a.Store.ListGrantRequests(ctx, store.GrantRequestPending)
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
			resolved, err := a.Store.GetGrantRequest(ctx, id)
			if err != nil {
				logPollError("api: streamEvents: fetching resolved grant request", err, "id", id)
				continue
			}
			if !send("grant_request_resolved", toGrantRequestView(resolved)) {
				return false
			}
		}
		seenRequests = currentRequests
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
