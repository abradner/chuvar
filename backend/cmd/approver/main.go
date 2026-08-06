// Command approver is a keyboard-driven terminal approval surface: it connects
// to the apiserver's GET /api/events stream (internal/api/events.go) and lets a
// reviewer approve/reject staged diffs and approve/deny grant requests from a
// byobu/tmux pane next to the agents generating them, instead of switching to
// the web dashboard for every decision. See the Consent Surfaces workshop
// (Notion project 3a876cbe0b1281d5bf4dc28222e18310) for the design this
// implements.
//
// A separate binary from apiserver/mcpserver, same reasoning as those two: this
// is a terminal client of the REST API, not a server — it never touches the
// database or internal/store directly. The actual HTTP/SSE plumbing lives in
// internal/sseclient, shared with cmd/pushbridge.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
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
	// CHUVAR_API_TOKEN required, fail-fast — same stance as every other required
	// credential in this codebase (AGENTS.md §6): a TUI that silently started
	// with no way to authenticate would just fail every request one at a time
	// instead of explaining the problem once, up front.
	// config.Secret so CHUVAR_API_TOKEN_FILE works here too — see
	// config.requireSecret on why a file beats an environment variable.
	token, secretErr := config.Secret("CHUVAR_API_TOKEN")
	if secretErr != nil && !errors.Is(secretErr, config.ErrNotSet) {
		fmt.Fprintf(os.Stderr, "%s: %v\n", "approver", secretErr)
		os.Exit(1)
	}
	ok := secretErr == nil
	if !ok || token == "" {
		fmt.Fprintln(os.Stderr, "approver: required environment variable CHUVAR_API_TOKEN is not set")
		fmt.Fprintln(os.Stderr, "approver: issue one via POST /api/tokens (see internal/api/tokens.go) using an existing token, or the REVIEWER_BOOTSTRAP_TOKEN on a fresh install")
		os.Exit(1)
	}

	client := &sseclient.Client{BaseURL: baseURL, Token: token, HTTP: &http.Client{}}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	m := newModel()
	ui, err := newTerminalUI(m)
	if err != nil {
		log.Fatalf("approver: %v", err)
	}
	defer ui.Close()

	// events carries both server-pushed SSE frames and this program's own
	// action-result notifications (see runAction) — one channel, so every
	// mutation to m happens on this single goroutine via m.apply, and no other
	// goroutine ever touches m directly. That's what keeps model.go's "no mutex
	// needed" comment true even though key actions run their HTTP call in the
	// background (below).
	events := make(chan appEvent, 64)
	go streamEventsWithReconnect(ctx, client, events)

	keys := ui.ReadKeys(ctx)

	ui.Render(m)
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			m.apply(ev)
			ui.Render(m)
		case k, ok := <-keys:
			if !ok {
				return
			}
			if quit := handleKey(ctx, client, m, k, events); quit {
				return
			}
			ui.Render(m)
		}
	}
}

// streamEventsWithReconnect keeps a GET /api/events connection alive, retrying
// with a fixed backoff on any disconnect (network blip, apiserver restart) —
// a TUI meant to sit in a pane for hours needs to survive that without the
// operator noticing.
//
// Never closes out: it's shared with runAction's action-result notifications
// (main's event loop only exits via ctx.Done(), never a closed channel), and
// this function's own retry loop already exits cleanly on ctx cancellation.
func streamEventsWithReconnect(ctx context.Context, c *sseclient.Client, out chan<- appEvent) {
	const retryDelay = 2 * time.Second
	raw := make(chan sseclient.Event)
	go func() {
		for {
			if ctx.Err() != nil {
				return
			}
			err := c.Stream(ctx, raw)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				select {
				case out <- appEvent{Type: "connection_error", Detail: err.Error()}:
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
	}()
	for {
		select {
		case ev := <-raw:
			select {
			case out <- fromServerEvent(ev):
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// handleKey acts on one keypress. Returns true when the program should exit.
// Actions are fire-and-forget from the UI's perspective: the item stays in the
// queue until the corresponding "_resolved" SSE event confirms it, rather than
// being optimistically removed here — the server is the source of truth for
// whether an approval actually succeeded (e.g. it could 409 if someone else
// resolved it a moment earlier), and the status line reports failures instead
// of the queue silently lying about what's still pending.
func handleKey(ctx context.Context, c *sseclient.Client, m *model, k key, events chan<- appEvent) (quit bool) {
	if m.prompt != nil {
		return handlePromptKey(ctx, c, m, k, events)
	}
	switch {
	case k.special == keyCtrlC:
		return true
	case k.r == 'q':
		return true
	case k.special == keyUp || k.r == 'k':
		m.moveSelection(-1)
	case k.special == keyDown || k.r == 'j':
		m.moveSelection(1)
	case k.r == 'a':
		it, ok := m.current()
		if !ok {
			return false
		}
		// Approving requires a TOTP code (requireTOTP, internal/api/api.go) —
		// open the prompt instead of firing the request; handlePromptKey does
		// the actual approve once a code is entered.
		m.prompt = &promptState{it: it}
	case k.r == 'r':
		it, ok := m.current()
		if !ok {
			return false
		}
		go runAction(ctx, events, it, func() error {
			if it.kind == kindDiff {
				return c.RejectStagedDiff(ctx, it.id())
			}
			return c.DenyGrantRequest(ctx, it.id())
		}, "rejected")
	}
	return false
}

// handlePromptKey drives an in-progress TOTP code entry (m.prompt != nil).
// Ctrl-C still quits outright (a stuck prompt shouldn't trap the reviewer);
// digits accumulate up to 6, backspace removes one, Enter submits the approve
// action with whatever code has been entered so far (the server, not this
// program, is the source of truth on whether it's valid), and any other key
// cancels the prompt without acting — there's no dedicated Escape handling
// (ReadKeys' doc comment on why a bare Escape isn't reliably available here).
func handlePromptKey(ctx context.Context, c *sseclient.Client, m *model, k key, events chan<- appEvent) (quit bool) {
	if k.special == keyCtrlC {
		return true
	}
	switch {
	case k.special == keyEnter:
		p := m.prompt
		m.prompt = nil
		go runAction(ctx, events, p.it, func() error {
			if p.it.kind == kindDiff {
				return c.ApproveStagedDiff(ctx, p.it.id(), p.code)
			}
			return c.ApproveGrantRequest(ctx, p.it.id(), p.code)
		}, "approved")
	case k.special == keyBackspace:
		if n := len(m.prompt.code); n > 0 {
			m.prompt.code = m.prompt.code[:n-1]
		}
	case k.r >= '0' && k.r <= '9':
		if len(m.prompt.code) < 6 {
			m.prompt.code += string(k.r)
		}
	default:
		m.prompt = nil
	}
	return false
}

// runAction runs a REST call in the background (so a slow request doesn't
// freeze the keyboard/SSE event loop) and reports its outcome as a
// "status" event on the same channel the SSE reader publishes to — never by
// writing to m directly. That keeps every mutation of m on main's single
// goroutine (model.go's "no mutex needed" comment depends on this), at the
// cost of a couple of extra event-type cases; a genuinely simpler tradeoff
// than a mutex for how rarely this actually fires (one action at a time,
// human-paced).
//
// The item itself isn't removed here even on success — it stays in the queue
// until the server's own "_resolved" event confirms it, since the server is
// the source of truth for whether an approval actually landed (it could 409 if
// someone else resolved it a moment earlier).
func runAction(ctx context.Context, events chan<- appEvent, it item, do func() error, verb string) {
	id := shortID(it.id())
	msg := fmt.Sprintf("%s %s", verb, id)
	if err := do(); err != nil {
		msg = fmt.Sprintf("failed to %s %s: %v", verb, id, err)
	}
	select {
	case events <- appEvent{Type: "status", Detail: msg}:
	case <-ctx.Done():
	}
}

// shortID returns up to the first 8 characters of id for the status line.
// IDs come from server-supplied SSE payloads (sseclient.StagedDiff.ID etc.),
// so a bare id[:8] would panic on any future ID shape shorter than that
// rather than degrading gracefully. Found in review.
func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
