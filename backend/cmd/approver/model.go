package main

import "github.com/abradner/chuvar/backend/internal/sseclient"

// appEvent is what flows through this program's single event channel — every
// sseclient.Event the server sends, plus a few locally-synthesized Types
// ("status", "connection_error") for this program's own action results and
// connection state that the server protocol has no frame for. A thin wrapper
// rather than reusing sseclient.Event directly so those synthetic types don't
// need to pretend to be server events.
type appEvent struct {
	Type   string
	Diff   *sseclient.StagedDiff
	Req    *sseclient.GrantRequest
	Detail string
}

func fromServerEvent(ev sseclient.Event) appEvent {
	return appEvent{Type: ev.Type, Diff: ev.Diff, Req: ev.Req, Detail: ev.Detail}
}

// item is one entry in the review queue — either a staged diff or a grant
// request, never both. A tagged union rather than an interface: the render and
// action code both need to switch on kind anyway, and there are exactly two
// cases, permanently (the two write-approval shapes AGENTS.md §3.1 describes),
// not an open set a new type will keep getting added to.
type item struct {
	kind kind
	diff *sseclient.StagedDiff
	req  *sseclient.GrantRequest
}

type kind int

const (
	kindDiff kind = iota
	kindRequest
)

func (i item) id() string {
	if i.kind == kindDiff {
		return i.diff.ID
	}
	return i.req.ID
}

// promptState tracks an in-progress TOTP code entry for an approve action.
// Approving (unlike reject/deny) is gated behind requireTOTP's device-local
// second factor — see internal/api/api.go — so 'a' opens this prompt instead
// of firing the request immediately; any other key while it's open cancels
// without acting.
type promptState struct {
	it   item
	code string
}

// model is the queue of currently-pending items plus which one is selected.
// Owned entirely by main's event loop (single-goroutine — no mutex needed):
// SSE events and key presses both flow through the same select statement there.
type model struct {
	order    []string // ids, oldest first — display and selection order
	items    map[string]item
	selected int
	status   string // transient status line: last action result or a connection note
	prompt   *promptState
}

func newModel() *model {
	return &model{items: map[string]item{}}
}

func (m *model) upsert(it item) {
	id := it.id()
	if _, exists := m.items[id]; !exists {
		m.order = append(m.order, id)
	}
	m.items[id] = it
}

func (m *model) remove(id string) {
	if _, exists := m.items[id]; !exists {
		return
	}
	// An in-progress TOTP prompt for this exact item no longer makes sense if
	// it just got resolved out from under the reviewer (another surface acted
	// on it, or the server otherwise settled it) — submitting the code now
	// would just 409 against an item that's no longer pending.
	if m.prompt != nil && m.prompt.it.id() == id {
		m.prompt = nil
	}
	delete(m.items, id)
	for i, oid := range m.order {
		if oid == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			// Removing an item strictly before the selected one shifts every
			// later index down by one, so selected has to move with it or it
			// silently ends up pointing at a different item than the one the
			// reviewer was looking at. This was a real risk, not just a
			// display glitch: SSE resolutions and keypresses both flow
			// through main's single select loop, so a resolution for an
			// earlier item arriving between two keypresses could otherwise
			// make the very next 'a'/'r' act on the wrong item. Found in
			// review. i == m.selected (the selected item is the one being
			// removed) intentionally falls through unchanged — the index now
			// already points at the next item, or gets clamped below.
			if i < m.selected {
				m.selected--
			}
			break
		}
	}
	if m.selected >= len(m.order) && m.selected > 0 {
		m.selected = len(m.order) - 1
	}
}

// apply folds one SSE event into the model. "_resolved" events remove the item
// regardless of which surface resolved it (this TUI's own action, the web
// dashboard, another approver instance) — the queue always reflects "what's
// actually still pending," not just "what this connection decided."
func (m *model) apply(ev appEvent) {
	switch ev.Type {
	case "staged_diff_added":
		m.upsert(item{kind: kindDiff, diff: ev.Diff})
	case "staged_diff_resolved":
		m.remove(ev.Diff.ID)
	case "grant_request_added":
		m.upsert(item{kind: kindRequest, req: ev.Req})
	case "grant_request_resolved":
		m.remove(ev.Req.ID)
	case "ready":
		m.status = "connected"
	case "connection_error":
		m.status = "connection lost, retrying: " + ev.Detail
	case "parse_error":
		m.status = "malformed event from server: " + ev.Detail
	case "status":
		m.status = ev.Detail
	}
}

func (m *model) current() (item, bool) {
	if m.selected < 0 || m.selected >= len(m.order) {
		return item{}, false
	}
	return m.items[m.order[m.selected]], true
}

func (m *model) moveSelection(delta int) {
	if len(m.order) == 0 {
		return
	}
	m.selected += delta
	if m.selected < 0 {
		m.selected = 0
	}
	if m.selected >= len(m.order) {
		m.selected = len(m.order) - 1
	}
}
