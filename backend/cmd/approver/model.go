package main

// item is one entry in the review queue — either a staged diff or a grant
// request, never both. A tagged union rather than an interface: the render and
// action code both need to switch on kind anyway, and there are exactly two
// cases, permanently (the two write-approval shapes AGENTS.md §3.1 describes),
// not an open set a new type will keep getting added to.
type item struct {
	kind kind
	diff *stagedDiff
	req  *grantRequest
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

// model is the queue of currently-pending items plus which one is selected.
// Owned entirely by main's event loop (single-goroutine — no mutex needed):
// SSE events and key presses both flow through the same select statement there.
type model struct {
	order    []string // ids, oldest first — display and selection order
	items    map[string]item
	selected int
	status   string // transient status line: last action result or a connection note
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
	delete(m.items, id)
	for i, oid := range m.order {
		if oid == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
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
func (m *model) apply(ev sseEvent) {
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
