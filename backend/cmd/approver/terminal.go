package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// key is one parsed keypress: a plain rune for letter/digit keys, or one of the
// named constants below for keys with no single-rune representation.
type key struct {
	r       rune
	special specialKey
}

type specialKey int

const (
	keyNone specialKey = iota
	keyUp
	keyDown
	keyEnter
	keyCtrlC
)

// terminalUI owns raw-mode terminal state. MakeRaw disables line buffering and
// local echo so single keypresses (j/k, a/d/r/q) act immediately instead of
// waiting for Enter — the whole point of a keyboard-driven approval pane. Close
// must run before the process exits (main.go's defer) or the shell that spawned
// this TUI is left in raw mode after it quits.
type terminalUI struct {
	oldState *term.State
	out      *bufio.Writer
}

func newTerminalUI(_ *model) (*terminalUI, error) {
	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("entering raw terminal mode (is this running in a real terminal?): %w", err)
	}
	return &terminalUI{oldState: old, out: bufio.NewWriter(os.Stdout)}, nil
}

func (t *terminalUI) Close() {
	_ = term.Restore(int(os.Stdin.Fd()), t.oldState)
	// Raw mode also suppresses the terminal's own newline-on-exit behavior —
	// without this the shell prompt after quitting can end up on the same line
	// as the TUI's last frame.
	fmt.Print("\r\n")
}

// ReadKeys reads raw bytes from stdin and parses them into key values on a
// background goroutine, closing the channel when ctx is canceled or stdin
// closes. Escape sequences (arrow keys) are two bytes behind the initial 0x1b —
// this only recognizes the specific up/down sequences this program uses, not a
// general terminal-escape parser.
func (t *terminalUI) ReadKeys(ctx context.Context) <-chan key {
	out := make(chan key)
	go func() {
		defer close(out)
		buf := make([]byte, 3)
		for {
			n, err := os.Stdin.Read(buf[:1])
			if err != nil || n == 0 {
				return
			}
			b := buf[0]
			var k key
			switch {
			case b == 0x03: // Ctrl-C
				k = key{special: keyCtrlC}
			case b == '\r' || b == '\n':
				k = key{special: keyEnter}
			case b == 0x1b:
				// Best-effort: read the next two bytes of a CSI arrow sequence
				// (ESC [ A/B). A bare Escape with nothing following will block
				// here briefly and then be dropped — acceptable for this
				// program, which has no other use for a lone Escape keypress.
				n2, err := os.Stdin.Read(buf[1:3])
				if err != nil || n2 < 2 || buf[1] != '[' {
					continue
				}
				switch buf[2] {
				case 'A':
					k = key{special: keyUp}
				case 'B':
					k = key{special: keyDown}
				default:
					continue
				}
			default:
				k = key{r: rune(b)}
			}
			select {
			case out <- k:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

const clearScreen = "\x1b[2J\x1b[H"

// Render redraws the whole screen. Simple full-redraw rather than an in-place
// diff/patch — the queue is small (a handful of pending items at most, per
// AGENTS.md's v0 scale expectations) and this runs at most once per event or
// keypress, not on a tight loop, so the flicker/bandwidth cost of a full
// clear+redraw is not worth the complexity of a partial-update scheme.
func (t *terminalUI) Render(m *model) {
	var b strings.Builder
	b.WriteString(clearScreen)
	b.WriteString("chuvar approver")
	if m.status != "" {
		fmt.Fprintf(&b, "  — %s", m.status)
	}
	b.WriteString("\r\n\r\n")

	if len(m.order) == 0 {
		b.WriteString("Nothing pending.\r\n")
	}
	for i, id := range m.order {
		it := m.items[id]
		cursor := "  "
		if i == m.selected {
			cursor = "> "
		}
		fmt.Fprintf(&b, "%s%s\r\n", cursor, renderSummary(it))
	}

	b.WriteString("\r\n")
	if it, ok := m.current(); ok {
		b.WriteString(renderDetail(it))
	}

	b.WriteString("\r\n[j/k or ↑/↓] navigate  [a]pprove  [r]eject/deny  [q]uit\r\n")

	t.out.WriteString(b.String())
	t.out.Flush()
}

func renderSummary(it item) string {
	if it.kind == kindDiff {
		d := it.diff
		verdict := ""
		if d.DedupeVerdict != nil {
			verdict = " [" + *d.DedupeVerdict + "]"
		}
		return fmt.Sprintf("write  %-16s %s%s", truncate(d.Subject, 16), truncate(d.Content, 50), verdict)
	}
	r := it.req
	return fmt.Sprintf("grant  %-16s %s", truncate(r.Subject, 16), strings.Join(r.RequestedScopes, ", "))
}

func renderDetail(it item) string {
	var b strings.Builder
	if it.kind == kindDiff {
		d := it.diff
		fmt.Fprintf(&b, "from %s\r\n", d.Subject)
		if d.TargetFactID != nil {
			b.WriteString("⚠ this replaces an existing fact (fetch it via the web UI before approving)\r\n")
		}
		fmt.Fprintf(&b, "%s\r\n", d.Content)
		fmt.Fprintf(&b, "scopes: %s\r\n", strings.Join(d.ProposedScopes, ", "))
		if d.DedupeVerdict != nil && *d.DedupeVerdict == "contradiction" {
			b.WriteString("⚠ contradiction — review carefully, this may conflict with an existing fact\r\n")
		}
	} else {
		r := it.req
		fmt.Fprintf(&b, "from %s\r\n", r.Subject)
		fmt.Fprintf(&b, "requesting: %s (depth: %s)\r\n", strings.Join(r.RequestedScopes, ", "), r.Depth)
		if r.RequestedTTLSeconds != nil {
			fmt.Fprintf(&b, "for %d minutes\r\n", *r.RequestedTTLSeconds/60)
		}
		if r.Justification != "" {
			fmt.Fprintf(&b, "justification: %s\r\n", r.Justification)
		}
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
