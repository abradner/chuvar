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
// background goroutine, closing the channel when stdin closes or a send would
// block past ctx being canceled. os.Stdin.Read itself is a blocking syscall
// with no way to hand it a context, so ctx cancellation alone does not stop
// this goroutine while it's waiting on a keypress that never comes — it only
// takes effect at the next send attempt after a byte does arrive, or when
// stdin is closed out from under it (Close(), on process shutdown). Escape
// sequences (arrow keys) are two bytes behind the initial 0x1b — this only
// recognizes the specific up/down sequences this program uses, not a general
// terminal-escape parser. Found in review (doc accuracy).
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
		return fmt.Sprintf("write  %-16s %s%s", truncate(safe(d.Subject), 16), truncate(safe(d.Content), 50), verdict)
	}
	r := it.req
	return fmt.Sprintf("grant  %-16s %s", truncate(safe(r.Subject), 16), strings.Join(r.RequestedScopes, ", "))
}

func renderDetail(it item) string {
	var b strings.Builder
	if it.kind == kindDiff {
		d := it.diff
		fmt.Fprintf(&b, "from %s\r\n", safe(d.Subject))
		if d.TargetFactID != nil {
			b.WriteString("⚠ this replaces an existing fact (fetch it via the web UI before approving)\r\n")
		}
		fmt.Fprintf(&b, "%s\r\n", safe(d.Content))
		fmt.Fprintf(&b, "scopes: %s\r\n", strings.Join(d.ProposedScopes, ", "))
		if d.DedupeVerdict != nil && *d.DedupeVerdict == "contradiction" {
			b.WriteString("⚠ contradiction — review carefully, this may conflict with an existing fact\r\n")
		}
	} else {
		r := it.req
		fmt.Fprintf(&b, "from %s\r\n", safe(r.Subject))
		fmt.Fprintf(&b, "requesting: %s (depth: %s)\r\n", strings.Join(r.RequestedScopes, ", "), r.Depth)
		if r.RequestedTTLSeconds != nil {
			fmt.Fprintf(&b, "for %d minutes\r\n", *r.RequestedTTLSeconds/60)
		}
		if r.Justification != "" {
			fmt.Fprintf(&b, "justification: %s\r\n", safe(r.Justification))
		}
	}
	return b.String()
}

// safe strips terminal control-sequence injection vectors from agent-supplied
// free text (Subject/Content/Justification) before it's ever written to the
// reviewer's screen. This program's whole premise is that agent input is
// untrusted until a human reviews it — but "review" itself happens by reading
// this terminal, so a raw control byte in that text (most importantly ESC
// 0x1b, which begins every ANSI/CSI escape sequence) would let a malicious or
// compromised agent rewrite what's on screen: clear the pane, hide the actual
// scopes or the ⚠ contradiction warning above, or overlay a fake prompt,
// before the reviewer's next keypress acts on what they think they saw.
// Scopes and Depth aren't passed through this — both are already restricted
// to a closed character set/enum before they ever reach here (scope.Validate,
// the depth CHECK constraint), so they're not free text an agent controls the
// bytes of. Found in review (security).
func safe(s string) string {
	return strings.Map(func(r rune) rune {
		// C0 controls (0x00-0x1F) + DEL, plus the C1 range (0x80-0x9F) —
		// found in review (Codex P1) on this same followup PR: the first
		// version of this fix only stripped C0/DEL, but terminals that honor
		// 8-bit C1 controls treat U+009B as CSI too, so agent text encoding
		// that codepoint could still open an escape sequence and rewrite the
		// approval pane, bypassing the original fix entirely.
		if (r >= 0x00 && r <= 0x1f) || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return ' '
		}
		return r
	}, s)
}

// truncate shortens s to at most n runes, appending an ellipsis marker in
// place of the last one when it does. Rune-based rather than s[:n] byte
// slicing: Subject/Content can contain multi-byte UTF-8 (the render code
// already prints Unicode symbols like ⚠ itself), and byte-slicing mid-rune
// produces invalid UTF-8 in the truncated output. Found in review.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}
