package main

import "testing"

func TestSafe_StripsControlBytes(t *testing.T) {
	// The security-relevant case: ESC (0x1b) begins every ANSI/CSI escape
	// sequence — a raw one here would let a malicious agent rewrite the
	// reviewer's terminal (clear the pane, hide a warning) before their next
	// keypress. Regression test for the fix found in review.
	got := safe("clear the screen\x1b[2Jhidden warning")
	if got != "clear the screen [2Jhidden warning" {
		t.Errorf("safe() = %q, want ESC replaced with a space", got)
	}
}

func TestSafe_StripsCarriageReturnAndDel(t *testing.T) {
	got := safe("line one\rline two\x7fend")
	if got != "line one line two end" {
		t.Errorf("safe() = %q", got)
	}
}

func TestSafe_LeavesOrdinaryTextUnchanged(t *testing.T) {
	got := safe("user's favorite color is teal — ⚠ nothing scary here")
	if got != "user's favorite color is teal — ⚠ nothing scary here" {
		t.Errorf("safe() changed ordinary text: %q", got)
	}
}

func TestTruncate_IsRuneSafe(t *testing.T) {
	// A byte-slicing truncate would split "café" mid-rune (é is 2 bytes) and
	// produce invalid UTF-8. This string is 5 runes; truncating to 4 must cut
	// after "caf" and append the ellipsis, never split "é".
	got := truncate("café!", 4)
	want := "caf…"
	if got != want {
		t.Errorf("truncate(%q, 4) = %q, want %q", "café!", got, want)
	}
}

func TestTruncate_ShortStringUnchanged(t *testing.T) {
	if got := truncate("short", 50); got != "short" {
		t.Errorf("truncate() = %q, want unchanged", got)
	}
}

// TestSafe_StripsC1Controls is the regression test for the review finding on
// this same followup PR: the first version of safe() only stripped C0
// controls and DEL, leaving the C1 range (U+0080-U+009F) intact. U+009B is
// CSI on terminals that honor 8-bit C1 controls — functionally equivalent to
// ESC-[ for opening an escape sequence — so agent text containing it could
// still rewrite the approval pane even after the original fix.
func TestSafe_StripsC1Controls(t *testing.T) {
	// U+009B (C1 CSI) built via rune conversion rather than embedding the raw
	// control byte as a source-file literal.
	c1csi := string(rune(0x9b))
	got := safe("before" + c1csi + "2Jafter")
	if got != "before 2Jafter" {
		t.Errorf("safe() = %q, want U+009B (C1 CSI) replaced with a space", got)
	}
}

// TestSafe_StripsBidiControls is the regression test for the review finding
// on this same followup PR (Codex P2): U+202E (RLO) and its relatives aren't
// control bytes, but they can visually reorder text on a terminal that honors
// the bidi algorithm — the "Trojan Source" class of attack (CVE-2021-42574).
// Agent content containing one could reorder itself, or reorder the trusted
// "[contradiction]" suffix renderSummary appends after it, before a reviewer
// acts on what they think they saw.
func TestSafe_StripsBidiControls(t *testing.T) {
	rlo := string(rune(0x202e)) // Right-to-Left Override
	got := safe("before" + rlo + "after")
	if got != "before after" {
		t.Errorf("safe() = %q, want U+202E (RLO) replaced with a space", got)
	}
}

func TestShortID_HandlesShortInput(t *testing.T) {
	// Regression test for the panic risk found in review: a bare id[:8] would
	// panic on any ID shorter than 8 characters.
	if got := shortID("abc"); got != "abc" {
		t.Errorf("shortID(%q) = %q, want unchanged", "abc", got)
	}
	if got := shortID("019f99bb-c8a1-75de-839d-eec4b20d3057"); got != "019f99bb" {
		t.Errorf("shortID() = %q, want first 8 chars", got)
	}
	if got := shortID(""); got != "" {
		t.Errorf("shortID(\"\") = %q, want empty", got)
	}
}
