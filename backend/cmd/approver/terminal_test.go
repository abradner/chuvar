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
