// Package summarize provides the Summarizer interface used to project a
// fact's full content down to a shorter, disclosure-appropriate form for
// summary-depth grants, plus a deterministic stub implementation for v0.
// Interface rather than a bare function for the same reason internal/embed
// is: a real implementation means a real LLM call, which is separately
// gated future work (AGENTS.md §3.3 — no wiring a real AI provider without
// its own gated decision), not speculative abstraction for a hypothetical
// need.
package summarize

import (
	"context"
	"fmt"
	"unicode/utf8"
)

// Summarizer produces a shorter, disclosure-appropriate summary of content
// for summary-depth reads.
type Summarizer interface {
	Summarize(ctx context.Context, content string) (string, error)
}

// Stub is a deterministic, dependency-free Summarizer. It is NOT a real
// summary — deliberately not even a truncation of content. A first-N-chars
// truncation would, for any fact shorter than the cutoff (the common case:
// most facts here are a sentence or two), just be the fact's full content
// verbatim — exactly what summary depth exists to withhold. Stub instead
// returns a canned, content-length-only placeholder that never contains or
// reveals any of content, so summary-depth enforcement has something real
// (and actually redacting) to run against before a real summarizer lands.
// Mirrors embed.Stub's stance: this is the actual v0 runtime Summarizer,
// wired into cmd/apiserver today, not test-only code.
type Stub struct{}

func (Stub) Summarize(_ context.Context, content string) (string, error) {
	// utf8.RuneCountInString, not len(content): len counts bytes, which
	// over-reports length for any non-ASCII content. Found in review.
	return fmt.Sprintf("[stub summary: %d characters, no real summarizer wired yet]", utf8.RuneCountInString(content)), nil
}
