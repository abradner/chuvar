package summarize

import (
	"context"
	"strings"
	"testing"
)

func TestStub_Deterministic(t *testing.T) {
	s := Stub{}
	ctx := context.Background()

	a, err := s.Summarize(ctx, "user's favorite coffee is a flat white")
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	b, err := s.Summarize(ctx, "user's favorite coffee is a flat white")
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if a != b {
		t.Fatalf("Summarize() not deterministic: %q != %q", a, b)
	}
}

func TestStub_NeverContainsInputContent(t *testing.T) {
	s := Stub{}
	content := "user's medical condition is confidential and must not leak into a summary"

	got, err := s.Summarize(context.Background(), content)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	// The whole point of not truncating: a first-N-chars stub would, for any
	// content shorter than the cutoff, just BE the content — exactly what
	// summary depth exists to withhold. Assert the stub never reproduces any
	// substantial substring of the input, not just that it differs overall.
	if strings.Contains(got, content) {
		t.Fatalf("Summarize() output %q contains the full input content", got)
	}
	const probeLen = 20
	if len(content) >= probeLen && strings.Contains(got, content[:probeLen]) {
		t.Fatalf("Summarize() output %q leaks a content prefix", got)
	}
}

func TestStub_ShortContentNotEchoedVerbatim(t *testing.T) {
	// The case a naive first-N-chars stub gets wrong: content shorter than any
	// plausible truncation cutoff must still not come back unredacted.
	s := Stub{}
	content := "short"

	got, err := s.Summarize(context.Background(), content)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if got == content {
		t.Fatalf("Summarize(%q) = %q, want something other than the verbatim input", content, got)
	}
}
