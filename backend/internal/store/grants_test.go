package store

import "testing"

// Pure-function unit tests for the depth vocabulary (depthOrder, ValidDepth,
// depthRank, depthName) — no DB needed, unlike the rest of this package's
// tests, since these three all derive from the same in-process slice.

func TestValidDepth(t *testing.T) {
	for _, d := range []string{"summary", "facts", "full"} {
		if !ValidDepth(d) {
			t.Errorf("ValidDepth(%q) = false, want true", d)
		}
	}
	for _, d := range []string{"", "bogus", "Full", "summary "} {
		if ValidDepth(d) {
			t.Errorf("ValidDepth(%q) = true, want false", d)
		}
	}
}

func TestDepthRank_OrdersByPermissiveness(t *testing.T) {
	summary, err := depthRank("summary")
	if err != nil {
		t.Fatalf(`depthRank("summary") error = %v`, err)
	}
	facts, err := depthRank("facts")
	if err != nil {
		t.Fatalf(`depthRank("facts") error = %v`, err)
	}
	full, err := depthRank("full")
	if err != nil {
		t.Fatalf(`depthRank("full") error = %v`, err)
	}
	if !(summary < facts && facts < full) {
		t.Fatalf("depthRank ordering = (%d, %d, %d), want strictly increasing summary < facts < full", summary, facts, full)
	}
}

func TestDepthRank_InvalidDepthFailsClosed(t *testing.T) {
	if _, err := depthRank("bogus"); err == nil {
		t.Fatal(`depthRank("bogus"): want error, got nil (must fail closed, not panic or default to a rank)`)
	}
}

func TestDepthName_RoundTripsWithDepthRank(t *testing.T) {
	for _, d := range []string{"summary", "facts", "full"} {
		r, err := depthRank(d)
		if err != nil {
			t.Fatalf("depthRank(%q) error = %v", d, err)
		}
		name, err := depthName(r)
		if err != nil {
			t.Fatalf("depthName(%d) error = %v", r, err)
		}
		if name != d {
			t.Errorf("depthName(depthRank(%q)) = %q, want %q", d, name, d)
		}
	}
}

func TestDepthName_OutOfRangeFailsClosed(t *testing.T) {
	for _, rank := range []int{-1, 3, 100} {
		if _, err := depthName(rank); err == nil {
			t.Errorf("depthName(%d): want error, got nil (must fail closed, not default to the most-permissive name)", rank)
		}
	}
}
