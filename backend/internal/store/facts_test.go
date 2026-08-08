package store

import "testing"

// TestEffectiveDepth_InvalidGrantedDepthFailsClosed guards the read path that
// used to panic on an unrecognised depth (depthRank, called from here) —
// unreachable via the DB CHECK constraint today, but a corrupted or
// out-of-band row must deny, not crash the request handler or silently
// resolve to the most-permissive depth.
func TestEffectiveDepth_InvalidGrantedDepthFailsClosed(t *testing.T) {
	granted := []GrantedScope{{Scope: "identity", Depth: "bogus"}}
	if _, err := effectiveDepth([]string{"identity.basic"}, granted); err == nil {
		t.Fatal("effectiveDepth() with an invalid granted depth: want error, got nil")
	}
}

func TestEffectiveDepth_NoCoveringGrantFailsClosedToSummary(t *testing.T) {
	depth, err := effectiveDepth([]string{"identity.basic"}, nil)
	if err != nil {
		t.Fatalf("effectiveDepth() error = %v", err)
	}
	if depth != "summary" {
		t.Errorf("effectiveDepth() with no covering grant = %q, want %q", depth, "summary")
	}
}
