package embed

import (
	"context"
	"math"
	"testing"
)

func TestStub_Deterministic(t *testing.T) {
	s := Stub{}
	ctx := context.Background()

	a, err := s.Embed(ctx, "the sky is blue")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	b, err := s.Embed(ctx, "the sky is blue")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}

	if len(a) != Dim {
		t.Fatalf("len(a) = %d, want %d", len(a), Dim)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("Embed() not deterministic at index %d: %v != %v", i, a[i], b[i])
		}
	}
}

func TestStub_DistinctInputsDiffer(t *testing.T) {
	s := Stub{}
	ctx := context.Background()

	a, _ := s.Embed(ctx, "the sky is blue")
	b, _ := s.Embed(ctx, "the grass is green")

	same := true
	for i := range a {
		if a[i] != b[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("Embed() produced identical vectors for distinct inputs")
	}
}

func TestStub_UnitNormalized(t *testing.T) {
	s := Stub{}
	vec, err := s.Embed(context.Background(), "some arbitrary fact content")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}

	var sumSquares float64
	for _, v := range vec {
		sumSquares += float64(v) * float64(v)
	}
	norm := math.Sqrt(sumSquares)
	if math.Abs(norm-1.0) > 1e-4 {
		t.Errorf("||vec|| = %v, want ~1.0", norm)
	}
}
