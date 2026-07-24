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

	a, err := s.Embed(ctx, "the sky is blue")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	b, err := s.Embed(ctx, "the grass is green")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}

	// A byte-for-byte inequality check alone would pass even if a and b were
	// highly correlated (e.g. differing in one component) — which is exactly the
	// risk a weak seed hash introduces (see the SHA-256 comment on Stub.Embed).
	// Assert the cosine similarity is actually low, not just "not identical."
	cos := cosineSimilarity(a, b)
	const maxSimilarity = 0.3
	if cos > maxSimilarity {
		t.Fatalf("cosine similarity between distinct inputs = %v, want <= %v (vectors too correlated)", cos, maxSimilarity)
	}
}

func cosineSimilarity(a, b []float32) float64 {
	var dot, normA, normB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

func TestStub_EmptyString(t *testing.T) {
	s := Stub{}
	vec, err := s.Embed(context.Background(), "")
	if err != nil {
		t.Fatalf("Embed(\"\") error = %v", err)
	}
	if len(vec) != Dim {
		t.Fatalf("len(vec) = %d, want %d", len(vec), Dim)
	}
	var sumSquares float64
	for _, v := range vec {
		sumSquares += float64(v) * float64(v)
	}
	if math.Abs(math.Sqrt(sumSquares)-1.0) > 1e-4 {
		t.Errorf("Embed(\"\") not unit-normalized: ||vec|| = %v", math.Sqrt(sumSquares))
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
