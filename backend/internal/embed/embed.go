// Package embed provides the Embedder interface used by the bouncer's dedupe step,
// plus a deterministic stub implementation for v0. This is an interface rather than
// a bare function because we already know there's a second, real implementation
// coming (Bedrock in production, per the Notion design doc) — not speculative
// abstraction for a hypothetical future need.
package embed

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
)

// Dim is the embedding dimensionality, matching the `vector(384)` column in the
// facts table. Placeholder pending the Research track's model choice — see the
// migration comment in internal/db/migrations.
const Dim = 384

// Embedder turns text into a fixed-length vector for semantic similarity search.
type Embedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
}

// Stub is a deterministic, dependency-free Embedder for local development and
// tests. It is NOT a real semantic embedding — near-meaning text does not reliably
// land near each other in this space, only near-identical text does. It exists so
// the dedupe/retrieval pipeline has something to run against before the Research
// track (Notion: "Research — Scope Classifier & Dedup Model") lands a real model.
// Swap it out behind the Embedder interface; nothing downstream should need to
// change.
type Stub struct{}

func (Stub) Embed(_ context.Context, text string) ([]float32, error) {
	vec := make([]float32, Dim)

	// Seeded from SHA-256 rather than a fast non-cryptographic hash:
	// findDedupeCandidate (internal/store, a later PR) picks the single nearest fact
	// by embedding distance, so an adversary who could cheaply engineer a hash
	// collision against a specific existing fact could make unrelated content look
	// like a near-duplicate/contradiction of it. Human approval still gates every
	// commit (AGENTS.md §3.1) so this was never a full bypass, but there's no reason
	// to leave a cheap collision search on the table when a cryptographic hash is a
	// one-line swap. Only the seed derivation matters here — still deterministic,
	// still explicitly not a real embedding, see the Stub doc comment above.
	digest := sha256.Sum256([]byte(text))
	seed := binary.BigEndian.Uint64(digest[:8])

	// A simple splitmix64-style stream: deterministic, well-distributed enough to
	// give distinct strings distinct directions in the space without pulling in a
	// randomness dependency.
	state := seed
	var sumSquares float64
	for i := range vec {
		state += 0x9E3779B97F4A7C15
		z := state
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		z = z ^ (z >> 31)
		// Map to roughly [-1, 1].
		v := float32(int64(z)) / float32(math.MaxInt64)
		vec[i] = v
		sumSquares += float64(v) * float64(v)
	}

	// Unit-normalize so cosine distance behaves sensibly.
	norm := float32(math.Sqrt(sumSquares))
	if norm > 0 {
		for i := range vec {
			vec[i] /= norm
		}
	}
	return vec, nil
}
