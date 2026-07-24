package store

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pgvector/pgvector-go"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// embeddingDim must match the `vector(384)` column in the facts table
// (internal/db/migrations/0001_init.up.sql) and embed.Dim. Not imported from the
// embed package directly — store shouldn't depend on it just for a constant it can
// state locally, since store's job is to persist whatever embedding it's handed,
// not to know how embeddings are produced.
const embeddingDim = 384

// toVectorParam converts an embedding into a query parameter: nil (SQL NULL) for an
// empty embedding — the degraded no-embedder mode already handled elsewhere in this
// package (see findDedupeCandidate) — or a pgvector.Vector for a correctly-sized
// one. A non-empty embedding of the wrong dimension is a caller bug and gets a
// clear error here rather than reaching Postgres as a confusing dimension-mismatch
// failure from the vector column/operator.
func toVectorParam(embedding []float32) (any, error) {
	if len(embedding) == 0 {
		return nil, nil
	}
	if len(embedding) != embeddingDim {
		return nil, fmt.Errorf("store: embedding has %d dimensions, want %d", len(embedding), embeddingDim)
	}
	return pgvector.NewVector(embedding), nil
}
