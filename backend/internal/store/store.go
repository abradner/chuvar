package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pgvector/pgvector-go"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// queryer is satisfied by both *pgxpool.Pool and pgx.Tx. Functions that need to
// run either standalone or as part of a caller's transaction (see logAudit) take
// this instead of a concrete pool, so a mutation and its audit_log row can commit
// or roll back together atomically rather than the audit write happening as a
// separate, non-atomic follow-up call.
type queryer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

var (
	_ queryer = (*pgxpool.Pool)(nil)
	_ queryer = (pgx.Tx)(nil)
)

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
