package store

import (
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pgvector/pgvector-go"

	"github.com/abradner/chuvar/backend/internal/custody"
	"github.com/abradner/chuvar/backend/internal/store/sqlcgen"
)

type Store struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries

	// secrets seals and opens the sealed columns (reviewer TOTP secrets today).
	// Nil is a legitimate state — most of this package never touches a sealed
	// value, and every caller that doesn't need one shouldn't have to hold key
	// material to get a Store. The methods that do need it fail closed rather
	// than falling back to plaintext; see VerifyReviewerTOTP.
	secrets *custody.Key
}

// New returns a Store with no sealing key. Methods that read or write sealed
// columns will refuse to run — deliberately, since the alternative to sealing
// is storing the secret in the clear.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, q: sqlcgen.New(pool)}
}

// NewSealed returns a Store that can seal and open secret columns under the
// given data-encryption key, which callers obtain from LoadOrCreateDataKey.
func NewSealed(pool *pgxpool.Pool, secrets *custody.Key) *Store {
	s := New(pool)
	s.secrets = secrets
	return s
}

// embeddingDim must match the `vector(384)` column in the facts table
// (internal/db/migrations) and embed.Dim. Not imported from the embed package
// directly — store shouldn't depend on it just for a constant it can state
// locally, since store's job is to persist whatever embedding it's handed, not to
// know how embeddings are produced.
const embeddingDim = 384

// toVectorParam converts an embedding into a query parameter: nil (SQL NULL) for
// an empty embedding — the degraded no-embedder mode already handled elsewhere in
// this package (see findDedupeCandidate) — or a pgvector.Vector for a correctly-
// sized one. A non-empty embedding of the wrong dimension is a caller bug and gets
// a clear error here rather than reaching Postgres as a confusing dimension-
// mismatch failure from the vector column/operator.
func toVectorParam(embedding []float32) (*pgvector.Vector, error) {
	if len(embedding) == 0 {
		return nil, nil
	}
	if len(embedding) != embeddingDim {
		return nil, fmt.Errorf("store: embedding has %d dimensions, want %d", len(embedding), embeddingDim)
	}
	v := pgvector.NewVector(embedding)
	return &v, nil
}

// toTimestamptz adapts a nullable Go time into the pgtype wrapper sqlc generates
// for a couple of INSERT/UPDATE parameters bound to nullable timestamptz columns
// (input-side nullability inference doesn't consistently pick up this package's
// sqlc.yaml overrides the way output-column scanning does — see grants.go and
// staged_diffs.go's two call sites).
func toTimestamptz(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}
