package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abradner/chuvar/backend/internal/db"
)

// testPool is this package's equivalent of internal/store's testStore: real
// integration tests against a live Postgres, skipped cleanly when
// DATABASE_URL isn't set. internal/broker deliberately has no dependency on
// internal/store (see store.go's doc comment), so this doesn't reuse that
// package's test helper even though the shape is identical.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping broker integration tests (see docker-compose.yml)")
	}

	if err := db.Migrate(url); err != nil {
		t.Fatalf("db.Migrate() error = %v", err)
	}

	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatalf("db.Open() error = %v", err)
	}
	t.Cleanup(pool.Close)

	_, err = pool.Exec(ctx, `TRUNCATE grants, grant_scopes, capability_grant_identities, capability_grant_tokens, audit_log CASCADE`)
	if err != nil {
		t.Fatalf("truncating tables: %v", err)
	}
	return pool
}

// grantFixture is a capability grant inserted directly (no creation surface
// exists — issue #96), the way capability-broker.md's own scope for this
// build says tests must: "tests insert grant rows directly as fixtures."
type grantFixture struct {
	GrantID   string
	Token     string // plaintext — only ever known here, at fixture-insertion time
	ExpiresAt *time.Time
}

// insertCapabilityGrant seeds one fully-provisioned capability grant: a
// grants row (kind='capability'), its scopes, its committer identity, and
// its socket-auth token — the same four pieces loadCapabilityGrants' inner
// joins require. ttl of nil means no expiry, mirroring store.CreateGrant's
// convention.
func insertCapabilityGrant(t *testing.T, pool *pgxpool.Pool, subject, committerEmail string, scopes []string, ttl *time.Duration) grantFixture {
	t.Helper()
	ctx := context.Background()

	var expiresAt *time.Time
	if ttl != nil {
		e := time.Now().Add(*ttl)
		expiresAt = &e
	}

	var grantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO grants (subject, kind, depth, expires_at) VALUES ($1, 'capability', NULL, $2) RETURNING id`,
		subject, expiresAt,
	).Scan(&grantID); err != nil {
		t.Fatalf("insertCapabilityGrant: insert grants row: %v", err)
	}

	for _, s := range scopes {
		if _, err := pool.Exec(ctx, `INSERT INTO grant_scopes (grant_id, scope) VALUES ($1, $2)`, grantID, s); err != nil {
			t.Fatalf("insertCapabilityGrant: insert grant_scopes row: %v", err)
		}
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO capability_grant_identities (grant_id, committer_email) VALUES ($1, $2)`,
		grantID, committerEmail,
	); err != nil {
		t.Fatalf("insertCapabilityGrant: insert capability_grant_identities row: %v", err)
	}

	token := randomToken(t)
	if _, err := pool.Exec(ctx,
		`INSERT INTO capability_grant_tokens (grant_id, token_hash) VALUES ($1, $2)`,
		grantID, hashToken(token),
	); err != nil {
		t.Fatalf("insertCapabilityGrant: insert capability_grant_tokens row: %v", err)
	}

	return grantFixture{GrantID: grantID, Token: token, ExpiresAt: expiresAt}
}

func randomToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("randomToken: %v", err)
	}
	return hex.EncodeToString(b)
}

func revokeGrant(t *testing.T, pool *pgxpool.Pool, grantID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `UPDATE grants SET revoked_at = now() WHERE id = $1`, grantID); err != nil {
		t.Fatalf("revokeGrant: %v", err)
	}
}
