package broker

import (
	"context"
	"testing"
)

// TestCapabilityGrantTokens_DuplicateTokenHashRefused is the regression test
// for round-2 review's P2 finding: the index the 20260809140000 migration
// put on capability_grant_tokens (token_hash) was not unique, so two
// different grants could share a token_hash. Cache.apply (cache.go) keys
// byToken by that hash and stores exactly one Entry per key, with no
// ORDER BY on the load query to make a collision deterministic — a
// duplicate would silently bind the shared plaintext token to whichever
// grant's row the query happened to return last, misattributing every
// signature made with it. 20260811100000_capability_token_hash_unique.up.sql
// replaces the index with a genuinely unique one; this proves the database
// itself now refuses the second insert rather than merely trusting
// application code never to attempt it — direct SQL is the documented
// provisioning path today (issue #96), so this is the actual boundary.
func TestCapabilityGrantTokens_DuplicateTokenHashRefused(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	first := insertCapabilityGrant(t, pool, "subject-one", "one@example.com", []string{"git.sign:github.com/abradner/chuvar"}, nil)

	var secondGrantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO grants (subject, kind, depth, expires_at) VALUES ('subject-two', 'capability', NULL, NULL) RETURNING id`,
	).Scan(&secondGrantID); err != nil {
		t.Fatalf("insert second grants row: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO capability_grant_identities (grant_id, committer_email) VALUES ($1, $2)`,
		secondGrantID, "two@example.com",
	); err != nil {
		t.Fatalf("insert second capability_grant_identities row: %v", err)
	}

	// Reuse the FIRST grant's token — same plaintext, same hash — for the
	// second grant. This is exactly the misconfiguration the unique index
	// must catch: two live grants, two different scopes/identities, one
	// shared bearer token.
	_, err := pool.Exec(ctx,
		`INSERT INTO capability_grant_tokens (grant_id, token_hash) VALUES ($1, $2)`,
		secondGrantID, hashToken(first.Token),
	)
	if err == nil {
		t.Fatal("inserting a second grant's token row with an already-used token_hash succeeded; want a unique-constraint violation")
	}
}
