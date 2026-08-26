package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// versionBeforeEnrollmentLatchBackfill is the migration version immediately
// preceding 20260811110000_enrollment_latch_backfill
// (20260811100000_capability_token_hash_unique) — i.e. "the backfill
// migration has not run yet." Used instead of m.Steps(-1) below: Steps(-1)
// means "one step back from whatever the latest embedded migration
// currently is," which silently stopped meaning "immediately before the
// backfill" the moment a later migration (20260812120000_agent_tokens)
// landed after it. Targeting this fixed version keeps these tests correct
// regardless of how many migrations get added later.
const versionBeforeEnrollmentLatchBackfill = 20260811100000

// TestEnrollmentLatchBackfill_SeedsLatchForPriorEnrollment is the upgrade-path
// proof for the P1 finding that 20260810000000_enrollment_latch only CREATE
// TABLEs and never backfills: seed a TOTP enrollment as if it existed before
// the latch migration ever ran (schema at the version immediately below this
// backfill migration, exactly matching the state of a real deployment that
// applied 20260810000000 without this fix), then re-apply migrations and
// confirm the latch comes out set. Without 20260811110000_enrollment_latch_backfill,
// the latch would stay unset here — which is exactly the gap that let Step 1
// of the documented break-glass recovery (docs/operations.md) alone reopen
// createToken's enrollment gate on any upgraded deployment.
func TestEnrollmentLatchBackfill_SeedsLatchForPriorEnrollment(t *testing.T) {
	url := testDatabaseURL(t)
	require.NoError(t, Migrate(url))

	ctx := context.Background()
	pool, err := Open(ctx, url)
	require.NoError(t, err)
	defer pool.Close()

	// Isolate: this test owns these four tables' contents (webauthn_challenges
	// is included only because it FK-references reviewer_tokens ON DELETE
	// CASCADE and would block a bare TRUNCATE of it, matching the TRUNCATE
	// lists elsewhere in this repo, e.g. internal/store/store_test.go).
	_, err = pool.Exec(ctx, `TRUNCATE reviewer_tokens, webauthn_credentials, webauthn_challenges, enrollment_latch`)
	require.NoError(t, err)

	// Step the schema back to immediately before the backfill migration —
	// reproduces "20260810000000 has run (the table exists) but this fix has
	// not" without disturbing anything else in the schema.
	m, closeFn, err := migrator(url)
	require.NoError(t, err)
	require.NoError(t, m.Migrate(versionBeforeEnrollmentLatchBackfill))
	closeFn()

	// Seed a pre-existing TOTP enrollment directly — standing in for a real
	// device enrolled before 20260811110000 ever existed. The sealed-secret
	// bytes don't need to be openable; the backfill's WHERE clause only checks
	// totp_secret_enc IS NOT NULL, matching CountEverEnrolledReviewerTokens
	// exactly.
	var tokenID string
	err = pool.QueryRow(ctx,
		`INSERT INTO reviewer_tokens (label, token_hash, totp_secret_enc) VALUES ($1, $2, $3) RETURNING id`,
		"pre-existing-device", []byte("hash-stand-in"), []byte("sealed-secret-stand-in"),
	).Scan(&tokenID)
	require.NoError(t, err)

	// Confirm the bug this migration fixes: with the backfill not yet applied,
	// a genuine prior enrollment leaves the latch unset.
	var latchedBeforeBackfill bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM enrollment_latch)`).Scan(&latchedBeforeBackfill))
	require.False(t, latchedBeforeBackfill, "latch should be unset before the backfill migration runs, reproducing the bug")

	// Re-apply migrations: this runs the backfill's up.sql against the
	// now-seeded reviewer_tokens row.
	require.NoError(t, Migrate(url))

	var latchedAfterBackfill bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM enrollment_latch)`).Scan(&latchedAfterBackfill))
	require.True(t, latchedAfterBackfill, "backfill migration did not latch a deployment with a pre-existing TOTP enrollment")
}

// TestEnrollmentLatchBackfill_PriorWebAuthnEnrollmentAlsoLatches is the
// passkey half of the same proof — CountEverEnrolledWebAuthnCredentials
// counts any row in webauthn_credentials at all (revoked included), and the
// backfill must match that definition, not just the TOTP one.
func TestEnrollmentLatchBackfill_PriorWebAuthnEnrollmentAlsoLatches(t *testing.T) {
	url := testDatabaseURL(t)
	require.NoError(t, Migrate(url))

	ctx := context.Background()
	pool, err := Open(ctx, url)
	require.NoError(t, err)
	defer pool.Close()

	_, err = pool.Exec(ctx, `TRUNCATE reviewer_tokens, webauthn_credentials, webauthn_challenges, enrollment_latch`)
	require.NoError(t, err)

	m, closeFn, err := migrator(url)
	require.NoError(t, err)
	require.NoError(t, m.Migrate(versionBeforeEnrollmentLatchBackfill))
	closeFn()

	// A factorless reviewer token (no TOTP secret) with a passkey bound to
	// it — the WebAuthn count is deliberately independent of the TOTP one
	// (see CountEverEnrolledWebAuthnCredentials' doc comment).
	var tokenID string
	err = pool.QueryRow(ctx,
		`INSERT INTO reviewer_tokens (label, token_hash, totp_secret_enc) VALUES ($1, $2, NULL) RETURNING id`,
		"passkey-only-device", []byte("hash-stand-in-2"),
	).Scan(&tokenID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`INSERT INTO webauthn_credentials (reviewer_token_id, label, credential_id, public_key, attestation_type)
		 VALUES ($1, 'yubikey', $2, $3, 'none')`,
		tokenID, []byte("cred-id-stand-in"), []byte("pub-key-stand-in"),
	)
	require.NoError(t, err)

	var latchedBefore bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM enrollment_latch)`).Scan(&latchedBefore))
	require.False(t, latchedBefore, "latch should be unset before the backfill migration runs")

	require.NoError(t, Migrate(url))

	var latchedAfter bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM enrollment_latch)`).Scan(&latchedAfter))
	require.True(t, latchedAfter, "backfill migration did not latch a deployment with a pre-existing passkey enrollment (TOTP-less)")
}

// TestEnrollmentLatchBackfill_NoPriorEnrollmentStaysUnlatched is the negative
// case the task explicitly calls out: a deployment with nothing EVER
// enrolled (a genuine fresh install, or one that never got past the
// factorless bootstrap token) must NOT come out of this migration latched —
// that would break createToken's first-enrollment bootstrap carve-out for
// every fresh install.
func TestEnrollmentLatchBackfill_NoPriorEnrollmentStaysUnlatched(t *testing.T) {
	url := testDatabaseURL(t)
	require.NoError(t, Migrate(url))

	ctx := context.Background()
	pool, err := Open(ctx, url)
	require.NoError(t, err)
	defer pool.Close()

	_, err = pool.Exec(ctx, `TRUNCATE reviewer_tokens, webauthn_credentials, webauthn_challenges, enrollment_latch`)
	require.NoError(t, err)

	m, closeFn, err := migrator(url)
	require.NoError(t, err)
	require.NoError(t, m.Migrate(versionBeforeEnrollmentLatchBackfill))
	closeFn()

	// Deliberately nothing seeded: reviewer_tokens and webauthn_credentials
	// are both empty, same as a fresh install.

	require.NoError(t, Migrate(url))

	var latched bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM enrollment_latch)`).Scan(&latched))
	require.False(t, latched, "backfill migration latched a deployment with no prior enrollment at all — this would break fresh-install bootstrap")
}
