package db

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// connectAs provisions a login password for one of the least-privilege roles
// and returns a pool connected as it.
//
// The migration deliberately creates these roles NOLOGIN and passwordless — a
// credential belongs to a deployment, not to a public repository — so the test
// grants LOGIN itself rather than depending on a checked-in secret or on an
// operator having run the provisioning step first.
func connectAs(t *testing.T, adminPool *pgxpool.Pool, role string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	const pw = "test-only-not-a-deployment-credential"
	_, err := adminPool.Exec(ctx, fmt.Sprintf("ALTER ROLE %s WITH LOGIN PASSWORD '%s'", role, pw))
	require.NoError(t, err, "granting LOGIN to %s", role)
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), fmt.Sprintf("ALTER ROLE %s WITH NOLOGIN PASSWORD NULL", role))
	})

	u, err := url.Parse(testDatabaseURL(t))
	require.NoError(t, err)
	u.User = url.UserPassword(role, pw)

	pool, err := Open(ctx, u.String())
	require.NoError(t, err, "connecting as %s", role)
	t.Cleanup(pool.Close)
	return pool
}

func adminPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testDatabaseURL(t)
	require.NoError(t, Migrate(dsn))
	pool, err := Open(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// The reason this ticket exists. An agent holding mcpserver's credentials must
// not be able to grant itself scopes — that is the consent model defeated in
// one statement, and no API-layer control sees it happen.
func TestAgentRoleCannotGrantItselfScopes(t *testing.T) {
	admin := adminPool(t)
	agent := connectAs(t, admin, "chuvar_agent")
	ctx := context.Background()

	_, err := agent.Exec(ctx,
		`INSERT INTO grants (subject, kind, depth, expires_at) VALUES ('rogue', 'memory', 'full', NULL)`)
	require.Error(t, err, "the agent role could insert a grant")
	require.ErrorContains(t, err, "permission denied")

	_, err = agent.Exec(ctx, `INSERT INTO grant_scopes (grant_id, scope) VALUES (gen_random_uuid(), 'identity.basic')`)
	require.Error(t, err, "the agent role could insert a grant scope")

	// Nor widen an existing one.
	_, err = agent.Exec(ctx, `UPDATE grants SET expires_at = NULL`)
	require.Error(t, err, "the agent role could extend a grant")

	_, err = agent.Exec(ctx, `DELETE FROM grants`)
	require.Error(t, err, "the agent role could delete grants")
}

// Secrets the agent has no use for: it should not be able to read them even as
// ciphertext. Defence in depth rather than the primary control — both are
// already hashed or sealed — but there is no reason to hand them over.
func TestAgentRoleCannotReadSecretTables(t *testing.T) {
	admin := adminPool(t)
	agent := connectAs(t, admin, "chuvar_agent")
	ctx := context.Background()

	for _, table := range []string{"reviewer_tokens", "data_keys"} {
		t.Run(table, func(t *testing.T) {
			var n int
			err := agent.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n)
			require.Error(t, err, "the agent role could read %s", table)
			require.ErrorContains(t, err, "permission denied")
		})
	}
}

// The audit trail is append-only from the agent's side: it can write entries
// but cannot read them back, so it can neither enumerate nor audit-check its
// own history. InsertAuditLog has no RETURNING clause, so nothing needs SELECT.
func TestAgentRoleCanAppendButNotReadAuditLog(t *testing.T) {
	admin := adminPool(t)
	agent := connectAs(t, admin, "chuvar_agent")
	ctx := context.Background()

	_, err := agent.Exec(ctx,
		`INSERT INTO audit_log (event_type, subject, scopes) VALUES ('read', 'agent-a', ARRAY['identity.basic'])`)
	require.NoError(t, err, "the agent role could not append to audit_log")

	var n int
	err = agent.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&n)
	require.Error(t, err, "the agent role could read audit_log")
}

// Everything mcpserver legitimately does must still work, or the role is not a
// constraint but a breakage. These mirror the store methods reachable from
// internal/mcptools.
func TestAgentRoleCanDoItsActualJob(t *testing.T) {
	admin := adminPool(t)
	agent := connectAs(t, admin, "chuvar_agent")
	ctx := context.Background()

	t.Run("read grants and scopes", func(t *testing.T) {
		var n int
		require.NoError(t, agent.QueryRow(ctx, `SELECT count(*) FROM grants`).Scan(&n))
		require.NoError(t, agent.QueryRow(ctx, `SELECT count(*) FROM grant_scopes`).Scan(&n))
	})

	t.Run("read facts and scopes", func(t *testing.T) {
		var n int
		require.NoError(t, agent.QueryRow(ctx, `SELECT count(*) FROM facts`).Scan(&n))
		require.NoError(t, agent.QueryRow(ctx, `SELECT count(*) FROM fact_scopes`).Scan(&n))
	})

	// INSERT ... RETURNING over only the generated columns — the shape
	// ProposeDiff and RequestGrant now use. Column-level SELECT is what makes
	// this work without granting a table-wide read.
	t.Run("stage a diff with RETURNING", func(t *testing.T) {
		var id string
		require.NoError(t, agent.QueryRow(ctx,
			`INSERT INTO staged_diffs (subject, content, proposed_scopes)
			 VALUES ('agent-a', 'proposed content', ARRAY['identity.basic'])
			 RETURNING id, status, created_at`).Scan(&id, new(string), new(any)))
		require.NotEmpty(t, id)
	})

	t.Run("request a grant with RETURNING", func(t *testing.T) {
		var id string
		require.NoError(t, agent.QueryRow(ctx,
			`INSERT INTO grant_requests (subject, requested_scopes, kind, depth)
			 VALUES ('agent-a', ARRAY['identity.basic'], 'memory', 'facts')
			 RETURNING id, status, created_at`).Scan(&id, new(string), new(any)))
		require.NotEmpty(t, id)
	})

	// The propose_write rate limit's atomic upsert — INSERT ... ON CONFLICT ...
	// DO UPDATE SET count = count + 1 ... RETURNING count — needs INSERT plus
	// SELECT+UPDATE on the relevant columns. Exercised here rather than assumed,
	// per the least_privilege_roles migration's own stated practice; see the
	// propose_write_rate_limit migration's doc comment for what that turned out
	// to require.
	//
	// Subject here is a value unique to this test (not "agent-a", which other
	// subtests in this file and other packages' propose_write/ProposeWrite
	// tests also use): every other table in this suite dedupes on a fresh UUID
	// per row, so cross-test reuse of "agent-a" is harmless, but this table's
	// primary key is (subject, window_start) — reusing a common subject would
	// make the counter's starting value depend on what else ran against the
	// shared database in the same minute, which is exactly the kind of
	// inter-test pollution the fixed-window design (this file's migration
	// comment) accepts as a tradeoff for tests, not for production.
	t.Run("increment the propose_write rate limit counter", func(t *testing.T) {
		// Fixed window_start (not date_trunc('minute', now())) so the two
		// executions of q below can't straddle a minute boundary and miss the
		// conflict path — which also means the row survives across runs on a
		// shared database, so clear it first (as admin: chuvar_agent
		// deliberately has no DELETE here).
		_, err := admin.Exec(ctx,
			`DELETE FROM propose_write_rate_limits WHERE subject = 'roles-test-rate-limit-increment'`)
		require.NoError(t, err)
		const q = `INSERT INTO propose_write_rate_limits (subject, window_start, count)
			 VALUES ('roles-test-rate-limit-increment', TIMESTAMPTZ '2026-01-01 00:00:00+00', 1)
			 ON CONFLICT (subject, window_start)
			 DO UPDATE SET count = propose_write_rate_limits.count + 1
			 RETURNING count`
		var count int
		require.NoError(t, agent.QueryRow(ctx, q).Scan(&count))
		require.Equal(t, 1, count)
		require.NoError(t, agent.QueryRow(ctx, q).Scan(&count))
		require.Equal(t, 2, count, "the conflict branch did not see its own prior increment")
	})
}

// Postgres requires SELECT on a conflict target's own columns to evaluate
// `ON CONFLICT (subject, window_start)` — verified in the migration's own doc
// comment, not assumed — so all three columns end up needing SELECT, unlike
// the narrower staged_diffs/grant_requests grants this table's shape was
// modeled on. What's still withheld: the ability to repoint an existing row
// at a different subject or window via UPDATE, so the only way to affect a
// row is through the same atomic upsert path store.CheckProposeWriteRateLimit
// uses, not an arbitrary rewrite of who a counter belongs to.
func TestAgentRoleCannotRepointRateLimitRowsToAnotherSubjectOrWindow(t *testing.T) {
	admin := adminPool(t)
	ctx := context.Background()

	// A subject unique to this test, for the same reason as the "increment"
	// subtest above: this table's primary key is (subject, window_start), so a
	// commonly-reused subject would make this test's outcome depend on
	// whatever else ran against the shared database in the same minute.
	const subject = "roles-test-rate-limit-repoint"
	// Fixed window_start for the same no-minute-boundary reason as the
	// increment subtest, with the same consequence: the row outlives a run,
	// so clear it before inserting.
	_, err := admin.Exec(ctx,
		`DELETE FROM propose_write_rate_limits WHERE subject = $1`, subject)
	require.NoError(t, err)
	_, err = admin.Exec(ctx,
		`INSERT INTO propose_write_rate_limits (subject, window_start, count)
		 VALUES ($1, TIMESTAMPTZ '2026-01-01 00:00:00+00', 7)`, subject)
	require.NoError(t, err)

	agent := connectAs(t, admin, "chuvar_agent")

	_, err = agent.Exec(ctx, `UPDATE propose_write_rate_limits SET subject = 'agent-a' WHERE subject = $1`, subject)
	require.Error(t, err, "the agent role could repoint a rate-limit row to a different subject")

	_, err = agent.Exec(ctx, `UPDATE propose_write_rate_limits SET window_start = now() WHERE subject = $1`, subject)
	require.Error(t, err, "the agent role could repoint a rate-limit row to a different window")

	// The one column it may write remains writable — this is what the upsert's
	// conflict-branch SET clause depends on.
	_, err = agent.Exec(ctx, `UPDATE propose_write_rate_limits SET count = 8 WHERE subject = $1`, subject)
	require.NoError(t, err, "the agent role could not update its granted count column")
}

// The agent must not be able to reshape the schema — the question that started
// this ticket, even though it turned out to be the smaller half.
func TestAgentRoleHasNoDDL(t *testing.T) {
	admin := adminPool(t)
	agent := connectAs(t, admin, "chuvar_agent")
	ctx := context.Background()

	_, err := agent.Exec(ctx, `CREATE TABLE e8_probe (id int)`)
	require.Error(t, err, "the agent role could create a table")

	_, err = agent.Exec(ctx, `DROP TABLE IF EXISTS facts`)
	require.Error(t, err, "the agent role could drop a table")
}

// apiserver's role needs full DML — it commits diffs, approves requests, writes
// grants — but must not hold DDL. This one survives E3.
func TestAppRoleHasFullDMLButNoDDL(t *testing.T) {
	admin := adminPool(t)
	app := connectAs(t, admin, "chuvar_app")
	ctx := context.Background()

	var id string
	require.NoError(t, app.QueryRow(ctx,
		`INSERT INTO grants (subject, kind, depth) VALUES ('app-created', 'memory', 'facts') RETURNING id`).Scan(&id))
	_, err := app.Exec(ctx, `UPDATE grants SET revoked_at = now() WHERE id = $1`, id)
	require.NoError(t, err)

	// Unlike the agent, apiserver legitimately reads reviewer tokens and data
	// keys — it authenticates reviewers and holds the master key.
	var n int
	require.NoError(t, app.QueryRow(ctx, `SELECT count(*) FROM reviewer_tokens`).Scan(&n))
	require.NoError(t, app.QueryRow(ctx, `SELECT count(*) FROM data_keys`).Scan(&n))

	_, err = app.Exec(ctx, `CREATE TABLE e8_probe_app (id int)`)
	require.Error(t, err, "the app role could create a table")

	_, err = admin.Exec(ctx, `DELETE FROM grants WHERE id = $1`, id)
	require.NoError(t, err)
}

// A table added later must not become agent-readable by default. ALTER DEFAULT
// PRIVILEGES covers chuvar_app deliberately and chuvar_agent deliberately not —
// this asserts the asymmetry, which is the bit that rots silently otherwise.
func TestNewTablesAreAgentInvisibleButAppWritable(t *testing.T) {
	admin := adminPool(t)
	ctx := context.Background()

	_, err := admin.Exec(ctx, `CREATE TABLE IF NOT EXISTS e8_future_table (id int)`)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), `DROP TABLE IF EXISTS e8_future_table`) })

	agent := connectAs(t, admin, "chuvar_agent")
	var n int
	err = agent.QueryRow(ctx, `SELECT count(*) FROM e8_future_table`).Scan(&n)
	require.Error(t, err, "a newly created table was readable by the agent role by default")

	// Exercise every verb ALTER DEFAULT PRIVILEGES is supposed to confer, not
	// just SELECT: a regression that granted reads but dropped writes would
	// otherwise pass here while breaking apiserver at runtime.
	app := connectAs(t, admin, "chuvar_app")
	require.NoError(t, app.QueryRow(ctx, `SELECT count(*) FROM e8_future_table`).Scan(&n),
		"app role cannot read a new table; ALTER DEFAULT PRIVILEGES has regressed")
	_, err = app.Exec(ctx, `INSERT INTO e8_future_table (id) VALUES (1)`)
	require.NoError(t, err, "app role cannot INSERT into a new table")
	_, err = app.Exec(ctx, `UPDATE e8_future_table SET id = 2 WHERE id = 1`)
	require.NoError(t, err, "app role cannot UPDATE a new table")
	_, err = app.Exec(ctx, `DELETE FROM e8_future_table WHERE id = 2`)
	require.NoError(t, err, "app role cannot DELETE from a new table")
}

// Both services call CheckSchema at boot, which reads golang-migrate's
// bookkeeping table. The privilege tests originally missed this because they
// exercised CheckSchema on the admin pool — the omission only surfaced when
// mcpserver was actually run under chuvar_agent and refused to start. This
// asserts the boot path works under each service's own role.
func TestServiceRolesCanRunTheBootSchemaCheck(t *testing.T) {
	admin := adminPool(t)
	ctx := context.Background()

	for _, role := range []string{"chuvar_agent", "chuvar_app"} {
		t.Run(role, func(t *testing.T) {
			pool := connectAs(t, admin, role)
			require.NoError(t, CheckSchema(ctx, pool),
				"%s cannot run the boot schema check", role)
		})
	}
}

// Neither service may write the version table: forging a version or clearing
// the dirty flag would let a process talk its way past the check that exists to
// stop it running against a schema it does not understand.
func TestServiceRolesCannotWriteTheVersionTable(t *testing.T) {
	admin := adminPool(t)
	ctx := context.Background()

	for _, role := range []string{"chuvar_agent", "chuvar_app"} {
		t.Run(role, func(t *testing.T) {
			pool := connectAs(t, admin, role)
			_, err := pool.Exec(ctx, `UPDATE schema_migrations SET dirty = false`)
			require.Error(t, err, "%s could write schema_migrations", role)
		})
	}
}

// The point of narrowing the RETURNING clauses: an agent can learn the id of
// what it just wrote, and read nothing else. Before this, RETURNING the whole
// row forced a table-wide SELECT grant, letting any agent enumerate every other
// subject's proposed content and stated justifications — a cross-subject read
// in a system whose premise is that subjects see only what they are granted.
func TestAgentRoleCannotReadOtherSubjectsProposals(t *testing.T) {
	admin := adminPool(t)
	ctx := context.Background()

	// Someone else's pending work, written by a privileged caller.
	_, err := admin.Exec(ctx,
		`INSERT INTO staged_diffs (subject, content, proposed_scopes)
		 VALUES ('someone-else', 'a secret nobody else should read', ARRAY['identity.basic'])`)
	require.NoError(t, err)
	_, err = admin.Exec(ctx,
		`INSERT INTO grant_requests (subject, requested_scopes, kind, depth, justification)
		 VALUES ('someone-else', ARRAY['identity.basic'], 'memory', 'facts', 'a private reason')`)
	require.NoError(t, err)

	agent := connectAs(t, admin, "chuvar_agent")

	for _, q := range []string{
		`SELECT content FROM staged_diffs`,
		`SELECT subject FROM staged_diffs`,
		`SELECT justification FROM grant_requests`,
		`SELECT subject FROM grant_requests`,
		`SELECT * FROM staged_diffs`,
	} {
		t.Run(q, func(t *testing.T) {
			rows, err := agent.Query(ctx, q)
			if err == nil {
				rows.Close()
				err = rows.Err()
			}
			require.Error(t, err, "the agent role could run: %s", q)
		})
	}

	// The generated columns it does need remain readable.
	var n int
	require.NoError(t, agent.QueryRow(ctx, `SELECT count(id) FROM staged_diffs`).Scan(&n))
}
