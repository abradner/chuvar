-- Per-subject rate limiting for propose_write (Notion ticket: "propose_write
-- requires no grant at all — the review queue is spammable").
--
-- bouncer.ProposeWrite fetches a proposer's granted scopes to scope-filter the
-- dedupe candidate search, but never requires them to be non-empty — any
-- configured MCP_SUBJECT can stage unlimited diffs while holding zero grants.
-- That's an attention denial-of-service against the one resource this system
-- cannot scale: the human reviewer. Painless review is called out in the
-- architecture notes as the primary defence against poisoned/manipulative
-- writes; an unbounded queue defeats that without tripping a single other
-- control.
--
-- Of the three options on the table — require an active grant before
-- proposing at all; rate-limit; cap outstanding pending diffs per subject —
-- rate-limiting was chosen. Requiring a grant breaks onboarding (a brand-new
-- agent has to propose before it holds anything to be granted), and a
-- rate limit is cheapest to add without touching that bootstrap flow. It
-- surfaces as a signal (RATE_LIMITED, see mcptools/propose_write.go) rather
-- than silent backpressure — a tripwire, not an admission gate, the same
-- stance the Agent Capability Broker takes on count bounds elsewhere.
--
-- Fixed-window counters, one row per (subject, window_start), incremented
-- atomically via INSERT ... ON CONFLICT ... DO UPDATE — see
-- store.CheckProposeWriteRateLimit for why the atomic upsert (rather than a
-- separate SELECT-then-write) is what actually closes the race between two
-- concurrent proposals from the same subject. subject here is always the
-- authenticated MCP_SUBJECT bound once at server construction
-- (mcptools.Register's doc comment) — never a client-supplied value — so this
-- cannot be keyed or spoofed by the caller.
CREATE TABLE propose_write_rate_limits (
    subject       TEXT NOT NULL,
    window_start  TIMESTAMPTZ NOT NULL,
    count         INT NOT NULL DEFAULT 0,
    PRIMARY KEY (subject, window_start)
);

-- chuvar_agent (mcpserver's role, least_privilege_roles migration) needs to
-- increment its own counter and read the post-increment count back. The first
-- attempt here granted only SELECT+UPDATE on `count` (reasoning: the upsert
-- never reads subject/window_start back, so why grant them) — verifying it
-- against a live chuvar_agent connection (rather than assuming, per that
-- migration's stated practice) turned up that Postgres rejects even
-- `... ON CONFLICT (subject, window_start) DO NOTHING` without SELECT on the
-- conflict target's own columns: evaluating the arbiter needs to read them,
-- not just the columns being written. So all three columns need SELECT
-- (subject and window_start for the conflict check, count for the increment
-- expression and RETURNING), and only `count` needs UPDATE — still no
-- table-level SELECT/UPDATE grant, and still no privilege to change which
-- (subject, window_start) a row belongs to. The residual cost: an agent that
-- ran a raw `SELECT subject, window_start FROM ...` (not something
-- store.CheckProposeWriteRateLimit's queries ever do) could enumerate which
-- other subjects have called propose_write and in which time buckets — no
-- content, no scopes, nothing this project otherwise treats as
-- confidential, unlike the staged_diffs/grant_requests case this pattern is
-- modeled on. Accepted rather than reached for a SECURITY DEFINER function to
-- close it further, which would be the next step if that residual ever
-- matters.
GRANT INSERT ON propose_write_rate_limits TO chuvar_agent;
GRANT SELECT (subject, window_start, count), UPDATE (count) ON propose_write_rate_limits TO chuvar_agent;

-- chuvar_app has no runtime path that touches this table today — only
-- mcpserver calls propose_write — but ALTER DEFAULT PRIVILEGES already grants
-- it full DML on every new table (least_privilege_roles migration), and
-- there's no reason to special-case an exception here.
