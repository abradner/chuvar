-- facts and staged_diffs now reference each other (facts.source_staged_diff_id ->
-- staged_diffs, staged_diffs.target_fact_id -> facts), so neither can be dropped
-- first individually — drop them together in one statement so Postgres resolves the
-- pair, rather than reaching for CASCADE (which would also silently take out
-- anything unexpected that later comes to depend on these tables).
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS grant_scopes;
DROP TABLE IF EXISTS grants;
DROP TABLE IF EXISTS fact_scopes;
DROP TABLE IF EXISTS staged_diffs, facts;
