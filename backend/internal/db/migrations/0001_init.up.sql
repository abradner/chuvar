-- Core schema: facts, scope tags, grants, staged diffs, and audit log all live in one
-- transactionally-consistent place, per the "Postgres+pgvector is the sole canonical
-- store" decision (AGENTS.md §3.2). No dedicated vector DB, no split metadata store.

CREATE EXTENSION IF NOT EXISTS vector;

-- Embedding dimension is a placeholder (MiniLM-sized) pending the Research track's
-- classifier/embedding-model choice (Notion: "Research — Scope Classifier & Dedup
-- Model"). Changing it later means a new migration that rebuilds the column and its
-- index — expected, not a design flaw; don't treat 384 as load-bearing.
CREATE TABLE facts (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    content                TEXT NOT NULL,
    embedding              vector(384),
    content_tsv            tsvector GENERATED ALWAYS AS (to_tsvector('english', content)) STORED,
    metadata               JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Provenance: which staged diff produced this fact, and (on supersession) which
    -- fact replaced it. Never hard-delete a superseded fact — soft-invalidate via
    -- invalid_at/expired_at instead, mirroring Graphiti's bi-temporal pattern (Notion
    -- §7): both the old and new fact persist, so the audit trail stays intact.
    source_staged_diff_id  UUID,
    superseded_by          UUID REFERENCES facts(id),

    -- Bi-temporal columns: valid_at/invalid_at track when the fact was true in the
    -- world (event time); created_at/expired_at track when Memory Vault recorded
    -- that (system time). A fact being superseded sets invalid_at to the new fact's
    -- valid_at and expired_at to the commit time — distinct timestamps, matching why
    -- Graphiti keeps the two pairs separate rather than collapsing them.
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    invalid_at             TIMESTAMPTZ,
    expired_at             TIMESTAMPTZ
);

-- Partial HNSW index: only non-null embeddings need it, and there's no point paying
-- the index-maintenance cost for facts that haven't been embedded yet.
CREATE INDEX facts_embedding_hnsw_idx ON facts
    USING hnsw (embedding vector_cosine_ops)
    WHERE embedding IS NOT NULL;

CREATE INDEX facts_content_tsv_idx ON facts USING gin (content_tsv);

-- Fast lookup of "still-current" facts (used by both retrieval and the dashboard).
CREATE INDEX facts_active_idx ON facts (id) WHERE invalid_at IS NULL;

-- Scope tags: a normalized junction table, not just an array column on facts.
-- Letta's passages use the same dual approach (array column for display + junction
-- table for filtered search, Notion §7) — here we skip the array column entirely
-- since the junction table alone is what the WHERE-clause scope filter needs, and a
-- second copy would just be a sync hazard.
--
-- Scopes are plain TEXT, not a fixed enum/lookup table — the taxonomy is explicitly
-- unsettled (Notion §6, AGENTS.md §3.4). text_pattern_ops supports the hierarchical
-- prefix match (`scope LIKE 'projects.spritz.%'`) that a granted scope like
-- "projects.spritz" needs to cover its descendants, without needing a fixed set of
-- known scopes up front.
CREATE TABLE fact_scopes (
    fact_id  UUID NOT NULL REFERENCES facts(id) ON DELETE CASCADE,
    scope    TEXT NOT NULL,
    PRIMARY KEY (fact_id, scope)
);

CREATE INDEX fact_scopes_scope_idx ON fact_scopes (scope text_pattern_ops);

-- Grants: time-boxed, revocable, depth-leveled (progressive disclosure per Notion §3).
CREATE TABLE grants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject     TEXT NOT NULL,
    depth       TEXT NOT NULL DEFAULT 'facts' CHECK (depth IN ('summary', 'facts', 'full')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX grants_subject_idx ON grants (subject) WHERE revoked_at IS NULL;

CREATE TABLE grant_scopes (
    grant_id  UUID NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    scope     TEXT NOT NULL,
    PRIMARY KEY (grant_id, scope)
);

CREATE INDEX grant_scopes_scope_idx ON grant_scopes (scope text_pattern_ops);

-- Staged diffs: the only path a proposed fact can take toward becoming a real fact.
-- No code anywhere should insert directly into `facts` outside of committing a
-- staged diff — see AGENTS.md §3.1.
CREATE TABLE staged_diffs (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject                   TEXT NOT NULL,
    content                   TEXT NOT NULL,
    proposed_scopes           TEXT[] NOT NULL,

    -- Set when this diff proposes updating/superseding an existing fact rather than
    -- creating a new one.
    target_fact_id            UUID REFERENCES facts(id),

    status                    TEXT NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending', 'approved', 'rejected', 'committed')),

    -- Populated by the bouncer's dedupe step. 'contradiction' is what makes this
    -- table the poisoning tripwire, not just a write queue: a near-duplicate that
    -- conflicts with an existing fact is flagged for human review rather than
    -- silently merged or appended (Notion §4) — the opposite of what every prior-art
    -- project we mined does automatically (Notion §7).
    dedupe_verdict            TEXT CHECK (dedupe_verdict IN ('novel', 'duplicate', 'contradiction')),
    dedupe_candidate_fact_id  UUID REFERENCES facts(id),

    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at                TIMESTAMPTZ,
    decided_by                TEXT
);

CREATE INDEX staged_diffs_status_idx ON staged_diffs (status);

-- Append-only. Logs both writes AND reads (grants being exercised), not just
-- mutations — mem0's memory_access_logs and Letta's block_history both separate
-- audit history from the mutable record; we do the same by never updating a row
-- here after insert.
CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type      TEXT NOT NULL,
    subject         TEXT NOT NULL,
    fact_id         UUID REFERENCES facts(id),
    grant_id        UUID REFERENCES grants(id),
    staged_diff_id  UUID REFERENCES staged_diffs(id),
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    detail          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_subject_idx ON audit_log (subject);
CREATE INDEX audit_log_created_at_idx ON audit_log (created_at);
