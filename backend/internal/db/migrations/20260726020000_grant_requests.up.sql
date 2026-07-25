-- Agent-initiated grant requests. Before this, grants could only be created by an
-- operator acting first — an agent that hit insufficient_scope on
-- read_with_scope_check had no way to ask for what it needed, short of the
-- operator noticing the audit log. This table is the request half of that gap: an
-- agent stages a request (via the request_grant MCP tool), a human approves or
-- denies it through the REST API / approval surfaces, exactly mirroring the
-- staged_diffs write-path pattern (propose, never write directly — AGENTS.md §3.1)
-- rather than inventing a new shape for the same idea.
CREATE TABLE grant_requests (
    id                     UUID PRIMARY KEY DEFAULT uuidv7(),
    subject                TEXT NOT NULL,
    requested_scopes       TEXT[] NOT NULL,
    depth                  TEXT NOT NULL DEFAULT 'facts' CHECK (depth IN ('summary', 'facts', 'full')),

    -- NULL means "no expiry requested" — mirrors grants.expires_at's own
    -- nullability, not a magic sentinel.
    requested_ttl_seconds  INT,

    -- Free-text, agent-supplied context for why it wants this access — shown to
    -- the human reviewer as part of the approval prompt (the "risk framing" /
    -- plain-language-ask anatomy from the approval-surfaces workshop). Not
    -- validated for content, only bounded in length at the MCP tool boundary
    -- (mirrors mcptools' maxContentLength stance) — this is display text, not a
    -- security-relevant field.
    justification          TEXT NOT NULL DEFAULT '',

    status                 TEXT NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'approved', 'denied')),

    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at             TIMESTAMPTZ,
    decided_by             TEXT,

    -- Set when approved: which real grant this request became. NULL for
    -- pending/denied requests. Lets a reviewer trace "why does this grant exist"
    -- back to the original request, same provenance idea as
    -- staged_diffs -> facts.source_staged_diff_id.
    resulting_grant_id     UUID REFERENCES grants(id)
);

CREATE INDEX grant_requests_status_idx ON grant_requests (status);
CREATE INDEX grant_requests_subject_idx ON grant_requests (subject);
