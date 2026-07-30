-- audit_log predates grant_requests and has no column referencing it, so a
-- grant_request_denied row carries only event_type and the actor — every
-- target identifier is NULL, since there's nowhere to put the request's own
-- id. Multiple denials by the same reviewer are indistinguishable in the
-- audit trail without cross-referencing mutable grant_requests rows by
-- timestamp. grant_request_approved rows already link forward via grant_id
-- (the newly created grant); this adds the matching backward link for both
-- outcomes. Flagged by Codex during review of PR #21, deliberately not
-- actioned there since it needs a real schema change, not a code-only patch.
ALTER TABLE audit_log ADD COLUMN grant_request_id UUID REFERENCES grant_requests(id);
