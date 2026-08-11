-- Closes issue #83: findDedupeCandidate (internal/store/staged_diffs.go) is a
-- second content-disclosure surface reachable via propose_write, alongside
-- SearchFacts, and it was scope-filtered but not depth-filtered. A subject
-- holding only a summary-depth grant could confirm a fact's exact content by
-- proposing an exact-text guess (verdict "duplicate", real fact ID attached)
-- and distinguish it from a wrong guess (verdict "novel") — an oracle
-- SearchFacts' own depth redaction was supposed to close off.
--
-- The fix (staged_diffs.go's findDedupeCandidate) collapses "duplicate" and
-- "contradiction" into this new "needs_review" verdict whenever the nearest
-- dedupe candidate's effective depth for the proposer is "summary" —
-- withholding both which case it was and the candidate's fact ID, while still
-- telling an honest proposer that something it can't fully see may already
-- cover this content. "facts"/"full" depth callers are unaffected: they can
-- already read the candidate's full content via SearchFacts, so the precise
-- verdict discloses nothing new to them.
ALTER TABLE staged_diffs DROP CONSTRAINT staged_diffs_dedupe_verdict_check;
ALTER TABLE staged_diffs ADD CONSTRAINT staged_diffs_dedupe_verdict_check
    CHECK (dedupe_verdict IN ('novel', 'duplicate', 'contradiction', 'needs_review'));
