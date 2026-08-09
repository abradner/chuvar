// Package scope implements the hierarchical, dotted scope model that grants,
// facts, and (per the capability broker workstream) capabilities are checked
// against — e.g. "identity.basic", "projects.spritz.read", or, with a target,
// "git.sign:github.com/abradner/chuvar". The taxonomy itself (which scopes
// exist, how granular they should be) is an open product question (AGENTS.md
// §3.4); this package only encodes the matching rules, not any specific
// vocabulary.
//
// Grammar (decided 2026-08-09, docs/capability-broker.md decision log,
// "Scope grammar: dotted operation, optional colon-delimited target"):
//
//	scope := operation [ ":" target ]
//
// split on the FIRST colon — a target may itself contain further colons
// syntactically (Covers does not reject them), though this package's own
// target charset does not allow one (see targetPattern). The operation part
// keeps the pre-existing dotted-segment grammar and ancestor-match semantics,
// completely unchanged: a scope with no colon ("memory scope") parses as an
// operation with no target and is bit-for-bit identical, in every function in
// this file, to how it behaved before targets existed — see
// TestScope_Covers/TestValidate for the regression tests that pin this down.
package scope

import (
	"fmt"
	"regexp"
	"strings"
)

// Scope is a dot-delimited hierarchical access scope, optionally with a
// colon-delimited target (see package doc).
type Scope string

var segmentPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// targetPattern bounds the target's charset. Deliberately more conservative
// than it needs to be for any single known use case, because a target is
// free text that ends up compared, logged, and potentially interpolated into
// paths/URLs by whatever the operation class is (git remotes, hostnames,
// filesystem paths) — this package is the one chokepoint all of those share,
// so it's the right place to keep the surface small rather than trusting
// every downstream consumer to re-validate:
//   - No `*`/`?` (glob semantics). The decision log is explicit that globs
//     are aspirational vocabulary, not committed grammar, "until a real need
//     names one" — allowing them in the charset would make that an accident
//     of validation rather than a deliberate future decision.
//   - No `:`. Colon is the operation/target delimiter; a target charset that
//     allowed embedded colons would make "split on the first colon" a lossy
//     description of the actual grammar for any consumer that re-parses a
//     stored scope string instead of holding onto the already-split value.
//   - No whitespace or shell metacharacters (`;`, `|`, `$`, backticks, etc.)
//     for the same reason a target isn't allowed to carry glob syntax: this
//     is the boundary, not the eventual consumer, and the eventual consumer
//     is unknown.
//   - No `~` (shell/library-specific home-directory expansion — not part of
//     this grammar; the fs.write:~/code/worktrees/** example in the decision
//     doc is explicitly aspirational, not committed).
//   - No `..` path segment. The charset alone allows `.` and `/`, which
//     together spell directory traversal ("../../../etc/passwd") even though
//     Covers only ever does exact-string comparison today and grants no
//     unintended access by itself. This package is the one chokepoint every
//     downstream target consumer shares (see above), including the future
//     fs.write:~/code/worktrees/** operation class the decision log names —
//     the day a consumer treats a target as a filesystem path prefix instead
//     of an opaque string, a validated `..` becomes a real escape, and this
//     is the only place that can still catch it. Checked separately from
//     targetPattern (see hasTraversalSegment) because it's a structural rule
//     about path segments, not a charset rule.
//
// What it does allow: letters (both cases — unlike operation segments,
// targets are expected to hold hostnames and repo paths like
// "github.com/abradner/chuvar", which are conventionally mixed- or
// lower-case but not restricted to lower-case by any spec this package
// should be enforcing), digits, `.`, `-`, `_`, and `/` — enough to express
// the decided example without inventing grammar the decision didn't commit
// to.
var targetPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// hasTraversalSegment reports whether target contains a literal ".." path
// segment — i.e. target itself is "..", or ".." appears between two "/"
// (or at either end). This is a structural check, not a charset one: "/"
// and "." are both individually allowed (repo paths and hostnames need
// them), but the segment ".." specifically is directory-traversal syntax
// and has no legitimate meaning for any target this package currently
// documents (hostnames, repo paths) — see targetPattern's doc comment.
func hasTraversalSegment(target string) bool {
	for _, seg := range strings.Split(target, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// MaxLength bounds how long a single scope string can be — operation, the
// colon, and target together, since they share one TEXT column and no
// separate target bound exists (or is needed: bounding the whole string
// bounds the target transitively). No real taxonomy needs anywhere near this
// many characters — it exists to stop a pathological input from becoming a
// cheap CPU-amplification lever downstream, where every granted scope gets
// turned into a LIKE pattern evaluated against every fact_scopes row on every
// read (the store package, added later in this series).
const MaxLength = 256

// split parses s into its operation and (optional) target on the FIRST
// colon, per the package-level grammar. It does no validation — Covers calls
// this directly on already-granted/requested values without re-checking
// Validate, matching this package's pre-existing design (Covers has never
// validated its inputs; callers validate at the boundary — see
// read_with_scope_check.go).
func split(s Scope) (op string, target string, hasTarget bool) {
	str := string(s)
	idx := strings.IndexByte(str, ':')
	if idx == -1 {
		return str, "", false
	}
	return str[:idx], str[idx+1:], true
}

// Operation returns the dotted-operation part of s, stripping any
// colon-delimited target. For a scope with no target, Operation returns s
// unchanged. Exported for callers that pin a request to exactly one
// operation before ever consulting Covers — e.g. a capability broker binary
// that implements a single operation class (git.sign) and must refuse every
// other one, including a syntactically-covered descendant like
// "git.sign.extra": authorizing purely on Covers would let a grant row
// seeded with an unrelated operation's scope exercise an operation its
// human never named it for.
func (s Scope) Operation() Scope {
	op, _, _ := split(s)
	return Scope(op)
}

// Validate checks that s is well-formed. The operation part (everything
// before the first colon, or the whole string if there is no colon) must be
// non-empty, dot-delimited, lowercase alphanumeric/underscore segments —
// exactly the pre-existing rule, unchanged. If a colon is present, the
// target (everything after the first colon) must additionally be non-empty,
// match the conservative charset in targetPattern, and contain no ".." path
// segment (see hasTraversalSegment). The whole string, including any
// target, is bounded by MaxLength. Validate does not check segments or
// targets against any known taxonomy — there isn't a fixed one (yet).
func Validate(s Scope) error {
	if s == "" {
		return fmt.Errorf("scope: empty scope is not valid")
	}
	if len(s) > MaxLength {
		// Report the length, not the value: s is caller-controlled and can be
		// pathologically large, and %q would spend O(n) quoting/escaping it right
		// where the bound exists to avoid unbounded work on bad input.
		return fmt.Errorf("scope: exceeds max length %d (got %d characters)", MaxLength, len(s))
	}
	op, target, hasTarget := split(s)
	segments := strings.Split(op, ".")
	for _, seg := range segments {
		if !segmentPattern.MatchString(seg) {
			return fmt.Errorf("scope: invalid segment %q in %q (segments must be lowercase alphanumeric/underscore)", seg, s)
		}
	}
	if hasTarget {
		if target == "" {
			return fmt.Errorf("scope: empty target in %q (omit the colon for an untargeted scope)", s)
		}
		if !targetPattern.MatchString(target) {
			return fmt.Errorf("scope: invalid target %q in %q (targets must be letters/digits/./-/_ or /)", target, s)
		}
		if hasTraversalSegment(target) {
			return fmt.Errorf("scope: target %q in %q contains a %q path segment (directory traversal is not a valid target)", target, s, "..")
		}
	}
	return nil
}

// ValidateCapability checks that s is well-formed (via Validate) AND, in
// addition, that s carries a target. This is the require-target rule
// decided 2026-08-09 (docs/capability-broker.md decision log, "Capability
// scope Covers is fail-closed on target; untargeted capability scopes are
// rejected at grant creation"): Covers is fail-closed on target presence —
// an untargeted grant does not cover a targeted request, and a targeted
// grant does not cover an untargeted one — so an untargeted *capability*
// scope would be a grant that structurally can never authorize the
// targeted request a real capability operation (git.sign:<repo>, and every
// operation class named in the design doc) actually makes. Rather than
// pick a meaning for that dead-or-ambiguous state after the fact (fail
// open and let it mean "any target," which is exactly the over-scoped
// grant this workstream exists to prevent — see the decision log entry),
// this function makes the state unrepresentable at the one place a
// capability grant's scopes are accepted: one chokepoint per property.
//
// Validate itself does NOT enforce this: Validate is also the grammar
// check for memory scopes, which legitimately have no target (and must
// keep behaving exactly as they do today — see TestScope_Covers and
// TestValidate). The require-target rule is specific to capability-kind
// scopes, which only the caller can identify — this package has no
// "kind" of its own — so every caller that accepts or loads a
// capability-kind grant's scopes must call ValidateCapability instead of
// (or in addition to) Validate. That includes the future capability-grant
// creation surface (currently gated, issue #96) and every surface that
// exists today and persists or reads back a capability-kind grant's
// scopes — a grant row inserted straight into the database (a fixture, or
// an operator's psql) with a bare untargeted scope must be refused loudly
// wherever it is next read, not silently kept as a grant that can never
// cover anything.
func ValidateCapability(s Scope) error {
	if err := Validate(s); err != nil {
		return err
	}
	if _, _, hasTarget := split(s); !hasTarget {
		return fmt.Errorf("scope: capability scope %q must specify a target (a bare operation with no %q-delimited target is not a valid capability scope, decided 2026-08-09 — see docs/capability-broker.md)", s, ":")
	}
	return nil
}

// opCovers is the pre-existing (unchanged) ancestor-match rule, applied to
// the operation part of a scope: either an exact match, or g is an ancestor
// of r in the dotted hierarchy. Granting "projects.spritz" authorizes
// "projects.spritz.read" and "projects.spritz.write", but not
// "projects.spritzy" (segment-boundary match, not a raw string prefix).
func opCovers(g, r string) bool {
	if g == r {
		return true
	}
	return strings.HasPrefix(r, g+".")
}

// Covers reports whether the granted scope g authorizes the requested scope
// r. The operation part uses the ancestor-match rule above, unchanged. The
// target part is fail-closed and exact-match-only, decided 2026-08-09
// (docs/capability-broker.md): whether g has a target must match whether r
// has a target — an untargeted grant does NOT cover a targeted request (no
// silent all-targets grant), and symmetrically a targeted grant does not
// cover an untargeted request (there is no target on the request to compare
// against "the identical target"). When both are targeted, the targets must
// be byte-for-byte identical; no prefix, glob, or case-insensitive matching.
// When neither has a target — i.e. both are memory scopes — this reduces
// exactly to the pre-existing opCovers check with no target logic in the
// path at all, which is what keeps memory-scope behavior bit-for-bit
// unaffected by this function's target-awareness.
func (g Scope) Covers(r Scope) bool {
	gOp, gTarget, gHasTarget := split(g)
	rOp, rTarget, rHasTarget := split(r)
	if gHasTarget != rHasTarget {
		return false
	}
	if gHasTarget && gTarget != rTarget {
		return false
	}
	return opCovers(gOp, rOp)
}

// AnyCovers reports whether any scope in granted covers r.
func AnyCovers(granted []Scope, r Scope) bool {
	for _, g := range granted {
		if g.Covers(r) {
			return true
		}
	}
	return false
}

// Missing returns the subset of requested not covered by any scope in granted,
// in order of first appearance with duplicates dropped. This is the payload for
// the "insufficient scope" MCP response: it tells the caller exactly which
// additional scopes a human would need to grant.
func Missing(requested, granted []Scope) []Scope {
	seen := make(map[Scope]bool, len(requested))
	var missing []Scope
	for _, r := range requested {
		if seen[r] {
			continue
		}
		seen[r] = true
		if !AnyCovers(granted, r) {
			missing = append(missing, r)
		}
	}
	return missing
}

// Satisfied reports whether every scope in requested is covered by granted. A fact
// tagged with multiple scopes (e.g. a wedding-planning fact touching identity,
// relationships, finances, and schedule) requires all of them to be covered —
// grants evaluate as an intersection against a fact's scope tags, not a match
// against any single tag.
func Satisfied(requested, granted []Scope) bool {
	return len(Missing(requested, granted)) == 0
}

// Dedupe returns scopes with exact duplicates removed, preserving first-appearance
// order. Every caller that persists a scope list into a (fact_id, scope) or
// (grant_id, scope) primary key needs this: an un-deduped list reaches the DB as a
// constraint violation instead of a clean validation error. Callers that want to
// reject duplicates outright (rather than silently collapsing them) can compare
// len(Dedupe(s)) against len(s).
func Dedupe(scopes []Scope) []Scope {
	seen := make(map[Scope]bool, len(scopes))
	deduped := make([]Scope, 0, len(scopes))
	for _, s := range scopes {
		if seen[s] {
			continue
		}
		seen[s] = true
		deduped = append(deduped, s)
	}
	return deduped
}
