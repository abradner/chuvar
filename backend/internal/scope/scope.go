// Package scope implements the hierarchical, dotted scope model that grants and
// facts are checked against — e.g. "identity.basic", "projects.spritz.read". The
// taxonomy itself (which scopes exist, how granular they should be) is an open
// product question (AGENTS.md §3.4); this package only encodes the matching rules,
// not any specific vocabulary.
package scope

import (
	"fmt"
	"regexp"
	"strings"
)

// Scope is a dot-delimited hierarchical access scope, with an optional
// colon-delimited target: `<dotted-operation>[:<target>]` — e.g.
// "git.sign:github.com/abradner/chuvar" (capability-broker.md, "Scope
// grammar: dotted operation, optional colon-delimited target", 2026-08-09).
// Memory scopes never carry a target and are untouched by this addition.
type Scope string

var segmentPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// targetPattern is deliberately looser than segmentPattern: a target names
// something in another system's own namespace (a repo path, a host), not a
// chuvar scope segment, so it needs to hold '/' and '.' at minimum for a
// value like "github.com/abradner/chuvar". Exact-match targets only, per the
// decision — this pattern exists to bound what can be stored and compared,
// not to define a glob/path-pattern grammar (there isn't one yet, and the
// decision is explicit that there shouldn't be until a real need names one).
var targetPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// MaxLength bounds how long a single scope string can be. No real taxonomy needs
// anywhere near this many characters — it exists to stop a pathological input from
// becoming a cheap CPU-amplification lever downstream, where every granted scope
// gets turned into a LIKE pattern evaluated against every fact_scopes row on every
// read (the store package, added later in this series).
const MaxLength = 256

// split divides s into its operation and target parts at the first ':'. The
// second return value is false when s carries no target at all (a bare
// memory-style scope, or a capability scope with no target restriction) —
// distinct from a target that happens to be the empty string, which split
// itself never produces since Validate rejects a trailing bare ':'.
func (s Scope) split() (op string, target string, hasTarget bool) {
	str := string(s)
	idx := strings.IndexByte(str, ':')
	if idx < 0 {
		return str, "", false
	}
	return str[:idx], str[idx+1:], true
}

// Operation returns the dotted-operation part of s, stripping any
// colon-delimited target. For a scope with no target it is s unchanged.
// Exported for callers that implement exactly one operation class and must
// refuse every other (brokerd pins requests to "git.sign" with this —
// authorizing purely on Covers would let a grant row seeded with an
// unrelated operation's scope exercise an operation its human never named).
func (s Scope) Operation() Scope {
	op, _, _ := s.split()
	return Scope(op)
}

// Validate checks that s is well-formed: non-empty, bounded length, a
// dot-delimited lowercase alphanumeric/underscore operation, with an optional
// ':'-delimited target. It does not check the operation segments or the
// target against any known taxonomy — there isn't a fixed one (yet), for
// either half.
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
	op, target, hasTarget := s.split()
	if hasTarget && !targetPattern.MatchString(target) {
		return fmt.Errorf("scope: invalid target %q in %q (must be non-empty and match %s)", target, s, targetPattern)
	}
	if hasTarget {
		// Reject path-traversal-shaped '/'-segments ("." and "..") in a
		// target outright. Inert today — Covers matches targets by exact
		// string equality only (the 2026-08-09 decision: no globs, no path
		// patterns) — but the same colon-delimited grammar is the one a
		// future capability class with path-shaped targets (the design doc's
		// own fs.write example) would layer prefix/path semantics onto, and
		// a stored target that aliases another path under such semantics
		// must never have been storable in the first place. Closing it at
		// validation time costs nothing and removes a foot-gun a later
		// operation class would otherwise inherit silently.
		for _, seg := range strings.Split(target, "/") {
			if seg == "." || seg == ".." {
				return fmt.Errorf("scope: invalid target %q in %q (path-traversal segments %q are not allowed)", target, s, seg)
			}
		}
	}
	segments := strings.Split(op, ".")
	for _, seg := range segments {
		if !segmentPattern.MatchString(seg) {
			return fmt.Errorf("scope: invalid segment %q in %q (segments must be lowercase alphanumeric/underscore)", seg, s)
		}
	}
	return nil
}

// Covers reports whether the granted scope g authorizes the requested scope r.
// The operation half keeps its original hierarchical semantics unchanged:
// either an exact match, or g's operation is an ancestor of r's in the dotted
// hierarchy (granting "projects.spritz" authorizes "projects.spritz.read",
// not "projects.spritzy" — segment-boundary match, not a raw string prefix).
//
// The target half is new: a grant with no target (hasTarget false — every
// existing memory scope, plus an operation-wide capability grant) covers a
// request regardless of that request's target, same as before this scope
// gained targets at all. A grant that does specify a target only covers a
// request for that exact target — never a request with no target specified,
// and never a different one. Exact-match only, per the 2026-08-09 decision:
// no prefix/glob matching on targets.
func (g Scope) Covers(r Scope) bool {
	gOp, gTarget, gHasTarget := g.split()
	rOp, rTarget, rHasTarget := r.split()
	if !opCovers(gOp, rOp) {
		return false
	}
	if !gHasTarget {
		return true
	}
	return rHasTarget && gTarget == rTarget
}

// opCovers is Covers' pre-target-grammar logic, applied to the operation half
// of each scope only.
func opCovers(g, r string) bool {
	if g == r {
		return true
	}
	return strings.HasPrefix(r, g+".")
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
