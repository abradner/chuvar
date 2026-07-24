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

// Scope is a dot-delimited hierarchical access scope.
type Scope string

var segmentPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// MaxLength bounds how long a single scope string can be. No real taxonomy needs
// anywhere near this many characters — it exists to stop a pathological input from
// becoming a cheap CPU-amplification lever downstream, where every granted scope
// gets turned into a LIKE pattern evaluated against every fact_scopes row on every
// read (the store package, added later in this series).
const MaxLength = 256

// Validate checks that s is well-formed: non-empty, bounded length, dot-delimited,
// lowercase alphanumeric/underscore segments. It does not check the segments
// against any known taxonomy — there isn't a fixed one (yet).
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
	segments := strings.Split(string(s), ".")
	for _, seg := range segments {
		if !segmentPattern.MatchString(seg) {
			return fmt.Errorf("scope: invalid segment %q in %q (segments must be lowercase alphanumeric/underscore)", seg, s)
		}
	}
	return nil
}

// Covers reports whether the granted scope g authorizes the requested scope r —
// either an exact match, or g is an ancestor of r in the dotted hierarchy. Granting
// "projects.spritz" authorizes "projects.spritz.read" and "projects.spritz.write",
// but not "projects.spritzy" (segment-boundary match, not a raw string prefix).
func (g Scope) Covers(r Scope) bool {
	if g == r {
		return true
	}
	return strings.HasPrefix(string(r), string(g)+".")
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
