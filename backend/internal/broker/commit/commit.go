// Package commit parses and validates the exact byte format of a git commit
// object — the thing brokerd's sign operation is allowed to produce a
// signature over, and nothing else (capability-broker.md, "The broker must
// not blind-sign"). A generic ssh-agent SIGN_REQUEST will sign arbitrary
// bytes, including an SSH host-authentication challenge; parsing the payload
// as a commit object and refusing anything that doesn't fit is what makes
// "a signing grant does not confer host access" (success criterion 7) true
// by construction rather than by policy.
//
// This package only parses and validates structure and extracts the
// committer identity. It has no opinion on grants, scopes, or policy — that
// judgment belongs to the broker package, which is what decides whether a
// successfully-parsed Commit's CommitterEmail is the one a given grant
// actually authorizes.
package commit

import (
	"bytes"
	"fmt"
	"regexp"
)

// Commit is the parsed, validated shape of a git commit object's headers.
// Message and Raw retain the original bytes verbatim — Raw is what actually
// gets hashed and signed (sshsig.Sign takes the whole payload, not a
// reserialization of these fields), so a round-trip bug in this package can
// never desync what was validated from what gets signed.
type Commit struct {
	Tree           string
	Parents        []string
	Author         string
	Committer      string
	CommitterEmail string
	Message        []byte
	Raw            []byte
}

// treeOrParentPattern matches a 40-character (SHA-1) or 64-character
// (SHA-256) lowercase hex object id — git supports both repository hash
// algorithms, and this package has no reason to assume one over the other.
var treeOrParentPattern = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)

// identityLinePattern matches an author/committer line's value half (the
// part after the "author "/"committer " key): "Name <email> timestamp tz".
// Deliberately conservative rather than matching every byte git itself
// tolerates in a name — this is the boundary that decides what may be
// signed, and a stricter parser that refuses an unusual-but-legal commit is
// a far smaller problem than a looser one that accepts something ambiguous.
//
// The name half is restricted to [^<>]+ — no angle brackets — specifically
// so a line can contain at most one "<...>" pair. Real git's own ident-line
// parser (ident.c) does not require this: fed a line with two bracket pairs
// ("Real Name <legit@example.com> <attacker@evil.com> 1723190400 +0000"),
// verified empirically against git 2.47.3 (`git show -s --format=%ce` on
// the identical bytes via `git hash-object -w --literally`), it resolves
// the FIRST pair as the identity while still finding the trailing
// timestamp — a fallback-heavy algorithm this package has no reason to
// reproduce. A naive greedy Go regex resolves the opposite: `(.+) <...>`
// backtracks to the RIGHTMOST pair. Rather than chase git's exact fallback
// behaviour (or risk another subtly-wrong reimplementation of it), any line
// with more than one bracket pair is refused outright as ambiguous — an
// agent authorized for one committer_email must never be able to construct
// a payload whose signed identity, as brokerd computes it, differs from
// what every downstream git tool displays.
var identityLinePattern = regexp.MustCompile(`^([^<>]+) <([^<>\s]*)> (\d+) ([+-]\d{4})$`)

// ErrMalformed wraps every structural parse failure, so callers (the
// broker's sign handler) can distinguish "this isn't a commit object at
// all" from an authorization decision without string-matching messages.
type ErrMalformed struct{ Reason string }

func (e *ErrMalformed) Error() string { return "commit: malformed commit object: " + e.Reason }

func malformed(format string, args ...any) error {
	return &ErrMalformed{Reason: fmt.Sprintf(format, args...)}
}

// Parse validates payload as a well-formed, not-yet-signed git commit
// object and extracts its headers. It requires exactly one tree line, zero
// or more parent lines, exactly one author line and one committer line (in
// that relative order — git always writes them this way, and accepting a
// reordered object would mean tolerating something no real git ever
// produces), and refuses a payload that already carries a gpgsig header —
// signing an already-(claimed-)signed commit is never a legitimate request
// this broker should service, and refusing it outright is cheaper and safer
// than trying to reason about what re-signing one would even mean.
//
// Any other extension header (encoding, mergetag, etc.) is tolerated and
// ignored: git's commit format is deliberately extensible, and rejecting an
// otherwise-well-formed commit over a header this package doesn't recognise
// would make brokerd reject legitimate commits from any git version or
// extension newer than this parser.
//
// "gpgsig" is not the only real git signature header: gpgsig-sha256 is a
// second, independent signature git writes for SHA-256 commit objects (the
// hash-function-transition mirror signature). A payload carrying only a
// gpgsig-sha256 header — and no plain gpgsig header — already claims to be
// signed exactly as much as one carrying gpgsig, so it is refused for the
// same reason.
func Parse(payload []byte) (*Commit, error) {
	headerBlock, message, ok := bytes.Cut(payload, []byte("\n\n"))
	if !ok {
		return nil, malformed("no blank line separating headers from the commit message")
	}

	// splitHeaderLines always returns at least one element for any input
	// (including empty) — bytes.Split's documented behavior for a slice
	// that doesn't contain the separator is to return the whole input as a
	// single-element result, never an empty result. An empty headerBlock
	// therefore produces one empty-string line, which the "tree" check
	// immediately below rejects on its own; there is no reachable input
	// that makes lines itself empty, so no separate check for that belongs
	// here — one was tried and removed for being untestable dead code.
	lines := splitHeaderLines(headerBlock)

	c := &Commit{Message: message, Raw: payload}

	idx := 0
	if idx >= len(lines) || !hasKey(lines[idx], "tree") {
		return nil, malformed("first header line must be \"tree <id>\", got %q", truncate(safeLine(lines, idx)))
	}
	tree := value(lines[idx], "tree")
	if !treeOrParentPattern.MatchString(tree) {
		return nil, malformed("tree %q is not a valid 40- or 64-character hex object id", tree)
	}
	c.Tree = tree
	idx++

	for idx < len(lines) && hasKey(lines[idx], "parent") {
		parent := value(lines[idx], "parent")
		if !treeOrParentPattern.MatchString(parent) {
			return nil, malformed("parent %q is not a valid 40- or 64-character hex object id", parent)
		}
		c.Parents = append(c.Parents, parent)
		idx++
	}

	if idx >= len(lines) || !hasKey(lines[idx], "author") {
		return nil, malformed("expected \"author\" header after tree/parents, got %q", truncate(safeLine(lines, idx)))
	}
	author := value(lines[idx], "author")
	if !identityLinePattern.MatchString(author) {
		return nil, malformed("author line %q is not \"Name <email> timestamp tz\"", author)
	}
	c.Author = author
	idx++

	if idx >= len(lines) || !hasKey(lines[idx], "committer") {
		return nil, malformed("expected \"committer\" header after author, got %q", truncate(safeLine(lines, idx)))
	}
	committer := value(lines[idx], "committer")
	m := identityLinePattern.FindStringSubmatch(committer)
	if m == nil {
		return nil, malformed("committer line %q is not \"Name <email> timestamp tz\"", committer)
	}
	c.Committer = committer
	c.CommitterEmail = m[2]
	idx++

	// Every remaining header (if any) is tolerated but must not be gpgsig —
	// see this function's doc comment.
	for ; idx < len(lines); idx++ {
		if hasKey(lines[idx], "gpgsig") || hasKey(lines[idx], "gpgsig-sha256") {
			return nil, malformed("payload already carries a gpgsig/gpgsig-sha256 header; refusing to sign a commit that claims to already be signed")
		}
	}

	if c.CommitterEmail == "" {
		return nil, malformed("committer email is empty")
	}

	return c, nil
}

// splitHeaderLines splits the header block into logical header lines,
// joining continuation lines (git prefixes a multi-line header value's
// second and later lines with a single space) back onto the header they
// continue — so a multi-line gpgsig or mergetag header is still recognised
// as one logical line by hasKey/value, rather than its continuation lines
// being misread as headers of their own.
func splitHeaderLines(block []byte) []string {
	raw := bytes.Split(block, []byte("\n"))
	var lines []string
	for _, l := range raw {
		if len(l) > 0 && l[0] == ' ' && len(lines) > 0 {
			lines[len(lines)-1] += "\n" + string(l[1:])
			continue
		}
		lines = append(lines, string(l))
	}
	return lines
}

func hasKey(line, key string) bool {
	return line == key || (len(line) > len(key) && line[:len(key)+1] == key+" ")
}

func value(line, key string) string {
	if line == key {
		return ""
	}
	return line[len(key)+1:]
}

func safeLine(lines []string, idx int) string {
	if idx < 0 || idx >= len(lines) {
		return "<end of headers>"
	}
	return lines[idx]
}

func truncate(s string) string {
	const max = 80
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
