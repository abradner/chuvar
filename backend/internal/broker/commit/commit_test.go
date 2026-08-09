package commit

import (
	"errors"
	"strings"
	"testing"
)

const validTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
const validParent = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"

func build(lines ...string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n\n" + "commit message\n")
}

func TestParse_ValidRootCommit(t *testing.T) {
	payload := build(
		"tree "+validTree,
		"author Agent <agent@example.com> 1723190400 +0000",
		"committer Agent <agent@example.com> 1723190400 +0000",
	)
	c, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Tree != validTree {
		t.Errorf("Tree = %q, want %q", c.Tree, validTree)
	}
	if len(c.Parents) != 0 {
		t.Errorf("Parents = %v, want none", c.Parents)
	}
	if c.CommitterEmail != "agent@example.com" {
		t.Errorf("CommitterEmail = %q, want agent@example.com", c.CommitterEmail)
	}
	if string(c.Message) != "commit message\n" {
		t.Errorf("Message = %q", c.Message)
	}
	if string(c.Raw) != string(payload) {
		t.Error("Raw does not match the original payload byte-for-byte")
	}
}

func TestParse_OneParent(t *testing.T) {
	payload := build(
		"tree "+validTree,
		"parent "+validParent,
		"author Agent <agent@example.com> 1723190400 +0000",
		"committer Agent <agent@example.com> 1723190400 +0000",
	)
	c, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Parents) != 1 || c.Parents[0] != validParent {
		t.Errorf("Parents = %v, want [%s]", c.Parents, validParent)
	}
}

func TestParse_MergeCommitTwoParents(t *testing.T) {
	secondParent := strings.Repeat("1", 40)
	payload := build(
		"tree "+validTree,
		"parent "+validParent,
		"parent "+secondParent,
		"author Agent <agent@example.com> 1723190400 +0000",
		"committer Agent <agent@example.com> 1723190400 +0000",
	)
	c, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Parents) != 2 {
		t.Fatalf("Parents = %v, want 2 entries", c.Parents)
	}
}

func TestParse_Sha256Tree(t *testing.T) {
	tree64 := strings.Repeat("a", 64)
	payload := build(
		"tree "+tree64,
		"author Agent <agent@example.com> 1723190400 +0000",
		"committer Agent <agent@example.com> 1723190400 +0000",
	)
	c, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Tree != tree64 {
		t.Errorf("Tree = %q, want %q", c.Tree, tree64)
	}
}

func TestParse_ToleratesUnknownHeader(t *testing.T) {
	payload := build(
		"tree "+validTree,
		"author Agent <agent@example.com> 1723190400 +0000",
		"committer Agent <agent@example.com> 1723190400 +0000",
		"encoding UTF-8",
	)
	if _, err := Parse(payload); err != nil {
		t.Fatalf("Parse rejected an otherwise-valid commit over an unrecognised header: %v", err)
	}
}

func TestParse_EmptyMessage(t *testing.T) {
	payload := []byte("tree " + validTree + "\n" +
		"author Agent <agent@example.com> 1723190400 +0000\n" +
		"committer Agent <agent@example.com> 1723190400 +0000\n\n")
	c, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Message) != 0 {
		t.Errorf("Message = %q, want empty", c.Message)
	}
}

func TestParse_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{
			"missing tree header entirely",
			build(
				"author Agent <agent@example.com> 1723190400 +0000",
				"committer Agent <agent@example.com> 1723190400 +0000",
			),
		},
		{
			"malformed tree hash (too short)",
			build(
				"tree deadbeef",
				"author Agent <agent@example.com> 1723190400 +0000",
				"committer Agent <agent@example.com> 1723190400 +0000",
			),
		},
		{
			"malformed tree hash (uppercase)",
			build(
				"tree "+strings.ToUpper(validTree),
				"author Agent <agent@example.com> 1723190400 +0000",
				"committer Agent <agent@example.com> 1723190400 +0000",
			),
		},
		{
			"malformed parent hash",
			build(
				"tree "+validTree,
				"parent not-a-hash",
				"author Agent <agent@example.com> 1723190400 +0000",
				"committer Agent <agent@example.com> 1723190400 +0000",
			),
		},
		{
			"missing author header",
			build(
				"tree "+validTree,
				"committer Agent <agent@example.com> 1723190400 +0000",
			),
		},
		{
			"author line missing angle brackets",
			build(
				"tree "+validTree,
				"author Agent agent@example.com 1723190400 +0000",
				"committer Agent <agent@example.com> 1723190400 +0000",
			),
		},
		{
			"missing committer header",
			build(
				"tree "+validTree,
				"author Agent <agent@example.com> 1723190400 +0000",
			),
		},
		{
			// "committer Agent <> ..." matches identityLinePattern (the
			// email capture group permits empty) and reaches Parse's
			// dedicated empty-CommitterEmail check — the one branch that
			// rejects it. Without that branch, this payload would parse
			// with CommitterEmail == "", and a (misprovisioned) grant whose
			// committer_email was also empty would then pass the broker's
			// identity match vacuously.
			"empty committer email",
			build(
				"tree "+validTree,
				"author Agent <agent@example.com> 1723190400 +0000",
				"committer Agent <> 1723190400 +0000",
			),
		},
		{
			"committer line missing angle brackets",
			build(
				"tree "+validTree,
				"author Agent <agent@example.com> 1723190400 +0000",
				"committer Agent agent@example.com 1723190400 +0000",
			),
		},
		{
			"committer line missing timezone",
			build(
				"tree "+validTree,
				"author Agent <agent@example.com> 1723190400 +0000",
				"committer Agent <agent@example.com> 1723190400",
			),
		},
		{
			"gpgsig header present — refuse to co-sign an already-signed commit",
			build(
				"tree "+validTree,
				"author Agent <agent@example.com> 1723190400 +0000",
				"committer Agent <agent@example.com> 1723190400 +0000",
				"gpgsig -----BEGIN SSH SIGNATURE-----\n someb64\n -----END SSH SIGNATURE-----",
			),
		},
		{
			// gpgsig-sha256 is git's real second signature header (used for
			// SHA-256 commit objects / the hash-function transition). A
			// commit carrying only this header, and no plain "gpgsig"
			// header, must be refused for the exact same reason as above —
			// it already claims to be signed.
			"gpgsig-sha256 header present — refuse to co-sign an already-signed commit",
			build(
				"tree "+validTree,
				"author Agent <agent@example.com> 1723190400 +0000",
				"committer Agent <agent@example.com> 1723190400 +0000",
				"gpgsig-sha256 -----BEGIN SSH SIGNATURE-----\n someb64\n -----END SSH SIGNATURE-----",
			),
		},
		{
			// Verified against git 2.47.3: `git show -s --format=%ce` on
			// this exact payload (written via `git hash-object -w
			// --literally`) reports committer email "legit@example.com" —
			// the FIRST bracket pair — not "attacker@evil.com". A regex
			// that greedily matches the rightmost "<...>" pair as the
			// email would extract "attacker@evil.com" instead, letting a
			// grant authorized only for "attacker@evil.com" sign a payload
			// that every downstream git tool displays as authored by a
			// different, ungranted identity. Rather than replicate git's
			// own ident-line fallback parsing (which tolerates the
			// resulting date ambiguity in ways this package has no reason
			// to reproduce), a line with more than one bracket pair is
			// refused outright as ambiguous.
			"committer line has two bracket pairs (spoofed identity)",
			build(
				"tree "+validTree,
				"author Agent <agent@example.com> 1723190400 +0000",
				"committer Real Name <legit@example.com> <attacker@evil.com> 1723190400 +0000",
			),
		},
		{
			"author line has two bracket pairs (same ambiguity, author side)",
			build(
				"tree "+validTree,
				"author Real Name <legit@example.com> <attacker@evil.com> 1723190400 +0000",
				"committer Agent <agent@example.com> 1723190400 +0000",
			),
		},
		{
			"no blank line separating headers from message",
			[]byte("tree " + validTree + "\n" +
				"author Agent <agent@example.com> 1723190400 +0000\n" +
				"committer Agent <agent@example.com> 1723190400 +0000\n" +
				"just one newline, no message separator"),
		},
		{
			"empty payload",
			[]byte(""),
		},
		{
			"headers out of order (committer before author)",
			build(
				"tree "+validTree,
				"committer Agent <agent@example.com> 1723190400 +0000",
				"author Agent <agent@example.com> 1723190400 +0000",
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.payload)
			if err == nil {
				t.Fatalf("Parse(%q): want error, got nil", tt.payload)
			}
			var malformedErr *ErrMalformed
			if !errors.As(err, &malformedErr) {
				t.Errorf("Parse error is not an *ErrMalformed: %T %v", err, err)
			}
		})
	}
}

// TestParse_HostAuthChallengeIsRejected is success criterion 7's other half,
// exercised at this package's level: an SSH host-authentication challenge
// (an arbitrary blob with no commit structure at all) must not parse as a
// commit, so it can never reach sshsig.Sign under the "git" namespace.
func TestParse_HostAuthChallengeIsRejected(t *testing.T) {
	// A representative not-a-commit blob — the shape of what an SSH
	// SIGN_REQUEST for host authentication would hand a generic ssh-agent:
	// opaque bytes with no relation to git's header grammar at all.
	challenge := []byte{0x00, 0x01, 0x02, 0x03, 'S', 'S', 'H', '2', 0x00, 0x00}
	if _, err := Parse(challenge); err == nil {
		t.Fatal("Parse accepted an arbitrary non-commit blob")
	}
}
