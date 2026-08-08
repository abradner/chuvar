package scope

import (
	"reflect"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		scope   Scope
		wantErr bool
	}{
		{"simple", "identity", false},
		{"dotted", "projects.spritz.read", false},
		{"underscore segment", "identity.date_of_birth", false},
		{"empty", "", true},
		{"empty segment", "projects..read", true},
		{"trailing dot", "projects.spritz.", true},
		{"leading dot", ".projects", true},
		{"uppercase", "Projects.Spritz", true},
		{"whitespace", "projects spritz", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.scope)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%q) error = %v, wantErr %v", tt.scope, err, tt.wantErr)
			}
		})
	}
}

// TestValidate_Target covers the colon-delimited target grammar decided
// 2026-08-09 (docs/capability-broker.md), including the hostile inputs the
// decision's fail-closed framing calls for: multiple colons, an empty
// target, a colon in the first position (empty operation), and max length.
func TestValidate_Target(t *testing.T) {
	tests := []struct {
		name    string
		scope   Scope
		wantErr bool
	}{
		{"valid target from decision doc example", "git.sign:github.com/abradner/chuvar", false},
		{"valid target, single segment op", "fs.write:some/relative/path", false},
		{"target allows mixed case (repo/host names)", "git.sign:GitHub.com/Org/Repo", false},
		{"target allows underscore and hyphen", "git.sign:my-host_1.example.com", false},
		{"empty target after colon", "git.sign:", true},
		{"colon in first position, empty operation", ":github.com/abradner/chuvar", true},
		{"multiple colons: extra colon lands in target, fails charset", "git.sign:host:1234", true},
		{"target with glob star rejected", "fs.write:some/path/*", true},
		{"target with glob question-mark rejected", "fs.write:some/path?", true},
		{"target with tilde rejected", "fs.write:~/code/worktrees", true},
		{"target with space rejected", "git.sign:my host", true},
		{"target with shell metacharacter rejected", "git.sign:host;rm -rf", true},
		{"target with at-sign (scp-style) rejected", "git.sign:user@host", true},
		{"invalid operation segment with valid target still rejected", "Git.Sign:github.com/a/b", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.scope)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%q) error = %v, wantErr %v", tt.scope, err, tt.wantErr)
			}
		})
	}
}

func TestValidate_MaxLength(t *testing.T) {
	tooLong := Scope("a" + strings.Repeat(".b", (MaxLength/2)+1))
	if err := Validate(tooLong); err == nil {
		t.Errorf("Validate() on a %d-char scope: want error, got nil", len(tooLong))
	}

	atLimit := Scope(strings.Repeat("a", MaxLength))
	if err := Validate(atLimit); err != nil {
		t.Errorf("Validate() on a %d-char scope (at MaxLength): want nil, got %v", len(atLimit), err)
	}
}

// TestValidate_TargetMaxLength proves the target shares the single overall
// MaxLength bound with the operation (no separate, easily-forgotten target
// bound) — both at the exact limit (valid) and one character past it
// (invalid), for a scope that includes a colon-delimited target.
func TestValidate_TargetMaxLength(t *testing.T) {
	// "a" (1 char) + ":" (1 char) + target sized to land exactly on MaxLength.
	targetAtLimit := strings.Repeat("x", MaxLength-2)
	atLimit := Scope("a:" + targetAtLimit)
	if len(atLimit) != MaxLength {
		t.Fatalf("test setup: atLimit is %d chars, want exactly %d", len(atLimit), MaxLength)
	}
	if err := Validate(atLimit); err != nil {
		t.Errorf("Validate() on a %d-char targeted scope (at MaxLength): want nil, got %v", len(atLimit), err)
	}

	tooLong := Scope("a:" + targetAtLimit + "x")
	if err := Validate(tooLong); err == nil {
		t.Errorf("Validate() on a %d-char targeted scope: want error, got nil", len(tooLong))
	}
}

func TestAnyCovers(t *testing.T) {
	granted := []Scope{"identity.basic", "projects.spritz"}

	tests := []struct {
		name string
		r    Scope
		want bool
	}{
		{"exact match on first granted scope", "identity.basic", true},
		{"descendant of second granted scope", "projects.spritz.read", true},
		{"not covered by any granted scope", "finances.budget", false},
		{"segment-boundary near-miss", "projects.spritzy", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AnyCovers(granted, tt.r); got != tt.want {
				t.Errorf("AnyCovers(%v, %q) = %v, want %v", granted, tt.r, got, tt.want)
			}
		})
	}

	if AnyCovers(nil, "identity.basic") {
		t.Error("AnyCovers(nil, ...) = true, want false")
	}
}

// TestScope_Covers is the regression guard proving memory-scope (no colon)
// behavior is bit-for-bit unaffected by adding target support: every case
// here predates targets and is unchanged, byte-for-byte, from before
// issue #93.
func TestScope_Covers(t *testing.T) {
	tests := []struct {
		granted Scope
		request Scope
		want    bool
	}{
		{"projects.spritz", "projects.spritz", true},
		{"projects.spritz", "projects.spritz.read", true},
		{"projects.spritz", "projects.spritz.read.detail", true},
		{"projects", "projects.spritz.read", true},
		{"projects.spritz", "projects.spritzy", false}, // segment-boundary, not raw prefix
		{"projects.spritz.read", "projects.spritz", false},
		{"projects.spritz", "projects.other", false},
		{"identity.basic", "identity", false},
	}
	for _, tt := range tests {
		t.Run(string(tt.granted)+"_covers_"+string(tt.request), func(t *testing.T) {
			if got := tt.granted.Covers(tt.request); got != tt.want {
				t.Errorf("%q.Covers(%q) = %v, want %v", tt.granted, tt.request, got, tt.want)
			}
		})
	}
}

// TestScope_Covers_Target exercises the colon-delimited target coverage
// semantics decided 2026-08-09 (docs/capability-broker.md): fail-closed,
// exact-target-match-only, with dotted ancestor rules still applying to the
// operation part.
func TestScope_Covers_Target(t *testing.T) {
	tests := []struct {
		name    string
		granted Scope
		request Scope
		want    bool
	}{
		{"exact op, exact target", "git.sign:host1", "git.sign:host1", true},
		{"ancestor op, exact target", "git:host1", "git.sign:host1", true},
		{"same op, different target", "git.sign:host1", "git.sign:host2", false},
		{
			name:    "untargeted grant does NOT cover targeted request (fail closed, no silent all-targets)",
			granted: "git.sign", request: "git.sign:host1", want: false,
		},
		{
			name:    "targeted grant does NOT cover untargeted request (no target to match)",
			granted: "git.sign:host1", request: "git.sign", want: false,
		},
		{"op segment-boundary near-miss still enforced with a target present", "git.sign:host1", "git.signing:host1", false},
		{"different op entirely, same target string", "fs.write:host1", "git.sign:host1", false},
		{"ancestor op covers deeper op, exact target", "git", "git.sign.gpg:host1", false}, // request is targeted, grant is not
		{"target case-sensitive, no folding", "git.sign:Host1", "git.sign:host1", false},
		{
			name: "multi-colon target: Covers splits on first colon only and compares the rest verbatim " +
				"(Covers does not validate charset — this string would fail Validate)",
			granted: "git.sign:host:1234", request: "git.sign:host:1234", want: true,
		},
		{"multi-colon target: differing remainder does not match", "git.sign:host:1234", "git.sign:host:5678", false},
		{"both untargeted, ancestor op still covers (regression via the unified path)", "git.sign", "git.sign.gpg", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.granted.Covers(tt.request); got != tt.want {
				t.Errorf("%q.Covers(%q) = %v, want %v", tt.granted, tt.request, got, tt.want)
			}
		})
	}
}

func TestMissing(t *testing.T) {
	tests := []struct {
		name      string
		requested []Scope
		granted   []Scope
		want      []Scope
	}{
		{
			name:      "fully covered by exact matches",
			requested: []Scope{"identity.basic", "projects.spritz.read"},
			granted:   []Scope{"identity.basic", "projects.spritz.read"},
			want:      nil,
		},
		{
			name:      "fully covered by ancestor grants",
			requested: []Scope{"projects.spritz.read", "projects.spritz.write"},
			granted:   []Scope{"projects.spritz"},
			want:      nil,
		},
		{
			name:      "partially covered - intersection semantics",
			requested: []Scope{"identity.basic", "finances.read"},
			granted:   []Scope{"identity.basic"},
			want:      []Scope{"finances.read"},
		},
		{
			name:      "nothing granted",
			requested: []Scope{"identity.basic"},
			granted:   nil,
			want:      []Scope{"identity.basic"},
		},
		{
			name:      "duplicates in requested collapse",
			requested: []Scope{"finances.read", "finances.read"},
			granted:   nil,
			want:      []Scope{"finances.read"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Missing(tt.requested, tt.granted)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Missing(%v, %v) = %v, want %v", tt.requested, tt.granted, got, tt.want)
			}
		})
	}
}

// TestMissing_Target proves the targeted fail-closed rule flows through
// Missing/AnyCovers, not just Covers in isolation — this is the path
// read_with_scope_check.go actually calls.
func TestMissing_Target(t *testing.T) {
	tests := []struct {
		name      string
		requested []Scope
		granted   []Scope
		want      []Scope
	}{
		{
			name:      "targeted request covered by identical targeted grant",
			requested: []Scope{"git.sign:host1"},
			granted:   []Scope{"git.sign:host1"},
			want:      nil,
		},
		{
			name:      "targeted request NOT covered by untargeted grant of same op",
			requested: []Scope{"git.sign:host1"},
			granted:   []Scope{"git.sign"},
			want:      []Scope{"git.sign:host1"},
		},
		{
			name:      "targeted request NOT covered by grant on a different target",
			requested: []Scope{"git.sign:host1"},
			granted:   []Scope{"git.sign:host2"},
			want:      []Scope{"git.sign:host1"},
		},
		{
			name:      "mixed targeted/untargeted requests evaluated independently",
			requested: []Scope{"git.sign:host1", "identity.basic"},
			granted:   []Scope{"git.sign:host1", "identity.basic"},
			want:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Missing(tt.requested, tt.granted)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Missing(%v, %v) = %v, want %v", tt.requested, tt.granted, got, tt.want)
			}
		})
	}
}

func TestSatisfied(t *testing.T) {
	// A fact touching multiple scopes (e.g. wedding planning: identity, relationships,
	// finances, schedule) must have every one of those scopes covered — a grant on
	// only some of them must not satisfy the read.
	requested := []Scope{"identity.basic", "relationships.partner", "finances.budget", "schedule.events"}

	if Satisfied(requested, []Scope{"identity.basic", "relationships.partner", "finances.budget"}) {
		t.Error("Satisfied() = true with one requested scope ungranted, want false")
	}
	if !Satisfied(requested, []Scope{"identity", "relationships", "finances", "schedule"}) {
		t.Error("Satisfied() = false with all requested scopes covered by ancestor grants, want true")
	}
}

// TestSatisfied_Target proves the intersection semantics above also hold
// when some requested scopes carry targets: a capability request touching
// two distinct targets under the same operation needs a grant per target,
// not one grant treated as covering both.
func TestSatisfied_Target(t *testing.T) {
	requested := []Scope{"git.sign:host1", "git.sign:host2"}

	if Satisfied(requested, []Scope{"git.sign:host1"}) {
		t.Error("Satisfied() = true with only one of two targets granted, want false")
	}
	if !Satisfied(requested, []Scope{"git.sign:host1", "git.sign:host2"}) {
		t.Error("Satisfied() = false with both targets granted, want true")
	}
	if Satisfied(requested, []Scope{"git.sign"}) {
		t.Error("Satisfied() = true with only an untargeted grant present, want false (fail closed)")
	}
}

func TestDedupe(t *testing.T) {
	tests := []struct {
		name   string
		scopes []Scope
		want   []Scope
	}{
		{"no duplicates", []Scope{"a", "b", "c"}, []Scope{"a", "b", "c"}},
		{"adjacent duplicate", []Scope{"a", "a", "b"}, []Scope{"a", "b"}},
		{"non-adjacent duplicate preserves first position", []Scope{"a", "b", "a"}, []Scope{"a", "b"}},
		{"empty", nil, []Scope{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Dedupe(tt.scopes)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Dedupe(%v) = %v, want %v", tt.scopes, got, tt.want)
			}
		})
	}
}
