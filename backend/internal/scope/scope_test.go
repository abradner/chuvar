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
		{"targeted capability scope", "git.sign:github.com/abradner/chuvar", false},
		{"target with dots, slashes, hyphens", "git.sign:github.com/abradner/chuvar-repo.git", false},
		{"empty target after colon", "git.sign:", true},
		{"target with whitespace", "git.sign:not a target", true},
		{"target with colon", "git.sign:host:port/path", true},
		{"invalid operation with target present", "Git.Sign:github.com/x", true},
		{"target of a lone dot-dot", "git.sign:..", true},
		{"target with a dot-dot path segment", "git.sign:github.com/../other-org/repo", true},
		{"target with a lone-dot path segment", "git.sign:github.com/./repo", true},
		{"target with a trailing dot-dot segment", "git.sign:github.com/abradner/..", true},
		{"dots inside a target name are fine", "git.sign:github.com/abradner/chuvar..mirror", false},
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

func TestScope_Covers_Target(t *testing.T) {
	tests := []struct {
		name    string
		granted Scope
		request Scope
		want    bool
	}{
		{
			"exact target match",
			"git.sign:github.com/abradner/chuvar", "git.sign:github.com/abradner/chuvar", true,
		},
		{
			"different target, same operation, denied",
			"git.sign:github.com/abradner/chuvar", "git.sign:github.com/other/repo", false,
		},
		{
			"targeted grant does not cover an untargeted request",
			"git.sign:github.com/abradner/chuvar", "git.sign", false,
		},
		{
			"untargeted grant covers any target",
			"git.sign", "git.sign:github.com/abradner/chuvar", true,
		},
		{
			"untargeted grant covers an untargeted request",
			"git.sign", "git.sign", true,
		},
		{
			"target exact-match only, no prefix match",
			"git.sign:github.com/abradner", "git.sign:github.com/abradner/chuvar", false,
		},
		{
			"operation hierarchy still applies alongside a target",
			"git:github.com/abradner/chuvar", "git.sign:github.com/abradner/chuvar", true,
		},
		{
			"same target, different operation, denied",
			"git.sign:github.com/abradner/chuvar", "git.push:github.com/abradner/chuvar", false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.granted.Covers(tt.request); got != tt.want {
				t.Errorf("%q.Covers(%q) = %v, want %v", tt.granted, tt.request, got, tt.want)
			}
		})
	}
}

func TestScope_Operation(t *testing.T) {
	tests := []struct {
		s    Scope
		want Scope
	}{
		{"git.sign:github.com/abradner/chuvar", "git.sign"},
		{"git.sign", "git.sign"},
		{"identity.basic", "identity.basic"},
	}
	for _, tt := range tests {
		if got := tt.s.Operation(); got != tt.want {
			t.Errorf("%q.Operation() = %q, want %q", tt.s, got, tt.want)
		}
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
