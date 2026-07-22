package scope

import (
	"reflect"
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
