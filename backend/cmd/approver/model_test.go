package main

import (
	"testing"

	"github.com/abradner/chuvar/backend/internal/sseclient"
)

func TestModel_ApplyAddThenResolve(t *testing.T) {
	m := newModel()

	m.apply(appEvent{Type: "staged_diff_added", Diff: &sseclient.StagedDiff{ID: "d1", Subject: "agent-a", Content: "x"}})
	if len(m.order) != 1 {
		t.Fatalf("order = %v, want 1 item", m.order)
	}
	if _, ok := m.items["d1"]; !ok {
		t.Fatal("d1 not in items after staged_diff_added")
	}

	m.apply(appEvent{Type: "staged_diff_resolved", Diff: &sseclient.StagedDiff{ID: "d1"}})
	if len(m.order) != 0 {
		t.Fatalf("order after resolve = %v, want empty", m.order)
	}
	if _, ok := m.items["d1"]; ok {
		t.Fatal("d1 still in items after staged_diff_resolved")
	}
}

func TestModel_UpsertDoesNotDuplicate(t *testing.T) {
	m := newModel()
	it := item{kind: kindDiff, diff: &sseclient.StagedDiff{ID: "d1", Content: "first"}}
	m.upsert(it)
	m.upsert(item{kind: kindDiff, diff: &sseclient.StagedDiff{ID: "d1", Content: "updated"}})

	if len(m.order) != 1 {
		t.Fatalf("order = %v, want exactly one entry for a repeated ID", m.order)
	}
	if m.items["d1"].diff.Content != "updated" {
		t.Errorf("content = %q, want the later upsert's value", m.items["d1"].diff.Content)
	}
}

func TestModel_RemoveUnknownIDIsNoop(t *testing.T) {
	m := newModel()
	m.upsert(item{kind: kindDiff, diff: &sseclient.StagedDiff{ID: "d1"}})
	m.remove("does-not-exist")
	if len(m.order) != 1 {
		t.Fatalf("order = %v, want unchanged (1 item)", m.order)
	}
}

func TestModel_MoveSelectionClampsToBounds(t *testing.T) {
	m := newModel()
	m.upsert(item{kind: kindDiff, diff: &sseclient.StagedDiff{ID: "d1"}})
	m.upsert(item{kind: kindDiff, diff: &sseclient.StagedDiff{ID: "d2"}})

	m.moveSelection(-5)
	if m.selected != 0 {
		t.Errorf("selected = %d, want clamped to 0", m.selected)
	}
	m.moveSelection(5)
	if m.selected != 1 {
		t.Errorf("selected = %d, want clamped to 1 (last index)", m.selected)
	}
}

func TestModel_MoveSelectionOnEmptyQueueIsNoop(t *testing.T) {
	m := newModel()
	m.moveSelection(1)
	if m.selected != 0 {
		t.Errorf("selected = %d, want 0", m.selected)
	}
	if _, ok := m.current(); ok {
		t.Error("current() on an empty queue should report ok=false")
	}
}

func TestModel_RemoveSelectedLastItemMovesSelectionBack(t *testing.T) {
	m := newModel()
	m.upsert(item{kind: kindDiff, diff: &sseclient.StagedDiff{ID: "d1"}})
	m.upsert(item{kind: kindDiff, diff: &sseclient.StagedDiff{ID: "d2"}})
	m.selected = 1 // the last item, "d2"

	m.remove("d2")

	if m.selected != 0 {
		t.Errorf("selected = %d, want 0 after removing the last item while it was selected", m.selected)
	}
	it, ok := m.current()
	if !ok || it.id() != "d1" {
		t.Errorf("current() = %+v, ok=%v, want d1", it, ok)
	}
}

func TestModel_MixedDiffsAndRequestsCoexist(t *testing.T) {
	m := newModel()
	m.apply(appEvent{Type: "staged_diff_added", Diff: &sseclient.StagedDiff{ID: "d1"}})
	m.apply(appEvent{Type: "grant_request_added", Req: &sseclient.GrantRequest{ID: "r1"}})

	if len(m.order) != 2 {
		t.Fatalf("order = %v, want both a diff and a request", m.order)
	}
	if m.items["d1"].kind != kindDiff {
		t.Error("d1 should be kindDiff")
	}
	if m.items["r1"].kind != kindRequest {
		t.Error("r1 should be kindRequest")
	}

	// Resolving one must not touch the other.
	m.apply(appEvent{Type: "grant_request_resolved", Req: &sseclient.GrantRequest{ID: "r1"}})
	if len(m.order) != 1 || m.order[0] != "d1" {
		t.Fatalf("order after resolving r1 = %v, want only d1 left", m.order)
	}
}
