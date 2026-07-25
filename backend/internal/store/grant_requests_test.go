package store

import (
	"context"
	"testing"
)

func TestGrantRequests_RequestApproveCreatesRealGrant(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	ttl := 3600
	req, err := s.RequestGrant(ctx, "agent-a", []string{"identity.basic"}, "facts", &ttl, "need this to answer a question")
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	if req.Status != GrantRequestPending {
		t.Fatalf("Status = %q, want %q", req.Status, GrantRequestPending)
	}

	// Before approval, no grant exists yet — RequestGrant must never write to
	// `grants` directly, same invariant as ProposeDiff/facts.
	granted, err := s.GrantedScopes(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopes() error = %v", err)
	}
	if len(granted) != 0 {
		t.Fatalf("GrantedScopes() before approval = %v, want empty", granted)
	}

	grant, err := s.ApproveGrantRequest(ctx, req.ID, "human-reviewer")
	if err != nil {
		t.Fatalf("ApproveGrantRequest() error = %v", err)
	}
	if grant.ExpiresAt == nil {
		t.Error("approved grant should carry the requested TTL as an expiry")
	}

	granted, err = s.GrantedScopes(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopes() error = %v", err)
	}
	if len(granted) != 1 || granted[0] != "identity.basic" {
		t.Fatalf("GrantedScopes() after approval = %v, want [identity.basic]", granted)
	}

	got, err := s.GetGrantRequest(ctx, req.ID)
	if err != nil {
		t.Fatalf("GetGrantRequest() error = %v", err)
	}
	if got.Status != GrantRequestApproved {
		t.Errorf("Status after approval = %q, want %q", got.Status, GrantRequestApproved)
	}
	if got.ResultingGrantID == nil || *got.ResultingGrantID != grant.ID {
		t.Errorf("ResultingGrantID = %v, want %q", got.ResultingGrantID, grant.ID)
	}

	// Approving again should fail, not silently succeed or create a second grant.
	if _, err := s.ApproveGrantRequest(ctx, req.ID, "human-reviewer"); err == nil {
		t.Fatal("ApproveGrantRequest() on an already-approved request succeeded, want an error")
	}
}

func TestGrantRequests_Deny(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	req, err := s.RequestGrant(ctx, "agent-a", []string{"identity.basic"}, "facts", nil, "")
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}

	if err := s.DenyGrantRequest(ctx, req.ID, "human-reviewer"); err != nil {
		t.Fatalf("DenyGrantRequest() error = %v", err)
	}

	got, err := s.GetGrantRequest(ctx, req.ID)
	if err != nil {
		t.Fatalf("GetGrantRequest() error = %v", err)
	}
	if got.Status != GrantRequestDenied {
		t.Errorf("Status = %q, want %q", got.Status, GrantRequestDenied)
	}
	if got.ResultingGrantID != nil {
		t.Error("a denied request must never have a ResultingGrantID")
	}

	// No grant should have been created.
	granted, err := s.GrantedScopes(ctx, "agent-a")
	if err != nil {
		t.Fatalf("GrantedScopes() error = %v", err)
	}
	if len(granted) != 0 {
		t.Fatalf("GrantedScopes() after denial = %v, want empty", granted)
	}

	// Denying again should fail, not silently succeed.
	if err := s.DenyGrantRequest(ctx, req.ID, "human-reviewer"); err == nil {
		t.Fatal("DenyGrantRequest() on an already-denied request succeeded, want an error")
	}
}

func TestGrantRequests_ListByStatus(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	pending, err := s.RequestGrant(ctx, "agent-a", []string{"identity.basic"}, "facts", nil, "")
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	toApprove, err := s.RequestGrant(ctx, "agent-b", []string{"preferences.food"}, "facts", nil, "")
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	if _, err := s.ApproveGrantRequest(ctx, toApprove.ID, "human-reviewer"); err != nil {
		t.Fatalf("ApproveGrantRequest() error = %v", err)
	}

	pendingList, err := s.ListGrantRequests(ctx, GrantRequestPending)
	if err != nil {
		t.Fatalf("ListGrantRequests(pending) error = %v", err)
	}
	if len(pendingList) != 1 || pendingList[0].ID != pending.ID {
		t.Fatalf("ListGrantRequests(pending) = %+v, want only %q", pendingList, pending.ID)
	}

	approvedList, err := s.ListGrantRequests(ctx, GrantRequestApproved)
	if err != nil {
		t.Fatalf("ListGrantRequests(approved) error = %v", err)
	}
	if len(approvedList) != 1 || approvedList[0].ID != toApprove.ID {
		t.Fatalf("ListGrantRequests(approved) = %+v, want only %q", approvedList, toApprove.ID)
	}
}

func TestRequestGrant_InvalidDepthRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.RequestGrant(ctx, "agent-a", []string{"identity.basic"}, "bogus", nil, ""); err == nil {
		t.Fatal("RequestGrant() with an invalid depth succeeded, want an error")
	}
}

func TestRequestGrant_EmptyScopesRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.RequestGrant(ctx, "agent-a", nil, "facts", nil, ""); err == nil {
		t.Fatal("RequestGrant() with no scopes succeeded, want an error")
	}
}
