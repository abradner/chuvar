package store

import (
	"context"
	"testing"
)

func TestGrantRequests_RequestApproveCreatesRealGrant(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	ttl := 3600
	req, err := s.RequestGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", &ttl, "need this to answer a question")
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

func TestGrantRequests_ApproveCapabilityKindCarriesNoDepth(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	req, err := s.RequestGrant(ctx, "agent-a", []string{"git.sign:github.com/abradner/chuvar"}, "capability", "", nil, "")
	if err != nil {
		t.Fatalf("RequestGrant() with kind=capability error = %v", err)
	}
	if req.Kind != GrantKindCapability || req.Depth != "" {
		t.Fatalf("RequestGrant() = %+v, want kind=capability with empty depth", req)
	}

	grant, err := s.ApproveGrantRequest(ctx, req.ID, "human-reviewer")
	if err != nil {
		t.Fatalf("ApproveGrantRequest() error = %v", err)
	}
	if grant.Kind != GrantKindCapability || grant.Depth != "" {
		t.Fatalf("approved grant = %+v, want kind=capability with empty depth (kind flows request -> grant unchanged)", grant)
	}
}

func TestGrantRequests_Deny(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	req, err := s.RequestGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "")
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

// TestDenyGrantRequest_AuditRowIsAttributable is the regression test for the
// gap flagged by Codex during review of PR #21: before audit_log had a
// grant_request_id column, a denial's audit row carried only event_type and
// the actor — every target identifier was NULL, so multiple denials by the
// same reviewer were indistinguishable without cross-referencing the mutable
// grant_requests table by timestamp.
func TestDenyGrantRequest_AuditRowIsAttributable(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	req, err := s.RequestGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "")
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	if err := s.DenyGrantRequest(ctx, req.ID, "human-reviewer"); err != nil {
		t.Fatalf("DenyGrantRequest() error = %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE event_type = 'grant_request_denied' AND grant_request_id = $1 AND subject = 'human-reviewer'`,
		req.ID,
	).Scan(&count); err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if count != 1 {
		t.Fatalf("audit_log rows for this denial attributed via grant_request_id = %d, want 1", count)
	}
}

// TestApproveGrantRequest_AuditRowLinksBackToTheRequest checks the same
// backward link on the approval path — it already linked forward via
// grant_id (the newly created grant); this confirms it now links backward to
// the request that was approved too, for consistent traceability either way.
func TestApproveGrantRequest_AuditRowLinksBackToTheRequest(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	req, err := s.RequestGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "")
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	if _, err := s.ApproveGrantRequest(ctx, req.ID, "human-reviewer"); err != nil {
		t.Fatalf("ApproveGrantRequest() error = %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE event_type = 'grant_request_approved' AND grant_request_id = $1`,
		req.ID,
	).Scan(&count); err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if count != 1 {
		t.Fatalf("audit_log rows for this approval linked back via grant_request_id = %d, want 1", count)
	}
}

func TestGrantRequests_ListByStatus(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	pending, err := s.RequestGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "facts", nil, "")
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	toApprove, err := s.RequestGrant(ctx, "agent-b", []string{"preferences.food"}, "memory", "facts", nil, "")
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

	if _, err := s.RequestGrant(ctx, "agent-a", []string{"identity.basic"}, "memory", "bogus", nil, ""); err == nil {
		t.Fatal("RequestGrant() with an invalid depth succeeded, want an error")
	}
}

func TestRequestGrant_EmptyScopesRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.RequestGrant(ctx, "agent-a", nil, "memory", "facts", nil, ""); err == nil {
		t.Fatal("RequestGrant() with no scopes succeeded, want an error")
	}
}

// TestRequestGrant_DuplicateScopesDedupedSoApprovalSucceeds is the regression
// test for the review finding: without deduping, ApproveGrantRequest's
// per-scope grant_scopes insert would fail on the (grant_id, scope) primary
// key, leaving a request that staged fine but could never be approved.
func TestRequestGrant_DuplicateScopesDedupedSoApprovalSucceeds(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	req, err := s.RequestGrant(ctx, "agent-a", []string{"identity.basic", "identity.basic"}, "memory", "facts", nil, "")
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	if len(req.RequestedScopes) != 1 {
		t.Fatalf("RequestedScopes = %v, want deduped to 1", req.RequestedScopes)
	}

	// Without deduping in RequestGrant, this would fail here instead: approval
	// inserts one grant_scopes row per proposed scope, and (grant_id, scope)
	// is that table's primary key.
	if _, err := s.ApproveGrantRequest(ctx, req.ID, "human-reviewer"); err != nil {
		t.Fatalf("ApproveGrantRequest() error = %v (duplicate scopes not deduped before staging?)", err)
	}
}
