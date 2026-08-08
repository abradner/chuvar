package store

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestUpsertSigningPolicy_CreateThenRead(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	p, err := s.UpsertSigningPolicy(ctx, "github.com/abradner/chuvar", "required", "human-reviewer")
	if err != nil {
		t.Fatalf("UpsertSigningPolicy() error = %v", err)
	}
	if p.Repo != "github.com/abradner/chuvar" || p.Policy != "required" || p.SetBy != "human-reviewer" {
		t.Fatalf("UpsertSigningPolicy() = %+v, want repo/policy/set_by round-tripped", p)
	}
	if p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		t.Fatalf("UpsertSigningPolicy() timestamps = %+v, want both set", p)
	}

	got, err := s.GetSigningPolicy(ctx, "github.com/abradner/chuvar")
	if err != nil {
		t.Fatalf("GetSigningPolicy() error = %v", err)
	}
	if got.Policy != "required" {
		t.Fatalf("GetSigningPolicy() = %+v, want policy=required", got)
	}
}

// TestUpsertSigningPolicy_SecondCallReplacesTheFirst is the "a human changing
// their mind" case the query's own doc comment describes: setting a policy
// twice for the same repo must update the existing row (and record who most
// recently set it), not fail on a duplicate key or leave two rows behind.
func TestUpsertSigningPolicy_SecondCallReplacesTheFirst(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	first, err := s.UpsertSigningPolicy(ctx, "github.com/abradner/chuvar", "preferred", "reviewer-a")
	if err != nil {
		t.Fatalf("UpsertSigningPolicy() (first) error = %v", err)
	}

	second, err := s.UpsertSigningPolicy(ctx, "github.com/abradner/chuvar", "required", "reviewer-b")
	if err != nil {
		t.Fatalf("UpsertSigningPolicy() (second) error = %v", err)
	}
	if second.Policy != "required" || second.SetBy != "reviewer-b" {
		t.Fatalf("UpsertSigningPolicy() (second) = %+v, want policy=required set_by=reviewer-b", second)
	}
	if second.UpdatedAt.Before(first.UpdatedAt) {
		t.Fatalf("UpsertSigningPolicy() (second) UpdatedAt = %v, want it not before the first row's %v", second.UpdatedAt, first.UpdatedAt)
	}

	got, err := s.GetSigningPolicy(ctx, "github.com/abradner/chuvar")
	if err != nil {
		t.Fatalf("GetSigningPolicy() error = %v", err)
	}
	if got.Policy != "required" || got.SetBy != "reviewer-b" {
		t.Fatalf("GetSigningPolicy() after second upsert = %+v, want the replaced value, not both rows or the original", got)
	}
}

func TestUpsertSigningPolicy_InvalidPolicyRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.UpsertSigningPolicy(ctx, "github.com/abradner/chuvar", "bogus", "human-reviewer"); err == nil {
		t.Fatal("UpsertSigningPolicy() with invalid policy: want error, got nil")
	}
}

func TestUpsertSigningPolicy_EmptyRepoRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.UpsertSigningPolicy(ctx, "", "required", "human-reviewer"); err == nil {
		t.Fatal("UpsertSigningPolicy() with empty repo: want error, got nil")
	}
}

func TestUpsertSigningPolicy_EmptySetByRejected(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.UpsertSigningPolicy(ctx, "github.com/abradner/chuvar", "required", ""); err == nil {
		t.Fatal("UpsertSigningPolicy() with empty setBy: want error, got nil")
	}
}

func TestGetSigningPolicy_UnsetRepoReturnsNoRows(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	// A repo with no policy ever set must come back as a distinguishable
	// pgx.ErrNoRows, not silently default to any of the three values — see
	// GetSigningPolicy's doc comment. internal/api's getSigningPolicy relies
	// on errors.Is(err, pgx.ErrNoRows) surviving the store's fmt.Errorf(...%w)
	// wrap to turn this into a clean 404.
	_, err := s.GetSigningPolicy(ctx, "github.com/never-configured/repo")
	if err == nil {
		t.Fatal("GetSigningPolicy() for an unconfigured repo: want error, got nil")
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetSigningPolicy() error = %v, want it to wrap pgx.ErrNoRows", err)
	}
}

func TestUpsertSigningPolicy_LogsAuditEventAtomically(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	if _, err := s.UpsertSigningPolicy(ctx, "github.com/abradner/chuvar", "required", "human-reviewer"); err != nil {
		t.Fatalf("UpsertSigningPolicy() error = %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE event_type = 'signing_policy_set' AND subject = 'human-reviewer' AND 'git.sign:github.com/abradner/chuvar' = ANY(scopes)`,
	).Scan(&count); err != nil {
		t.Fatalf("querying audit_log: %v", err)
	}
	if count != 1 {
		t.Fatalf("audit_log rows for signing_policy_set = %d, want 1", count)
	}
}

// TestUpsertSigningPolicy_FailedTransactionDoesNotPersistPartialState guards
// the same all-or-nothing property CreateGrant/RenewGrant already rely on:
// an invalid policy must fail before the transaction is opened at all, so a
// bad request never leaves a partially-written row for a repo that had none
// before.
func TestUpsertSigningPolicy_FailedTransactionDoesNotPersistPartialState(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if _, err := s.UpsertSigningPolicy(ctx, "github.com/abradner/chuvar", "bogus", "human-reviewer"); err == nil {
		t.Fatal("UpsertSigningPolicy() with invalid policy: want error, got nil")
	}

	if _, err := s.GetSigningPolicy(ctx, "github.com/abradner/chuvar"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetSigningPolicy() after a rejected upsert = %v, want pgx.ErrNoRows (no row should have been created)", err)
	}
}
