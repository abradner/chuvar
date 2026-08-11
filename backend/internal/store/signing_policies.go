package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/abradner/chuvar/backend/internal/store/sqlcgen"
)

// SigningPolicy is the closed vocabulary for a repository's git-commit-signing
// requirement (issue #94; docs/capability-broker.md's 2026-08-09 "Signing
// policy lives broker-side" decision). Mirrors the CHECK constraint on
// signing_policies.policy the same way GrantKind mirrors grants.kind.
type SigningPolicy string

const (
	SigningPolicyRequired  SigningPolicy = "required"
	SigningPolicyPreferred SigningPolicy = "preferred"
	SigningPolicyOff       SigningPolicy = "off"
)

// ValidSigningPolicy reports whether policy is one of the closed vocabulary's
// values — the single copy internal/api calls before this ever reaches the
// store, same "validate at every layer that accepts external input" stance
// as store.ValidDepth.
func ValidSigningPolicy(policy string) bool {
	switch SigningPolicy(policy) {
	case SigningPolicyRequired, SigningPolicyPreferred, SigningPolicyOff:
		return true
	default:
		return false
	}
}

// RepoSigningPolicy is the store-facing view of a repository's current
// signing policy — one row per repo, current state only (see the
// signing_policies migration's doc comment for why the audit trail lives in
// audit_log instead of a history table here).
type RepoSigningPolicy struct {
	Repo      string
	Policy    string
	SetBy     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func toRepoSigningPolicy(row sqlcgen.SigningPolicy) RepoSigningPolicy {
	return RepoSigningPolicy{
		Repo:      row.Repo,
		Policy:    row.Policy,
		SetBy:     row.SetBy,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}

// signingPolicyAuditDetail is the JSON shape written to audit_log.detail for
// a "signing_policy_set" event. audit_log has no dedicated FK column for a
// signing policy row (unlike fact_id/grant_id/staged_diff_id/
// grant_request_id) — repo is a plain string, not a row this schema can
// reference — so it travels in detail instead, the same mechanism
// ReadAuditDetail uses for its own per-call structure.
type signingPolicyAuditDetail struct {
	Repo   string `json:"repo"`
	Policy string `json:"policy"`
}

// UpsertSigningPolicy sets repo's signing policy, creating the row if none
// exists yet or replacing the previous policy if one does — a human changing
// their mind about a policy is "set it again," not "unset then set" (see the
// query's own doc comment). setBy is who's setting it — required, logged to
// audit_log atomically with the write, same actor-provenance discipline as
// CreateGrant/RevokeGrant/RenewGrant. This method itself only requires setBy
// to be non-empty; it does not authenticate it — that guarantee (the
// authenticated reviewer token's label, never a request-body field) holds for
// the REST API call path specifically (internal/api/signing_policies.go
// passes reviewerFromContext(...).Label), same caveat as every other mutation
// in this package.
//
// The audit row also tags scopes with the capability-scope-shaped target
// (`git.sign:<repo>`, per the 2026-08-09 scope-grammar decision) even though
// no grant is created here — purely so a reviewer scanning audit_log can
// correlate a policy change with capability grants over the same target,
// without this table or this method depending on scope.Validate/Covers ever
// landing colon-target support.
func (s *Store) UpsertSigningPolicy(ctx context.Context, repo, policy, setBy string) (RepoSigningPolicy, error) {
	if repo == "" {
		return RepoSigningPolicy{}, fmt.Errorf("store: repo must not be empty")
	}
	if !ValidSigningPolicy(policy) {
		return RepoSigningPolicy{}, fmt.Errorf("store: invalid signing policy %q (want required, preferred, or off)", policy)
	}
	if setBy == "" {
		return RepoSigningPolicy{}, fmt.Errorf("store: setBy must not be empty")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return RepoSigningPolicy{}, fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op if already committed
	qtx := s.q.WithTx(tx)

	row, err := qtx.UpsertSigningPolicy(ctx, sqlcgen.UpsertSigningPolicyParams{
		Repo:   repo,
		Policy: policy,
		SetBy:  setBy,
	})
	if err != nil {
		return RepoSigningPolicy{}, fmt.Errorf("store: upsert signing policy: %w", err)
	}

	detail, err := json.Marshal(signingPolicyAuditDetail{Repo: repo, Policy: policy})
	if err != nil {
		return RepoSigningPolicy{}, fmt.Errorf("store: marshal signing policy audit detail: %w", err)
	}
	if err := logAudit(ctx, qtx, "signing_policy_set", setBy, nil, nil, nil, nil,
		[]string{"git.sign:" + repo}, detail); err != nil {
		return RepoSigningPolicy{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return RepoSigningPolicy{}, fmt.Errorf("store: commit signing policy upsert: %w", err)
	}
	return toRepoSigningPolicy(row), nil
}

// GetSigningPolicy fetches repo's current signing policy. Returns an error
// wrapping pgx.ErrNoRows (via sqlc's :one — see internal/api's
// getSigningPolicy handler for the errors.Is(err, pgx.ErrNoRows) check that
// turns that into a clean 404) when no policy has ever been set for repo —
// that's a distinct, legible state from any of the three policy values, not
// defaulted to one of them here: this layer doesn't decide what
// "unconfigured" means for a caller, and shouldn't guess at a
// fail-open-vs-fail-closed default the project hasn't made yet.
func (s *Store) GetSigningPolicy(ctx context.Context, repo string) (RepoSigningPolicy, error) {
	row, err := s.q.GetSigningPolicy(ctx, repo)
	if err != nil {
		return RepoSigningPolicy{}, fmt.Errorf("store: get signing policy for %q: %w", repo, err)
	}
	return toRepoSigningPolicy(row), nil
}
