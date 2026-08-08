package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5"

	"github.com/abradner/chuvar/backend/internal/store"
)

// maxRepoLength bounds the repository identifier a signing-policy request can
// name. No real identifier (a host+path string like
// "github.com/abradner/chuvar") needs anywhere near this many characters —
// exists for the same reason maxTokenLabelLength/maxScopesPerGrant do: a
// malformed or hostile request shouldn't be able to stuff an arbitrarily
// large string into a primary key column.
const maxRepoLength = 512

type signingPolicyView struct {
	Repo      string `json:"repo"`
	Policy    string `json:"policy"`
	SetBy     string `json:"set_by"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func toSigningPolicyView(p store.RepoSigningPolicy) signingPolicyView {
	return signingPolicyView{
		Repo:      p.Repo,
		Policy:    p.Policy,
		SetBy:     p.SetBy,
		CreatedAt: p.CreatedAt.Format(timeFormat),
		UpdatedAt: p.UpdatedAt.Format(timeFormat),
	}
}

// validateRepo rejects an empty, oversized, or whitespace-containing repo
// identifier before it reaches the store. This is politeness, not
// enforcement (AGENTS.md §6's deletion test): there is no DB CHECK backing a
// repo identifier's shape — like the scope taxonomy (§3.4), it isn't a closed
// vocabulary — so store.UpsertSigningPolicy/GetSigningPolicy's own
// repo == "" checks are the real floor, not this function. Deleting this
// function would turn a malformed request into a less legible failure
// further down the stack, never make a new state possible that the store
// layer doesn't already guard.
func validateRepo(repo string) error {
	if repo == "" {
		return fmt.Errorf("repo is required")
	}
	if len(repo) > maxRepoLength {
		return fmt.Errorf("repo exceeds max length of %d", maxRepoLength)
	}
	// A repo identifier is a bare host+path string (e.g.
	// "github.com/abradner/chuvar") — whitespace anywhere in it means either
	// a client bug or an attempt to smuggle something else through a field
	// this table treats as an opaque key.
	if strings.ContainsFunc(repo, unicode.IsSpace) {
		return fmt.Errorf("repo must not contain whitespace")
	}
	return nil
}

type upsertSigningPolicyRequest struct {
	Repo   string `json:"repo"`
	Policy string `json:"policy"`
}

// upsertSigningPolicy handles POST /api/signing-policies. Gated by
// requireTOTP — same self-escalation-prevention rationale as createGrant/
// renewGrant/approveGrantRequest/approveStagedDiff (requireTOTP's doc
// comment): a signing shim (or, later, brokerd) is meant to treat this policy
// as authoritative, so setting or downgrading it needs the same second
// factor as minting authority itself — a bearer token alone (readable by
// anything with shell access to the reviewer's environment, per requireTOTP's
// doc comment) must not be able to flip a repo from required to off.
// set_by is the authenticated reviewer (reviewerFromContext), never a
// request-body field — see the package comment.
func (a *API) upsertSigningPolicy(w http.ResponseWriter, r *http.Request) {
	setBy := reviewerFromContext(r.Context()).Label

	var req upsertSigningPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request body: %w", err))
		return
	}
	if err := validateRepo(req.Repo); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !store.ValidSigningPolicy(req.Policy) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("policy must be one of required, preferred, off (got %q)", req.Policy))
		return
	}

	p, err := a.Store.UpsertSigningPolicy(r.Context(), req.Repo, req.Policy, setBy)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "upsertSigningPolicy", "could not set signing policy", err)
		return
	}
	writeJSON(w, http.StatusOK, toSigningPolicyView(p))
}

// getSigningPolicy handles GET /api/signing-policies/{repo...}. The {repo...}
// wildcard (not {repo}) is deliberate: a repo identifier like
// "github.com/abradner/chuvar" contains slashes, which a plain single-segment
// path parameter can't capture — net/http's wildcard-suffix pattern (Go
// 1.22+) matches the rest of the path instead, slashes included.
//
// Reviewer-authenticated like every route (requireAuth wraps Routes() as a
// whole, api.go), but not TOTP-gated — same "reads don't need the second
// factor, only authority-changing mutations do" stance as listGrants/
// listTokens. This is also the preflight read path issue #94 calls for: a
// signing shim asks "what does this repo require?" before deciding whether
// to fail closed. A repo with no policy ever set is a distinct, legible 404,
// not defaulted to any of the three policy values here — see
// store.GetSigningPolicy's doc comment for why.
func (a *API) getSigningPolicy(w http.ResponseWriter, r *http.Request) {
	repo := r.PathValue("repo")
	if err := validateRepo(repo); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	p, err := a.Store.GetSigningPolicy(r.Context(), repo)
	if err != nil {
		// Only pgx.ErrNoRows means "no policy set for this repo" — same
		// error-masking guard as grantRequestExists/approveStagedDiff: a real
		// database failure must surface as a 500 an operator investigates,
		// not as an indistinguishable 404 that reads as "this repo just
		// isn't configured yet."
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, errors.New("no signing policy set for this repo"))
			return
		}
		writeStoreError(w, http.StatusInternalServerError, "getSigningPolicy", "could not look up signing policy", err)
		return
	}
	writeJSON(w, http.StatusOK, toSigningPolicyView(p))
}
