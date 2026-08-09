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

// validateRepo rejects an empty, oversized, whitespace-containing, or
// non-canonical repo identifier before it reaches the store. Unlike the
// `policy` column (a closed vocabulary backed by both a DB CHECK constraint and
// API validation — see the migration's doc comment), repo has no DB CHECK
// behind it: the signing_policies migration only constrains it as NOT NULL
// PRIMARY KEY, and neither store.UpsertSigningPolicy nor store.GetSigningPolicy
// checks its length, content, or spelling — UpsertSigningPolicy's own repo == ""
// guard covers only the empty case. So the deletion test (AGENTS.md §6) does
// not apply uniformly across this function's checks:
//   - The empty check IS politeness only: deleting it would surface a less
//     legible failure (UpsertSigningPolicy's "repo must not be empty" error,
//     or on the read path a 404 that reads as "no policy set" rather than a
//     400 "repo is required"), never a new possible state — the store layer
//     already guards emptiness on the write path, and an empty string
//     matches no row on the read path either way.
//   - The length, whitespace, and canonical-form checks are NOT backed by the
//     store or by any DB constraint. They are the sole enforcement of those
//     properties. Deleting any of them (or this function) would let an
//     unbounded-length, whitespace-containing, or non-canonically-spelled repo
//     string reach signing_policies unchecked — a genuinely new state, not just
//     a less legible failure — with no error raised anywhere in the write path
//     to reveal it. The canonical-form check is the load-bearing one: it is
//     what keeps two spellings of the same repo from keying two rows and
//     letting a policy set under one spelling be evaded under another (see
//     requireCanonicalRepo). Do not delete these on the belief that something
//     further down the stack already guards them; nothing does.
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
	return requireCanonicalRepo(repo)
}

// canonicalRepoHint names the one accepted spelling in every rejection message
// requireCanonicalRepo returns, so an operator who typed a URL, a .git clone
// suffix, or a trailing slash is told exactly what to send instead.
const canonicalRepoHint = "use the canonical form host/owner/repo (e.g. github.com/abradner/chuvar) — not a URL, a .git suffix, or a trailing slash"

// requireCanonicalRepo rejects any repo string that is not already in the one
// canonical form this table is keyed on: the bare capability-scope target
// host/owner/repo — lowercase host, no URL scheme, no ".git" clone suffix, no
// trailing/leading/doubled slash, no "." or ".." path segment (the 2026-08-09
// scope-grammar decision, docs/capability-broker.md).
//
// This is a fail-closed control, not cosmetics. signing_policies is keyed on
// repo as an opaque TEXT primary key, and GetSigningPolicy/UpsertSigningPolicy
// compare it byte-for-byte. So two spellings of the same repository —
// "github.com/acme/repo", "github.com/acme/repo.git", "https://github.com/
// acme/repo", "github.com/acme/repo/" — key four different rows. A human could
// set `required` under one spelling while brokerd (or any later reader) derives
// the bare form and looks it up under another: the `required` row reads as
// absent, and if absent is treated as not-required an agent-controlled remote
// spelling silently evades the human-set policy. That is a fail-OPEN on the
// exact boundary this table exists to defend (CLAUDE.md principle 5).
//
// We reject rather than silently normalize on purpose: a silent rewrite is
// itself a way for two distinct inputs to collapse onto one key and surprise
// the operator, so the fail-closed, legible choice is to refuse and name the
// canonical form. validateRepo applies this on BOTH the write and the read
// path, so a lookup under a non-canonical spelling is a clean 400, never a
// silent miss that reads as "no policy set".
//
// There is no DB CHECK behind canonical form (repo is a plain TEXT PRIMARY KEY)
// and internal/scope exposes no target validator yet — the colon-target grammar
// is unbuilt. So this is the SOLE enforcement of the rule, the same standing as
// validateRepo's length/whitespace branches: deleting it is a new possible
// state (a divergent spelling stored under a non-matching key), not a less
// legible failure. The full repo-identifier grammar unification with
// internal/scope's target validation is issue #98; when it lands this rule
// moves there and both callers reuse it (one chokepoint, no Go-vs-Go drift —
// today there is no second validator to drift against).
func requireCanonicalRepo(repo string) error {
	// No colon anywhere: the canonical target has none. This rejects URL
	// schemes ("https://", "git://") and host:port forms in one check, and is
	// robust to net/http ServeMux path-cleaning collapsing "https://" to
	// "https:/" before the handler ever sees it (a "://"-only check would miss
	// the cleaned form). The colon that separates a capability scope's
	// operation from its target (`git.sign:<target>`) belongs to the scope
	// string, never to the bare target this column stores.
	if strings.Contains(repo, ":") {
		return fmt.Errorf("repo must not contain ':' (no URL scheme or host:port): %s", canonicalRepoHint)
	}
	if strings.HasSuffix(repo, ".git") {
		return fmt.Errorf("repo must not include a .git suffix: %s", canonicalRepoHint)
	}
	segments := strings.Split(repo, "/")
	if len(segments) < 3 {
		return fmt.Errorf("repo must be host/owner/repo: %s", canonicalRepoHint)
	}
	for _, seg := range segments {
		if seg == "" {
			return fmt.Errorf("repo must not contain empty path segments (no leading, trailing, or doubled slash): %s", canonicalRepoHint)
		}
		if seg == "." || seg == ".." {
			return fmt.Errorf("repo must not contain a %q path segment: %s", seg, canonicalRepoHint)
		}
	}
	if host := segments[0]; host != strings.ToLower(host) {
		return fmt.Errorf("repo host must be lowercase: %s", canonicalRepoHint)
	}
	return nil
}

// upsertSigningPolicyRequest types Policy as store.SigningPolicy, not a bare
// string, for the same reason listStagedDiffs types its status filter as
// store.DiffStatus: the field carries a closed vocabulary (required/preferred/
// off), so it reads as one at every layer and an invalid value is caught by
// store.ValidSigningPolicy at this boundary (a clean 400) rather than flowing
// on to the signing_policies.policy CHECK constraint as a raw driver 500. The
// CHECK is the enforcement and exists once; this boundary check is legibility
// (AGENTS.md §6's deletion test) — deleting it changes 400-vs-500, never
// whether a fourth value can land in the column.
type upsertSigningPolicyRequest struct {
	Repo   string              `json:"repo"`
	Policy store.SigningPolicy `json:"policy"`
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
	if !store.ValidSigningPolicy(string(req.Policy)) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("policy must be one of required, preferred, off (got %q)", req.Policy))
		return
	}

	p, err := a.Store.UpsertSigningPolicy(r.Context(), req.Repo, string(req.Policy), setBy)
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
