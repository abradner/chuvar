package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
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
// host/owner/repo — exactly three slash-separated segments, all lowercase, no
// URL scheme, no ".git" clone suffix, no trailing/leading/doubled slash, no
// "." or ".." path segment, no trailing DNS root dot on the host (the
// 2026-08-09 scope-grammar decision, docs/capability-broker.md).
//
// This is a fail-closed control, not cosmetics. signing_policies is keyed on
// repo as an opaque TEXT primary key, and GetSigningPolicy/UpsertSigningPolicy
// compare it byte-for-byte. So multiple spellings of the same repository —
// "github.com/acme/repo", "github.com/acme/repo.git", "https://github.com/
// acme/repo", "github.com/acme/repo/", "github.com./acme/repo" (trailing DNS
// root dot — the same host, a different byte string), "github.com/ACME/Repo"
// (GitHub treats owner/repo case-insensitively) — key as many different rows.
// A human could set `required` under one spelling while brokerd (or any later
// reader) derives the bare form and looks it up under another: the `required`
// row reads as absent, and if absent is treated as not-required an
// agent-controlled remote spelling silently evades the human-set policy. That
// is a fail-OPEN on the exact boundary this table exists to defend (CLAUDE.md
// principle 5).
//
// The lowercase rule folds the WHOLE repo string, not just the host: this
// project's only forge target today is GitHub, which resolves owner/repo
// case-insensitively (github.com/ACME/Repo and github.com/acme/repo are the
// same repository), so a case-only difference must not key a second row. If
// a future forge target treats path case as significant, that forge needs its
// own rule here rather than a silent exception carved into this one — a
// case-insensitive host and a case-sensitive one can't share a single
// lowercase-or-reject check without one of them going wrong.
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
	// Exactly 3, not "at least 3": host/owner/repo is the whole canonical
	// shape, so a fourth segment (github.com/org/repo/extra) is a distinct,
	// non-canonical string that must not silently key its own row alongside
	// the 3-segment canonical one.
	if len(segments) != 3 {
		return fmt.Errorf("repo must be host/owner/repo (got %d segments): %s", len(segments), canonicalRepoHint)
	}
	for _, seg := range segments {
		if seg == "" {
			return fmt.Errorf("repo must not contain empty path segments (no leading, trailing, or doubled slash): %s", canonicalRepoHint)
		}
		if seg == "." || seg == ".." {
			return fmt.Errorf("repo must not contain a %q path segment: %s", seg, canonicalRepoHint)
		}
	}
	// The trailing DNS root dot ("github.com.") names the exact same host as
	// "github.com" — resolvers treat it as an explicit fully-qualified name,
	// not a different one — so it is rejected as a divergent spelling of the
	// same host rather than folded away: this function rejects, it does not
	// rewrite (see the doc comment above).
	if host := segments[0]; strings.HasSuffix(host, ".") {
		return fmt.Errorf("repo host must not end with a trailing '.' (it names the same host as without it): %s", canonicalRepoHint)
	}
	if repo != strings.ToLower(repo) {
		return fmt.Errorf("repo must be all lowercase: %s", canonicalRepoHint)
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

// signingPoliciesPathPrefix is the path prefix rejectUncleanSigningPolicyPath
// guards — every route this file registers (api.go) lives under it.
const signingPoliciesPathPrefix = "/api/signing-policies"

// rejectUncleanSigningPolicyPath closes finding 3 of the round-2 review: this
// package's getSigningPolicy doc comment (above) and requireCanonicalRepo's
// doc comment both promise that a non-canonical repo spelling — including one
// built from doubled slashes or "."/".." path segments — gets a clean 400
// naming the canonical form, on both the write and the read path. That
// promise does not hold for the GET route as registered: net/http's
// ServeMux.findHandler cleans the request path (net/http/server.go's
// cleanPath — path.Clean plus trailing-slash preservation) and, when cleaning
// changes it, returns its OWN redirect handler (307, empirically confirmed
// against this handler, not the 301 an "old-style" redirect might suggest)
// BEFORE dispatch ever reaches a registered pattern. getSigningPolicy (and
// therefore validateRepo/requireCanonicalRepo) never runs for a request like
// "/api/signing-policies/github.com//abradner/chuvar" or one containing a
// "/./" or "/../" segment: the caller gets redirected to the CLEANED path
// instead, and a redirect-following client silently receives whatever policy
// is stored under that different key — not the 400 the doc comments claim,
// and not even the caller's own requested key. Per CLAUDE.md principle 8, a
// security comment describing a check the code doesn't reach is a bug, and
// per principle 5 a client that doesn't follow the redirect must not read a
// wrong-key 200/404 as "no policy" either.
//
// This runs upstream of both ServeMux layers Routes() builds (the redirect
// is issued by whichever mux's own findHandler sees the request first — for
// "/api/signing-policies/..." that's the outer "top" mux, since path
// cleaning happens before top even decides whether to dispatch into its "/"
// pattern — so the guard has to wrap Routes()'s handler chain from outside,
// not sit inside a mux.HandleFunc registration) and rejects, with a 400
// naming the canonical form, any request under /api/signing-policies whose
// path net/http would otherwise silently clean and redirect. That makes the
// reject-not-rewrite promise actually reachable over HTTP for the inputs that
// matter, instead of true only of validateRepo called directly — see the HTTP
// round-trip tests in signing_policies_test.go (run with redirects NOT
// followed, so they observe what a non-redirect-following client — e.g. a
// signing shim's HTTP client configured to treat any 3xx as a failure —
// actually gets).
//
// Scoped to the /api/signing-policies prefix only: every other route's
// existing (undocumented, pre-existing) susceptibility to the same mux
// cleaning behavior is unchanged and out of scope for this fix.
func rejectUncleanSigningPolicyPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped := r.URL.EscapedPath()
		if r.Method != http.MethodConnect &&
			(escaped == signingPoliciesPathPrefix || strings.HasPrefix(escaped, signingPoliciesPathPrefix+"/")) {
			if cleaned := cleanHTTPPath(escaped); cleaned != escaped {
				writeError(w, http.StatusBadRequest, fmt.Errorf(
					"repo path must not contain doubled slashes or '.'/'..' segments (net/http would otherwise silently redirect this request to %q instead of rejecting it): %s",
					cleaned, canonicalRepoHint))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// cleanHTTPPath reimplements net/http's own unexported cleanPath
// (net/http/server.go), including its trailing-slash-preservation quirk, so
// rejectUncleanSigningPolicyPath's "would ServeMux redirect this" check
// matches net/http's actual decision exactly — no more, no less — rather than
// approximating it with a bare path.Clean call (which drops a meaningful
// trailing slash cleanPath puts back, and would then over-reject the
// legitimate "github.com/abradner/chuvar/" trailing-slash case
// requireCanonicalRepo already handles on its own).
func cleanHTTPPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	if p[len(p)-1] == '/' && np != "/" {
		np += "/"
	}
	return np
}
