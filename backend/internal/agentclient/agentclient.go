// Package agentclient is a small HTTP client for internal/api's agent-facing
// surface (agent_routes.go): POST /api/agent/search, POST
// /api/agent/proposals, GET /api/agent/grants, POST /api/agent/grant-requests,
// and GET /api/agent/whoami — served on its own listener (CHUVAR_AGENT_ADDR)
// and authenticated with an agent-class bearer token (store.AuthenticateAgentToken),
// never a reviewer token.
//
// This is a new package, not an addition to internal/sseclient, even though
// the two look superficially similar (both are "a Client{BaseURL, Token,
// HTTP} that wraps net/http against this same apiserver"). sseclient is
// shaped for its own callers (cmd/approver, cmd/pushbridge): a reviewer
// token, GET /api/events plus staged-diff/grant-request review actions, and
// view types (StagedDiff, GrantRequest) that mirror the *reviewer*-facing
// JSON shapes. This package's caller (mcpserver, in a later PR — ticket E3)
// authenticates with a structurally different credential class against a
// structurally different set of routes and JSON shapes (agentSearchRequest,
// agentProposalResponse, etc. in agent_routes.go — mirrored here field-for-
// field). AGENTS.md §3.3's rule is "the second caller is already decided,
// not speculative" for extracting a shared abstraction; the mirror image
// applies here just as much — a second, shape-mismatched caller earns its
// own type rather than bending a reviewer-shaped client to also carry an
// agent token and agent view types it was never designed around. Nothing
// imports this package yet (as of its introduction): it is purely additive,
// built ahead of the mcpserver integration that will be its first caller.
//
// Nothing in this package ever logs, wraps into an error message, or
// otherwise surfaces the bearer token — see newRequest and every error type
// below.
package agentclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// maxResponseBodyBytes bounds every response body this client reads,
// regardless of status code. Without a bound, a hostile or simply broken
// agent-listener endpoint could stream an unbounded response and exhaust
// memory in the calling agent process — exactly the process this package
// exists to keep least-privileged (AGENTS.md §3.0's zero-ambient-authority
// framing extends to resource exhaustion, not just credential reach). 8MiB
// comfortably covers the largest legitimate response (a full /api/agent/search
// page: up to agentMaxSearchLimit=200 facts, each up to agentMaxContentLength
// =16384 bytes of content, plus provenance) with headroom, while still
// capping a runaway or adversarial response well short of unbounded.
const maxResponseBodyBytes = 8 << 20 // 8MiB

// Status values echoed verbatim in SearchResult.Status and
// ProposeResult.Status — mirrors agent_routes.go's own string constants
// (which aren't exported from internal/api, so they're reproduced here as
// the contract this client's callers compare against instead of a magic
// string at each call site).
const (
	StatusOK                = "ok"
	StatusInsufficientScope = "insufficient_scope"
	StatusRateLimited       = "RATE_LIMITED"
)

// --- request/response shapes, mirroring internal/api/agent_routes.go ------

// FactProvenance mirrors agentFactProvenanceView field-for-field.
type FactProvenance struct {
	SourceStagedDiffID string  `json:"source_staged_diff_id"`
	DecidedBy          *string `json:"decided_by,omitempty"`
	DecidedAt          *string `json:"decided_at,omitempty"`
	SupersededBy       *string `json:"superseded_by,omitempty"`
	CreatedAt          string  `json:"created_at"`
	ValidAt            string  `json:"valid_at"`
	InvalidAt          *string `json:"invalid_at,omitempty"`
	ExpiredAt          *string `json:"expired_at,omitempty"`
}

// Fact mirrors agentFactView field-for-field.
type Fact struct {
	ID         string          `json:"id"`
	Content    string          `json:"content,omitempty"`
	Summary    string          `json:"summary,omitempty"`
	Depth      string          `json:"depth"`
	Scopes     []string        `json:"scopes"`
	Provenance *FactProvenance `json:"provenance,omitempty"`
}

// SearchRequest mirrors agentSearchRequest field-for-field. There is
// deliberately no Subject field — the server derives the caller from the
// bearer token, never the body (agent_routes.go's package doc comment).
type SearchRequest struct {
	Query           string   `json:"query"`
	RequestedScopes []string `json:"requested_scopes"`
	Limit           int      `json:"limit,omitempty"`
}

// SearchResult mirrors agentSearchResponse field-for-field, including its
// Status contract: StatusOK or StatusInsufficientScope, both delivered over
// a 200 response. insufficient_scope is a legitimate, structured answer
// ("you don't have that scope, go request it") rather than a Go error —
// callers branch on Status, the same way the MCP tool this feeds does today.
type SearchResult struct {
	Status        string   `json:"status"`
	Facts         []Fact   `json:"facts,omitempty"`
	MissingScopes []string `json:"missing_scopes,omitempty"`
}

// ProposeRequest mirrors agentProposalRequest field-for-field.
type ProposeRequest struct {
	Content        string   `json:"content"`
	ProposedScopes []string `json:"proposed_scopes"`
	TargetFactID   string   `json:"target_fact_id,omitempty"`
}

// ProposeResult mirrors agentProposalResponse field-for-field. A 429 from
// the server carries this same shape with Status=StatusRateLimited and every
// other field at its zero value — Propose decodes that response into a
// ProposeResult exactly like a 200, not an error, so the caller backs off
// and retries rather than treating rate-limiting as a failure.
type ProposeResult struct {
	DiffID          string  `json:"diff_id"`
	Status          string  `json:"status"`
	DedupeVerdict   string  `json:"dedupe_verdict"`
	CandidateFactID *string `json:"candidate_fact_id,omitempty"`
}

// GrantView mirrors agentGrantView field-for-field.
type GrantView struct {
	ID        string   `json:"id"`
	Scopes    []string `json:"scopes"`
	Depth     string   `json:"depth"`
	Active    bool     `json:"active"`
	ExpiresAt *string  `json:"expires_at,omitempty"`
	RevokedAt *string  `json:"revoked_at,omitempty"`
}

// ListGrantsResult mirrors agentGrantsResponse field-for-field.
type ListGrantsResult struct {
	Grants []GrantView `json:"grants"`
}

// GrantRequestRequest mirrors agentGrantRequestRequest field-for-field.
type GrantRequestRequest struct {
	RequestedScopes []string `json:"requested_scopes"`
	Depth           string   `json:"depth,omitempty"`
	TTLSeconds      int      `json:"ttl_seconds,omitempty"`
	Justification   string   `json:"justification,omitempty"`
}

// GrantRequestResult mirrors agentGrantRequestResponse field-for-field.
type GrantRequestResult struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

// WhoamiResult mirrors agentWhoamiResponse field-for-field.
type WhoamiResult struct {
	Subject string `json:"subject"`
}

// errorBody mirrors internal/api's errorResponse ({"error": "..."}) — the
// shape every error path in agent_routes.go (via writeError/writeStoreError)
// responds with, whether it's a 400 built from this package's own text or a
// 401/5xx built from a fixed client message.
type errorBody struct {
	Error string `json:"error"`
}

// --- Client -----------------------------------------------------------------

// Client talks to one apiserver's agent listener (CHUVAR_AGENT_ADDR).
// BaseURL is that listener's origin (e.g. "http://127.0.0.1:8081"); Token is
// an agent-class bearer token, never a reviewer token — see the package doc
// comment for why the two aren't interchangeable at either the client or
// server layer.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// newRequest builds a request carrying the bearer token and, for a non-nil
// body, a JSON content type — mirrors internal/sseclient's helper of the
// same name exactly (same two headers, same shape), reproduced here rather
// than imported because the two packages otherwise share nothing (see the
// package doc comment on why this isn't one package).
func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// doJSON sends reqBody (if non-nil) as a JSON request and returns the raw
// status code and a bounded response body for the caller to decode per
// status — every status-code branching (401/400/429/5xx) lives in the five
// exported methods below, not here, because which statuses are even
// possible (e.g. 429 only from proposals) and how each maps differs per
// endpoint.
func (c *Client) doJSON(ctx context.Context, op, method, path string, reqBody any) (int, []byte, error) {
	var bodyReader io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return 0, nil, fmt.Errorf("agentclient: %s: encoding request: %w", op, err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := c.newRequest(ctx, method, path, bodyReader)
	if err != nil {
		return 0, nil, fmt.Errorf("agentclient: %s: building request: %w", op, err)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		// If ctx itself is done, that's why Do failed — surface ctx.Err()
		// (wrapped, so errors.Is(err, context.Canceled) /
		// errors.Is(err, context.DeadlineExceeded) both work) rather than
		// folding it into the same generic *serverError every other
		// transport failure gets. Found in review (#118, Copilot): an
		// intentional cancellation (the caller gave up, a request-scoped
		// deadline elapsed) is not a server or network fault, and callers
		// need to tell the two apart — different retry behaviour, and a
		// cancellation showing up as noisy "server error" logs is
		// misleading. This also covers this package's own Timeout
		// (net/http.Client.Timeout cancels the request's context under the
		// hood, so ctx.Err() reports it the same way an explicit caller
		// cancellation would).
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, nil, fmt.Errorf("agentclient: %s: %w", op, ctxErr)
		}
		// Every other transport failure (DNS, connection refused, TLS
		// handshake failure, ...) — generic per the brief: don't fold local
		// network detail into a message an agent-facing caller might
		// display or log verbatim alongside server errors.
		return 0, nil, &serverError{Op: op}
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return 0, nil, fmt.Errorf("agentclient: %s: reading response: %w", op, err)
	}
	return resp.StatusCode, data, nil
}

// decodeValidationError turns a 400 body into a *ValidationError carrying
// the server's message verbatim (agent_routes.go's 400s are always built
// from writeError with this package's own constructed text — never raw
// store/driver detail — so passing it straight through is safe, and is the
// point: it's validation feedback the calling agent should see). Falls back
// to a generic message if the body isn't the expected {"error": "..."}
// shape, which should not happen against this server but must not panic or
// return an empty message if it somehow did.
func decodeValidationError(op string, body []byte) error {
	var eb errorBody
	if err := json.Unmarshal(body, &eb); err != nil || eb.Error == "" {
		return &ValidationError{Message: fmt.Sprintf("agentclient: %s: bad request", op)}
	}
	return &ValidationError{Message: eb.Error}
}

// Search calls POST /api/agent/search. See SearchResult's doc comment for
// why insufficient_scope is a structured result, not an error.
func (c *Client) Search(ctx context.Context, req SearchRequest) (*SearchResult, error) {
	const op = "search"
	status, body, err := c.doJSON(ctx, op, http.MethodPost, "/api/agent/search", req)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		var out SearchResult
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("agentclient: %s: decoding response: %w", op, err)
		}
		return &out, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("agentclient: %s: %w", op, ErrUnauthorized)
	case http.StatusBadRequest:
		return nil, decodeValidationError(op, body)
	default:
		return nil, &serverError{Op: op, Status: status}
	}
}

// Propose calls POST /api/agent/proposals. A 429 decodes into the same
// ProposeResult shape as a 200 (Status=StatusRateLimited) rather than an
// error — see ProposeResult's doc comment.
func (c *Client) Propose(ctx context.Context, req ProposeRequest) (*ProposeResult, error) {
	const op = "propose"
	status, body, err := c.doJSON(ctx, op, http.MethodPost, "/api/agent/proposals", req)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK, http.StatusTooManyRequests:
		var out ProposeResult
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("agentclient: %s: decoding response: %w", op, err)
		}
		return &out, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("agentclient: %s: %w", op, ErrUnauthorized)
	case http.StatusBadRequest:
		return nil, decodeValidationError(op, body)
	default:
		return nil, &serverError{Op: op, Status: status}
	}
}

// ListGrants calls GET /api/agent/grants — the calling agent's own grants,
// resolved server-side from the bearer token's subject.
func (c *Client) ListGrants(ctx context.Context) (*ListGrantsResult, error) {
	const op = "list_grants"
	status, body, err := c.doJSON(ctx, op, http.MethodGet, "/api/agent/grants", nil)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		var out ListGrantsResult
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("agentclient: %s: decoding response: %w", op, err)
		}
		return &out, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("agentclient: %s: %w", op, ErrUnauthorized)
	case http.StatusBadRequest:
		return nil, decodeValidationError(op, body)
	default:
		return nil, &serverError{Op: op, Status: status}
	}
}

// RequestGrant calls POST /api/agent/grant-requests. Like the server side
// (request_grant.go, agentRequestGrant), this never creates a real grant —
// it only stages a request for a human to approve or deny.
func (c *Client) RequestGrant(ctx context.Context, req GrantRequestRequest) (*GrantRequestResult, error) {
	const op = "request_grant"
	status, body, err := c.doJSON(ctx, op, http.MethodPost, "/api/agent/grant-requests", req)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		var out GrantRequestResult
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("agentclient: %s: decoding response: %w", op, err)
		}
		return &out, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("agentclient: %s: %w", op, ErrUnauthorized)
	case http.StatusBadRequest:
		return nil, decodeValidationError(op, body)
	default:
		return nil, &serverError{Op: op, Status: status}
	}
}

// Whoami calls GET /api/agent/whoami. A later PR (mcpserver becoming this
// package's first caller, ticket E3) uses this as a boot health check: call
// it once at startup and abort loudly (via errors.Is(err, ErrUnauthorized))
// if the configured token doesn't authenticate, rather than starting up and
// failing every subsequent tool call one at a time.
func (c *Client) Whoami(ctx context.Context) (*WhoamiResult, error) {
	const op = "whoami"
	status, body, err := c.doJSON(ctx, op, http.MethodGet, "/api/agent/whoami", nil)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		var out WhoamiResult
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("agentclient: %s: decoding response: %w", op, err)
		}
		return &out, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("agentclient: %s: %w", op, ErrUnauthorized)
	case http.StatusBadRequest:
		return nil, decodeValidationError(op, body)
	default:
		return nil, &serverError{Op: op, Status: status}
	}
}
