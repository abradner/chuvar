package api

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestAgentTokens_LifecycleIssueAuthenticateRevoke(t *testing.T) {
	srv, st := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{Subject: "mcpserver-prod", Label: "prod host"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/agent-tokens status = %d, want 201", resp.StatusCode)
	}
	created := decodeInto[createAgentTokenResponse](t, resp)
	if created.Token == "" {
		t.Fatal("POST /api/agent-tokens response did not include a plaintext token")
	}
	if created.Subject != "mcpserver-prod" {
		t.Errorf("Subject = %q, want %q", created.Subject, "mcpserver-prod")
	}
	if !created.Active {
		t.Error("newly created agent token should be Active")
	}

	// The new token authenticates on the store method — this PR builds no
	// HTTP surface that itself accepts an agent token as a bearer credential
	// (that's mcpserver's later PR); the round trip is verified at the store
	// layer, which is what any future consumer will call into.
	agent, ok, err := st.AuthenticateAgentToken(context.Background(), created.Token)
	if err != nil {
		t.Fatalf("AuthenticateAgentToken() error = %v", err)
	}
	if !ok || agent.Subject != "mcpserver-prod" {
		t.Fatalf("AuthenticateAgentToken() = (%+v, %v), want subject %q, ok=true", agent, ok, "mcpserver-prod")
	}

	// It shows up in the listing, without the plaintext or hash.
	tokens := decodeInto[[]agentTokenView](t, doJSON(t, http.MethodGet, srv.URL+"/api/agent-tokens", nil))
	found := false
	for _, tk := range tokens {
		if tk.ID == created.ID {
			found = true
			if tk.Subject != "mcpserver-prod" || tk.Label != "prod host" {
				t.Errorf("listed agent token = %+v, want subject %q label %q", tk, "mcpserver-prod", "prod host")
			}
		}
	}
	if !found {
		t.Error("newly created agent token not present in GET /api/agent-tokens")
	}

	// Revoke it, then confirm it can no longer authenticate.
	resp = doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens/"+created.ID+"/revoke", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /api/agent-tokens/{id}/revoke status = %d, want 204", resp.StatusCode)
	}
	_, ok, err = st.AuthenticateAgentToken(context.Background(), created.Token)
	if err != nil {
		t.Fatalf("AuthenticateAgentToken() after revoke: error = %v", err)
	}
	if ok {
		t.Fatal("AuthenticateAgentToken() with a revoked token succeeded, want failure")
	}

	// Revoking again should fail, not silently succeed.
	resp = doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens/"+created.ID+"/revoke", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST /api/agent-tokens/{id}/revoke (already revoked) status = %d, want 409", resp.StatusCode)
	}
}

// TestCreateAgentToken_MissingTOTPHeaderRejected is the strong-factor-
// required proof: a correctly authenticated (bearer) reviewer with an
// enrolled factor still must present it — no TOTP header at all must be
// refused, exactly like the requireStrongFactor-gated reviewer routes
// (createGrant, approveStagedDiff, etc).
func TestCreateAgentToken_MissingTOTPHeaderRejected(t *testing.T) {
	srv, _ := testServer(t)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/agent-tokens", bytes.NewReader(mustJSON(t, createAgentTokenRequest{Subject: "mcpserver-x", Label: "no factor"})))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	// Deliberately no X-Chuvar-TOTP-Code header.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/agent-tokens with no TOTP header: status = %d, want 401", resp.StatusCode)
	}
}

// TestCreateAgentToken_BootstrapTokenCannotMint is the invariant named
// explicitly in the brief: unlike createToken (tokens.go), there is NO
// bootstrap carve-out for agent tokens. The factorless bootstrap reviewer
// token (the one shape createToken's conditional gate deliberately lets
// through when zero devices are enrolled yet) must be refused outright here
// — an agent-class credential is pure standing authority, and minting one
// always demands a present human factor, with no "first ever call" escape
// hatch.
func TestCreateAgentToken_BootstrapTokenCannotMint(t *testing.T) {
	srv, bootstrapToken := testServerWithBootstrapToken(t)

	// The bootstrap token has zero enrolled devices ahead of it — exactly the
	// state createToken's gate treats as its carve-out. createAgentToken must
	// not have an equivalent one.
	resp := doJSONWithAuth(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{Subject: "mcpserver-x", Label: "via bootstrap"}, bootstrapToken)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/agent-tokens from the factorless bootstrap token: status = %d, want 401 (no bootstrap carve-out for agent tokens)", resp.StatusCode)
	}
}

// TestAgentTokens_ListAndRevoke_BearerOnly confirms list/revoke need no
// second factor — matching listTokens/revokeToken's stance that revocation
// only ever reduces authority, and listing is a read.
func TestAgentTokens_ListAndRevoke_BearerOnly(t *testing.T) {
	srv, st := testServer(t)

	tok, err := st.CreateAgentToken(context.Background(), "subject-a", "label-a", "plaintext-a")
	if err != nil {
		t.Fatalf("CreateAgentToken() error = %v", err)
	}

	// No TOTP header attached — built manually so we don't get doJSON's
	// automatic TOTP attachment, proving these routes don't need it.
	listReq, err := http.NewRequest(http.MethodGet, srv.URL+"/api/agent-tokens", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	listReq.Header.Set("Authorization", "Bearer "+testAuthToken)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/agent-tokens with no TOTP header: status = %d, want 200 (bearer-only)", listResp.StatusCode)
	}

	revokeReq, err := http.NewRequest(http.MethodPost, srv.URL+"/api/agent-tokens/"+tok.ID+"/revoke", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	revokeReq.Header.Set("Authorization", "Bearer "+testAuthToken)
	revokeResp, err := http.DefaultClient.Do(revokeReq)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /api/agent-tokens/{id}/revoke with no TOTP header: status = %d, want 204 (bearer-only)", revokeResp.StatusCode)
	}
}

func TestCreateAgentToken_MissingSubjectRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{Label: "no-subject"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/agent-tokens with empty subject: status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateAgentToken_MissingLabelRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{Subject: "no-label"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/agent-tokens with empty label: status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateAgentToken_WhitespaceOnlyFieldsRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{Subject: "   ", Label: "whitespace-subject"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/agent-tokens with whitespace-only subject: status = %d, want 400", resp.StatusCode)
	}

	resp = doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{Subject: "whitespace-label", Label: "   "})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/agent-tokens with whitespace-only label: status = %d, want 400", resp.StatusCode)
	}
}

// TestCreateAgentToken_SubjectAtMaxLengthAccepted and its sibling below are
// the boundary tests the max-length branches never had (found in review,
// Codex P2s on #116): the empty/whitespace cases above exercise the "too
// short" end of subject/label validation, but maxAgentTokenFieldLength's own
// rejection branch — len(field) > maxAgentTokenFieldLength — was never
// exercised at either edge. Exactly at the limit must still succeed (this
// isn't an off-by-one "must be strictly less than" check); one character
// over must be rejected.
func TestCreateAgentToken_SubjectAtMaxLengthAccepted(t *testing.T) {
	srv, _ := testServer(t)

	subject := strings.Repeat("s", maxAgentTokenFieldLength)
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{Subject: subject, Label: "at-max-subject"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/agent-tokens with subject exactly at maxAgentTokenFieldLength (%d): status = %d, want 201", maxAgentTokenFieldLength, resp.StatusCode)
	}
}

func TestCreateAgentToken_SubjectOverMaxLengthRejected(t *testing.T) {
	srv, _ := testServer(t)

	subject := strings.Repeat("s", maxAgentTokenFieldLength+1)
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{Subject: subject, Label: "over-max-subject"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/agent-tokens with subject one over maxAgentTokenFieldLength (%d): status = %d, want 400", maxAgentTokenFieldLength+1, resp.StatusCode)
	}
}

func TestCreateAgentToken_LabelAtMaxLengthAccepted(t *testing.T) {
	srv, _ := testServer(t)

	label := strings.Repeat("l", maxAgentTokenFieldLength)
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{Subject: "at-max-label", Label: label})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/agent-tokens with label exactly at maxAgentTokenFieldLength (%d): status = %d, want 201", maxAgentTokenFieldLength, resp.StatusCode)
	}
}

func TestCreateAgentToken_LabelOverMaxLengthRejected(t *testing.T) {
	srv, _ := testServer(t)

	label := strings.Repeat("l", maxAgentTokenFieldLength+1)
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{Subject: "over-max-label", Label: label})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/agent-tokens with label one over maxAgentTokenFieldLength (%d): status = %d, want 400", maxAgentTokenFieldLength+1, resp.StatusCode)
	}
}
