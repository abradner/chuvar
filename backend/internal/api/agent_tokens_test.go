package api

import (
	"bytes"
	"net/http"
	"testing"
)

// TestCreateAgentToken_MissingStrongFactorRejected is the strong-factor-
// required proof this PR's brief demands: POST /api/agent-tokens must be
// refused without a present human second factor, even from an otherwise
// fully-authenticated reviewer bearer token. Built manually (not via
// doJSON/doJSONWithAuth), since both of those attach a valid TOTP code
// automatically for testAuthToken — exactly the shortcut this test must not
// take.
func TestCreateAgentToken_MissingStrongFactorRejected(t *testing.T) {
	srv, _ := testServer(t)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/agent-tokens", bytes.NewReader(mustJSON(t, createAgentTokenRequest{
		Subject: "agent-a",
		Label:   "laptop-agent-1",
	})))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/agent-tokens with no TOTP header: status = %d, want 401 (minting an agent token must always demand a present human second factor)", resp.StatusCode)
	}
}

// TestCreateAgentToken_BootstrapTokenCannotMint is the "no bootstrap
// carve-out" half of the invariant: unlike POST /api/tokens, the factorless
// bootstrap reviewer token must never be able to mint an agent-class token —
// an agent credential is pure standing authority, and there is no equivalent
// chicken-and-egg problem to justify an exception.
func TestCreateAgentToken_BootstrapTokenCannotMint(t *testing.T) {
	srv, bootstrapToken := testServerWithBootstrapToken(t)

	resp := doJSONWithAuth(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{
		Subject: "agent-a",
		Label:   "laptop-agent-1",
	}, bootstrapToken)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/agent-tokens from the factorless bootstrap token: status = %d, want 401 (the bootstrap token has no TOTP secret of its own, so it can never pass requireStrongFactor)", resp.StatusCode)
	}
}

// TestCreateAgentToken_LifecycleIssueAuthenticateRevoke exercises the full
// mint -> authenticate -> list -> revoke path over HTTP, mirroring
// TestCreateToken_LifecycleIssueAuthenticateRevoke's shape.
func TestCreateAgentToken_LifecycleIssueAuthenticateRevoke(t *testing.T) {
	srv, st := testServer(t)

	// doJSON attaches a valid TOTP code for testAuthToken automatically —
	// exercising the gate being satisfied, not bypassed.
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{
		Subject: "agent-a",
		Label:   "laptop-agent-1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/agent-tokens status = %d, want 201", resp.StatusCode)
	}
	created := decodeInto[createAgentTokenResponse](t, resp)
	if created.Token == "" {
		t.Fatal("POST /api/agent-tokens response did not include a plaintext token")
	}
	if created.Subject != "agent-a" {
		t.Errorf("Subject = %q, want %q", created.Subject, "agent-a")
	}
	if created.Label != "laptop-agent-1" {
		t.Errorf("Label = %q, want %q", created.Label, "laptop-agent-1")
	}
	if !created.Active {
		t.Error("newly created agent token should be Active")
	}

	// The plaintext round-trips through the store's own authentication path
	// (the agent-tokens HTTP surface has no bearer-auth middleware of its own
	// in this PR — mcpserver wiring is a later PR — so this exercises the
	// store method the future middleware will call).
	agent, ok, err := st.AuthenticateAgentToken(t.Context(), created.Token)
	if err != nil {
		t.Fatalf("AuthenticateAgentToken() error = %v", err)
	}
	if !ok || agent.Subject != "agent-a" {
		t.Fatalf("AuthenticateAgentToken() = (%+v, %v), want (subject=agent-a, true)", agent, ok)
	}

	// It shows up in the listing, without the plaintext.
	tokens := decodeInto[[]agentTokenView](t, doJSON(t, http.MethodGet, srv.URL+"/api/agent-tokens", nil))
	found := false
	for _, tk := range tokens {
		if tk.ID == created.ID {
			found = true
			if tk.Subject != "agent-a" || tk.Label != "laptop-agent-1" {
				t.Errorf("listed agent token = %+v, want subject=agent-a label=laptop-agent-1", tk)
			}
		}
	}
	if !found {
		t.Error("newly created agent token not present in GET /api/agent-tokens")
	}

	// Revoke it (bearer-only, no TOTP code attached needed beyond doJSON's
	// default), then confirm it can no longer authenticate.
	resp = doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens/"+created.ID+"/revoke", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /api/agent-tokens/{id}/revoke status = %d, want 204", resp.StatusCode)
	}
	_, ok, err = st.AuthenticateAgentToken(t.Context(), created.Token)
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

// TestListAgentTokens_BearerOnly confirms GET /api/agent-tokens needs no
// second factor — only requireAuth (the outer Routes() wrap), no
// requireStrongFactor — since listing never returns a hash or plaintext.
func TestListAgentTokens_BearerOnly(t *testing.T) {
	srv, _ := testServer(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/agent-tokens", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	// Deliberately no X-Chuvar-TOTP-Code header.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/agent-tokens with a bearer token but no TOTP code: status = %d, want 200 (listing is bearer-only)", resp.StatusCode)
	}
}

// TestRevokeAgentToken_BearerOnly is listing's sibling: revocation only ever
// reduces authority, so it must not require a second factor either.
func TestRevokeAgentToken_BearerOnly(t *testing.T) {
	srv, st := testServer(t)

	tok, err := st.CreateAgentToken(t.Context(), "agent-a", "throwaway", "throwaway-plaintext")
	if err != nil {
		t.Fatalf("CreateAgentToken() error = %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/agent-tokens/"+tok.ID+"/revoke", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	// Deliberately no X-Chuvar-TOTP-Code header.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /api/agent-tokens/{id}/revoke with a bearer token but no TOTP code: status = %d, want 204 (revocation is bearer-only)", resp.StatusCode)
	}
}

func TestCreateAgentToken_MissingSubjectRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{Label: "laptop-agent-1"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/agent-tokens with no subject: status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateAgentToken_MissingLabelRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{Subject: "agent-a"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/agent-tokens with no label: status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateAgentToken_WhitespaceOnlyFieldsRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{Subject: "   ", Label: "laptop-agent-1"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/agent-tokens with a whitespace-only subject: status = %d, want 400", resp.StatusCode)
	}

	resp = doJSON(t, http.MethodPost, srv.URL+"/api/agent-tokens", createAgentTokenRequest{Subject: "agent-a", Label: "   "})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/agent-tokens with a whitespace-only label: status = %d, want 400", resp.StatusCode)
	}
}
