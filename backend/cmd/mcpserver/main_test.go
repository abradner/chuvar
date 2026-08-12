package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abradner/chuvar/backend/internal/agentclient"
)

// fakeAgentServer stands in for internal/api's AgentRoutes() whoami endpoint
// (agent_routes.go's agentWhoami) — just enough of its HTTP contract
// (Authorization: Bearer <token>, {"subject": "..."} on success,
// {"error": "..."} + 401 on a bad/missing token) to prove checkHealth's own
// branching, without dragging in a real database. The full-stack proof that
// the real backend and this exact code path compose correctly lives in
// internal/mcptools's TestCutover_AllToolsEndToEnd, which boots a real
// api.API; this file's job is narrower and specific to main.go: does
// checkHealth tell an unauthorized token apart from an unreachable server,
// and does it surface the resolved subject on success.
func fakeAgentServer(t *testing.T, wantToken, subject string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/agent/whoami", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if auth != "Bearer "+wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"subject": subject})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckHealth_Success(t *testing.T) {
	srv := fakeAgentServer(t, "good-token", "agent-under-test")
	client := &agentclient.Client{BaseURL: srv.URL, Token: "good-token", HTTP: &http.Client{}}

	subject, err := checkHealth(context.Background(), client)
	if err != nil {
		t.Fatalf("checkHealth() error = %v, want nil", err)
	}
	if subject != "agent-under-test" {
		t.Fatalf("checkHealth() subject = %q, want %q", subject, "agent-under-test")
	}
}

// TestCheckHealth_BadTokenFailsFastWithDistinctMessage is the revert-and-
// confirm target: a bad/revoked token must fail boot with a message that
// specifically calls out the token (via errors.Is(err, agentclient.ErrUnauthorized)),
// not the same generic "could not reach" text an unreachable backend gets
// below. See this package's PR report for the revert-and-confirm run: with
// the errors.Is branch in checkHealth deleted, this test fails because the
// returned message no longer mentions the token at all.
func TestCheckHealth_BadTokenFailsFastWithDistinctMessage(t *testing.T) {
	srv := fakeAgentServer(t, "good-token", "agent-under-test")
	client := &agentclient.Client{BaseURL: srv.URL, Token: "wrong-token", HTTP: &http.Client{}}

	_, err := checkHealth(context.Background(), client)
	if err == nil {
		t.Fatal("checkHealth() with a bad token succeeded, want an error")
	}
	if !errors.Is(err, agentclient.ErrUnauthorized) {
		t.Fatalf("checkHealth() error = %v, want it to wrap agentclient.ErrUnauthorized", err)
	}
	if !strings.Contains(err.Error(), "token") {
		t.Fatalf("checkHealth() error = %q, want it to mention the token (a distinct message from an unreachable backend)", err.Error())
	}
}

// TestCheckHealth_UnreachableBaseURLFailsFast is the other named failure
// mode: a backend that can't be reached at all (wrong host/port, nothing
// listening) must also fail boot, with a message that does NOT claim the
// token was rejected — that would misdirect an operator toward rotating a
// perfectly good token when the real problem is connectivity/configuration.
func TestCheckHealth_UnreachableBaseURLFailsFast(t *testing.T) {
	srv := fakeAgentServer(t, "good-token", "agent-under-test")
	unreachableURL := srv.URL
	srv.Close() // now nothing is listening at this URL

	client := &agentclient.Client{BaseURL: unreachableURL, Token: "good-token", HTTP: &http.Client{}}
	_, err := checkHealth(context.Background(), client)
	if err == nil {
		t.Fatal("checkHealth() against an unreachable base URL succeeded, want an error")
	}
	if errors.Is(err, agentclient.ErrUnauthorized) {
		t.Fatalf("checkHealth() error = %v, want it NOT to claim the token was rejected — the backend was unreachable, not the token bad", err)
	}
	if strings.Contains(err.Error(), "rejected") {
		t.Fatalf("checkHealth() error = %q, want it not to say the token was rejected for an unreachable backend", err.Error())
	}
}

// --- requiredSecret ---------------------------------------------------------

func TestRequiredSecret_MissingFailsFastWithVariableName(t *testing.T) {
	t.Setenv("CHUVAR_TEST_REQUIRED_SECRET", "")
	_, err := requiredSecret("CHUVAR_TEST_REQUIRED_SECRET")
	if err == nil {
		t.Fatal("requiredSecret() with nothing set succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "CHUVAR_TEST_REQUIRED_SECRET") {
		t.Fatalf("requiredSecret() error = %q, want it to name the missing variable", err.Error())
	}
}

func TestRequiredSecret_PresentSucceeds(t *testing.T) {
	t.Setenv("CHUVAR_TEST_REQUIRED_SECRET", "a-value")
	v, err := requiredSecret("CHUVAR_TEST_REQUIRED_SECRET")
	if err != nil {
		t.Fatalf("requiredSecret() error = %v, want nil", err)
	}
	if v != "a-value" {
		t.Fatalf("requiredSecret() = %q, want %q", v, "a-value")
	}
}
