package agentclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestClient wires a Client at srv with the given token.
func newTestClient(srv *httptest.Server, token string) *Client {
	return &Client{BaseURL: srv.URL, Token: token, HTTP: srv.Client()}
}

// --- round-trip: request shape ---------------------------------------------

func TestSearch_RoundTrip(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotContentType string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","facts":[{"id":"f1","content":"user likes tea","depth":"facts","scopes":["identity.basic"]}]}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "secret-agent-token")
	out, err := c.Search(context.Background(), SearchRequest{Query: "tea", RequestedScopes: []string{"identity.basic"}, Limit: 5})
	if err != nil {
		t.Fatalf("Search returned error: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/agent/search" {
		t.Errorf("path = %q, want /api/agent/search", gotPath)
	}
	if gotAuth != "Bearer secret-agent-token" {
		t.Errorf("Authorization = %q, want Bearer secret-agent-token", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}

	var sentReq SearchRequest
	if err := json.Unmarshal(gotBody, &sentReq); err != nil {
		t.Fatalf("could not decode sent body: %v", err)
	}
	if sentReq.Query != "tea" || sentReq.Limit != 5 || len(sentReq.RequestedScopes) != 1 || sentReq.RequestedScopes[0] != "identity.basic" {
		t.Errorf("sent request = %+v, want Query=tea Limit=5 RequestedScopes=[identity.basic]", sentReq)
	}

	if out.Status != StatusOK {
		t.Errorf("Status = %q, want %q", out.Status, StatusOK)
	}
	if len(out.Facts) != 1 || out.Facts[0].ID != "f1" || out.Facts[0].Content != "user likes tea" {
		t.Errorf("Facts = %+v, want one fact f1 with content 'user likes tea'", out.Facts)
	}
}

func TestPropose_RoundTrip(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"diff_id":"d1","status":"pending","dedupe_verdict":"novel"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	out, err := c.Propose(context.Background(), ProposeRequest{Content: "user likes tea", ProposedScopes: []string{"identity.basic"}})
	if err != nil {
		t.Fatalf("Propose returned error: %v", err)
	}

	if gotMethod != http.MethodPost || gotPath != "/api/agent/proposals" {
		t.Errorf("got %s %s, want POST /api/agent/proposals", gotMethod, gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want Bearer tok", gotAuth)
	}

	var sentReq ProposeRequest
	if err := json.Unmarshal(gotBody, &sentReq); err != nil {
		t.Fatalf("could not decode sent body: %v", err)
	}
	if sentReq.Content != "user likes tea" {
		t.Errorf("sent Content = %q, want %q", sentReq.Content, "user likes tea")
	}

	if out.DiffID != "d1" || out.Status != "pending" || out.DedupeVerdict != "novel" {
		t.Errorf("out = %+v, want DiffID=d1 Status=pending DedupeVerdict=novel", out)
	}
}

func TestListGrants_RoundTrip(t *testing.T) {
	var gotMethod, gotPath, gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"grants":[{"id":"g1","scopes":["identity.basic"],"depth":"facts","active":true}]}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	out, err := c.ListGrants(context.Background())
	if err != nil {
		t.Fatalf("ListGrants returned error: %v", err)
	}

	if gotMethod != http.MethodGet || gotPath != "/api/agent/grants" {
		t.Errorf("got %s %s, want GET /api/agent/grants", gotMethod, gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want Bearer tok", gotAuth)
	}
	if len(out.Grants) != 1 || out.Grants[0].ID != "g1" || !out.Grants[0].Active {
		t.Errorf("Grants = %+v, want one active grant g1", out.Grants)
	}
}

func TestRequestGrant_RoundTrip(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"request_id":"r1","status":"pending"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	out, err := c.RequestGrant(context.Background(), GrantRequestRequest{
		RequestedScopes: []string{"identity.basic"},
		Depth:           "facts",
		TTLSeconds:      3600,
		Justification:   "need it",
	})
	if err != nil {
		t.Fatalf("RequestGrant returned error: %v", err)
	}

	if gotMethod != http.MethodPost || gotPath != "/api/agent/grant-requests" {
		t.Errorf("got %s %s, want POST /api/agent/grant-requests", gotMethod, gotPath)
	}

	var sentReq GrantRequestRequest
	if err := json.Unmarshal(gotBody, &sentReq); err != nil {
		t.Fatalf("could not decode sent body: %v", err)
	}
	if sentReq.TTLSeconds != 3600 || sentReq.Justification != "need it" {
		t.Errorf("sent request = %+v, want TTLSeconds=3600 Justification='need it'", sentReq)
	}

	if out.RequestID != "r1" || out.Status != "pending" {
		t.Errorf("out = %+v, want RequestID=r1 Status=pending", out)
	}
}

func TestWhoami_RoundTrip(t *testing.T) {
	var gotMethod, gotPath, gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"subject":"agent-a"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	out, err := c.Whoami(context.Background())
	if err != nil {
		t.Fatalf("Whoami returned error: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/api/agent/whoami" {
		t.Errorf("got %s %s, want GET /api/agent/whoami", gotMethod, gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want Bearer tok", gotAuth)
	}
	if out.Subject != "agent-a" {
		t.Errorf("Subject = %q, want agent-a", out.Subject)
	}
}

// --- error mapping ------------------------------------------------------

// jsonHandler builds an httptest server that always responds with the given
// status and body, regardless of method/path — enough for the error-mapping
// tests below, which only care about how each Client method reacts to a
// given response, not the request it sent (round-trip tests above already
// cover that).
func jsonHandler(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func TestSearch_401IsTypedAuthError(t *testing.T) {
	srv := httptest.NewServer(jsonHandler(http.StatusUnauthorized, `{"error":"unauthorized"}`))
	defer srv.Close()

	c := newTestClient(srv, "bad-token")
	_, err := c.Search(context.Background(), SearchRequest{Query: "x"})
	if err == nil {
		t.Fatal("Search() with a 401 response: want an error, got nil")
	}
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("errors.Is(err, ErrUnauthorized) = false, err = %v", err)
	}
	if strings.Contains(err.Error(), "bad-token") {
		t.Errorf("error message leaks the token: %v", err)
	}
}

func TestPropose_429IsStructuredResultNotError(t *testing.T) {
	srv := httptest.NewServer(jsonHandler(http.StatusTooManyRequests, `{"status":"RATE_LIMITED"}`))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	out, err := c.Propose(context.Background(), ProposeRequest{Content: "x", ProposedScopes: []string{"identity.basic"}})
	if err != nil {
		t.Fatalf("Propose() with a 429 response: want a structured result, got error: %v", err)
	}
	if out.Status != StatusRateLimited {
		t.Errorf("Status = %q, want %q", out.Status, StatusRateLimited)
	}
}

func TestSearch_InsufficientScopeIsStructuredResultNotError(t *testing.T) {
	srv := httptest.NewServer(jsonHandler(http.StatusOK, `{"status":"insufficient_scope","missing_scopes":["identity.basic"]}`))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	out, err := c.Search(context.Background(), SearchRequest{Query: "x", RequestedScopes: []string{"identity.basic"}})
	if err != nil {
		t.Fatalf("Search() with insufficient_scope: want a structured result, got error: %v", err)
	}
	if out.Status != StatusInsufficientScope {
		t.Errorf("Status = %q, want %q", out.Status, StatusInsufficientScope)
	}
	if len(out.MissingScopes) != 1 || out.MissingScopes[0] != "identity.basic" {
		t.Errorf("MissingScopes = %v, want [identity.basic]", out.MissingScopes)
	}
}

func TestRequestGrant_400CarriesServerMessageVerbatim(t *testing.T) {
	const msg = "requested_scopes exceeds max of 50"
	srv := httptest.NewServer(jsonHandler(http.StatusBadRequest, fmt.Sprintf(`{"error":%q}`, msg)))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	_, err := c.RequestGrant(context.Background(), GrantRequestRequest{RequestedScopes: []string{"x"}})
	if err == nil {
		t.Fatal("RequestGrant() with a 400 response: want an error, got nil")
	}
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("error is not a *ValidationError: %v (%T)", err, err)
	}
	if verr.Message != msg {
		t.Errorf("Message = %q, want %q", verr.Message, msg)
	}
	if err.Error() != msg {
		t.Errorf("Error() = %q, want the server message verbatim: %q", err.Error(), msg)
	}
}

func TestWhoami_500IsGenericErrorNoLeakage(t *testing.T) {
	// writeStoreError would put a client-safe message here in the real
	// server, but this test simulates the worst case (raw internal detail
	// somehow reaching the body) to prove the client never surfaces it.
	srv := httptest.NewServer(jsonHandler(http.StatusInternalServerError, `{"error":"pq: relation \"agent_tokens\" secret leak detail"}`))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	_, err := c.Whoami(context.Background())
	if err == nil {
		t.Fatal("Whoami() with a 500 response: want an error, got nil")
	}
	if strings.Contains(err.Error(), "pq:") || strings.Contains(err.Error(), "secret leak detail") {
		t.Errorf("error leaks internal server detail: %v", err)
	}
	var verr *ValidationError
	if errors.As(err, &verr) {
		t.Errorf("500 must not decode as a *ValidationError, got: %v", verr)
	}
}

func TestListGrants_TransportFailureIsGenericError(t *testing.T) {
	// A server that isn't listening at all: Do() itself fails.
	c := &Client{BaseURL: "http://127.0.0.1:1", Token: "tok", HTTP: &http.Client{}}
	_, err := c.ListGrants(context.Background())
	if err == nil {
		t.Fatal("ListGrants() against an unreachable server: want an error, got nil")
	}
	if errors.Is(err, ErrUnauthorized) {
		t.Errorf("transport failure must not be reported as ErrUnauthorized: %v", err)
	}
}

// --- token/body hygiene ---------------------------------------------------

func TestToken_NeverLoggedOrInErrorMessage(t *testing.T) {
	const token = "super-secret-agent-token-xyz"
	srv := httptest.NewServer(jsonHandler(http.StatusBadRequest, `{"error":"bad request"}`))
	defer srv.Close()

	c := newTestClient(srv, token)
	_, err := c.Search(context.Background(), SearchRequest{Query: "x"})
	if err == nil {
		t.Fatal("want an error from a 400 response")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error message contains the bearer token: %v", err)
	}
}

// --- bounded reads -----------------------------------------------------

// roundTripperFunc adapts a function to http.RoundTripper, letting the
// bounded-read test below fabricate a response with a body that never runs
// out of data — deterministically, with no real network/TCP buffering
// involved (and so no risk of the test itself hanging on OS socket timing).
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// countingInfiniteReader never returns EOF and counts every byte it hands
// out, so the test can assert exactly how much the client actually
// consumed.
type countingInfiniteReader struct{ n int64 }

func (r *countingInfiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	atomic.AddInt64(&r.n, int64(len(p)))
	return len(p), nil
}

// TestResponseBodyIsBounded proves a huge/unbounded response body is capped
// rather than read in full: the fabricated response body never returns EOF
// on its own, so if doJSON's io.LimitReader (agentclient.go) were missing,
// io.ReadAll would spin forever and this test would hang and time out. It
// returning promptly, with a decode error and with the byte count capped at
// maxResponseBodyBytes, is the proof the bound is actually wired in — not
// just that a huge body happens to fail to decode.
func TestResponseBodyIsBounded(t *testing.T) {
	reader := &countingInfiniteReader{}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(reader),
	}
	rt := roundTripperFunc(func(*http.Request) (*http.Response, error) { return resp, nil })
	c := &Client{BaseURL: "http://agentclient.invalid", Token: "tok", HTTP: &http.Client{Transport: rt}}

	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		_, err := c.ListGrants(context.Background())
		done <- result{err: err}
	}()

	select {
	case res := <-done:
		if res.err == nil {
			t.Fatal("ListGrants() against an unbounded body: want a decode error, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ListGrants() did not return promptly against an unbounded response body — the read is not bounded")
	}

	if got := atomic.LoadInt64(&reader.n); got > maxResponseBodyBytes {
		t.Errorf("client read %d bytes, want at most maxResponseBodyBytes=%d", got, maxResponseBodyBytes)
	}
	if got := atomic.LoadInt64(&reader.n); got == 0 {
		t.Error("client read 0 bytes, test fixture is broken")
	}
}
