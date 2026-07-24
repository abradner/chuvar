package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/abradner/chuvar/backend/internal/db"
	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/store"
)

const testAuthToken = "test-token-do-not-use-in-prod"

func testServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping api integration tests")
	}
	if err := db.Migrate(url); err != nil {
		t.Fatalf("db.Migrate() error = %v", err)
	}

	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatalf("db.Open() error = %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := store.New(pool)
	a := New(st, embed.Stub{}, "http://localhost:5173", testAuthToken, 10*time.Second)
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)
	return srv, st
}

// doJSON sends an authenticated request (the common case for these tests — most
// of them are testing business logic, not the auth gate itself, which has its own
// dedicated tests below).
func doJSON(t *testing.T, method, url string, body any) *http.Response {
	t.Helper()
	return doJSONWithAuth(t, method, url, body, testAuthToken)
}

func doJSONWithAuth(t *testing.T, method, url string, body any, token string) *http.Response {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshaling request body: %v", err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func decodeInto[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding response body: %v", err)
	}
	return out
}

func TestRequireAuth_MissingTokenRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSONWithAuth(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /api/grants with no Authorization header: status = %d, want 401", resp.StatusCode)
	}
}

func TestRequireAuth_WrongTokenRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSONWithAuth(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil, "wrong-token")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /api/grants with wrong token: status = %d, want 401", resp.StatusCode)
	}
}

func TestRequireAuth_CorrectTokenAccepted(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/grants with correct token: status = %d, want 200", resp.StatusCode)
	}
}

func TestCreateAndListGrants(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		ApprovedBy: "human-reviewer",
		Subject:    "agent-a",
		Scopes:     []string{"identity.basic"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/grants status = %d, want 201", resp.StatusCode)
	}
	created := decodeInto[grantView](t, resp)
	if !created.Active {
		t.Error("created grant should be Active")
	}

	resp = doJSON(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/grants status = %d, want 200", resp.StatusCode)
	}
	grants := decodeInto[[]grantView](t, resp)
	if len(grants) != 1 {
		t.Fatalf("GET /api/grants returned %d grants, want 1", len(grants))
	}
}

func TestCreateGrant_InvalidScopeRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		ApprovedBy: "human-reviewer",
		Subject:    "agent-a",
		Scopes:     []string{"Not A Valid Scope"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with invalid scope: status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateGrant_InvalidDepthRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		ApprovedBy: "human-reviewer",
		Subject:    "agent-a",
		Scopes:     []string{"identity.basic"},
		Depth:      "bogus",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with invalid depth: status = %d, want 400", resp.StatusCode)
	}
	body := decodeInto[errorResponse](t, resp)
	if body.Error == "" {
		t.Error("expected a clean validation message, got empty error")
	}
	// This is the regression case from review: an invalid depth used to reach
	// Postgres's CHECK constraint and leak a raw driver error (constraint name,
	// SQLSTATE) as a 500. It must now be caught before ever reaching the store.
	if want := "depth must be one of"; len(body.Error) < len(want) || body.Error[:len(want)] != want {
		t.Errorf("error message = %q, want it to start with %q (a clean validation message, not a raw driver error)", body.Error, want)
	}
}

func TestCreateGrant_NegativeTTLRejected(t *testing.T) {
	srv, _ := testServer(t)

	negative := -60
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		ApprovedBy: "human-reviewer",
		Subject:    "agent-a",
		Scopes:     []string{"identity.basic"},
		TTLSeconds: &negative,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with negative ttl_seconds: status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateGrant_DuplicateScopesRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		ApprovedBy: "human-reviewer",
		Subject:    "agent-a",
		Scopes:     []string{"identity.basic", "identity.basic"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with duplicate scopes: status = %d, want 400", resp.StatusCode)
	}
	// This is the regression case from review: a duplicate scope used to reach
	// grant_scopes' (grant_id, scope) primary key and come back as a 500 instead
	// of a clean 400.
	body := decodeInto[errorResponse](t, resp)
	if body.Error == "" {
		t.Error("expected a clean validation message, got empty error")
	}
}

func TestCreateGrant_TTLTooLargeRejected(t *testing.T) {
	srv, _ := testServer(t)

	huge := maxGrantTTLSeconds + 1
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		ApprovedBy: "human-reviewer",
		Subject:    "agent-a",
		Scopes:     []string{"identity.basic"},
		TTLSeconds: &huge,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with ttl_seconds over max: status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateGrant_MissingApprovedByRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		Subject: "agent-a",
		Scopes:  []string{"identity.basic"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with no approved_by: status = %d, want 400", resp.StatusCode)
	}
}

func TestRevokeGrant_MissingRevokedByRejected(t *testing.T) {
	srv, _ := testServer(t)

	created := decodeInto[grantView](t, doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		ApprovedBy: "human-reviewer",
		Subject:    "agent-a",
		Scopes:     []string{"identity.basic"},
	}))

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants/"+created.ID+"/revoke", revokeGrantRequest{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST revoke with no revoked_by: status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateGrant_EmptyScopesRejected(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		ApprovedBy: "human-reviewer",
		Subject:    "agent-a",
		Scopes:     []string{},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with no scopes: status = %d, want 400", resp.StatusCode)
	}
}

func TestRevokeGrant(t *testing.T) {
	srv, _ := testServer(t)

	created := decodeInto[grantView](t, doJSON(t, http.MethodPost, srv.URL+"/api/grants", createGrantRequest{
		ApprovedBy: "human-reviewer",
		Subject:    "agent-a",
		Scopes:     []string{"identity.basic"},
	}))

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants/"+created.ID+"/revoke", revokeGrantRequest{RevokedBy: "human-reviewer"})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST revoke status = %d, want 204", resp.StatusCode)
	}

	grants := decodeInto[[]grantView](t, doJSON(t, http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil))
	if len(grants) != 1 || grants[0].Active {
		t.Fatalf("grant after revoke = %+v, want present but not Active", grants)
	}

	// Revoking again should fail, not silently succeed.
	resp = doJSON(t, http.MethodPost, srv.URL+"/api/grants/"+created.ID+"/revoke", revokeGrantRequest{RevokedBy: "human-reviewer"})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST revoke (already revoked) status = %d, want 409", resp.StatusCode)
	}
}

func TestStagedDiffs_ListApproveReject(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()

	vec := []float32{1, 0, 0}
	vec384 := make([]float32, 384)
	copy(vec384, vec)

	approveMe, err := st.ProposeDiff(ctx, "agent-a", "user likes tea", []string{"preferences.tea"}, vec384, nil, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	rejectMe, err := st.ProposeDiff(ctx, "agent-a", "user likes coffee", []string{"preferences.coffee"}, vec384, nil, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}

	pending := decodeInto[[]stagedDiffView](t, doJSON(t, http.MethodGet, srv.URL+"/api/staged-diffs?status=pending", nil))
	if len(pending) != 2 {
		t.Fatalf("pending diffs = %d, want 2", len(pending))
	}

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/staged-diffs/"+approveMe.ID+"/approve", decisionRequest{DecidedBy: "test-reviewer"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST approve status = %d, want 200", resp.StatusCode)
	}

	resp = doJSON(t, http.MethodPost, srv.URL+"/api/staged-diffs/"+rejectMe.ID+"/reject", decisionRequest{DecidedBy: "test-reviewer"})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST reject status = %d, want 204", resp.StatusCode)
	}

	stillPending := decodeInto[[]stagedDiffView](t, doJSON(t, http.MethodGet, srv.URL+"/api/staged-diffs?status=pending", nil))
	if len(stillPending) != 0 {
		t.Fatalf("pending diffs after decisions = %d, want 0", len(stillPending))
	}
}

func TestGetFact_ViaAPI(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()

	vec := make([]float32, 384)
	vec[0] = 1
	d, err := st.ProposeDiff(ctx, "agent-a", "user's favorite color is teal", []string{"preferences.color"}, vec, nil, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}
	fact, err := st.CommitDiff(ctx, d.ID, "human-reviewer", vec)
	if err != nil {
		t.Fatalf("CommitDiff() error = %v", err)
	}

	resp := doJSON(t, http.MethodGet, srv.URL+"/api/facts/"+fact.ID, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/facts/{id} status = %d, want 200", resp.StatusCode)
	}
	got := decodeInto[factView](t, resp)
	if got.Content != "user's favorite color is teal" {
		t.Errorf("GET /api/facts/{id} content = %q, want the fact's content", got.Content)
	}

	resp = doJSON(t, http.MethodGet, srv.URL+"/api/facts/00000000-0000-0000-0000-000000000000", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /api/facts/{id} for nonexistent fact: status = %d, want 404", resp.StatusCode)
	}
}

func TestApproveStagedDiff_MissingDecidedByRejected(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()

	vec := make([]float32, 384)
	diff, err := st.ProposeDiff(ctx, "agent-a", "user likes tea", []string{"preferences.tea"}, vec, nil, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}

	// Regression case from review: a missing/empty decided_by used to silently
	// become "unknown-reviewer" in the permanent audit trail rather than being
	// rejected. It must now be a 400, and the diff must remain untouched (still
	// pending, not committed).
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/staged-diffs/"+diff.ID+"/approve", decisionRequest{DecidedBy: ""})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST approve with empty decided_by: status = %d, want 400", resp.StatusCode)
	}

	pending := decodeInto[[]stagedDiffView](t, doJSON(t, http.MethodGet, srv.URL+"/api/staged-diffs?status=pending", nil))
	found := false
	for _, d := range pending {
		if d.ID == diff.ID {
			found = true
		}
	}
	if !found {
		t.Error("diff should still be pending after a rejected approve request, but it's gone from the pending list")
	}
}

func TestApproveStagedDiff_NotFoundReturnsCleanError(t *testing.T) {
	srv, _ := testServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/api/staged-diffs/00000000-0000-0000-0000-000000000000/approve",
		decisionRequest{DecidedBy: "test-reviewer"})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST approve for nonexistent diff: status = %d, want 404", resp.StatusCode)
	}
	body := decodeInto[errorResponse](t, resp)
	if body.Error != "staged diff not found" {
		t.Errorf("error message = %q, want a clean not-found message, not a raw store/driver error", body.Error)
	}
}

func TestRoutes_CORSReflectsConfiguredOriginOnly(t *testing.T) {
	srv, _ := testServer(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/grants?subject=agent-a", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()

	got := resp.Header.Get("Access-Control-Allow-Origin")
	if got != "http://localhost:5173" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the configured origin, not a wildcard", got)
	}
}

func TestRoutes_OPTIONSPreflightDoesNotRequireAuth(t *testing.T) {
	srv, _ := testServer(t)

	// Browsers never send Authorization on a CORS preflight OPTIONS request — if
	// the auth check ran before CORS, every real cross-origin request from the
	// frontend would fail at the preflight stage before the browser ever got a
	// chance to attach the real request's Authorization header.
	req, err := http.NewRequest(http.MethodOptions, srv.URL+"/api/grants", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Origin", "http://localhost:5173")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("OPTIONS preflight with no Authorization header: status = %d, want 204", resp.StatusCode)
	}
}

func TestNew_WildcardOriginRejected(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New() with CORS_ALLOWED_ORIGIN=\"*\": want panic, got none")
		}
	}()
	New(nil, nil, "*", testAuthToken, 10*time.Second)
}

func TestNew_NullOriginRejected(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal(`New() with CORS_ALLOWED_ORIGIN="null": want panic, got none`)
		}
	}()
	New(nil, nil, "null", testAuthToken, 10*time.Second)
}

func TestNew_OriginWithPathRejected(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New() with a CORS_ALLOWED_ORIGIN containing a path: want panic, got none")
		}
	}()
	New(nil, nil, "http://localhost:5173/app", testAuthToken, 10*time.Second)
}

func TestNew_NonPositiveRequestTimeoutRejected(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New() with a zero RequestTimeout: want panic, got none")
		}
	}()
	New(nil, nil, "", testAuthToken, 0)
}

// slowThenCheckContextEmbedder sleeps past the request timeout, then reports
// whether the context it was given had already been cancelled by the time it
// woke up — the actual thing under test, not just "did the HTTP call time out."
type slowThenCheckContextEmbedder struct {
	sleep    time.Duration
	canceled chan bool
}

func (e slowThenCheckContextEmbedder) Embed(ctx context.Context, _ string) ([]float32, error) {
	select {
	case <-time.After(e.sleep):
		e.canceled <- false
	case <-ctx.Done():
		e.canceled <- true
	}
	return nil, ctx.Err()
}

func TestWithRequestTimeout_CancelsSlowHandlerContext(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping api integration tests")
	}
	if err := db.Migrate(url); err != nil {
		t.Fatalf("db.Migrate() error = %v", err)
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatalf("db.Open() error = %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE facts, fact_scopes, grants, grant_scopes, staged_diffs, audit_log`); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	st := store.New(pool)
	canceled := make(chan bool, 1)
	// RequestTimeout much shorter than the embedder's sleep: without
	// withRequestTimeout wiring a.RequestTimeout into the handler's context, the
	// embedder would just sleep out its full duration and report canceled=false.
	a := New(st, slowThenCheckContextEmbedder{sleep: 200 * time.Millisecond, canceled: canceled}, "", testAuthToken, 20*time.Millisecond)
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)

	diff, err := st.ProposeDiff(ctx, "agent-a", "user likes tea", []string{"preferences.tea"}, nil, nil, nil)
	if err != nil {
		t.Fatalf("ProposeDiff() error = %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/staged-diffs/"+diff.ID+"/approve",
		bytes.NewReader([]byte(`{"decided_by":"human-reviewer"}`)))
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

	select {
	case wasCanceled := <-canceled:
		if !wasCanceled {
			t.Fatal("embedder's context was never canceled — a.RequestTimeout is not reaching the handler's context")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("embedder never reported back — handler likely hung")
	}
}

func TestLimitBody_OversizedRequestRejected(t *testing.T) {
	srv, _ := testServer(t)

	// Subject has no length validation of its own anywhere in createGrant — that's
	// deliberate here: a check on Subject's length would give this test the same
	// right-status-wrong-reason problem an oversized Scopes entry has (scope.Validate's
	// own MaxLength would reject it first, never exercising MaxBytesReader at all).
	// Without the body limit, this request would fully decode and succeed (201); the
	// limit has to be what turns it into a body-read failure instead.
	oversized := createGrantRequest{
		ApprovedBy: "human-reviewer",
		Subject:    strings.Repeat("a", maxRequestBodyBytes+1),
		Scopes:     []string{"identity.basic"},
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/api/grants", oversized)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /api/grants with an oversized body: status = %d, want 400", resp.StatusCode)
	}
}
