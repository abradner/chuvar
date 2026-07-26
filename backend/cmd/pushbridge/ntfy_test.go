package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNtfyNotifier_PostsTitleMessageAndClickLink(t *testing.T) {
	var gotTitle, gotClick, gotBody, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotTitle = r.Header.Get("Title")
		gotClick = r.Header.Get("Click")
		// io.ReadAll, not a single Read() call: Read is not guaranteed to fill
		// the buffer or return the whole body in one call — a single call can
		// flake or truncate on a body split across reads. Found in review.
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &ntfyNotifier{baseURL: srv.URL, topic: "chuvar-test", http: srv.Client()}
	if err := n.notify(context.Background(), "New staged diff from agent-a", "user likes tea", "http://localhost:5173"); err != nil {
		t.Fatalf("notify() error = %v", err)
	}

	if gotPath != "/chuvar-test" {
		t.Errorf("path = %q, want /chuvar-test (posted to the configured topic)", gotPath)
	}
	if gotTitle != "New staged diff from agent-a" {
		t.Errorf("Title header = %q", gotTitle)
	}
	if gotClick != "http://localhost:5173" {
		t.Errorf("Click header = %q", gotClick)
	}
	if gotBody != "user likes tea" {
		t.Errorf("body = %q, want the message text", gotBody)
	}
}

func TestNtfyNotifier_ServerErrorIsReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := &ntfyNotifier{baseURL: srv.URL, topic: "chuvar-test", http: srv.Client()}
	if err := n.notify(context.Background(), "t", "m", ""); err == nil {
		t.Fatal("notify() with a 500 response: want an error, got nil")
	}
}

func TestSanitizeHeader_StripsNewlines(t *testing.T) {
	got := sanitizeHeader("line one\nline two\r\nline three")
	if got != "line one line two  line three" {
		t.Errorf("sanitizeHeader() = %q", got)
	}
}
