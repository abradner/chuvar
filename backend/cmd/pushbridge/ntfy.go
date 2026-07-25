package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// ntfyNotifier posts to an ntfy (https://ntfy.sh, or a self-hosted instance —
// NTFY_URL) topic. ntfy's publish API is deliberately simple: an HTTP request
// whose body is the message text, with metadata (title, click-through link,
// priority) as headers — no client library needed for something this small.
type ntfyNotifier struct {
	baseURL string
	topic   string
	http    *http.Client
}

// notify posts one message. title and link are optional (empty means omit that
// header); ntfy handles a missing Title by falling back to the topic name and a
// missing Click by just not making the notification tappable.
func (n *ntfyNotifier) notify(ctx context.Context, title, message, link string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.baseURL+"/"+n.topic, strings.NewReader(message))
	if err != nil {
		return fmt.Errorf("pushbridge: building ntfy request: %w", err)
	}
	if title != "" {
		// Go's net/http already refuses to send a header value containing a raw
		// CR/LF (no injection risk), but it does so by failing the whole
		// request — which here means silently dropping the notification via
		// the logged error path in main.go. Staged-diff content and grant
		// justifications are agent-supplied free text (mcptools bounds their
		// length, not their character set) and end up in this Title header, so
		// stripping newlines here is what keeps a routine multi-line fact from
		// quietly failing to notify at all.
		req.Header.Set("Title", sanitizeHeader(title))
	}
	if link != "" {
		req.Header.Set("Click", sanitizeHeader(link))
	}

	resp, err := n.http.Do(req)
	if err != nil {
		return fmt.Errorf("pushbridge: posting to ntfy: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("pushbridge: ntfy responded with status %d", resp.StatusCode)
	}
	return nil
}

func sanitizeHeader(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}
