// Cursor pagination shared by every listing endpoint that needs it (today:
// GET /api/staged-diffs, GET /api/grants). See store.ListCursor's doc comment
// for why keyset, not offset: the tables these listings page over keep
// gaining and losing rows while a reviewer works through them, and offset
// pagination silently skips or repeats rows across that churn.
package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/abradner/chuvar/backend/internal/store"
)

// defaultListLimit is the page size a paginated listing endpoint uses when
// the caller doesn't specify ?limit= — "no limit" must mean "the default,"
// never "unbounded" (the whole point of this ticket). maxListLimit bounds how
// large a single page can be requested, the same way maxScopesPerGrant/
// maxGrantTTLSeconds bound their own inputs elsewhere in this package: a
// client asking for limit=10000000 shouldn't be able to turn a paginated
// endpoint back into the unbounded one it replaced.
const (
	defaultListLimit = 50
	maxListLimit     = 200
)

// parseListLimit reads and validates the ?limit= query parameter, defaulting
// to defaultListLimit when absent. A present-but-invalid value (non-numeric,
// zero, negative, or over maxListLimit) is a clean 400, not a silent clamp —
// matching this package's existing stance on out-of-range input (see
// createGrant's maxScopesPerGrant/maxGrantTTLSeconds checks).
func parseListLimit(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return defaultListLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("limit must be a positive integer (got %q)", raw)
	}
	if n > maxListLimit {
		return 0, fmt.Errorf("limit exceeds max of %d (got %d)", maxListLimit, n)
	}
	return n, nil
}

// parseListCursor decodes a ?cursor= value produced by encodeCursor into a
// store.ListCursor. Returns (nil, nil) when cursor is absent — "no cursor"
// means "first page," not an error. Any present-but-malformed value (not our
// own base64 token, or missing/unparseable fields) is a 400: an opaque cursor
// is not meant to be hand-constructed, but a bit-flipped/truncated one from a
// client should read as a clear input error, not a raw parse panic or a
// query that silently returns the wrong page.
func parseListCursor(r *http.Request) (*store.ListCursor, error) {
	raw := r.URL.Query().Get("cursor")
	if raw == "" {
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor")
	}
	parts := strings.SplitN(string(decoded), "|", 2)
	if len(parts) != 2 || parts[1] == "" {
		return nil, fmt.Errorf("invalid cursor")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid cursor")
	}
	return &store.ListCursor{CreatedAt: createdAt, ID: parts[1]}, nil
}

// encodeCursor renders a store.ListCursor as the opaque token handed back to
// the client as next_cursor — the exact inverse of parseListCursor. Base64
// rather than a bare "timestamp|id" string so the wire format stays visibly
// opaque (not something a client is invited to construct or parse itself).
func encodeCursor(c store.ListCursor) string {
	raw := c.CreatedAt.UTC().Format(time.RFC3339Nano) + "|" + c.ID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// nextCursorFor returns the next_cursor value for a page response, or nil
// when hasMore is false — nil (omitted from the JSON response, see page's
// omitempty tag) is how a client tells "no further page" apart from "there
// is one, go fetch it."
func nextCursorFor(hasMore bool, createdAt time.Time, id string) *string {
	if !hasMore {
		return nil
	}
	c := encodeCursor(store.ListCursor{CreatedAt: createdAt, ID: id})
	return &c
}

// page is the JSON envelope every cursor-paginated listing endpoint responds
// with. next_cursor is omitted, not null, when no further page exists.
type page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor,omitempty"`
}
