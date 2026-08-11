package broker

// Request is brokerd's socket protocol request: one JSON object per line,
// one request per connection (see socket.go's doc comment for why the
// connection isn't kept open for multiple requests). Deliberately NOT the
// ssh-agent protocol — capability-broker.md's "The broker must not
// blind-sign" section explains why a generic agent SIGN_REQUEST is exactly
// the surface this design forbids.
type Request struct {
	// Op selects the operation: "preflight" or "sign".
	Op string `json:"op"`

	// Token is the per-grant pre-shared socket-auth token (plaintext, over
	// a connection already gated by filesystem permissions and SO_PEERCRED
	// — see socket.go). It is the sole credential: the broker derives which
	// grant is being invoked from the token itself (Cache.Lookup), rather
	// than trusting a separately-supplied grant id that could name a
	// different grant than the one the token actually authenticates. See
	// AGENTS.md §6: "actor identity derives from the authenticated
	// credential, never the request body."
	Token string `json:"token"`

	// Scope is the capability scope being invoked, e.g.
	// "git.sign:github.com/abradner/chuvar" — checked against the token's
	// grant via scope.Covers.
	Scope string `json:"scope"`

	// Payload is the exact bytes to sign — a git commit object, still
	// unsigned. Only meaningful for Op == "sign"; ignored for "preflight".
	// encoding/json base64-encodes a []byte field automatically, so the
	// wire format is ordinary JSON despite payload being arbitrary binary.
	Payload []byte `json:"payload,omitempty"`
}
