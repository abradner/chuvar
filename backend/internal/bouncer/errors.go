package bouncer

import "fmt"

// ValidationError marks an error returned by ProposeWrite as a genuine,
// caller-input validation failure: the proposing agent supplied something
// malformed (an invalid scope string, empty content, no scopes at all), and
// showing that message back to the agent verbatim is both safe (it never
// contains store/driver internals) and useful (the agent can self-correct and
// retry). mcptools.propose_write uses errors.As to detect this type and, only
// for these, skips the generic "internal error" masking every other error out
// of ProposeWrite gets.
//
// Fail closed: this type is opt-in, not opt-out. Every other failure path in
// ProposeWrite — a nil Classifier/Embedder/Store misconfiguration, a Classifier
// or Embedder call failing, or anything that comes back from the Store (which
// may embed raw pgx/driver text) — deliberately stays a plain wrapped error, not
// a ValidationError. An error that isn't positively constructed as one of these
// never becomes "safe to show verbatim" by accident.
type ValidationError struct {
	msg string
}

func (e *ValidationError) Error() string { return e.msg }

// newValidationError builds a ValidationError from a formatted message. It
// intentionally never wraps another error with %w: that would let
// errors.As(err, &ValidationError{}) walk into whatever chain that other error
// carries (e.g. a store/pgx error passed through here by a future edit) and
// mask it as safe-to-show. Any upstream error text this needs to include must be
// interpolated as a value (%s/%v), which flattens it to a string and breaks the
// chain, not forwarded via %w.
func newValidationError(format string, args ...any) error {
	return &ValidationError{msg: fmt.Sprintf(format, args...)}
}
