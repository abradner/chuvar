package db

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestToPgx5URL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{
			name: "postgres scheme",
			in:   "postgres://user:pass@localhost:5433/chuvar?sslmode=disable",
			want: "pgx5://user:pass@localhost:5433/chuvar?sslmode=disable",
		},
		{
			name: "postgresql scheme",
			in:   "postgresql://user:pass@localhost:5433/chuvar",
			want: "pgx5://user:pass@localhost:5433/chuvar",
		},
		{
			name:    "unsupported scheme",
			in:      "mysql://user:pass@localhost:3306/chuvar",
			wantErr: true,
		},
		{
			name:    "empty scheme (non-URL DSN)",
			in:      "host=localhost dbname=chuvar",
			wantErr: true,
		},
		{
			name:    "unparseable URL",
			in:      "://not-a-url",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toPgx5URL(tt.in)
			if tt.wantErr {
				require.Error(t, err, "toPgx5URL(%q) = %q, want error", tt.in, got)
				return
			}
			require.NoError(t, err, "toPgx5URL(%q)", tt.in)
			require.Equal(t, tt.want, got, "toPgx5URL(%q)", tt.in)
		})
	}
}

// The invariant: a password must never reach an error that a command will log.
//
// This passes today with or without redactPassword, because pgx v5 sanitises
// the DSN itself — which is exactly why the assertion is worth having. It pins
// the property rather than the mechanism, so it keeps holding if the driver
// stops doing that for us.
//
// An invalid port rather than a bad percent-escape: pgxpool connects lazily, so
// most malformed DSNs return no error at all from New, and an earlier version of
// this test passed vacuously for that reason.
func TestOpenDoesNotLeakThePasswordInErrors(t *testing.T) {
	const secret = "sup3r-s3cret-pw"
	bad := "postgres://user:" + secret + "@localhost:99999/db"

	_, err := Open(context.Background(), bad)
	require.Error(t, err, "expected a parse failure; if this stops erroring the test proves nothing")
	require.NotContains(t, err.Error(), secret, "the password appeared in the error text")
}

func TestRedactPassword(t *testing.T) {
	t.Run("replaces the password wherever it appears", func(t *testing.T) {
		err := errors.New(`cannot parse "postgres://u:hunter2@h/db": bad`)
		got := redactPassword(err, "postgres://u:hunter2@h/db")
		require.NotContains(t, got.Error(), "hunter2")
		require.Contains(t, got.Error(), "[REDACTED]")
	})

	t.Run("passes through when there is no password to leak", func(t *testing.T) {
		err := errors.New("some failure")
		require.Equal(t, err, redactPassword(err, "postgres://u@h/db"))
	})

	t.Run("withholds detail when the DSN cannot be parsed", func(t *testing.T) {
		// If the password can't be located it can't be removed, so the error
		// text — which may embed it — must not be passed along.
		err := errors.New("cannot parse \x7f://bad:pw@h: nope")
		got := redactPassword(err, "\x7f://bad:pw@h")
		require.NotContains(t, got.Error(), "pw@h")
		require.Contains(t, got.Error(), "details withheld")
	})

	t.Run("nil stays nil", func(t *testing.T) {
		require.NoError(t, redactPassword(nil, "postgres://u:p@h/db"))
	})
}
