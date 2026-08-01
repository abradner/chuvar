package db

import (
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
