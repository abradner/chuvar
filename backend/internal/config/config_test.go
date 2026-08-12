package config

import (
	"testing"
	"time"
)

func TestLoad_MissingRequiredVar(t *testing.T) {
	t.Setenv("DATABASE_URL", "")

	if _, err := Load(); err == nil {
		t.Fatal("expected an error when DATABASE_URL is unset, got nil")
	}
}

func TestLoad_Defaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost:54322/chuvar")
	t.Setenv("HTTP_ADDR", "")
	t.Setenv("CHUVAR_AGENT_ADDR", "")
	t.Setenv("REQUEST_TIMEOUT", "")
	t.Setenv("PROPOSE_WRITE_RATE_LIMIT", "")
	t.Setenv("PROPOSE_WRITE_RATE_LIMIT_WINDOW", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.HTTPAddr != "127.0.0.1:8080" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, "127.0.0.1:8080")
	}
	if cfg.AgentAddr != "127.0.0.1:8081" {
		t.Errorf("AgentAddr = %q, want %q", cfg.AgentAddr, "127.0.0.1:8081")
	}
	if cfg.RequestTimeout != 10*time.Second {
		t.Errorf("RequestTimeout = %v, want %v", cfg.RequestTimeout, 10*time.Second)
	}
	if cfg.ProposeWriteRateLimit != 20 {
		t.Errorf("ProposeWriteRateLimit = %d, want 20", cfg.ProposeWriteRateLimit)
	}
	if cfg.ProposeWriteRateLimitWindow != time.Minute {
		t.Errorf("ProposeWriteRateLimitWindow = %v, want %v", cfg.ProposeWriteRateLimitWindow, time.Minute)
	}
}

func TestLoad_OverridesApplied(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost:54322/chuvar")
	t.Setenv("HTTP_ADDR", ":9090")
	t.Setenv("CHUVAR_AGENT_ADDR", ":9091")
	t.Setenv("REQUEST_TIMEOUT", "30s")
	t.Setenv("PROPOSE_WRITE_RATE_LIMIT", "5")
	t.Setenv("PROPOSE_WRITE_RATE_LIMIT_WINDOW", "10s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.HTTPAddr != ":9090" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":9090")
	}
	if cfg.AgentAddr != ":9091" {
		t.Errorf("AgentAddr = %q, want %q", cfg.AgentAddr, ":9091")
	}
	if cfg.RequestTimeout != 30*time.Second {
		t.Errorf("RequestTimeout = %v, want %v", cfg.RequestTimeout, 30*time.Second)
	}
	if cfg.ProposeWriteRateLimit != 5 {
		t.Errorf("ProposeWriteRateLimit = %d, want 5", cfg.ProposeWriteRateLimit)
	}
	if cfg.ProposeWriteRateLimitWindow != 10*time.Second {
		t.Errorf("ProposeWriteRateLimitWindow = %v, want %v", cfg.ProposeWriteRateLimitWindow, 10*time.Second)
	}
}

func TestLoad_InvalidDurationFallsBackToDefault(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost:54322/chuvar")
	t.Setenv("REQUEST_TIMEOUT", "not-a-duration")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.RequestTimeout != 10*time.Second {
		t.Errorf("RequestTimeout = %v, want fallback %v", cfg.RequestTimeout, 10*time.Second)
	}
}

// A set-but-invalid or non-positive rate limit is a config mistake worth a
// warning, not a boot failure (this is a tuning knob, not required config
// like DatabaseURL) — but it must fall back to the safe default rather than
// being reinterpreted as "unlimited."
func TestLoad_InvalidOrNonPositiveRateLimitFallsBackToDefault(t *testing.T) {
	for _, v := range []string{"not-a-number", "0", "-5"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("DATABASE_URL", "postgres://localhost:54322/chuvar")
			t.Setenv("PROPOSE_WRITE_RATE_LIMIT", v)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() returned unexpected error: %v", err)
			}
			if cfg.ProposeWriteRateLimit != 20 {
				t.Errorf("ProposeWriteRateLimit = %d, want fallback 20", cfg.ProposeWriteRateLimit)
			}
		})
	}
}

// Same stance as the rate-limit count above, and higher stakes: the store
// fails closed on a non-positive window, so "0" surviving Load() would brick
// propose_write entirely off a one-character typo rather than falling back.
func TestLoad_InvalidOrNonPositiveRateLimitWindowFallsBackToDefault(t *testing.T) {
	for _, v := range []string{"not-a-duration", "0", "-1s"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("DATABASE_URL", "postgres://localhost:54322/chuvar")
			t.Setenv("PROPOSE_WRITE_RATE_LIMIT_WINDOW", v)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() returned unexpected error: %v", err)
			}
			if cfg.ProposeWriteRateLimitWindow != time.Minute {
				t.Errorf("ProposeWriteRateLimitWindow = %v, want fallback %v", cfg.ProposeWriteRateLimitWindow, time.Minute)
			}
		})
	}
}
