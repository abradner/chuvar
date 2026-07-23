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
	t.Setenv("DATABASE_URL", "postgres://localhost:5433/memoryvault")
	t.Setenv("HTTP_ADDR", "")
	t.Setenv("REQUEST_TIMEOUT", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.HTTPAddr != "127.0.0.1:8080" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, "127.0.0.1:8080")
	}
	if cfg.RequestTimeout != 10*time.Second {
		t.Errorf("RequestTimeout = %v, want %v", cfg.RequestTimeout, 10*time.Second)
	}
}

func TestLoad_OverridesApplied(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost:5433/memoryvault")
	t.Setenv("HTTP_ADDR", ":9090")
	t.Setenv("REQUEST_TIMEOUT", "30s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.HTTPAddr != ":9090" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":9090")
	}
	if cfg.RequestTimeout != 30*time.Second {
		t.Errorf("RequestTimeout = %v, want %v", cfg.RequestTimeout, 30*time.Second)
	}
}

func TestLoad_InvalidDurationFallsBackToDefault(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost:5433/memoryvault")
	t.Setenv("REQUEST_TIMEOUT", "not-a-duration")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.RequestTimeout != 10*time.Second {
		t.Errorf("RequestTimeout = %v, want fallback %v", cfg.RequestTimeout, 10*time.Second)
	}
}
