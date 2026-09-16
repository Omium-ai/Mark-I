//go:build integration

package memory

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestSmokeDriverRunSyncsFromEnv is the edge leg of go/controld/internal/memory/smoke_crossservice_test.go: the real cache's Run against a live controld route, custody left in M1_SMOKE_STATE_DIR for the caller to read.
func TestSmokeDriverRunSyncsFromEnv(t *testing.T) {
	base := os.Getenv("M1_SMOKE_MEMORY_URL")
	if base == "" {
		t.Skip("driver for controld's cross-service smoke; M1_SMOKE_MEMORY_URL unset")
	}
	c, err := New(Config{StateDir: os.Getenv("M1_SMOKE_STATE_DIR"), BaseURL: base, Token: os.Getenv("M1_SMOKE_DEVICE_TOKEN"), EdgeVersion: "mark1d/smoke"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c.Run(ctx)
	if len(c.artifacts()) == 0 {
		t.Fatal("Run synced nothing from the live route")
	}
}
