//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
)

// testEndpoint is the platform's fabric endpoint for one daemon under test:
// a per-test named pipe (07 §5), which fabric.Listen creates owner-only.
func testEndpoint(t *testing.T) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return `\\.\pipe\omium-mark1-test-` + hex.EncodeToString(b[:])
}

// dialEndpoint connects to a daemon's fabric endpoint, retrying until the
// daemon has bound it (run() binds after its stores open).
func dialEndpoint(t *testing.T, endpoint string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := winio.DialPipe(endpoint, nil)
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("fabric endpoint %s never came up: %v", endpoint, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
