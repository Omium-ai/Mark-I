//go:build unix

package main

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric/fabrictest"
)

// testEndpoint is the platform's fabric endpoint for one daemon under test:
// a UDS path short enough for sun_path.
func testEndpoint(t *testing.T) string {
	t.Helper()
	return filepath.Join(fabrictest.SocketDir(t), "sock", "m1p.sock")
}

// dialEndpoint connects to a daemon's fabric endpoint, retrying until the
// daemon has bound it (run() binds after its stores open).
func dialEndpoint(t *testing.T, endpoint string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.Dial("unix", endpoint)
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
