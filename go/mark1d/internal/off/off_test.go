package off

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestOffMarkerAndEnv(t *testing.T) {
	dir := t.TempDir()
	if Off(dir) {
		t.Fatal("no marker, no env: must be on")
	}
	if err := os.WriteFile(Marker(dir), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !Off(dir) {
		t.Fatal("marker present: must be off (08 §7.6 step 1)")
	}
	if err := os.Remove(Marker(dir)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MARK1_DISABLE", "1")
	if !Off(dir) {
		t.Fatal("MARK1_DISABLE=1: must be off (invariant 2)")
	}
	t.Setenv("MARK1_DISABLE", "0")
	if Off(dir) {
		t.Fatal("MARK1_DISABLE=0 is not the disable value")
	}
}

// TestOffFailsClosedOnUnreadableState: an unreadable state dir cannot prove
// the user has not turned capture off — the switch reads OFF.
func TestOffFailsClosedOnUnreadableState(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores modes")
	}
	if runtime.GOOS == "windows" {
		// Mkdir 0o000 is ignored here, so the fault cannot be constructed.
		// Off's posture holds unchanged — an ACL-denied Lstat is
		// ERROR_ACCESS_DENIED, not IsNotExist, and reads as off — but this
		// test leaves that unproven on windows (08 §7.6 fail-closed).
		t.Skip("windows: directory modes cannot make the state dir unreadable")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locked, 0o700) //nolint:errcheck // best-effort cleanup unlock
	if !Off(locked) {
		t.Fatal("unreadable state dir must read as off, not on")
	}
}

func TestWaitReturnsWhenMarkerRemoved(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(Marker(dir), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = os.Remove(Marker(dir))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Wait(ctx, dir, 5*time.Millisecond); err != nil {
		t.Fatalf("Wait must return nil once the marker clears, got %v", err)
	}
}

func TestWatchCtxCancelsWhenMarkerAppears(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := WatchCtx(context.Background(), dir, 5*time.Millisecond)
	defer cancel()
	select {
	case <-ctx.Done():
		t.Fatal("cancelled while on")
	case <-time.After(30 * time.Millisecond):
	}
	if err := os.WriteFile(Marker(dir), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("marker appeared but the capture context survived — kill switch circumvented")
	}
}
