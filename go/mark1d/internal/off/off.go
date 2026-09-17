// Package off is mark1d's half of the uncircumventable kill switch (08 §7.6,
// invariant 2): the ~/.omium/mark1/OFF marker and MARK1_DISABLE=1 are checked
// BEFORE any spool, fabric, or tailer I/O — and kept checked, because the
// supervisor's KeepAlive/Restart=on-failure WILL restart the daemon while the
// user has Mark 1 off, and a restarted daemon that captures anyway is the
// kill switch circumvented. No bundle, server, or config state can override
// a true answer here; there is no parameter that skips the check.
package off

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

// Marker is the off-marker path `mark1 off` writes (08 §7.6 step 1),
// anchored to the daemon's state root (default ~/.omium/mark1).
func Marker(stateDir string) string { return filepath.Join(stateDir, "OFF") }

// Off answers "is Mark 1 off right now?". A stat error other than not-exist
// reads as OFF: when the state dir is unreadable we cannot prove the user has
// not turned capture off, and this switch fails closed by contract.
func Off(stateDir string) bool {
	if os.Getenv("MARK1_DISABLE") == "1" {
		return true
	}
	_, err := os.Lstat(Marker(stateDir))
	return err == nil || !os.IsNotExist(err)
}

// AgentMarker is the per-agent twin of Marker, written by POST /v1/agents/{name}/pause; a global OFF still wins because every reader checks Off first.
func AgentMarker(stateDir, agent string) string { return filepath.Join(stateDir, "paused", agent) }

// AgentOff is Off for one agent, same fail-closed stat; a name that is not a bare catalog word is never paused (nothing writes such a marker).
func AgentOff(stateDir, agent string) bool {
	if agent == "" || agent[0] == '.' || filepath.Base(agent) != agent {
		return false
	}
	_, err := os.Lstat(AgentMarker(stateDir, agent))
	return err == nil || !os.IsNotExist(err)
}

// Unless gates a tailer's emit on the agent's pause marker: a paused agent's stream never reaches admission; the pause is journalled as its own coverage transition, so nothing is lost silently.
func Unless[T any](stateDir, agent string, next func(context.Context, T) error) func(context.Context, T) error {
	return func(ctx context.Context, v T) error {
		if AgentOff(stateDir, agent) {
			return nil
		}
		return next(ctx, v)
	}
}

// Wait parks until Mark 1 is on (marker gone, MARK1_DISABLE unset) or ctx
// ends; the return value is ctx.Err(). Polling, not fsnotify: the marker is
// the correctness path and a watch on a possibly-not-yet-existing directory
// adds failure modes to the one component that must never fail toward
// capture-while-off.
func Wait(ctx context.Context, stateDir string, poll time.Duration) error {
	for Off(stateDir) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
	return ctx.Err()
}

// WatchCtx derives a context that is cancelled the moment Mark 1 goes off —
// the runtime half of 08 §7.6 step 3 ("stops tailers"): the capture session
// hangs its fabric listener, tailers, and drain on this context.
func WatchCtx(parent context.Context, stateDir string, poll time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		t := time.NewTicker(poll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if Off(stateDir) {
					cancel()
					return
				}
			}
		}
	}()
	return ctx, cancel
}
