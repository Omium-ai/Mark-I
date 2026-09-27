package uplink

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestWakeSignalFiresOnlyOnAWallClockJumpBeyondTheMonotonicElapsed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex // the fake clocks are read by WakeSignal's goroutine after tick k and written by step before tick k+1: no channel orders those two
	wall, mono := time.Unix(1_800_000_000, 0), time.Duration(0)
	ticks := make(chan time.Time)
	sig := WakeSignal(ctx, time.Second,
		func() time.Time { mu.Lock(); defer mu.Unlock(); return wall },
		func() time.Duration { mu.Lock(); defer mu.Unlock(); return mono },
		func(time.Duration) <-chan time.Time { return ticks })
	step := func(wallDelta, monoDelta time.Duration) {
		mu.Lock()
		wall, mono = wall.Add(wallDelta), mono+monoDelta
		mu.Unlock()
		ticks <- time.Time{}
	}
	fired := func() bool {
		select {
		case <-sig:
			return true
		case <-time.After(50 * time.Millisecond):
			return false
		}
	}
	step(time.Second, time.Second)
	if fired() {
		t.Fatal("a normal tick fired the wake signal")
	}
	step(10*time.Minute, time.Second)
	if !fired() {
		t.Fatal("a 10-minute wall jump over a 1 s monotonic tick did not fire")
	}
	step(-3*time.Hour, time.Second)
	if !fired() {
		t.Fatal("a backwards wall jump did not fire")
	}
	step(2*time.Second, 2*time.Second)
	if fired() {
		t.Fatal("a slow tick with no jump fired")
	}
}
