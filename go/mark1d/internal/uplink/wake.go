package uplink

import (
	"context"
	"time"
)

// WakeSignal fires once per sleep/wake or wall-clock jump larger than 2×tick (08 §2.5: parked work re-queues on wake); it is the daemon's only network-change source until an interface watcher exists.
func WakeSignal(ctx context.Context, tick time.Duration, wall func() time.Time, mono func() time.Duration, after func(time.Duration) <-chan time.Time) <-chan struct{} {
	out := make(chan struct{}, 1)
	lastWall, lastMono := wall(), mono() // the baseline is the call's instant, not whenever the goroutine is first scheduled
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-after(tick):
			}
			w, m := wall(), mono()
			jump := w.Sub(lastWall) - (m - lastMono)
			lastWall, lastMono = w, m
			if jump > 2*tick || jump < -2*tick {
				select {
				case out <- struct{}{}:
				default:
				}
			}
		}
	}()
	return out
}
