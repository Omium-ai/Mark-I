//go:build soak

package soak

import (
	"container/heap"
	"sync"
	"testing"
	"time"
)

type timer struct {
	when time.Time
	seq  uint64
	ch   chan time.Time
	fn   func()
}

type timers []*timer

func (h timers) Len() int { return len(h) }

// At one instant component timers fire before driver callbacks, so a probe sees that instant's state.
func (h timers) Less(i, j int) bool {
	if !h[i].when.Equal(h[j].when) {
		return h[i].when.Before(h[j].when)
	}
	if (h[i].ch != nil) != (h[j].ch != nil) {
		return h[i].ch != nil
	}
	return h[i].seq < h[j].seq
}
func (h timers) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *timers) Push(x any)   { *h = append(*h, x.(*timer)) }
func (h *timers) Pop() any {
	o := *h
	t := o[len(o)-1]
	*h = o[:len(o)-1]
	return t
}

// clock fires the earliest timer only once every sleeper is parked again: a deterministic total order.
type clock struct {
	t        *testing.T
	mu       sync.Mutex
	now      time.Time
	seq      uint64
	h        timers
	sleeping int
	sleepers int
	parked   chan struct{}
	wd       *time.Timer
}

func newClock(t *testing.T, start time.Time, sleepers int) *clock {
	wd := time.NewTimer(time.Hour)
	wd.Stop()
	return &clock{t: t, now: start, sleepers: sleepers, parked: make(chan struct{}, 1), wd: wd}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) push(t *timer) {
	c.seq++
	t.seq = c.seq
	heap.Push(&c.h, t)
}

func (c *clock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	c.push(&timer{when: c.now.Add(d), ch: ch})
	c.sleeping++
	c.mu.Unlock()
	select {
	case c.parked <- struct{}{}:
	default:
	}
	return ch
}

func (c *clock) at(when time.Time, fn func()) {
	c.mu.Lock()
	c.push(&timer{when: when, fn: fn})
	c.mu.Unlock()
}

func (c *clock) quiesce() {
	armed := false
	for {
		c.mu.Lock()
		ok := c.sleeping >= c.sleepers
		sleeping, now := c.sleeping, c.now
		c.mu.Unlock()
		if ok {
			if armed {
				c.wd.Stop()
			}
			return
		}
		if !armed {
			c.wd.Reset(20 * time.Second)
			armed = true
		}
		select {
		case <-c.parked:
		case <-c.wd.C:
			c.t.Fatalf("soak: %d of %d sleepers parked after 20 s wall at virtual %v", sleeping, c.sleepers, now)
		}
	}
}

// step fires the earliest timer; false when the heap holds nothing.
func (c *clock) step() (time.Time, bool) {
	c.quiesce()
	c.mu.Lock()
	if len(c.h) == 0 {
		c.mu.Unlock()
		return c.now, false
	}
	t := heap.Pop(&c.h).(*timer)
	if t.when.After(c.now) {
		c.now = t.when
	}
	if t.ch != nil {
		c.sleeping--
	}
	now := c.now
	c.mu.Unlock()
	if t.ch != nil {
		t.ch <- now
	} else {
		t.fn()
	}
	return now, true
}

func (c *clock) runUntil(end time.Time) {
	for {
		c.quiesce()
		c.mu.Lock()
		done := len(c.h) == 0 || c.h[0].when.After(end)
		if done && end.After(c.now) {
			c.now = end
		}
		c.mu.Unlock()
		if done {
			return
		}
		c.step()
	}
}
