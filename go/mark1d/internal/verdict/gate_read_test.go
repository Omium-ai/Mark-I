package verdict

import (
	"testing"
	"time"
)

// gateReadSlack is the CI ceiling on one Reader.Get. 12 §7.1 budgets the gate
// cache read at ≤ 1 µs per evaluation (NFR-LATENCY-004) — on the pinned
// runner. A shared runner cannot hold 1 µs honestly, so the assertion here is
// the allocation count (which does not get noisier on a busy box) and the
// timing only fails past a slack no map lookup reaches without someone having
// put work on the gate path.
const gateReadSlack = 5 * time.Microsecond

// Sinks keep the compiler from proving the lookup unused.
var (
	sinkCached Cached
	sinkOK     bool
)

// TestGateReadIsAllocationFreeAndSubMicrosecond pins NFR-LATENCY-004 on the
// read the gate actually performs (fabric.Gate.Answer step 6: g.reader.Get):
// on a warm entry AND on a miss, zero heap allocations per call, and a
// per-call time under the CI slack. It reads through the Reader interface,
// as the gate does, not through *Cache.
func TestGateReadIsAllocationFreeAndSubMicrosecond(t *testing.T) {
	e := NewEngine(kneeBundle(), NewBlocks(), nil)
	hit, miss := TaskID{1}, TaskID{2}
	e.Recompute(hit, golden32Votes(), 1)
	e.drainOne(t)
	r := e.Reader()
	if _, ok := r.Get(hit); !ok {
		t.Fatal("warm entry not published")
	}
	if _, ok := r.Get(miss); ok {
		t.Fatal("miss task unexpectedly present")
	}

	for _, tc := range []struct {
		name string
		task TaskID
	}{{"hit", hit}, {"miss", miss}} {
		read := func() { sinkCached, sinkOK = r.Get(tc.task) }

		allocs := testing.AllocsPerRun(1000, read)
		nsPerOp := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				read()
			}
		}).NsPerOp()
		t.Logf("%s: %.0f allocs/op, %d ns/op (12 §7.1 budget 1000 ns on the pinned runner; CI slack %v)",
			tc.name, allocs, nsPerOp, gateReadSlack)

		if allocs != 0 {
			t.Errorf("%s: gate read allocates (%.0f allocs/op) — NFR-LATENCY-004 forbids allocation on the gate path", tc.name, allocs)
		}
		if time.Duration(nsPerOp) > gateReadSlack {
			t.Errorf("%s: gate read %d ns/op exceeds the CI slack %v — someone put work on the gate path", tc.name, nsPerOp, gateReadSlack)
		}
	}
}
