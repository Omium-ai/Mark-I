package sidefx

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// memLeaves is the LeafStore in a map: tests (here and in ingest) and nothing else — pgLeaves is what runs, and the integration tests exercise it. Ties on (batch, idx) — test leaves carry neither — keep insertion order.
type memLeaves struct {
	mu   sync.Mutex
	rows map[uuid.UUID][]memLeaf // per device
}

type memLeaf struct {
	leaf
	n        int
	consumed bool
}

// NewMemoryLeafStore is the tests' LeafStore (SetLeafStore); production wires none and runs on m1_083.
func NewMemoryLeafStore() LeafStore { return newMemLeaves() }

func newMemLeaves() *memLeaves { return &memLeaves{rows: map[uuid.UUID][]memLeaf{}} }

func (m *memLeaves) Add(_ context.Context, _ querychoke.TenantID, device uuid.UUID, leaves []leaf) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range leaves {
		dup := false
		for _, have := range m.rows[device] {
			if have.id == l.id {
				dup = true
				break
			}
		}
		if !dup {
			m.rows[device] = append(m.rows[device], memLeaf{leaf: l, n: len(m.rows[device])})
		}
	}
	return nil
}

func (m *memLeaves) Window(_ context.Context, _ querychoke.TenantID, device uuid.UUID, n int) ([]leaf, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []leaf
	rows := append([]memLeaf(nil), m.rows[device]...)
	for i := 1; i < len(rows); i++ { // insertion sort by (batch, idx, n)
		for j := i; j > 0 && less(rows[j], rows[j-1]); j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
	for _, r := range rows {
		if r.consumed {
			continue
		}
		out = append(out, r.leaf)
		if len(out) == n {
			break
		}
	}
	return out, nil
}

func less(a, b memLeaf) bool {
	if a.batch != b.batch {
		return a.batch.String() < b.batch.String()
	}
	if a.idx != b.idx {
		return a.idx < b.idx
	}
	return a.n < b.n
}

func (m *memLeaves) Consume(_ context.Context, _ pgx.Tx, _ querychoke.TenantID, device uuid.UUID, ids []uuid.UUID, _ int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.rows[device] {
		for _, id := range ids {
			if m.rows[device][i].id == id {
				m.rows[device][i].consumed = true
			}
		}
	}
	return nil
}

func (m *memLeaves) Sweep(context.Context, querychoke.TenantID, time.Duration) error { return nil }
