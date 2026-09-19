package sidefx

import (
	"context"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// pendingLeaves lists one device's unconsumed leaves (deletion_test reads the deletion a refused row carries).
func (m *memLeaves) pending(device uuid.UUID) []leaf {
	w, _ := m.Window(context.Background(), querychoke.TenantID{}, device, 1<<30)
	return w
}

// newTestSidefx is New over a memory leaf store and no Postgres.
func newTestSidefx(chain ChainAppender, sec Security) (*Sidefx, *memLeaves) {
	s := New(nullDB{}, chain, sec, 1, 8)
	mem := newMemLeaves()
	s.leaves = mem
	if f, ok := chain.(*fakeChain); ok {
		f.runSealed = true
	}
	return s, mem
}
