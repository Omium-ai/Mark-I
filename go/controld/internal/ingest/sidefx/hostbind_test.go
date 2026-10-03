package sidefx

import (
	"bytes"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// TestHostBindingsMapTheWireFieldForField is ADR-0017's ingest half: the
// ReceiptCheckpoint's hosts reach receipts.CheckpointEvent exactly as sent —
// session, transport, host identity, profile hash, correlation id, tasks with
// an identity hash only where the wire carries one — and a v1 seal (no
// hosts) maps to nil, which keeps controld's reconstruction v1.
func TestHostBindingsMapTheWireFieldForField(t *testing.T) {
	if hostBindings(nil) != nil {
		t.Fatal("a v1 seal must map to nil hosts")
	}
	sid, task1, task2 := bytes.Repeat([]byte{0xaa}, 16), bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	ph, ih := bytes.Repeat([]byte{0x33}, 32), bytes.Repeat([]byte{0x44}, 32)
	in := []*m1pv1.HostBinding{{
		SessionId: sid, Transport: "fabric", HostId: "cem888", HostVersion: "2.0.1", ProfileHash: ph, HostCorrelationId: "run-7",
		Tasks: []*m1pv1.TaskBinding{{TaskId: task1, IdentityHash: ih}, {TaskId: task2}},
	}}
	out := hostBindings(in)
	if len(out) != 1 {
		t.Fatalf("mapped %d hosts, want 1", len(out))
	}
	h := out[0]
	if !bytes.Equal(h.SessionID[:], sid) || h.Transport != "fabric" || h.HostID != "cem888" || h.HostVersion != "2.0.1" || !bytes.Equal(h.ProfileHash[:], ph) || h.HostCorrelationID != "run-7" {
		t.Fatalf("host = %+v", h)
	}
	if len(h.Tasks) != 2 || !bytes.Equal(h.Tasks[0].TaskID[:], task1) || !bytes.Equal(h.Tasks[0].IdentityHash, ih) || h.Tasks[1].IdentityHash != nil {
		t.Fatalf("tasks = %+v", h.Tasks)
	}
}
