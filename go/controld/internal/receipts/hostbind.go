package receipts

import "encoding/hex"

// ADR-0017: the host block of a v2 checkpoint payload, as controld rebuilds
// it from ReceiptCheckpoint.hosts to verify the origin signature. Mirrors
// mark1d/internal/identity/hostbind.go field for field; the hostchain vectors
// hold the two to the same bytes.

// HostBinding is one session's host as the payload attests it.
type HostBinding struct {
	SessionID         [16]byte
	Transport         string
	HostID            string
	HostVersion       string
	ProfileHash       [32]byte
	HostCorrelationID string
	Tasks             []TaskBinding
}

// TaskBinding is one task under a host; IdentityHash is 32 bytes when the
// host supplies identity, nil otherwise.
type TaskBinding struct {
	TaskID       [16]byte
	IdentityHash []byte
}

// hostsValue is the payload's "hosts" array in the exact shape the hostchain
// vectors freeze: every key present, hashes hex, identity_hash only when set.
func hostsValue(hs []HostBinding) []any {
	out := make([]any, 0, len(hs))
	for _, h := range hs {
		tasks := make([]any, 0, len(h.Tasks))
		for _, t := range h.Tasks {
			tv := map[string]any{"task_id": hex.EncodeToString(t.TaskID[:])}
			if t.IdentityHash != nil {
				tv["identity_hash"] = hex.EncodeToString(t.IdentityHash)
			}
			tasks = append(tasks, tv)
		}
		out = append(out, map[string]any{
			"session_id":          hex.EncodeToString(h.SessionID[:]),
			"transport":           h.Transport,
			"host_id":             h.HostID,
			"host_version":        h.HostVersion,
			"profile_hash":        hex.EncodeToString(h.ProfileHash[:]),
			"host_correlation_id": h.HostCorrelationID,
			"tasks":               tasks,
		})
	}
	return out
}
