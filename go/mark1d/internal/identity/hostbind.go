package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
)

// ADR-0017: host-bound receipts. A v2 checkpoint payload carries, inside the
// signed bytes, which host each sealed session ran under (transport, host
// identity, profile hash, correlation id, the tasks — with a per-task identity
// hash when the host supplies identity) and how many arrests in the batch
// were acted versus recommended. v1 — today's payload, byte for byte — is
// what a sealer without a session lookup, or a batch with no bound session,
// still produces.

// HostBinding is one session's host as the payload attests it.
type HostBinding struct {
	SessionID         [16]byte
	Transport         string // "fabric" | "jsonl" | "native"
	HostID            string
	HostVersion       string
	ProfileHash       [32]byte // sha256 over hostprofile.Canonical(profile)
	HostCorrelationID string
	Tasks             []TaskBinding // sorted by TaskID
}

// TaskBinding is one task under a host; IdentityHash is 32 bytes when the
// host supplies identity (ADR-0013 supplies_identity), nil otherwise.
type TaskBinding struct {
	TaskID       [16]byte
	IdentityHash []byte
}

// SessionBinding is what the daemon knows about a session independent of any
// batch: the admit door's Session plus its profile hash. Bound is false for a
// native (first-party) session, which has no manifest and no host.
type SessionBinding struct {
	Transport         string
	HostID            string
	HostVersion       string
	HostCorrelationID string
	ProfileHash       [32]byte
	SuppliesIdentity  bool
	Bound             bool
}

// ProfileHash is sha256 over the profile's canonical JSON (ADR-0013 §4) —
// the same bytes `mark1d` logs at the Hello, so a payload's profile_hash can
// be checked against a host's manifest without the daemon.
func ProfileHash(p hostprofile.Profile) [32]byte { return sha256.Sum256(hostprofile.Canonical(p)) }

// identityDomain separates the per-task identity hash from every other
// sha256 in the estate.
const identityDomain = "m1p.v1/host-identity\x00"

// IdentityHash binds a task to the identity a host supplied for its session:
// sha256(domain ‖ host_id ‖ 0 ‖ host_correlation_id ‖ 0 ‖ task_id hex).
func IdentityHash(hostID, hostCorrelationID string, task [16]byte) []byte {
	h := sha256.New()
	h.Write([]byte(identityDomain))
	h.Write([]byte(hostID))
	h.Write([]byte{0})
	h.Write([]byte(hostCorrelationID))
	h.Write([]byte{0})
	h.Write([]byte(hex.EncodeToString(task[:])))
	return h.Sum(nil)
}

// BatchFacts is what one acked batch's leaves say: the sessions they belong
// to (with the tasks seen under each) and the arrest counts, acted and
// recommended, kept apart by construction (ADR-0015 §4).
type BatchFacts struct {
	Tasks              map[[16]byte]map[[16]byte]struct{}
	ArrestsActed       uint32
	ArrestsRecommended uint32
}

// Note records one leaf's session and task; a zero task notes the session only.
func (f *BatchFacts) Note(session, task [16]byte) {
	if f.Tasks == nil {
		f.Tasks = map[[16]byte]map[[16]byte]struct{}{}
	}
	ts := f.Tasks[session]
	if ts == nil {
		ts = map[[16]byte]struct{}{}
		f.Tasks[session] = ts
	}
	if task != ([16]byte{}) {
		ts[task] = struct{}{}
	}
}

// Merge folds o into f (carried-forward leaves join the next seal's facts).
func (f BatchFacts) Merge(o BatchFacts) BatchFacts {
	out := BatchFacts{ArrestsActed: f.ArrestsActed + o.ArrestsActed, ArrestsRecommended: f.ArrestsRecommended + o.ArrestsRecommended}
	for _, src := range []BatchFacts{f, o} {
		for sid, ts := range src.Tasks {
			out.Note(sid, [16]byte{})
			for t := range ts {
				out.Note(sid, t)
			}
		}
	}
	return out
}

// Bind resolves the batch's sessions through lookup into the payload's hosts
// list, sorted by session id. nil — the v1 posture — when there is no lookup
// or no session in the batch is bound: a solo developer's receipts do not
// change shape because a feature exists.
func (f BatchFacts) Bind(lookup func(session [16]byte) SessionBinding) []HostBinding {
	if lookup == nil || len(f.Tasks) == 0 {
		return nil
	}
	bound := false
	out := make([]HostBinding, 0, len(f.Tasks))
	for sid, ts := range f.Tasks {
		b := lookup(sid)
		if b.Bound {
			bound = true
		}
		hb := HostBinding{SessionID: sid, Transport: b.Transport, HostID: b.HostID, HostVersion: b.HostVersion, ProfileHash: b.ProfileHash, HostCorrelationID: b.HostCorrelationID}
		if hb.Transport == "" {
			hb.Transport = "native"
		}
		for t := range ts {
			tb := TaskBinding{TaskID: t}
			if b.SuppliesIdentity {
				tb.IdentityHash = IdentityHash(b.HostID, b.HostCorrelationID, t)
			}
			hb.Tasks = append(hb.Tasks, tb)
		}
		sort.Slice(hb.Tasks, func(i, j int) bool { return string(hb.Tasks[i].TaskID[:]) < string(hb.Tasks[j].TaskID[:]) })
		out = append(out, hb)
	}
	if !bound {
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i].SessionID[:]) < string(out[j].SessionID[:]) })
	return out
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
