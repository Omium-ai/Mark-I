// Package coverage is 04 §2.7's single door: every capture-affecting state
// change anywhere in mark1d routes through Emitter.Transition and lands as a
// per-event-receipted m1p.v1.CoverageTransition (contract C13). That receipting
// is what lets a TVO report carry an honest coverage band instead of an assumed
// one, and it is why the door is one function and not a convention.
//
// The transition rides the ordinary event path — capture.Admit → spool →
// checkpoint → device-signed receipt — exactly like every other event class.
// Nothing here signs or spools anything itself: the tamper-evidence is the
// receipt chain's, so a transition is only as unforgeable as the chain, which
// is the property the customer verifies offline.
//
// Durability is DIAGNOSTIC (spool class byte 2), per intelligence.proto: 07 §6
// closes the billing-grade set at exactly {usage, verdict_event,
// receipt_checkpoint}, so a coverage record sheds on a full spool rather than
// blocking a developer's keystroke. See Emitter.Transition on what that costs.
package coverage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The reason_code vocabulary, frozen at nine values in
// proto/m1p/v1/intelligence.proto and mirrored VERBATIM by m1_043's `reason`
// column. 04 §2.7 is its only authority; a tenth code is a doc change first.
// The two agent_* codes are POST /v1/agents/{name}/pause|resume (desktop spec
// §5.9); the wire carries no agent field, so the agent name stays in the local
// journal line and the transition lands device-wide, exactly as `mark1 off --all` does.
const (
	ReasonMark1Off                = "mark1_off"
	ReasonDiskHardStop            = "disk_hard_stop"
	ReasonUserEnable              = "user_enable"
	ReasonProxyBypass             = "proxy_bypass"
	ReasonProxyFailed             = "proxy_failed"
	ReasonUnsupportedAgentVersion = "unsupported_agent_version"
	ReasonTranscriptRetentionGap  = "transcript_retention_gap"
	ReasonAgentPause              = "agent_pause"
	ReasonAgentResume             = "agent_resume"
)

// reasonKind pairs each frozen code with the ONE kind it can legally carry.
// The pairing is validated rather than inferred because kind and reason are
// separate wire fields that the server reads for different purposes — kind
// decides which side of the band's numerator a window lands on (m1_043's
// coverage_kind), reason only explains it — so a caller that passes BYPASS
// where it meant DISABLE writes a row that is wrong in the one field nobody
// downstream can second-guess. Refused here, at the door, not audited later.
var reasonKind = map[string]m1pv1.CoverageKind{
	ReasonUserEnable:              m1pv1.CoverageKind_COVERAGE_KIND_ENABLE,
	ReasonMark1Off:                m1pv1.CoverageKind_COVERAGE_KIND_DISABLE,
	ReasonDiskHardStop:            m1pv1.CoverageKind_COVERAGE_KIND_BYPASS,
	ReasonProxyBypass:             m1pv1.CoverageKind_COVERAGE_KIND_BYPASS,
	ReasonProxyFailed:             m1pv1.CoverageKind_COVERAGE_KIND_BYPASS,
	ReasonUnsupportedAgentVersion: m1pv1.CoverageKind_COVERAGE_KIND_BYPASS,
	ReasonTranscriptRetentionGap:  m1pv1.CoverageKind_COVERAGE_KIND_BYPASS,
	ReasonAgentPause:              m1pv1.CoverageKind_COVERAGE_KIND_DISABLE,
	ReasonAgentResume:             m1pv1.CoverageKind_COVERAGE_KIND_ENABLE,
}

// WorkspaceIDLen is m1_043's CHECK (octet_length(workspace_digest) = 32),
// enforced on THIS side of the wire because the server's insert runs inside
// AppendCheckpoint's same-transaction callback: a digest of the wrong length
// does not fail one row, it fails the whole checkpoint append and the receipt
// chain stalls. A local length check is the cheap half of that guarantee.
const WorkspaceIDLen = 32

// DeviceWide is the workspace_id for a transition whose cause is the MACHINE
// and not any one workspace — a failed proxy, a full disk, an unsupported
// agent binary. All-zero because m1_043 requires exactly 32 bytes and there is
// no honest per-tenant HMAC of "no path"; a zero digest is a value no keyed
// HMAC produces, so "device-wide" stays distinguishable from a real surface.
//
// Ceiling, stated because it is load-bearing and not fixable from here: the
// band query (m1_043 :100-120) partitions by (device_id, workspace_digest), so
// a device-wide bypass forms its own partition and does NOT narrow the band of
// the workspaces it actually degraded. Fanning one transition out per enabled
// workspace is the fix; it belongs with whoever builds that query, since only
// there is it observable whether the two agree.
func DeviceWide() []byte { return make([]byte, WorkspaceIDLen) }

// ErrNotWired is returned by a nil Emitter. Coverage is the one plane where a
// nilable no-op consumer would be the defect itself — a silently dropped
// transition is indistinguishable from a window that never happened, which is
// precisely the assumed-100%-coverage failure this package exists to end. So a
// half-wired daemon gets a loud error at every call site, never a quiet nil.
var ErrNotWired = errors.New("coverage: emitter not wired; this transition is NOT receipted")

// AdmitFunc is capture.Admitter.Admit — the single admission door into the
// spool (04 §2.0). A seam, not an abstraction: tests supply their own.
type AdmitFunc func(context.Context, *m1pv1.Event) error

// Emitter holds the admission door and the tenant path key. One per daemon.
type Emitter struct {
	admit   AdmitFunc
	pathKey []byte
	now     func() time.Time
}

// New returns the daemon's emitter. pathKey is taskseg.DeriveKey's per-tenant
// path key — the same key the R2 overlap digests use, so a workspace has ONE
// digest across the estate and coverage rows join to task rows. A nil key
// still yields usable digests (they never leave the machine unkeyed-comparable
// across tenants); it does not disable anything, because a coverage plane with
// an off switch is a coverage plane that reports zero and looks fine.
func New(admit AdmitFunc, pathKey []byte) *Emitter {
	if admit == nil {
		return nil // ErrNotWired at every call, rather than a panic at boot
	}
	return &Emitter{admit: admit, pathKey: pathKey, now: time.Now}
}

// WorkspaceID is HMAC_tenant(filepath.Clean(path)) — the same recipe
// taskseg.Segmenter.digest uses, so the two planes name a workspace with the
// same 32 bytes. Evidence carries no paths (m1_043).
func (e *Emitter) WorkspaceID(path string) []byte {
	if e == nil {
		return DeviceWide()
	}
	mac := hmac.New(sha256.New, e.pathKey)
	mac.Write([]byte(filepath.Clean(path)))
	return mac.Sum(nil)
}

// Transition is THE door. kind and reason must agree per reasonKind;
// workspaceID must be exactly 32 bytes (DeviceWide for a machine-wide cause);
// window is the length of a bypass window being CLOSED and zero for every
// other transition — the server distinguishes bypass_end from bypass_start on
// that field alone (sidefx.coverageKind), so a door that could not carry it
// would leave every bypass window open forever.
//
// Returns capture's error verbatim. Two of them matter to callers:
//
//   - capture.ErrShed — the spool was full, so THIS transition was dropped.
//     The loss is accounted in the drop ledger (never silent), but the
//     coverage row does not exist. That is not survivable by retrying here:
//     the diagnostic class is 07 §6's, and promoting coverage to billing-grade
//     is explicitly refused by intelligence.proto ("a backpressure contract 07
//     never authorized"). Callers must log it as a gap, not as a warning.
//   - capture.ErrQuarantined — a malformed transition, i.e. a bug here.
func (e *Emitter) Transition(ctx context.Context, kind m1pv1.CoverageKind, workspaceID []byte, reason string, window time.Duration) error {
	if e == nil {
		return fmt.Errorf("%w (reason %q)", ErrNotWired, reason)
	}
	return e.emit(ctx, kind, workspaceID, reason, window, e.now())
}

// emit is Transition with the occurrence time supplied. Separate because a
// journalled CLI transition happened when the CLI wrote it, which may be hours
// before this daemon drains it: stamping now() there would silently move a
// window, and a window in the wrong place is worse than no window at all.
func (e *Emitter) emit(ctx context.Context, kind m1pv1.CoverageKind, workspaceID []byte, reason string, window time.Duration, at time.Time) error {
	want, ok := reasonKind[reason]
	if !ok {
		// The vocabulary is frozen and mirrored into a Postgres column that
		// deliberately has no CHECK (m1_043: codes must be able to land as
		// data). This map is therefore the only place an invented code is
		// caught before it becomes an unclassifiable row in the band query.
		return fmt.Errorf("coverage: %q is not one of 04 §2.7's reason codes", reason)
	}
	if kind != want {
		return fmt.Errorf("coverage: reason %q is kind %v, not %v", reason, want, kind)
	}
	if len(workspaceID) != WorkspaceIDLen {
		return fmt.Errorf("coverage: workspace_id is %d bytes, m1_043 requires exactly %d (use DeviceWide for a machine-wide cause)",
			len(workspaceID), WorkspaceIDLen)
	}
	if window < 0 {
		return fmt.Errorf("coverage: window %v is negative", window)
	}
	return e.admit(ctx, &m1pv1.Event{
		// No session_id: a coverage transition reports on a workspace or the
		// machine, never on one session — capture.deviceScoped names this
		// body for exactly that reason.
		OccurredAt: timestamppb.New(at.UTC()),
		Body: &m1pv1.Event_CoverageTransition{CoverageTransition: &m1pv1.CoverageTransition{
			Kind:        kind,
			WorkspaceId: workspaceID,
			DurationMs:  uint64(window.Milliseconds()), //nolint:gosec // G115: window >= 0 checked above
			ReasonCode:  reason,
		}},
	})
}
