package coverage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

// wire builds the REAL path a transition takes: emitter → capture.Admitter →
// spool. No fake admit function, because the two properties that matter most
// here are properties of that path and not of this package — that a coverage
// event survives capture's admission at all (it carries no session_id, and
// capture quarantines a session-less body unless deviceScoped names it), and
// that it lands stamped diagnostic class.
func wire(t *testing.T) (*Emitter, *spool.Spool) {
	t.Helper()
	dir := t.TempDir()
	sp, err := spool.Open(spool.Config{Dir: filepath.Join(dir, "spool")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	adm, err := capture.New(sp, capture.Config{
		EpochPath: filepath.Join(dir, "epoch"),
		Redact:    func(*m1pv1.Event) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(adm.Admit, []byte("tenant-path-key")), sp
}

// landed reads back every CoverageTransition the spool holds, with its
// durability class. Decoding is the anti-vacuity guard: "a record exists" is
// satisfied by any bytes, "these bytes decode to a CoverageTransition carrying
// this reason" is not.
type landedEvent struct {
	ev    *m1pv1.Event
	ct    *m1pv1.CoverageTransition
	class spool.Class
}

func landed(t *testing.T, sp *spool.Spool) []landedEvent {
	t.Helper()
	// Records reads the DURABLE region only; the fsync cadence is 250 ms, and a
	// test that slept for it would be a flake generator.
	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	var out []landedEvent
	for _, r := range recs {
		ev := &m1pv1.Event{}
		if err := proto.Unmarshal(r.Payload, ev); err != nil {
			t.Fatalf("a spooled record did not decode as an Event: %v", err)
		}
		body, ok := ev.GetBody().(*m1pv1.Event_CoverageTransition)
		if !ok {
			continue
		}
		out = append(out, landedEvent{ev: ev, ct: body.CoverageTransition, class: r.ID.Class()})
	}
	return out
}

// TestTransitionLandsInTheSpoolAsADecodableCoverageEvent is the positive
// control for this whole package: it proves the mechanism accepts the exact
// shape mark1d ships — a session-less, workspace-scoped body — rather than
// only proving it rejects bad ones.
func TestTransitionLandsInTheSpoolAsADecodableCoverageEvent(t *testing.T) {
	cov, sp := wire(t)
	ws := cov.WorkspaceID("/home/dev/project")

	before := time.Now().Add(-time.Second)
	if err := cov.Transition(context.Background(),
		m1pv1.CoverageKind_COVERAGE_KIND_ENABLE, ws, ReasonUserEnable, 0); err != nil {
		t.Fatalf("Transition: %v", err)
	}

	got := landed(t, sp)
	if len(got) != 1 {
		t.Fatalf("spooled CoverageTransitions = %d, want exactly 1 — nothing was emitted", len(got))
	}
	e := got[0]
	if e.ct.GetReasonCode() != ReasonUserEnable {
		t.Errorf("reason_code = %q, want %q", e.ct.GetReasonCode(), ReasonUserEnable)
	}
	if e.ct.GetKind() != m1pv1.CoverageKind_COVERAGE_KIND_ENABLE {
		t.Errorf("kind = %v, want ENABLE", e.ct.GetKind())
	}
	if string(e.ct.GetWorkspaceId()) != string(ws) {
		t.Errorf("workspace_id did not survive the wire")
	}
	if len(e.ct.GetWorkspaceId()) != WorkspaceIDLen {
		t.Errorf("workspace_id is %d bytes; m1_043 CHECKs exactly %d and the insert runs inside "+
			"AppendCheckpoint's transaction, so a wrong length fails the whole checkpoint",
			len(e.ct.GetWorkspaceId()), WorkspaceIDLen)
	}
	if e.ct.GetDurationMs() != 0 {
		t.Errorf("duration_ms = %d, want 0 — a non-zero duration files this as bypass_end server-side", e.ct.GetDurationMs())
	}
	// Diagnostic, not billing: 07 §6 closes the billing-grade set at three
	// families and intelligence.proto refuses to widen it for coverage. A
	// coverage record that blocked a developer's keystroke would be the defect.
	if e.class != spool.ClassDiagnostic {
		t.Errorf("durability class = %v, want diagnostic (07 §6)", e.class)
	}
	// occurred_at is what the band query orders windows by; an unset one makes
	// every window land on the server's fallback clock instead.
	at := e.ev.GetOccurredAt()
	if at == nil || at.AsTime().Before(before) || at.AsTime().After(time.Now().Add(time.Second)) {
		t.Errorf("occurred_at = %v, want a stamp from this call", at)
	}
	// No session_id, deliberately: coverage reports on a surface, not a session.
	if len(e.ev.GetSessionId()) != 0 {
		t.Errorf("session_id = %x, want empty — a coverage transition has no session to belong to", e.ev.GetSessionId())
	}
}

// TestEveryFrozenReasonCodeIsEmittable walks all seven of 04 §2.7's codes with
// the kind each one legally carries. It is the positive control for the
// vocabulary: without it, a refusal test is satisfied by a door that refuses
// everything, and the plane would be just as dead as it was empty.
func TestEveryFrozenReasonCodeIsEmittable(t *testing.T) {
	all := []string{
		ReasonMark1Off, ReasonDiskHardStop, ReasonUserEnable, ReasonProxyBypass,
		ReasonProxyFailed, ReasonUnsupportedAgentVersion, ReasonTranscriptRetentionGap,
	}
	if len(all) != len(reasonKind) {
		t.Fatalf("the vocabulary is frozen at seven values in proto/m1p/v1/intelligence.proto; "+
			"this package knows %d and the test lists %d", len(reasonKind), len(all))
	}
	cov, sp := wire(t)
	for _, r := range all {
		if err := cov.Transition(context.Background(), reasonKind[r], DeviceWide(), r, 0); err != nil {
			t.Errorf("reason %q could not be emitted: %v", r, err)
		}
	}
	got := landed(t, sp)
	if len(got) != len(all) {
		t.Fatalf("spooled = %d, want %d — some reason code silently emitted nothing", len(got), len(all))
	}
	seen := map[string]bool{}
	for _, e := range got {
		seen[e.ct.GetReasonCode()] = true
	}
	for _, r := range all {
		if !seen[r] {
			t.Errorf("reason %q never reached the spool", r)
		}
	}
}

// TestServerFilesEachKindAsTheRightRow mirrors sidefx.coverageKind — the
// server's 3-value-wire-enum → 4-value-column-enum map — and asserts each of
// the four m1_043 rows is REACHABLE from this door. bypass_end is the one that
// matters: it exists on the server only because duration_ms distinguishes it,
// so a door that could not carry a duration would leave every bypass window
// open forever and that branch dead.
//
// Ceiling, stated: this is a MIRROR of the server's mapping, not a link to it.
// Go's internal-package rule blocks go/mark1d from importing
// go/controld/internal/ingest/sidefx, so nothing fails if the server's map and
// this one drift. Closing that needs a shared conformance vector, which is the
// lead's call — it would live in conformance/, outside this row's territory.
func TestServerFilesEachKindAsTheRightRow(t *testing.T) {
	serverKind := func(ct *m1pv1.CoverageTransition) string {
		switch ct.GetKind() {
		case m1pv1.CoverageKind_COVERAGE_KIND_ENABLE:
			return "enable"
		case m1pv1.CoverageKind_COVERAGE_KIND_DISABLE:
			return "disable"
		case m1pv1.CoverageKind_COVERAGE_KIND_BYPASS:
			if ct.GetDurationMs() > 0 {
				return "bypass_end"
			}
			return "bypass_start"
		default:
			return ""
		}
	}
	cases := []struct {
		reason string
		window time.Duration
		want   string
	}{
		{ReasonUserEnable, 0, "enable"},
		{ReasonMark1Off, 0, "disable"},
		{ReasonProxyFailed, 0, "bypass_start"},
		{ReasonDiskHardStop, 90 * time.Second, "bypass_end"},
	}
	cov, sp := wire(t)
	for _, c := range cases {
		if err := cov.Transition(context.Background(), reasonKind[c.reason], DeviceWide(), c.reason, c.window); err != nil {
			t.Fatalf("%s: %v", c.reason, err)
		}
	}
	got := landed(t, sp)
	if len(got) != len(cases) {
		t.Fatalf("spooled = %d, want %d", len(got), len(cases))
	}
	for i, c := range cases {
		if k := serverKind(got[i].ct); k != c.want {
			t.Errorf("%s (window %v) files as %q, want %q", c.reason, c.window, k, c.want)
		}
	}
	if got[3].ct.GetDurationMs() != 90_000 {
		t.Errorf("duration_ms = %d, want 90000", got[3].ct.GetDurationMs())
	}
}

// TestTheDoorRefusesWhatTheServerCannotStore covers the three refusals that are
// not style points: an eighth reason code (m1_043's column deliberately has no
// CHECK, so this map is the only place it is caught), a kind/reason
// disagreement (kind decides which side of the band's numerator a window lands
// on — nothing downstream can second-guess it), and a workspace_id of the wrong
// length (m1_043 CHECKs 32 bytes INSIDE AppendCheckpoint's transaction, so a
// bad one does not fail a row, it stalls the receipt chain).
func TestTheDoorRefusesWhatTheServerCannotStore(t *testing.T) {
	cov, sp := wire(t)
	ctx := context.Background()
	bad := []struct {
		name   string
		kind   m1pv1.CoverageKind
		ws     []byte
		reason string
		window time.Duration
	}{
		{"invented reason", m1pv1.CoverageKind_COVERAGE_KIND_BYPASS, DeviceWide(), "network_flake", 0},
		{"empty reason", m1pv1.CoverageKind_COVERAGE_KIND_BYPASS, DeviceWide(), "", 0},
		{"kind disagrees with reason", m1pv1.CoverageKind_COVERAGE_KIND_DISABLE, DeviceWide(), ReasonUserEnable, 0},
		{"unspecified kind", m1pv1.CoverageKind_COVERAGE_KIND_UNSPECIFIED, DeviceWide(), ReasonUserEnable, 0},
		{"nil workspace", m1pv1.CoverageKind_COVERAGE_KIND_ENABLE, nil, ReasonUserEnable, 0},
		{"short workspace", m1pv1.CoverageKind_COVERAGE_KIND_ENABLE, make([]byte, 16), ReasonUserEnable, 0},
		{"long workspace", m1pv1.CoverageKind_COVERAGE_KIND_ENABLE, make([]byte, 33), ReasonUserEnable, 0},
		{"negative window", m1pv1.CoverageKind_COVERAGE_KIND_BYPASS, DeviceWide(), ReasonProxyFailed, -time.Second},
	}
	for _, c := range bad {
		if err := cov.Transition(ctx, c.kind, c.ws, c.reason, c.window); err == nil {
			t.Errorf("%s: accepted, want a refusal", c.name)
		}
	}
	// The refusals must refuse, not merely return an error after spooling.
	if got := landed(t, sp); len(got) != 0 {
		t.Fatalf("%d refused transitions still reached the spool", len(got))
	}
	// Positive control on the same wire: the door still works.
	if err := cov.Transition(ctx, m1pv1.CoverageKind_COVERAGE_KIND_ENABLE, DeviceWide(), ReasonUserEnable, 0); err != nil {
		t.Fatalf("the door refuses everything, which is the same dead plane by another route: %v", err)
	}
	if got := landed(t, sp); len(got) != 1 {
		t.Fatalf("spooled = %d after the positive control, want 1", len(got))
	}
}

// TestWorkspaceIDIsKeyedAndPathStable: two paths must not collide, the same
// path must give the same 32 bytes however it is spelled, and DeviceWide must
// be distinguishable from every real surface.
func TestWorkspaceIDIsKeyedAndPathStable(t *testing.T) {
	cov, _ := wire(t)
	a := cov.WorkspaceID("/home/dev/project")
	b := cov.WorkspaceID("/home/dev/project/")
	c := cov.WorkspaceID("/home/dev/other")
	if len(a) != WorkspaceIDLen {
		t.Fatalf("digest is %d bytes, want %d", len(a), WorkspaceIDLen)
	}
	if string(a) != string(b) {
		t.Errorf("a trailing slash produced a different surface; the band query would split one workspace in two")
	}
	if string(a) == string(c) {
		t.Errorf("two workspaces share a digest")
	}
	if string(a) == string(DeviceWide()) {
		t.Errorf("a real workspace collided with the device-wide sentinel")
	}
	// The digest must be KEYED — an unkeyed hash of a path is reversible by
	// anyone with a wordlist, and m1_043 exists so evidence carries no paths.
	other := New(cov.admit, []byte("a-different-tenant"))
	if string(other.WorkspaceID("/home/dev/project")) == string(a) {
		t.Errorf("two tenants derive the same digest for one path; the key is not being used")
	}
}

// TestNilEmitterIsLoud: coverage is the one plane where a nilable no-op
// consumer IS the defect — a silently dropped transition is indistinguishable
// from a window that never happened.
func TestNilEmitterIsLoud(t *testing.T) {
	var cov *Emitter
	err := cov.Transition(context.Background(), m1pv1.CoverageKind_COVERAGE_KIND_ENABLE,
		DeviceWide(), ReasonUserEnable, 0)
	if !errors.Is(err, ErrNotWired) {
		t.Fatalf("nil emitter returned %v, want ErrNotWired", err)
	}
	if New(nil, nil) != nil {
		t.Fatal("New with no admission door returned a live emitter; it would drop every transition silently")
	}
}
