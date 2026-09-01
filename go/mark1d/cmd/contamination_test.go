package main

import (
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// TestContaminationRollbackDetachesTheAgent is 04 §3.1 step 6: when the guard
// reports OAuth contamination, the agent's NEXT request must bypass the proxy.
// The log line is asserted too — a P0 legal event stays visible in the
// operator's log even when recovery succeeded.
func TestContaminationRollbackDetachesTheAgent(t *testing.T) {
	home, state := t.TempDir(), filepath.Join(t.TempDir(), "mark1")
	settings := filepath.Join(home, ".claude", "settings.json")
	const body = "{\n  \"model\": \"opus\"\n}\n"
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	// A real listener on a real port, answering the way the guard answers a
	// request carrying no M1-Cred-Ref (rust/mark1-proxy/src/router.rs:143-149).
	// ApplyProxyPointer now probes the published port before it will write the
	// pointer, so a literal port here is a port nothing holds and the setup
	// below would refuse — which would make this test pass for the wrong reason.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"M1E-8001","message":"request without a valid M1-Cred-Ref"}}`))
	}))
	t.Cleanup(srv.Close)
	authority := srv.Listener.Addr().String()
	port := strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)
	if err := os.WriteFile(claudecode.ProxyPortPath(state), []byte(port), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

	a := &claudecode.Adapter{Home: home, StateDir: state}
	if _, err := a.ApplyProxyPointer(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if b, _ := os.ReadFile(settings); !bytes.Contains(b, []byte(authority)) {
		t.Fatalf("setup wrote no proxy pointer, so this test proves nothing:\n%s", b)
	}

	var log bytes.Buffer
	contaminationRollback{
		log:      slog.New(slog.NewTextHandler(&log, nil)),
		stateDir: state,
	}.OnContamination([16]byte{1}, "claudecode", "oauth-shape")

	got, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("rollback did not detach the agent:\n%s", got)
	}
	line := log.String()
	for _, want := range []string{"level=ERROR", "M1E-8002", "oauth-shape", "reverted"} {
		if !strings.Contains(line, want) {
			t.Errorf("log line missing %q: %s", want, line)
		}
	}
}

// TestContaminationIsAdmittedAsAGuardDecision — CON-001's durable half. Until
// this landed, the one P0 legal event the whole OAuth guard exists to produce
// lived exclusively in a local slog line: deletable, unordered, unuploadable,
// provable to nobody. 07 §11 keys the `guard_contamination` receipt on
// `subject_id` = this event's event_id, so an event that is never admitted is a
// receipt that can never be minted.
//
// The spool is read back through spool.Records rather than trusting the log
// line's own "record=admitted": that string is the subject's account of itself,
// and grading a subject on its own account is how the last three decorations in
// this repo got written.
func TestContaminationIsAdmittedAsAGuardDecision(t *testing.T) {
	state := t.TempDir()
	sp, err := spool.Open(spool.Config{Dir: filepath.Join(state, "spool")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()
	sc, err := redact.NewScanner(nil)
	if err != nil {
		t.Fatal(err)
	}
	adm, err := capture.New(sp, capture.Config{
		EpochPath: filepath.Join(state, "session_epoch"),
		Redact:    sc.RedactEvent,
	})
	if err != nil {
		t.Fatal(err)
	}

	var log bytes.Buffer
	session := [16]byte{9, 9, 9, 4}
	contaminationRollback{
		log:      slog.New(slog.NewTextHandler(&log, nil)),
		stateDir: state,
		adm:      adm,
	}.OnContamination(session, "claudecode", "oauth_marker")

	// Records reads to the DURABLE cursor, and Append does not fsync — the
	// adaptive cadence (07 §6: 500 ms while only diagnostics are pending) owns
	// that. Without this the first run of this test read zero records while the
	// log line said `record=admitted`, which is the durability boundary working
	// exactly as specified and not a defect. Deliberately NOT forcing a sync in
	// OnContamination itself: 07 §6 forces a full drain on SessionEnd and daemon
	// shutdown and nothing else, and an fsync on the connection's reader
	// goroutine is precisely the slow thing fabric/session.go:72 forbids.
	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("the spool holds %d records, want exactly 1: the contamination handler reverted the "+
			"agent's config and logged, but admitted nothing, so the only account of this P0 is a "+
			"local log line. Log was:\n%s", len(recs), log.String())
	}
	ev := &m1pv1.Event{}
	if err := proto.Unmarshal(recs[0].Payload, ev); err != nil {
		t.Fatal(err)
	}
	gd := ev.GetGuardDecision()
	if gd == nil {
		t.Fatalf("the admitted event is not a GuardDecision but %T — the receipt class 07 §11 mints "+
			"is keyed on this body", ev.GetBody())
	}
	if gd.GetOutcome() != m1pv1.GuardOutcome_GUARD_OUTCOME_REFUSED {
		t.Errorf("outcome = %v, want REFUSED: contamination is the refusal, and an event that does "+
			"not say so files a P0 as routine traffic", gd.GetOutcome())
	}
	if gd.GetReasonCode() != "oauth_marker" {
		t.Errorf("reason_code = %q, want the alert's own code", gd.GetReasonCode())
	}
	if gd.GetSampleRate() != 1 {
		t.Errorf("sample_rate = %v, want 1: contamination is never sampled, and a rate below 1 lets "+
			"the compliance surface speak only about a SAMPLE of refusals (07 §3)", gd.GetSampleRate())
	}
	if !bytes.Equal(ev.GetSessionId(), session[:]) {
		t.Errorf("session_id = %x, want the handshake-authenticated id %x", ev.GetSessionId(), session)
	}
	// Class byte 2. 07 §6 closes billing-grade at {usage, verdict_event,
	// receipt_checkpoint} and makes receipted and block-on-full independent
	// properties; a GuardDecision that blocked on a full spool would be this
	// repo quietly widening a set the spec says is a m1p.v2 conversation.
	if c := recs[0].ID.Class(); c != spool.ClassDiagnostic {
		t.Errorf("spool class = %v, want ClassDiagnostic (07 §6's closure)", c)
	}
	if !strings.Contains(log.String(), "record=admitted") {
		t.Errorf("the log line does not report the record's fate: %s", log.String())
	}
}

// A contamination event on an agent that was never pointed at the proxy still
// logs at ERROR — the P0 is the event, not the rollback's outcome.
func TestContaminationRollbackWithNothingProvisioned(t *testing.T) {
	var log bytes.Buffer
	contaminationRollback{
		log:      slog.New(slog.NewTextHandler(&log, nil)),
		stateDir: t.TempDir(),
	}.OnContamination([16]byte{2}, "claudecode", "oauth-shape")
	if line := log.String(); !strings.Contains(line, "level=ERROR") || !strings.Contains(line, "nothing to revert") {
		t.Errorf("log line = %s", line)
	}
}
