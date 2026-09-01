// The full-session arm of `neg_wire_no_paths_no_excerpts` (12 §9 row 4;
// 02 CON-004, NFR-PRIVACY-001). anchors/wire_test.go audits the anchor
// runner's own emissions; this file audits the OTHER three planes that put
// bytes on the same wire, in the order the bytes actually travel:
//
//	tailer (reads transcripts off the customer's disk)
//	  → capture admission (normalize → redact → seq → class → spool)
//	    → uplink (what is POSTed to controld over M1P/1)
//
// It lives in package uplink because uplink is the only one of the three that
// can import the other two without a cycle, and because the last stage — the
// bytes on the socket — is the only place the claim is finally true. Each
// plane keeps its own non-emptiness assertion: an audit that walked an empty
// event set reports "no paths on the wire" exactly like a clean one does.
package uplink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/taskseg"
)

// ---------------------------------------------------------------------------
// The detector
// ---------------------------------------------------------------------------

// wirePathToken is anchors/wire_test.go's pathToken, deliberately kept
// identical: one privacy plane, one definition of "looks like a path". A path
// is rooted/relative-prefixed, carries a traversal segment, or is
// separator-joined with a file extension on its last component. It is NOT
// "contains a slash" — eslint rule ids ("import/order") and media types
// legitimately contain one, and a check that flagged those would be deleted by
// the first engineer it blocked, which is how privacy tests die.
var wirePathToken = regexp.MustCompile(`^(/|\./|\.\./|~/|[A-Za-z]:[\\/])` +
	`|[/\\]\.{1,2}[/\\]` +
	`|[/\\][^/\\]*\.[A-Za-z0-9]{1,8}($|[^A-Za-z0-9])`)

func looksLikeWirePath(s string) bool {
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '"' || r == '\'' || r == ',' || r == '`'
	}) {
		if wirePathToken.MatchString(tok) {
			return true
		}
	}
	return false
}

// wireViolation names the leak precisely enough to fix: which plane, which
// audit point, which proto field, which rule.
type wireViolation struct {
	plane, at, field, val, rule string
}

func (v wireViolation) String() string {
	return fmt.Sprintf("[%s @ %s] %s = %q violates the %s rule", v.plane, v.at, v.field, v.val, v.rule)
}

// visitWireStrings calls fn for every populated string field, string map key
// and nested-message string in m. Reflecting over the message rather than
// grepping the marshaled bytes is what makes the assertion structural: it names
// the field that leaked, and it keeps working when a new field appears.
func visitWireStrings(m protoreflect.Message, prefix string, fn func(field, val string)) {
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		name := prefix + string(fd.Name())
		switch {
		case fd.IsMap():
			v.Map().Range(func(k protoreflect.MapKey, mv protoreflect.Value) bool {
				if fd.MapKey().Kind() == protoreflect.StringKind {
					fn(name+".<key>", k.String())
				}
				visitWireValue(fd.MapValue(), mv, name+"["+k.String()+"]", fn)
				return true
			})
		case fd.IsList():
			l := v.List()
			for i := range l.Len() {
				visitWireValue(fd, l.Get(i), fmt.Sprintf("%s[%d]", name, i), fn)
			}
		default:
			visitWireValue(fd, v, name, fn)
		}
		return true
	})
}

func visitWireValue(fd protoreflect.FieldDescriptor, v protoreflect.Value, name string, fn func(field, val string)) {
	switch fd.Kind() {
	case protoreflect.StringKind:
		fn(name, v.String())
	case protoreflect.MessageKind, protoreflect.GroupKind:
		visitWireStrings(v.Message(), name+".", fn)
	}
}

// auditWireStrings walks every string on one wire message and returns both the
// violations and the number of fields actually inspected. The count is not
// decoration: a walk that visited nothing satisfies every negative below.
func auditWireStrings(plane, at string, m proto.Message) (vs []wireViolation, visited int) {
	visitWireStrings(m.ProtoReflect(), "", func(field, val string) {
		visited++
		if looksLikeWirePath(val) {
			vs = append(vs, wireViolation{plane, at, field, val, "path"})
		}
		if strings.ContainsAny(val, " \t\n\r") {
			// E0 fields are closed vocabularies (tool names, model ids, vendor
			// ids, enum-ish codes). Prose is the opt-in E1 class, and free text
			// is how an excerpt travels.
			vs = append(vs, wireViolation{plane, at, field, val, "excerpt"})
		}
	})
	return vs, visited
}

// auditWireBytes is the backstop for everything the string walk cannot see —
// digests, HMACs, opaque payloads, compressed framing: the literals planted in
// the drivers' INPUT must not survive anywhere in the encoding.
func auditWireBytes(plane, at string, raw []byte) []wireViolation {
	var vs []wireViolation
	for _, plant := range wirePlants {
		if bytes.Contains(raw, []byte(plant)) {
			vs = append(vs, wireViolation{plane, at, "<raw bytes>", plant, "planted-literal"})
		}
	}
	return vs
}

func failOnViolations(t *testing.T, vs []wireViolation) {
	t.Helper()
	for _, v := range vs {
		t.Errorf("%s\n\t02 CON-004 / NFR-PRIVACY-001: evidence is typed, never free text — "+
			"path_role, never path; no excerpts on the default tier", v)
	}
}

// ---------------------------------------------------------------------------
// The plants
// ---------------------------------------------------------------------------

// wirePlants are the literals the drivers are fed. Every one of them is a
// filesystem path fragment, a home directory, or a source excerpt that a real
// coding session puts in front of these planes, and NONE of them may appear in
// any byte the daemon sends. They double as the fixture's own proof of
// adversariality: wirePlantsAreInTheInput asserts each one really is present in
// what the drivers consumed, so a fixture that quietly went clean fails loudly
// rather than passing vacuously.
var wirePlants = []string{
	// From the committed corpus (conformance/hooks/claudecode/v2.1.251).
	"/home/devuser",
	"workspace/acme-app",
	"run-tests.sh",
	"retry helper",
	// Planted into the adversarial transcript lines below.
	"/home/jsmith",
	"acme-merger",
	"valuation.py",
	"def price(deal)",
	`C:\Users\jsmith`,
	"~/notes/merger.md",
	".claude/projects",
	// Planted into taskseg's touched-file input.
	"payroll/salaries.go",
	"clients/acme-merger/term-sheet.md",
}

// ---------------------------------------------------------------------------
// Plane 1 driver: the tailer, over the committed corpus plus adversarial lines
// ---------------------------------------------------------------------------

const wireCorpusRoot = "../../../../conformance/hooks/claudecode/v2.1.251"

// corpusSession is the parent session of the committed transcript layout; the
// adversarial lines are appended to that same stream so they ride the real
// discovery + containment path rather than a stream invented here.
const corpusSession = "3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55"

// adversarialLines are transcript lines in the vendor's v2.1.251 shape,
// carrying what a real session carries and the fixtures happen not to: an
// absolute path under another user's home, a source excerpt on both sides of an
// edit, a stack trace, a Windows path, a `~/` home reference, and the vendor's
// own transcript-store path. Each has usage and a fresh (message.id, requestId)
// so it MUST emit — an adversarial line the plane skips proves nothing.
var adversarialLines = []string{
	`{"parentUuid":"aa000000-0000-4000-8000-000000000090","isSidechain":false,"type":"assistant",` +
		`"cwd":"/home/devuser/workspace/acme-app","gitBranch":"feature/acme-merger","userType":"external",` +
		`"entrypoint":"cli","version":"2.1.251","sessionId":"` + corpusSession + `",` +
		`"uuid":"aa000000-0000-4000-8000-000000000091","timestamp":"2026-08-29T10:20:00.000Z",` +
		`"requestId":"req_01AdvPathLeakAAAAAAAA","message":{"id":"msg_01AdvPathLeakAAAAAAAA","type":"message",` +
		`"role":"assistant","model":"claude-fable-5","content":[{"type":"tool_use","id":"toolu_01AdvAAAA",` +
		`"name":"Edit","input":{"file_path":"/home/jsmith/clients/acme-merger/valuation.py",` +
		`"old_string":"def price(deal):\n    return deal.base\n",` +
		`"new_string":"def price(deal):\n    return deal.base * 1.07\n"}}],` +
		`"usage":{"input_tokens":12,"output_tokens":231,"cache_creation_input_tokens":0,` +
		`"cache_read_input_tokens":4096,"service_tier":"standard"}}}`,
	`{"parentUuid":"aa000000-0000-4000-8000-000000000091","isSidechain":false,"type":"assistant",` +
		`"cwd":"/home/jsmith/clients/acme-merger","gitBranch":"feature/acme-merger","userType":"external",` +
		`"entrypoint":"cli","version":"2.1.251","sessionId":"` + corpusSession + `",` +
		`"uuid":"aa000000-0000-4000-8000-000000000092","timestamp":"2026-08-29T10:21:00.000Z",` +
		`"requestId":"req_01AdvPathLeakBBBBBBBB","message":{"id":"msg_01AdvPathLeakBBBBBBBB","type":"message",` +
		`"role":"assistant","model":"claude-fable-5","content":[{"type":"text","text":` +
		`"Traceback (most recent call last):\n  File \"/home/jsmith/clients/acme-merger/valuation.py\", line 42, in price\n` +
		`    return deal.base * rate  # see C:\\Users\\jsmith\\secrets\\rates.csv and ~/notes/merger.md"}],` +
		`"usage":{"input_tokens":9,"output_tokens":64,"cache_creation_input_tokens":0,` +
		`"cache_read_input_tokens":4160,"service_tier":"standard"}}}`,
	`{"parentUuid":"aa000000-0000-4000-8000-000000000092","isSidechain":false,"type":"assistant",` +
		`"cwd":"/home/devuser/workspace/acme-app","gitBranch":"main","userType":"external",` +
		`"entrypoint":"cli","version":"2.1.251","sessionId":"` + corpusSession + `",` +
		`"uuid":"aa000000-0000-4000-8000-000000000093","timestamp":"2026-08-29T10:22:00.000Z",` +
		`"requestId":"req_01AdvPathLeakCCCCCCCC","message":{"id":"msg_01AdvPathLeakCCCCCCCC","type":"message",` +
		`"role":"assistant","model":"claude-fable-5","content":[{"type":"tool_use","id":"toolu_01AdvCCCC",` +
		`"name":"Read","input":{"file_path":"/home/jsmith/.claude/projects/-home-jsmith-clients-acme-merger/notes.md",` +
		`"offset":1}}],"usage":{"input_tokens":7,"output_tokens":31,"cache_creation_input_tokens":0,` +
		`"cache_read_input_tokens":4191,"service_tier":"standard"}}}`,
}

// adversarialKeys are the (message.id) values the lines above must produce —
// the sighting that proves the plants traversed the plane instead of being
// skipped as noise.
var adversarialKeys = []string{
	"msg_01AdvPathLeakAAAAAAAA", "msg_01AdvPathLeakBBBBBBBB", "msg_01AdvPathLeakCCCCCCCC",
}

// taskFiles is the R2 overlap input: the touched-file paths taskseg digests
// into TaskOpen.file_set_digest. Real paths, because a digest fed a clean path
// proves nothing about the digest.
var taskFiles = [][]string{
	{"/home/jsmith/clients/acme-merger/valuation.py", "/home/devuser/workspace/acme-app/internal/payroll/salaries.go"},
	{"/home/jsmith/clients/acme-merger/term-sheet.md"},
}

type corpusExpectations struct {
	WorkspaceRoot string `json:"workspace_root"`
	Streams       []struct {
		File        string            `json:"file"`
		UsageEvents []json.RawMessage `json:"usage_events"`
	} `json:"streams"`
}

func loadCorpusExpectations(t *testing.T) corpusExpectations {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(wireCorpusRoot, "transcripts", "expectations.json"))
	if err != nil {
		t.Fatalf("corpus missing (08 §5 rule 3: no fixture, no adapter): %v", err)
	}
	var e corpusExpectations
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

// stageTranscripts copies the committed transcript tree into a temp dir — the
// corpus is read-only — and appends the adversarial lines to the parent stream.
// Returns the staged dir and the exact bytes the tailer will read, so the
// positive control can prove the input was adversarial.
func stageTranscripts(t *testing.T) (dir string, consumed []byte) {
	t.Helper()
	src := filepath.Join(wireCorpusRoot, "transcripts", "-home-devuser-workspace-acme-app")
	dir = t.TempDir()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		dst := filepath.Join(dir, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o700)
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if filepath.Base(p) == corpusSession+".jsonl" {
			if !bytes.HasSuffix(b, []byte("\n")) {
				b = append(b, '\n')
			}
			b = append(b, []byte(strings.Join(adversarialLines, "\n")+"\n")...)
		}
		consumed = append(consumed, b...)
		return os.WriteFile(dst, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dir, consumed
}

// ---------------------------------------------------------------------------
// The audit
// ---------------------------------------------------------------------------

// TestWirePipelineNoPathsNoExcerpts drives tailer → capture → uplink with input
// that genuinely carries absolute paths, another user's home directory, Windows
// paths and source excerpts, and asserts at each plane's own output that none of
// it survives. Each plane asserts it SAW events before it asserts what they do
// not contain (02 CON-004, NFR-PRIVACY-001).
func TestWirePipelineNoPathsNoExcerpts(t *testing.T) {
	exp := loadCorpusExpectations(t)
	dir, consumed := stageTranscripts(t)

	// Positive control 0: the input really carries what the audit hunts.
	// Without this, everything below is a proof about a clean fixture.
	fed := string(consumed) + " " + strings.Join(taskFiles[0], " ") + " " + strings.Join(taskFiles[1], " ")
	for _, plant := range wirePlants {
		// A Windows path is `\`-escaped in the JSON source and unescaped once
		// parsed; either form counts as fed.
		if !strings.Contains(fed, plant) && !strings.Contains(fed, strings.ReplaceAll(plant, `\`, `\\`)) {
			t.Fatalf("plant %q is in neither the staged transcripts nor the taskseg file set — "+
				"the audit would be hunting something nothing feeds it", plant)
		}
	}

	// -----------------------------------------------------------------------
	// Plane 1: the tailer. Real Manager, real discovery, real containment
	// gate, over the staged corpus.
	// -----------------------------------------------------------------------
	set, err := tailers.NewWorkspaceSet(exp.WorkspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	var tailed []*m1pv1.Event
	mgr, err := tailers.NewManager(tailers.Config{
		Dir:          dir,
		StateDir:     t.TempDir(),
		Allowed:      set.Allowed,
		UsageIdemKey: []byte("m1p-usage-idem-TEST-KEY-32bytes!"),
		Emit: func(_ context.Context, ev *m1pv1.Event) error {
			tailed = append(tailed, ev)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mgr.Sweep(ctx)
	if err := mgr.CloseFlush(ctx); err != nil {
		t.Fatal(err)
	}

	wantTailed := len(adversarialLines)
	for _, st := range exp.Streams {
		wantTailed += len(st.UsageEvents)
	}
	if len(tailed) == 0 {
		t.Fatal("PLANE tailer: zero events — an audit over an empty set reports " +
			"'no paths on the wire' exactly like a clean one does")
	}
	if len(tailed) != wantTailed {
		t.Fatalf("PLANE tailer: %d events, want %d (corpus + %d adversarial lines)",
			len(tailed), wantTailed, len(adversarialLines))
	}
	// ...and the adversarial lines specifically must have been PROCESSED, not
	// skipped as noise: a plane that ignored the path-bearing input is a plane
	// this audit never exercised.
	for _, key := range adversarialKeys {
		found := false
		for _, ev := range tailed {
			if ev.GetUsage().GetMessageId() == key {
				found = true
			}
		}
		if !found {
			t.Fatalf("PLANE tailer: adversarial line %s never emitted — the path-bearing "+
				"input was skipped, so nothing about it was proven", key)
		}
	}
	tailerFields := 0
	for i, ev := range tailed {
		vs, n := auditWireStrings("tailer", fmt.Sprintf("Emit event %d", i), ev)
		tailerFields += n
		failOnViolations(t, vs)
		raw, err := proto.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		failOnViolations(t, auditWireBytes("tailer", fmt.Sprintf("Emit event %d", i), raw))
	}
	if tailerFields == 0 {
		t.Fatal("PLANE tailer: walked zero string fields — the walk proved nothing")
	}

	// -----------------------------------------------------------------------
	// Plane 2: capture admission. Real redact scanner, real spool, real epoch
	// file. Fed the tailer's output plus the two other producer shapes that
	// reach admission with path-derived data: taskseg (touched-file digests)
	// and the fabric door (AdmitBytes, encoded Event bytes from a writer).
	// -----------------------------------------------------------------------
	sc, err := redact.NewScanner([]byte("wire-audit-tenant-hmac-root"))
	if err != nil {
		t.Fatal(err)
	}
	sp := openSpool(t)
	adm, err := capture.New(sp, capture.Config{
		EpochPath: filepath.Join(t.TempDir(), "epoch"),
		Redact:    sc.RedactEvent,
	})
	if err != nil {
		t.Fatal(err)
	}
	admitted := 0
	admit := func(ev *m1pv1.Event) {
		t.Helper()
		if err := adm.Admit(ctx, ev); err != nil {
			// Quarantine/shed means the event never reached the spool, so the
			// audit below would walk past it in silence.
			t.Fatalf("PLANE capture: admission refused an event the daemon produces: %v", err)
		}
		admitted++
	}
	for _, ev := range tailed {
		admit(ev)
	}

	// taskseg: the one producer that takes raw filesystem paths as input. Its
	// wire output must be digests only. Production passes nil files today
	// (cmd/main.go), so this arm exercises the path the wiring is built for.
	segKey, err := taskseg.DeriveKey([]byte("wire-audit-tenant-hmac-root"))
	if err != nil {
		t.Fatal(err)
	}
	seg := taskseg.New(segKey)
	sid := uuid.MustParse(corpusSession)
	segEvents := 0
	drive := func(ev *m1pv1.Event, files []string) {
		t.Helper()
		admit(ev)
		for _, te := range seg.Observe(ev, files) {
			admit(te)
			segEvents++
		}
	}
	turn := func() *m1pv1.Event {
		return &m1pv1.Event{SessionId: sid[:], Body: &m1pv1.Event_Turn{
			Turn: &m1pv1.Turn{Initiator: m1pv1.Initiator_INITIATOR_HUMAN}}}
	}
	tool := func(name string) *m1pv1.Event {
		// tool_name from the committed hook corpus's allow-listed vocabulary.
		return &m1pv1.Event{SessionId: sid[:], Body: &m1pv1.Event_ToolUse{
			ToolUse: &m1pv1.ToolUse{ToolName: name, ToolUseId: "toolu_01SynthFixtureTTTTTTTT",
				DurationMs: 4180, Status: m1pv1.ToolStatus_TOOL_STATUS_OK}}}
	}
	drive(turn(), nil)
	drive(tool("Edit"), taskFiles[0])
	drive(turn(), nil)
	drive(tool("Read"), taskFiles[1])
	drive(&m1pv1.Event{SessionId: sid[:], Body: &m1pv1.Event_SessionEnd{
		SessionEnd: &m1pv1.SessionEnd{Reason: m1pv1.EndReason_END_REASON_EXIT, DurationMs: 1320, Drained: true}}}, nil)
	if segEvents == 0 {
		t.Fatal("PLANE capture: taskseg emitted nothing — its path-digest fields were never populated, " +
			"so the file-set digest was never audited")
	}

	// The fabric door: the same pipeline entered as opaque encoded bytes.
	fabricPayload, err := proto.Marshal(&m1pv1.Event{
		SessionId: sid[:],
		Body: &m1pv1.Event_SessionStart{SessionStart: &m1pv1.SessionStart{
			Agent: "claudecode", AgentVersion: "2.1.251",
			WorkspaceId:  bytes.Repeat([]byte{0x7f}, 32), // HMAC_tenant(root path), never the path
			CapturePaths: []m1pv1.CapturePath{m1pv1.CapturePath_CAPTURE_PATH_TRANSCRIPT},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adm.AdmitBytes(ctx, fabricPayload); err != nil {
		t.Fatalf("PLANE capture: the fabric door refused a well-formed event: %v", err)
	}
	admitted++

	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("PLANE capture: the spool is empty — nothing was admitted, so nothing was audited")
	}
	if len(recs) != admitted {
		t.Fatalf("PLANE capture: %d spool records for %d admitted events", len(recs), admitted)
	}
	captureFields, sawFileSetDigest := 0, 0
	census := map[string]int{}
	for i, r := range recs {
		var ev m1pv1.Event
		if err := proto.Unmarshal(r.Payload, &ev); err != nil {
			t.Fatalf("PLANE capture: record %d is not an Event: %v", i, err)
		}
		body := fmt.Sprintf("%T", ev.GetBody())
		census[body[strings.LastIndexByte(body, '.')+1:]]++
		if len(ev.GetTaskOpen().GetFileSetDigest()) > 0 {
			sawFileSetDigest++
		}
		vs, n := auditWireStrings("capture", fmt.Sprintf("spool record %d", i), &ev)
		captureFields += n
		failOnViolations(t, vs)
		// The payload bytes are what ride the Batch verbatim (batch.go's
		// opaque-payload rule), so the byte backstop runs on them, not on a
		// re-encode.
		failOnViolations(t, auditWireBytes("capture", fmt.Sprintf("spool record %d", i), r.Payload))
	}
	if captureFields == 0 {
		t.Fatal("PLANE capture: walked zero string fields — the walk proved nothing")
	}
	// The taskseg arm's own sighting: a TaskOpen with an EMPTY file_set_digest
	// is a path-derived field that was never populated, so the bytes below it
	// were never audited.
	if sawFileSetDigest == 0 {
		t.Fatal("PLANE capture: no TaskOpen carried a file_set_digest — the one field derived " +
			"from real filesystem paths was never on the wire to audit")
	}
	// A census, not a count: one Usage-shaped body repeated 10 times would
	// satisfy len(recs) while leaving TaskOpen, ToolUse and SessionStart —
	// the bodies carrying path-DERIVED fields — unaudited.
	for _, want := range []string{
		"Event_Usage", "Event_TaskOpen", "Event_TaskClose",
		"Event_ToolUse", "Event_SessionStart", "Event_Turn", "Event_SessionEnd",
	} {
		if census[want] == 0 {
			t.Errorf("PLANE capture: no %s reached the spool — that body's fields were never audited", want)
		}
	}

	// -----------------------------------------------------------------------
	// Plane 3: uplink. The bytes on the socket, decoded back off a fake ingest
	// — not the objects we handed it.
	// -----------------------------------------------------------------------
	ingest := &fakeIngest{respond: func(_ int, w http.ResponseWriter, bid string) {
		writeAck(w, http.StatusOK, bid, nil)
	}}
	u, _, _ := newTestUplink(t, sp, ingest, nil)
	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatalf("PLANE uplink: cycle = %v, want advanced", res)
	}
	if ingest.count() != 1 {
		t.Fatalf("PLANE uplink: %d requests, want 1 — nothing was sent, so nothing was audited", ingest.count())
	}
	req := ingest.req(0)
	batch, frames := decodeBody(t, req.body)
	if len(frames) == 0 {
		t.Fatal("PLANE uplink: the POSTed batch carries zero events — an empty batch leaks nothing " +
			"and proves nothing")
	}
	if len(frames) != len(recs) {
		t.Fatalf("PLANE uplink: %d event frames on the wire for %d spool records", len(frames), len(recs))
	}
	uplinkFields := 0
	vs, n := auditWireStrings("uplink", "Batch envelope", batch)
	uplinkFields += n
	failOnViolations(t, vs)
	sawAdversarial := 0
	for i, f := range frames {
		var ev m1pv1.Event
		if err := proto.Unmarshal(f, &ev); err != nil {
			t.Fatalf("PLANE uplink: frame %d is not an Event: %v", i, err)
		}
		for _, key := range adversarialKeys {
			if ev.GetUsage().GetMessageId() == key {
				sawAdversarial++
			}
		}
		vs, n := auditWireStrings("uplink", fmt.Sprintf("POSTed event %d", i), &ev)
		uplinkFields += n
		failOnViolations(t, vs)
	}
	if uplinkFields == 0 {
		t.Fatal("PLANE uplink: walked zero string fields — the walk proved nothing")
	}
	// End-to-end sighting: the path-bearing transcript lines reached the socket.
	// This is what makes the three planes one claim rather than three.
	if sawAdversarial != len(adversarialKeys) {
		t.Fatalf("PLANE uplink: %d of %d adversarial events reached the POST body — "+
			"the plants did not traverse the pipeline the audit claims to cover",
			sawAdversarial, len(adversarialKeys))
	}
	t.Logf("audited tailer %d events/%d fields → capture %d records/%d fields → uplink %d frames/%d fields",
		len(tailed), tailerFields, len(recs), captureFields, len(frames), uplinkFields)
	// The byte backstop over the whole decompressed request body: covers the
	// framing, the digests, the dropped rows and anything a future field adds.
	failOnViolations(t, auditWireBytes("uplink", "decompressed POST body", unzstd(t, req.body)))
	// Headers get the planted-literal rule only: they legitimately carry
	// whitespace ("Bearer tok") and slash-dot shapes ("Go-http-client/1.1"),
	// so the path and excerpt rules do not apply to them.
	for k, vals := range req.header {
		for _, v := range vals {
			failOnViolations(t, auditWireBytes("uplink", "request header "+k, []byte(v)))
		}
	}
}

func unzstd(t *testing.T, body []byte) []byte {
	t.Helper()
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	raw, err := dec.DecodeAll(body, nil)
	if err != nil {
		t.Fatalf("body is not zstd: %v", err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// Positive controls: prove the detector detects, per rule
// ---------------------------------------------------------------------------

// TestWireAuditDetectorRules is the unit half: every rule the audit relies on
// fires on the shapes it exists for, and — the half that keeps the test alive —
// does NOT fire on the legal slash-bearing and dotted traffic that really does
// ride this wire.
func TestWireAuditDetectorRules(t *testing.T) {
	for _, c := range []struct {
		val  string
		want bool
		why  string
	}{
		{"/home/jsmith/clients/acme-merger/valuation.py", true, "absolute path"},
		{"~/notes/merger.md", true, "home-relative path"},
		{"./scripts/run-tests.sh", true, "relative path"},
		{`C:\Users\jsmith\secrets\rates.csv`, true, "windows path"},
		{"acme-plugin/../../etc/passwd", true, "traversal segment"},
		{"src/app/vault.ts", true, "separator-joined with an extension"},
		{"/home/devuser/workspace/acme-app", true, "workspace root"},
		{"import/order", false, "eslint rule id — legal slash-bearing traffic"},
		{"@typescript-eslint/no-explicit-any", false, "scoped eslint rule id"},
		{"claude-fable-5", false, "model id"},
		{"task_seg.v1", false, "algorithm version"},
		{"msg_01SynthFixtureAAAAAAAA", false, "vendor message id"},
		{"standard", false, "service tier"},
		{"claudecode", false, "agent name"},
	} {
		if got := looksLikeWirePath(c.val); got != c.want {
			t.Errorf("looksLikeWirePath(%q) = %v, want %v (%s)", c.val, got, c.want, c.why)
		}
	}
	// The excerpt rule is whitespace, because prose is how an excerpt travels
	// and every legal E0 value is a closed-vocabulary token.
	for _, c := range []struct {
		val  string
		want bool
	}{
		{"def price(deal):\n    return deal.base", true},
		{"Traceback (most recent call last):", true},
		{"unreachable code", true},
		{"claude-fable-5", false},
		{"TOOL_STATUS_OK", false},
	} {
		if got := strings.ContainsAny(c.val, " \t\n\r"); got != c.want {
			t.Errorf("excerpt rule on %q = %v, want %v", c.val, got, c.want)
		}
	}
	// The planted-literal backstop.
	if len(auditWireBytes("x", "y", []byte("...valuation.py..."))) == 0 {
		t.Error("the byte backstop did not fire on a planted literal — it can catch nothing")
	}
	if len(auditWireBytes("x", "y", []byte("nothing to see here"))) != 0 {
		t.Error("the byte backstop fired on clean bytes")
	}
}

// TestWireAuditCatchesAPlantedLeak is the end-to-end half: an event that DOES
// carry a path and DOES carry prose is pushed through the real capture and
// uplink planes, and the audit must catch it at BOTH — once on the spooled
// bytes, once on the bytes that came back off the socket. Without this, a
// green TestWirePipelineNoPathsNoExcerpts is equally consistent with a
// detector that cannot detect.
//
// It also documents a property worth stating out loud: capture admits the leak.
// The admit axis is fail-closed for SECRETS (redact, CON-008) and transparent
// for paths — the path guarantee is upstream, in the typed protos and in what
// the producers put in them. Nothing between here and controld would stop a
// producer that decided to send one.
func TestWireAuditCatchesAPlantedLeak(t *testing.T) {
	const leakPath = "/home/jsmith/clients/acme-merger/valuation.py"
	const leakProse = "grep the merger rate"

	sc, err := redact.NewScanner([]byte("wire-audit-tenant-hmac-root"))
	if err != nil {
		t.Fatal(err)
	}
	sp := openSpool(t)
	adm, err := capture.New(sp, capture.Config{
		EpochPath: filepath.Join(t.TempDir(), "epoch"),
		Redact:    sc.RedactEvent,
	})
	if err != nil {
		t.Fatal(err)
	}
	sid := uuid.MustParse(corpusSession)
	ctx := context.Background()
	// One leak per rule: a path in a string field, prose in another.
	if err := adm.Admit(ctx, &m1pv1.Event{SessionId: sid[:], Body: &m1pv1.Event_Usage{
		Usage: &m1pv1.Usage{IdemKey: bytes.Repeat([]byte{1}, 32), MessageId: "msg_leak",
			RequestId: "req_leak", Model: "claude-fable-5", ServiceTier: leakPath}}}); err != nil {
		t.Fatal(err)
	}
	if err := adm.Admit(ctx, &m1pv1.Event{SessionId: sid[:], Body: &m1pv1.Event_ToolUse{
		ToolUse: &m1pv1.ToolUse{ToolName: leakProse, ToolUseId: "toolu_leak",
			Status: m1pv1.ToolStatus_TOOL_STATUS_OK}}}); err != nil {
		t.Fatal(err)
	}
	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}

	check := func(stage string, vs []wireViolation) {
		t.Helper()
		byRule := map[string]int{}
		for _, v := range vs {
			byRule[v.rule]++
		}
		for _, rule := range []string{"path", "excerpt", "planted-literal"} {
			if byRule[rule] == 0 {
				t.Errorf("%s: the audit did not report a %s violation for a deliberately leaky event "+
					"— the detector cannot detect, so every green run above is meaningless", stage, rule)
			}
		}
	}

	// Capture stage.
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("capture stage: %d records, want 2 — the leak never reached the audit point", len(recs))
	}
	var captureVs []wireViolation
	for i, r := range recs {
		var ev m1pv1.Event
		if err := proto.Unmarshal(r.Payload, &ev); err != nil {
			t.Fatal(err)
		}
		vs, _ := auditWireStrings("capture", fmt.Sprintf("spool record %d", i), &ev)
		captureVs = append(captureVs, vs...)
		captureVs = append(captureVs, auditWireBytes("capture", fmt.Sprintf("spool record %d", i), r.Payload)...)
	}
	check("capture stage", captureVs)

	// Uplink stage: the same leak, read back off the socket.
	ingest := &fakeIngest{respond: func(_ int, w http.ResponseWriter, bid string) {
		writeAck(w, http.StatusOK, bid, nil)
	}}
	u, _, _ := newTestUplink(t, sp, ingest, nil)
	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatalf("uplink stage: cycle = %v, want advanced", res)
	}
	req := ingest.req(0)
	_, frames := decodeBody(t, req.body)
	if len(frames) != 2 {
		t.Fatalf("uplink stage: %d frames, want 2", len(frames))
	}
	var uplinkVs []wireViolation
	for i, f := range frames {
		var ev m1pv1.Event
		if err := proto.Unmarshal(f, &ev); err != nil {
			t.Fatal(err)
		}
		vs, _ := auditWireStrings("uplink", fmt.Sprintf("POSTed event %d", i), &ev)
		uplinkVs = append(uplinkVs, vs...)
	}
	uplinkVs = append(uplinkVs, auditWireBytes("uplink", "decompressed POST body", unzstd(t, req.body))...)
	check("uplink stage", uplinkVs)

	// The tailer plane's audit point is the same walk over the same shape, so
	// the control above covers it; assert it explicitly anyway, since a plane
	// whose detector is only proven by inference is a plane nobody checked.
	tailerVs, visited := auditWireStrings("tailer", "Emit event", &m1pv1.Event{
		SessionId: sid[:], Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{ServiceTier: leakPath, Model: leakProse}}})
	if visited == 0 || len(tailerVs) < 2 {
		t.Errorf("tailer stage: audit reported %d violations over %d fields for a leaky Usage event, want ≥2",
			len(tailerVs), visited)
	}
}
