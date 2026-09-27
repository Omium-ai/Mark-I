package anchors

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
)

// fakeSandbox returns a canned RunResult — runner/scheduler logic is platform-
// independent; the REAL sandbox is exercised in sandbox_probe_test.go.
type fakeSandbox struct {
	res      RunResult
	err      error
	confined bool
	// floorUp keeps Status() available while err refuses: the Landlock-less Linux shape, where pure parsers still run.
	floorUp bool
	// run, when set, answers per spec.
	run   func(RunSpec) (RunResult, error)
	mu    sync.Mutex
	specs []RunSpec
}

func (f *fakeSandbox) Run(ctx context.Context, spec RunSpec) (RunResult, error) {
	f.mu.Lock()
	f.specs = append(f.specs, spec)
	f.mu.Unlock()
	if f.run != nil {
		return f.run(spec)
	}
	res := f.res
	if len(res.EffectiveEnv) == 0 {
		for k, v := range spec.Env {
			res.EffectiveEnv = append(res.EffectiveEnv, k+"="+v)
		}
	}
	return res, f.err
}
func (f *fakeSandbox) FSConfined() bool { return f.confined }
func (f *fakeSandbox) Status() SandboxStatus {
	if f.err != nil && !f.floorUp {
		return SandboxStatus{Reason: f.err.Error()}
	}
	return SandboxStatus{Available: true}
}

// enabledRuff derives + consents the fixture ruff entry so the runner sees a
// legitimate Enabled row (the only legal provenance).
func enabledRuff(t *testing.T) (CatalogEntry, string) {
	t.Helper()
	wt, _ := fixtureWorkspace(t)
	path := ConsentPath(t.TempDir())
	derived, err := Derive(testSandbox(t), wt)
	if err != nil {
		t.Fatal(err)
	}
	if err := Approve(path, time.Now(), derived...); err != nil {
		t.Fatal(err)
	}
	consented, err := LoadConsent(path)
	if err != nil {
		t.Fatal(err)
	}
	rep := Reconcile(derived, consented)
	for _, e := range rep.Enabled {
		if e.Kind == KindRuff {
			return e, wt
		}
	}
	t.Fatal("no enabled ruff entry")
	return CatalogEntry{}, ""
}

// consentFor writes a fresh consent store covering exactly the given entries
// and returns its path — the Scheduler re-reads it per run.
func consentFor(t *testing.T, entries ...CatalogEntry) string {
	t.Helper()
	path := ConsentPath(t.TempDir())
	if err := Approve(path, time.Now(), entries...); err != nil {
		t.Fatal(err)
	}
	return path
}

var (
	testSession = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	testTask    = [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
)

func TestRunOneEmitsTypedEvidenceOnly(t *testing.T) {
	e, wt := enabledRuff(t)
	// Output the real tool would produce: paths and free text that must NEVER
	// appear in any emitted field.
	sb := &fakeSandbox{res: RunResult{
		ExitCode: 1,
		Stdout: []byte("src/secret_module.py:10:5: E501 Line too long (110 > 100)\n" +
			"src/secret_module.py:44:1: F401 'os' imported but unused\n" +
			"lib/other.py:1:1: E501 Line too long (200 > 100)\n"),
	}}
	em := &fakeEmitter{}
	key, _ := DeriveOutputHMACKey(bytes.Repeat([]byte{7}, 32))
	r := NewRunner(sb, em, key, false)

	if err := r.RunOne(context.Background(), e, testSession, testTask, wt); err != nil {
		t.Fatal(err)
	}
	evs := em.all()
	if len(evs) != 1 {
		t.Fatalf("want exactly one event, got %d", len(evs))
	}
	ev := evs[0]
	if !bytes.Equal(ev.GetSessionId(), testSession[:]) || !bytes.Equal(ev.GetTaskId(), testTask[:]) {
		t.Error("event lost session/task identity")
	}
	vote := ev.GetAnchorVote()
	if vote == nil {
		t.Fatal("body is not AnchorVote")
	}
	if vote.GetAnchorId() != e.ID {
		t.Errorf("anchor_id %q, want %q", vote.GetAnchorId(), e.ID)
	}
	if vote.GetVote() != m1pv1.Verdict_VERDICT_VIOLATED {
		t.Errorf("vote %v, want VIOLATED", vote.GetVote())
	}
	rec := vote.GetEvidence()
	if rec.GetTool() != "ruff" || rec.GetDiagnosticCode() != "E501" {
		t.Errorf("evidence tool/code = %q/%q", rec.GetTool(), rec.GetDiagnosticCode())
	}
	if c := rec.GetCounts(); c.GetErrors() != 3 || c.GetFilesAffected() != 2 {
		t.Errorf("counts %+v, want errors=3 files=2", c)
	}
	if rec.GetCategory() != m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_LINT {
		t.Errorf("category %v", rec.GetCategory())
	}
	if len(rec.GetOutputHmac()) != 32 {
		t.Errorf("output_hmac len %d, want 32", len(rec.GetOutputHmac()))
	}

	// THE typed-evidence discipline (07 §4): no path, no excerpt, anywhere in
	// the marshaled event. Structural in the proto; asserted here against the
	// bytes so a future field can't smuggle content past the type system.
	raw, err := proto.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"secret_module", "src/", "lib/other", "Line too long", "imported but unused"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Errorf("marshaled event leaks %q", leak)
		}
	}

	// Integrity envelope: resolved binary hash matches the consent-time hash
	// (binary untouched), env attested, no L0 root ⇒ empty root, no tamper.
	integ := vote.GetIntegrity()
	if !bytes.Equal(integ.GetResolvedBinaryHashes()["ruff"], e.BinaryHash) {
		t.Error("resolved binary hash != consent-time hash for untouched binary")
	}
	if len(integ.GetEnvScrubAttestation()) != 32 {
		t.Error("env scrub attestation missing")
	}
	if len(integ.GetWorktreeMerkleRoot()) != 0 {
		t.Error("no cortexd root was pushed; worktree_merkle_root must be EMPTY, never a placeholder")
	}
	if integ.GetTamper() {
		t.Error("tamper flagged on a clean run")
	}

	// The sandbox saw the scrubbed allow-list and the consented argv.
	spec := sb.specs[0]
	if spec.Argv[0] != e.BinaryPath {
		t.Errorf("argv[0] %q is not the consented binary", spec.Argv[0])
	}
	for k := range spec.Env {
		switch k {
		case "PATH", "LANG", "TZ":
		default:
			t.Errorf("env key %q outside the allow-list", k)
		}
	}
}

func TestRunOneL0RootSeam(t *testing.T) {
	e, wt := enabledRuff(t)
	sb := &fakeSandbox{res: RunResult{ExitCode: 0}}
	em := &fakeEmitter{}
	r := NewRunner(sb, em, nil, false)
	root := bytes.Repeat([]byte{9}, 32)
	r.SetL0Root(root)
	if err := r.RunOne(context.Background(), e, testSession, testTask, wt); err != nil {
		t.Fatal(err)
	}
	if got := em.all()[0].GetAnchorVote().GetIntegrity().GetWorktreeMerkleRoot(); !bytes.Equal(got, root) {
		t.Errorf("worktree_merkle_root %x, want pushed L0 root", got)
	}
	// cortexd down ⇒ cleared ⇒ back to incomplete.
	r.SetL0Root(nil)
	if err := r.RunOne(context.Background(), e, testSession, testTask, wt); err != nil {
		t.Fatal(err)
	}
	if got := em.all()[1].GetAnchorVote().GetIntegrity().GetWorktreeMerkleRoot(); len(got) != 0 {
		t.Errorf("cleared root must yield empty (incomplete) envelope, got %x", got)
	}
}

// fakeDeviceKey satisfies identity.DeviceKey with a key the test retains the
// public half of -- SetSigner takes the interface, so this drives the exact
// same Runner.signVote/RunOne path a real identity.DeviceKey would.
type fakeDeviceKey struct{ priv ed25519.PrivateKey }

func (f fakeDeviceKey) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(f.priv, msg), nil }
func (f fakeDeviceKey) KeyID() string                   { return "test-device-key" }

// canonicalAnchorVote reproduces verify.proto's signing input independently
// of production code: deterministic marshal with signature cleared.
func canonicalAnchorVote(t *testing.T, av *m1pv1.AnchorVote) []byte {
	t.Helper()
	clone, ok := proto.Clone(av).(*m1pv1.AnchorVote)
	if !ok {
		t.Fatal("clone is not *AnchorVote")
	}
	clone.Signature = nil
	canon, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		t.Fatal(err)
	}
	return canon
}

func TestRunOneSignsVoteWithDeviceKey(t *testing.T) {
	e, wt := enabledRuff(t)
	sb := &fakeSandbox{res: RunResult{ExitCode: 0}}
	em := &fakeEmitter{}
	r := NewRunner(sb, em, nil, false)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r.SetSigner(fakeDeviceKey{priv: priv})
	if err := r.RunOne(context.Background(), e, testSession, testTask, wt); err != nil {
		t.Fatal(err)
	}
	vote := em.all()[0].GetAnchorVote()
	if len(vote.GetSignature()) == 0 {
		t.Fatal("armed signer produced an empty signature")
	}
	if !ed25519.Verify(pub, canonicalAnchorVote(t, vote), vote.GetSignature()) {
		t.Fatal("signature does not verify over canonical(anchor_id, vote, evidence, integrity)")
	}
}

func TestRunOneNoSignerLeavesVoteUnsigned(t *testing.T) {
	e, wt := enabledRuff(t)
	sb := &fakeSandbox{res: RunResult{ExitCode: 0}}
	em := &fakeEmitter{}
	r := NewRunner(sb, em, nil, false) // no SetSigner call: pre-enrollment / soft-fail posture
	if err := r.RunOne(context.Background(), e, testSession, testTask, wt); err != nil {
		t.Fatal(err)
	}
	if got := em.all()[0].GetAnchorVote().GetSignature(); len(got) != 0 {
		t.Fatalf("unarmed runner emitted a signature (%x); empty is required, never forged", got)
	}
}

func TestRunOneTamperOnSwappedBinary(t *testing.T) {
	e, wt := enabledRuff(t)
	// Swap the binary AFTER consent, without re-deriving: run-time effective-
	// execution hashing must flip tamper (FR-VERIFY-005, PATH-shim axis).
	if err := os.WriteFile(e.BinaryPath, []byte("#!/bin/sh\necho shimmed\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sb := &fakeSandbox{res: RunResult{ExitCode: 0}}
	em := &fakeEmitter{}
	r := NewRunner(sb, em, nil, false)
	if err := r.RunOne(context.Background(), e, testSession, testTask, wt); err != nil {
		t.Fatal(err)
	}
	vote := em.all()[0].GetAnchorVote()
	if !vote.GetIntegrity().GetTamper() {
		t.Fatal("swapped binary did not raise tamper")
	}
	// The consent gate is AT the execution point: the swapped binary must
	// never have reached the sandbox (doc.go "NOTHING RUNS WITHOUT CONSENT").
	if len(sb.specs) != 0 {
		t.Fatal("swapped binary was executed before the tamper check")
	}
	if vote.GetVote() != m1pv1.Verdict_VERDICT_ERROR {
		t.Fatalf("tamper refusal voted %v, want VERDICT_ERROR", vote.GetVote())
	}
	if got := vote.GetEvidence().GetDiagnosticCode(); got != "binary_tamper" {
		t.Errorf("diagnostic_code %q, want binary_tamper", got)
	}
}

// EvidenceRecord.tool and the resolved_binary_hashes key carry the same
// finite-catalog vocabulary as diagnostic_code (artifacts.proto), so they come
// from the derivation table, not from the entry — an entry that names its own
// tool must not push that string into the emitted event.
func TestRunOneToolNameComesFromTheCatalogTable(t *testing.T) {
	e, wt := enabledRuff(t)
	e.Tool = "/home/dev/secret-project AKIAIOSFODNN7EXAMPLE"
	em := &fakeEmitter{}
	r := NewRunner(&fakeSandbox{res: RunResult{ExitCode: 0}}, em, nil, false)
	if err := r.RunOne(context.Background(), e, testSession, testTask, wt); err != nil {
		t.Fatal(err)
	}
	vote := em.all()[0].GetAnchorVote()
	if _, ok := vote.GetIntegrity().GetResolvedBinaryHashes()["ruff"]; !ok {
		t.Errorf("resolved_binary_hashes keyed %v, want the table name \"ruff\"", vote.GetIntegrity().GetResolvedBinaryHashes())
	}
	raw, err := proto.Marshal(em.all()[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("AKIA")) {
		t.Error("entry-supplied tool name reached the emitted event")
	}
}

func TestRunOneInfraFailureIsErrorNeverViolated(t *testing.T) {
	e, wt := enabledRuff(t)
	cases := map[string]struct {
		sb   *fakeSandbox
		code string
	}{
		"sandbox unavailable": {&fakeSandbox{err: ErrSandboxUnavailable}, "sandbox_unavailable"},
		"timeout":             {&fakeSandbox{res: RunResult{TimedOut: true, ExitCode: -1, Signal: "killed"}}, "timeout"},
		"output cap":          {&fakeSandbox{res: RunResult{Truncated: true, ExitCode: -1, Signal: "killed"}, err: ErrOutputCap}, "output_cap"},
		"crash":               {&fakeSandbox{res: RunResult{ExitCode: -1, Signal: "segmentation fault"}}, "killed"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			em := &fakeEmitter{}
			r := NewRunner(tc.sb, em, nil, false)
			if err := r.RunOne(context.Background(), e, testSession, testTask, wt); err != nil {
				t.Fatal(err)
			}
			vote := em.all()[0].GetAnchorVote()
			if vote.GetVote() != m1pv1.Verdict_VERDICT_ERROR {
				t.Fatalf("infra failure voted %v — must be ERROR, never VIOLATED (F-31)", vote.GetVote())
			}
			if got := vote.GetEvidence().GetDiagnosticCode(); got != tc.code {
				t.Errorf("failure code %q, want %q", got, tc.code)
			}
		})
	}
}

func TestRunOneRefusals(t *testing.T) {
	e, wt := enabledRuff(t)
	em := &fakeEmitter{}
	r := NewRunner(&fakeSandbox{}, em, nil, false)

	t.Run("unimplemented kind refused, never faked", func(t *testing.T) {
		bad := e
		bad.Kind = Kind("mystery")
		if err := r.RunOne(context.Background(), bad, testSession, testTask, wt); !errors.Is(err, ErrRefused) {
			t.Fatalf("err = %v, want ErrRefused", err)
		}
	})
	t.Run("unconsented entry refused", func(t *testing.T) {
		bad := e
		bad.ConsentedAt = time.Time{}
		if err := r.RunOne(context.Background(), bad, testSession, testTask, wt); !errors.Is(err, ErrRefused) {
			t.Fatalf("err = %v, want ErrRefused", err)
		}
	})
	t.Run("test-class without opt-in refused", func(t *testing.T) {
		bad := e
		bad.SideEffect = SideEffectTest
		if err := r.RunOne(context.Background(), bad, testSession, testTask, wt); !errors.Is(err, ErrRefused) {
			t.Fatalf("err = %v, want ErrRefused", err)
		}
	})
	if len(em.all()) != 0 {
		t.Fatal("a refusal emitted a vote — refusals must emit NOTHING")
	}

	t.Run("repo-code executor demands FS confinement", func(t *testing.T) {
		// eslint/cargo-check/go-vet evaluate repo-supplied code: without
		// kernel write confinement they must refuse, same as test-class.
		sb := &fakeSandbox{confined: false}
		rc := NewRunner(sb, em, nil, false)
		re := e
		re.ExecsRepoCode = true
		if err := rc.RunOne(context.Background(), re, testSession, testTask, wt); err != nil {
			t.Fatal(err)
		}
		if !sb.specs[0].RequireFSConfined {
			t.Fatal("ExecsRepoCode run did not set RequireFSConfined")
		}
		// The flag is also sourced from the detector table by kind: a
		// hand-built entry of a repo-code kind with the flag zeroed must not
		// weaken the precondition (same rule as the table-sourced tool name).
		spoofed := e
		spoofed.Kind = KindEslint
		spoofed.ExecsRepoCode = false
		if err := rc.RunOne(context.Background(), spoofed, testSession, testTask, wt); err != nil {
			t.Fatal(err)
		}
		if !sb.specs[1].RequireFSConfined {
			t.Fatal("table-flagged kind with entry flag zeroed skipped RequireFSConfined")
		}
	})

	t.Run("test-class with opt-in demands FS confinement", func(t *testing.T) {
		optIn := NewRunner(&fakeSandbox{confined: false}, em, nil, true)
		te := e
		te.SideEffect = SideEffectTest
		if err := optIn.RunOne(context.Background(), te, testSession, testTask, wt); err != nil {
			t.Fatal(err)
		}
		// The spec must carry the precondition; the real sandbox refuses on it.
		spec := optIn.sb.(*fakeSandbox).specs[0]
		if !spec.RequireFSConfined {
			t.Fatal("test-class run did not set RequireFSConfined (FR-VERIFY-003)")
		}
	})
}

func TestHandlerRegistryExhaustive(t *testing.T) {
	// The init() assert already panics on mismatch; this pins the property in
	// a test so a deleted assert cannot pass silently.
	for k := range detectors {
		if _, ok := defaultHandlers[k]; !ok {
			t.Errorf("detector %q has no handler", k)
		}
	}
	for k := range defaultHandlers {
		if _, ok := detectors[k]; !ok {
			t.Errorf("handler %q has no detector", k)
		}
	}
}

func TestParsers(t *testing.T) {
	cases := []struct {
		kind    Kind
		res     RunResult
		verdict m1pv1.Verdict
		code    string
		errs    uint32
		warns   uint32
	}{
		{KindRuff, RunResult{ExitCode: 0}, m1pv1.Verdict_VERDICT_SATISFIED, "", 0, 0},
		{KindRuff, RunResult{ExitCode: 2, Stderr: []byte("ruff failed: bad config")}, m1pv1.Verdict_VERDICT_ERROR, "tool_error", 0, 0},
		{KindTsc, RunResult{ExitCode: 1, Stdout: []byte("src/a.ts(1,5): error TS2345: nope\nsrc/a.ts(9,1): warning TS6133: unused")}, m1pv1.Verdict_VERDICT_VIOLATED, "TS2345", 1, 1},
		{KindCargoCheck, RunResult{ExitCode: 101, Stderr: []byte("src/main.rs:2:5: error[E0308]: mismatched types")}, m1pv1.Verdict_VERDICT_VIOLATED, "E0308", 1, 0},
		{KindGoVet, RunResult{ExitCode: 1, Stderr: []byte("# x\n./main.go:3:2: unreachable code")}, m1pv1.Verdict_VERDICT_VIOLATED, "", 1, 0},
		{KindEslint, RunResult{ExitCode: 1, Stdout: []byte(`[{"filePath":"/w/a.js","errorCount":2,"warningCount":1,"messages":[{"ruleId":"no-unused-vars","severity":2}]}]`)}, m1pv1.Verdict_VERDICT_VIOLATED, "no-unused-vars", 2, 1},
		{KindEslint, RunResult{ExitCode: 2, Stdout: []byte("Oops! Something went wrong!")}, m1pv1.Verdict_VERDICT_ERROR, "tool_error", 0, 0},
		// libtest's classic and terse (1.90+) failure lines both count; the `failures:` summary does not.
		{KindCargoTest, RunResult{ExitCode: 101, Stdout: []byte("test a::b ... FAILED\nc::d --- FAILED\n\nfailures:\n    a::b\n    c::d\n\ntest result: FAILED. 0 passed; 2 failed")}, m1pv1.Verdict_VERDICT_VIOLATED, "test_failed", 2, 0},
		// A suite the sandbox cannot host (a socket bind refused) is infra, never the change's fault.
		{KindCargoTest, RunResult{ExitCode: 101, Stdout: []byte("x --- FAILED\nthread 'x' panicked: called `Result::unwrap()` on an `Err` value: Os { code: 13, kind: PermissionDenied, message: \"Permission denied\" }")}, m1pv1.Verdict_VERDICT_ERROR, "sandbox_denied", 1, 0},
		{KindGoTest, RunResult{ExitCode: 1, Stderr: []byte("listen unix /tmp/x.sock: bind: permission denied\nFAIL\tpkg\t0.1s")}, m1pv1.Verdict_VERDICT_ERROR, "sandbox_denied", 0, 0},
		// Scoped plugin rule ids are legitimate vocabulary and pass through.
		{KindEslint, RunResult{ExitCode: 1, Stdout: []byte(`[{"filePath":"/w/a.ts","errorCount":1,"warningCount":0,"messages":[{"ruleId":"@typescript-eslint/no-explicit-any","severity":2}]}]`)}, m1pv1.Verdict_VERDICT_VIOLATED, "@typescript-eslint/no-explicit-any", 1, 0},
		// A repo-controlled plugin names its own rules: free text (paths,
		// secrets, whitespace) must NEVER reach diagnostic_code.
		{KindEslint, RunResult{ExitCode: 1, Stdout: []byte(`[{"filePath":"/w/a.js","errorCount":1,"warningCount":0,"messages":[{"ruleId":"AKIAIOSFODNN7EXAMPLE/home/dev/secret-project/src/pricing.ts leaked","severity":2}]}]`)}, m1pv1.Verdict_VERDICT_VIOLATED, "rule_other", 1, 0},
	}
	for _, tc := range cases {
		v, rec := defaultHandlers[tc.kind](tc.res)
		if v != tc.verdict {
			t.Errorf("%s exit=%d: verdict %v, want %v", tc.kind, tc.res.ExitCode, v, tc.verdict)
		}
		if rec.GetDiagnosticCode() != tc.code {
			t.Errorf("%s: code %q, want %q", tc.kind, rec.GetDiagnosticCode(), tc.code)
		}
		if rec.GetCounts().GetErrors() != tc.errs || rec.GetCounts().GetWarnings() != tc.warns {
			t.Errorf("%s: counts %+v, want e=%d w=%d", tc.kind, rec.GetCounts(), tc.errs, tc.warns)
		}
	}
}

func TestSchedulerCoalescesFastAndDefersSlow(t *testing.T) {
	e, wt := enabledRuff(t)
	slow := e
	slow.ID = "cargo-check@cat-1"
	slow.Kind = KindCargoCheck
	slow.Tool = "cargo-check"
	slow.Class = ClassSlow

	sb := &fakeSandbox{res: RunResult{ExitCode: 0}}
	em := &fakeEmitter{}
	r := NewRunner(sb, em, nil, false)
	s := NewScheduler(r, []CatalogEntry{e, slow}, consentFor(t, e, slow), wt, nil)
	s.Debounce = 30 * time.Millisecond
	s.IdleAfter = 500 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)

	// A burst of tool events: coalesced per (task, anchor) ⇒ exactly ONE fast
	// run; the slow anchor stays deferred while activity continues.
	for i := 0; i < 5; i++ {
		s.NoteToolUse(testSession, testTask)
		time.Sleep(5 * time.Millisecond)
	}
	// past the debounce, well before idle: the fast run hashes the binary twice and reads git first (a CI Windows runner takes tens of ms for that), so wait for the vote rather than sleep a fixed slice
	first := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(first) && len(em.all()) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	votes := em.all()
	if len(votes) != 1 || votes[0].GetAnchorVote().GetAnchorId() != e.ID {
		ids := []string{}
		for _, v := range votes {
			ids = append(ids, v.GetAnchorVote().GetAnchorId())
		}
		t.Fatalf("after burst want exactly one fast vote, got %v", ids)
	}

	// Idle: the slow anchor runs once.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(em.all()) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	votes = em.all()
	if len(votes) != 2 || votes[1].GetAnchorVote().GetAnchorId() != slow.ID {
		t.Fatalf("slow anchor did not run at idle: %d votes", len(votes))
	}

	// Idle again with nothing owed: no duplicate slow run.
	time.Sleep(200 * time.Millisecond)
	if got := len(em.all()); got != 2 {
		t.Fatalf("idle re-ran slow work that was not owed: %d votes", got)
	}
}

func TestSchedulerStopDrainsSlowNow(t *testing.T) {
	e, wt := enabledRuff(t)
	e.Class = ClassSlow
	sb := &fakeSandbox{res: RunResult{ExitCode: 0}}
	em := &fakeEmitter{}
	s := NewScheduler(NewRunner(sb, em, nil, false), []CatalogEntry{e}, consentFor(t, e), wt, nil)
	s.IdleAfter = time.Hour // idle can never fire; only Stop may drain
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)

	s.NoteToolUse(testSession, testTask)
	s.Stop(testSession, testTask)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(em.all()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if len(em.all()) != 1 {
		t.Fatal("Stop did not drain the owed slow anchor")
	}
	// Stop with nothing owed is a no-op.
	s.Stop(testSession, testTask)
	time.Sleep(50 * time.Millisecond)
	if len(em.all()) != 1 {
		t.Fatal("second Stop re-ran drained work")
	}
}

// Settle is Stop plus the wait the gate needs: it returns once the owed slow run has voted, and no later than its ctx.
func TestSchedulerSettleWaitsForTheOwedRun(t *testing.T) {
	e, wt := enabledRuff(t)
	e.Class = ClassSlow
	sb := &fakeSandbox{run: func(RunSpec) (RunResult, error) {
		time.Sleep(150 * time.Millisecond)
		return RunResult{ExitCode: 0}, nil
	}}
	em := &fakeEmitter{}
	s := NewScheduler(NewRunner(sb, em, nil, false), []CatalogEntry{e}, consentFor(t, e), wt, nil)
	s.IdleAfter = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)

	s.NoteToolUse(testSession, testTask)
	sctx, scancel := context.WithTimeout(ctx, 5*time.Second)
	defer scancel()
	s.Settle(sctx, testSession, testTask)
	if len(em.all()) != 1 {
		t.Fatalf("Settle returned before the owed run voted: %d votes", len(em.all()))
	}
	s.NoteToolUse(testSession, testTask)
	short, shortCancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer shortCancel()
	start := time.Now()
	s.Settle(short, testSession, testTask)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("Settle outlived its ctx")
	}
}

// The slow queue is quickest-first by the newest run's wall time: after one round in which cargo-test took long and go-vet did not, the next Stop queues go-vet first.
func TestSchedulerSlowQueueIsQuickestFirst(t *testing.T) {
	e, wt := enabledRuff(t)
	slowA := e
	slowA.ID, slowA.Kind, slowA.Tool, slowA.Class = "cargo-test@cat-1", KindCargoTest, "cargo-test", ClassSlow
	slowA.SideEffect = SideEffectTest
	slowA.Argv = []string{e.Argv[0], "test"}
	slowB := e
	slowB.ID, slowB.Kind, slowB.Tool, slowB.Class = "go-vet@cat-1", KindGoVet, "go-vet", ClassSlow
	slowB.Argv = []string{e.Argv[0], "vet"}
	sb := &fakeSandbox{run: func(spec RunSpec) (RunResult, error) {
		if spec.Argv[1] == "test" {
			time.Sleep(120 * time.Millisecond)
		}
		return RunResult{ExitCode: 0}, nil
	}}
	s := NewScheduler(NewRunner(sb, &fakeEmitter{}, nil, true), []CatalogEntry{slowA, slowB}, consentFor(t, slowA, slowB), wt, nil)
	s.IdleAfter = time.Hour
	if got := s.slowOrder(wt); got[0].ID != slowB.ID {
		t.Fatalf("never-run anchors put static checks before test suites, got %s first", got[0].ID)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	s.NoteToolUse(testSession, testTask)
	sctx, scancel := context.WithTimeout(ctx, 5*time.Second)
	s.Settle(sctx, testSession, testTask)
	scancel()
	if got := s.slowOrder(wt); got[0].ID != slowB.ID {
		t.Fatalf("after a slow cargo-test the next Stop must queue go-vet first, got %s", got[0].ID)
	}
}

// Two enabled roots, two catalogs: a session runs the anchors of the worktree its hook cwd names, a session no cwd places runs the default's — never another project's.
func TestSchedulerRunsEachSessionsOwnWorktree(t *testing.T) {
	e, wtA := enabledRuff(t)
	wtB := t.TempDir()
	if err := os.WriteFile(filepath.Join(wtB, "pyproject.toml"), []byte("[tool.ruff]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eB := e
	eB.ID = "ruff@cat-1" // same tool, second project
	var mu sync.Mutex
	var ran []string
	sb := &fakeSandbox{run: func(spec RunSpec) (RunResult, error) {
		mu.Lock()
		ran = append(ran, spec.WorktreeRO)
		mu.Unlock()
		return RunResult{ExitCode: 0}, nil
	}}
	s := NewScheduler(NewRunner(sb, &fakeEmitter{}, nil, false), nil, consentFor(t, e), "", nil)
	s.SetCatalogs(wtA, map[string][]CatalogEntry{wtA: {e}, wtB: {eB}})
	s.Debounce = 10 * time.Millisecond
	s.IdleAfter = time.Hour
	sessA, sessB, sessNone := [16]byte{1}, [16]byte{2}, [16]byte{3}
	s.WorktreeFor = func(sid [16]byte) string {
		switch sid {
		case sessA:
			return wtA
		case sessB:
			return wtB
		}
		return ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	for _, sid := range [][16]byte{sessA, sessB, sessNone} {
		s.NoteToolUse(sid, testTask)
		sctx, scancel := context.WithTimeout(ctx, 5*time.Second)
		s.Settle(sctx, sid, testTask)
		scancel()
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ran) != 3 || ran[0] != wtA || ran[1] != wtB || ran[2] != wtA {
		t.Fatalf("worktrees run %v, want [%s %s %s]", ran, wtA, wtB, wtA)
	}
}

// A monorepo (a repository whose top holds no config) runs the anchors of each project directly below it; a plain folder of repositories runs its own catalog alone.
func TestSchedulerFansOutToAMonorepoSubprojects(t *testing.T) {
	e, _ := enabledRuff(t)
	mono := t.TempDir()
	if err := os.MkdirAll(filepath.Join(mono, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	backend, frontend := filepath.Join(mono, "backend"), filepath.Join(mono, "frontend")
	for _, d := range []string{backend, frontend} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "pyproject.toml"), []byte("[tool.ruff]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(mono, "README.md"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ProjectSubdirs(mono); len(got) != 2 || got[0] != backend || got[1] != frontend {
		t.Fatalf("ProjectSubdirs %v", got)
	}
	if err := os.WriteFile(filepath.Join(mono, "package.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ProjectSubdirs(mono); got != nil {
		t.Fatalf("a top with its own config derives itself, not its children: %v", got)
	}
	if err := os.Remove(filepath.Join(mono, "package.json")); err != nil {
		t.Fatal(err)
	}
	folder := t.TempDir() // no .git: a workspace of repositories, never fanned out
	if got := ProjectSubdirs(folder); got != nil {
		t.Fatalf("a folder that is no repository derives nothing below it: %v", got)
	}

	var mu sync.Mutex
	var ran []string
	sb := &fakeSandbox{run: func(spec RunSpec) (RunResult, error) {
		mu.Lock()
		ran = append(ran, spec.WorktreeRO)
		mu.Unlock()
		return RunResult{ExitCode: 0}, nil
	}}
	s := NewScheduler(NewRunner(sb, &fakeEmitter{}, nil, false), nil, consentFor(t, e), "", nil)
	s.SetCatalogs(mono, map[string][]CatalogEntry{mono: {}, backend: {e}, frontend: {e}, folder: {}, filepath.Join(folder, "svc"): {e}})
	s.Debounce = 10 * time.Millisecond
	s.IdleAfter = time.Hour
	inMono, inFolder := [16]byte{1}, [16]byte{2}
	s.WorktreeFor = func(sid [16]byte) string {
		if sid == inMono {
			return mono
		}
		return folder
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	for _, sid := range [][16]byte{inMono, inFolder} {
		s.NoteToolUse(sid, testTask)
		sctx, scancel := context.WithTimeout(ctx, 5*time.Second)
		s.Settle(sctx, sid, testTask)
		scancel()
	}
	mu.Lock()
	defer mu.Unlock()
	sort.Strings(ran)
	if len(ran) != 2 || ran[0] != backend || ran[1] != frontend {
		t.Fatalf("worktrees run %v, want the monorepo's two projects and nothing under the folder", ran)
	}
}

// TestSchedulerConsentRevocationStopsRuns pins doc.go's "NOTHING RUNS WITHOUT
// CONSENT" against the Scheduler's lifetime: entries are snapshotted at
// construction, and the runner's pre-exec binary-hash gate catches a swapped
// binary but NOT a withdrawn consent — so a revocation mid-lifetime must be
// caught by the per-run store re-check, not wait for a daemon restart.
func TestSchedulerConsentRevocationStopsRuns(t *testing.T) {
	e, wt := enabledRuff(t)
	cpath := consentFor(t, e)
	em := &fakeEmitter{}
	s := NewScheduler(NewRunner(&fakeSandbox{res: RunResult{ExitCode: 0}}, em, nil, false), []CatalogEntry{e}, cpath, wt, nil)
	s.Debounce = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)

	// Consented: the anchor runs.
	s.NoteToolUse(testSession, testTask)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(em.all()) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if len(em.all()) != 1 {
		t.Fatal("consented anchor did not run")
	}

	// Revoke mid-lifetime: the SAME Scheduler must stop running it.
	if err := Revoke(cpath, e.ID); err != nil {
		t.Fatal(err)
	}
	s.NoteToolUse(testSession, testTask)
	time.Sleep(150 * time.Millisecond)
	if got := len(em.all()); got != 1 {
		t.Fatalf("revoked anchor still ran (%d votes) — revocation did not propagate", got)
	}
}

func TestSchedulerDeferSlowSeam(t *testing.T) {
	e, wt := enabledRuff(t)
	e.Class = ClassSlow
	em := &fakeEmitter{}
	s := NewScheduler(NewRunner(&fakeSandbox{res: RunResult{ExitCode: 0}}, em, nil, false), []CatalogEntry{e}, consentFor(t, e), wt, nil)
	s.IdleAfter = 20 * time.Millisecond
	s.DeferSlow = func() bool { return true } // battery-saver: always deferred
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	s.NoteToolUse(testSession, testTask)
	time.Sleep(150 * time.Millisecond)
	if len(em.all()) != 0 {
		t.Fatal("DeferSlow=true still ran a slow anchor")
	}
}

// enabledTest derives + consents the fixture go-test entry under the repo opt-in.
func enabledTest(t *testing.T) (CatalogEntry, string) {
	t.Helper()
	wt, _ := fixtureWorkspace(t)
	optInTests(t, wt)
	derived, err := Derive(testSandbox(t), wt)
	if err != nil {
		t.Fatal(err)
	}
	rep := Reconcile(derived, mustLoad(t, consentFor(t, derived...)))
	for _, e := range rep.Enabled {
		if e.Kind == KindGoTest {
			return e, wt
		}
	}
	t.Fatal("no enabled go-test entry")
	return CatalogEntry{}, ""
}

func mustLoad(t *testing.T, path string) []ConsentRecord {
	t.Helper()
	c, err := LoadConsent(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestRunOneTestAnchorRepoOptIn (FR-VERIFY-003): refused without the repo opt-in, RequireFSConfined with it.
func TestRunOneTestAnchorRepoOptIn(t *testing.T) {
	e, wt := enabledTest(t)
	em := &fakeEmitter{}
	sb := &fakeSandbox{res: RunResult{ExitCode: 1, Stdout: []byte("--- FAIL: TestX (0.00s)\n--- FAIL: TestY (0.00s)\nFAIL\n")}}
	r := NewRunner(sb, em, nil, false)

	if err := os.Remove(RepoOptInPath(wt)); err != nil {
		t.Fatal(err)
	}
	if err := r.RunOne(context.Background(), e, testSession, testTask, wt); !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused without %s", err, RepoOptInPath(wt))
	}
	if len(em.all()) != 0 || len(sb.specs) != 0 {
		t.Fatal("refusal ran or emitted something")
	}

	optInTests(t, wt)
	if err := r.RunOne(context.Background(), e, testSession, testTask, wt); err != nil {
		t.Fatal(err)
	}
	if !sb.specs[0].RequireFSConfined || sb.specs[0].Argv[1] != "test" {
		t.Fatalf("test anchor spec %+v lacks RequireFSConfined", sb.specs[0])
	}
	ev := em.all()[0].GetAnchorVote()
	if ev.GetVote() != m1pv1.Verdict_VERDICT_VIOLATED || ev.GetEvidence().GetCounts().GetErrors() != 2 ||
		ev.GetEvidence().GetCategory() != m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_TEST {
		t.Fatalf("vote %v evidence %v, want VIOLATED with 2 TEST errors", ev.GetVote(), ev.GetEvidence())
	}
}

// gitFake answers the runner's sandboxed git calls with planted output, everything else with res.
func gitFake(status, diff string, res RunResult) func(RunSpec) (RunResult, error) {
	return func(spec RunSpec) (RunResult, error) {
		switch gitSub(spec.Argv) {
		case "config":
			return RunResult{}, nil
		case "status":
			return RunResult{Stdout: []byte(status)}, nil
		case "diff":
			return RunResult{Stdout: []byte(diff)}, nil
		}
		return res, nil
	}
}

// gitSub is the subcommand of a hardened git argv ("" for any other binary's argv).
func gitSub(argv []string) string {
	if len(argv) == 0 || strings.TrimSuffix(filepath.Base(argv[0]), filepath.Ext(argv[0])) != "git" {
		return ""
	}
	for i := 1; i < len(argv); i++ {
		if argv[i] == "-c" {
			i++
			continue
		}
		if !strings.HasPrefix(argv[i], "-") {
			return argv[i]
		}
	}
	return ""
}

func TestDiffTaxonomy(t *testing.T) {
	for name, c := range map[string]struct {
		paths []string
		delta int32
		want  m1pv1.DiffClassification
	}{
		"none":            {nil, 0, m1pv1.DiffClassification_DIFF_CLASSIFICATION_NONE},
		"src":             {[]string{"src/app.py", "lib/x.go"}, 0, m1pv1.DiffClassification_DIFF_CLASSIFICATION_SRC_ONLY},
		"test dir":        {[]string{"src/app.py", "tests/test_app.py"}, 0, m1pv1.DiffClassification_DIFF_CLASSIFICATION_TEST_TOUCHED},
		"go test file":    {[]string{"pkg/x_test.go"}, 0, m1pv1.DiffClassification_DIFF_CLASSIFICATION_TEST_TOUCHED},
		"jest spec":       {[]string{"src/a.spec.tsx"}, 0, m1pv1.DiffClassification_DIFF_CLASSIFICATION_TEST_TOUCHED},
		"config wins":     {[]string{"tests/test_app.py", "ruff.toml"}, 3, m1pv1.DiffClassification_DIFF_CLASSIFICATION_CONFIG_TOUCHED},
		"eslintrc":        {[]string{".eslintrc.json"}, 0, m1pv1.DiffClassification_DIFF_CLASSIFICATION_CONFIG_TOUCHED},
		"suppression":     {[]string{"src/app.py"}, 1, m1pv1.DiffClassification_DIFF_CLASSIFICATION_SUPPRESSION_TOUCHED},
		"test beats supp": {[]string{"tests/x.py"}, 1, m1pv1.DiffClassification_DIFF_CLASSIFICATION_TEST_TOUCHED},
	} {
		if got := classifyDiff(c.paths, c.delta); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	diff := "--- a/x.py\n+++ b/x.py\n@@ -1 +1,3 @@\n-import os  # noqa\n+import os  # noqa: F401\n+x = 1  # type: ignore\n+// nolint:gosec\n+#[allow(dead_code)]\n+/* eslint-disable */ // @ts-ignore\n # noqa in context is not counted\n"
	if got := suppressionDelta([]byte(diff)); got != 5 {
		t.Errorf("suppression delta %d, want 5 (6 added − 1 removed)", got)
	}
}

// TestRunOneDiffReachesTheEnvelope (FR-VERIFY-004): the sandboxed git read lands both diff fields on the vote.
func TestRunOneDiffReachesTheEnvelope(t *testing.T) {
	e, wt := enabledRuff(t)
	fakeBin(t, filepath.Dir(e.BinaryPath), "git", "git version 2.46.0")
	if err := os.Mkdir(filepath.Join(wt, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	em := &fakeEmitter{}
	sb := &fakeSandbox{run: gitFake(
		"# branch.oid 1111111111111111111111111111111111111111\x001 .M N... 100644 100644 100644 aaaa aaaa src/app.py\x00? tests/test_new.py\x00",
		"--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n+import os  # noqa\n",
		RunResult{ExitCode: 0})}
	if err := NewRunner(sb, em, nil, false).RunOne(context.Background(), e, testSession, testTask, wt); err != nil {
		t.Fatal(err)
	}
	in := em.all()[0].GetAnchorVote().GetIntegrity()
	if in.GetDiffClassification() != m1pv1.DiffClassification_DIFF_CLASSIFICATION_TEST_TOUCHED || in.GetSuppressionDirectiveDelta() != 1 {
		t.Fatalf("integrity %v, want TEST_TOUCHED with delta 1", in)
	}
	if len(sb.specs) != 4 || sb.specs[3].Argv[0] != e.BinaryPath {
		t.Fatalf("%d sandbox runs, want three git reads (config, status, diff) then the anchor", len(sb.specs))
	}
	for i, s := range sb.specs[:3] {
		if gitSub(s.Argv) != []string{"config", "status", "diff"}[i] || s.WorktreeRO != wt || !slices.Equal(s.Argv[1:1+len(gitHardening)], gitHardening) {
			t.Fatalf("git read %+v is not the hardened read of the worktree", s.Argv)
		}
	}
	// No git on PATH ⇒ UNSPECIFIED, never a guess.
	t.Setenv("PATH", t.TempDir())
	em2 := &fakeEmitter{}
	if err := NewRunner(&fakeSandbox{res: RunResult{ExitCode: 0}}, em2, nil, false).RunOne(context.Background(), e, testSession, testTask, wt); err != nil {
		t.Fatal(err)
	}
	if c := em2.all()[0].GetAnchorVote().GetIntegrity().GetDiffClassification(); c != m1pv1.DiffClassification_DIFF_CLASSIFICATION_UNSPECIFIED {
		t.Fatalf("without git: %v, want UNSPECIFIED", c)
	}
}

// TestEmitExcerptRefusals (FR-VERIFY-016): E1 needs a receipt, E2 a vpc|selfhost profile, E0 has no excerpt.
func TestEmitExcerptRefusals(t *testing.T) {
	em := &fakeEmitter{}
	r := NewRunner(&fakeSandbox{}, em, nil, false)
	emit := func(x *m1pv1.EvidenceExcerpt) error {
		return r.EmitExcerpt(context.Background(), testSession, testTask, x)
	}
	e1 := &m1pv1.EvidenceExcerpt{Tier: m1pv1.EvidenceTier_EVIDENCE_TIER_E1, AttachmentName: "hunks"}
	e2 := &m1pv1.EvidenceExcerpt{Tier: m1pv1.EvidenceTier_EVIDENCE_TIER_E2, AttachmentName: "diff"}
	t.Setenv("MARK1_PROFILE", "")
	for name, x := range map[string]*m1pv1.EvidenceExcerpt{
		"E1 without receipt": e1, "E2 on the cloud path": e2,
		"E0": {Tier: m1pv1.EvidenceTier_EVIDENCE_TIER_E0}, "unspecified": {},
	} {
		if err := emit(x); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: err = %v, want ErrRefused", name, err)
		}
	}
	t.Setenv("MARK1_PROFILE", "cloud")
	if err := emit(e2); !errors.Is(err, ErrRefused) {
		t.Errorf("E2 under an unknown profile: err = %v, want ErrRefused", err)
	}
	if len(em.all()) != 0 {
		t.Fatal("a refused excerpt was emitted")
	}
	e1.RedactionReceiptId = []byte{1, 2, 3}
	r.StateDir = t.TempDir()
	if err := consents.Write(r.StateDir, consents.Consents{E1: true}); err != nil {
		t.Fatal(err)
	}
	if err := emit(e1); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MARK1_PROFILE", "vpc")
	if err := emit(e2); err != nil {
		t.Fatal(err)
	}
	if evs := em.all(); len(evs) != 2 || evs[0].GetEvidenceExcerpt().GetTier() != m1pv1.EvidenceTier_EVIDENCE_TIER_E1 {
		t.Fatalf("emitted %v", evs)
	}
}

// TestEmitExcerptE1NeedsTheStepFourConsent: a receipted E1 excerpt still needs
// gates/consents.json {e1:true} (desktop spec §3.2 Step 4) — absent, false or
// a runner with no state dir refuses with a Dropped{e1_consent_absent} row and
// emits nothing; the consent flipping on mid-run admits the next one without a
// restart, and the E2/E0 paths never read it.
func TestEmitExcerptE1NeedsTheStepFourConsent(t *testing.T) {
	em := &fakeEmitter{}
	r := NewRunner(&fakeSandbox{}, em, nil, false)
	var dropped []string
	r.OnDropped = func(reason string) { dropped = append(dropped, reason) }
	e1 := func() *m1pv1.EvidenceExcerpt {
		return &m1pv1.EvidenceExcerpt{Tier: m1pv1.EvidenceTier_EVIDENCE_TIER_E1, AttachmentName: "hunks", RedactionReceiptId: []byte{1, 2, 3}}
	}
	emit := func(x *m1pv1.EvidenceExcerpt) error {
		return r.EmitExcerpt(context.Background(), testSession, testTask, x)
	}
	if err := emit(e1()); !errors.Is(err, ErrRefused) {
		t.Fatalf("no state dir: err = %v, want ErrRefused", err)
	}
	r.StateDir = t.TempDir()
	if err := emit(e1()); !errors.Is(err, ErrRefused) {
		t.Fatalf("no consents.json: err = %v, want ErrRefused", err)
	}
	if err := consents.Write(r.StateDir, consents.Consents{E1: false, CloudJudge: true, Training: true}); err != nil {
		t.Fatal(err)
	}
	if err := emit(e1()); !errors.Is(err, ErrRefused) {
		t.Fatalf("e1:false: err = %v, want ErrRefused", err)
	}
	if len(em.all()) != 0 {
		t.Fatal("a refused E1 excerpt was emitted")
	}
	if len(dropped) != 3 || dropped[0] != "e1_consent_absent" {
		t.Fatalf("dropped = %v, want three e1_consent_absent rows — a consent refusal is accounted, never silent", dropped)
	}
	if err := consents.Write(r.StateDir, consents.Consents{E1: true}); err != nil {
		t.Fatal(err)
	}
	if err := emit(e1()); err != nil {
		t.Fatalf("e1:true: %v", err)
	}
	if evs := em.all(); len(evs) != 1 || evs[0].GetEvidenceExcerpt().GetTier() != m1pv1.EvidenceTier_EVIDENCE_TIER_E1 {
		t.Fatalf("emitted %v", evs)
	}
	if err := consents.Write(r.StateDir, consents.Consents{}); err != nil {
		t.Fatal(err)
	}
	if err := emit(e1()); !errors.Is(err, ErrRefused) {
		t.Fatalf("consent withdrawn: err = %v, want ErrRefused on the very next excerpt", err)
	}
	r.OnDropped = nil
	if err := emit(e1()); !errors.Is(err, ErrRefused) {
		t.Fatalf("no OnDropped wired: err = %v, want ErrRefused still", err)
	}
	t.Setenv("MARK1_PROFILE", "vpc")
	if err := emit(&m1pv1.EvidenceExcerpt{Tier: m1pv1.EvidenceTier_EVIDENCE_TIER_E2, AttachmentName: "diff"}); err != nil {
		t.Fatalf("E2 does not read the e1 consent: %v", err)
	}
	if len(dropped) != 4 || len(em.all()) != 2 {
		t.Fatalf("dropped %v, emitted %d", dropped, len(em.all()))
	}
}

// TestBaselineFindingsNeverViolate: the verdict is about the change. A repo that already carried 243 ruff findings (omium-mark1's own root, 2026-09-19) must not read VIOLATED on every turn — only a finding in a file the agent touched does; untouched findings are the baseline, and a tool that failed on the baseline alone is SATISFIED with diagnostic baseline_only.
func TestBaselineFindingsNeverViolate(t *testing.T) {
	h := defaultHandlers[KindRuff]
	out := []byte("legacy/old.py:3:1: F401 `os` imported but unused\nsrc/new.py:7:5: F821 Undefined name `x`\nvendor/lib/x.py:1:1: E501 Line too long\n")
	set := map[string]bool{"src/new.py": true, "vendor/": true}
	v, ev := h(RunResult{ExitCode: 1, Stdout: out, Touched: set, Worktree: "/w"})
	if v != m1pv1.Verdict_VERDICT_VIOLATED || ev.GetCounts().GetErrors() != 2 || ev.GetCounts().GetFilesAffected() != 2 || ev.GetDiagnosticCode() != "F821" {
		t.Fatalf("touched findings must violate and be counted: %v %+v", v, ev)
	}
	v, ev = h(RunResult{ExitCode: 1, Stdout: out, Touched: map[string]bool{"README.md": true}, Worktree: "/w"})
	if v != m1pv1.Verdict_VERDICT_SATISFIED || ev.GetDiagnosticCode() != "baseline_only" || ev.GetCounts().GetErrors() != 0 {
		t.Fatalf("baseline-only failure must read SATISFIED/baseline_only: %v %+v", v, ev)
	}
	v, ev = h(RunResult{ExitCode: 1, Stdout: out, Worktree: "/w"})
	if v != m1pv1.Verdict_VERDICT_VIOLATED || ev.GetCounts().GetErrors() != 3 {
		t.Fatalf("no git ⇒ every finding counts: %v %+v", v, ev)
	}
	v, ev = h(RunResult{ExitCode: 2, Stdout: []byte("ruff: error: bad flag\n"), Touched: set, Worktree: "/w"})
	if v != m1pv1.Verdict_VERDICT_ERROR || ev.GetDiagnosticCode() != "tool_error" {
		t.Fatalf("a tool failure with no findings stays an error: %v %+v", v, ev)
	}
	wt := t.TempDir()
	if !touched(set, wt, filepath.Join(wt, "src", "new.py")) || touched(set, wt, "./legacy/old.py") || !touched(set, wt, "vendor/lib/x.py") {
		t.Fatal("touched must resolve absolute, ./-prefixed and directory-listed paths")
	}
}

func TestTouchedSetDistinguishesCleanFromUnknown(t *testing.T) {
	if (diffFacts{}).touchedSet() != nil {
		t.Fatal("no git answer must read as unknown (nil)")
	}
	if s := (diffFacts{known: true}).touchedSet(); s == nil || len(s) != 0 {
		t.Fatalf("a clean tree is the empty set, got %v", s)
	}
	if s := (diffFacts{known: true, paths: []string{"a/b.py", "dir/"}}).touchedSet(); !s["a/b.py"] || !s["dir"] {
		t.Fatalf("paths lost: %v", s)
	}
}

// A test suite the sandbox cannot host (its last run said sandbox_denied) is not owed again for an hour: it fails the same way every Stop and costs minutes each time. A suite that merely failed is owed as before.
func TestSchedulerSuspendsASandboxDeniedSuite(t *testing.T) {
	e, wt := enabledRuff(t)
	slow := e
	slow.ID, slow.Kind, slow.Tool, slow.Class = "cargo-test@cat-1", KindCargoTest, "cargo-test", ClassSlow
	slow.SideEffect = SideEffectTest
	slow.Argv = []string{e.Argv[0], "test"}
	out := "x --- FAILED\nthread 'x' panicked: Os { code: 13, kind: PermissionDenied, message: \"Permission denied\" }"
	sb := &fakeSandbox{run: func(spec RunSpec) (RunResult, error) {
		if spec.Argv[1] == "test" {
			return RunResult{ExitCode: 101, Stdout: []byte(out)}, nil
		}
		return RunResult{ExitCode: 0}, nil
	}}
	s := NewScheduler(NewRunner(sb, &fakeEmitter{}, nil, true), []CatalogEntry{slow}, consentFor(t, slow), wt, nil)
	s.IdleAfter = time.Hour
	if got := s.slowOrder(wt); len(got) != 1 {
		t.Fatalf("a never-run suite is owed: %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	s.NoteToolUse(testSession, testTask)
	sctx, scancel := context.WithTimeout(ctx, 5*time.Second)
	s.Settle(sctx, testSession, testTask)
	scancel()
	if s.runner.LastCode(wt, slow.ID) != "sandbox_denied" {
		t.Fatalf("last code: %q", s.runner.LastCode(wt, slow.ID))
	}
	if got := s.slowOrder(wt); len(got) != 0 {
		t.Fatalf("a sandbox-denied suite must be suspended, still owed: %v", got)
	}
	s.mu.Lock()
	s.lastAt[wt+"\x00"+slow.ID] = time.Now().Add(-2 * suspendFor)
	s.mu.Unlock()
	if got := s.slowOrder(wt); len(got) != 1 {
		t.Fatalf("after the suspension the suite is owed again: %v", got)
	}
	out = "y --- FAILED\nassertion failed: left == right"
	s.NoteToolUse(testSession, testTask)
	sctx, scancel = context.WithTimeout(ctx, 5*time.Second)
	s.Settle(sctx, testSession, testTask)
	scancel()
	if got := s.slowOrder(wt); len(got) != 1 {
		t.Fatalf("a genuinely failing suite is owed as before: %v", got)
	}
}

// Probe is first run's "checks ready": the project's consented static anchors run once through RunOne's path, no vote is emitted, tests stay out, and a second probe or an unarmed project is refused.
func TestSchedulerProbeRunsStaticOnceAndEmitsNothing(t *testing.T) {
	e, wt := enabledRuff(t)
	tests := e
	tests.ID, tests.Kind, tests.Tool, tests.SideEffect = "pytest@cat-1", KindPytest, "pytest", SideEffectTest
	release := make(chan struct{})
	sb := &fakeSandbox{run: func(RunSpec) (RunResult, error) {
		<-release
		return RunResult{ExitCode: 0}, nil
	}}
	em := &fakeEmitter{}
	s := NewScheduler(NewRunner(sb, em, nil, true), []CatalogEntry{e, tests}, consentFor(t, e, tests), wt, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := s.Probe(ctx, t.TempDir(), func(string, string) {}); !errors.Is(err, ErrProbeUnknown) {
		t.Fatalf("an unarmed project must be refused, got %v", err)
	}
	got := make(chan [2]string, 4)
	n, err := s.Probe(ctx, wt, func(id, code string) { got <- [2]string{id, code} })
	if err != nil || n != 1 {
		t.Fatalf("Probe = %d, %v; want the one static anchor", n, err)
	}
	if _, err := s.Probe(ctx, wt, func(string, string) {}); !errors.Is(err, ErrProbeBusy) {
		t.Fatalf("a second probe while one runs must be refused, got %v", err)
	}
	close(release)
	select {
	case r := <-got:
		if r[0] != e.ID || r[1] != "" {
			t.Fatalf("done(%q, %q), want (%q, \"\")", r[0], r[1], e.ID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probe never reported")
	}
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := s.Probe(ctx, wt, func(id, code string) { got <- [2]string{id, code} }); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("the finished probe still holds the project: %v", err)
		}
	}
	<-got
	if n := len(em.all()); n != 0 {
		t.Fatalf("a probe emitted %d events; it must emit no AnchorVote", n)
	}
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if n := len(sb.specs); n != 2 {
		t.Fatalf("sandbox ran %d times over two probes, want 2 (static only)", n)
	}
}
