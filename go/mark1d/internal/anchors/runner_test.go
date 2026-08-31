//go:build unix

package anchors

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"
)

// fakeSandbox returns a canned RunResult — runner/scheduler logic is platform-
// independent; the REAL sandbox is exercised in sandbox_linux_test.go.
type fakeSandbox struct {
	res      RunResult
	err      error
	confined bool
	mu       sync.Mutex
	specs    []RunSpec
}

func (f *fakeSandbox) Run(ctx context.Context, spec RunSpec) (RunResult, error) {
	f.mu.Lock()
	f.specs = append(f.specs, spec)
	f.mu.Unlock()
	res := f.res
	if len(res.EffectiveEnv) == 0 {
		for k, v := range spec.Env {
			res.EffectiveEnv = append(res.EffectiveEnv, k+"="+v)
		}
	}
	return res, f.err
}
func (f *fakeSandbox) FSConfined() bool { return f.confined }

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
	s.IdleAfter = 120 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)

	// A burst of tool events: coalesced per (task, anchor) ⇒ exactly ONE fast
	// run; the slow anchor stays deferred while activity continues.
	for i := 0; i < 5; i++ {
		s.NoteToolUse(testSession, testTask)
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(60 * time.Millisecond) // past debounce, before idle
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
