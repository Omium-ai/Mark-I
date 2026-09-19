package anchors

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"lukechampine.com/blake3"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/evidence"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
)

// ErrRefused means the runner declined to execute at all — unimplemented kind,
// unconsented entry, or a test-class anchor without its opt-in. Per 06 §2.1 a
// refusal emits NO vote: refusing is a statement about this plane, and faking
// a vote for a kind we cannot run is the exact failure PROBE_HANDLERS exists
// to make impossible.
var ErrRefused = errors.New("anchors: run refused")

// Handler turns one completed sandboxed run into (verdict, typed evidence).
// It sees only RunResult — the Runner owns the sandbox call so the integrity
// envelope is computed over the SAME run the handler judged (04 §2.2). The
// handler never sees infra failures: crash/timeout/sandbox-error short-circuit
// to VERDICT_ERROR before parsing (F-31, "error, never violated"). A finding in a file res.Touched does not name is the repo's baseline and never violates (RunResult.Touched); test-class anchors carry no file per failure, so every failure counts there.
type Handler func(res RunResult) (m1pv1.Verdict, *m1pv1.EvidenceRecord)

// defaultHandlers is the PROBE_HANDLERS twin of the detector table: every
// runnable kind, keyed identically; init() in catalog.go asserts the two key
// sets are equal in both directions at process start.
var defaultHandlers = map[Kind]Handler{
	KindRuff:       lineHandler("ruff", m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_LINT, ruffLine),
	KindTsc:        lineHandler("tsc", m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_TYPE, tscLine),
	KindCargoCheck: lineHandler("cargo-check", m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_BUILD, cargoLine),
	KindGoVet:      lineHandler("go-vet", m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_LINT, goVetLine),
	KindEslint:     eslintHandler,
	KindGoTest:     lineHandler("go-test", m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_TEST, failLine(goTestFailRe)),
	KindCargoTest:  lineHandler("cargo-test", m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_TEST, failLine(cargoTestFailRe)),
	KindPytest:     lineHandler("pytest", m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_TEST, failLine(pytestFailRe)),
	KindNpmTest:    lineHandler("npm-test", m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_TEST, failLine(npmTestFailRe)),
}

// diag is one parsed diagnostic line: the file token is used ONLY to count
// distinct files (EvidenceCounts.files_affected) and is never emitted —
// EvidenceRecord structurally has no field that could carry it (artifacts.proto).
type diag struct {
	file    string
	code    string // the tool's own finite vocabulary ("E501", "TS2345", …)
	warning bool
}

var (
	// ruff concise: "path.py:10:5: E501 Line too long"
	ruffRe = regexp.MustCompile(`^(.+?):\d+:\d+: ([A-Z]{1,4}\d{1,4})\b`)
	// tsc --pretty false: "src/x.ts(1,5): error TS2345: ..."
	tscRe = regexp.MustCompile(`^(.+?)\(\d+,\d+\): (error|warning) (TS\d+)`)
	// cargo --message-format=short: "src/main.rs:2:5: error[E0308]: ..."
	cargoRe = regexp.MustCompile(`^(.+?):\d+:\d+: (error|warning)(?:\[([A-Z]\d+)\])?`)
	// go vet: "./file.go:3:2: unreachable code" (vet prints no codes)
	goVetRe = regexp.MustCompile(`^(.+?\.go):\d+:\d+: `)
	// eslint ruleId: "no-unused-vars", "import/order",
	// "@typescript-eslint/no-explicit-any". Unlike ruff/tsc/cargo codes, a
	// ruleId is REPO-CONTROLLED — a local plugin names its own rules, so the
	// string can carry a path, an excerpt or an attacker-chosen payload.
	// artifacts.proto licenses diagnostic_code as "a finite public vocabulary,
	// safe to carry literally"; this grammar (plus the length cap below) is
	// what makes that true here, the same job the bounded regexes above do.
	eslintRuleRe = regexp.MustCompile(`^(@[a-z0-9-]+/)?([a-z0-9-]+/)?[a-z0-9-]+$`)
	// Test runners: one failed test per matching line; no file, no per-test code.
	goTestFailRe    = regexp.MustCompile(`^--- FAIL: `)
	cargoTestFailRe = regexp.MustCompile(`^test \S+ \.\.\. FAILED$`)
	pytestFailRe    = regexp.MustCompile(`^FAILED \S`)
	npmTestFailRe   = regexp.MustCompile(`^(not ok \d+|[✕✗×] )`)
)

func failLine(re *regexp.Regexp) func(string) (diag, bool) {
	return func(l string) (diag, bool) { return diag{code: "test_failed"}, re.MatchString(l) }
}

// eslintRuleCodeMax bounds the emitted rule id; real ids are well under it and
// ingest applies its own length validation (artifacts.proto).
const eslintRuleCodeMax = 64

// eslintRuleCode returns the ruleId when it fits the public rule-id grammar,
// and the fixed "rule_other" otherwise — a violation still votes VIOLATED with
// honest counts, it just declines to carry an unvouched string off the device.
func eslintRuleCode(ruleID string) string {
	if len(ruleID) > eslintRuleCodeMax || !eslintRuleRe.MatchString(ruleID) {
		return "rule_other"
	}
	return ruleID
}

func ruffLine(l string) (diag, bool) {
	m := ruffRe.FindStringSubmatch(l)
	if m == nil {
		return diag{}, false
	}
	return diag{file: m[1], code: m[2]}, true
}

func tscLine(l string) (diag, bool) {
	m := tscRe.FindStringSubmatch(l)
	if m == nil {
		return diag{}, false
	}
	return diag{file: m[1], code: m[3], warning: m[2] == "warning"}, true
}

func cargoLine(l string) (diag, bool) {
	m := cargoRe.FindStringSubmatch(l)
	if m == nil {
		return diag{}, false
	}
	return diag{file: m[1], code: m[3], warning: m[2] == "warning"}, true
}

func goVetLine(l string) (diag, bool) {
	m := goVetRe.FindStringSubmatch(l)
	if m == nil {
		return diag{}, false
	}
	return diag{file: m[1]}, true
}

// lineHandler is the shared line-oriented parser: scan stdout+stderr, count
// errors/warnings/distinct files, take the FIRST error's code as
// diagnostic_code. Verdict mapping is uniform: clean exit ⇒ SATISFIED;
// nonzero exit with parsed errors ⇒ VIOLATED; nonzero without a single parsed
// diagnostic ⇒ the tool itself failed ⇒ VERDICT_ERROR (never violated —
// artifacts.proto: conflating infra failure with violation misstates the
// customer's code as broken).
func lineHandler(tool string, cat m1pv1.EvidenceCategory, parse func(string) (diag, bool)) Handler {
	return func(res RunResult) (m1pv1.Verdict, *m1pv1.EvidenceRecord) {
		var errs, warns, baseline uint32
		files := map[string]bool{}
		code := ""
		for _, l := range strings.Split(string(res.Stdout)+"\n"+string(res.Stderr), "\n") {
			d, ok := parse(strings.TrimSpace(l))
			if !ok {
				continue
			}
			if d.file != "" && !touched(res.Touched, res.Worktree, d.file) {
				baseline++ // the repo carried this before the agent touched anything
				continue
			}
			if d.file != "" {
				files[d.file] = true
			}
			if d.warning {
				warns++
				continue
			}
			errs++
			if code == "" {
				code = d.code
			}
		}
		ev := &m1pv1.EvidenceRecord{
			Tool:           tool,
			DiagnosticCode: code,
			Category:       cat,
			//nolint:gosec // G115: len() of a slice parsed from one tool run, never negative
			Counts: &m1pv1.EvidenceCounts{Errors: errs, Warnings: warns, FilesAffected: uint32(len(files))},
		}
		switch {
		case res.ExitCode == 0:
			return m1pv1.Verdict_VERDICT_SATISFIED, ev
		case errs > 0:
			return m1pv1.Verdict_VERDICT_VIOLATED, ev
		case baseline > 0:
			ev.DiagnosticCode = "baseline_only" // the tool failed on findings the change did not introduce
			return m1pv1.Verdict_VERDICT_SATISFIED, ev
		default:
			ev.DiagnosticCode = "tool_error"
			return m1pv1.Verdict_VERDICT_ERROR, ev
		}
	}
}

// eslintHandler parses `eslint --format json` (a JSON array on stdout) rather
// than lines. Same verdict mapping as lineHandler.
func eslintHandler(res RunResult) (m1pv1.Verdict, *m1pv1.EvidenceRecord) {
	var results []struct {
		FilePath     string `json:"filePath"`
		ErrorCount   uint32 `json:"errorCount"`
		WarningCount uint32 `json:"warningCount"`
		Messages     []struct {
			RuleID   string `json:"ruleId"`
			Severity int    `json:"severity"`
		} `json:"messages"`
	}
	ev := &m1pv1.EvidenceRecord{
		Tool:     "eslint",
		Category: m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_LINT,
		Counts:   &m1pv1.EvidenceCounts{},
	}
	if err := json.Unmarshal(res.Stdout, &results); err != nil {
		ev.DiagnosticCode = "tool_error"
		return m1pv1.Verdict_VERDICT_ERROR, ev
	}
	baseline := uint32(0)
	for _, r := range results {
		if !touched(res.Touched, res.Worktree, r.FilePath) {
			baseline += r.ErrorCount
			continue
		}
		ev.Counts.Errors += r.ErrorCount
		ev.Counts.Warnings += r.WarningCount
		if r.ErrorCount+r.WarningCount > 0 {
			ev.Counts.FilesAffected++
		}
		for _, m := range r.Messages {
			if ev.DiagnosticCode == "" && m.Severity == 2 && m.RuleID != "" {
				ev.DiagnosticCode = eslintRuleCode(m.RuleID)
			}
		}
	}
	switch {
	case res.ExitCode == 0:
		return m1pv1.Verdict_VERDICT_SATISFIED, ev
	case ev.Counts.Errors > 0:
		return m1pv1.Verdict_VERDICT_VIOLATED, ev
	case baseline > 0:
		ev.DiagnosticCode = "baseline_only"
		return m1pv1.Verdict_VERDICT_SATISFIED, ev
	default:
		ev.DiagnosticCode = "tool_error"
		return m1pv1.Verdict_VERDICT_ERROR, ev
	}
}

// Emitter is the capture-admission seam: *capture.Admitter satisfies it, and
// tests substitute a fake to assert the typed-evidence discipline.
type Emitter interface {
	Admit(ctx context.Context, ev *m1pv1.Event) error
}

// treeNoter is the in-package side channel from the runner to the vote tee: which state of the tree a vote judged (the wire vote carries no slot for it — WorktreeMerkleRoot is cortexd's certification root, not this).
type treeNoter interface {
	NoteTree(task [16]byte, anchorID, fingerprint string)
}

// DeriveOutputHMACKey derives the per-tenant anchor-output HMAC key from the
// tenant HMAC root (label parallel to tailers.DeriveUsageIdemKey). Per-tenant
// keyed and not a plain hash for artifacts.proto's reason: diagnostics have
// small vocabularies, so a plain digest is dictionary-invertible and equal
// digests across tenants would leak cross-org correlation.
func DeriveOutputHMACKey(tenantRoot []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, tenantRoot, nil, "m1p.anchor.output", 32)
}

// Runner executes consented catalog entries through the sandbox and emits
// AnchorVote events through capture admission (04 §2.2).
type Runner struct {
	sb   Sandbox
	emit Emitter
	// outputHMACKey is the tenant-derived key for EvidenceRecord.output_hmac.
	// Empty ⇒ the field is omitted (enrollment not landed; P1 fields degrade
	// to absent, never to an unkeyed hash).
	outputHMACKey []byte
	// testOptIn overrides the per-repo opt-in (TestsOptedIn, read per run); the daemon passes false.
	testOptIn bool

	// Evidence is the raw local store (NFR-PRIVACY-005); nil stores nothing.
	Evidence *evidence.Store
	// CacheRoot holds the per-tool build caches a compiler anchor may write (toolchainEnv); empty ⇒ cold caches in scratch.
	CacheRoot string
	// StateDir locates gates/consents.json, the Step-4 record EmitExcerpt reads for E1; empty reads as nothing consented (consents.Read).
	StateDir string
	// OnDropped receives the Dropped{reason} accounting for an excerpt refused at the door (wired to capture.AccountDropped); nil is legal.
	OnDropped func(reason string)

	mu     sync.Mutex
	l0root []byte // latest cortexd L0 root; nil ⇒ integrity incomplete
	// signer mints AnchorVote.signature (verify.proto field 5, founder ruling
	// 2026-09-16); nil ⇒ votes stay unsigned, the same fail-soft posture
	// receipt sealing already has with no enrolled device key.
	signer identity.DeviceKey
}

// aliasIntact: when argv[0] is a symlink alias of the consented binary (rustup's cargo), the alias must still resolve to it — a re-pointed alias would run a file the hash never covered.
func aliasIntact(e CatalogEntry) bool {
	if len(e.Argv) == 0 || e.Argv[0] == e.BinaryPath {
		return true
	}
	resolved, err := filepath.EvalSymlinks(e.Argv[0])
	return err == nil && resolved == e.BinaryPath
}

// NewRunner wires the sandbox and the capture emitter.
func NewRunner(sb Sandbox, emit Emitter, outputHMACKey []byte, testOptIn bool) *Runner {
	return &Runner{sb: sb, emit: emit, outputHMACKey: outputHMACKey, testOptIn: testOptIn}
}

// SetL0Root is the cortexd seam (04 §6.7): cortexd pushes its L0 merkle root
// on every index-clock bump. nil clears it (cortexd down). While absent,
// votes carry an EMPTY worktree_merkle_root — never a placeholder — which is
// the "incomplete integrity" state: emitted, fusion-visible, never certifies.
func (r *Runner) SetL0Root(root []byte) {
	r.mu.Lock()
	r.l0root = append([]byte(nil), root...)
	if root == nil {
		r.l0root = nil
	}
	r.mu.Unlock()
}

// RunOne executes one Enabled catalog entry (from Reconcile — the ONLY legal
// source) for (session, task) in worktree, and emits exactly one AnchorVote —
// or refuses with ErrRefused and emits nothing. Infra failure emits
// VERDICT_ERROR, never VIOLATED (F-31).
func (r *Runner) RunOne(ctx context.Context, e CatalogEntry, session, task [16]byte, worktree string) error {
	handler, ok := defaultHandlers[e.Kind]
	if !ok {
		// Unreachable for table-derived entries (init asserts the sets match);
		// kept because a hand-built entry must be REFUSED, never faked.
		return fmt.Errorf("%w: no handler for kind %q", ErrRefused, e.Kind)
	}
	// EvidenceRecord.tool and the resolved_binary_hashes key are the SAME
	// finite-vocabulary contract as diagnostic_code (artifacts.proto: "the
	// finite vocabulary is a property of the catalog"), so both are sourced
	// from the derivation table by kind rather than from e.Tool — the handler
	// path already does exactly this (lineHandler's fixed tool string), and a
	// hand-built entry must not be able to name its own tool. Non-empty by the
	// init() exhaustiveness assert, since the handler lookup above succeeded.
	tool := detectors[e.Kind].tool
	if e.ConsentedAt.IsZero() || len(e.BinaryHash) == 0 {
		return fmt.Errorf("%w: entry %s is not consented (04 §2.2: nothing runs without consent)", ErrRefused, e.ID)
	}
	if e.SideEffect == SideEffectTest && !r.testOptIn && !TestsOptedIn(worktree) {
		return fmt.Errorf("%w: test-class anchor %s without per-repo opt-in %s (FR-VERIFY-003)", ErrRefused, e.ID, RepoOptInPath(worktree))
	}

	// Env allow-list (04 §2.2): PATH = the resolved catalog dir only, LANG/TZ
	// passed through when the daemon has them; HOME is sandbox-owned scratch.
	env := map[string]string{"PATH": filepath.Dir(e.BinaryPath)}
	for _, k := range []string{"LANG", "TZ"} {
		if v := os.Getenv(k); v != "" {
			env[k] = v
		}
	}
	cacheDir := ""
	if r.CacheRoot != "" {
		cacheDir = filepath.Join(r.CacheRoot, tool)
		if err := os.MkdirAll(cacheDir, 0o700); err != nil {
			cacheDir = ""
		}
	}
	maps.Copy(env, toolchainEnv(detectors[e.Kind].binary, cacheDir))
	spec := RunSpec{
		Argv:       e.Argv,
		WorktreeRO: worktree,
		Env:        env,
		CacheDir:   cacheDir,
		Limits:     DefaultLimits(e.Class),
		// FR-VERIFY-003 precondition, extended to repo-code executors: a tool
		// that EVALUATES repo-supplied code (eslint config JS, build.rs, cgo)
		// must never run with chdir+env-scrub only — without kernel write
		// confinement a hostile repo gets arbitrary same-uid writes. The
		// detector table is OR'd in for the same reason `tool` is sourced from
		// it above: a hand-built entry must not be able to unflag its own kind.
		RequireFSConfined: e.SideEffect == SideEffectTest || e.ExecsRepoCode ||
			detectors[e.Kind].execsRepoCode,
	}

	// Consent gate AT the execution point (doc.go "NOTHING RUNS WITHOUT
	// CONSENT"; 04 §2.2 F-32): the binary is hashed at the resolved path
	// BEFORE exec and compared to the consent-time hash. A mismatch means the
	// entry has drifted — consent binds to the hash, not the path — so the
	// swapped binary must never execute; the F-32 tamper vote is still emitted
	// ("vote flagged ... doctor surfaces"), it just attests a refusal to run.
	// ponytail: hash-then-exec leaves a sub-ms TOCTOU window; closing it needs
	// fexecve on the hashed fd threaded through the helper re-exec.
	var verdict m1pv1.Verdict
	var evidence *m1pv1.EvidenceRecord
	var integrity *m1pv1.AnchorIntegrity
	var stdout, stderr []byte
	var d diffFacts
	if preHash, preErr := hashFile(e.BinaryPath); preErr != nil || !bytes.Equal(preHash, e.BinaryHash) || !aliasIntact(e) {
		integrity = &m1pv1.AnchorIntegrity{
			WorktreeMerkleRoot:   r.currentL0Root(), // empty ⇒ incomplete, never certifies
			ResolvedBinaryHashes: map[string][]byte{tool: preHash},
			EnvScrubAttestation:  envAttestation(RunResult{}, env), // attests the INTENDED env; nothing ran
			Tamper:               true,
		}
		verdict = m1pv1.Verdict_VERDICT_ERROR
		evidence = &m1pv1.EvidenceRecord{
			Tool:           tool,
			DiagnosticCode: "binary_tamper", // finite vocabulary, see failureCode
			Category:       categoryOf(e.Kind),
		}
	} else {
		d = r.diff(ctx, worktree) // read before the run: the touched set is the baseline boundary the handler judges against, and the anchor is side-effect-free so the tree it sees is this one
		res, runErr := r.sb.Run(ctx, spec)
		res.Touched, res.Worktree = d.touchedSet(), worktree

		// Anti-tamper envelope (04 §2.2 table): effective-execution hashing —
		// the binary is re-hashed AFTER the run too, so a swap that lands
		// mid-run (past the pre-exec gate above) still flips tamper.
		// ponytail: that is two reads of a tens-of-MB toolchain binary per run
		// (page-cache warm, ~ms); collapse to the pre-exec hash alone if anchor
		// scheduling ever shows up in a latency profile.
		runHash, hashErr := hashFile(e.BinaryPath)
		integrity = &m1pv1.AnchorIntegrity{
			WorktreeMerkleRoot:   r.currentL0Root(), // empty ⇒ incomplete, never certifies
			ResolvedBinaryHashes: map[string][]byte{tool: runHash},
			EnvScrubAttestation:  envAttestation(res, env),
			Tamper:               hashErr != nil || !bytes.Equal(runHash, e.BinaryHash),
		}
		stdout, stderr = res.Stdout, res.Stderr

		switch {
		case runErr != nil || res.TimedOut || res.Signal != "":
			// F-31: crash / timeout / sandbox failure ⇒ error, NEVER violated.
			verdict = m1pv1.Verdict_VERDICT_ERROR
			evidence = &m1pv1.EvidenceRecord{
				Tool:           tool,
				DiagnosticCode: failureCode(runErr, res),
				Category:       categoryOf(e.Kind),
			}
		default:
			verdict, evidence = handler(res)
			if len(r.outputHMACKey) > 0 {
				evidence.OutputHmac = outputHMAC(r.outputHMACKey, res)
			}
		}
	}
	integrity.DiffClassification, integrity.SuppressionDirectiveDelta = d.class, d.delta
	// Raw evidence stays on this device; a failed local write never fails the vote.
	_, _ = r.Evidence.Put(task, e.ID, stdout, stderr, d.raw)

	av := &m1pv1.AnchorVote{
		AnchorId:  e.ID,
		Vote:      verdict,
		Evidence:  evidence,
		Integrity: integrity,
	}
	r.signVote(av)
	if n, ok := r.emit.(treeNoter); ok {
		n.NoteTree(task, e.ID, d.fingerprint()) // the attempt boundary the vote tee counts on: the tree this vote judged
	}
	ev := &m1pv1.Event{
		SessionId:  session[:],
		TaskId:     task[:],
		OccurredAt: timestamppb.Now(), // mark1d IS the origin of this event
		Body:       &m1pv1.Event_AnchorVote{AnchorVote: av},
	}
	return r.emit.Admit(ctx, ev)
}

func (r *Runner) currentL0Root() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.l0root...)
}

// SetSigner arms per-vote signing with the device origin key -- the same key
// receipt.OpenKey opens for checkpoint sealing (reused, not re-derived). It is
// late-bound like SetL0Root: the daemon wires it once enrollment identity is
// known, which lands after the runner is constructed.
func (r *Runner) SetSigner(key identity.DeviceKey) {
	r.mu.Lock()
	r.signer = key
	r.mu.Unlock()
}

func (r *Runner) currentSigner() identity.DeviceKey {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.signer
}

// signVote mints AnchorVote.signature over the deterministic proto marshal of
// av with signature cleared -- av.Signature must be unset at call time, so the
// bytes signed and the bytes shipped agree on what "cleared" means. No domain
// prefix: verify.proto's contract is exactly canonical(anchor_id, vote,
// evidence, integrity), not the receipt-chain's JSON signing scheme. A
// marshal or sign failure degrades to unsigned rather than dropping the vote
// -- "empty on pre-ruling producers, never forged" licenses absent, never
// fabricated.
func (r *Runner) signVote(av *m1pv1.AnchorVote) {
	signer := r.currentSigner()
	if signer == nil {
		return
	}
	canon, err := proto.MarshalOptions{Deterministic: true}.Marshal(av)
	if err != nil {
		return
	}
	sig, err := signer.Sign(canon)
	if err != nil {
		return
	}
	av.Signature = sig
}

// EmitExcerpt is the only door for opt-in tiers (FR-VERIFY-016, 07 §4): E1 needs redaction_receipt_id, E2 needs MARK1_PROFILE=vpc|selfhost (04 §3 gateway mode).
func (r *Runner) EmitExcerpt(ctx context.Context, session, task [16]byte, x *m1pv1.EvidenceExcerpt) error {
	switch x.GetTier() {
	case m1pv1.EvidenceTier_EVIDENCE_TIER_E1:
		if len(x.GetRedactionReceiptId()) == 0 {
			return fmt.Errorf("%w: E1 excerpt without redaction_receipt_id (FR-VERIFY-016)", ErrRefused)
		}
		// Read per call, like the off marker: a consent withdrawn in Settings takes effect on the next excerpt, and the refusal is accounted, never silent.
		if !consents.Read(r.StateDir).E1 {
			if r.OnDropped != nil {
				r.OnDropped("e1_consent_absent")
			}
			return fmt.Errorf("%w: E1 excerpt without the Step-4 e1 consent in %s (FR-VERIFY-016)", ErrRefused, consents.Path(r.StateDir))
		}
	case m1pv1.EvidenceTier_EVIDENCE_TIER_E2:
		if p := os.Getenv("MARK1_PROFILE"); p != "vpc" && p != "selfhost" {
			return fmt.Errorf("%w: E2 excerpt outside a vpc|selfhost profile, MARK1_PROFILE=%q (FR-VERIFY-016)", ErrRefused, p)
		}
	default:
		return fmt.Errorf("%w: tier %v carries no excerpt", ErrRefused, x.GetTier())
	}
	return r.emit.Admit(ctx, &m1pv1.Event{
		SessionId:  session[:],
		TaskId:     task[:],
		OccurredAt: timestamppb.Now(),
		Body:       &m1pv1.Event_EvidenceExcerpt{EvidenceExcerpt: x},
	})
}

// failureCode names the infra-failure category with a finite vocabulary —
// EvidenceRecord.diagnostic_code carries codes, never free text. The pre-exec
// consent gate adds "binary_tamper" to this vocabulary (set inline in RunOne).
func failureCode(runErr error, res RunResult) string {
	switch {
	case errors.Is(runErr, ErrSandboxUnavailable):
		return "sandbox_unavailable"
	case errors.Is(runErr, ErrOutputCap):
		return "output_cap"
	case res.TimedOut:
		return "timeout"
	case res.Signal != "":
		return "killed"
	default:
		return "sandbox_error"
	}
}

func categoryOf(k Kind) m1pv1.EvidenceCategory {
	switch k {
	case KindTsc:
		return m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_TYPE
	case KindCargoCheck:
		return m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_BUILD
	case KindGoTest, KindCargoTest, KindPytest, KindNpmTest:
		return m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_TEST
	default:
		return m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_LINT
	}
}

// envAttestation hashes the EXACT env the child ran under (verify.proto field
// 3). When the run never started, the intended allow-list is attested instead
// so the ERROR vote still states what WOULD have been passed.
func envAttestation(res RunResult, intended map[string]string) []byte {
	kv := res.EffectiveEnv
	if len(kv) == 0 {
		for k, v := range intended {
			kv = append(kv, k+"="+v)
		}
		sort.Strings(kv)
	}
	h := blake3.New(32, nil)
	for _, e := range kv {
		_, _ = h.Write([]byte(e))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum(nil)
}

// outputHMAC is HMAC_tenant over the structurally-normalized tool output:
// trimmed non-empty lines of stdout+stderr, sorted, joined by \n — stable
// across diagnostic ordering. ponytail: v0 normalization; per-tool structural
// canonicalization when cross-run join quality demands it.
func outputHMAC(key []byte, res RunResult) []byte {
	lines := strings.Split(string(res.Stdout)+"\n"+string(res.Stderr), "\n")
	norm := lines[:0]
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" {
			norm = append(norm, t)
		}
	}
	sort.Strings(norm)
	mac := hmac.New(sha256.New, key)
	for _, l := range norm {
		mac.Write([]byte(l))
		mac.Write([]byte{0})
	}
	return mac.Sum(nil)
}
