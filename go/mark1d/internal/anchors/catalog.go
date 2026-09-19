package anchors

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"lukechampine.com/blake3"
)

// Kind is the anchor kind — the key of both the detector table and the
// handler registry, kept in lockstep by the init assert below.
type Kind string

const (
	KindRuff       Kind = "ruff"
	KindTsc        Kind = "tsc"
	KindCargoCheck Kind = "cargo-check"
	KindGoVet      Kind = "go-vet"
	KindEslint     Kind = "eslint"
	KindGoTest     Kind = "go-test"
	KindCargoTest  Kind = "cargo-test"
	KindPytest     Kind = "pytest"
	KindNpmTest    Kind = "npm-test"
)

// Class is the scheduling cost class (04 §2.2): Fast runs on the PostToolUse
// debounce; Slow only at idle or Stop. Test anchors are always Slow.
type Class string

const (
	ClassFast Class = "fast"
	ClassSlow Class = "slow"
)

// SideEffect is the FR-VERIFY-003 axis: static-analysis entries are the only
// defaults; test-class entries are per-repo opt-in AND refuse to run without
// the full sandbox (the precondition the runner enforces). NOTE "static"
// describes the derived argv, NOT safety: several static tools execute
// repo-controlled code as part of analysis (see detector.execsRepoCode),
// which carries the same write-confinement precondition as test-class.
type SideEffect string

const (
	SideEffectStatic SideEffect = "static"
	SideEffectTest   SideEffect = "test"
)

// CatalogEntry is LOCALLY DERIVED — never server-named (04 §2.2). Bundles
// enable entries by ID only; there is no constructor here that takes an argv
// from outside the detector table.
type CatalogEntry struct {
	ID         string     // "ruff@cat-1" — stable per (tool, derivation rule)
	Kind       Kind       // detector/handler key
	Tool       string     // public tool name, EvidenceRecord.tool vocabulary
	Argv       []string   // derived locally, shown verbatim in `mark1 doctor`
	Class      Class      // fast | slow
	SideEffect SideEffect // static | test
	// ExecsRepoCode marks tools whose analysis EVALUATES repo-supplied code
	// (eslint runs eslint.config.js in node; cargo check runs build.rs and
	// proc macros; go vet compiles cgo with repo-supplied flags). Such an
	// anchor requires kernel-enforced write confinement exactly like a
	// test-class one — without Landlock a hostile repo would get arbitrary
	// same-uid writes (doc.go "NOT ENFORCED without Landlock").
	ExecsRepoCode bool
	BinaryPath    string    // resolved at derivation time
	BinaryHash    []byte    // BLAKE3 at consent time — the PATH-shim reference
	ToolVersion   string    // version sniff at derivation time
	ConsentedAt   time.Time // zero until consented
}

// detector is one row of the const derivation table. probe answers "does this
// worktree configure the tool"; argv is the ONLY source of command lines in
// the package (CON-009: bundles can never name commands, so nothing else may
// either).
type detector struct {
	rule          int    // derivation rule number → the "@cat-N" ID suffix
	tool          string // EvidenceRecord.tool name
	binary        string // PATH lookup name
	wants         string // the config the probe looks for, for the miss line a person reads
	class         Class  //
	sideEffect    SideEffect
	execsRepoCode bool     // see CatalogEntry.ExecsRepoCode
	versionArgs   []string // argv tail for the version sniff
	probe         func(worktree string) bool
	argv          func(binaryPath string) []string
}

// detectors is the PROBE_HANDLERS-shaped const table (06 §2.1 adopts the
// estate pattern verbatim): every derivable kind appears here, every runnable
// kind appears in defaultHandlers, and init asserts the two sets are equal —
// an unimplemented kind is REFUSED, never faked.
var detectors = map[Kind]detector{
	KindRuff: {
		rule: 1, tool: "ruff", binary: "ruff", wants: "ruff.toml, .ruff.toml or [tool.ruff] in pyproject.toml",
		class: ClassFast, sideEffect: SideEffectStatic,
		versionArgs: []string{"--version"},
		probe: func(wt string) bool {
			if fileExists(filepath.Join(wt, "ruff.toml")) || fileExists(filepath.Join(wt, ".ruff.toml")) {
				return true
			}
			// pyproject only counts when it actually configures ruff — a bare
			// pyproject would derive a linter the repo never asked for.
			b, err := os.ReadFile(filepath.Join(wt, "pyproject.toml"))
			return err == nil && bytes.Contains(b, []byte("[tool.ruff"))
		},
		argv: func(bin string) []string {
			return []string{bin, "check", "--output-format", "concise", "."}
		},
	},
	KindTsc: {
		rule: 1, tool: "tsc", binary: "tsc", wants: "tsconfig.json",
		class: ClassFast, sideEffect: SideEffectStatic,
		versionArgs: []string{"--version"},
		probe:       func(wt string) bool { return fileExists(filepath.Join(wt, "tsconfig.json")) },
		argv: func(bin string) []string {
			// --noEmit keeps the type check side-effect-free even if the
			// tsconfig says otherwise; --pretty false keeps output parseable.
			return []string{bin, "--noEmit", "--pretty", "false"}
		},
	},
	KindCargoCheck: {
		rule: 1, tool: "cargo-check", binary: "cargo", wants: "Cargo.toml",
		class: ClassSlow, sideEffect: SideEffectStatic, // compiles: slow even warm-ish
		// `cargo check` executes build.rs and proc macros — repo code.
		execsRepoCode: true,
		versionArgs:   []string{"--version"},
		probe:         func(wt string) bool { return fileExists(filepath.Join(wt, "Cargo.toml")) },
		argv: func(bin string) []string {
			return []string{bin, "check", "--quiet", "--message-format=short"}
		},
	},
	KindGoVet: {
		rule: 1, tool: "go-vet", binary: "go", wants: "go.mod",
		class: ClassSlow, sideEffect: SideEffectStatic, // vet compiles the package graph
		// vet's compile step honors repo-supplied cgo directives (#cgo
		// CFLAGS/LDFLAGS reach the host compiler/linker) — repo-steered exec.
		execsRepoCode: true,
		versionArgs:   []string{"version"}, // `go version`, no dashes
		probe:         func(wt string) bool { return fileExists(filepath.Join(wt, "go.mod")) },
		argv: func(bin string) []string {
			return []string{bin, "vet", "./..."}
		},
	},
	KindEslint: {
		rule: 1, tool: "eslint", binary: "eslint", wants: "eslint.config.* or .eslintrc* file",
		class: ClassFast, sideEffect: SideEffectStatic,
		// eslint's config (eslint.config.js / .eslintrc.js) is JS EVALUATED by
		// node, and plugins are arbitrary repo deps — repo code.
		execsRepoCode: true,
		versionArgs:   []string{"--version"},
		probe: func(wt string) bool {
			for _, f := range []string{
				"eslint.config.js", "eslint.config.mjs", "eslint.config.cjs",
				".eslintrc", ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.json",
				".eslintrc.yml", ".eslintrc.yaml",
			} {
				if fileExists(filepath.Join(wt, f)) {
					return true
				}
			}
			return false
		},
		argv: func(bin string) []string {
			return []string{bin, "--format", "json", "."}
		},
	},
	// Test runners (06 §2.5): SideEffectTest, always Slow, derived only under the per-repo opt-in.
	KindGoTest: {
		rule: 1, tool: "go-test", binary: "go", wants: "go.mod",
		class: ClassSlow, sideEffect: SideEffectTest, execsRepoCode: true,
		versionArgs: []string{"version"},
		probe:       func(wt string) bool { return fileExists(filepath.Join(wt, "go.mod")) },
		argv:        func(bin string) []string { return []string{bin, "test", "./..."} },
	},
	KindCargoTest: {
		rule: 1, tool: "cargo-test", binary: "cargo", wants: "Cargo.toml",
		class: ClassSlow, sideEffect: SideEffectTest, execsRepoCode: true,
		versionArgs: []string{"--version"},
		probe:       func(wt string) bool { return fileExists(filepath.Join(wt, "Cargo.toml")) },
		argv:        func(bin string) []string { return []string{bin, "test", "--quiet", "--no-fail-fast"} },
	},
	KindPytest: {
		rule: 1, tool: "pytest", binary: "pytest", wants: "pytest.ini, conftest.py or [tool.pytest] in pyproject.toml",
		class: ClassSlow, sideEffect: SideEffectTest, execsRepoCode: true,
		versionArgs: []string{"--version"},
		probe: func(wt string) bool {
			if fileExists(filepath.Join(wt, "pytest.ini")) || fileExists(filepath.Join(wt, "conftest.py")) {
				return true
			}
			b, err := os.ReadFile(filepath.Join(wt, "pyproject.toml"))
			return err == nil && bytes.Contains(b, []byte("[tool.pytest"))
		},
		argv: func(bin string) []string { return []string{bin, "-q", "-p", "no:cacheprovider"} },
	},
	KindNpmTest: {
		rule: 1, tool: "npm-test", binary: "npm", wants: `"test" script in package.json`,
		class: ClassSlow, sideEffect: SideEffectTest, execsRepoCode: true,
		versionArgs: []string{"--version"},
		probe: func(wt string) bool {
			var m struct {
				Scripts map[string]string `json:"scripts"`
			}
			b, err := os.ReadFile(filepath.Join(wt, "package.json"))
			return err == nil && json.Unmarshal(b, &m) == nil && m.Scripts["test"] != ""
		},
		argv: func(bin string) []string { return []string{bin, "test", "--silent"} },
	},
}

// RepoOptInPath is the FR-VERIFY-003 / 04 §2.2 per-repo opt-in: <workspace>/.mark1/anchors.json {"tests": true}.
func RepoOptInPath(worktree string) string { return filepath.Join(worktree, ".mark1", "anchors.json") }

// TestsOptedIn reads the opt-in per call, like fabric's gate opt-in.
func TestsOptedIn(worktree string) bool {
	raw, err := os.ReadFile(RepoOptInPath(worktree))
	if err != nil {
		return false
	}
	var a struct {
		Tests bool `json:"tests"`
	}
	return json.Unmarshal(raw, &a) == nil && a.Tests
}

// init is the PROBE_HANDLERS exhaustiveness assert: handled kinds ==
// registered kinds, both directions, at process start — a kind added to one
// table without the other is a build defect, not a runtime surprise.
func init() {
	for k := range detectors {
		if _, ok := defaultHandlers[k]; !ok {
			panic(fmt.Sprintf("anchors: kind %q derivable but has no handler — unimplemented kinds are refused, never faked (06 §2.1)", k))
		}
	}
	for k := range defaultHandlers {
		if _, ok := detectors[k]; !ok {
			panic(fmt.Sprintf("anchors: kind %q has a handler but no detector — dead handler or missing derivation rule", k))
		}
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// versionSniffTimeout bounds the derivation-time `tool --version` exec —
// derivation runs at `mark1 enable`, interactively; a hung tool must not
// hang the CLI.
const versionSniffTimeout = 5 * time.Second

// sniffVersionOutputCap bounds what a version sniff may print. A version line
// is tens of bytes; the cap exists so a hostile binary cannot make the CLI
// buffer its output without limit.
const sniffVersionOutputCap = 64 << 10

// Derive probes the worktree and PATH and returns every available anchor,
// sorted by ID. This is the ONLY producer of CatalogEntry argvs. A tool whose
// config is present but whose binary is not on PATH is simply absent — a
// catalog states what CAN run, not what should be installed.
//
// The version sniff execs the resolved binary with its version flag — and it
// runs INSIDE sb, exactly like an anchor run. Derivation happens before the
// consent prompt, and exec.LookPath resolves against the caller's PATH, which
// in npm/direnv shells routinely contains the repo's own node_modules/.bin: an
// unsandboxed sniff would hand a freshly cloned hostile repo an unconfined
// exec on the user's machine before they were asked anything (doc.go property
// 2). A sniff failure leaves ToolVersion empty rather than running unsandboxed;
// a sniff the SANDBOX refused drops the entry when the run would be refused
// the same way (no floor, or no write confinement for an entry that needs it):
// publishing it would only mint VERDICT_ERROR/sandbox_unavailable votes, and
// candidates.json's sandbox field says why instead (candidates.go).
//
// sb must be the same Sandbox the runner uses; nil skips every sniff. NOTE any
// process calling this with a LinuxSandbox must call MaybeRunHelper() first
// (mark1d does, cmd/main.go) — the sandbox re-execs the caller as its helper.
func Derive(sb Sandbox, worktree string) ([]CatalogEntry, error) {
	d, err := Explain(sb, worktree)
	return d.Entries, err
}

// Miss is one anchor kind Explain looked for and did not derive, with the reason a person can act on (v3 item 3: a workspace with zero anchors says what was looked for).
type Miss struct {
	Tool string `json:"tool"`
	Why  string `json:"why"`
}

// Derivation is Explain's answer: the entries Derive returns plus a Miss per kind that did not make it, both sorted by tool.
type Derivation struct {
	Entries []CatalogEntry
	Looked  []Miss
}

// Explain is Derive with the misses kept.
func Explain(sb Sandbox, worktree string) (Derivation, error) {
	abs, err := filepath.Abs(worktree)
	if err != nil {
		return Derivation{}, err
	}
	var out []CatalogEntry
	var looked []Miss
	miss := func(d detector, why string) { looked = append(looked, Miss{Tool: d.tool, Why: why}) }
	tests := TestsOptedIn(abs)
	for kind, d := range detectors {
		if !d.probe(abs) {
			miss(d, "no "+d.wants)
			continue
		}
		if d.sideEffect == SideEffectTest && !tests {
			miss(d, "tests are off for this project")
			continue
		}
		bin, err := exec.LookPath(d.binary)
		if err != nil {
			miss(d, d.binary+" is not on PATH") // config present, tool absent: not derivable
			continue
		}
		if bin, err = filepath.Abs(bin); err != nil {
			miss(d, err.Error())
			continue
		}
		// Consent binds to the file that executes, not a symlink alias of it — but argv[0] keeps the alias when the two names differ: rustup's `cargo` is a symlink to rustup, which dispatches on argv[0] and ran `rustup check --quiet` on the founder's machine (the runner re-resolves the alias to BinaryPath before every run).
		alias := bin
		if resolved, rerr := filepath.EvalSymlinks(bin); rerr == nil {
			bin = resolved
		}
		if trimExe(filepath.Base(bin)) == d.binary {
			alias = bin
		}
		// What executes is argv[0]; a script tool's argv is interpreter + script (npm's Windows .cmd shims, which no sandbox can run as-is).
		prefix := []string{alias}
		if ext := strings.ToLower(filepath.Ext(bin)); ext == ".cmd" || ext == ".bat" {
			node, script, ok := npmShimTarget(bin)
			if !ok {
				miss(d, filepath.Base(bin)+" is a batch file, which cannot run inside the sandbox")
				continue
			}
			bin, prefix = node, []string{node, script}
		}
		hash, err := hashFile(bin)
		if err != nil {
			miss(d, bin+" is unreadable") // unreadable binary cannot be consent-hashed, so cannot exist
			continue
		}
		version, err := sniffVersion(sb, abs, prefix, d.versionArgs)
		if errors.Is(err, ErrSandboxUnavailable) && (!sb.Status().Available || d.execsRepoCode || d.sideEffect == SideEffectTest) {
			miss(d, "the sandbox cannot run it here: "+sb.Status().Reason) // the run would be refused exactly like the sniff was
			continue
		}
		if err != nil && !errors.Is(err, ErrSandboxUnavailable) {
			miss(d, d.tool+" did not answer its version check: "+err.Error()) // a run would fail the same way, and consent needs the version
			continue
		}
		out = append(out, CatalogEntry{
			ID:            fmt.Sprintf("%s@cat-%d", d.tool, d.rule),
			Kind:          kind,
			Tool:          d.tool,
			Argv:          append(prefix, d.argv(bin)[1:]...),
			Class:         d.class,
			SideEffect:    d.sideEffect,
			ExecsRepoCode: d.execsRepoCode,
			BinaryPath:    bin,
			BinaryHash:    hash,
			ToolVersion:   version,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	sort.Slice(looked, func(i, j int) bool { return looked[i].Tool < looked[j].Tool })
	return Derivation{Entries: out, Looked: looked}, nil
}

// sniffVersion runs `bin <versionArgs>` under the sandbox. RequireFSConfined
// is set because the binary is UNCONSENTED at this point: a kernel that cannot
// confine its writes gets no sniff at all (empty version) rather than a
// pre-consent exec with only chdir + env scrub — the same "weaker isolation
// gets a smaller privilege, not a waiver" rule as 04 §11.5. The sandbox's
// refusal is returned so Derive can tell it from a tool that merely failed.
func trimExe(name string) string { return strings.TrimSuffix(strings.ToLower(name), ".exe") }

func sniffVersion(sb Sandbox, worktree string, prefix, args []string) (string, error) {
	if sb == nil {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), versionSniffTimeout)
	defer cancel()
	limits := DefaultLimits(ClassFast)
	limits.CPUSeconds = uint64(versionSniffTimeout / time.Second)
	limits.Wall = versionSniffTimeout
	limits.OutputCap = sniffVersionOutputCap
	res, err := sb.Run(ctx, RunSpec{
		Argv:              append(append([]string{}, prefix...), args...),
		WorktreeRO:        worktree,
		Env:               map[string]string{"PATH": filepath.Dir(prefix[0]), "LANG": "C"},
		Limits:            limits,
		RequireFSConfined: true,
	})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		detail := strings.TrimSpace(string(res.Stderr))
		if detail == "" {
			detail = strings.TrimSpace(string(res.Stdout))
		}
		if len(detail) > 200 {
			detail = detail[:200]
		}
		if res.Signal != "" {
			detail = res.Signal
		}
		return "", fmt.Errorf("exit %d: %s", res.ExitCode, detail)
	}
	line, _, _ := strings.Cut(string(res.Stdout), "\n")
	return strings.TrimSpace(line), nil
}

// npmShimRe matches the script line of both cmd-shim generations: `"%_prog%"  "%dp0%\node_modules\typescript\bin\tsc" %*` and the older `"%~dp0\node.exe"  "%~dp0\node_modules\...\tsc" %*`.
var npmShimRe = regexp.MustCompile(`"%~?dp0%?\\([^"]+)"\s+%\*`)

// npmShimTarget reads an npm .cmd shim and returns the node.exe that would run it and the script it runs, absolute. Any other batch file is not ok: an AppContainer cannot run one, so the catalog refuses it by name instead of deriving an anchor that can only ever fail.
func npmShimTarget(shim string) (node, script string, ok bool) {
	b, err := os.ReadFile(shim)
	if err != nil || len(b) > sniffVersionOutputCap {
		return "", "", false
	}
	m := npmShimRe.FindSubmatch(b)
	if m == nil {
		return "", "", false
	}
	dir := filepath.Dir(shim)
	script = filepath.Join(dir, filepath.FromSlash(strings.ReplaceAll(string(m[1]), "\\", "/")))
	if !fileExists(script) {
		return "", "", false
	}
	node = filepath.Join(dir, "node.exe")
	if !fileExists(node) {
		if node, err = exec.LookPath("node"); err != nil {
			return "", "", false
		}
	}
	if node, err = filepath.Abs(node); err != nil {
		return "", "", false
	}
	if resolved, rerr := filepath.EvalSymlinks(node); rerr == nil {
		node = resolved
	}
	return node, script, true
}

func hashFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// ponytail: whole-file read; streaming blake3 if multi-GB binaries ever
	// show up on PATH (they don't — toolchain binaries are tens of MB).
	sum := blake3.Sum256(b)
	return sum[:], nil
}

// envAllowKeys is the fixed env allow-list (04 §2.2): PATH to the resolved
// catalog dirs, HOME to a per-run scratch dir, LANG/TZ. It participates in
// the effective-execution hash by NAME (values of HOME vary per run and are
// attested per run instead, in AnchorIntegrity.env_scrub_attestation).
var envAllowKeys = []string{"PATH", "HOME", "LANG", "TZ"}

// ExecHash is the consent-time effective-execution hash:
// blake3(binary BLAKE3 ‖ canonical argv ‖ env allow-list keys), each part
// length-prefixed so no two field sequences collide. It is the 06 §2.4 hash
// minus config_file_hashes and the suppression set, which need per-run diff
// inputs this phase does not collect. Any drift in argv, binary content, or
// the allow-list changes this hash and therefore invalidates consent.
func ExecHash(e CatalogEntry) []byte {
	h := blake3.New(32, nil)
	part := func(b []byte) {
		var n [8]byte
		binary.LittleEndian.PutUint64(n[:], uint64(len(b)))
		_, _ = h.Write(n[:])
		_, _ = h.Write(b)
	}
	part(e.BinaryHash)
	part([]byte(e.ToolVersion))
	for _, a := range e.Argv {
		part([]byte(a))
	}
	for _, k := range envAllowKeys {
		part([]byte(k))
	}
	return h.Sum(nil)
}
