package enroll

// FR-ENROLL-001's negative half: "No credential prompt exists in any
// enrollment path" (02 §12). That is a universal negative, and the naive
// version — run the happy path, assert it did not prompt — proves one path and
// silently exempts every path added afterwards. This scan is structural
// instead: it resolves the ACTUAL dependency closure of both enrollment
// packages with `go list -deps` and classifies every first-party source file in
// it, so a helper added under either package tomorrow is covered by this code
// rather than by someone remembering to extend a list.
//
// What it asserts, at the terminal rather than at intent, is that no code
// reachable from an enrollment path can acquire a secret from the environment
// a human controls:
//
//	1. no dependency, direct or transitive, is a terminal password-prompt
//	   library (the absence proof, at module resolution);
//	2. nothing reads standard input — os.Stdin, syscall.Stdin, or the fmt.Scan
//	   family, which reads it without ever naming it;
//	3. nothing disables terminal echo or calls a password reader, matched on
//	   the selector alone so an import alias cannot hide it;
//	4. nothing opens the controlling terminal directly (/dev/tty), which is the
//	   obvious way around rule 2;
//	5. no credential-shaped environment variable is read — and an environment
//	   variable whose NAME is computed is refused too, because this scan cannot
//	   clear what it cannot read.
//
// What it does NOT catch, stated so nobody reads more into a green: it says
// nothing about whether a credential that arrives some other way is later
// stored or forwarded (the operator's own IdP bearer token legitimately
// arrives on the wire in controld's handlers, and is deliberately permitted
// below), and it does not model reflection, cgo, or a subprocess that prompts
// on our behalf. It is an acquisition scan, not a taint analysis.
//
// It lives on the CLI side because that is where a human sits at a terminal
// and where a prompt would be written, but it scans BOTH modules' closures —
// one classifier, one place to widen it. `cd go/controld && go test
// ./internal/enroll/` therefore does not run it; CI running both suites does.
//
// Modelled on go/mark1d/internal/obs/no_otel_test.go, including its lesson:
// a scan that reads nothing reports exactly what a clean tree reports, so the
// counts and anchors below are assertions, not decoration.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

const firstPartyPrefix = "github.com/Omium-ai/omium-mark1/"

// enrollClosures: both halves of "any enrollment path" — the CLI that faces
// the human and the server that runs the device-code state machine.
var enrollClosures = []struct{ module, pattern string }{
	{"go/mark1", "./internal/enroll/"},
	{"go/controld", "./internal/enroll/"},
}

// scanAnchors are files the scan must have parsed. The counts below prove it
// read something; these prove it read the enrollment code specifically. A
// rename that drops one fails loudly and asks a human to re-anchor, which is
// the intended cost.
//
// cli.go is anchored deliberately: it is not in an enrollment directory, it is
// a DEPENDENCY of one, and it holds the Env that owns stdout, the state dir and
// the HTTP client — the likeliest place a prompt would be written and the
// likeliest place a directory-scoped scan would miss it. Its presence here is
// what distinguishes walking the resolved closure from walking two folders.
var scanAnchors = []string{
	"go/mark1/internal/enroll/enroll.go",
	"go/mark1/internal/cli/cli.go",
	"go/controld/internal/enroll/enroll.go",
	"go/controld/internal/enroll/handlers.go",
	"go/controld/internal/enroll/idp.go",
}

// entryDoors names the exported symbols an enrollment path is entered
// through. They are asserted present so the inventory logged below is a real
// walk of a non-empty entry-point set and not an empty map reporting success.
var entryDoors = map[string][]string{
	"go/mark1/internal/enroll":    {"Run"},
	"go/controld/internal/enroll": {"New", "RegisterRoutes"},
}

// promptPackages are libraries whose purpose is acquiring a secret from a
// human at a terminal. Matched on the import path, so neither an alias nor a
// subpackage dodges the ban.
var promptPackages = []string{
	"golang.org/x/term",
	"golang.org/x/crypto/ssh/terminal",
	"github.com/howeyc/gopass",
	"github.com/bgentry/speakeasy",
	"github.com/manifoldco/promptui",
	"github.com/AlecAivazis/survey",
	"github.com/charmbracelet/huh",
	"github.com/erikgeiser/promptkit",
}

func isPromptPackage(p string) bool {
	for _, b := range promptPackages {
		if p == b || strings.HasPrefix(p, b+"/") {
			return true
		}
	}
	return false
}

// stdinReads: package-qualified forms that reach the process's input side.
// The fmt.Scan family is here because `fmt.Scanln(&apiKey)` reads os.Stdin
// without naming it, and an os.Stdin-only matcher misses it entirely. Sscan
// and Fscan are deliberately absent — one parses a string already in hand and
// the other takes an explicit reader, so neither touches a terminal.
var stdinReads = map[string]string{
	"os.Stdin":      "reads standard input",
	"syscall.Stdin": "reads standard input by descriptor",
	"fmt.Scan":      "reads standard input (fmt.Scan family)",
	"fmt.Scanf":     "reads standard input (fmt.Scan family)",
	"fmt.Scanln":    "reads standard input (fmt.Scan family)",
}

// echoControl: selector names no enrollment path calls under any package
// qualifier. Matched bare, so aliasing the import does not help.
var echoControl = map[string]string{
	"ReadPassword":    "reads a secret from the terminal with echo disabled",
	"MakeRaw":         "puts the terminal in raw mode — the echo-off half of a hand-rolled prompt",
	"IoctlGetTermios": "manipulates terminal echo directly",
	"IoctlSetTermios": "manipulates terminal echo directly",
	"GetPasswd":       "reads a password",
	"AskPass":         "asks for a password",
}

// ttyPaths: opening the controlling terminal is the way around the stdin rule.
var ttyPaths = []string{"/dev/tty", "/dev/stdin", "CONIN$"}

// credentialEnvRe matches environment variable names shaped like a credential.
// It deliberately does not match XDG_RUNTIME_DIR or the *_DSN store gates —
// a matcher that flagged every getenv would be a matcher that flagged nothing,
// because it would be deleted.
var credentialEnvRe = regexp.MustCompile(`(?i)pass|secret|token|credential|api[-_]?key|(^|_)keys?($|_)|bearer|auth`)

// credentialAcquisitions is the classifier, kept separate from the walk so the
// positive control can drive it on planted source without touching the tree.
func credentialAcquisitions(fset *token.FileSet, f *ast.File) []string {
	var out []string
	at := func(n ast.Node, format string, args ...any) {
		out = append(out, fset.Position(n.Pos()).String()+": "+fmt.Sprintf(format, args...))
	}
	for _, imp := range f.Imports {
		if p := strings.Trim(imp.Path.Value, `"`); isPromptPackage(p) {
			at(imp, "imports %s, a terminal password-prompt library", p)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if why, ok := echoControl[x.Sel.Name]; ok {
				at(x, "calls %s — %s", x.Sel.Name, why)
			}
			id, ok := x.X.(*ast.Ident)
			if !ok {
				return true
			}
			if why, ok := stdinReads[id.Name+"."+x.Sel.Name]; ok {
				at(x, "%s — %s", id.Name+"."+x.Sel.Name, why)
			}
		case *ast.BasicLit:
			if x.Kind != token.STRING {
				return true
			}
			for _, p := range ttyPaths {
				if strings.Contains(x.Value, p) {
					at(x, "names %s — opening the controlling terminal is a prompt by another route", p)
				}
			}
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != "os" || (sel.Sel.Name != "Getenv" && sel.Sel.Name != "LookupEnv") {
				return true
			}
			if len(x.Args) != 1 {
				return true
			}
			lit, ok := x.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				at(x, "os.%s with a computed name — this scan cannot clear an environment variable it cannot read", sel.Sel.Name)
				return true
			}
			if name := strings.Trim(lit.Value, `"`); credentialEnvRe.MatchString(name) {
				at(x, "os.%s(%q) — a credential-shaped environment variable", sel.Sel.Name, name)
			}
		}
		return true
	})
	return out
}

type depPkg struct {
	path, dir string
	standard  bool
}

// listDeps resolves the real closure. Nothing here is hardcoded on purpose:
// a package added to an enrollment path but missing from a hand-kept list is
// exactly where the prompt would land.
func listDeps(t *testing.T, dir, pattern string) []depPkg {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}\t{{.Dir}}\t{{.Standard}}", pattern)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps %s in %s: %v", pattern, dir, err)
	}
	var pkgs []depPkg
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			continue
		}
		pkgs = append(pkgs, depPkg{path: f[0], dir: f[1], standard: f[2] == "true"})
	}
	return pkgs
}

// goSources reads the directory rather than go list's GoFiles: a file excluded
// by a build constraint on this platform still ships to the platform it names,
// and a `//go:build windows` prompt is still a prompt.
func goSources(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		files = append(files, filepath.Join(dir, n))
	}
	return files
}

func enrollRepoRoot(t *testing.T) string {
	t.Helper()
	// internal/enroll → internal → mark1 → go → repo root.
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.work")); err != nil {
		t.Fatalf("repo root not at %s: %v", root, err)
	}
	return root
}

func TestNoEnrollmentPathReadsACredential(t *testing.T) {
	root := enrollRepoRoot(t)
	fset := token.NewFileSet()
	parsed := map[string]bool{}
	exported := map[string][]string{}
	files := 0

	for _, c := range enrollClosures {
		deps := listDeps(t, filepath.Join(root, c.module), c.pattern)
		if len(deps) == 0 {
			t.Fatalf("go list -deps %s in %s named no packages — this scan just covered nothing and passed", c.pattern, c.module)
		}

		// (1) The absence proof, at module resolution: over the WHOLE closure,
		// third-party included, since a prompt library is usually somebody
		// else's code.
		for _, d := range deps {
			if isPromptPackage(d.path) {
				t.Errorf("%s %s depends on %s — a terminal password-prompt library has no place in an enrollment path (FR-ENROLL-001)",
					c.module, c.pattern, d.path)
			}
		}

		// (2)-(5) The source scan, over the first-party closure: the stdlib is
		// where os.Stdin is DEFINED, so scanning it would report the definition
		// as the offence.
		pkgs := 0
		for _, d := range deps {
			if d.standard || !strings.HasPrefix(d.path, firstPartyPrefix) {
				continue
			}
			pkgs++
			srcs := goSources(t, d.dir)
			if len(srcs) == 0 {
				t.Fatalf("package %s contributed no non-test .go file; scanning it proved nothing", d.path)
			}
			relDir, err := filepath.Rel(root, d.dir)
			if err != nil {
				t.Fatal(err)
			}
			relDir = filepath.ToSlash(relDir)
			decls := 0
			for _, src := range srcs {
				af, err := parser.ParseFile(fset, src, nil, parser.SkipObjectResolution)
				if err != nil {
					t.Fatalf("parsing %s: %v", src, err)
				}
				rel, err := filepath.Rel(root, src)
				if err != nil {
					t.Fatal(err)
				}
				parsed[filepath.ToSlash(rel)] = true
				files++
				decls += len(af.Decls)
				for _, decl := range af.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					if ok && fn.Name.IsExported() {
						exported[relDir] = append(exported[relDir], fn.Name.Name)
					}
				}
				for _, hit := range credentialAcquisitions(fset, af) {
					t.Errorf("FR-ENROLL-001 violated — an enrollment path acquires a credential: %s", hit)
				}
			}
			// Per package, not per file: a doc.go legitimately declares
			// nothing, but a PACKAGE that parsed to nothing is a walk over
			// empty ASTs reporting the same clean result a real one does.
			if decls == 0 {
				t.Fatalf("package %s parsed to zero declarations; an empty parse matches nothing and would pass on anything", d.path)
			}
		}
		if pkgs < 2 {
			t.Fatalf("%s %s resolved to %d first-party package(s); the enroll package plus at least one of its own is the floor, so the closure walk is not walking",
				c.module, c.pattern, pkgs)
		}
	}

	for _, a := range scanAnchors {
		if !parsed[a] {
			t.Fatalf("%s was never parsed — the closure walk missed the enrollment code itself, so a green here means nothing. Re-anchor scanAnchors if the file moved.", a)
		}
	}

	// The entry-point inventory: every exported door into an enrollment
	// package, walked rather than hand-picked. It is the anti-vacuity half —
	// "no prompt found" and "no code found" are the same sentence otherwise.
	for pkg, want := range entryDoors {
		got := exported[pkg]
		if len(got) == 0 {
			t.Fatalf("%s exported no functions to walk; the entry-point set is empty and proves nothing", pkg)
		}
		sort.Strings(got)
		for _, w := range want {
			if !slices.Contains(got, w) {
				t.Fatalf("%s no longer exports %s — re-anchor entryDoors on the new entry point before trusting this scan", pkg, w)
			}
		}
		t.Logf("%s: %d exported entry points scanned: %s", pkg, len(got), strings.Join(got, ", "))
	}
	t.Logf("scanned %d non-test source files across both enrollment closures", files)
}

// TestCredentialScannerSeesPlantedPrompts is the positive control, run on
// every invocation rather than on the day somebody remembers to plant a prompt
// by hand. Both directions matter: a classifier that flagged everything would
// go red on a planted prompt too, so the permitted half is asserted as tightly
// as the rejected half — and the permitted shapes are the REAL ones from this
// flow, including the operator bearer token that legitimately arrives on the
// wire. Rejecting that would make the scan unsatisfiable by the product it
// guards.
func TestCredentialScannerSeesPlantedPrompts(t *testing.T) {
	classify := func(t *testing.T, body string) []string {
		t.Helper()
		fset := token.NewFileSet()
		src := "package p\n" + body
		f, err := parser.ParseFile(fset, "planted.go", src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("planted source does not parse: %v\n%s", err, src)
		}
		return credentialAcquisitions(fset, f)
	}

	planted := map[string]string{
		"x_term_readpassword": `
import "golang.org/x/term"
func f() { _, _ = term.ReadPassword(0) }`,
		"aliased_prompt_import": `
import tty "golang.org/x/term"
func f() { _, _ = tty.ReadPassword(0) }`,
		"bufio_over_stdin": `
import ("bufio"; "os")
func f() { _, _ = bufio.NewReader(os.Stdin).ReadString('\n') }`,
		"fmt_scanln_never_names_stdin": `
import "fmt"
func f() { var k string; _, _ = fmt.Scanln(&k) }`,
		"credential_env_var": `
import "os"
func f() string { return os.Getenv("ANTHROPIC_API_KEY") }`,
		"password_env_var": `
import "os"
func f() (string, bool) { return os.LookupEnv("IDP_PASSWORD") }`,
		"computed_env_var": `
import "os"
func f(name string) string { return os.Getenv(name) }`,
		"opens_controlling_terminal": `
import "os"
func f() { _, _ = os.OpenFile("/dev/tty", os.O_RDWR, 0) }`,
		"raw_mode_ritual": `
import "golang.org/x/term"
func f() { st, _ := term.MakeRaw(0); _ = st }`,
		"termios_by_syscall": `
import "golang.org/x/sys/unix"
func f() { _ = unix.IoctlSetTermios }`,
	}
	for name, body := range planted {
		t.Run("planted_"+name, func(t *testing.T) {
			if hits := classify(t, body); len(hits) == 0 {
				t.Errorf("a planted credential prompt passed the scan clean:\n%s", body)
			}
		})
	}

	// The shapes this flow actually has. Each one is a place the scan would
	// have to be loosened if it fired, and loosening under pressure is how an
	// absence proof becomes a comment.
	permitted := map[string]string{
		"operator_bearer_arrives_on_the_wire": `
import ("net/http"; "strings")
func f(r *http.Request) string {
	b, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return b
}`,
		"non_credential_env_var": `
import "os"
func f() string { return os.Getenv("XDG_RUNTIME_DIR") }`,
		"prints_the_user_code": `
import ("fmt"; "io")
func f(w io.Writer, userCode, uri string) {
	_, _ = fmt.Fprintf(w, "visit %s and enter code: %s\n", uri, userCode)
}`,
		"reads_our_own_device_key": `
import "os"
func f(path string) ([]byte, error) { return os.ReadFile(path) }`,
		"writes_our_own_device_key_0600": `
import "os"
func f(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}`,
		"device_token_fields_and_names": `
type doc struct {
	DeviceToken string
	UserCode    string
	Sig         string
}
func f() doc { token := "m1tok.v1.x.y"; return doc{DeviceToken: token} }`,
		"signs_a_nonce": `
import ("crypto/ed25519"; "crypto/rand")
func f(priv ed25519.PrivateKey) []byte {
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	return ed25519.Sign(priv, seed)
}`,
		"decodes_the_request_body": `
import ("encoding/json"; "net/http")
func f(r *http.Request) error {
	var req struct{ DeviceCode string }
	return json.NewDecoder(r.Body).Decode(&req)
}`,
		"parses_a_string_it_already_holds": `
import "fmt"
func f(s string) int { var n int; _, _ = fmt.Sscan(s, &n); return n }`,
	}
	for name, body := range permitted {
		t.Run("permitted_"+name, func(t *testing.T) {
			if hits := classify(t, body); len(hits) != 0 {
				t.Errorf("the scan rejects a shape this flow legitimately has (%v); a matcher that refuses the product cannot guard it:\n%s", hits, body)
			}
		})
	}
}
