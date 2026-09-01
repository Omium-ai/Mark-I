package cli

// FR-CLI-008: the exit codes of 08 §7 are a wire contract — customers script
// `if [ $? -eq 5 ]` and MDM keys on them — so a silent renumber is a breaking
// change with no compiler and no reviewer to catch it. Every use in this module
// is by NAME, which is exactly why nothing here fails when a number moves.
//
// Three properties, none of which a per-subcommand test can hold:
//
//  1. Each code equals its LITERAL number. `ExitVerify == ExitVerify` is a
//     tautology and would survive the renumber this row exists to catch, so the
//     table carries the digit and the constant separately and compares them.
//  2. The taxonomy is EXHAUSTIVE. A seventh constant added to cli.go without a
//     row here is a code with no asserted number, so the source is parsed and
//     the declared set is compared against the table in both directions — the
//     `assert set(HANDLERS) == set(KINDS)` shape anchors/catalog.go:172 already
//     runs at init and anchors/runner_test.go:356 pins in a test.
//  3. Every M1E code this module hands to Failf is `M1E-dddd` or empty. Empty is
//     DELIBERATE, not a gap: cli.go:41 says `"" when no taxonomy row applies;
//     --json then carries the exit class`, and EmitError (cli.go:424-429)
//     implements exactly that by substituting exitClass(). So the assertion is
//     the shape of the non-empty ones, and the class every code renders as.
//
// Ceiling, stated so a green is not read wider than it is: property 3 is a scan
// of string LITERALS. Five call sites forward the server's own code verbatim out
// of cli.APIError (cli.go:461-473, which does no shape check), and no static
// scan can clear a value that arrives on the wire. Those sites are anchored by
// file below rather than waved through, so a sixth one costs a human a decision.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// exitCodes is the contract, written as digits. `want` is what a customer's
// script compares against; `got` is what this module compiles. They are two
// different things and this file exists to keep them equal.
var exitCodes = []struct {
	name  string
	got   int
	want  int
	class string // exitClass(); "" for a code EmitError is never handed
}{
	{"ExitOK", ExitOK, 0, ""},
	{"ExitRuntime", ExitRuntime, 1, "runtime"},
	{"ExitUsage", ExitUsage, 2, "usage"},
	{"ExitNotEnrolled", ExitNotEnrolled, 3, "not_enrolled"},
	{"ExitRefused", ExitRefused, 4, "refused"},
	{"ExitVerify", ExitVerify, 5, "verification_failure"},
}

// exhaustivenessAnchor is the constant whose const block defines the taxonomy.
// Membership of that block is what makes a name a code, so a seventh entry is
// caught whatever it is called; the Exit prefix additionally catches one
// declared in a block of its own.
const exhaustivenessAnchor = "ExitOK"

var m1eRe = regexp.MustCompile(`^M1E-\d{4}$`)

// declaredExitCodes reads the taxonomy out of source: every name in the const
// block that declares the anchor, plus every top-level const named Exit*. Kept
// separate from the test so the positive control can drive it on planted source
// without mutating the tree.
func declaredExitCodes(f *ast.File) []string {
	var block, prefixed []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		var names []string
		anchored := false
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, n := range vs.Names {
				names = append(names, n.Name)
				if n.Name == exhaustivenessAnchor {
					anchored = true
				}
				if strings.HasPrefix(n.Name, "Exit") {
					prefixed = append(prefixed, n.Name)
				}
			}
		}
		if anchored {
			block = append(block, names...)
		}
	}
	out := block
	for _, n := range prefixed {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// m1eLiterals returns the M1E argument of every Failf call in one file, split
// into string literals (checkable here) and computed expressions (not).
func m1eLiterals(f *ast.File) (lits []string, computed int) {
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 3 {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if fn.Name != "Failf" {
				return true
			}
		case *ast.SelectorExpr:
			id, ok := fn.X.(*ast.Ident)
			if !ok || id.Name != "cli" || fn.Sel.Name != "Failf" {
				return true
			}
		default:
			return true
		}
		lit, ok := call.Args[1].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			computed++
			return true
		}
		lits = append(lits, strings.Trim(lit.Value, `"`))
		return true
	})
	return lits, computed
}

// serverEchoFiles forward cli.APIError's code straight into the M1E slot. The
// server owns that string, so this scan cannot clear it; the list is here so a
// NEW file doing the same thing turns this test red and asks a human whether
// the value should be shape-checked before it reaches --json.
var serverEchoFiles = []string{
	"internal/enroll/enroll.go",
	"internal/report/report.go",
	"internal/verifyreceipts/verifyreceipts.go",
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	// internal/cli → internal → mark1 (module root).
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not at %s: %v", root, err)
	}
	return root
}

func TestExitCodeTaxonomyIsExhaustiveAndStable(t *testing.T) {
	// (1) The numbers. Literal on the right, compiled constant on the left.
	for _, c := range exitCodes {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d — the exit codes are a wire contract (08 §7); renumbering one breaks every customer script that keys on it. Change the product, not this number.", c.name, c.got, c.want)
		}
		if c.class == "" {
			continue
		}
		if got := exitClass(c.got); got != c.class {
			t.Errorf("exitClass(%s=%d) = %q, want %q — --json puts this string in error.code whenever the M1E slot is empty (cli.go:426-429), so it is wire too.", c.name, c.got, got, c.class)
		}
	}

	// (2) Exhaustiveness, read out of source rather than remembered.
	root := moduleRoot(t)
	fset := token.NewFileSet()
	src := filepath.Join(root, "internal", "cli", "cli.go")
	af, err := parser.ParseFile(fset, src, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v — a parse failure must not read as a clean taxonomy", src, err)
	}
	declared := declaredExitCodes(af)
	if len(declared) == 0 {
		t.Fatalf("no exit-code constants found in %s; an empty declared set matches an empty table and would pass on anything. Re-anchor exhaustivenessAnchor if %s moved.", src, exhaustivenessAnchor)
	}
	listed := make([]string, 0, len(exitCodes))
	for _, c := range exitCodes {
		listed = append(listed, c.name)
	}
	sort.Strings(listed)
	for _, n := range declared {
		if !slices.Contains(listed, n) {
			t.Errorf("cli.go declares exit code %s, which no row of exitCodes asserts a number for. A code customers can receive with no pinned value is the renumber this test exists to prevent — add the row.", n)
		}
	}
	for _, n := range listed {
		if !slices.Contains(declared, n) {
			t.Errorf("exitCodes lists %s, which cli.go no longer declares. Deleting a code IS a breaking change; if it really went away, say so here deliberately.", n)
		}
	}
	// Positive control on the unmutated tree: the parse read the real block,
	// so a red above is a disagreement and not an empty walk.
	if len(declared) != len(exitCodes) {
		t.Fatalf("cli.go declares %d exit codes %v, exitCodes lists %d %v", len(declared), declared, len(exitCodes), listed)
	}

	// (3) The M1E shapes across the whole module — the CLI is one binary and a
	// malformed code is equally wrong wherever it is typed.
	sites, files, nonEmpty, echoSites := 0, 0, 0, 0
	echoed := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		files++
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		lits, computed := m1eLiterals(f)
		if computed > 0 {
			echoed[rel] = true
		}
		for _, l := range lits {
			sites++
			if l == "" {
				continue // cli.go:41: no taxonomy row applies; --json carries the exit class
			}
			nonEmpty++
			if !m1eRe.MatchString(l) {
				t.Errorf("%s: Failf carries M1E code %q, which is not M1E-dddd — 08 §9 codes are parsed by customers; free text in that slot is unclassifiable. Use a real code or the empty string.", rel, l)
			}
		}
		sites += computed
		echoSites += computed
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 9 || sites < 40 {
		t.Fatalf("scanned %d source files and %d Failf sites; that is too few to have walked this module, and a scan that reads nothing reports exactly what a clean one reports", files, sites)
	}
	if nonEmpty == 0 {
		t.Fatal("no non-empty M1E literal was seen; the regexp assertion above proved nothing")
	}
	for f := range echoed {
		if !slices.Contains(serverEchoFiles, f) {
			t.Errorf("%s passes a computed value as the M1E code. Only the cli.APIError echo sites may (the server owns that string and cli.go:461-473 does not shape-check it) — if this is another one, decide whether it should be validated before it reaches --json, then anchor it in serverEchoFiles.", f)
		}
	}
	t.Logf("%d Failf sites across %d files: %d carry an M1E-dddd code, %d are deliberately empty (cli.go:41), %d echo the server across %d files", sites, files, nonEmpty, sites-nonEmpty-echoSites, echoSites, len(echoed))
}

// TestExitCodeScannerSeesAPlantedSeventhCode drives both classifiers on planted
// source on every run, so the red direction is proven without anyone mutating
// cli.go by hand — and so a green above cannot be a scanner that matches nothing.
func TestExitCodeScannerSeesAPlantedSeventhCode(t *testing.T) {
	parse := func(t *testing.T, body string) *ast.File {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "planted.go", "package p\n"+body, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("planted source does not parse: %v", err)
		}
		return f
	}

	t.Run("seventh code in the anchored block", func(t *testing.T) {
		got := declaredExitCodes(parse(t, "const (\nExitOK = 0\nExitPanic = 6\n)"))
		if !slices.Contains(got, "ExitPanic") {
			t.Errorf("a seventh code added to the taxonomy block was not seen: %v", got)
		}
	})
	t.Run("seventh code in a block of its own", func(t *testing.T) {
		got := declaredExitCodes(parse(t, "const (\nExitOK = 0\n)\nconst ExitPanic = 6"))
		if !slices.Contains(got, "ExitPanic") {
			t.Errorf("a code declared outside the anchored block was not seen: %v", got)
		}
	})
	t.Run("unprefixed name in the anchored block", func(t *testing.T) {
		got := declaredExitCodes(parse(t, "const (\nExitOK = 0\nFatalIO = 6\n)"))
		if !slices.Contains(got, "FatalIO") {
			t.Errorf("block membership, not the Exit prefix, is what makes a name a code: %v", got)
		}
	})
	t.Run("unrelated const block is not a code", func(t *testing.T) {
		got := declaredExitCodes(parse(t, "const (\nExitOK = 0\n)\nconst (\nStateActive = \"active\"\n)"))
		if slices.Contains(got, "StateActive") {
			t.Errorf("StateActive is not an exit code; a matcher this broad would flag every const in the file: %v", got)
		}
	})

	// The M1E classifier, both directions. Bad shapes must be seen and the real
	// vocabulary — including the deliberate empty — must pass, or the assertion
	// is one the product cannot satisfy.
	lits, computed := m1eLiterals(parse(t, `
func f() {
	Failf(1, "", "a")
	Failf(3, "M1E-1002", "b")
	cli.Failf(4, "M1E-5004", "c")
	cli.Failf(1, "not-a-code", "d")
	Failf(1, "M1E-12", "e")
	Failf(1, code, "f")
}`))
	if len(lits) != 5 || computed != 1 {
		t.Fatalf("classifier saw %d literals %v and %d computed args, want 5 and 1", len(lits), lits, computed)
	}
	for _, bad := range []string{"not-a-code", "M1E-12"} {
		if m1eRe.MatchString(bad) {
			t.Errorf("%q passed the M1E shape check", bad)
		}
	}
	for _, good := range []string{"M1E-1002", "M1E-5004"} {
		if !m1eRe.MatchString(good) {
			t.Errorf("%q is a real 08 §9 code and must pass; a check the taxonomy fails is a check that gets deleted", good)
		}
	}
}
