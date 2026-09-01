// ADR-0005 clause 4 executed in Go's own test runner: "a CI step fails if
// `go mod graph` for any module matches" the banned prefix. It is the Go twin
// of python/intel/tests/test_no_clickhouse_dep.py and the in-language belt to
// tools/ci/otel_gate.sh's suspenders — a shell gate someone forgets to run in
// their editor is a gate that reports the breach after the commit.
//
// It lives in internal/obs because obs IS the alternative: mark1d's health
// leaves the box as EdgeHealth over M1P and nothing else (CON-005), so the
// package that emits telemetry is the right place to keep the door shut.
package obs

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The banned module prefix is ASSEMBLED from fragments, never written out.
// Clause (3) of the D-M waiver in tools/ci/otel_gate.sh greps EVERY .go file
// under go/ for the literal and refuses the waiver on any hit — so a scanner
// that spelled its own subject would turn the repo's own gate red merely by
// existing, and the file documenting the ban would be the file breaking it.
// The Python twin dodges the same trap by matching package names instead of
// grepping its own source.
var (
	otelPrefix = "go.opentele" + "metry.io/"
	otlpToken  = "ot" + "lp"
)

// forbiddenFamilies transcribes otel_gate.sh's FORBIDDEN_OTEL_PKGS, matched
// against the path AFTER otelPrefix. otel/ and otel/trace/ are deliberately
// absent: the inert API stub is exactly what D-M waives, and this list is the
// place a widening would have to happen, so it must stay legible as a list.
var forbiddenFamilies = []string{
	"otel/sdk", "otel/exporters", "otel/metric", "otel/bridge", "otel/log",
	"contrib", "auto", "proto", "collector",
}

// forbidden reports whether a module or package path is a telemetry STACK
// rather than the stub — an SDK, an exporter, OTLP in any spelling, contrib,
// auto-instrumentation or the collector.
func forbidden(path string) bool {
	if strings.Contains(path, otlpToken) {
		return true
	}
	rest, ok := strings.CutPrefix(path, otelPrefix)
	if !ok {
		return false
	}
	for _, f := range forbiddenFamilies {
		if rest == f || strings.HasPrefix(rest, f+"/") {
			return true
		}
	}
	return false
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// internal/obs → internal → mark1d → go → repo root.
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.work")); err != nil {
		t.Fatalf("repo root not at %s: %v", root, err)
	}
	return root
}

// workModules reads go.work for otel_gate.sh's stated reason: a module added to
// the build but never added to a hardcoded list here is an unscanned module,
// and an unscanned module is where the dependency lands.
func workModules(t *testing.T, root string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "go.work"))
	if err != nil {
		t.Fatal(err)
	}
	var mods []string
	in := false
	for _, line := range strings.Split(string(b), "\n") {
		switch s := strings.TrimSpace(line); {
		case s == "use (":
			in = true
		case in && s == ")":
			in = false
		case in && strings.HasPrefix(s, "./"):
			mods = append(mods, strings.TrimPrefix(s, "./"))
		}
	}
	return mods
}

// goIn runs the toolchain in one module with the WORKSPACE OFF. That flag is
// the whole reason this scan is per-module: inside the workspace `go mod graph`
// answers with the UNION of every module's graph, so mark1d — whose go.mod has
// not one otel line — reports its neighbour's 32 otel edges as its own, and a
// scan run from here could never say whose dependency it was.
func goIn(t *testing.T, dir string, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go %s in %s: %v", strings.Join(args, " "), dir, err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

// TestModuleGraphHasNoTelemetryStack is the deliverable: the RESOLVED module
// graph of every workspace module, not anybody's import list — a transitive
// dependency nothing imports yet is still a dependency that ships.
func TestModuleGraphHasNoTelemetryStack(t *testing.T) {
	root := repoRoot(t)
	mods := workModules(t, root)
	if len(mods) == 0 {
		t.Fatal("go.work named no modules — this scan just covered nothing and passed")
	}
	var scanned []string
	for _, m := range mods {
		dir := filepath.Join(root, m)
		edges := goIn(t, dir, "mod", "graph")
		if len(edges) == 0 {
			t.Fatalf("`go mod graph` in %s is empty; an empty graph matches nothing and would pass on anything", m)
		}
		scanned = append(scanned, m)

		var hits []string
		for _, e := range edges {
			for _, node := range strings.Fields(e) {
				if strings.HasPrefix(node, otelPrefix) {
					hits = append(hits, node)
				}
			}
		}
		if len(hits) == 0 {
			continue
		}
		requireInertStub(t, root, m, hits)
	}
	if len(scanned) != len(mods) {
		t.Fatalf("scanned %v of %v", scanned, mods)
	}
}

// requireInertStub applies the D-M waiver as written, and no wider. A module
// graph hit is tolerated ONLY as the inert API stub the sanctioned ClickHouse
// client compiles; clause (3) is a separate test because it is repo-wide.
func requireInertStub(t *testing.T, root, mod string, hits []string) {
	t.Helper()
	dir := filepath.Join(root, mod)

	// (1) A human typing a direct otel require is refused, whatever it is.
	b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, otelPrefix) && !strings.HasSuffix(strings.TrimSpace(line), "// indirect") {
			t.Fatalf("%s/go.mod carries a DIRECT otel require: %q. D-M covers a transitive stub, never a deliberate one.", mod, strings.TrimSpace(line))
		}
	}

	// (2) The compiled import graph, tests included — which is what
	// "transitive" means for a binary. Module-graph residue that corresponds
	// to zero compiled packages is inert by construction; a compiled package
	// from a stack family is not, whatever the go.mod says.
	pkgs := goIn(t, dir, "list", "-deps", "-test", "./...")
	if len(pkgs) == 0 {
		t.Fatalf("`go list -deps -test ./...` in %s listed no packages; clause (2) proved nothing", mod)
	}
	for _, p := range pkgs {
		if forbidden(p) {
			t.Fatalf("%s COMPILES %s — an SDK/exporter/OTLP package is a telemetry stack, not the D-M stub. Telemetry rides M1P (ADR-0005); there is no flag.", mod, p)
		}
	}
	t.Logf("%s: %d otel module-graph nodes WAIVED under D-M (inert API stub, nothing from a stack family compiles)", mod, len(hits))
}

// TestNoFirstPartyGoSourceImportsTelemetry is waiver clause (3), and it parses
// IMPORT DECLARATIONS rather than grepping. A textual scan cannot tell an
// import from the sentence describing why there is none, so it either goes red
// on this repo's own documentation or is written loosely enough to go green
// while the real import sits two lines below the comment that excuses it.
func TestNoFirstPartyGoSourceImportsTelemetry(t *testing.T) {
	goDir := filepath.Join(repoRoot(t), "go")
	fset := token.NewFileSet()
	files := 0
	err := filepath.WalkDir(goDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		files++
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if strings.HasPrefix(p, otelPrefix) || strings.Contains(p, otlpToken) {
				t.Errorf("%s imports %s — the stub is reachable from vendor code only (D-M clause 3)", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 {
		t.Fatalf("parsed only %d .go files under %s; the import scan covered almost nothing", files, goDir)
	}
}

// TestScannerRejectsAPlantedStack drives the classifier from both sides on
// synthetic paths, so the red direction is proven on every run and not only on
// the day someone remembers to plant a dependency by hand.
func TestScannerRejectsAPlantedStack(t *testing.T) {
	stack := []string{
		otelPrefix + "otel/sdk",
		otelPrefix + "otel/sdk/metric",
		otelPrefix + "otel/exporters/" + otlpToken + "/" + otlpToken + "trace",
		otelPrefix + "otel/metric",
		otelPrefix + "contrib/instrumentation/net/http/otelhttp",
		otelPrefix + "auto/sdk",
		otelPrefix + "proto/" + otlpToken + "/collector/trace/v1",
		"github.com/example/" + otlpToken + "-shipper",
	}
	for _, p := range stack {
		if !forbidden(p) {
			t.Errorf("a planted telemetry stack passed the scan: %s", p)
		}
	}
	// The stub, and only the stub, is allowed through — widening this set is
	// what D-M forbids, so it is asserted as tightly as the rejection is.
	for _, p := range []string{otelPrefix + "otel", otelPrefix + "otel/trace"} {
		if forbidden(p) {
			t.Errorf("%s is the inert API stub D-M waives; rejecting it widens the gate into one that cannot be satisfied", p)
		}
	}
	for _, p := range []string{"github.com/google/uuid", "google.golang.org/protobuf/proto"} {
		if forbidden(p) {
			t.Errorf("%s is not telemetry; the matcher is too broad", p)
		}
	}
}
