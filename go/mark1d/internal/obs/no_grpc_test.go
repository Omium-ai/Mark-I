// FR-SPINE-008's second clause — "never gRPC to the edge" (08 §2) — executed
// in Go's own test runner, because until now the clause was asserted NOWHERE:
// the only artifacts were a comment in proto/buf.gen.yaml, a sentence at the
// top of internal/uplink/transport.go, a depguard rule in .golangci.yml and a
// cargo-deny row in deny.toml. The two enforced ones are real gates but neither
// is a test, neither reads a module graph, and neither would notice a `service`
// block appearing in a .proto — which is the FIRST thing that has to happen for
// an edge gRPC surface to exist at all.
//
// It lives beside no_otel_test.go and is built the same way, for the same
// reason: an absence claim is only worth what its positive control and its
// anti-vacuity guards are worth. Every scan below asserts it SAW something
// before it reports that it found nothing.
package obs

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// grpcImport classifies a Go module or package path as gRPC. Segment-matched,
// not substring-matched: `google.golang.org/genproto/googleapis/rpc/status`
// ships in this estate through ClickHouse and is protobuf status codes, not a
// transport — a scanner that matched "rpc" would fail on it and be widened
// until it matched nothing.
func grpcImport(path string) bool {
	if path == "connectrpc.com" || strings.HasPrefix(path, "connectrpc.com/") {
		return true
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "grpc" || strings.HasPrefix(seg, "grpc-") || strings.HasSuffix(seg, "-grpc") {
			return true
		}
	}
	return false
}

// grpcCrate classifies a cargo crate name. The Rust half of the edge (the
// hookshim, m1p-wire, mark1-redact) is where a gRPC client would be least
// visible from Go, and deny.toml's tonic ban is a gate nothing in `cargo test`
// runs.
func grpcCrate(name string) bool {
	return name == "tonic" || strings.HasPrefix(name, "tonic-") || strings.Contains(name, "grpc")
}

// serviceDecl and rpcDecl are line-anchored on purpose. events.proto carries
// `string service_tier = 9;`, so a substring match for "service" reports the
// M1P envelope as a gRPC interface; and the comments that explain why there is
// no service would each be a hit.
var (
	serviceDecl = regexp.MustCompile(`(?m)^\s*service\s+[A-Za-z_]`)
	rpcDecl     = regexp.MustCompile(`(?m)^\s*rpc\s+[A-Za-z_]`)
	messageDecl = regexp.MustCompile(`(?m)^\s*message\s+[A-Za-z_]`)
)

// TestNoModuleDependsOnGRPC is the dependency half, at both levels every
// workspace module can carry one: the resolved module graph (a transitive
// dependency nothing imports yet still ships) and the compiled package set,
// tests included. Unlike the otel ban there is no waiver to apply — 08 §2 makes
// M1P plain HTTPS, so an inert gRPC stub is not a category that exists.
func TestNoModuleDependsOnGRPC(t *testing.T) {
	root := repoRoot(t)
	mods := workModules(t, root)
	if len(mods) == 0 {
		t.Fatal("go.work named no modules — this scan just covered nothing and passed")
	}
	for _, m := range mods {
		dir := filepath.Join(root, m)

		edges := goIn(t, dir, "mod", "graph")
		if len(edges) == 0 {
			t.Fatalf("`go mod graph` in %s is empty; an empty graph matches nothing and would pass on anything", m)
		}
		for _, e := range edges {
			for _, node := range strings.Fields(e) {
				// Strip the @version half: the ban is on the module, not a release.
				if mod, _, _ := strings.Cut(node, "@"); grpcImport(mod) {
					t.Errorf("%s depends on %s — M1P is plain HTTPS and the fabric is M1PL; there is no gRPC leg to the edge (08 §2)", m, node)
				}
			}
		}

		pkgs := goIn(t, dir, "list", "-deps", "-test", "./...")
		if len(pkgs) == 0 {
			t.Fatalf("`go list -deps -test ./...` in %s listed no packages; the compiled scan proved nothing", m)
		}
		for _, p := range pkgs {
			if grpcImport(p) {
				t.Errorf("%s COMPILES %s — a gRPC package in the binary is a gRPC port waiting for a listener (08 §2)", m, p)
			}
		}
	}
}

// TestNoFirstPartyGoSourceImportsGRPC parses import declarations rather than
// grepping, for no_otel_test.go's reason: a textual scan cannot tell an import
// from the sentence explaining why there is none, so it goes red on this repo's
// own documentation or is loosened until the real import slips past. This is
// the in-language twin of .golangci.yml's depguard `no-grpc` rule, which only
// covers what the linter is pointed at.
func TestNoFirstPartyGoSourceImportsGRPC(t *testing.T) {
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
			if p := strings.Trim(imp.Path.Value, `"`); grpcImport(p) {
				t.Errorf("%s imports %s — M1P is plain HTTPS (08 §2)", path, p)
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

// TestNoProtoDeclaresAService is the clause at its source. Every artifact above
// is downstream of one fact: m1p defines MESSAGES and no services, so there is
// no interface for a gRPC plugin to generate a stub from and nothing to serve.
// A `service` block would be the first commit of an edge gRPC port, and would
// land in a directory the codegen freshness gate regenerates without complaint.
func TestNoProtoDeclaresAService(t *testing.T) {
	root := repoRoot(t)
	files, messages := 0, 0
	err := filepath.WalkDir(filepath.Join(root, "proto"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".proto") {
			return err
		}
		b, rerr := os.ReadFile(path) // #nosec G304 -- walking the repo's own proto dir
		if rerr != nil {
			return rerr
		}
		files++
		messages += len(messageDecl.FindAll(b, -1))
		if m := serviceDecl.Find(b); m != nil {
			t.Errorf("%s declares a service (%q) — Mark 1 has no gRPC surface at all (08 §2)", path, strings.TrimSpace(string(m)))
		}
		if m := rpcDecl.Find(b); m != nil {
			t.Errorf("%s declares an rpc method (%q) — Mark 1 has no gRPC surface at all (08 §2)", path, strings.TrimSpace(string(m)))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Anti-vacuity: an empty walk, a moved proto tree or a regexp that matches
	// nothing all produce the same silent green as a clean schema.
	if files == 0 || messages == 0 {
		t.Fatalf("scanned %d .proto files holding %d message declarations under %s/proto; a scan that parsed no schema cannot report one is clean", files, messages, root)
	}
}

// TestNoRustCrateIsAGRPCStack covers the half no Go scan can see: the shim,
// m1p-wire and mark1-redact are the edge too, and deny.toml's tonic row is a
// cargo-deny gate that `cargo test` never runs. Cargo.lock is the resolved set,
// so this is the Rust analogue of the module graph above.
func TestNoRustCrateIsAGRPCStack(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "Cargo.lock"))
	if err != nil {
		t.Fatal(err)
	}
	crates := 0
	for _, line := range strings.Split(string(b), "\n") {
		name, ok := strings.CutPrefix(strings.TrimSpace(line), "name = ")
		if !ok {
			continue
		}
		crates++
		if name = strings.Trim(name, `"`); grpcCrate(name) {
			t.Errorf("Cargo.lock resolves %q — no gRPC in Mark 1 (deny.toml, 08 §2)", name)
		}
	}
	if crates < 20 {
		t.Fatalf("parsed %d crate names out of Cargo.lock; the lockfile format changed and this scan covered almost nothing", crates)
	}
}

// TestGRPCScannerAcceptsWhatMark1ActuallyShips drives all three classifiers
// from both sides on synthetic input, so the red direction is proven on every
// run and not only on the day someone plants a dependency by hand.
//
// The accept sets are the load-bearing half. gRPC rides HTTP/2 and speaks
// protobuf, and so does M1P — `h2`, `hyper`, `tower` and `prost` are all in
// this repo's real lockfile — so a matcher that reached for the transport or
// the encoding would condemn exactly what 08 §2 prescribes, and the honest
// response to that red would be to delete the test.
func TestGRPCScannerAcceptsWhatMark1ActuallyShips(t *testing.T) {
	for _, p := range []string{
		"google.golang.org/grpc",
		"google.golang.org/grpc/credentials/insecure",
		"github.com/grpc-ecosystem/go-grpc-middleware",
		"connectrpc.com/connect",
		"example.com/edge/grpc/server",
		"github.com/example/proto-grpc",
	} {
		if !grpcImport(p) {
			t.Errorf("a planted gRPC import passed the scan: %s", p)
		}
	}
	for _, p := range []string{
		"google.golang.org/protobuf/proto",
		"google.golang.org/genproto/googleapis/rpc/status",
		"google.golang.org/genproto/googleapis/api",
		"golang.org/x/net/http2",
		"github.com/google/uuid",
		"net/http",
	} {
		if grpcImport(p) {
			t.Errorf("%s is not gRPC; the matcher is too broad and would ban M1P's own transport", p)
		}
	}

	for _, c := range []string{"tonic", "tonic-build", "grpcio", "tower-grpc", "grpc"} {
		if !grpcCrate(c) {
			t.Errorf("a planted gRPC crate passed the scan: %s", c)
		}
	}
	for _, c := range []string{"h2", "hyper", "hyper-util", "tower", "tower-service", "prost", "prost-types", "reqwest"} {
		if grpcCrate(c) {
			t.Errorf("%q is HTTP/2, protobuf or middleware — all of which M1P uses; the matcher is too broad", c)
		}
	}

	planted := []byte("syntax = \"proto3\";\n\nservice Ingest {\n  rpc Push(Batch) returns (Ack);\n}\n")
	if serviceDecl.Find(planted) == nil {
		t.Error("a planted `service` block passed the proto scan")
	}
	if rpcDecl.Find(planted) == nil {
		t.Error("a planted `rpc` method passed the proto scan")
	}
	// The near-misses that live in the real schema and in the comments around
	// it. Any of these matching turns the scan into one that must be deleted.
	permitted := []byte("message Usage {\n  string service_tier = 9;\n}\n// there is no gRPC service here\n//   service Foo {}\n")
	if m := serviceDecl.Find(permitted); m != nil {
		t.Errorf("the proto scan reads %q as a service declaration", strings.TrimSpace(string(m)))
	}
	if m := rpcDecl.Find(permitted); m != nil {
		t.Errorf("the proto scan reads %q as an rpc declaration", strings.TrimSpace(string(m)))
	}
	if messageDecl.Find(permitted) == nil {
		t.Error("the anti-vacuity counter does not recognise a message declaration, so it can never prove the walk parsed a schema")
	}
}
