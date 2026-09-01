//go:build unix

package anchors

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// enabledAll derives + consents the whole fixture catalog, so the wire audit
// below runs the DEFAULT set of anchors rather than a hand-built entry whose
// shape the test chose. Provenance matters here: RunOne sources `tool` and the
// FSConfined precondition from the detector table by kind, which a fabricated
// CatalogEntry would sidestep.
func enabledAll(t *testing.T) ([]CatalogEntry, string) {
	t.Helper()
	wt, _ := fixtureWorkspace(t)
	derived, err := Derive(testSandbox(t), wt)
	if err != nil {
		t.Fatal(err)
	}
	path := ConsentPath(t.TempDir())
	if err := Approve(path, time.Now(), derived...); err != nil {
		t.Fatal(err)
	}
	consented, err := LoadConsent(path)
	if err != nil {
		t.Fatal(err)
	}
	rep := Reconcile(derived, consented)
	if len(rep.Enabled) != len(derived) || len(rep.Enabled) == 0 {
		t.Fatalf("enabled %d of %d derived entries", len(rep.Enabled), len(derived))
	}
	return rep.Enabled, wt
}

// adversarialRuns is what these tools print against a real repository:
// absolute paths, relative paths, and the tool's own prose about the
// customer's identifiers. Under 02 CON-004 none of it may reach the wire on
// the default tier. The second eslint row is the interesting one — a ruleId is
// REPO-controlled (runner.go), so a local plugin can name a rule after a path.
var adversarialRuns = []struct {
	kind Kind
	res  RunResult
}{
	{KindRuff, RunResult{ExitCode: 1, Stdout: []byte(
		"src/billing/secret_module.py:10:5: E501 Line too long (110 > 100)\n" +
			"/home/ana/work/acme/lib/other.py:1:1: F401 'os' imported but unused\n")}},
	{KindTsc, RunResult{ExitCode: 2, Stdout: []byte(
		"src/app/vault.ts(12,3): error TS2345: Argument of type 'CustomerSecret' is not assignable to parameter of type 'string'.\n")}},
	{KindCargoCheck, RunResult{ExitCode: 101, Stderr: []byte(
		"src/keys/rotate.rs:42:9: error[E0308]: mismatched types, expected `SigningKey`, found `String`\n")}},
	{KindGoVet, RunResult{ExitCode: 1, Stderr: []byte(
		"./internal/payroll/salaries.go:3:2: unreachable code\n")}},
	{KindEslint, RunResult{ExitCode: 1, Stdout: []byte(
		`[{"filePath":"/home/ana/work/acme/src/admin/keys.js","errorCount":2,"warningCount":0,` +
			`"messages":[{"ruleId":"import/order","severity":2,"message":"'./secretVault' import should occur before import of '../keys'"},` +
			`{"ruleId":"acme-plugin/../../etc/passwd","severity":2,"message":"Unexpected console statement in redactSecret()"}]}]`)}},
	{KindEslint, RunResult{ExitCode: 1, Stdout: []byte(
		`[{"filePath":"/home/ana/work/acme/src/admin/keys.js","errorCount":1,"warningCount":0,` +
			`"messages":[{"ruleId":"acme-plugin/../../etc/passwd","severity":2,"message":"Unexpected console statement in redactSecret()"}]}]`)}},
}

// pathToken is a filesystem-path shape, deliberately NOT "contains a slash":
// eslint rule ids legitimately contain one ("import/order",
// "@typescript-eslint/no-explicit-any") and a check that flagged those would
// be deleted by the first engineer it blocked, which is how privacy tests die.
// A path is rooted/relative-prefixed, carries a traversal segment, or is
// separator-joined with a file extension on its last component. The traversal
// arm exists because it is what an eslint plugin naming a rule
// "acme-plugin/../../etc/passwd" produces — caught first by the byte-level
// backstop below, which is what a structural check is supposed to catch first.
var pathToken = regexp.MustCompile(`^(/|\./|\.\./|~/|[A-Za-z]:[\\/])` +
	`|[/\\]\.{1,2}[/\\]` +
	`|[/\\][^/\\]*\.[A-Za-z0-9]{1,8}($|[^A-Za-z0-9])`)

// looksLikePath reports whether any whitespace/quote-delimited token in s has
// a path shape. It is applied to single wire field values AND to the raw tool
// output, so that the fixtures can prove the detector fires at all.
func looksLikePath(s string) bool {
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '"' || r == '\'' || r == ',' || r == '`'
	}) {
		if pathToken.MatchString(tok) {
			return true
		}
	}
	return false
}

// visitWireStrings calls fn for every populated string field, string map key
// and nested-message string in m. Reflecting over the message rather than
// grepping the marshaled bytes is what makes the assertion structural: it
// names the field that leaked, and it keeps working when a new field appears.
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

// TestWireNoPathsNoExcerpts is the anchors-plane arm of
// `neg_wire_no_paths_no_excerpts` (12 §9 row 4; 02 CON-004, NFR-PRIVACY-001):
// every event the runner emits under the DEFAULT catalog and default config,
// driven by tool output loaded with paths and prose, walked field by field.
//
// Scope, stated because it bounds the claim: this covers the events the anchor
// runner emits. The other three planes that put bytes on the same wire — the
// tailer, capture admission, and the uplink's POST body — are asserted by
// TestWirePipelineNoPathsNoExcerpts in internal/uplink/wire_audit_test.go,
// which reuses this file's detector verbatim. Together the two are the whole
// of the CON-004 / NFR-PRIVACY-001 claim; either one alone is a partial.
func TestWireNoPathsNoExcerpts(t *testing.T) {
	entries, wt := enabledAll(t)
	byKind := map[Kind]CatalogEntry{}
	for _, e := range entries {
		byKind[e.Kind] = e
	}
	key, err := DeriveOutputHMACKey(bytes.Repeat([]byte{0x5A}, 32))
	if err != nil {
		t.Fatal(err)
	}

	em := &fakeEmitter{}
	for _, c := range adversarialRuns {
		e, ok := byKind[c.kind]
		if !ok {
			t.Fatalf("kind %s is not in the derived catalog — the audit would skip it silently", c.kind)
		}
		// Default config: no test opt-in, tenant key present.
		r := NewRunner(&fakeSandbox{res: c.res}, em, key, false)
		if err := r.RunOne(context.Background(), e, testSession, testTask, wt); err != nil {
			t.Fatalf("%s: %v", c.kind, err)
		}
	}
	evs := em.all()
	if len(evs) != len(adversarialRuns) {
		t.Fatalf("emitted %d events, want %d", len(evs), len(adversarialRuns))
	}

	// Positive control 1: the fixtures really do carry what the walk hunts.
	// Without this the whole test passes if looksLikePath never matches
	// anything, which is also what a broken regexp looks like.
	for _, c := range adversarialRuns {
		raw := string(c.res.Stdout) + string(c.res.Stderr)
		if !looksLikePath(raw) {
			t.Fatalf("%s fixture carries no path shape — the detector has nothing to catch", c.kind)
		}
		if !strings.ContainsAny(raw, " \t") {
			t.Fatalf("%s fixture carries no free text — the excerpt check has nothing to catch", c.kind)
		}
	}

	// Positive control 2: the events carry real typed evidence. A wire of empty
	// messages satisfies every negative below and proves nothing.
	// diagnostic_code is NOT asserted non-empty per event: go vet prints no
	// codes (runner.go goVetLine), so its records legitimately carry counts and
	// no code. Errors > 0 is the signal that the parse actually landed.
	sawImportOrder := false
	for i, ev := range evs {
		rec := ev.GetAnchorVote().GetEvidence()
		if rec.GetTool() == "" || rec.GetCounts().GetErrors() == 0 {
			t.Errorf("event %d: tool %q, errors %d — no evidence to audit", i, rec.GetTool(), rec.GetCounts().GetErrors())
		}
		if rec.GetDiagnosticCode() == "import/order" {
			sawImportOrder = true
		}
	}
	// ...and the false-positive guard: a legitimate slash-bearing eslint rule id
	// DOES reach the wire and DOES survive the path check below. A privacy test
	// that fired on legal traffic gets deleted, so prove it does not.
	if !sawImportOrder {
		t.Error(`no event carried diagnostic_code "import/order" — the path check is never exercised against legal slash-bearing traffic`)
	}

	visited := 0
	for i, ev := range evs {
		visitWireStrings(ev.ProtoReflect(), "", func(field, val string) {
			visited++
			if looksLikePath(val) {
				t.Errorf("event %d: %s = %q carries a filesystem path shape. 02 NFR-PRIVACY-001: path_role is the ONLY path-derived field on the default tier", i, field, val)
			}
			if strings.ContainsAny(val, " \t\n\r") {
				t.Errorf("event %d: %s = %q carries whitespace, i.e. free text. E0 fields are closed vocabularies (tool names, tool diagnostic codes); prose belongs in the opt-in E1 class", i, field, val)
			}
		})
	}
	if visited == 0 {
		t.Fatal("walked zero string fields — the walk found nothing, so it proved nothing")
	}

	// Byte-level backstop for the non-string fields (digests, attestations):
	// the literals planted above must not survive anywhere in the encoding.
	for i, ev := range evs {
		raw, err := proto.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		for _, leak := range []string{
			"secret_module", "other.py", "vault.ts", "rotate.rs", "salaries.go", "keys.js",
			"/home/ana", "acme", "Line too long", "imported but unused", "mismatched types",
			"unreachable code", "redactSecret", "CustomerSecret", "SigningKey", "etc/passwd",
		} {
			if bytes.Contains(raw, []byte(leak)) {
				t.Errorf("event %d: marshaled bytes leak %q", i, leak)
			}
		}
	}
}

// TestRunOneOutputHMACIsTenantScoped is the end-to-end half of
// `neg_digests_tenant_salted` (02 NFR-PRIVACY-002): privacy_test.go proves the
// digest function is tenant-keyed, this proves the RUNNER actually reaches for
// the tenant key on the emit path rather than falling back to something
// globally joinable.
func TestRunOneOutputHMACIsTenantScoped(t *testing.T) {
	e, wt := enabledRuff(t)
	res := adversarialRuns[0].res

	digest := func(root byte) []byte {
		t.Helper()
		key, err := DeriveOutputHMACKey(bytes.Repeat([]byte{root}, 32))
		if err != nil {
			t.Fatal(err)
		}
		em := &fakeEmitter{}
		r := NewRunner(&fakeSandbox{res: res}, em, key, false)
		if err := r.RunOne(context.Background(), e, testSession, testTask, wt); err != nil {
			t.Fatal(err)
		}
		return em.all()[0].GetAnchorVote().GetEvidence().GetOutputHmac()
	}

	first, again, other := digest(0x11), digest(0x11), digest(0x22)
	if len(first) != 32 {
		t.Fatalf("output_hmac is %d bytes, want 32 — nothing below means anything", len(first))
	}
	if !bytes.Equal(first, again) {
		t.Error("same tenant root, same output, different digests — cross-run dedupe cannot join")
	}
	if bytes.Equal(first, other) {
		t.Error("two tenant roots produced the SAME digest for identical tool output — the value is a global join key, which is the correlation NFR-PRIVACY-002 forbids")
	}
}
