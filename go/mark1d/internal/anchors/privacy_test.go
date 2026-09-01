package anchors

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// evidenceRecordSchema is artifacts.proto's EvidenceRecord, frozen field by
// field. The duplication is the point: 02 CON-004 promises the default wire
// type is STRUCTURALLY unable to carry a path or free text, and today that
// promise is enforced only by the prose above the message ("Adding a path, a
// message, a line number or an excerpt field to THIS message would collapse
// that whole tiering into a promise"). A comment blocks nobody at review time.
var evidenceRecordSchema = []struct {
	name protoreflect.Name
	num  protoreflect.FieldNumber
	kind protoreflect.Kind
	// ref is the enum/message type name for composite kinds, empty for
	// scalars — pinned so that swapping `counts` for a free-text message under
	// the same name and number is caught too.
	ref protoreflect.FullName
}{
	{"tool", 1, protoreflect.StringKind, ""},
	{"diagnostic_code", 2, protoreflect.StringKind, ""},
	{"category", 3, protoreflect.EnumKind, "m1p.v1.EvidenceCategory"},
	{"counts", 4, protoreflect.MessageKind, "m1p.v1.EvidenceCounts"},
	{"path_role", 5, protoreflect.EnumKind, "m1p.v1.PathRole"},
	{"output_hmac", 6, protoreflect.BytesKind, ""},
}

// TestEvidenceRecordSchemaClosed is `unit_evidencerecord_schema_closed`
// (12 §9 row 4; 02 CON-004, NFR-PRIVACY-001). It reflects over the GENERATED
// descriptor rather than grepping artifacts.proto because the promise is about
// what gets SERIALISED — a field that exists in the descriptor is a field that
// can travel, whatever the .proto text says.
//
// The field this exists to stop is not malicious. It is `string message = 7`,
// added in good faith to make a diagnostic readable in a dashboard.
func TestEvidenceRecordSchemaClosed(t *testing.T) {
	md := (&m1pv1.EvidenceRecord{}).ProtoReflect().Descriptor()

	// Resolve positively FIRST: "the descriptor carries no forbidden field" is
	// equally what a test that resolved the wrong message — or none — reports.
	if got := md.FullName(); got != "m1p.v1.EvidenceRecord" {
		t.Fatalf("resolved descriptor %q, want m1p.v1.EvidenceRecord", got)
	}
	fields := md.Fields()

	for _, want := range evidenceRecordSchema {
		fd := fields.ByName(want.name)
		if fd == nil {
			t.Errorf("EvidenceRecord lost field %q — E0 evidence is a fixed six-field shape; removing one is a wire break, not a cleanup", want.name)
			continue
		}
		if fd.Number() != want.num {
			t.Errorf("field %q has number %d, want %d (renumbering re-reads old bytes as a different field)", want.name, fd.Number(), want.num)
		}
		if fd.Kind() != want.kind {
			t.Errorf("field %q has kind %s, want %s", want.name, fd.Kind(), want.kind)
		}
		if fd.IsList() || fd.IsMap() {
			t.Errorf("field %q became repeated/map — a repeated string is an excerpt list wearing a scalar's name", want.name)
		}
		switch {
		case want.ref == "":
		case fd.Kind() == protoreflect.EnumKind:
			if got := fd.Enum().FullName(); got != want.ref {
				t.Errorf("field %q is enum %q, want %q — a closed vocabulary is what makes it safe", want.name, got, want.ref)
			}
		case fd.Kind() == protoreflect.MessageKind:
			if got := fd.Message().FullName(); got != want.ref {
				t.Errorf("field %q is message %q, want %q", want.name, got, want.ref)
			}
		}
	}
	if fields.Len() != len(evidenceRecordSchema) {
		t.Errorf("EvidenceRecord has %d fields, want exactly %d", fields.Len(), len(evidenceRecordSchema))
	}

	// Closure. Anything the six rows above do not name can carry content, and
	// content on the default tier is the promise CON-004 sells.
	allowed := map[protoreflect.Name]bool{}
	for _, want := range evidenceRecordSchema {
		allowed[want.name] = true
	}
	for i := range fields.Len() {
		fd := fields.Get(i)
		if allowed[fd.Name()] {
			continue
		}
		t.Errorf("EvidenceRecord grew field %q (number %d, kind %s).\n"+
			"E0 evidence is a TIERING PROMISE, not a message that happens to be small: 02 CON-004 states the default wire type is structurally unable to carry a path or an excerpt, and every enterprise security review is answered by pointing at this message's field list.\n"+
			"Free text and excerpts belong in the opt-in E1 class (EvidenceExcerpt: per-tenant opt-in, structurally scrubbed, mandatory redaction_receipt_id, payload travels as a multipart attachment so the default decode path physically cannot receive it — artifacts.proto).\n"+
			"If this field is genuinely needed on the default tier, that is a change to 02 CON-004, reviewed as a requirement change, not a proto edit.",
			fd.Name(), fd.Number(), fd.Kind())
	}

	// A oneof or an extension range reopens the message without adding a
	// visible field — same escape, quieter.
	if n := md.Oneofs().Len(); n != 0 {
		t.Errorf("EvidenceRecord grew %d oneof(s) — a oneof arm is a field the field list does not show", n)
	}
	if n := md.ExtensionRanges().Len(); n != 0 {
		t.Errorf("EvidenceRecord declares %d extension range(s) — extensions let a caller add the excerpt field this test forbids", n)
	}
}

// anchorVocabulary is the attacker's dictionary. artifacts.proto states the
// threat directly: "diagnostics have small effective vocabularies, so a plain
// digest is dictionary-invertible". These are the normalized outputs an
// adversary with the algorithm and no tenant key would enumerate.
var anchorVocabulary = []string{
	"src/a.py:1:1: E501 Line too long (110 > 100)",
	"src/a.py:1:1: F401 'os' imported but unused",
	"src/a.ts(1,1): error TS2345: Argument of type 'string' is not assignable",
	"src/a.rs:1:1: error[E0308]: mismatched types",
	"./a.go:1:1: unreachable code",
	"", // the overwhelmingly common case: a clean run, one dictionary entry
}

// attackerDigest is the digest an enumerating adversary computes: the SAME
// structural normalization outputHMAC applies, hashed with no key. It is
// written out here rather than delegating to outputHMAC with an empty key
// because the attack model is "adversary knows the algorithm, lacks the tenant
// key" — the attacker's half of the test must be constructed independently of
// the code under test.
func attackerDigest(raw string) []byte {
	var norm []string
	for _, l := range strings.Split(raw+"\n", "\n") {
		if t := strings.TrimSpace(l); t != "" {
			norm = append(norm, t)
		}
	}
	sort.Strings(norm)
	h := sha256.New()
	for _, l := range norm {
		h.Write([]byte(l))
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

// TestOutputHMACResistsDictionaryAndCrossTenantJoin is `neg_digests_tenant_salted`
// (12 §9 row 4) for 02 NFR-PRIVACY-002's two acceptance clauses: "same content
// under two tenants yields different digests" and "dictionary attack on fixture
// digests fails". The second is the clause with teeth — the leak the
// requirement forbids is Omium being ABLE to learn that org A and org B hit the
// same failure in the same code.
func TestOutputHMACResistsDictionaryAndCrossTenantJoin(t *testing.T) {
	if len(anchorVocabulary) < 4 {
		t.Fatalf("dictionary has %d entries — too few for the attack it models", len(anchorVocabulary))
	}
	keyA, err := DeriveOutputHMACKey(bytes.Repeat([]byte{0xA1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := DeriveOutputHMACKey(bytes.Repeat([]byte{0xB2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keyA, keyB) {
		t.Fatal("two tenant roots derived the SAME key — every assertion below would be vacuous")
	}

	// Positive control on the attacker's side: the dictionary is non-empty and
	// its unkeyed digests are all distinct, so "no HMAC equals one of them" is
	// a statement about the keying rather than about a collapsed fixture set.
	unkeyed := map[string]string{} // digest hex -> the entry it inverts to
	for _, v := range anchorVocabulary {
		h := hex.EncodeToString(attackerDigest(v))
		if prev, dup := unkeyed[h]; dup {
			t.Fatalf("dictionary entries %q and %q share an unkeyed digest — the fixture set, not the keying, would carry the test", prev, v)
		}
		unkeyed[h] = v
	}

	seen := map[string]string{}
	for _, v := range anchorVocabulary {
		res := RunResult{Stdout: []byte(v)}
		a, b := outputHMAC(keyA, res), outputHMAC(keyB, res)
		if len(a) != sha256.Size {
			t.Fatalf("output_hmac is %d bytes, want %d (artifacts.proto: 32 bytes)", len(a), sha256.Size)
		}
		// Determinism first: without it the inequalities below are satisfied by
		// any random value, and dedupe joins break on the ingest side.
		if !bytes.Equal(a, outputHMAC(keyA, RunResult{Stdout: []byte(v)})) {
			t.Errorf("output_hmac is not deterministic for %q — cross-run dedupe cannot join", v)
		}
		if bytes.Equal(a, b) {
			t.Errorf("identical output %q digests identically under two tenant roots — that value IS a global join key, which is exactly what NFR-PRIVACY-002 forbids", v)
		}
		for who, d := range map[string][]byte{"tenant A": a, "tenant B": b} {
			if entry, inverted := unkeyed[hex.EncodeToString(d)]; inverted {
				t.Errorf("%s output_hmac equals the UNKEYED digest of %q — enumerating the diagnostic vocabulary inverts it", who, entry)
			}
		}
		// Distinct content must stay distinguishable within one tenant, else a
		// constant would satisfy every assertion above.
		if prev, dup := seen[hex.EncodeToString(a)]; dup {
			t.Errorf("distinct outputs %q and %q collide under one tenant", prev, v)
		}
		seen[hex.EncodeToString(a)] = v
	}
}

// TestDeriveOutputHMACKeyLabelFrozen pins the HKDF label "m1p.anchor.output"
// with a golden vector. The label is wire contract, not an implementation
// detail: changing it silently re-keys every tenant, so every output_hmac
// already ingested stops joining with everything emitted afterwards, with no
// error anywhere. A label change is a wire break needing an m1p schema window
// (12 §10.1, `conf_m1p_schema_windows`), not a refactor — if this vector moves,
// the vector is not what needs updating.
func TestDeriveOutputHMACKeyLabelFrozen(t *testing.T) {
	key, err := DeriveOutputHMACKey(bytes.Repeat([]byte{0x07}, 32))
	if err != nil {
		t.Fatal(err)
	}
	const want = "f48c46d95859b0c343d4ffbe01fc3c40a2ffdb7a45c91f26f655ec52fac0bb02"
	if got := hex.EncodeToString(key); got != want {
		t.Errorf("HKDF-SHA256(root = 32 x 0x07, salt = nil, info = \"m1p.anchor.output\", 32) = %s, want %s", got, want)
	}
}
