//go:build unix

package evidence_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/evidence"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/receipt"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
)

const (
	tenantID = "11111111-1111-1111-1111-111111111111"
	deviceID = "22222222-2222-2222-2222-222222222222"
)

var (
	plantedAWS = "AKIAIOSFODNN7EXAMPLE"
	plantedGH  = "ghp_" + strings.Repeat("a1B2", 9)
	rawHunk    = "diff --git a/cfg.py b/cfg.py\n+AWS_KEY = \"" + plantedAWS + "\"\n+GH = \"" + plantedGH + "\"\n"
	subject    = uuid.MustParse("0191c5a0-0000-7000-8000-000000000001")
	tokenRe    = regexp.MustCompile(`⟨redacted:([a-z_]+):([0-9a-f]{16})⟩`)
)

type fixture struct {
	state string
	store *evidence.Store
	sc    *redact.Scanner
	id    evidence.Identity
	pub   ed25519.PublicKey
}

func setup(t *testing.T) fixture {
	t.Helper()
	state := t.TempDir()
	store, err := evidence.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := redact.NewScanner([]byte("tenant-hmac-key"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewDeviceKey(identity.FileCustody{Path: filepath.Join(state, "device.key")})
	if err != nil {
		t.Fatal(err)
	}
	pub := key.(interface{ Public() ed25519.PublicKey }).Public()
	return fixture{state: state, store: store, sc: sc, pub: pub,
		id: evidence.Identity{Key: key, TenantID: tenantID, DeviceID: deviceID}}
}

func (f fixture) prepare(t *testing.T, raw string) *m1pv1.EvidenceExcerpt {
	t.Helper()
	x, err := f.store.PrepareE1(f.sc, f.id, subject, []byte(raw), time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func (f fixture) receipt(t *testing.T, x *m1pv1.EvidenceExcerpt) (receipt.RedactionFile, map[string]any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(receipt.RedactionDir(f.state), hex.EncodeToString(x.GetRedactionReceiptId())+".json"))
	if err != nil {
		t.Fatalf("receipt file: %v", err)
	}
	var rf receipt.RedactionFile
	if err := json.Unmarshal(b, &rf); err != nil {
		t.Fatal(err)
	}
	decoded, err := identity.DecodePayload([]byte(rf.Payload))
	if err != nil {
		t.Fatal(err)
	}
	return rf, decoded.(map[string]any)
}

// grepState walks every file under the state dir and returns the paths holding needle.
func grepState(t *testing.T, state string, needle string) []string {
	t.Helper()
	var hits []string
	err := filepath.WalkDir(state, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(needle)) {
			hits = append(hits, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

type recorder struct{ evs []*m1pv1.Event }

func (r *recorder) Admit(_ context.Context, ev *m1pv1.Event) error {
	r.evs = append(r.evs, ev)
	return nil
}

type noSandbox struct{}

func (noSandbox) Run(context.Context, anchors.RunSpec) (anchors.RunResult, error) {
	return anchors.RunResult{}, errors.New("unused")
}
func (noSandbox) FSConfined() bool              { return false }
func (noSandbox) Status() anchors.SandboxStatus { return anchors.SandboxStatus{Available: true} }

func TestPrepareE1RedactsSignsAndPassesTheEmitDoor(t *testing.T) {
	f := setup(t)
	x := f.prepare(t, rawHunk)
	if x.GetTier() != m1pv1.EvidenceTier_EVIDENCE_TIER_E1 || !bytes.Equal(x.GetEvidenceEventId(), subject[:]) {
		t.Fatalf("excerpt %v", x)
	}
	if x.GetAttachmentName() != "attach."+subject.String()+".e1" {
		t.Fatalf("attachment_name %q is not 08 §2.1's attach.<event_id>.<name>", x.GetAttachmentName())
	}
	if len(x.GetRedactionReceiptId()) != 32 {
		t.Fatalf("receipt id is %d bytes, want the 32-byte receipt hash", len(x.GetRedactionReceiptId()))
	}

	part, err := os.ReadFile(filepath.Join(evidence.E1Dir(f.state), x.GetAttachmentName()))
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(evidence.E1Dir(f.state), x.GetAttachmentName())); st.Mode().Perm() != 0o600 {
		t.Fatalf("part mode %o, want 0600", st.Mode().Perm())
	}
	toks := tokenRe.FindAllStringSubmatch(string(part), -1)
	if len(toks) != 2 || toks[0][1] != "api_key" || toks[1][1] != "api_key" {
		t.Fatalf("sanitized part carries %d tokens: %q", len(toks), part)
	}

	rf, payload := f.receipt(t, x)
	signingInput := append([]byte(identity.DomainPrefix), rf.Payload...)
	sig, _ := hex.DecodeString(rf.DeviceSignature)
	if !identity.Verify(f.pub, sig, signingInput) {
		t.Fatal("receipt signature does not verify under the device key")
	}
	if sum := sha256.Sum256(signingInput); !bytes.Equal(sum[:], x.GetRedactionReceiptId()) || rf.ReceiptHash != hex.EncodeToString(sum[:]) {
		t.Fatal("redaction_receipt_id is not sha256(domain prefix || payload)")
	}
	if canon, err := identity.CanonicalJSON(payload); err != nil || canon != rf.Payload {
		t.Fatalf("stored payload is not its own canonical form: %v", err)
	}
	want := map[string]string{
		"type": receipt.RedactionType, "tenant_id": tenantID, "device_id": deviceID,
		"device_key_id": f.id.Key.KeyID(), "subject_id": subject.String(),
		"issued_at": "2026-09-16T12:00:00Z", "tier": "E1",
		"pre_hash": hex.EncodeToString(sha256sum(rawHunk)), "post_hash": hex.EncodeToString(sha256sum(string(part))),
	}
	for k, v := range want {
		if got, _ := payload[k].(string); got != v {
			t.Errorf("payload[%s] = %q, want %q", k, got, v)
		}
	}
	if classes, _ := payload["classes"].(map[string]any); len(classes) != 1 || classes["api_key"] != json.Number("2") {
		t.Errorf("classes = %v, want {api_key: 2}", payload["classes"])
	}
	digests, _ := payload["span_digests"].([]any)
	if len(digests) != 2 {
		t.Fatalf("span_digests = %v", digests)
	}
	for _, tok := range toks {
		if digests[0] != tok[2] && digests[1] != tok[2] {
			t.Errorf("token digest %s is not in the receipt's span_digests %v", tok[2], digests)
		}
	}

	rec := &recorder{}
	r := anchors.NewRunner(noSandbox{}, rec, nil, false)
	r.StateDir = f.state
	if err := consents.Write(f.state, consents.Consents{E1: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.EmitExcerpt(context.Background(), [16]byte{9}, [16]byte{8}, x); err != nil {
		t.Fatalf("the emit door refused a receipted, consented E1 excerpt: %v", err)
	}
	if len(rec.evs) != 1 || !bytes.Equal(rec.evs[0].GetEvidenceExcerpt().GetRedactionReceiptId(), x.GetRedactionReceiptId()) {
		t.Fatalf("emitted %v", rec.evs)
	}
	x.RedactionReceiptId = nil
	if err := r.EmitExcerpt(context.Background(), [16]byte{9}, [16]byte{8}, x); !errors.Is(err, anchors.ErrRefused) {
		t.Fatalf("the door admitted an E1 excerpt without its receipt: %v", err)
	}
}

func sha256sum(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func TestPrepareE1PersistsNoPreRedactionPlaintext(t *testing.T) {
	f := setup(t)
	x := f.prepare(t, rawHunk)
	for _, secret := range []string{plantedAWS, plantedGH} {
		if hits := grepState(t, f.state, secret); len(hits) != 0 {
			t.Fatalf("planted secret %q persisted at %v", secret, hits)
		}
	}
	if hits := grepState(t, f.state, "⟨redacted:api_key:"); len(hits) != 1 || filepath.Base(hits[0]) != x.GetAttachmentName() {
		t.Fatalf("the sanitized part is not the one file carrying tokens: %v", hits)
	}
}

func TestPrepareE1CleanHunkSignsAnEmptyCut(t *testing.T) {
	f := setup(t)
	clean := "diff --git a/a.py b/a.py\n+print('hello')\n"
	x := f.prepare(t, clean)
	_, payload := f.receipt(t, x)
	if payload["pre_hash"] != payload["post_hash"] {
		t.Fatal("a clean hunk must hash the same before and after")
	}
	if classes, _ := payload["classes"].(map[string]any); len(classes) != 0 {
		t.Fatalf("classes = %v, want none", classes)
	}
	if digests, _ := payload["span_digests"].([]any); len(digests) != 0 {
		t.Fatalf("span_digests = %v, want none", digests)
	}
	part, _ := os.ReadFile(filepath.Join(evidence.E1Dir(f.state), x.GetAttachmentName()))
	if string(part) != clean {
		t.Fatalf("clean bytes changed: %q", part)
	}
}

func TestPrepareE1RefusalsWriteNothing(t *testing.T) {
	f := setup(t)
	now := time.Now()
	var nilScanner *redact.Scanner
	if _, err := f.store.PrepareE1(nilScanner, f.id, subject, []byte(rawHunk), now); !errors.Is(err, evidence.ErrQuarantined) {
		t.Fatalf("scanner failure: err = %v, want ErrQuarantined", err)
	}
	if _, err := f.store.PrepareE1(f.sc, f.id, [16]byte{}, []byte(rawHunk), now); err == nil {
		t.Fatal("a nil subject was accepted")
	}
	if _, err := f.store.PrepareE1(f.sc, f.id, subject, nil, now); err == nil {
		t.Fatal("an empty hunk was accepted")
	}
	if _, err := f.store.PrepareE1(f.sc, evidence.Identity{Key: f.id.Key}, subject, []byte(rawHunk), now); err == nil {
		t.Fatal("a receipt without tenant/device ids was signed")
	}
	var nilStore *evidence.Store
	if _, err := nilStore.PrepareE1(f.sc, f.id, subject, []byte(rawHunk), now); err == nil {
		t.Fatal("a nil store produced an excerpt it could not receipt")
	}
	for _, dir := range []string{evidence.E1Dir(f.state), receipt.RedactionDir(f.state)} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("%s exists after refusals only", dir)
		}
	}
	if hits := grepState(t, f.state, plantedAWS); len(hits) != 0 {
		t.Fatalf("refused input persisted at %v", hits)
	}
}
