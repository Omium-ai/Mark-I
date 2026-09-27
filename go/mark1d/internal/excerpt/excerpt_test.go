package excerpt_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/evidence"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/excerpt"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/receipt"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
)

var (
	planted  = "AKIAIOSFODNN7EXAMPLE"
	plantedI = "ghp_" + strings.Repeat("a1B2", 9)
	session  = uuid.MustParse("0191c5a0-0000-7000-8000-00000000000a")
	task     = uuid.MustParse("0191c5a0-0000-7000-8000-00000000000b")
)

type upload struct {
	name    string
	receipt receipt.RedactionFile
	part    []byte
	auth    string
}

type server struct {
	mu      sync.Mutex
	status  int
	uploads []upload
	srv     *httptest.Server
}

func newServer(t *testing.T) *server {
	s := &server{status: http.StatusOK}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mr, err := r.MultipartReader()
		if err != nil {
			t.Errorf("not multipart: %v", err)
			return
		}
		var u upload
		u.auth = r.Header.Get("Authorization")
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			b, _ := io.ReadAll(p)
			if p.FormName() == "receipt" {
				if err := json.Unmarshal(b, &u.receipt); err != nil {
					t.Errorf("receipt part: %v", err)
				}
				continue
			}
			u.name, u.part = p.FormName(), b
		}
		s.mu.Lock()
		s.uploads = append(s.uploads, u)
		code := s.status
		s.mu.Unlock()
		w.WriteHeader(code)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *server) got() []upload {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]upload(nil), s.uploads...)
}

type rig struct {
	state   string
	u       *excerpt.Uploader
	srv     *server
	pub     ed25519.PublicKey
	emits   []*m1pv1.EvidenceExcerpt
	diff    []byte
	intent  string
	restart func()
}

func setup(t *testing.T) *rig {
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
	r := &rig{state: state, srv: newServer(t), pub: key.(interface{ Public() ed25519.PublicKey }).Public(),
		diff: []byte("diff --git a/cfg.py b/cfg.py\n--- a/cfg.py\n+++ b/cfg.py\n@@ -1 +1 @@\n-x = 1\n+AWS_KEY = \"" + planted + "\"\n"), intent: "fix the config, token " + plantedI}
	r.restart = func() {
		r.u = r.start(t, store, sc, key)
	}
	r.restart()
	return r
}

// start is one daemon lifetime's uploader over the rig's state dir.
func (r *rig) start(t *testing.T, store *evidence.Store, sc *redact.Scanner, key identity.DeviceKey) *excerpt.Uploader {
	t.Helper()
	u, err := excerpt.New(excerpt.Config{
		StateDir: r.state, Store: store, Scanner: sc, AttachURL: r.srv.srv.URL + "/api/v1/attach", Token: func(context.Context) (string, error) { return "dev-token", nil }, Version: "0.0.0",
		Intent: func([16]byte) string { return r.intent },
		Diff:   func(context.Context, [16]byte, [16]byte) []byte { return r.diff },
		Emit: func(_ context.Context, s, tk [16]byte, x *m1pv1.EvidenceExcerpt) error {
			if s != session || tk != task {
				t.Errorf("emit for %x/%x", s, tk)
			}
			r.emits = append(r.emits, x)
			return nil
		},
		Now: func() time.Time { return time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	u.SetIdentity(evidence.Identity{Key: key, TenantID: "11111111-1111-1111-1111-111111111111", DeviceID: "22222222-2222-2222-2222-222222222222"})
	return u
}

// consent writes the Step-4 record and marks it acknowledged by controld, as a relayed record is.
func (r *rig) consent(t *testing.T, e1 bool) {
	t.Helper()
	if err := consents.Write(r.state, consents.Consents{E1: e1}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(consents.Path(r.state))
	if err := os.WriteFile(consents.Path(r.state)+".relayed", b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) grep(t *testing.T, needle string) []string {
	t.Helper()
	var hits []string
	_ = filepath.WalkDir(r.state, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(needle)) {
				hits = append(hits, p)
			}
		}
		return nil
	})
	return hits
}

func (r *rig) pendingParts(t *testing.T) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(evidence.E1Dir(r.state), "*"))
	return m
}

func TestNoConsentNoUploadNoFile(t *testing.T) {
	r := setup(t)
	r.u.OnTaskClose(session, task, m1pv1.Resolution_RESOLUTION_VERDICT)
	r.u.Process(context.Background(), session, task)
	if len(r.srv.got()) != 0 || len(r.pendingParts(t)) != 0 || len(r.emits) != 0 {
		t.Fatalf("without the e1 consent: uploads %d, parts %v, emits %d", len(r.srv.got()), r.pendingParts(t), len(r.emits))
	}
}

func TestRedactedBeforeSpoolAndUploadAndReceipted(t *testing.T) {
	r := setup(t)
	r.consent(t, true)
	r.u.Process(context.Background(), session, task)
	ups := r.srv.got()
	if len(ups) != 1 {
		t.Fatalf("uploads = %d, want 1", len(ups))
	}
	up := ups[0]
	if up.name != "attach."+task.String()+".e1" || up.auth != "Bearer dev-token" {
		t.Fatalf("part %q under %q", up.name, up.auth)
	}
	for _, secret := range []string{planted, plantedI} {
		if bytes.Contains(up.part, []byte(secret)) {
			t.Fatalf("secret %q left the machine", secret)
		}
		if hits := r.grep(t, secret); len(hits) != 0 {
			t.Fatalf("secret %q persisted at %v", secret, hits)
		}
	}
	intent, hunks, ok := bytes.Cut(up.part, []byte{0})
	if !ok || !bytes.HasPrefix(intent, []byte("fix the config")) || !bytes.Contains(hunks, []byte("diff --git a/cfg.py")) {
		t.Fatalf("part is not intent NUL hunks: %q", up.part)
	}
	sig, _ := hex.DecodeString(up.receipt.DeviceSignature)
	if !identity.Verify(r.pub, sig, append([]byte(identity.DomainPrefix), up.receipt.Payload...)) {
		t.Fatal("the uploaded receipt does not verify under the device key")
	}
	var payload struct {
		Subject  string `json:"subject_id"`
		PostHash string `json:"post_hash"`
	}
	if err := json.Unmarshal([]byte(up.receipt.Payload), &payload); err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(up.part); payload.Subject != task.String() || payload.PostHash != hex.EncodeToString(sum[:]) {
		t.Fatalf("receipt subject %s post %s does not attest this part", payload.Subject, payload.PostHash)
	}
	if len(r.emits) != 1 || r.emits[0].GetTier() != m1pv1.EvidenceTier_EVIDENCE_TIER_E1 || r.emits[0].GetAttachmentName() != up.name ||
		!bytes.Equal(r.emits[0].GetEvidenceEventId(), task[:]) || hex.EncodeToString(r.emits[0].GetRedactionReceiptId()) != up.receipt.ReceiptHash {
		t.Fatalf("emitted %v", r.emits)
	}
	if parts := r.pendingParts(t); len(parts) != 0 {
		t.Fatalf("landed part still on disk: %v", parts)
	}
	r.u.Process(context.Background(), session, task)
	if len(r.srv.got()) != 1 {
		t.Fatal("a second close of the same task uploaded again")
	}
}

func TestSizeBoundsCutWholeHunks(t *testing.T) {
	r := setup(t)
	r.consent(t, true)
	r.intent = strings.Repeat("é", 2000)
	var d strings.Builder
	for i := range 400 {
		d.WriteString("diff --git a/f" + string(rune('a'+i%26)) + ".go b/f.go\n--- a/f.go\n+++ b/f.go\n@@ -1 +1 @@\n-" + strings.Repeat("x", 200) + "\n+" + strings.Repeat("y", 200) + "\n")
	}
	r.diff = []byte(d.String())
	r.u.Process(context.Background(), session, task)
	ups := r.srv.got()
	if len(ups) != 1 {
		t.Fatalf("uploads = %d", len(ups))
	}
	intent, hunks, _ := bytes.Cut(ups[0].part, []byte{0})
	if len(ups[0].part) > excerpt.MaxPart || len(intent) > excerpt.MaxIntent || !strings.HasPrefix(string(intent), "é") || !bytes.Equal(bytes.ToValidUTF8(intent, nil), intent) {
		t.Fatalf("part %d bytes (max %d), intent %d bytes (max %d)", len(ups[0].part), excerpt.MaxPart, len(intent), excerpt.MaxIntent)
	}
	n := bytes.Count(hunks, []byte("@@ -1 +1 @@\n"))
	if n == 0 || n >= 400 || bytes.Count(hunks, []byte("\n+"+strings.Repeat("y", 200)+"\n")) != n || bytes.Count(hunks, []byte("\n-"+strings.Repeat("x", 200)+"\n")) != n {
		t.Fatalf("hunks were not cut at whole-hunk boundaries: %d hunk headers", n)
	}
}

func TestTransientFailureRetriesAndWithdrawalPurges(t *testing.T) {
	r := setup(t)
	r.consent(t, true)
	r.srv.status = http.StatusServiceUnavailable
	r.u.Process(context.Background(), session, task)
	if len(r.pendingParts(t)) != 2 || len(r.emits) != 0 {
		t.Fatalf("a 503 must keep the part and its sidecar: %v", r.pendingParts(t))
	}
	r.srv.status = http.StatusOK
	r.u.Retry(context.Background())
	if len(r.srv.got()) != 2 || len(r.emits) != 1 || len(r.pendingParts(t)) != 0 {
		t.Fatalf("retry: uploads %d emits %d parts %v", len(r.srv.got()), len(r.emits), r.pendingParts(t))
	}

	other := uuid.MustParse("0191c5a0-0000-7000-8000-00000000000c")
	r.srv.status = http.StatusServiceUnavailable
	r.u.Process(context.Background(), session, other)
	r.consent(t, false)
	r.srv.status = http.StatusOK
	r.u.Retry(context.Background())
	if len(r.srv.got()) != 3 || len(r.pendingParts(t)) != 0 {
		t.Fatalf("withdrawal must purge the pending part and upload nothing: uploads %d parts %v", len(r.srv.got()), r.pendingParts(t))
	}
}

func TestServerQuarantineSettlesWithoutAnExcerpt(t *testing.T) {
	r := setup(t)
	r.consent(t, true)
	r.srv.status = http.StatusAccepted
	r.u.Process(context.Background(), session, task)
	if len(r.srv.got()) != 1 || len(r.emits) != 0 || len(r.pendingParts(t)) != 0 {
		t.Fatalf("202 quarantined: uploads %d emits %d parts %v", len(r.srv.got()), len(r.emits), r.pendingParts(t))
	}
}

func TestUnacknowledgedConsentWaits(t *testing.T) {
	r := setup(t)
	if err := consents.Write(r.state, consents.Consents{E1: true}); err != nil {
		t.Fatal(err)
	}
	r.u.Process(context.Background(), session, task)
	if len(r.srv.got()) != 0 || len(r.pendingParts(t)) != 2 {
		t.Fatalf("a consent controld has not seen must wait (its refusal would drop the part): uploads %d parts %v", len(r.srv.got()), r.pendingParts(t))
	}
}

// A re-close after a daemon restart must not re-prepare: controld answers 409 for a task that already has its part, and the part would be dropped.
func TestSettledSetSurvivesRestartAndWithdrawal(t *testing.T) {
	r := setup(t)
	r.consent(t, true)
	r.u.Process(context.Background(), session, task)
	if len(r.srv.got()) != 1 {
		t.Fatalf("first close: %d uploads", len(r.srv.got()))
	}
	path := filepath.Join(evidence.Dir(r.state), "e1-settled")
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("settled set: %v %v", fi, err)
	}
	r.restart()
	r.u.Process(context.Background(), session, task)
	r.u.Retry(context.Background())
	if len(r.srv.got()) != 1 || len(r.pendingParts(t)) != 0 {
		t.Fatalf("a restart re-prepared a settled task: uploads %d, parts %v", len(r.srv.got()), r.pendingParts(t))
	}
	r.consent(t, false)
	r.u.Retry(context.Background()) // withdrawal purges parts, never the settled record
	r.consent(t, true)
	r.restart()
	r.u.Process(context.Background(), session, task)
	if len(r.srv.got()) != 1 {
		t.Fatalf("withdrawal forgot the task had its part: %d uploads", len(r.srv.got()))
	}
}

// A task closed while e1 was off is not settled: turning e1 on and re-closing gets it its part.
func TestClosedWithoutConsentIsNotSettled(t *testing.T) {
	r := setup(t)
	r.u.Process(context.Background(), session, task)
	r.consent(t, true)
	r.u.Process(context.Background(), session, task)
	if len(r.srv.got()) != 1 {
		t.Fatalf("uploads %d", len(r.srv.got()))
	}
}

// The file stays bounded: past 4096 tasks it is rewritten to the newest half, oldest first out.
func TestSettledSetIsPruned(t *testing.T) {
	r := setup(t)
	var b strings.Builder
	ids := make([]uuid.UUID, 5000)
	for i := range ids {
		ids[i] = uuid.New()
		b.WriteString(ids[i].String() + "\n")
	}
	path := filepath.Join(evidence.Dir(r.state), "e1-settled")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	r.restart()
	raw, _ := os.ReadFile(path)
	lines := strings.Fields(string(raw))
	if len(lines) != 2048 || lines[len(lines)-1] != ids[4999].String() || strings.Contains(string(raw), ids[0].String()) {
		t.Fatalf("pruned to %d lines", len(lines))
	}
	r.consent(t, true)
	r.u.Process(context.Background(), session, ids[4999])
	if len(r.srv.got()) != 0 {
		t.Fatal("a kept settled task was re-prepared")
	}
}
