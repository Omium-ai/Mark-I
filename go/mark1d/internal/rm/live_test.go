package rm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// exportParity is training_jobs/rm/export.py parity(): the HF↔GGUF vectors an export ships as parity.json.
type exportParity struct {
	TemplateVersion string         `json:"template_version"`
	YesTokenID      int            `json:"yes_token_id"`
	NoTokenID       int            `json:"no_token_id"`
	Tokenization    string         `json:"tokenization"`
	Request         map[string]any `json:"request"`
	Vectors         []struct {
		Task       string  `json:"task"`
		Diff       string  `json:"diff"`
		Prefix     string  `json:"prefix"`
		Rendered   string  `json:"rendered"`
		InputIDs   []int   `json:"input_ids"`
		TextSHA256 string  `json:"text_sha256"`
		HFScore    float64 `json:"hf_fp32_score"`
		GGUFScore  float64 `json:"gguf_q8_0_score"`
	} `json:"vectors"`
	Quants map[string]struct {
		TokenizerMismatches int `json:"tokenizer_mismatches"`
	} `json:"quants"`
}

func readExportParity(t *testing.T, path string) exportParity {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: a test fixture
	if err != nil {
		t.Fatal(err)
	}
	var ep exportParity
	if err := json.Unmarshal(b, &ep); err != nil {
		t.Fatal(err)
	}
	return ep
}

// The export's own parity vectors (base qwen2.5-coder-1.5b / granite-4.0-1b-base, Q8_0 on b11193) render here byte for byte, under the request serving sends; HF↔GGUF score deltas are export's served gate, not this test's.
func TestExportParityVectorsRenderIdentically(t *testing.T) {
	files, _ := filepath.Glob("testdata/export-parity-*.json")
	if len(files) != 2 {
		t.Fatalf("want the RM-A and RM-B export parity fixtures, got %v", files)
	}
	var want map[string]any
	b, _ := json.Marshal(scoreRequest)
	_ = json.Unmarshal(b, &want)
	want["logit_bias_both"] = logitBias
	for _, f := range files {
		ep := readExportParity(t, f)
		if ep.TemplateVersion != TemplateVersion || ep.Quants["q8_0"].TokenizerMismatches != 0 || !reflect.DeepEqual(ep.Request, want) || len(ep.Vectors) < 5 {
			t.Fatalf("%s: template %s, tokenizer mismatches %d, request %v (want %v), %d vectors", f, ep.TemplateVersion, ep.Quants["q8_0"].TokenizerMismatches, ep.Request, want, len(ep.Vectors))
		}
		full := false
		for i, v := range ep.Vectors {
			r := Render(v.Task, v.Diff, MaxDiffChars)
			sum := sha256.Sum256([]byte(r.Text()))
			if r.Abstain != "" || r.Prefix != v.Prefix || r.Text() != v.Rendered || hex.EncodeToString(sum[:]) != v.TextSHA256 {
				t.Errorf("%s vector %d: the edge renders a different input than training", f, i)
			}
			if len(v.InputIDs) > MaxSeqLen {
				t.Errorf("%s vector %d: %d ids past max_seq_len", f, i, len(v.InputIDs))
			}
			full = full || len(v.InputIDs) == MaxSeqLen
		}
		if !full {
			t.Errorf("%s: no vector reaches max_seq_len, so the token cut is unproven", f)
		}
	}
}

// TestLiveParityOnPinnedRuntime runs the plane's real child when MARK1_RM_LIVE_SERVER (b11193 llama-server), MARK1_RM_LIVE_GGUF and MARK1_RM_LIVE_PARITY (that GGUF's export parity.json) are set; MARK1_RM_LIVE_SLOT picks a|b.
func TestLiveParityOnPinnedRuntime(t *testing.T) {
	bin, gguf, parity := os.Getenv("MARK1_RM_LIVE_SERVER"), os.Getenv("MARK1_RM_LIVE_GGUF"), os.Getenv("MARK1_RM_LIVE_PARITY")
	if bin == "" || gguf == "" || parity == "" {
		t.Skip("MARK1_RM_LIVE_SERVER / MARK1_RM_LIVE_GGUF / MARK1_RM_LIVE_PARITY unset")
	}
	ep := readExportParity(t, parity)
	slot := os.Getenv("MARK1_RM_LIVE_SLOT")
	if slot == "" {
		slot = "a"
	}
	m := stubManifest(slot)
	sum, err := sha256File(gguf)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(gguf)
	runtimeID, err := RuntimeID(context.Background(), bin)
	if err != nil || runtimeID != "llama.cpp b11193" {
		t.Fatalf("runtime %q %v: parity is pinned to llama.cpp b11193", runtimeID, err)
	}
	x, err := ExecutionHash(gguf, runtimeID)
	if err != nil {
		t.Fatal(err)
	}
	m.SHA256, m.SizeBytes, m.ExecutionHash = sum, fi.Size(), hex.EncodeToString(x)
	dir := t.TempDir()
	stage(t, gguf, ModelPath(dir, m))
	v0 := ep.Vectors[0]
	admitted := make(chan *m1pv1.Event, 1)
	p := testPlane(t, Config{
		StateDir: dir, Catalog: []Manifest{m}, BaseURL: "http://127.0.0.1:1", Binary: bin, Poll: 100 * time.Millisecond,
		Intent: func(_, _ [16]byte) (string, bool) { return v0.Task, true },
		Diff:   func(context.Context, [16]byte, [16]byte) []byte { return []byte(v0.Diff) },
		Admit:  func(_ context.Context, ev *m1pv1.Event) error { admitted <- ev; return nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); p.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(time.Second) {
		if st, _ := ReadStatus(dir); st.State == "ready" {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("the real child never became ready: %+v", st)
		}
	}
	s := p.slots[0]
	for i, v := range ep.Vectors {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Minute)
		base, key, err := waitHealthy(sctx, s)
		if err != nil {
			scancel()
			t.Fatal(err)
		}
		ids, yes, no, err := inputIDs(sctx, base, key, m, v.Prefix)
		if err != nil || yes != ep.YesTokenID || no != ep.NoTokenID || !reflect.DeepEqual(ids, v.InputIDs) {
			scancel()
			t.Fatalf("vector %d: serving ids differ from training's (%d vs %d ids, yes %d/%d, no %d/%d, err %v)", i, len(ids), len(v.InputIDs), yes, ep.YesTokenID, no, ep.NoTokenID, err)
		}
		t0 := time.Now()
		score, err := logitDiff(sctx, base, key, ids, yes, no)
		scancel()
		if err != nil {
			t.Fatal(err)
		}
		d := math.Log(score / (1 - score))
		t.Logf("vector %d: %d ids, %.1fs, logit %.4f, export gguf %.4f, hf %.4f", i, len(ids), time.Since(t0).Seconds(), d, v.GGUFScore, v.HFScore)
		if math.Abs(d-v.GGUFScore) > 0.05 {
			t.Errorf("vector %d: logit %.4f vs the export's gguf %.4f", i, d, v.GGUFScore)
		}
	}
	task := [16]byte{1}
	p.Observe(&m1pv1.Event{SessionId: task[:], TaskId: task[:], Body: &m1pv1.Event_TaskClose{TaskClose: &m1pv1.TaskClose{Resolution: m1pv1.Resolution_RESOLUTION_VERDICT}}})
	select {
	case ev := <-admitted:
		sc := ev.GetRmScore().GetScore()
		if d := math.Log(sc / (1 - sc)); math.Abs(d-v0.GGUFScore) > 0.05 || ev.GetRmScore().GetModelId() != m.ModelID() {
			t.Fatalf("end to end: %v logit %.4f, export gguf %.4f", ev.GetRmScore(), d, v0.GGUFScore)
		}
	case <-time.After(2 * time.Minute):
		log, _ := os.ReadFile(filepath.Join(dir, "rm", "runtime-"+slot+".log"))
		t.Fatalf("no score from the live runtime; log tail:\n%s", tail(string(log), 4000))
	}
}

// stage puts the operator's GGUF where ensureModel finds it pinned, linked when the filesystem allows.
func stage(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	if os.Link(src, dst) == nil {
		return
	}
	in, err := os.Open(src) //nolint:gosec // G304: operator-named test model
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst) //nolint:gosec // G304: under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

func tail(s string, n int) string { return s[max(0, len(s)-n):] }
