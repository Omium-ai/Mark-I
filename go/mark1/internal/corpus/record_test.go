package corpus

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDeriveExpectationsReproducesThePinnedOracle: the recorder's derivation is
// selfcheck.py's rules, proven by re-deriving v2.1.251's committed
// expectations.json from its committed transcripts.
func TestDeriveExpectationsReproducesThePinnedOracle(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "conformance", "hooks", "claudecode", "v2.1.251")
	want, err := os.ReadFile(filepath.Join(root, "transcripts", "expectations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pinned struct {
		Streams        []json.RawMessage `json:"streams"`
		OutOfWorkspace []struct {
			File      string `json:"file"`
			NeverEmit string `json:"never_emit_message_id"`
		} `json:"out_of_workspace_streams"`
		Overcount map[string]any `json:"overcount_case"`
	}
	if err := json.Unmarshal(want, &pinned); err != nil {
		t.Fatal(err)
	}
	load := func(rel, role string) stream {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		return stream{rel: rel, role: role, lines: bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))}
	}
	var streams []stream
	for _, s := range pinned.Streams {
		var h struct{ File, Role string }
		_ = json.Unmarshal(s, &h)
		streams = append(streams, load(h.File, h.Role))
	}
	streams = append(streams, load(pinned.OutOfWorkspace[0].File, "foreign"))

	got, err := deriveExpectations("2.1.251", streams)
	if err != nil {
		t.Fatal(err)
	}
	gb, _ := json.Marshal(got)
	var derived struct {
		Streams        []json.RawMessage `json:"streams"`
		OutOfWorkspace []struct {
			NeverEmit string `json:"never_emit_message_id"`
		} `json:"out_of_workspace_streams"`
		Overcount map[string]any `json:"overcount_case"`
	}
	_ = json.Unmarshal(gb, &derived)
	for i := range pinned.Streams {
		var p, d struct {
			UsageEvents []usageEvent `json:"usage_events"`
			NeverEmit   []neverEmit  `json:"never_emit"`
		}
		_ = json.Unmarshal(pinned.Streams[i], &p)
		_ = json.Unmarshal(derived.Streams[i], &d)
		pj, _ := json.Marshal(p.UsageEvents)
		dj, _ := json.Marshal(d.UsageEvents)
		if !bytes.Equal(pj, dj) {
			t.Fatalf("stream %d usage_events diverge from the pinned oracle:\n pinned  %s\n derived %s", i, pj, dj)
		}
		if len(p.NeverEmit) != len(d.NeverEmit) || (len(p.NeverEmit) > 0 && p.NeverEmit[0].MessageID != d.NeverEmit[0].MessageID) {
			t.Fatalf("stream %d never_emit: pinned %v derived %v", i, p.NeverEmit, d.NeverEmit)
		}
	}
	if derived.OutOfWorkspace[0].NeverEmit != pinned.OutOfWorkspace[0].NeverEmit {
		t.Fatalf("foreign never_emit_message_id %q, want %q", derived.OutOfWorkspace[0].NeverEmit, pinned.OutOfWorkspace[0].NeverEmit)
	}
	for _, k := range []string{"message_id", "request_id", "streamed_lines", "naive_per_line_output_token_sum", "correct_output_tokens"} {
		p, _ := json.Marshal(pinned.Overcount[k])
		d, _ := json.Marshal(derived.Overcount[k])
		if !bytes.Equal(p, d) {
			t.Fatalf("overcount_case.%s: pinned %s derived %s", k, p, d)
		}
	}
}

func TestSanitizerLeavesNumbersAlone(t *testing.T) {
	san := sanitizer(nil)
	in := `{"totalCostUSD":0.02843960000000001,"agentId":"agent-a7f3e2d1c0b9a8001","uuid":"3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55"}`
	out := string(san([]byte(in)))
	if !strings.Contains(out, `"totalCostUSD":0.02843960000000001`) {
		t.Fatalf("a 17-digit decimal fraction was rewritten as a hex id: %s", out)
	}
	if strings.Contains(out, "a7f3e2d1c0b9a8001") || strings.Contains(out, "3f9c2e71") {
		t.Fatalf("ids kept their recording-machine values: %s", out)
	}
}
