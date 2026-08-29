// Conformance + round-trip suite for the Go M1PL/1 codec. Test names matching
// `ConfVectors` are load-bearing: conformance_crosslang.sh selects Go tests by
// that filter and treats a filter matching nothing as a FAILED run (12 §3.4).
package fabric

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Path-relative to the package dir so the test runs from any checkout; the
// vectors are the frozen cross-language contract (12 §3.4).
const vectorsDir = "../../../../conformance/vectors/m1pl"

type expectation struct {
	Outcome    string        `json:"outcome"`
	PayloadLen uint64        `json:"payload_len"`
	Consumed   int           `json:"consumed"`
	RejectCode string        `json:"reject_code"`
	Sequence   []expectation `json:"sequence"`
}

func loadManifest(t *testing.T) map[string]expectation {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "manifest.json"))
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	var m map[string]expectation
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	return m
}

// Apply the decoder repeatedly against one vector, matching each manifest
// outcome in order (README §Decoder model).
func runExpectations(t *testing.T, vector string, data []byte, expected []expectation) {
	t.Helper()
	var dec Decoder
	dec.Push(data)
	totalConsumed := 0
	last := len(expected) - 1
	for i, exp := range expected {
		payload, consumed, err := dec.Next()
		switch {
		case err != nil:
			if exp.Outcome != "reject" {
				t.Fatalf("%s[%d]: want %s, got reject %v", vector, i, exp.Outcome, err)
			}
			var rej *RejectError
			if !errors.As(err, &rej) {
				t.Fatalf("%s[%d]: reject is not a *RejectError: %v", vector, i, err)
			}
			if rej.Code != exp.RejectCode {
				t.Fatalf("%s[%d]: reject code %s, want %s", vector, i, rej.Code, exp.RejectCode)
			}
			// Reject means close the connection — the manifest never
			// expects an outcome after one.
			if i != last {
				t.Fatalf("%s: reject must be the final outcome", vector)
			}
		case payload == nil:
			if exp.Outcome != "incomplete" {
				t.Fatalf("%s[%d]: want %s, got incomplete", vector, i, exp.Outcome)
			}
			if i != last {
				t.Fatalf("%s: incomplete must be the final outcome", vector)
			}
		default:
			if exp.Outcome != "accept" {
				t.Fatalf("%s[%d]: want %s, got accept", vector, i, exp.Outcome)
			}
			if uint64(len(payload)) != exp.PayloadLen {
				t.Fatalf("%s[%d]: payload_len %d, want %d", vector, i, len(payload), exp.PayloadLen)
			}
			if consumed != exp.Consumed {
				t.Fatalf("%s[%d]: consumed %d, want %d", vector, i, consumed, exp.Consumed)
			}
			totalConsumed += consumed
		}
	}
	// All-accept vectors must consume the whole file: leftover bytes would
	// mean the manifest and the decoder disagree on frame extents.
	allAccept := true
	for _, exp := range expected {
		allAccept = allAccept && exp.Outcome == "accept"
	}
	if allAccept && totalConsumed != len(data) {
		t.Fatalf("%s: consumed %d of %d bytes", vector, totalConsumed, len(data))
	}
}

func TestConfVectorsM1pl(t *testing.T) {
	manifest := loadManifest(t)
	// A run that executes zero vectors is a failed run, not an empty pass
	// (12 §3.4; conformance_crosslang.sh enforces the same at the CI layer).
	if len(manifest) == 0 {
		t.Fatal("empty m1pl manifest")
	}
	for file, exp := range manifest {
		data, err := os.ReadFile(filepath.Join(vectorsDir, file))
		if err != nil {
			t.Fatalf("%s: vector missing: %v", file, err)
		}
		seq := exp.Sequence
		if seq == nil {
			seq = []expectation{exp}
		}
		runExpectations(t, file, data, seq)
	}
}

// README §Split iteration — the "header split across two socket reads" bug
// class that single-shot vectors cannot see. Required of both languages.
func TestConfVectorsM1plSplitIteration(t *testing.T) {
	min, err := os.ReadFile(filepath.Join(vectorsDir, "accept_min.bin"))
	if err != nil || len(min) != 10 {
		t.Fatalf("accept_min.bin: len %d, err %v", len(min), err)
	}
	for k := 1; k <= 9; k++ {
		var dec Decoder
		dec.Push(min[:k])
		if p, _, err := dec.Next(); p != nil || err != nil {
			t.Fatalf("accept_min split at %d: prefix must be incomplete (p=%v err=%v)", k, p, err)
		}
		dec.Push(min[k:])
		p, consumed, err := dec.Next()
		if err != nil || len(p) != 1 || consumed != 10 {
			t.Fatalf("accept_min split at %d: payload %d consumed %d err %v", k, len(p), consumed, err)
		}
	}

	two, err := os.ReadFile(filepath.Join(vectorsDir, "accept_two_frames.bin"))
	if err != nil || len(two) != 22 {
		t.Fatalf("accept_two_frames.bin: len %d, err %v", len(two), err)
	}
	for k := 1; k <= 21; k++ {
		var dec Decoder
		var accepts [][2]int
		for _, chunk := range [][]byte{two[:k], two[k:]} {
			dec.Push(chunk)
			for {
				p, consumed, err := dec.Next()
				if err != nil {
					t.Fatalf("two_frames split at %d: reject %v", k, err)
				}
				if p == nil {
					break
				}
				accepts = append(accepts, [2]int{len(p), consumed})
			}
		}
		// Cumulative sequence must be identical at every split point — no
		// split may produce a reject or a third outcome.
		want := [][2]int{{1, 10}, {3, 12}}
		if len(accepts) != 2 || accepts[0] != want[0] || accepts[1] != want[1] {
			t.Fatalf("two_frames split at %d: %v", k, accepts)
		}
	}
}

// Encode → decode round-trip plus the encoder's half of the bound: an
// unframeable payload fails at the writer, not as a peer's connection close.
func TestWriteFrameRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xA5}, 1234)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatal(err)
	}
	var dec Decoder
	dec.Push(buf.Bytes())
	got, consumed, err := dec.Next()
	if err != nil || !bytes.Equal(got, payload) || consumed != headerLen+len(payload) {
		t.Fatalf("round-trip: consumed %d err %v", consumed, err)
	}

	var rej *RejectError
	if err := WriteFrame(&buf, nil); !errors.As(err, &rej) || rej.Code != CodeProtocol {
		t.Fatalf("zero-length payload must refuse with M1E-4002, got %v", err)
	}
	if err := WriteFrame(&buf, make([]byte, MaxFrame+1)); !errors.As(err, &rej) || rej.Code != CodeProtocol {
		t.Fatalf("oversized payload must refuse with M1E-4002, got %v", err)
	}
}

// FuzzM1plFrameRead: the conformance vectors double as the seed corpus
// (13 §11 row C3; README — non-.bin files are deliberately fine as garbage
// seeds). The differential invariant is chunking-independence: single-shot and
// byte-at-a-time feeds must produce the identical outcome sequence.
func FuzzM1plFrameRead(f *testing.F) {
	entries, err := os.ReadDir(vectorsDir)
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(vectorsDir, e.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		type outcome struct {
			payloadLen, consumed int
			code                 string
		}
		drain := func(dec *Decoder) ([]outcome, bool) {
			var out []outcome
			for {
				p, consumed, err := dec.Next()
				if err != nil {
					var rej *RejectError
					if !errors.As(err, &rej) {
						t.Fatalf("non-RejectError from Next: %v", err)
					}
					return append(out, outcome{code: rej.Code}), true
				}
				if p == nil {
					return out, false
				}
				if len(p) > MaxFrame || consumed != headerLen+len(p) {
					t.Fatalf("accept violates bound/consumed arithmetic: len %d consumed %d", len(p), consumed)
				}
				out = append(out, outcome{payloadLen: len(p), consumed: consumed})
			}
		}

		var whole Decoder
		whole.Push(data)
		wantSeq, wantRej := drain(&whole)

		var incr Decoder
		var gotSeq []outcome
		gotRej := false
		for i := range data {
			incr.Push(data[i : i+1])
			seq, rej := drain(&incr)
			gotSeq = append(gotSeq, seq...)
			if rej {
				gotRej = true
				break
			}
		}
		if gotRej != wantRej || len(gotSeq) != len(wantSeq) {
			t.Fatalf("chunking changed the outcome sequence: %v vs %v", gotSeq, wantSeq)
		}
		for i := range wantSeq {
			if gotSeq[i] != wantSeq[i] {
				t.Fatalf("chunking changed outcome %d: %v vs %v", i, gotSeq[i], wantSeq[i])
			}
		}
	})
}
