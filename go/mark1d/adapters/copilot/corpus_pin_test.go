package copilot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// recordedCorpusDigest freezes the BYTES of each pinned corpus (FR-AGENT-004:
// fixture drift fails the build). Updating it is an attestation that the
// corpus was re-recorded from the vendor at a new pin, never a way to go green.
var recordedCorpusDigest = map[string]string{
	"1.0.85": "4ec781175242972a3325ca3ea6a443f840195b326678684ae72f415880bae016",
}

var corpusPinExempt = map[string]bool{"README.md": true, "selfcheck.py": true}

func TestPinnedCorpusMatchesRecordedDigest(t *testing.T) {
	root := filepath.Dir(fixtureRoot)
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("fixture tree unreadable at %s: %v", root, err)
	}
	onDisk := map[string]bool{}
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), "v") {
			onDisk[strings.TrimPrefix(e.Name(), "v")] = true
		}
	}
	if len(onDisk) == 0 {
		t.Fatalf("no version directories under %s", root)
	}
	for v := range recordedCorpusDigest {
		if !onDisk[v] {
			t.Errorf("a digest is recorded for %q but conformance/hooks/copilot/v%s does not exist", v, v)
		}
	}
	for v := range onDisk {
		want, ok := recordedCorpusDigest[v]
		if !ok {
			t.Errorf("conformance/hooks/copilot/v%s has no entry in recordedCorpusDigest", v)
			continue
		}
		got, files := digestCorpus(t, filepath.Join(root, "v"+v), v)
		if got != want {
			t.Errorf(`copilot %s corpus has changed.
  recorded %s
  on disk  %s   (%d files)
These bytes are the vendor's schema, the hook bodies and the events.jsonl files
a pinned Copilot CLI wrote on a recording. A replay disagreeing with expectations.json
means the READER is wrong; a vendor change is a NEW conformance/hooks/copilot/v<new>/
plus a SupportedVersions entry, never an edit here.`, v, want, got, files)
		}
	}
}

func digestCorpus(t *testing.T, dir, version string) (string, int) {
	t.Helper()
	type entry struct {
		rel string
		sum [sha256.Size]byte
	}
	var entries []entry
	var hooks, schemas, streams int
	var expectations bool
	err := fs.WalkDir(os.DirFS(dir), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || corpusPinExempt[d.Name()] {
			return err
		}
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		if len(b) == 0 {
			t.Errorf("%s is empty — hashing zero bytes pins nothing", rel)
		}
		switch {
		case rel == "transcripts/expectations.json":
			assertExpectations(t, rel, b, version)
			expectations = true
		case strings.HasPrefix(rel, "hooks/") && strings.HasSuffix(rel, ".json"):
			assertHookBody(t, rel, b)
			hooks++
		case strings.HasPrefix(rel, "schema/"):
			schemas++
		case strings.HasPrefix(rel, "transcripts/session-state/") && strings.HasSuffix(rel, "/events.jsonl"):
			assertStream(t, rel, b)
			streams++
		}
		entries = append(entries, entry{rel, sha256.Sum256(b)})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	if hooks < 7 || schemas < 2 || streams < 3 || !expectations {
		t.Fatalf("%s: %d hook bodies, %d schemas, %d streams, expectations=%v — not the pinned corpus", dir, hooks, schemas, streams, expectations)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	h := sha256.New()
	for _, e := range entries {
		_, _ = fmt.Fprintf(h, "%s\n%x\n", e.rel, e.sum)
	}
	return hex.EncodeToString(h.Sum(nil)), len(entries)
}

// assertStream: line 1 is session.start for the directory's session, carrying its cwd,
// and no line is the ephemeral assistant.usage the vendor never persists.
func assertStream(t *testing.T, rel string, b []byte) {
	t.Helper()
	first, rest, _ := strings.Cut(string(b), "\n")
	var head struct {
		Type string `json:"type"`
		Data struct {
			SessionID string `json:"sessionId"`
			Context   struct {
				Cwd string `json:"cwd"`
			} `json:"context"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(first), &head); err != nil || head.Type != "session.start" || head.Data.Context.Cwd == "" {
		t.Errorf("%s line 1 is not a session.start with a cwd (%v)", rel, err)
	}
	if filepath.Base(filepath.Dir(rel)) != head.Data.SessionID {
		t.Errorf("%s: directory != line sessionId %s", rel, head.Data.SessionID)
	}
	if strings.Contains(rest, `"type":"assistant.usage"`) {
		t.Errorf("%s persists assistant.usage — the DIAGNOSTIC-only reading of this surface is wrong", rel)
	}
	if !strings.Contains(rest, `"type":"session.shutdown"`) {
		t.Errorf("%s has no session.shutdown", rel)
	}
}

func assertHookBody(t *testing.T, rel string, b []byte) {
	t.Helper()
	var body struct {
		HookEventName string `json:"hook_event_name"`
		SessionID     string `json:"session_id"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		t.Errorf("%s is not JSON: %v", rel, err)
		return
	}
	if want := strings.TrimSuffix(filepath.Base(rel), ".json"); body.HookEventName != want {
		t.Errorf("%s carries hook_event_name %q", rel, body.HookEventName)
	}
	if body.SessionID == "" {
		t.Errorf("%s has no session_id", rel)
	}
}

func assertExpectations(t *testing.T, rel string, b []byte, version string) {
	t.Helper()
	var exp struct {
		AgentVersion string `json:"agent_version"`
		VendorPin    struct {
			RuntimeSHA string `json:"runtime_tgz_sha256"`
			DocsCommit string `json:"docs_commit"`
		} `json:"vendor_pin"`
		UsageEventsExpected int `json:"usage_events_expected"`
		Streams             []struct {
			File             string `json:"file"`
			DiagnosticEvents []any  `json:"diagnostic_events"`
		} `json:"streams"`
	}
	if err := json.Unmarshal(b, &exp); err != nil {
		t.Errorf("%s is not JSON: %v", rel, err)
		return
	}
	if exp.AgentVersion != version {
		t.Errorf("%s claims agent_version %q but is filed under v%s", rel, exp.AgentVersion, version)
	}
	if len(exp.VendorPin.RuntimeSHA) != 64 || len(exp.VendorPin.DocsCommit) != 40 {
		t.Errorf("%s: vendor_pin lacks the runtime tarball sha256 or the docs commit", rel)
	}
	if exp.UsageEventsExpected != 0 {
		t.Errorf("%s expects Usage from a surface with no per-request id", rel)
	}
	if len(exp.Streams) == 0 {
		t.Errorf("%s expects no streams", rel)
	}
	for _, s := range exp.Streams {
		if len(s.DiagnosticEvents) == 0 {
			t.Errorf("%s: stream %q expects no diagnostic events", rel, s.File)
		}
	}
}
