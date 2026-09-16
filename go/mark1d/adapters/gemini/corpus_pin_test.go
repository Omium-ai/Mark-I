package gemini

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
// corpus was re-derived from the vendor at a new pin, never a way to go green.
var recordedCorpusDigest = map[string]string{
	"0.59.0": "d1bbe0ebca296cc1f580c9146401755d643471f5ba2fb55e625977fef9a5914d",
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
			t.Errorf("a digest is recorded for %q but conformance/hooks/gemini/v%s does not exist", v, v)
		}
	}
	for v := range onDisk {
		want, ok := recordedCorpusDigest[v]
		if !ok {
			t.Errorf("conformance/hooks/gemini/v%s has no entry in recordedCorpusDigest", v)
			continue
		}
		got, files := digestCorpus(t, filepath.Join(root, "v"+v), v)
		if got != want {
			t.Errorf(`gemini %s corpus has changed.
  recorded %s
  on disk  %s   (%d files)
These bytes are the vendor's types plus fixtures derived from them at a pinned
commit. A replay disagreeing with expectations.json means the PARSER is wrong;
a vendor change is a NEW conformance/hooks/gemini/v<new>/ plus a
SupportedVersions entry, never an edit here.`, v, want, got, files)
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
	var hooks, schemas, chats, markers int
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
		case strings.HasPrefix(rel, "schema/") && strings.HasSuffix(rel, ".ts"):
			schemas++
		case strings.HasPrefix(rel, "transcripts/tmp/") && strings.HasSuffix(rel, ".jsonl"):
			assertChat(t, rel, b)
			chats++
		case strings.HasPrefix(rel, "transcripts/tmp/") && d.Name() == ".project_root":
			markers++
		}
		entries = append(entries, entry{rel, sha256.Sum256(b)})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	if hooks < 7 || schemas < 2 || chats < 4 || markers < 2 || !expectations {
		t.Fatalf("%s: %d hook bodies, %d schemas, %d chats, %d markers, expectations=%v — not the pinned corpus", dir, hooks, schemas, chats, markers, expectations)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	h := sha256.New()
	for _, e := range entries {
		_, _ = fmt.Fprintf(h, "%s\n%x\n", e.rel, e.sum)
	}
	return hex.EncodeToString(h.Sum(nil)), len(entries)
}

// assertChat: line 1 is the metadata head with a sessionId and a projectHash.
func assertChat(t *testing.T, rel string, b []byte) {
	t.Helper()
	var head struct {
		SessionID   string `json:"sessionId"`
		ProjectHash string `json:"projectHash"`
	}
	first, _, _ := strings.Cut(string(b), "\n")
	if err := json.Unmarshal([]byte(first), &head); err != nil || head.SessionID == "" || len(head.ProjectHash) != 64 {
		t.Errorf("%s line 1 is not a metadata head with sessionId + projectHash (%v)", rel, err)
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
			Commit string `json:"commit"`
		} `json:"vendor_pin"`
		Streams []struct {
			File        string `json:"file"`
			UsageEvents []any  `json:"usage_events"`
		} `json:"streams"`
	}
	if err := json.Unmarshal(b, &exp); err != nil {
		t.Errorf("%s is not JSON: %v", rel, err)
		return
	}
	if exp.AgentVersion != version {
		t.Errorf("%s claims agent_version %q but is filed under v%s", rel, exp.AgentVersion, version)
	}
	if len(exp.VendorPin.Commit) != 40 {
		t.Errorf("%s: vendor_pin.commit is not a full sha", rel)
	}
	if len(exp.Streams) == 0 {
		t.Errorf("%s expects no streams", rel)
	}
	for _, s := range exp.Streams {
		if len(s.UsageEvents) == 0 {
			t.Errorf("%s: stream %q expects no Usage events", rel, s.File)
		}
	}
}
