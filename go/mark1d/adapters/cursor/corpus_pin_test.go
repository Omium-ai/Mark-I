package cursor

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
	"2026.09.10-fd3934a": "b945fcba82a55adc847f8254e6b95999057a01d327a6d32eafe3e215c13957a9",
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
			t.Errorf("a digest is recorded for %q but conformance/hooks/cursor/v%s does not exist", v, v)
		}
	}
	for v := range onDisk {
		want, ok := recordedCorpusDigest[v]
		if !ok {
			t.Errorf("conformance/hooks/cursor/v%s has no entry in recordedCorpusDigest", v)
			continue
		}
		got, files := digestCorpus(t, filepath.Join(root, "v"+v), v)
		if got != want {
			t.Errorf(`cursor %s corpus has changed.
  recorded %s
  on disk  %s   (%d files)
These bytes are the vendor's hooks module, the CLI's payload builders and the
bodies composed from them at a pinned build. A vendor change is a NEW
conformance/hooks/cursor/v<new>/ plus a SupportedVersions entry, never an edit here.`, v, want, got, files)
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
	var hooks, schemas int
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
		case rel == "expectations.json":
			assertExpectations(t, rel, b, version)
			expectations = true
		case strings.HasPrefix(rel, "hooks/") && strings.HasSuffix(rel, ".json"):
			assertHookBody(t, rel, b)
			hooks++
		case strings.HasPrefix(rel, "schema/"):
			schemas++
		case strings.HasPrefix(rel, "transcripts/"):
			t.Errorf("%s: a transcript surface appeared; no durable local usage source is GO for cursor", rel)
		}
		entries = append(entries, entry{rel, sha256.Sum256(b)})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	if hooks < 8 || schemas < 5 || !expectations {
		t.Fatalf("%s: %d hook bodies, %d schemas, expectations=%v — not the pinned corpus", dir, hooks, schemas, expectations)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	h := sha256.New()
	for _, e := range entries {
		_, _ = fmt.Fprintf(h, "%s\n%x\n", e.rel, e.sum)
	}
	return hex.EncodeToString(h.Sum(nil)), len(entries)
}

func assertHookBody(t *testing.T, rel string, b []byte) {
	t.Helper()
	var body struct {
		HookEventName  string `json:"hook_event_name"`
		SessionID      string `json:"session_id"`
		ConversationID string `json:"conversation_id"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		t.Errorf("%s is not JSON: %v", rel, err)
		return
	}
	if want := strings.TrimSuffix(filepath.Base(rel), ".json"); body.HookEventName != want {
		t.Errorf("%s carries hook_event_name %q", rel, body.HookEventName)
	}
	if body.SessionID == "" || body.SessionID != body.ConversationID {
		t.Errorf("%s: session_id %q is not the conversation id", rel, body.SessionID)
	}
}

func assertExpectations(t *testing.T, rel string, b []byte, version string) {
	t.Helper()
	var exp struct {
		AgentVersion string `json:"agent_version"`
		VendorPin    struct {
			CLISHA    string `json:"cli_tgz_sha256"`
			IDECommit string `json:"ide_commit"`
		} `json:"vendor_pin"`
		LiveRecording string `json:"live_recording"`
		Hooks         struct {
			Registered []string `json:"registered"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(b, &exp); err != nil {
		t.Errorf("%s is not JSON: %v", rel, err)
		return
	}
	if exp.AgentVersion != version {
		t.Errorf("%s claims agent_version %q but is filed under v%s", rel, exp.AgentVersion, version)
	}
	if len(exp.VendorPin.CLISHA) != 64 || len(exp.VendorPin.IDECommit) != 40 {
		t.Errorf("%s: vendor_pin lacks the CLI tarball sha256 or the IDE commit", rel)
	}
	if !strings.HasPrefix(exp.LiveRecording, "none") {
		t.Errorf("%s: a live recording is claimed; record it under a new version directory and say how", rel)
	}
	if len(exp.Hooks.Registered) == 0 {
		t.Errorf("%s registers nothing", rel)
	}
}
