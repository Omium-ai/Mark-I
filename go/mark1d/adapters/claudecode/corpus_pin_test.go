package claudecode

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

// recordedCorpusDigest freezes the BYTES of each pinned agent version's
// conformance corpus, keyed by version. The replay suites
// (internal/tailers.TestReplayStreams and friends) prove the tailer agrees with
// transcripts/expectations.json; nothing there — and nothing anywhere before
// this file — proved the corpus itself is the thing we recorded. Editing the
// fixture and regenerating the expectations to match, which is exactly what a
// well-meaning engineer does when a replay goes red, keeps every one of those
// tests green while the vendor format we claim to conform to changes
// underneath. This digest is the only assertion in the repo that goes red for
// that edit.
//
// The digest lives in the adapter's Go source, deliberately NOT in a manifest
// beside the fixtures: the threat model is a co-ordinated multi-file edit that
// reads as one tidy "regenerated fixtures" diff. Keeping the recorded value in
// a different top-level tree means such a change cannot be staged without also
// touching an adapter test file, which is the diff line a reviewer notices.
//
// Adding a version: land conformance/hooks/claudecode/v<new>/, add its entry
// here and to SupportedVersions. The test below enumerates version directories
// from disk, so a new one with no entry fails closed — nobody has to remember.
var recordedCorpusDigest = map[string]string{
	"2.1.251": "feab581125d058af1a707f496e36c7732da93692517c879a7aa498385ed5d6dd",
}

// corpusPinExempt: the two files under a version directory that are not
// evidence about the vendor. README.md is prose about the corpus and
// selfcheck.py is a checker that runs against it; a hash bump means "I
// re-recorded from a real install", and forcing that attestation for a typo fix
// is how an attestation gets treated as a chore. Everything else is pinned,
// including files added later — the walk is fail-closed by construction.
var corpusPinExempt = map[string]bool{"README.md": true, "selfcheck.py": true}

// TestPinnedCorpusMatchesRecordedDigest is FR-AGENT-004's "fixture drift fails
// the build" clause taken literally: drift of the FIXTURES, not of the parser.
func TestPinnedCorpusMatchesRecordedDigest(t *testing.T) {
	// claudecode -> adapters -> mark1d -> go -> repo root.
	root := filepath.Join("..", "..", "..", "..", "conformance", "hooks", "claudecode")
	ents, err := os.ReadDir(root)
	if err != nil {
		// Never a skip: an unreadable corpus is precisely the state in which a
		// digest comparison would prove nothing.
		t.Fatalf("fixture tree unreadable at %s: %v", root, err)
	}
	onDisk := map[string]bool{}
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), "v") {
			onDisk[strings.TrimPrefix(e.Name(), "v")] = true
		}
	}
	if len(onDisk) == 0 {
		t.Fatalf("no version directories under %s — every assertion below would be vacuous", root)
	}
	for v := range recordedCorpusDigest {
		if !onDisk[v] {
			t.Errorf("a digest is recorded for %q but conformance/hooks/claudecode/v%s does not exist — the pin guards nothing", v, v)
		}
	}
	for v := range onDisk {
		want, ok := recordedCorpusDigest[v]
		if !ok {
			t.Errorf("conformance/hooks/claudecode/v%s has no entry in recordedCorpusDigest — an unpinned corpus can be rewritten into anything and every replay test stays green", v)
			continue
		}
		got, files := digestCorpus(t, filepath.Join(root, "v"+v), v)
		if got == want {
			continue
		}
		t.Errorf(`claudecode %s corpus has changed.
  recorded %s
  on disk  %s   (%d files)

These bytes are a RECORDING of a third-party vendor's on-disk format at a pinned
version. They are evidence about the outside world, not our design: editing them
is closer to editing a measurement than to changing code, and the ~2.5x
streaming overcount defence (NFR-CORRECTNESS-001, 07 §7) is calibrated against
exactly this corpus. The replay suites cannot see this change — regenerate
expectations.json to match an edited transcript and they all stay green, which
is why this digest exists.

Updating the constant is an attestation that you re-recorded these shapes from a
real 'claude %s' install, sanitized them, and that selfcheck.py passes on the
result. It is NOT a way to make the build green:
  - a replay disagreeing with expectations.json means the PARSER is wrong; fix
    the parser, leave the corpus alone;
  - a vendor format change is a NEW directory conformance/hooks/claudecode/v<new>/
    plus a SupportedVersions entry (12 §3.2 refresh policy — this tree is frozen
    so the old pin keeps documenting the supported window), never an edit here.`,
			v, want, got, files, v)
	}
}

// digestCorpus hashes every evidence file under dir into one canonical digest
// over (relative path, file digest) pairs — so a rename, an addition and a
// deletion all move it, not just a content edit. It refuses to return a digest
// unless the tree it walked is recognisably the pinned claudecode corpus: a
// digest over an empty or wrong-shaped directory is a stable, useless constant.
func digestCorpus(t *testing.T, dir, version string) (string, int) {
	t.Helper()
	type entry struct {
		rel string
		sum [sha256.Size]byte
	}
	var entries []entry
	var hooks, transcripts int
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
		case strings.HasSuffix(rel, ".jsonl"):
			assertTranscript(t, rel, b, version)
			transcripts++
		}
		entries = append(entries, entry{rel, sha256.Sum256(b)})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	// The corpus README's own contents table: nine hook bodies, the parent +
	// subagent + foreign-workspace transcripts, and the expectations oracle.
	if hooks < 9 || transcripts < 3 || !expectations {
		t.Fatalf("%s: walked %d hook bodies, %d transcripts, expectations=%v — that is not the pinned corpus, so its digest asserts nothing", dir, hooks, transcripts, expectations)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	h := sha256.New()
	for _, e := range entries {
		// hash.Hash.Write is documented never to return an error.
		_, _ = fmt.Fprintf(h, "%s\n%x\n", e.rel, e.sum)
	}
	return hex.EncodeToString(h.Sum(nil)), len(entries)
}

// assertTranscript: a transcript line is the vendor's, and it says so. Every
// v2.1.251 line stamps `version` and `sessionId`; checking the first line
// against the directory the file is filed under makes a fixture that drifted
// into some other version's shape a failure here rather than a silent
// re-pinning of what "2.1.251" means.
func assertTranscript(t *testing.T, rel string, b []byte, version string) {
	t.Helper()
	var line struct {
		Version   string `json:"version"`
		SessionID string `json:"sessionId"`
		Type      string `json:"type"`
	}
	first, _, _ := strings.Cut(string(b), "\n")
	if err := json.Unmarshal([]byte(first), &line); err != nil {
		t.Errorf("%s line 1 is not JSON (%v) — this is meant to be a recorded transcript", rel, err)
		return
	}
	if line.Version != version {
		t.Errorf("%s line 1 carries version %q but is filed under v%s", rel, line.Version, version)
	}
	if line.SessionID == "" || line.Type == "" {
		t.Errorf("%s line 1 has no sessionId/type — not a transcript line", rel)
	}
}

// assertHookBody: a hook fixture is the stdin body for the event its filename
// names (08 §5.1). Filename-only agreement is already covered by
// TestRegistrationsMatchPinnedFixtures; this reads the bytes.
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
		t.Errorf("%s has no session_id — not a hook body", rel)
	}
}

// assertExpectations: the oracle is pinned with the transcripts on purpose. It
// is not parser output — it is our reading of the vendor's bytes, re-derived
// independently by selfcheck.py from 08 §5.1's dedupe and sidechain rules. A
// parser fix does not change what a correct tailer must emit; a change here is
// a change to the claim, and a fixture+expectations edit made together is the
// exact drift this row names.
func assertExpectations(t *testing.T, rel string, b []byte, version string) {
	t.Helper()
	var exp struct {
		AgentVersion string `json:"agent_version"`
		Streams      []struct {
			File        string `json:"file"`
			UsageEvents []struct {
				IdemKeyInputs map[string]string `json:"idem_key_inputs"`
			} `json:"usage_events"`
		} `json:"streams"`
	}
	if err := json.Unmarshal(b, &exp); err != nil {
		t.Errorf("%s is not JSON: %v", rel, err)
		return
	}
	if exp.AgentVersion != version {
		t.Errorf("%s claims agent_version %q but is filed under v%s", rel, exp.AgentVersion, version)
	}
	if len(exp.Streams) == 0 {
		t.Errorf("%s expects no streams — replaying it would assert nothing", rel)
	}
	for _, s := range exp.Streams {
		if len(s.UsageEvents) == 0 {
			t.Errorf("%s: stream %q expects no Usage events", rel, s.File)
		}
	}
}
