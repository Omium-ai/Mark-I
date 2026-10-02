package codex

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ADR-0014 drift-aware revert (FR-SPINE-039/040), the same five cases in
// every strict-JSON fence adapter. driftSeed is this adapter's pre-Mark1
// file; the rest is shared verbatim across the four packages.

func driftSeed(t *testing.T) (target, state string, original []byte) {
	t.Helper()
	dir := t.TempDir()
	target = filepath.Join(dir, driftTargetName)
	original = []byte(driftSeedBody)
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatal(err)
	}
	return target, t.TempDir(), original
}

// insertNeighbour puts a second writer's entry right before or after our
// tagged entry in whichever hooks array holds it, re-encoding the document.
func insertNeighbour(t *testing.T, target string, before bool) {
	t.Helper()
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	var hooks map[string]json.RawMessage
	if err := json.Unmarshal(root["hooks"], &hooks); err != nil {
		t.Fatal(err)
	}
	placed := false
	for ev, raw := range hooks {
		var list []json.RawMessage
		if json.Unmarshal(raw, &list) != nil {
			continue
		}
		for i, e := range list {
			if !bytes.Contains(e, []byte(entryTag)) {
				continue
			}
			neighbour := json.RawMessage(`{"command":"theirs-neighbour"}`)
			at := i + 1
			if before {
				at = i
			}
			list = append(list[:at], append([]json.RawMessage{neighbour}, list[at:]...)...)
			hooks[ev], _ = json.Marshal(list)
			placed = true
			break
		}
		if placed {
			break
		}
	}
	if !placed {
		t.Fatalf("no tagged entry to neighbour in %s", b)
	}
	root["hooks"], _ = json.Marshal(hooks)
	out, _ := json.MarshalIndent(root, "", "  ")
	if err := os.WriteFile(target, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDriftNoneRevertsVerbatim(t *testing.T) {
	target, state, original := driftSeed(t)
	if _, err := ApplyFragment(target, state, ""); err != nil {
		t.Fatal(err)
	}
	rev, err := Revert(state)
	if err != nil || rev.Kind != "verbatim" || !rev.ByteEquality {
		t.Fatalf("revert: %+v %v", rev, err)
	}
	if after, _ := os.ReadFile(target); !bytes.Equal(after, original) {
		t.Fatalf("not byte-identical:\n%s", after)
	}
}

// TestDriftReformatOnlyRestoresTheOriginal is the new behaviour: a CRLF
// rewrite of the file we wrote is DriftNone by structure, so the original
// bytes come back verbatim instead of a surgical edit of a reformatted file.
func TestDriftReformatOnlyRestoresTheOriginal(t *testing.T) {
	target, state, original := driftSeed(t)
	if _, err := ApplyFragment(target, state, ""); err != nil {
		t.Fatal(err)
	}
	post, _ := os.ReadFile(target)
	reformatted := bytes.ReplaceAll(post, []byte("\n"), []byte("\r\n"))
	if err := os.WriteFile(target, reformatted, 0o644); err != nil {
		t.Fatal(err)
	}
	rev, err := Revert(state)
	if err != nil || rev.Kind != "verbatim" || !rev.ByteEquality {
		t.Fatalf("revert after a reformat: %+v %v", rev, err)
	}
	if after, _ := os.ReadFile(target); !bytes.Equal(after, original) {
		t.Fatalf("not the original bytes:\n%s", after)
	}
}

func TestDriftNeighbourAfterOurEntrySurvivesDetach(t *testing.T)  { neighbourSurvives(t, false) }
func TestDriftNeighbourBeforeOurEntrySurvivesDetach(t *testing.T) { neighbourSurvives(t, true) }

func neighbourSurvives(t *testing.T, before bool) {
	t.Helper()
	target, state, _ := driftSeed(t)
	if _, err := ApplyFragment(target, state, ""); err != nil {
		t.Fatal(err)
	}
	insertNeighbour(t, target, before)
	rev, err := Revert(state)
	if err != nil || rev.Kind != "surgical" {
		t.Fatalf("revert with a neighbour: %+v %v", rev, err)
	}
	after, _ := os.ReadFile(target)
	if !bytes.Contains(after, []byte("theirs-neighbour")) {
		t.Fatalf("the second writer's entry was lost:\n%s", after)
	}
	if bytes.Contains(after, []byte(entryTag)) || bytes.Contains(after, []byte("_mark1_managed")) {
		t.Fatalf("something of ours survived detach:\n%s", after)
	}
	if !strings.Contains(string(after), driftSeedMarker) {
		t.Fatalf("the user's own content was lost:\n%s", after)
	}
}

// TestDriftLegacyManifestKeepsTheOldRule: a manifest without post_image
// (written before ADR-0014) cannot classify structurally and takes the
// previous path — a reformatted file is surgical, exactly as it was.
func TestDriftLegacyManifestKeepsTheOldRule(t *testing.T) {
	target, state, _ := driftSeed(t)
	if _, err := ApplyFragment(target, state, ""); err != nil {
		t.Fatal(err)
	}
	mp := ManifestPath(state)
	mb, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "post_image")
	legacy, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(mp, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	post, _ := os.ReadFile(target)
	if err := os.WriteFile(target, bytes.ReplaceAll(post, []byte("\n"), []byte("\r\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	rev, err := Revert(state)
	if err != nil || rev.Kind != "surgical" {
		t.Fatalf("legacy manifest after a reformat: %+v %v", rev, err)
	}
}
