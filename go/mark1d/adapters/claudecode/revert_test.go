package claudecode

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// provisioned applies the fragment to a copy of userSettings and asserts the
// fence is REALLY there before the caller starts asserting it can be removed.
// This repo has been bitten by tests that pass by never executing; a revert
// test whose fixture was never provisioned would pass trivially and prove
// exactly nothing.
func provisioned(t *testing.T, body string) (path, state string) {
	t.Helper()
	path, state = writeSettings(t, body)
	res, err := ApplyFragment(path, state, "")
	if err != nil {
		t.Fatalf("setup apply: %v", err)
	}
	if !res.Changed || len(res.Pointers) != len(hookRegistrations) {
		t.Fatalf("setup apply did nothing: %+v", res)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), managedKey) || !strings.Contains(string(b), entryTag) {
		t.Fatalf("setup left no fence to revert:\n%s", b)
	}
	if _, err := os.Stat(ManifestPath(state)); err != nil {
		t.Fatalf("setup wrote no manifest: %v", err)
	}
	return path, state
}

// TestOffByteEquality is F-46 and the load-bearing promise of this whole file:
// `mark1 off` restores the user's config to BYTE equality. Not "equivalent
// JSON", not "semantically the same" — the same bytes, because the failure
// this design exists to prevent is a customer who cannot be told exactly what
// we changed.
func TestOffByteEquality(t *testing.T) {
	path, state := provisioned(t, userSettings)

	res, err := Revert(state)
	if err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if res.Kind != "verbatim" || !res.ByteEquality {
		t.Fatalf("revert of an untouched file: %+v, want verbatim byte-equality", res)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != userSettings {
		t.Fatalf("off did not restore the user's bytes:\nwant %q\ngot  %q", userSettings, after)
	}
	if strings.Contains(string(after), managedKey) || strings.Contains(string(after), entryTag) {
		t.Fatalf("fence survived a byte-equal revert:\n%s", after)
	}
	// §8.4 step 4: the manifest is gone, so nothing claims a fragment that is
	// no longer there.
	if _, err := os.Stat(ManifestPath(state)); !os.IsNotExist(err) {
		t.Fatalf("manifest survived revert: %v", err)
	}
}

// TestRevertIsIdempotent: `mark1 off` twice must succeed twice and must not
// touch the file the second time. An operator who learns the second run errors
// is an operator who stops running it.
func TestRevertIsIdempotent(t *testing.T) {
	path, state := provisioned(t, userSettings)
	if _, err := Revert(state); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Revert(state)
	if err != nil {
		t.Fatalf("second Revert: %v", err)
	}
	if res.Kind != "not-provisioned" || !res.ByteEquality {
		t.Fatalf("second revert: %+v", res)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("second revert rewrote the file:\n%s", second)
	}
}

// TestRevertResumesAfterACrashMidRevert: the manifest is deleted LAST (§8.4
// step 4), so a SIGKILL between the restore and the delete leaves a manifest
// pointing at an already-restored file. The re-run must recognize that as done
// and byte-equal, not report a downgrade that never happened.
func TestRevertResumesAfterACrashMidRevert(t *testing.T) {
	path, state := provisioned(t, userSettings)
	man, err := LoadManifest(state)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := RestorePreImage(man)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pre, 0o600); err != nil { // the crashed run's write
		t.Fatal(err)
	}
	res, err := Revert(state)
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != "verbatim" || !res.ByteEquality {
		t.Fatalf("resumed revert: %+v, want verbatim", res)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != userSettings {
		t.Fatalf("resumed revert disturbed an already-restored file:\n%s", after)
	}
}

// TestRevertSurgicalKeepsUserEditsMadeAfterApply: §8.4 step 3. The pre-image is
// stale the moment the user edits their settings, so restoring it would
// silently destroy work they did after we provisioned. Remove exactly our
// block and report the honest non-byte-equal outcome.
func TestRevertSurgicalKeepsUserEditsMadeAfterApply(t *testing.T) {
	path, state := provisioned(t, userSettings)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(b), `"model": "opus"`, `"model": "sonnet",
  "env": { "FOO": "bar" }`, 1)
	if edited == string(b) {
		t.Fatal("fixture drift: nothing to edit")
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Revert(state)
	if err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if res.Kind != "surgical" || res.ByteEquality {
		t.Fatalf("revert after a user edit: %+v, want a non-byte-equal surgical removal", res)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), managedKey) || strings.Contains(string(after), entryTag) {
		t.Fatalf("surgical revert left our fence behind:\n%s", after)
	}
	m := readJSON(t, path)
	if m["model"] != "sonnet" {
		t.Fatalf("the user's post-apply edit was reverted away: %v", m["model"])
	}
	if _, ok := m["env"]; !ok {
		t.Fatalf("the user's post-apply key was deleted:\n%s", after)
	}
	// Their own Stop handler survives, alone, in the array that also held ours.
	stop := m["hooks"].(map[string]any)["Stop"].([]any)
	if len(stop) != 1 {
		t.Fatalf("Stop array after revert: %v, want just the user's handler", stop)
	}
	if got := stop[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)["command"]; got != "/usr/bin/mine.sh" {
		t.Fatalf("we removed the USER's handler: %v", got)
	}
	// SessionStart existed only because we created it: leave nothing behind.
	if _, ok := m["hooks"].(map[string]any)["SessionStart"]; ok {
		t.Fatalf("a hook-event key we created survived revert:\n%s", after)
	}
}

// TestRevertFindsOurEntryAfterTheUserReorderedTheArray is the single most
// dangerous case in this file. The manifest records /hooks/Stop/1; the user
// then inserts their own handler above ours, so index 1 now points at THEIR
// config. Removing by recorded index would delete it. Identity is the `_mark1`
// tag, never the index.
func TestRevertFindsOurEntryAfterTheUserReorderedTheArray(t *testing.T) {
	path, state := provisioned(t, userSettings)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var hooks map[string]json.RawMessage
	if err := json.Unmarshal(doc["hooks"], &hooks); err != nil {
		t.Fatal(err)
	}
	var stop []json.RawMessage
	if err := json.Unmarshal(hooks["Stop"], &stop); err != nil {
		t.Fatal(err)
	}
	const inserted = `{"matcher":"","hooks":[{"type":"command","command":"/usr/bin/inserted.sh"}]}`
	stop = append([]json.RawMessage{json.RawMessage(inserted)}, stop...)
	if hooks["Stop"], err = json.Marshal(stop); err != nil {
		t.Fatal(err)
	}
	if doc["hooks"], err = json.Marshal(hooks); err != nil {
		t.Fatal(err)
	}
	moved, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, moved, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Revert(state); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	m := readJSON(t, path)
	got := m["hooks"].(map[string]any)["Stop"].([]any)
	if len(got) != 2 {
		t.Fatalf("Stop array: %v, want both of the user's handlers and neither of ours", got)
	}
	for _, want := range []string{"/usr/bin/inserted.sh", "/usr/bin/mine.sh"} {
		found := false
		for _, e := range got {
			if e.(map[string]any)["hooks"].([]any)[0].(map[string]any)["command"] == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("revert by stale index destroyed the user's %q handler: %v", want, got)
		}
	}
}

// TestRevertDoesNotRecreateADeletedTarget: the user deleted their settings
// file. Writing the pre-image back would be Mark 1 creating a user file, which
// is the same thing M1E-7101 refuses in the other direction.
func TestRevertDoesNotRecreateADeletedTarget(t *testing.T) {
	path, state := provisioned(t, userSettings)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	res, err := Revert(state)
	if err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if res.Kind != "target-absent" {
		t.Fatalf("revert with no target: %+v", res)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("revert recreated a file the user deleted")
	}
	if _, err := os.Stat(ManifestPath(state)); !os.IsNotExist(err) {
		t.Fatal("manifest survived: `mark1 off` would report this forever")
	}
}

// TestInspectReportsTheFourStates walks 08 §7.4's whole vocabulary against
// real files, and proves Inspect never writes: doctor is a diagnostic, and a
// diagnostic that mutates a user's config is the bug it was meant to find.
func TestInspectReportsTheFourStates(t *testing.T) {
	t.Run("MISSING when never provisioned", func(t *testing.T) {
		st, err := Inspect(filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		if st.State != StateMissing {
			t.Fatalf("state %q, want %q", st.State, StateMissing)
		}
	})

	t.Run("OK right after apply", func(t *testing.T) {
		path, state := provisioned(t, userSettings)
		st := inspectNoWrite(t, path, state)
		if st.State != StateOK {
			t.Fatalf("state %q (%s), want OK", st.State, st.Detail)
		}
		if len(st.Lines) != len(hookRegistrations) {
			t.Fatalf("%d provisioned lines, want %d — doctor must show every line we wrote",
				len(st.Lines), len(hookRegistrations))
		}
		// The lines are the bytes actually on disk, not a re-render of intent.
		if !strings.Contains(st.Lines[0].Value, DefaultShimPath) || st.Lines[0].Pointer != "/hooks/SessionStart/0" {
			t.Fatalf("line 0: %+v", st.Lines[0])
		}
	})

	t.Run("USER-EDITED when the rest of the file moved", func(t *testing.T) {
		path, state := provisioned(t, userSettings)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		edited := strings.Replace(string(b), `"model": "opus"`, `"model": "haiku"`, 1)
		if edited == string(b) {
			t.Fatal("fixture drift")
		}
		if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		if st := inspectNoWrite(t, path, state); st.State != StateUserEdited {
			t.Fatalf("state %q (%s), want %q", st.State, st.Detail, StateUserEdited)
		}
	})

	t.Run("FRAGMENT-DAMAGED when edited inside our markers", func(t *testing.T) {
		path, state := provisioned(t, userSettings)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		edited := strings.Replace(string(b), `"timeout": 30`, `"timeout": 90`, 1)
		if edited == string(b) {
			t.Fatal("fixture drift: no 30 s timeout to hand-edit")
		}
		if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		st := inspectNoWrite(t, path, state)
		if st.State != StateDamaged || !strings.Contains(st.Detail, CodeDamaged) {
			t.Fatalf("state %q detail %q, want %q + %s", st.State, st.Detail, StateDamaged, CodeDamaged)
		}
		if len(st.Lines) == 0 {
			t.Fatal("a damaged fragment must still be shown line by line, or it cannot be diffed")
		}
	})

	t.Run("FRAGMENT-DAMAGED when the checksum object is deleted", func(t *testing.T) {
		path, state := provisioned(t, userSettings)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		delete(doc, managedKey)
		stripped, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, stripped, 0o600); err != nil {
			t.Fatal(err)
		}
		st := inspectNoWrite(t, path, state)
		// MISSING here would make the next apply append a SECOND copy of all
		// nine handlers on top of the ones still sitting in the file.
		if st.State != StateDamaged {
			t.Fatalf("state %q, want %q: entries survived without their checksum", st.State, StateDamaged)
		}
		if len(st.Lines) != len(hookRegistrations) {
			t.Fatalf("%d lines, want the %d orphaned entries", len(st.Lines), len(hookRegistrations))
		}
	})

	t.Run("MISSING when the fragment was removed by hand", func(t *testing.T) {
		path, state := provisioned(t, userSettings)
		if err := os.WriteFile(path, []byte(userSettings), 0o600); err != nil {
			t.Fatal(err)
		}
		if st := inspectNoWrite(t, path, state); st.State != StateMissing {
			t.Fatalf("state %q (%s), want %q", st.State, st.Detail, StateMissing)
		}
	})
}

// inspectNoWrite runs Inspect and fails if the target changed by one byte.
func inspectNoWrite(t *testing.T, path, state string) Status {
	t.Helper()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Inspect(state)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("Inspect wrote to the user's settings file")
	}
	return st
}

// TestRepairRewritesOnlyTheDamagedFragment is `mark1 doctor --fix`, 08 §8.3(d)'s
// only sanctioned repair: apply still refuses the damaged file, --fix rewrites
// our entries, and nothing outside our pointers moves — including the pre-image
// the eventual `mark1 off` restores from.
func TestRepairRewritesOnlyTheDamagedFragment(t *testing.T) {
	path, state := provisioned(t, userSettings)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(b), `"timeout": 30`, `"timeout": 90`, 1)
	edited = strings.Replace(edited, `"model": "opus"`, `"model": "haiku"`, 1)
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyFragment(path, state, ""); err != ErrDamaged {
		t.Fatalf("apply over a damaged fragment: %v, want %v", err, ErrDamaged)
	}
	res, err := RepairFragment(path, state, "")
	if err != nil {
		t.Fatalf("RepairFragment: %v", err)
	}
	if !res.Changed {
		t.Fatal("--fix reported nothing to fix on a damaged fragment")
	}
	if st := inspectNoWrite(t, path, state); st.State != StateOK {
		t.Fatalf("after --fix: %q (%s), want OK", st.State, st.Detail)
	}
	m := readJSON(t, path)
	if m["model"] != "haiku" {
		t.Fatalf("--fix reverted a user key outside our pointers: %v", m["model"])
	}
	if got := entry(t, m, "Stop", 0)["hooks"].([]any)[0].(map[string]any)["command"]; got != "/usr/bin/mine.sh" {
		t.Fatalf("--fix touched the user's own handler: %v", got)
	}
	// The pre-image still describes the file from BEFORE Mark 1 existed, so
	// `mark1 off` after a repair still has a real byte-equality target.
	man, err := LoadManifest(state)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := RestorePreImage(man)
	if err != nil {
		t.Fatal(err)
	}
	if string(pre) != userSettings {
		t.Fatalf("--fix re-snapshotted our own output as the pre-image:\n%s", pre)
	}
}

// TestManifestTargetMustBeAbsoluteAndClean guards the one value in this package
// that reaches a write without being derived here. Revert and `doctor --fix`
// both write to manifest.target_path, so a forged one must be refused outright
// — resolving it would be the traversal, not a defense against it.
func TestManifestTargetMustBeAbsoluteAndClean(t *testing.T) {
	for _, bad := range []string{
		"/home/u/.claude/../../../etc/cron.d/x",
		"relative/settings.json",
		"",
		"/home/u/.claude/./settings.json",
	} {
		t.Run(bad, func(t *testing.T) {
			target, state := provisioned(t, userSettings)
			m, err := LoadManifest(state)
			if err != nil {
				t.Fatal(err)
			}
			m.TargetPath = bad
			b, _ := json.Marshal(m)
			if err := os.WriteFile(ManifestPath(state), b, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadManifest(state); !errors.Is(err, ErrManifestCorrupt) {
				t.Fatalf("LoadManifest(%q) = %v, want %v", bad, err, ErrManifestCorrupt)
			}
			if _, err := Revert(state); !errors.Is(err, ErrManifestCorrupt) {
				t.Fatalf("Revert(%q) = %v, want a refusal", bad, err)
			}
			// The refusal must be total: the real file is untouched and the
			// manifest survives so `mark1 doctor` can still report it.
			if _, err := os.Stat(target); err != nil {
				t.Fatalf("refused revert disturbed the real target: %v", err)
			}
			if _, err := os.Stat(ManifestPath(state)); err != nil {
				t.Fatalf("refused revert deleted the manifest: %v", err)
			}
		})
	}
}

// TestManifestIsPrivate: 08 §8.2 manifests hold a full copy of the user's
// config file. 0600, or we have quietly published it to every account on the
// machine.
func TestManifestIsPrivate(t *testing.T) {
	_, state := provisioned(t, userSettings)
	fi, err := os.Stat(ManifestPath(state))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode %o, want 0600 — it contains the user's whole config", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(ManifestPath(state)))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && di.Mode().Perm()&0o077 != 0 {
		t.Fatalf("manifest dir mode %o grants group or world", di.Mode().Perm())
	}
}

// TestApplyPreservesTargetMode: settings.json belongs to the user and so do its
// permissions. An apply that normalized them to 0600 would be a silent,
// unexplained change to a file we promised only to add a fenced block to.
func TestApplyPreservesTargetMode(t *testing.T) {
	path, state := writeSettings(t, userSettings)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	// Compare against the mode actually on disk beforehand rather than the
	// literal 0644: Windows synthesizes Perm() from one read-only attribute, so
	// a hardcoded constant would assert the platform, not the preservation.
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	want := before.Mode().Perm()
	if _, err := ApplyFragment(path, state, ""); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != want {
		t.Fatalf("apply changed the target's mode to %o, want %o", fi.Mode().Perm(), want)
	}
	if _, err := Revert(state); err != nil {
		t.Fatal(err)
	}
	if fi, err = os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != want {
		t.Fatalf("revert changed the target's mode to %o, want %o", fi.Mode().Perm(), want)
	}
}
