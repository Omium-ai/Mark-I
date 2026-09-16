package opencode

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func seedConfig(t *testing.T) (target, state string) {
	t.Helper()
	return filepath.Join(t.TempDir(), "plugins", "mark1.js"), t.TempDir()
}

// TestOwnedFileApplyIsIdempotentAndOffDeletesIt: mechanism A end to end —
// apply ∘ apply ≡ apply, then `mark1 off` leaves the config dir as found.
func TestOwnedFileApplyIsIdempotentAndOffDeletesIt(t *testing.T) {
	target, state := seedConfig(t)
	first, err := ApplyFragment(target, state, "")
	if err != nil || !first.Changed || first.Mechanism != "A" {
		t.Fatalf("first apply: %+v %v", first, err)
	}
	after1, _ := os.ReadFile(target)
	if !bytes.Equal(after1, Plugin("")) || !bytes.Contains(after1, []byte(DefaultShimPath)) || bytes.Contains(after1, []byte("__MARK1_SHIM__")) {
		t.Fatal("owned file is not the plugin with the shim path substituted")
	}
	if !bytes.Contains(after1, []byte(`MARK1_AGENT: "opencode"`)) || !bytes.Contains(after1, []byte(`export default`)) {
		t.Fatal("plugin must select the opencode map and default-export the v1 {id, server} module shape")
	}
	second, err := ApplyFragment(target, state, "")
	if err != nil || second.Changed {
		t.Fatalf("re-apply must be a no-op: %+v %v", second, err)
	}
	after2, _ := os.ReadFile(target)
	if !bytes.Equal(after1, after2) {
		t.Fatal("apply ∘ apply changed bytes")
	}
	st, err := Inspect(state)
	if err != nil || st.State != StateOK || st.Mechanism != "A" || st.Target != target {
		t.Fatalf("inspect: %+v %v", st, err)
	}
	res, err := Revert(state)
	if err != nil || res.Kind != "verbatim" || !res.ByteEquality {
		t.Fatalf("revert: %+v %v", res, err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("mechanism A revert must delete the owned file")
	}
	if _, err := os.Stat(ManifestPath(state)); !os.IsNotExist(err) {
		t.Fatal("manifest must be deleted last")
	}
	if res, err := Revert(state); err != nil || res.Kind != "not-provisioned" {
		t.Fatalf("second off must succeed as a no-op: %+v %v", res, err)
	}
	if st, _ := Inspect(state); st.State != StateMissing {
		t.Fatalf("after off: %+v", st)
	}
}

func TestShimPathOverrideChangesTheChecksum(t *testing.T) {
	target, state := seedConfig(t)
	a, _ := ApplyFragment(target, state, "")
	b, err := ApplyFragment(target, state, "/opt/mark1/bin/mark1-hookshim")
	if err != nil || !b.Changed || a.Checksum == b.Checksum {
		t.Fatalf("a new shim path is a stale fragment (08 §8.3 c): %+v %v", b, err)
	}
	cur, _ := os.ReadFile(target)
	if !bytes.Contains(cur, []byte("/opt/mark1/bin/mark1-hookshim")) {
		t.Fatal("rewritten plugin does not carry the new shim path")
	}
}

func TestHandEditRefusesUntilRepairAndRevertWritesNothing(t *testing.T) {
	target, state := seedConfig(t)
	if _, err := ApplyFragment(target, state, ""); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(target)
	tampered := append(bytes.Clone(b), []byte("\nconsole.log('mine')\n")...)
	if err := os.WriteFile(target, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyFragment(target, state, ""); !errors.Is(err, ErrDamaged) || RefusalCode(err) != CodeDamaged {
		t.Fatalf("apply over a hand-edited owned file: %v", err)
	}
	if st, _ := Inspect(state); st.State != StateDamaged {
		t.Fatalf("inspect: %+v", st)
	}
	rev, err := Revert(state)
	if err != nil || rev.Kind != "fragment-damaged" || rev.ByteEquality || len(rev.Retained) != 1 {
		t.Fatalf("revert of bytes we cannot vouch for must write nothing (08 §8.4 3b): %+v %v", rev, err)
	}
	if cur, _ := os.ReadFile(target); !bytes.Equal(cur, tampered) {
		t.Fatal("revert touched the user's bytes")
	}
	if _, err := os.Stat(ManifestPath(state)); err != nil {
		t.Fatal("manifest must survive a refused revert so `mark1 off` keeps seeing it")
	}
	if res, err := RepairFragment(target, state, ""); err != nil || !res.Changed {
		t.Fatalf("repair: %+v %v", res, err)
	}
	if st, _ := Inspect(state); st.State != StateOK {
		t.Fatalf("after repair: %+v", st)
	}
}

func TestForeignFileAtOurPathRefuses(t *testing.T) {
	target, state := seedConfig(t)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("export default { id: 'theirs', server: async () => ({}) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyFragment(target, state, ""); !errors.Is(err, ErrDamaged) {
		t.Fatalf("a file we did not write at our path must not be overwritten: %v", err)
	}
	if res, err := Revert(state); err != nil || res.Kind != "not-provisioned" {
		t.Fatalf("nothing provisioned, nothing to revert: %+v %v", res, err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("their file must survive")
	}
}

func TestRefusals(t *testing.T) {
	if _, err := ApplyFragment(filepath.Join(t.TempDir(), "nope", "plugins", "mark1.js"), t.TempDir(), ""); !errors.Is(err, ErrNoTarget) || RefusalCode(err) != CodeNoTarget {
		t.Fatalf("missing config dir must refuse: %v", err)
	}
	target, state := seedConfig(t)
	if err := os.MkdirAll(filepath.Dir(ManifestPath(state)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ManifestPath(state), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyFragment(target, state, ""); !errors.Is(err, ErrManifestCorrupt) || RefusalCode(err) != CodeManifestCorrupt {
		t.Fatalf("corrupt manifest must refuse: %v", err)
	}
	if _, err := Revert(state); !errors.Is(err, ErrManifestCorrupt) {
		t.Fatalf("revert over a corrupt manifest must refuse: %v", err)
	}
	if RefusalCode(errors.New("disk on fire")) != "" {
		t.Fatal("a genuine failure has no refusal code")
	}
	if !strings.HasPrefix(ManifestPath("/s"), filepath.Join("/s", "provisioned", "opencode")+string(filepath.Separator)) {
		t.Fatal("manifest lives under provisioned/opencode (08 §8.2)")
	}
}
