package copilot

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
)

// startFakeGuard answers exactly the frozen refusal shape the real guard
// answers a request carrying no M1-Cred-Ref: 403 with "M1E-8001" in the
// body. writePort=true mirrors what mark1-proxy actually does at bind time.
func startFakeGuard(t *testing.T, state string, writePort bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"reason_code":"M1E-8001"}`))
	}))
	t.Cleanup(srv.Close)
	if writePort {
		port := strings.TrimPrefix(srv.URL, "http://127.0.0.1:")
		if err := os.MkdirAll(state, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(state, "proxy.port"), []byte(port), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return srv
}

func byokAdapter(t *testing.T, state string) *Adapter {
	t.Helper()
	return &Adapter{
		Home: t.TempDir(), CopilotHome: t.TempDir(), StateDir: state,
		Env: envOf(map[string]string{"COPILOT_PROVIDER_BASE_URL": "https://api.openai.com/v1", "COPILOT_PROVIDER_API_KEY": "sk-synth"}),
	}
}

// TestApplyEnvPointerWritesTheSourceableFragment: eligible BYOK + a live
// guard on the published port writes <state>/env/copilot.sh pointing at it,
// and the printed source line names that exact file.
func TestApplyEnvPointerWritesTheSourceableFragment(t *testing.T) {
	state := t.TempDir()
	srv := startFakeGuard(t, state, true)
	a := byokAdapter(t, state)

	res, err := a.ApplyEnvPointer()
	if err != nil || !res.Changed || res.Mechanism != "A" {
		t.Fatalf("apply: %+v %v", res, err)
	}
	target := EnvFilePath(state, "linux")
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("export COPILOT_PROVIDER_BASE_URL="+strconv.Quote(srv.URL))) {
		t.Fatalf("fragment does not export the proxy URL: %s", b)
	}
	line := SourceLine(state, "linux")
	if !strings.HasPrefix(line, "source ") || !strings.HasSuffix(line, target) {
		t.Fatalf("source line %q does not name %q", line, target)
	}

	// Idempotent re-apply.
	second, err := a.ApplyEnvPointer()
	if err != nil || second.Changed {
		t.Fatalf("re-apply must be a no-op: %+v %v", second, err)
	}
	after, _ := os.ReadFile(target)
	if !bytes.Equal(b, after) {
		t.Fatal("apply ∘ apply changed bytes")
	}

	st, err := InspectEnvPointer(state)
	if err != nil || st.State != StateOK || st.Fragment != "env" || st.Target != target {
		t.Fatalf("inspect: %+v %v", st, err)
	}

	// Hand-edit is detected and refused, matching the hooks fragment's rule.
	if err := os.WriteFile(target, append(after, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ApplyEnvPointer(); !errors.Is(err, ErrDamaged) {
		t.Fatalf("hand-edited pointer file must refuse with ErrDamaged, got %v", err)
	}
	if st, _ := InspectEnvPointer(state); st.State != StateDamaged {
		t.Fatalf("inspect after edit: %+v", st)
	}

	// off deletes it byte-exactly and a second off is a clean no-op.
	rres, err := RevertEnvPointer(state)
	if err != nil || rres.Kind != "fragment-damaged" || len(rres.Retained) != 1 {
		t.Fatalf("revert over a hand-edit must retain, not overwrite: %+v %v", rres, err)
	}
	// Repair by re-applying over the corruption is out of scope here (no --fix
	// path for this fragment, mirroring claudecode's base-URL fragment); put
	// the correct bytes back directly to exercise the clean revert path.
	if err := os.WriteFile(target, b, 0o600); err != nil {
		t.Fatal(err)
	}
	rres, err = RevertEnvPointer(state)
	if err != nil || rres.Kind != "verbatim" || !rres.ByteEquality {
		t.Fatalf("revert: %+v %v", rres, err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("revert must delete the owned file")
	}
	if _, err := os.Stat(EnvManifestPath(state)); !os.IsNotExist(err) {
		t.Fatal("manifest must be deleted last")
	}
	if rres, err := RevertEnvPointer(state); err != nil || rres.Kind != "not-provisioned" {
		t.Fatalf("second off must succeed as a no-op: %+v %v", rres, err)
	}
}

// TestApplyEnvPointerRegistersTheBYOKFingerprint: the `<ref> <64 hex>` line the guard
// loads (10 §3.3), beside claudecode's, replaced on re-apply, absent when the pointer refuses.
func TestApplyEnvPointerRegistersTheBYOKFingerprint(t *testing.T) {
	state := t.TempDir()
	startFakeGuard(t, state, true)
	other := "claudecode " + strings.Repeat("ab", 32) + "\n"
	if err := os.WriteFile(filepath.Join(state, "registry"), []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	a := byokAdapter(t, state)
	if _, err := a.ApplyEnvPointer(); err != nil {
		t.Fatal(err)
	}

	key, err := os.ReadFile(filepath.Join(state, "guard.key"))
	if err != nil || len(key) != 32 {
		t.Fatalf("guard.key: %v (len %d)", err, len(key))
	}
	reg, err := os.ReadFile(filepath.Join(state, "registry"))
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("sk-synth"))
	want := other + "copilot " + hex.EncodeToString(mac.Sum(nil)) + "\n"
	if string(reg) != want {
		t.Fatalf("registry:\n%s\nwant:\n%s", reg, want)
	}
	if runtime.GOOS != "windows" {
		for _, name := range []string{"guard.key", "registry"} {
			fi, err := os.Stat(filepath.Join(state, name))
			if err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("%s: %v mode %v, want 0600", name, err, fi.Mode().Perm())
			}
		}
	}

	if _, err := a.ApplyEnvPointer(); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(filepath.Join(state, "registry")); string(again) != want {
		t.Fatalf("re-apply changed the registry:\n%s", again)
	}

	// A rotated key replaces copilot's line under the SAME guard.key.
	a.Env = envOf(map[string]string{"COPILOT_PROVIDER_BASE_URL": "https://api.openai.com/v1", "COPILOT_PROVIDER_API_KEY": "sk-synth-2"})
	if _, err := a.ApplyEnvPointer(); err != nil {
		t.Fatal(err)
	}
	mac = hmac.New(sha256.New, key)
	mac.Write([]byte("sk-synth-2"))
	rotated, _ := os.ReadFile(filepath.Join(state, "registry"))
	if string(rotated) != other+"copilot "+hex.EncodeToString(mac.Sum(nil))+"\n" {
		t.Fatalf("rotation did not replace copilot's line:\n%s", rotated)
	}

	// Same literal rust:guard::provenance::tests::registry_line_written_by_mark1d_admits_header_free loads.
	pinned := t.TempDir()
	startFakeGuard(t, pinned, true)
	if err := os.WriteFile(filepath.Join(pinned, "guard.key"), []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.StateDir = pinned
	a.Env = envOf(map[string]string{"COPILOT_PROVIDER_BASE_URL": "https://api.openai.com/v1",
		"COPILOT_PROVIDER_API_KEY": "sk-ant-api03-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01"})
	if _, err := a.ApplyEnvPointer(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(pinned, "registry")); string(got) != "copilot a47a9f209bb72c805c7e9cff25ea871a53b1b49559bed3f797cd808834038327\n" {
		t.Fatalf("pinned vector drifted:\n%s", got)
	}

	// Refused pointers register nothing.
	for _, tc := range []struct {
		name string
		a    *Adapter
	}{
		{"subscription", &Adapter{Home: t.TempDir(), CopilotHome: t.TempDir(), StateDir: t.TempDir(), Env: envOf(map[string]string{})}},
		{"no guard", byokAdapter(t, t.TempDir())},
	} {
		if _, err := tc.a.ApplyEnvPointer(); !errors.Is(err, ErrNotEligible) {
			t.Fatalf("%s: got %v", tc.name, err)
		}
		if _, err := os.Stat(filepath.Join(tc.a.StateDir, "registry")); !os.IsNotExist(err) {
			t.Fatalf("%s: a refused pointer wrote a registry line", tc.name)
		}
	}
}

// TestApplyEnvPointerRefusesIneligibleCredentials covers all three ways
// WireCredential refuses: subscription regime, providers.json-sourced key
// (unconfirmed entry schema), and a GitHub-token-shaped value planted in the
// API-key slot — the negative FR-AGENT-014 asks for at the pointer, not only
// at WireCredential.
func TestApplyEnvPointerRefusesIneligibleCredentials(t *testing.T) {
	state := t.TempDir()
	startFakeGuard(t, state, true)

	a := &Adapter{Home: t.TempDir(), CopilotHome: t.TempDir(), StateDir: state, Env: envOf(map[string]string{})}
	if _, err := a.ApplyEnvPointer(); !errors.Is(err, ErrNotEligible) || RefusalCode(err) != CodeNotEligible {
		t.Fatalf("GitHub-billed (no provider config): got %v", err)
	}
	if _, err := os.Stat(EnvFilePath(state, "linux")); !os.IsNotExist(err) {
		t.Fatal("no pointer must be written for a subscription session")
	}

	gh := "gho_AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTt"
	a.Env = envOf(map[string]string{"COPILOT_PROVIDER_BASE_URL": "https://api.openai.com/v1", "COPILOT_PROVIDER_API_KEY": gh})
	d, err := a.Detect()
	if err != nil || d.Regime != adapters.RegimeSubscription {
		t.Fatalf("a GitHub-token-shaped COPILOT_PROVIDER_API_KEY must sniff as subscription, got regime=%v err=%v", d.Regime, err)
	}
	if _, err := a.ApplyEnvPointer(); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("GitHub-token-shaped key beside a base URL: got %v, want ErrNotEligible (fail closed on legality)", err)
	}
	if _, err := os.Stat(EnvFilePath(state, "linux")); !os.IsNotExist(err) {
		t.Fatal("a GitHub-shaped credential must never reach the pointer file")
	}

	ch := t.TempDir()
	if err := os.WriteFile(filepath.Join(ch, "providers.json"), []byte(`{"providers":[{"baseUrl":"https://a","apiKey":"k"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	a2 := &Adapter{Home: t.TempDir(), CopilotHome: ch, StateDir: state, Env: envOf(map[string]string{})}
	if _, err := a2.ApplyEnvPointer(); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("providers.json-sourced credential: got %v", err)
	}
}

// TestApplyEnvPointerRefusesWithoutALiveGuard: the port file absent, holding
// garbage, or held by something that is not our guard's frozen refusal shape
// must all refuse rather than point Copilot's real key at an arbitrary
// listener.
func TestApplyEnvPointerRefusesWithoutALiveGuard(t *testing.T) {
	state := t.TempDir()
	a := byokAdapter(t, state)
	if _, err := a.ApplyEnvPointer(); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("no proxy.port at all: got %v", err)
	}

	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "proxy.port"), []byte("not-a-port"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ApplyEnvPointer(); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("garbage proxy.port: got %v", err)
	}

	squatter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(squatter.Close)
	port := strings.TrimPrefix(squatter.URL, "http://127.0.0.1:")
	if err := os.WriteFile(filepath.Join(state, "proxy.port"), []byte(port), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ApplyEnvPointer(); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("a squatter answering 200 instead of the guard's 403/M1E-8001 must refuse: got %v", err)
	}
	if _, err := os.Stat(EnvFilePath(state, "linux")); !os.IsNotExist(err) {
		t.Fatal("a squatted port must never receive a pointer — that would leak the BYOK key to it")
	}
}

// TestApplyEnvPointerWritesPowerShellOnWindows: the GOOS test seam selects
// the PowerShell syntax and the .ps1 target, and SourceLine dot-sources it.
func TestApplyEnvPointerWritesPowerShellOnWindows(t *testing.T) {
	state := t.TempDir()
	startFakeGuard(t, state, true)
	a := byokAdapter(t, state)
	a.GOOS = "windows"

	res, err := a.ApplyEnvPointer()
	if err != nil || !res.Changed {
		t.Fatalf("apply: %+v %v", res, err)
	}
	target := EnvFilePath(state, "windows")
	if !strings.HasSuffix(target, "copilot.ps1") {
		t.Fatalf("windows target is %q", target)
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("$env:COPILOT_PROVIDER_BASE_URL = ")) {
		t.Fatalf("not PowerShell syntax: %s", b)
	}
	if line := SourceLine(state, "windows"); !strings.HasPrefix(line, ". ") {
		t.Fatalf("windows source line %q must dot-source", line)
	}
}

// TestEnvPointerLiveState covers doctor's three-way row: never applied,
// applied but the current process env does not carry it (never sourced, or
// sourced somewhere else / stale after a proxy restart), and applied with
// the live env matching exactly what was written.
func TestEnvPointerLiveState(t *testing.T) {
	state := t.TempDir()
	if got := EnvPointerLiveState(state, envOf(nil)); got != PointerAbsent {
		t.Fatalf("never applied: %q", got)
	}
	srv := startFakeGuard(t, state, true)
	a := byokAdapter(t, state)
	if _, err := a.ApplyEnvPointer(); err != nil {
		t.Fatal(err)
	}
	if got := EnvPointerLiveState(state, envOf(nil)); got != PointerWrittenNotSourced {
		t.Fatalf("written but not sourced: %q", got)
	}
	if got := EnvPointerLiveState(state, envOf(map[string]string{"COPILOT_PROVIDER_BASE_URL": "https://not-the-proxy.example"})); got != PointerWrittenNotSourced {
		t.Fatalf("a stale or unrelated value must not read as active: %q", got)
	}
	if got := EnvPointerLiveState(state, envOf(map[string]string{"COPILOT_PROVIDER_BASE_URL": srv.URL})); got != PointerActive {
		t.Fatalf("exact match must read active: %q", got)
	}
}

func TestSourceLineDisplaysUnderHomeWithATilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no resolvable home:", err)
	}
	state := filepath.Join(home, ".omium-test-"+t.Name(), "mark1")
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(home, ".omium-test-"+t.Name())) })
	line := SourceLine(state, "linux")
	if !strings.HasPrefix(line, "source ~"+string(filepath.Separator)) {
		t.Fatalf("expected a tilde-relative path under $HOME, got %q", line)
	}
}
