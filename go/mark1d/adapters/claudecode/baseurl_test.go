package claudecode

import (
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// liveProxy asks apiKeyHome for a real listener on a real port instead of a
// literal. Not a port number, and deliberately not a number at all: proxyURL now
// probes the published port before the fragment is written, so any constant here
// would name a port nothing holds and every positive test below would refuse.
const liveProxy = "live"

// guardStubPort is the proxy's refusal, and only that: 403 with M1E-8001, which
// is what rust/mark1-proxy/src/router.rs:143-149 returns for a request carrying
// no M1-Cred-Ref. The probe never sends one, so this is the whole conversation.
func guardStubPort(t *testing.T) int {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The liveness probe must never carry the thing it exists to protect.
		for _, h := range []string{"x-api-key", "Authorization", credRefHeader} {
			if v := r.Header.Get(h); v != "" {
				t.Errorf("liveness probe sent %s: %q", h, v)
			}
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"M1E-8001","message":"request without a valid M1-Cred-Ref"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

// publishedURL is the URL the fragment must name: literal loopback plus exactly
// the port the proxy published. Read back rather than restated, because the port
// is the kernel's to choose.
func publishedURL(t *testing.T, state string) string {
	t.Helper()
	b, err := os.ReadFile(ProxyPortPath(state))
	if err != nil {
		t.Fatal(err)
	}
	return "http://127.0.0.1:" + strings.TrimSpace(string(b))
}

// apiKeyHome stands up a home + state dir with a settings.json, an API-key
// credential in the environment, and a proxy that has published a port — the
// only combination in which the base-URL fragment may be written.
func apiKeyHome(t *testing.T, settings, port string) (home, state string) {
	t.Helper()
	home, state = t.TempDir(), filepath.Join(t.TempDir(), "mark1")
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	// Prefix rather than equality, so a caller can still append the surrounding
	// whitespace the port parser has to tolerate.
	if strings.HasPrefix(port, liveProxy) {
		port = strconv.Itoa(guardStubPort(t)) + strings.TrimPrefix(port, liveProxy)
	}
	if port != "" {
		if err := os.WriteFile(ProxyPortPath(state), []byte(port), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
	return home, state
}

func TestBaseURLFragmentPointsTheAgentAtTheProxy(t *testing.T) {
	home, state := apiKeyHome(t, userSettings, liveProxy+"\n")
	a := &Adapter{Home: home, StateDir: state}
	res, err := a.ApplyProxyPointer()
	if err != nil {
		t.Fatalf("ApplyProxyPointer: %v", err)
	}
	if !res.Changed {
		t.Fatal("first apply reported no change")
	}

	m := readJSON(t, filepath.Join(home, ".claude", "settings.json"))
	env, ok := m["env"].(map[string]any)
	if !ok {
		t.Fatalf("no env object: %#v", m)
	}
	if got := env[envBaseURL]; got != publishedURL(t, state) {
		t.Errorf("%s = %#v, want the published proxy port", envBaseURL, got)
	}
	if got := env[envHeaders]; got != credRefHeader+": "+credRefID {
		t.Errorf("%s = %#v, want the cred-ref header the guard admits on", envHeaders, got)
	}
	// The user's own keys, and the hooks fragment's territory, are untouched.
	if m["model"] != "opus" {
		t.Errorf("user key rewritten: %#v", m["model"])
	}
	if _, ok := m[managedKey]; ok {
		t.Error("base-URL apply wrote the hooks checksum object")
	}
	if _, err := os.Stat(manifestPath(state, baseURLFragment)); err != nil {
		t.Errorf("no baseurl manifest: %v", err)
	}
	if _, err := os.Stat(ManifestPath(state)); !os.IsNotExist(err) {
		t.Errorf("base-URL apply wrote the hooks manifest: %v", err)
	}
}

func TestBaseURLApplyIsIdempotent(t *testing.T) {
	home, state := apiKeyHome(t, userSettings, liveProxy)
	a := &Adapter{Home: home, StateDir: state}
	if _, err := a.ApplyProxyPointer(); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.ApplyProxyPointer()
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Error("re-apply reported a change; §8.3(b) is an exact no-op")
	}
	second, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if string(first) != string(second) {
		t.Errorf("re-apply rewrote the file:\n%s\n%s", first, second)
	}
}

// TestProxyPointerRefusesWithoutAnAPIKeyCredential is CON-001's structural
// half: a subscription agent's config is never opened for write, so it has no
// route to the proxy to misconfigure.
func TestProxyPointerRefusesWithoutAnAPIKeyCredential(t *testing.T) {
	home, state := apiKeyHome(t, userSettings, liveProxy)
	t.Setenv("ANTHROPIC_API_KEY", "")
	a := &Adapter{Home: home, StateDir: state}
	if _, err := a.ApplyProxyPointer(); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("err = %v, want ErrNotEligible", err)
	}
	b, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if string(b) != userSettings {
		t.Errorf("settings touched for a subscription credential:\n%s", b)
	}
	if _, err := os.Stat(manifestPath(state, baseURLFragment)); !os.IsNotExist(err) {
		t.Error("a manifest was written for a refused apply")
	}
}

// A missing or unparseable proxy.port means nothing is listening. Fail closed:
// on this path "I could not tell" and "no" are the same answer.
func TestProxyPointerRefusesWhenNoProxyPublishedAPort(t *testing.T) {
	for _, port := range []string{"", "not-a-port", "0", "70000"} {
		home, state := apiKeyHome(t, userSettings, port)
		a := &Adapter{Home: home, StateDir: state}
		if _, err := a.ApplyProxyPointer(); !errors.Is(err, ErrNotEligible) {
			t.Errorf("port %q: err = %v, want ErrNotEligible", port, err)
		}
	}
}

// The case a TCP connect cannot see, and the reason the probe reads the body.
//
// proxy.port names an OS-chosen ephemeral port. When the proxy dies that port
// goes back to the pool, and the next local process to ask can be handed it —
// at which point the file is still there, still parses, and still names a live
// listener. Provisioning on "something answered" would write the developer's
// x-api-key straight to whatever that is.
func TestProxyPointerRefusesAListenerThatIsNotTheGuard(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
	}{
		{"a squatter that is happy to talk", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("hello"))
		}},
		// A 403 alone is not the fingerprint: plenty of local servers refuse an
		// unauthenticated GET, and one of them inheriting the port must not read
		// as our guard.
		{"a 403 without the guard's code", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
		}},
		// Right code, wrong answer: this is the shape a squatter reaches for if
		// it has read our docs, and it still must not be enough.
		{"the guard's code on a 200", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"error":{"code":"M1E-8001"}}`))
		}},
		// Accepts the connection and then says nothing. A liveness gate with no
		// budget hangs `mark1 enable` here; a timeout is a refusal like any other.
		{"a listener that never answers", func(http.ResponseWriter, *http.Request) {
			time.Sleep(2 * probeTimeout)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.h)
			t.Cleanup(srv.Close)
			port := srv.Listener.Addr().(*net.TCPAddr).Port
			home, state := apiKeyHome(t, userSettings, strconv.Itoa(port))

			a := &Adapter{Home: home, StateDir: state}
			if _, err := a.ApplyProxyPointer(); !errors.Is(err, ErrNotEligible) {
				t.Fatalf("err = %v, want ErrNotEligible", err)
			}
			// The refusal precedes the write, so the file is untouched.
			b, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
			if string(b) != userSettings {
				t.Errorf("settings written for a port held by something else:\n%s", b)
			}
			if _, err := os.Stat(manifestPath(state, baseURLFragment)); !os.IsNotExist(err) {
				t.Error("a manifest was written for a refused apply")
			}
		})
	}
}

func TestBaseURLRefusesToOverwriteAUserSetVariable(t *testing.T) {
	home, state := apiKeyHome(t, `{
  "env": { "ANTHROPIC_BASE_URL": "https://corp-gateway.example" }
}
`, liveProxy)
	a := &Adapter{Home: home, StateDir: state}
	_, err := a.ApplyProxyPointer()
	if !errors.Is(err, ErrEnvConflict) {
		t.Fatalf("err = %v, want ErrEnvConflict", err)
	}
	m := readJSON(t, filepath.Join(home, ".claude", "settings.json"))
	env := m["env"].(map[string]any)
	if env[envBaseURL] != "https://corp-gateway.example" {
		t.Errorf("the user's own base URL was rewritten: %#v", env[envBaseURL])
	}
}

// The rollback actuator's contract (04 §3.1 step 6): reverting the base-URL
// fragment puts the file back byte-for-byte and leaves nothing of ours behind.
func TestRevertBaseURLIsByteEqual(t *testing.T) {
	home, state := apiKeyHome(t, userSettings, liveProxy)
	a := &Adapter{Home: home, StateDir: state}
	if _, err := a.ApplyProxyPointer(); err != nil {
		t.Fatal(err)
	}
	res, err := RevertBaseURL(state)
	if err != nil {
		t.Fatalf("RevertBaseURL: %v", err)
	}
	if !res.ByteEquality {
		t.Error("revert did not restore byte-equality")
	}
	b, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if string(b) != userSettings {
		t.Errorf("settings not restored:\n--- got\n%s\n--- want\n%s", b, userSettings)
	}
	if _, err := os.Stat(manifestPath(state, baseURLFragment)); !os.IsNotExist(err) {
		t.Error("manifest survived the revert")
	}
	// Idempotent: `mark1 off` twice, and the contamination handler firing on a
	// session whose pointer is already gone, must both succeed.
	again, err := RevertBaseURL(state)
	if err != nil || again.Kind != "not-provisioned" {
		t.Errorf("second revert = %+v, %v", again, err)
	}
}

// A user who set their own base URL over ours owns those bytes now: 08 §8.1
// does not let us delete them, so the pointer stays and byte-equality is
// honestly false rather than quietly true.
//
// What must NOT happen is the rest of the old behaviour (D-CR): our checksum
// object deleted, our `M1-Cred-Ref` header left standing, and the manifest
// removed — our record erased while our footprint stays, so nothing can ever
// find the pointer again and `mark1 off` calls it a completed revert.
func TestRevertBaseURLLeavesAUserOverwriteAlone(t *testing.T) {
	home, state := apiKeyHome(t, userSettings, liveProxy)
	settings := filepath.Join(home, ".claude", "settings.json")
	a := &Adapter{Home: home, StateDir: state}
	if _, err := a.ApplyProxyPointer(); err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile(settings)
	edited := strings.Replace(string(cur), publishedURL(t, state), "https://mine.example", 1)
	if edited == string(cur) {
		t.Fatal("test did not edit anything")
	}
	if err := os.WriteFile(settings, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := RevertBaseURL(state)
	if err != nil {
		t.Fatal(err)
	}
	if res.ByteEquality {
		t.Error("byte_equality true after a user edit inside our pointers")
	}
	if res.Kind != "fragment-damaged" {
		t.Errorf("kind = %q, want fragment-damaged: the block could not be verified as ours", res.Kind)
	}
	if len(res.Retained) != 2 {
		t.Errorf("retained = %v, want both pointers named", res.Retained)
	}
	m := readJSON(t, settings)
	env := m["env"].(map[string]any)
	if env[envBaseURL] != "https://mine.example" {
		t.Errorf("the user's value was deleted: %#v", env[envBaseURL])
	}
	// Our header is still there, so our record of it must be too. Deleting the
	// checksum object here is what made the leftover unattributable.
	if _, ok := env[envHeaders]; !ok {
		t.Fatal("test premise gone: our header should still be in the file")
	}
	if _, ok := m[baseURLManagedKey]; !ok {
		t.Error("our checksum object was deleted while our header stayed — the leftover is now unattributable")
	}
	if _, err := os.Stat(manifestPath(state, baseURLFragment)); err != nil {
		t.Errorf("manifest deleted with our pointer still set: %v — `mark1 off` can never see it again", err)
	}
	// And `mark1 off` run again must still find it, not report a clean machine.
	again, err := RevertBaseURL(state)
	if err != nil || again.Kind != "fragment-damaged" {
		t.Errorf("second revert = %+v, %v; want it still reported", again, err)
	}
}

// The user took our block out by hand. Nothing of ours is left, so this is a
// success and must not nag: the manifest goes, and a later `mark1 off` says
// not-provisioned. This is the case that separates "cannot verify" from
// "verified there is nothing here" — collapsing them would make every run of
// `mark1 off` on a hand-cleaned machine exit 1 forever.
func TestRevertBaseURLAcceptsAHandRemovedBlock(t *testing.T) {
	home, state := apiKeyHome(t, userSettings, liveProxy)
	settings := filepath.Join(home, ".claude", "settings.json")
	a := &Adapter{Home: home, StateDir: state}
	if _, err := a.ApplyProxyPointer(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(userSettings), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := RevertBaseURL(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Retained) != 0 {
		t.Errorf("retained = %v on a file holding nothing of ours", res.Retained)
	}
	if !res.ByteEquality {
		t.Error("byte_equality false against a file identical to the pre-image")
	}
	if _, err := os.Stat(manifestPath(state, baseURLFragment)); !os.IsNotExist(err) {
		t.Error("manifest survived a revert with nothing left to revert")
	}
}

// The fragment names a ref-id the guard must already know, or the agent 403s on
// every request (04 §3.1 step 2).
func TestProxyPointerRegistersTheCredentialWithTheGuard(t *testing.T) {
	home, state := apiKeyHome(t, userSettings, liveProxy)
	a := &Adapter{Home: home, StateDir: state}
	if _, err := a.ApplyProxyPointer(); err != nil {
		t.Fatal(err)
	}
	reg, err := os.ReadFile(filepath.Join(state, "registry"))
	if err != nil {
		t.Fatalf("no registry: %v", err)
	}
	fields := strings.Fields(string(reg))
	if len(fields) != 2 || fields[0] != credRefID {
		t.Fatalf("registry = %q, want one `%s <hex>` line", reg, credRefID)
	}
	if raw, err := hex.DecodeString(fields[1]); err != nil || len(raw) != 32 {
		t.Errorf("fingerprint %q is not a 32-byte hex HMAC", fields[1])
	}
	for _, name := range []string{"guard.key", "registry"} {
		fi, err := os.Stat(filepath.Join(state, name))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS == "windows" {
			// POSIX mode bits do not exist here; owner-only on Windows is an
			// ACL, which nothing in the daemon sets yet — NFR-SECURITY-007
			// residual. Go reports every writable file as 0666.
			continue
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", name, fi.Mode().Perm())
		}
	}
	// Re-provisioning replaces the ref's line instead of growing the file.
	if _, err := a.ApplyProxyPointer(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(state, "registry"))
	if string(after) != string(reg) {
		t.Errorf("registry grew or changed on re-apply:\n%s\n%s", reg, after)
	}
}
