// FR-AGENT-014's BYOK proxy pointer (08 §5.5, 10 §3.3): Copilot's base URL
// is an OS environment variable with no fenceable config file, so there is
// nothing to fence into. Mark 1 writes an owned shell fragment under its own
// state tree and prints the one line the user adds to their shell profile by
// hand (CON-003: Mark 1 never edits a user's profile). Mechanism A in
// spirit — an owned file, apply = write, revert = delete — just rooted at
// <state>/env instead of the vendor's config dir.
package copilot

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// EnvDir is the pointer's own tree, never Copilot's config dir.
func EnvDir(stateDir string) string { return filepath.Join(stateDir, "env") }

// envFileName: PowerShell on Windows (Copilot's own shell there, and the
// only one `source` means nothing to), POSIX shell everywhere else.
func envFileName(goos string) string {
	if goos == "windows" {
		return "copilot.ps1"
	}
	return "copilot.sh"
}

// EnvFilePath is the owned pointer file for one OS. A plain function (not an
// Adapter method) so doctor and off can name it without constructing one.
func EnvFilePath(stateDir, goos string) string {
	return filepath.Join(EnvDir(stateDir), envFileName(goos))
}

// SourceLine is the ONE line `mark1 enable` prints — never written into a
// profile, only shown. `~` is cosmetic display only, never how the path is
// resolved.
func SourceLine(stateDir, goos string) string {
	path := EnvFilePath(stateDir, goos)
	if home, err := os.UserHomeDir(); err == nil {
		if rel, ok := strings.CutPrefix(path, home); ok && (rel == "" || rel[0] == filepath.Separator) {
			path = "~" + rel
		}
	}
	if goos == "windows" {
		return ". " + path
	}
	return "source " + path
}

func envFragment(url, goos string) []byte {
	if goos == "windows" {
		return []byte(fmt.Sprintf("# mark1 managed -- deleted by `mark1 off`; do not edit\n$env:COPILOT_PROVIDER_BASE_URL = %q\n", url))
	}
	return []byte(fmt.Sprintf("# mark1 managed -- deleted by `mark1 off`; do not edit\nexport COPILOT_PROVIDER_BASE_URL=%q\n", url))
}

// EnvManifestPath is this fragment's own §8.2 record, separate from the
// hooks fragment's: the two are applied and reverted independently, and a
// user who deletes ~/.copilot entirely must not strand the pointer's record
// or vice versa.
func EnvManifestPath(stateDir string) string {
	return filepath.Join(stateDir, "provisioned", "copilot", "env.manifest.json")
}

func loadEnvManifest(stateDir string) (Manifest, error) {
	b, err := os.ReadFile(EnvManifestPath(stateDir))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if json.Unmarshal(b, &m) != nil || m.PostImageHash == "" || m.Mechanism != "A" ||
		m.TargetPath == "" || !filepath.IsAbs(m.TargetPath) || filepath.Clean(m.TargetPath) != m.TargetPath {
		return Manifest{}, ErrManifestCorrupt
	}
	return m, nil
}

func writeEnvManifest(stateDir string, m Manifest) error {
	if err := os.MkdirAll(filepath.Dir(EnvManifestPath(stateDir)), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := EnvManifestPath(stateDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, EnvManifestPath(stateDir)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

const (
	// Same shape the claudecode base-URL fragment's guard probe checks
	// (rust/mark1-proxy/src/router.rs's frozen refusal for a request with no
	// M1-Cred-Ref). Duplicated rather than imported: adapters are peers, and
	// importing claudecode here to reach two unexported helpers would wire a
	// dependency between sibling packages neither owns.
	envGuardRefusalCode = "M1E-8001"
	envProbeTimeout     = 2 * time.Second
	envProbeBodyCap     = 4 << 10
)

var envProbeClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport: &http.Transport{
		DisableKeepAlives: true,
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: envProbeTimeout}).DialContext,
	},
}

// proxyPointerURL reads the port mark1-proxy published (the same
// <state>/proxy.port claudecode's ProxyPortPath names) and confirms
// something answering there is actually the guard, not an ephemeral port the
// kernel handed to an unrelated process after the proxy died — the same
// squatter concern claudecode's probe exists for, load-bearing here too
// because Copilot would otherwise send its real BYOK key to whatever holds
// the port.
func proxyPointerURL(stateDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, "proxy.port"))
	if err != nil {
		return "", err
	}
	port, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("%s does not hold a port", filepath.Join(stateDir, "proxy.port"))
	}
	url := "http://127.0.0.1:" + strconv.Itoa(port)
	if err := probeEnvProxy(url); err != nil {
		return "", err
	}
	return url, nil
}

func probeEnvProxy(url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), envProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/", nil)
	if err != nil {
		return err
	}
	res, err := envProbeClient.Do(req)
	if err != nil {
		return fmt.Errorf("nothing answered at %s: %w", url, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res.Body, envProbeBodyCap))
	if res.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte(envGuardRefusalCode)) {
		return fmt.Errorf("%s is held by something that is not a mark1-proxy guard: status %d, no %s", url, res.StatusCode, envGuardRefusalCode)
	}
	return nil
}

// ApplyEnvPointer is the eligibility gate and the only sanctioned caller of
// the env-fragment writer: WireCredential refuses a subscription regime, a
// providers.json-sourced credential (unconfirmed entry schema), and a
// GitHub-token-shaped value in the key slot (regime()); the guard probe
// refuses a dead or squatted port. Every refusal is ErrNotEligible — "I
// could not tell" and "no" are the same answer here, same as claudecode's.
func (a *Adapter) ApplyEnvPointer() (ApplyResult, error) {
	cred, err := a.WireCredential()
	if err != nil {
		return ApplyResult{}, err
	}
	_, state, err := a.paths()
	if err != nil {
		return ApplyResult{}, err
	}
	url, err := proxyPointerURL(state)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("%w: no proxy answered at the published port: %v", ErrNotEligible, err)
	}
	// Before the pointer, never after: with no M1-Cred-Ref the guard admits this key only by its fingerprint.
	if err := registerFingerprint(state, cred); err != nil {
		return ApplyResult{}, err
	}
	return applyEnvPointer(state, url, a.goos())
}

// credRefID: one agent, one registry line, as claudecode's.
const credRefID = "copilot"

// registerFingerprint is 10 §3.3 steps 1-2, duplicated from claudecode for the reason the probe above is.
func registerFingerprint(stateDir, cred string) error {
	key, err := guardKey(stateDir)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write([]byte(cred)); err != nil {
		return err
	}
	return putRegistryLine(stateDir, credRefID, hex.EncodeToString(mac.Sum(nil)))
}

func guardKey(stateDir string) ([]byte, error) {
	path := filepath.Join(stateDir, "guard.key")
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		return b, nil
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return os.ReadFile(path)
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(key); err != nil {
		return nil, err
	}
	return key, f.Close()
}

func putRegistryLine(stateDir, ref, fingerprint string) error {
	path := filepath.Join(stateDir, "registry")
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var out bytes.Buffer
	for _, line := range strings.Split(string(old), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), ref+" ") {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	out.WriteString(ref + " " + fingerprint + "\n")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return writeAtomic(path, out.Bytes(), 0o600)
}

func (a *Adapter) goos() string {
	if a.GOOS != "" {
		return a.GOOS
	}
	return runtime.GOOS
}

func applyEnvPointer(stateDir, url, goos string) (ApplyResult, error) {
	target := EnvFilePath(stateDir, goos)
	want := envFragment(url, goos)
	desired := sum(want)

	prior, perr := loadEnvManifest(stateDir)
	if perr != nil && !errors.Is(perr, os.ErrNotExist) {
		return ApplyResult{}, perr
	}
	cur, rerr := os.ReadFile(target)
	switch {
	case rerr != nil && !os.IsNotExist(rerr):
		return ApplyResult{}, rerr
	case rerr == nil && perr == nil && sum(cur) == prior.PostImageHash && prior.FragmentChecksum == desired:
		return ApplyResult{Changed: false, Mechanism: "A", Checksum: desired}, nil
	case rerr == nil && (perr != nil || sum(cur) != prior.PostImageHash) && sum(cur) != desired:
		// A file at our path we did not write, or ours edited by hand.
		return ApplyResult{}, ErrDamaged
	}

	m := Manifest{TargetPath: target, Mechanism: "A", PostImageHash: desired, FragmentChecksum: desired, URL: url,
		AppliedAt: time.Now().UTC().Format(time.RFC3339), AppliedBy: "mark1d"}
	if err := writeEnvManifest(stateDir, m); err != nil {
		return ApplyResult{}, err
	}
	if err := os.MkdirAll(EnvDir(stateDir), 0o700); err != nil {
		return ApplyResult{}, err
	}
	if err := writeAtomic(target, want, 0o600); err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{Changed: true, Mechanism: "A", Checksum: desired}, nil
}

// InspectEnvPointer classifies the owned pointer file without writing
// anything — the read half of `mark1 doctor`.
func InspectEnvPointer(stateDir string) (Status, error) {
	st := Status{Agent: "copilot", Fragment: "env", Manifest: EnvManifestPath(stateDir), State: StateMissing}
	m, err := loadEnvManifest(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		st.Detail = "not provisioned"
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.Target, st.Mechanism = m.TargetPath, m.Mechanism
	cur, err := os.ReadFile(m.TargetPath)
	if os.IsNotExist(err) {
		st.Detail = "target file no longer exists"
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if sum(cur) != m.PostImageHash {
		st.State, st.Detail = StateDamaged, CodeDamaged+": the owned file no longer matches its recorded checksum"
		return st, nil
	}
	st.State = StateOK
	return st, nil
}

// RevertEnvPointer is `mark1 off`/disable for this fragment: delete the
// owned file, manifest last — unless its bytes are not ours any more, in
// which case nothing is written and the manifest stays so doctor and the
// next `mark1 off` keep seeing it (08 §8.4 3b, mirrored from Revert).
func RevertEnvPointer(stateDir string) (RevertResult, error) {
	m, err := loadEnvManifest(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return RevertResult{Kind: "not-provisioned", ByteEquality: true}, nil
	}
	if err != nil {
		return RevertResult{}, err
	}
	res := RevertResult{Target: m.TargetPath}
	cur, rerr := os.ReadFile(m.TargetPath)
	switch {
	case os.IsNotExist(rerr):
		res.Kind, res.ByteEquality = "target-absent", true
	case rerr != nil:
		return res, rerr
	case sum(cur) != m.PostImageHash:
		res.Kind, res.Retained = "fragment-damaged", []string{m.TargetPath}
		return res, nil
	default:
		if err := os.Remove(m.TargetPath); err != nil && !os.IsNotExist(err) {
			return res, err
		}
		res.Kind, res.ByteEquality = "verbatim", true
	}
	if err := os.Remove(EnvManifestPath(stateDir)); err != nil && !os.IsNotExist(err) {
		return res, err
	}
	return res, nil
}

// The three states 08 §5.5's doctor row names: the manifest is the only
// record of what was ever applied, and the live process environment (the
// user's shell, if `mark1 doctor` runs inside it) is the only signal for
// whether sourcing actually happened.
const (
	PointerActive            = "active"
	PointerWrittenNotSourced = "written, not sourced"
	PointerAbsent            = "absent"
)

// EnvPointerLiveState is doctor's byok-pointer row: whether the fragment was
// ever applied, and whether ITS process environment — the user's shell, if
// they sourced the printed line into it — currently carries the exact URL
// that was written. getenv nil defaults to os.Getenv; a test seam, not a
// production knob.
func EnvPointerLiveState(stateDir string, getenv func(string) string) string {
	if getenv == nil {
		getenv = os.Getenv
	}
	m, err := loadEnvManifest(stateDir)
	if err != nil || m.URL == "" {
		return PointerAbsent
	}
	if getenv("COPILOT_PROVIDER_BASE_URL") == m.URL {
		return PointerActive
	}
	return PointerWrittenNotSourced
}
