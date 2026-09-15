// Package cli is the shared substrate under the seven mark1 subcommands
// (08 §7 global contract): wire-stable exit codes, the one-JSON-object
// stdout rule, state-dir layout under ~/.omium/mark1 (04 §2), and the
// 0600/0700 custody floor the daemon's identity package established —
// mark1d and controld are talked to via files and HTTP only, never
// imported (their internal/ trees are module-private by design).
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

// Exit codes, 08 §7 global contract — scripts and MDM key on these.
const (
	ExitOK          = 0
	ExitRuntime     = 1 // network, daemon unreachable where required, I/O
	ExitUsage       = 2
	ExitNotEnrolled = 3 // M1E-1xxx class
	ExitRefused     = 4 // refused by design (coverage floor, consent, M1E-5xxx)
	ExitVerify      = 5 // verify-receipts found a chain defect
)

// DefaultServer is the control-plane base of 08 §3 ("all under
// https://api.mark1.omium.ai/api/v1/…").
const DefaultServer = "https://api.mark1.omium.ai"

// ExitError carries the wire-stable exit code plus the M1E taxonomy code
// (08 §9) when one names this failure; --json renders it as the global
// contract's {"ok":false,"error":{code,message}} object.
type ExitError struct {
	Code int
	M1E  string // "" when no taxonomy row applies; --json then carries the exit class
	Msg  string
	// Emitted: the subcommand already printed its (partial-result) object —
	// main must not print a second one, or the one-JSON-object rule breaks.
	Emitted bool
}

func (e *ExitError) Error() string {
	if e.M1E != "" {
		return e.M1E + ": " + e.Msg
	}
	return e.Msg
}

// Failf builds the one error shape every subcommand returns; cmd/main.go
// maps anything else (cobra flag/arg noise) to ExitUsage.
func Failf(code int, m1e, format string, a ...any) *ExitError {
	msg := fmt.Sprintf(format, a...)
	// The M1E slot is parsed by customer scripts (08 §9), and five sites hand
	// it the control plane's own error.code straight out of APIError. A server
	// that sends free text there must not put free text into --json: keep the
	// string for the human in the message and let EmitError fall back to the
	// exit class, which is the documented meaning of an empty code.
	if m1e != "" && !m1eShape.MatchString(m1e) {
		msg = fmt.Sprintf("%s (server error code %q is not an M1E code)", msg, m1e)
		m1e = ""
	}
	return &ExitError{Code: code, M1E: m1e, Msg: msg}
}

// m1eShape is 08 §9's code grammar. The exit-code test carries its own copy on
// purpose: an oracle that reads the production regexp cannot catch it loosening.
var m1eShape = regexp.MustCompile(`^M1E-\d{4}$`)

// Env is the per-invocation world: injected so every subcommand test runs
// against a temp state dir, an httptest server, and captured writers.
type Env struct {
	StateDir string
	Server   string // explicit override; empty falls back to enrollment doc, then DefaultServer
	JSON     bool
	Quiet    bool
	Stdout   io.Writer
	Stderr   io.Writer
	HTTP     *http.Client
	Version  string // ldflags-injected; client_version in 08 §3.1
}

func (e *Env) Client() *http.Client {
	if e.HTTP != nil {
		return e.HTTP
	}
	return http.DefaultClient
}

// DefaultStateDir is the daemon's state root (04 §2: ~/.omium/mark1) — the
// CLI and mark1d must agree byte-for-byte or the OFF marker (08 §7.6) and
// enrollment doc land where nothing reads them.
func DefaultStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("no resolvable home directory: %w", err)
	}
	return filepath.Join(home, ".omium", "mark1"), nil
}

// State-dir filenames. OFF must equal go/mark1d/internal/off.Marker's name
// and rust/mark1-hookshim's ".omium/mark1/OFF" — the kill switch is the
// byte equality of this string across three codebases.
func (e *Env) OffMarkerPath() string  { return filepath.Join(e.StateDir, "OFF") }
func (e *Env) EnrollmentPath() string { return filepath.Join(e.StateDir, "enrollment.json") }
func (e *Env) DeviceKeyPath() string  { return filepath.Join(e.StateDir, "device.key") }
func (e *Env) WorkspacesPath() string { return filepath.Join(e.StateDir, "workspaces.json") }
func (e *Env) CoveragePath() string {
	return filepath.Join(e.StateDir, "coverage", "transitions.jsonl")
}
func (e *Env) ConsentPath() string    { return filepath.Join(e.StateDir, "consent.jsonl") }
func (e *Env) AnchorsCatalog() string { return filepath.Join(e.StateDir, "anchors", "catalog.json") }
func (e *Env) ProvisionedDir() string { return filepath.Join(e.StateDir, "provisioned") }
func (e *Env) BundleMetaPath() string { return filepath.Join(e.StateDir, "bundle", "meta.json") }
func (e *Env) SpoolDir() string       { return filepath.Join(e.StateDir, "spool") }
func (e *Env) QuarantineDir() string  { return filepath.Join(e.StateDir, "quarantine") }

// KeyCustody names the rung of 04 §2.9's ladder the device key actually sits
// on — keychain/TPM where available, the 0600 file floor otherwise — and, when
// it is not the top rung, why. NFR-PORTABILITY-004: the ladder is allowed to
// degrade, it is not allowed to degrade quietly, so `mark1 status` prints both.
//
// The degradation may never claim a probe that never ran. "keychain
// unavailable" would be a lie today — nothing looks for a keychain, because no
// rung above the floor is compiled in — and that lie is worse than silence: it
// blames the operator's platform for a rung we have not built.
//
// ponytail: the floor is duplicated in go/mark1d/internal/identity.FileCustody,
// which internal/ puts out of this module's reach. A real rung lands in both at
// once regardless — enroll mints the key here, the daemon adopts it there.
func KeyCustody() (tier, degradation string) {
	return "file", "no keychain/TPM rung is compiled into this build; the device key is a 0600 file under the state dir"
}

// WriteFileAtomic is 08 §7.6's "atomically": temp file in the target's own
// directory (rename never crosses a filesystem) + fsync + rename. Parent
// dirs are created 0700 — the state dir never carries a group/world grant.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	// fsync before rename: a marker that exists but is empty after a crash
	// still switches the daemon off (stat-only check), but the enrollment
	// doc and allow-list must never be readable-but-truncated.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// readPrivate loads a file refusing group/world-readable modes — the same
// honest refusal as mark1d identity.FileCustody: a leaked credential file
// is not proof the credential still only answers for this user. Windows
// permission bits are decoration; the check is unix-only there too.
func readPrivate(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %o; must be 0600 — refusing to read it", path, fi.Mode().Perm())
	}
	return os.ReadFile(path)
}

// ErrNotEnrolled maps to exit 3 (M1E-1002: device token missing).
var ErrNotEnrolled = errors.New("not enrolled — run `mark1 enroll`")

// Enrollment states the CLI can know about. ACTIVE is the server's poll
// verdict (08 §3.1); EXPIRED is derived locally from token_expires_at;
// REVOKED is stamped by NoteAuthRefusal when any device-token call meets the
// server's 401/M1E-1003 verdict. There is no local "deleted": revocation is
// columns, not deletion, server-side (m1_001 m1_devices — the row must keep
// existing so historical receipts stay attributable), and the same posture
// holds here: the doc is restated, never removed, until a fresh enrollment
// overwrites it.
const (
	StateActive  = "active"
	StateExpired = "expired"
	StateRevoked = "revoked"
)

// Enrollment is the document 08 §7.1 persists under ~/.omium/mark1/ (0600):
// the poll response of §3.1 plus what the CLI needs to talk to the control
// plane again. device_id/tenant_id are informational — never trusted by the
// server later (§3.1).
type Enrollment struct {
	Version        int       `json:"version"`
	State          string    `json:"state"` // StateActive/StateRevoked; expiry is derived, see LiveState
	DeviceID       string    `json:"device_id"`
	TenantID       string    `json:"tenant_id"`
	DeviceToken    string    `json:"device_token"`
	TokenExpiresAt time.Time `json:"token_expires_at"` // ≤24h per §3.1
	Server         string    `json:"server"`
	Channel        string    `json:"channel"`
	ServerMinEdge  string    `json:"server_min_edge,omitempty"`
	KeyManifestURI string    `json:"key_manifest_uri,omitempty"`
	Endpoints      struct {
		Ingest       string `json:"ingest,omitempty"`
		Attach       string `json:"attach,omitempty"`
		PolicyStream string `json:"policy_stream,omitempty"`
	} `json:"endpoints"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// LiveState is the honest state for the status/enroll surfaces (08 §7.1,
// §7.3): a stamped REVOKED is terminal until re-enrollment; an otherwise-
// active doc whose ≤24 h device token (08 §3.1) passed token_expires_at is
// EXPIRED — the stored doc alone must never claim ACTIVE past its own expiry.
func (d *Enrollment) LiveState(now time.Time) string {
	if d.State == StateRevoked {
		return StateRevoked
	}
	if !now.Before(d.TokenExpiresAt) {
		return StateExpired
	}
	return d.State
}

// NoteAuthRefusal persists what a device-token call just learned from the
// server: M1E-1003 ("device revoked", 08 §9) stamps REVOKED, any other 401
// stamps EXPIRED — so `mark1 status` and a re-run of `mark1 enroll` surface
// the recovery path (fresh enrollment, new key) instead of claiming ACTIVE
// forever. Best-effort by design: the caller's auth error is the primary
// fact and surfaces regardless; a failed stamp only warns on stderr.
func (e *Env) NoteAuthRefusal(status int, m1eCode string) {
	var state string
	switch {
	case m1eCode == "M1E-1003":
		state = StateRevoked
	case status == http.StatusUnauthorized:
		state = StateExpired
	default:
		return // 403 without M1E-1003 (e.g. M1E-1005 policy denial) says nothing about the enrollment
	}
	doc, err := e.LoadEnrollment()
	if err != nil || doc.State == state {
		return
	}
	doc.State = state
	if err := e.SaveEnrollment(doc); err != nil {
		_, _ = fmt.Fprintf(e.Stderr, "mark1: could not record enrollment state %q: %v\n", state, err)
	}
}

func (e *Env) LoadEnrollment() (*Enrollment, error) {
	data, err := readPrivate(e.EnrollmentPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	var doc Enrollment
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", e.EnrollmentPath(), err)
	}
	return &doc, nil
}

func (e *Env) SaveEnrollment(doc *Enrollment) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(e.EnrollmentPath(), data, 0o600)
}

// BaseURL resolves the control-plane base: explicit flag > enrollment doc >
// the 08 §3 default. Enrollment absence is not an error here — enroll
// itself has no doc yet.
func (e *Env) BaseURL() string {
	if e.Server != "" {
		return e.Server
	}
	if doc, err := e.LoadEnrollment(); err == nil && doc.Server != "" {
		return doc.Server
	}
	return DefaultServer
}

// Workspaces is the on-disk allow-list `mark1 enable` writes and the
// tailers' WorkspaceSet consults (04 §0.3 invariant 3: workspaces are DATA,
// not processes). This struct DEFINES the format; mark1d consumes it
// byte-compatibly (tailers.LoadWorkspacesFile) and reloads it live — a field
// change here is a cross-binary contract change. Paths are canonicalized
// (abs + symlinks resolved) before they land here, the same
// canonicalize-then-check discipline as 04 §11.
type Workspaces struct {
	Version    int              `json:"version"`
	Workspaces []WorkspaceEntry `json:"workspaces"`
}

type WorkspaceEntry struct {
	Path      string    `json:"path"`
	EnabledAt time.Time `json:"enabled_at"`
}

func (e *Env) LoadWorkspaces() (*Workspaces, error) {
	data, err := readPrivate(e.WorkspacesPath())
	if errors.Is(err, os.ErrNotExist) {
		return &Workspaces{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	var ws Workspaces
	if err := json.Unmarshal(data, &ws); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", e.WorkspacesPath(), err)
	}
	return &ws, nil
}

func (e *Env) SaveWorkspaces(ws *Workspaces) error {
	data, err := json.MarshalIndent(ws, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(e.WorkspacesPath(), data, 0o600)
}

// AppendCoverageTransition journals one enable/disable window locally (0600)
// for mark1d to receipt.
//
// The journal is the handoff, not a substitute for the receipt. 08 §7.6 is
// categorical that `off` works with the daemon down and the network down —
// "there is no server round-trip on the critical path" — so the CLI cannot be
// the thing that signs, and it holds no device key to sign with. mark1d drains
// this file (coverage.DrainJournal) and emits the per-event-receipted
// CoverageTransition of 08 §7.2/§7.6 step 4 through its own capture pipeline,
// where the device key lives. Residual, stated plainly: between this write and
// that drain the line is a file its owner can edit; the receipt chain makes
// every DRAINED transition tamper-evident, which bounds the window rather than
// closing it.
//
// The reason_code is stamped HERE, from the kind, because 04 §2.7's vocabulary
// is frozen at seven values and this command owns exactly two of them. A kind
// outside that pair is refused rather than journalled: mark1d cannot receipt a
// line it cannot classify, so a silent typo would cost the window entirely.
func (e *Env) AppendCoverageTransition(rec map[string]any) error {
	switch rec["kind"] {
	case "enable":
		rec["reason"] = "user_enable"
	case "disable":
		rec["reason"] = "mark1_off"
	default:
		return fmt.Errorf("coverage transition kind %v is not one of 04 §2.7's CLI codes (enable, disable)", rec["kind"])
	}
	return appendJSONL(e.CoveragePath(), rec)
}

// Consent is one line of <state>/consent.jsonl: the record FR-CLI-002 names
// ("enable is per-workspace, consent-recording") for the consent 03 §2 gives
// the developer authority over — this OS user admitted this workspace root to
// the read surface, at this time, and the §8 fragments provisioned in the same
// act. The allow-list is the live oracle and is rewritten in place, so it can
// carry the current roots but never the history of who consented to them; the
// journal is append-only, 0600, one object per FIRST enable of a root. Anchor
// consent (08 §7.2 anchors_consented) is a different subject with its own
// store (04 §2.2 anchors/catalog.json, written by mark1d) and is not here.
type Consent struct {
	TS        string `json:"ts"`
	User      string `json:"user,omitempty"` // OS account; absent when the platform cannot say, never guessed
	UID       string `json:"uid,omitempty"`
	Workspace string `json:"workspace"`
	// AgentsProvisioned names the agents whose config carries our fragment
	// after this enable — empty when every adapter refused (M1E-71xx), which is
	// itself the fact: consent to read, nothing yet capturing.
	AgentsProvisioned []string `json:"agents_provisioned"`
}

// AppendConsent journals one Consent (see the type for what and why).
func (e *Env) AppendConsent(c Consent) error {
	return appendJSONL(e.ConsentPath(), c)
}

// appendJSONL is the one append-only journal writer under the state dir:
// parent 0700, file 0600, one JSON object per line.
func appendJSONL(path string, rec any) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	// A close error on an appended journal is the write's real error surfacing
	// late; swallowing it would report a line that never hit the disk.
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	return err
}

// SocketPath mirrors 07 §5's transport endpoint (the resolution mark1d's
// fabric.Listen binds): $XDG_RUNTIME_DIR/omium-mark1/m1p.sock, else
// ~/.omium/mark1/m1p.sock. Restated here because mark1d/internal is
// module-private; the string, not the code, is the contract.
// ponytail: unix only — the Windows named pipe rides mark1d's own row.
func SocketPath() (string, error) {
	if rd := os.Getenv("XDG_RUNTIME_DIR"); rd != "" {
		return filepath.Join(rd, "omium-mark1", "m1p.sock"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".omium", "mark1", "m1p.sock"), nil
}

// DaemonReachable answers "is mark1d accepting on the fabric right now?" —
// the only live read surface the daemon exposes today (its counter/gauge
// query frame is a later row; 04 §2.11). A dial, not a handshake: connect
// then close is enough to distinguish running from gone.
func DaemonReachable(socket string) bool {
	conn, err := net.DialTimeout("unix", socket, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Emit prints the one-JSON-object-on-stdout contract (08 §7 global) when
// --json, else hands off to the human renderer. v must already carry
// "ok": true — shapes are per-subcommand contracts.
func (e *Env) Emit(v any, human func(w io.Writer)) error {
	if e.JSON {
		enc := json.NewEncoder(e.Stdout)
		return enc.Encode(v)
	}
	if !e.Quiet {
		human(e.Stdout)
	}
	return nil
}

// EmitError renders a failing invocation: --json gets the global contract's
// error object on stdout; humans get stderr. Exit code travels separately.
func (e *Env) EmitError(ee *ExitError) {
	if e.JSON {
		code := ee.M1E
		if code == "" {
			code = exitClass(ee.Code)
		}
		obj := map[string]any{
			"ok":    false,
			"error": map[string]string{"code": code, "message": ee.Msg},
		}
		if err := json.NewEncoder(e.Stdout).Encode(obj); err != nil {
			// stdout is gone; the exit code still carries the verdict, but say
			// so on stderr rather than exiting silently on a lost error object.
			_, _ = fmt.Fprintln(e.Stderr, "mark1:", ee.Error())
		}
		return
	}
	_, _ = fmt.Fprintln(e.Stderr, "mark1:", ee.Error())
}

func exitClass(code int) string {
	switch code {
	case ExitUsage:
		return "usage"
	case ExitNotEnrolled:
		return "not_enrolled"
	case ExitRefused:
		return "refused"
	case ExitVerify:
		return "verification_failure"
	default:
		return "runtime"
	}
}

// APIError decodes the server's {"error":{"code","message"}} body (08 §9
// reading rules: HTTP responses carry the code machine-readably).
func APIError(resp *http.Response) (code, msg string) {
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if json.Unmarshal(data, &body) == nil && body.Error.Code != "" {
		return body.Error.Code, body.Error.Message
	}
	return "", string(data)
}

// CanonicalPath is 04 §11's canonicalize-then-check: absolute, symlinks
// resolved — the same normalization tailers.WorkspaceSet applies, so the
// allow-list entry equals what the oracle will compare against.
func CanonicalPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return abs, nil
}
