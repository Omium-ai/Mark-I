// Package selfupdate is `mark1 update` (09 §11.2, FR-POLICY-009): the one door a self-update may pass. Allowed is its only entry; the artifact goes through verifyrelease.Run — the same verifier as `mark1 verify-release`, never a second one — before a byte of it lands under the install dir.
// ponytail: the manifest itself is TLS-trusted, not update-key-signed (FR-POLICY-003's main.go wiring is still owed); monotonic manifest_seq is persisted so a replayed CDN object cannot roll a client back.
package selfupdate

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/service"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/verifyrelease"
)

// ProfileEnv is the fleet profile mark1d already reads (anchors E2 gating); "managed" is what an MDM-provisioned install sets.
const ProfileEnv = "MARK1_PROFILE"

// Allowed reports whether a self-update may proceed and, when not, why.
func Allowed() (bool, string) {
	if os.Getenv(ProfileEnv) == "managed" {
		return false, "self-update is off on managed fleets (MARK1_PROFILE=managed, 08 §10.1)"
	}
	return true, ""
}

// DefaultManifestURL is the CDN-served update manifest of 09 §11.2; --manifest overrides it.
const DefaultManifestURL = "https://releases.mark1.omium.ai/edge/manifest.json"

// Manifest is the update manifest: monotonic seq, a version per ring, and per version the artifact for each goos/goarch.
type Manifest struct {
	ManifestSeq uint64                         `json:"manifest_seq"`
	Rings       map[string]string              `json:"rings"`
	Artifacts   map[string]map[string]Artifact `json:"artifacts"`
}

// Artifact is one release tarball (the release.yml shape: flat binaries) and where its Sigstore bundle lives (default <url>.sigstore.json).
type Artifact struct {
	URL        string `json:"url"`
	SHA256     string `json:"sha256"`
	Provenance string `json:"provenance,omitempty"`
}

type Options struct {
	Check      bool
	Manifest   string
	InstallDir string // default: the directory this executable runs from
	Ring       string // default: the enrollment channel, else stable
	Socket     string // test seam
}

type Result struct {
	OK              bool     `json:"ok"`
	Ring            string   `json:"ring"`
	ManifestSeq     uint64   `json:"manifest_seq"`
	Current         string   `json:"current"`
	Available       string   `json:"available"`
	UpdateAvailable bool     `json:"update_available"`
	Applied         bool     `json:"applied"`
	InstallDir      string   `json:"install_dir,omitempty"`
	Swapped         []string `json:"swapped,omitempty"`
	Daemon          string   `json:"daemon,omitempty"` // restarted | not running
	Note            string   `json:"note,omitempty"`
}

// verify is the FR-POLICY-009 gate. Tests make it fail; nothing may replace it with a second implementation.
var verify = verifyrelease.Run

var stopTimeout = 15 * time.Second

var binaries = []string{"mark1d", "mark1", "mark1-proxy", "mark1-hookshim", "cortexd"}

// ponytail: package-manager ownership by prefix (09 §11.2: notified, never overwritten); a receipt/db lookup per manager is the upgrade.
var managedPrefixes = []string{"/usr/bin", "/usr/lib", "/usr/local/Cellar", "/opt/homebrew", "/home/linuxbrew", `C:\Program Files`}

func Run(ctx context.Context, env *cli.Env, opts Options) error {
	if ok, why := Allowed(); !ok {
		return cli.Failf(cli.ExitRefused, "", "%s", why)
	}
	url := opts.Manifest
	if url == "" {
		url = DefaultManifestURL
	}
	m, err := fetchManifest(ctx, env, url)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "update manifest %s: %v", url, err)
	}
	seqPath := filepath.Join(env.StateDir, "update", "manifest_seq")
	if last := readSeq(seqPath); m.ManifestSeq < last {
		return cli.Failf(cli.ExitRefused, "", "manifest_seq %d is below the last applied %d — refusing a replayed manifest (09 §11.2)", m.ManifestSeq, last)
	}
	ring := opts.Ring
	if ring == "" {
		ring = "stable"
		if doc, err := env.LoadEnrollment(); err == nil && doc.Channel != "" {
			ring = doc.Channel
		}
	}
	version, ok := m.Rings[ring]
	if !ok {
		return cli.Failf(cli.ExitRuntime, "", "manifest names no version for ring %q", ring)
	}
	res := Result{OK: true, Ring: ring, ManifestSeq: m.ManifestSeq, Current: env.Version, Available: version, UpdateAvailable: version != env.Version}
	if opts.Check || !res.UpdateAvailable {
		return emit(env, res)
	}

	platform := runtime.GOOS + "/" + runtime.GOARCH
	art, ok := m.Artifacts[version][platform]
	if !ok {
		return cli.Failf(cli.ExitRuntime, "", "manifest has no %s artifact for %s", platform, version)
	}
	dir, err := installDir(opts.InstallDir)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	for _, p := range managedPrefixes {
		if strings.HasPrefix(dir, p) {
			return cli.Failf(cli.ExitRefused, "", "%s is owned by a package manager — update through it, not `mark1 update` (09 §11.2)", dir)
		}
	}
	st, err := service.Live(env, opts.Socket)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	if st.Running && !st.Registered {
		return cli.Failf(cli.ExitRefused, "", "mark1d is running but not registered with `mark1 service install` — stop it first, the updater cannot restart what it did not start")
	}
	if n := liveSessions(env.StateDir); st.Running && n > 0 {
		return cli.Failf(cli.ExitRefused, "", "%d agent session(s) live under mark1d — retry when they end (a mid-session swap would lose the session)", n)
	}

	work := filepath.Join(dir, ".update")
	if err := errors.Join(os.RemoveAll(work), os.MkdirAll(work, 0o700)); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "install dir %s: %v", dir, err)
	}
	defer func() { _ = os.RemoveAll(work) }()
	archive := filepath.Join(work, filepath.Base(art.URL))
	if err := download(ctx, env, art.URL, archive, art.SHA256); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "download %s: %v", art.URL, err)
	}
	prov := art.Provenance
	if prov == "" {
		prov = art.URL + ".sigstore.json"
	}
	provPath := archive + ".sigstore.json"
	if err := download(ctx, env, prov, provPath, ""); err != nil {
		return cli.Failf(cli.ExitVerify, "", "provenance_missing: %s: %v", prov, err)
	}
	quiet := &cli.Env{StateDir: env.StateDir, Stdout: io.Discard, Stderr: env.Stderr, Quiet: true, HTTP: env.HTTP}
	if err := verify(quiet, verifyrelease.Options{Artifact: archive, Provenance: provPath}); err != nil {
		return err
	}
	stage := filepath.Join(work, "stage")
	staged, err := extract(archive, stage)
	if err != nil {
		return cli.Failf(cli.ExitVerify, "", "release archive: %v", err)
	}

	res.Daemon = "not running"
	if st.Running {
		if err := service.Stop(quiet, service.Options{Socket: opts.Socket}); err != nil {
			return err
		}
		if !service.WaitStopped(env, opts.Socket, stopTimeout) {
			return cli.Failf(cli.ExitRuntime, "", "mark1d did not stop within %s; nothing swapped", stopTimeout)
		}
	}
	res.Swapped, err = swap(dir, stage, staged)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "swap: %v (previous binaries restored)", err)
	}
	if st.Running {
		if err := service.Start(quiet, service.Options{Socket: opts.Socket}); err != nil {
			return err
		}
		res.Daemon = "restarted"
	}
	if err := cli.WriteFileAtomic(seqPath, []byte(strconv.FormatUint(m.ManifestSeq, 10)), 0o600); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "recording manifest_seq: %v", err)
	}
	res.Applied, res.InstallDir = true, dir
	if runtime.GOOS == "windows" {
		res.Note = "the running mark1.exe cannot be replaced: it was renamed to mark1.exe.old and the new one placed beside it; the .old is removed on the next update"
	}
	return emit(env, res)
}

func emit(env *cli.Env, res Result) error {
	return env.Emit(res, func(w io.Writer) {
		switch {
		case res.Applied:
			_, _ = fmt.Fprintf(w, "updated %s -> %s (%s ring, manifest_seq %d): %s under %s; mark1d %s\n", res.Current, res.Available, res.Ring, res.ManifestSeq, strings.Join(res.Swapped, " "), res.InstallDir, res.Daemon)
			if res.Note != "" {
				_, _ = fmt.Fprintln(w, res.Note)
			}
		case res.UpdateAvailable:
			_, _ = fmt.Fprintf(w, "update available: %s -> %s (%s ring, manifest_seq %d); run `mark1 update` to apply\n", res.Current, res.Available, res.Ring, res.ManifestSeq)
		default:
			_, _ = fmt.Fprintf(w, "up to date: %s (%s ring, manifest_seq %d)\n", res.Current, res.Ring, res.ManifestSeq)
		}
	})
}

func fetchManifest(ctx context.Context, env *cli.Env, url string) (*Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Mark1-Edge-Version", env.Version)
	resp, err := env.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

func readSeq(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return n
}

func installDir(explicit string) (string, error) {
	if explicit != "" {
		return filepath.Abs(explicit)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(exe), nil
}

// liveSessions counts <state>/run/sessions/*.json — the daemon's own live-session files (go/mark1d/internal/cortex: written at SessionStart under an enabled root, removed at SessionEnd, cleared at boot). Restated by path because that package is module-private.
func liveSessions(stateDir string) int {
	files, _ := filepath.Glob(filepath.Join(stateDir, "run", "sessions", "*.json"))
	return len(files)
}

// download streams url to path; a non-empty wantHex must equal the SHA-256 of the bytes (the manifest's own digest, checked before the verifier spends a signature check).
func download(ctx context.Context, env *cli.Env, url, path, wantHex string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := env.Client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); wantHex != "" && got != wantHex {
		return fmt.Errorf("sha256 %s does not match the manifest's %s", got, wantHex)
	}
	return nil
}

// extract unpacks the flat release tarball into dir, refusing anything that is not one of ours: a member outside the binary set is not a release we built.
func extract(archive, dir string) ([]string, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	var out []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(filepath.ToSlash(hdr.Name), "./")
		if hdr.Typeflag == tar.TypeDir && (name == "" || name == ".") {
			continue
		}
		if hdr.Typeflag != tar.TypeReg || !isBinary(name) {
			return nil, fmt.Errorf("unexpected member %q (type %c)", hdr.Name, hdr.Typeflag)
		}
		dst := filepath.Join(dir, name)
		w, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755) //nolint:gosec // G302: executables
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(w, tr) //nolint:gosec // G110: the release tarball is our own, digest- and provenance-checked above
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil, errors.New("archive carries none of the edge binaries")
	}
	return out, nil
}

func isBinary(name string) bool {
	for _, b := range binaries {
		if name == b || (runtime.GOOS == "windows" && name == b+".exe") {
			return true
		}
	}
	return false
}

// swap renames every staged binary into place (cur -> cur.old, staged -> cur), rolling back the ones already moved if any step fails. Rename-swap, never write-in-place: a reader always sees a whole file.
func swap(dir, stage string, names []string) ([]string, error) {
	var done []string
	rollback := func() {
		for _, n := range done {
			cur := filepath.Join(dir, n)
			_ = os.Rename(cur, filepath.Join(stage, n))
			_ = os.Rename(cur+".old", cur)
		}
	}
	for _, n := range names {
		cur := filepath.Join(dir, n)
		_ = os.Remove(cur + ".old")
		if err := os.Rename(cur, cur+".old"); err != nil && !errors.Is(err, os.ErrNotExist) {
			rollback()
			return nil, err
		}
		if err := os.Rename(filepath.Join(stage, n), cur); err != nil {
			_ = os.Rename(cur+".old", cur)
			rollback()
			return nil, err
		}
		done = append(done, n)
	}
	for _, n := range done {
		_ = os.Remove(filepath.Join(dir, n+".old")) // fails only for the running mark1.exe on Windows; the next update clears it
	}
	return done, nil
}
