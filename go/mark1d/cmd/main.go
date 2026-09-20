// mark1d — the edge daemon. C8 wires the capture path: fabric UDS listener →
// capture admission → spool (single writer), plus the claudecode transcript
// tailer for one enabled workspace, plus the uplink drain (04 §2.5) when an
// ingest endpoint is configured, plus the 04 §2.3 verdict plane: the fusion
// Engine (sole cache writer), the anchor-vote tee that feeds it, and the Gate
// the fabric answers GateQuery from — fed by the 04 §2.2 anchor plane, whose
// scheduler is subscribed to the live ToolUse stream here, plus the 04 §9.4
// policy-bundle client (FR-POLICY-004): custody, ETag poll + SSE hint, verify,
// and the atomic matrices swap into the verdict plane. Supervision of children
// remains its own row (04 §2); nothing here fakes it.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/codex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/copilot"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/gemini"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/opencode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/bundle"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/control"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/cortex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/evidence"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/harden"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/judge"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/memory"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/receipt"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/route"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spill"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/supervise"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/taskseg"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/uplink"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// Injected at release via -ldflags "-X main.version=..." (13 §9: images are
// <sha7>, `latest` appears nowhere).
var version = "0.0.0-dev"

// spillDrainEvery paces the spill-ring drain between the startup scan and the
// (not-yet-landed) Hello handshake's ring-non-empty hint (04 §5): frequent
// enough that a recovered daemon replays within a minute, cheap when empty
// (one stat of a missing file).
const spillDrainEvery = 30 * time.Second

// coverageDrainEvery paces the CLI transition-journal drain (04 §2.7). Cheap
// when idle (one open of a file whose tail is already consumed), and the
// latency it costs is the gap between `mark1 off` and that window being
// receipted — bounded, not open-ended.
const coverageDrainEvery = 5 * time.Second

// dropGateTimeout is m1p.v1.DROP_REASON_GATE_TIMEOUT (envelope.proto = 5),
// numbered here for the same reason capture numbers LOCAL_QUARANTINE locally:
// spool.DropReason mirrors the proto enum and only names the rows it raises
// itself. Class is diagnostic — a fail-open gate answer loses no billable
// event, it loses a decision (11 §2.3's ledger line).
const dropGateTimeout spool.DropReason = 5

// dropE1ConsentAbsent reuses DROP_REASON_LOCAL_QUARANTINE (= 4): the admission door refused an E1 excerpt because the Step-4 consent is absent; the enum has no consent row.
const dropE1ConsentAbsent spool.DropReason = 4

// dropUnsupportedAgentVersion is m1p.v1.DROP_REASON_UNSUPPORTED_AGENT_VERSION
// (envelope.proto = 3), raised when the transcript surface is refused because
// the agent's version has no fixture. Class is BILLING-grade, unlike the gate
// timeout above: what is lost is Usage, and the whole point of the refusal is
// that those events are the ones we must never get wrong quietly.
//
// Quantity is 1 and means one refused SURFACE, not one lost event — the count
// is unknowable from here, since the refusal is what stops us reading the
// stream that would have told us. The honest quantity arrives with the
// coverage bypass 04 §10 F-12 pairs with this row, which is still owed.
const dropUnsupportedAgentVersion spool.DropReason = 3

type config struct {
	stateDir string
	flags    identityFlags // the flag-set identity, kept so a re-read of the enrollment document overrides only what flags did not
	flagsSet bool
	spoolDir string
	// spoolCap is 07 §6's spool byte cap (spool.DefaultCap, ~2 GiB); zero
	// takes the spool's default. The only operator-visible spool limit: past
	// it diagnostics shed (accounted DROP_REASON_SPOOL_SHED, FR-SPINE-007)
	// and billing-grade blocks. The 95 % disk hard stop is deliberately NOT a
	// flag (see diskUsage below).
	spoolCap  int64
	socket    string
	workspace string
	// backfillWindow bounds a first tail's history import (tailers.BackfillWindow); 0 imports every line, for replays of transcripts stamped long ago.
	backfillWindow time.Duration
	// saltHex, deviceToken, tenantID, deviceID and ingestURL are the identity
	// `mark1 enroll` persists in <state>/enrollment.json (08 §7.1, 04 §2.9);
	// applyEnrollment fills them from the document at boot. The flags of the
	// same names are DEV SEAM overrides — set, a flag wins over the document
	// (tests drive identity that way); with neither, boot is refused naming
	// `mark1 enroll`.
	saltHex string
	// ingestURL/deviceToken switch the uplink drain on.
	ingestURL   string
	deviceToken string
	// tenantID/deviceID switch receipt sealing on: both ride INSIDE the signed
	// checkpoint payload and must be the canonical UUIDs the server stamps
	// from verified claims (07 §2) — which is why the document, not the
	// operator, is their source.
	tenantID string
	deviceID string
	// policyURL/policyChannel drive the 08 §3.2 bundle client. An empty URL
	// leaves fetching off — the daemon still loads its persisted
	// last-known-good and still ages it out at max_age, which is the whole of
	// FR-POLICY-005's blackhole case.
	policyURL     string
	policyChannel string
	// offPoll paces the 08 §7.6 marker checks; a test seam only — the check
	// itself has no off switch.
	offPoll time.Duration
	// diskUsage overrides the 95 % hard-stop sampler (07 §6). A test seam of
	// the same kind as offPoll: unset is the real statfs, and there is no flag
	// — a hard stop an operator could disable is a hard stop that does not
	// exist. It is here because the hard stop is a coverage BYPASS site (04
	// §2.7) and a real 95 %-full disk is not something a test may arrange.
	diskUsage func(string) (float64, error)
	// matrices overrides the policy-apply seam for the verdict plane (04
	// §9.4): the verify+route slice of the applied bundle. Set, it pins the
	// boot matrices and the bundle client publishes nothing over them — a test
	// seam. Unset (the shipped path) the bundle client owns this: it boots on
	// last-known-good, or on verdict.Builtins() when there is none, which is
	// the fail-static posture (gates allow, verdicts flagged stale_cert
	// M1E-3006) and not an error state.
	matrices *verdict.BundleMatrices
	// gateway is `--fleet` (04 §3.4): the proxy runs `--mode gateway` behind mTLS and the local Detect()==apikey precondition does not apply.
	gateway *supervise.GatewayFlags
}

func main() {
	// Anchor-sandbox re-exec hook (04 §2.2): when mark1d is spawned as its own
	// sandbox helper this call applies rlimits + Landlock and execs the anchor,
	// never returning. It MUST precede flags, logging, everything — the helper
	// carries its spec in one env var and must touch no daemon state.
	anchors.MaybeRunHelper()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := harden.Apply(); err != nil {
		log.Error("mark1d refusing to start: core-dump suppression", "err", err)
		os.Exit(1)
	}
	stateDefault := ""
	if home, err := os.UserHomeDir(); err == nil {
		stateDefault = filepath.Join(home, ".omium", "mark1")
	}
	var cfg config
	flag.StringVar(&cfg.stateDir, "state-dir", stateDefault, "mark1d state root (epoch counter, tailer cursors, OFF marker)")
	flag.StringVar(&cfg.spoolDir, "spool-dir", "", "spool directory (default <state-dir>/spool)")
	flag.Int64Var(&cfg.spoolCap, "spool-cap", spool.DefaultCap, "spool byte cap (07 §6): past it diagnostics shed, accounted, and billing-grade blocks; below one 64 MiB segment the spool can never free space")
	flag.StringVar(&cfg.socket, "socket", "", "fabric endpoint (07 §5): unix socket path, default $XDG_RUNTIME_DIR/omium-mark1/m1p.sock else ~/.omium/mark1/m1p.sock; on Windows the named pipe \\\\.\\pipe\\omium-mark1-<user-SID>")
	flag.StringVar(&cfg.workspace, "workspace", "", "additive workspace root to tail besides <state-dir>/workspaces.json (mark1 enable writes the file)")
	flag.DurationVar(&cfg.backfillWindow, "backfill-window", tailers.BackfillWindow, "how much transcript history a never-tailed file imports, receipted as a history_import window; 0 imports everything")
	flag.StringVar(&cfg.saltHex, "tenant-salt", "", "hex tenant HMAC root for Usage idem_key derivation; DEV SEAM — overrides enrollment.json's tenant_root_hex (04 §2.9)")
	flag.StringVar(&cfg.ingestURL, "ingest-url", "", "full URL of POST /m1p/v1/ingest; overrides enrollment.json's endpoints.ingest; empty with no document leaves the uplink off (capture-local-only)")
	flag.StringVar(&cfg.deviceToken, "device-token", "", "bearer device token for ingest and policy; DEV SEAM — overrides enrollment.json's device_token (08 §3.1)")
	flag.StringVar(&cfg.tenantID, "tenant-id", "", "tenant UUID for receipt checkpoints; DEV SEAM — overrides enrollment.json's tenant_id (08 §3.1)")
	flag.StringVar(&cfg.deviceID, "device-id", "", "device UUID for receipt checkpoints; DEV SEAM — overrides enrollment.json's device_id (08 §3.1)")
	var gw supervise.GatewayFlags
	fleet := flag.Bool("fleet", false, "VPC gateway profile (04 §3.4): supervise mark1-proxy --mode gateway with the --gateway-* flags")
	flag.StringVar(&gw.Bind, "gateway-bind", "", "--fleet: host:port the mTLS gateway listener binds")
	flag.StringVar(&gw.TLSCert, "gateway-tls-cert", "", "--fleet: PEM server certificate")
	flag.StringVar(&gw.TLSKey, "gateway-tls-key", "", "--fleet: PEM server key")
	flag.StringVar(&gw.ClientCA, "gateway-client-ca", "", "--fleet: PEM CA every client certificate must chain to")
	flag.StringVar(&gw.CredDir, "gateway-cred-dir", "", "--fleet: credential directory for M1-Cred-Ref resolution (one 0600 file per ref)")
	flag.StringVar(&cfg.policyURL, "policy-url", "", "control-plane ORIGIN for policy distribution (08 §3.2/§3.5 hang /api/v1/policy/{bundle,stream,ack} and /.well-known/mark1-keys off it); empty leaves fetching off, last-known-good still runs")
	flag.StringVar(&cfg.policyChannel, "policy-channel", "stable", "policy rollout channel (08 §3.2)")
	flag.Parse()
	cfg.offPoll = time.Second
	// The daemon keeps its own log: the app's stderr relay is what the WSL lane lost (no daemon line reached the app log through wsl.exe), and a crash is diagnosed from the file either way.
	if lf, err := openLogFile(cfg.stateDir); err == nil {
		log = slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, lf), nil))
	} else {
		log.Warn("mark1d: no log file, stderr only", "err", err)
	}
	if *fleet {
		if gw.Bind == "" || gw.TLSCert == "" || gw.TLSKey == "" || gw.ClientCA == "" || gw.CredDir == "" {
			log.Error("mark1d exiting: --fleet needs all of --gateway-bind, --gateway-tls-cert, --gateway-tls-key, --gateway-client-ca, --gateway-cred-dir")
			os.Exit(1)
		}
		cfg.gateway = &gw
	}
	// Identity comes from the enrollment document `mark1 enroll` wrote, with
	// the flags above as overrides. Here and not in run(): tests drive run()
	// with flag-shaped configs and must not be refused for lacking a document.
	cfg.flags, cfg.flagsSet = cfg.identity(), true
	if err := applyEnrollment(&cfg, log); err != nil {
		log.Error("mark1d exiting", "err", err)
		os.Exit(1)
	}

	// The signal set lives here, not in run(): a test that drives the daemon
	// needs a stopper that is not a process-wide SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, log, cfg); err != nil {
		log.Error("mark1d exiting", "err", err)
		os.Exit(1)
	}
}

// enabledRootFor is the enabled workspace root cwd sits in (the deepest one), the same roots the tailers and cortex read (workspaces.json + --workspace).
func enabledRootFor(stateDir, extra, cwd string) (string, bool) {
	roots, err := cortex.Roots(stateDir, extra)
	if err != nil {
		return "", false
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return "", false
	}
	abs = realPath(abs)
	best := ""
	for _, r := range roots {
		if rel, rerr := filepath.Rel(r, abs); rerr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && len(r) > len(best) {
			best = r
		}
	}
	return best, best != ""
}

// realPath is EvalSymlinks that survives a path whose tail does not exist yet: the nearest existing ancestor is resolved and the rest re-joined (macOS /var → /private/var, Windows short names).
func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	parent := filepath.Dir(p)
	if parent == p {
		return p
	}
	return filepath.Join(realPath(parent), filepath.Base(p))
}

// openLogFile appends to <state>/logs/mark1d.log; past 8 MiB the file rotates once to mark1d.log.1.
func openLogFile(stateDir string) (*os.File, error) {
	dir := filepath.Join(stateDir, "logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "mark1d.log")
	if st, err := os.Stat(path); err == nil && st.Size() > 8<<20 {
		_ = os.Rename(path, path+".1")
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the daemon's own state dir
}

// enrollment is the slice of <state>/enrollment.json the daemon boots identity
// from. go/mark1/internal/cli.Enrollment DEFINES the format (the CLI writes it
// 0600, 08 §7.1); this mirrors the consumed keys byte-compatibly, because that
// module's internal/ tree is out of reach and the file, not the type, is the
// contract — exactly as workspaces.json is handled by tailers.
type enrollment struct {
	State         string `json:"state"`
	DeviceID      string `json:"device_id"`
	TenantID      string `json:"tenant_id"`
	DeviceToken   string `json:"device_token"`
	TenantRootHex string `json:"tenant_root_hex"` // 04 §2.9 root, delivered at enrollment
	Server        string `json:"server"`          // the control-plane origin: 08 §3.2's policy routes hang off it
	Endpoints     struct {
		Ingest string `json:"ingest"`
	} `json:"endpoints"`
}

func enrollmentPath(stateDir string) string { return filepath.Join(stateDir, "enrollment.json") }

// readEnrollment loads the document, refusing a group/world-readable one the
// same way the CLI (cli.readPrivate) and identity.FileCustody refuse theirs:
// it carries the bearer token and the tenant root. os.ErrNotExist passes
// through unwrapped so the caller can tell "never enrolled" from "broken".
func readEnrollment(stateDir string) (*enrollment, error) {
	path := enrollmentPath(stateDir)
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %o; must be 0600 — refusing to read it", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc enrollment
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", path, err)
	}
	return &doc, nil
}

// applyEnrollment is the boot identity rule: a DEV SEAM flag wins where set,
// the document fills whatever is unset, and a device with neither is refused
// legibly — 04 §9.3 starts mark1d AFTER `mark1 enroll` persists the document,
// so a daemon with no identity is a mis-install, not a mode. A REVOKED
// document (stamped by the CLI on M1E-1003) boots capture-local-only: egress
// closed, identity kept, re-enrollment surfaced (04 §9.3 REVOKED_LOCAL).
type identityFlags struct{ deviceToken, tenantID, deviceID, saltHex, ingestURL string }

func (c *config) identity() identityFlags {
	return identityFlags{c.deviceToken, c.tenantID, c.deviceID, c.saltHex, c.ingestURL}
}

func (c *config) setIdentity(f identityFlags) {
	c.deviceToken, c.tenantID, c.deviceID, c.saltHex, c.ingestURL = f.deviceToken, f.tenantID, f.deviceID, f.saltHex, f.ingestURL
}

func applyEnrollment(cfg *config, log *slog.Logger) error {
	if cfg.stateDir == "" {
		return nil // run() refuses this with the message that names --state-dir
	}
	flagged := cfg.saltHex != "" || cfg.deviceToken != "" || cfg.tenantID != "" || cfg.deviceID != ""
	doc, err := readEnrollment(cfg.stateDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if !flagged {
			log.Warn("mark1d: no enrollment yet — capture is local-only until `mark1 enroll` or the desktop app posts /v1/enroll (08 §7.1, 04 §9.3)", "path", enrollmentPath(cfg.stateDir))
		}
		return nil
	case err != nil:
		return fmt.Errorf("mark1d: enrollment: %w", err)
	}
	if doc.State == "revoked" {
		log.Warn("mark1d: enrollment is REVOKED — uplink off, capture local-only; re-enroll with `mark1 enroll` (04 §9.3)")
		doc.DeviceToken, doc.Endpoints.Ingest, doc.Server = "", "", ""
	}
	fill := func(dst *string, v string) {
		if *dst == "" {
			*dst = v
		}
	}
	fill(&cfg.deviceToken, doc.DeviceToken)
	fill(&cfg.tenantID, doc.TenantID)
	fill(&cfg.deviceID, doc.DeviceID)
	fill(&cfg.saltHex, doc.TenantRootHex)
	fill(&cfg.ingestURL, doc.Endpoints.Ingest)
	fill(&cfg.policyURL, doc.Server)
	log.Info("mark1d: identity from enrollment document", "path", enrollmentPath(cfg.stateDir),
		"tenant_id", cfg.tenantID, "device_id", cfg.deviceID, "tenant_root", cfg.saltHex != "", "flag_overrides", flagged)
	return nil
}

// docTokens is the uplink's and the sealer's TokenSource over the enrollment
// document. Token serves the bearer boot adopted; Refresh — the 401 row of
// 08 §2.4 — re-reads the document and adopts a NEWER token a refresh wrote
// there, so a refreshed document is the source without a daemon restart, and
// is ErrNoRefresh (the batch parks) when nothing changed: flag-only identity,
// a revoked document, or no refresher having run. The PoP refresh itself
// (04 §2.9: 80 % of expires_in, nonce + device-key signature) is not here yet
// — today nothing rewrites the token, so Refresh always parks, as before.
type docTokens struct {
	stateDir string
	mu       sync.Mutex
	current  string
}

func (d *docTokens) Token(context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.current, nil
}

func (d *docTokens) Refresh(context.Context) error {
	doc, err := readEnrollment(d.stateDir)
	if err != nil || doc.State == "revoked" || doc.DeviceToken == "" {
		return uplink.ErrNoRefresh
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if doc.DeviceToken == d.current {
		return uplink.ErrNoRefresh
	}
	d.current = doc.DeviceToken
	return nil
}

// run is the off-gated daemon loop (invariant 2, 08 §7.6): the marker and
// MARK1_DISABLE are checked BEFORE any spool, fabric, or tailer I/O — and the
// gate re-arms across `mark1 off`/`mark1 on` cycles, because the supervisor's
// KeepAlive/Restart=on-failure restarts this process while the user has
// Mark 1 off, and a restart that captures anyway circumvents the kill switch.
func run(ctx context.Context, log *slog.Logger, cfg config) error {
	if cfg.stateDir == "" {
		return errors.New("mark1d: --state-dir required (no resolvable home)")
	}
	if cfg.spoolDir == "" {
		cfg.spoolDir = filepath.Join(cfg.stateDir, "spool")
	}
	if cfg.socket == "" {
		p, err := fabric.SocketPath()
		if err != nil {
			return err
		}
		cfg.socket = p
	}
	if cfg.offPoll <= 0 {
		cfg.offPoll = time.Second
	}

	if err := supervise.InstallShim(cfg.stateDir, log); err != nil {
		log.Error("mark1d: could not install the packaged mark1-hookshim", "err", err)
	}
	ctl, err := control.Listen(control.Config{StateDir: cfg.stateDir, SpoolDir: cfg.spoolDir, SpoolCap: cfg.spoolCap, Version: version, Log: log})
	if err != nil {
		return err
	}
	defer func() { _ = ctl.Close() }()
	ctx, shutdown := context.WithCancel(ctx)
	defer shutdown()
	ctl.SetShutdown(shutdown)
	go func() {
		if err := ctl.Serve(); err != nil {
			log.Error("control API", "err", err)
		}
	}()
	log.Info("mark1d control API up", "addr", ctl.Addr(), "discovery", control.Path(cfg.stateDir))
	if !cfg.flagsSet { // tests drive run() with flag-shaped configs and never pass through main()
		cfg.flags, cfg.flagsSet = cfg.identity(), true
	}
	rearm := make(chan struct{}, 1)
	ctl.SetEnrolled(func() {
		select {
		case rearm <- struct{}{}:
		default:
		}
	})

	for {
		if off.Off(cfg.stateDir) {
			log.Info("mark1d off (08 §7.6): parked — no spool, no fabric, no tailers")
		}
		if err := off.Wait(ctx, cfg.stateDir, cfg.offPoll); err != nil {
			return nil // signal while parked: clean exit
		}
		sctx, cancel := context.WithCancel(ctx)
		go func() {
			select {
			case <-rearm:
				cancel() // an enrollment arrived or left over the control API: drain this session and rebuild on the new identity
			case <-sctx.Done():
			}
		}()
		err := session(sctx, log, cfg, ctl)
		cancel()
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		select {
		case <-rearm:
		default:
		}
		cfg.setIdentity(cfg.flags)
		if err := applyEnrollment(&cfg, log); err != nil {
			return err
		}
		// `mark1 off` mid-run: everything above drained and closed; park
		// until `mark1 on` clears the marker (step 3 of 08 §7.6, kept true
		// across supervisor restarts by the loop head).
	}
}

// session runs one on-window of capture: from off-marker clear to off-marker
// set (or signal), ending in the full 07 §6 shutdown drain either way.
func session(parent context.Context, log *slog.Logger, cfg config, ctl *control.Server) error {
	// off-watch wraps everything the session owns, so `mark1 off` tears the
	// listener, tailers, and drain down through the one cancellation path.
	ctx, cancel := off.WatchCtx(parent, cfg.stateDir, cfg.offPoll)
	defer cancel()

	// The tenant usage-idem key gates tailing (ingest 422s a Usage without
	// idem_key, 08 §2.4) — flag-validated up front, before any I/O.
	var idemKey, tenantRoot []byte
	if cfg.saltHex != "" {
		root, err := hex.DecodeString(cfg.saltHex)
		if err != nil || len(root) == 0 {
			return errors.New("mark1d: tenant root must be non-empty hex (enrollment.json tenant_root_hex or --tenant-salt)")
		}
		tenantRoot = root
		idemKey, err = tailers.DeriveUsageIdemKey(root)
		if err != nil {
			return err
		}
	}
	if cfg.workspace != "" && idemKey == nil {
		// An explicit flag ask that cannot be honored fails the boot; the
		// enable-file path below degrades instead (a CLI write must not brick
		// the running capture session).
		return errors.New("mark1d: --workspace requires a tenant root (enrollment.json tenant_root_hex, or --tenant-salt)")
	}

	sp, err := spool.Open(spool.Config{Dir: cfg.spoolDir, SpoolCap: cfg.spoolCap, DiskUsage: cfg.diskUsage})
	if err != nil {
		return err
	}
	// The tenant redaction key is daemon-materialized by enrollment (04 §2.9);
	// absent, the zero key still destroys every span — the hash leg then only
	// correlates per-device, the lesser property (same posture as the shim's
	// spill ring). The scanner itself is never optional.
	hmacKey, _ := os.ReadFile(filepath.Join(cfg.stateDir, "redact.key"))
	sc, err := redact.NewScanner(hmacKey)
	if err != nil {
		// A daemon that cannot construct the admit axis must not admit at all
		// (04 §2.0: fail-closed, no scannerless mode) — refuse to boot.
		_ = sp.Close()
		return err
	}
	adm, err := capture.New(sp, capture.Config{
		EpochPath: filepath.Join(cfg.stateDir, "session_epoch"),
		Redact:    sc.RedactEvent,
	})
	if err != nil {
		_ = sp.Close()
		return err
	}
	adm.Tap = ctl.Hub().Publish
	ctl.Hub().SetSessionResolver(tailers.Resolve)
	ctl.Hub().SetLocator(control.LocateClaude)

	// Self-monitoring is an EdgeHealth event through the one admission door,
	// not a metrics port (11 §0.4). Every consumer below takes it as a nilable
	// field, so a half-wired table loses gauges and never changes behaviour.
	health := obs.New(obs.Config{
		EdgeVersion: version,
		SpoolDir:    cfg.spoolDir,
		Admit:       adm.Admit,
		BootCount:   adm.Epoch(),
	})

	// The bundle client (04 §9.4, FR-POLICY-004) — constructed INSIDE the
	// session so an OFF daemon fetches no policy either (08 §7.6), and
	// constructed here because its boot posture is the verdict plane's boot
	// argument. New does disk custody only: a control plane that is down (or
	// absent) costs the daemon nothing at boot.
	bc, err := bundle.New(bundle.Config{
		StateDir:    cfg.stateDir,
		BaseURL:     cfg.policyURL,
		Channel:     cfg.policyChannel,
		TenantID:    cfg.tenantID,
		Token:       cfg.deviceToken,
		EdgeVersion: version,
		Log:         log,
		Health:      health,
	})
	if err != nil {
		_ = sp.Close()
		return err
	}

	// The cortex plane (04 §1.2, §6): cortexd supervised per enabled root,
	// its session identity published out of band (D-AT/D-AV letter: every
	// admitted writer is sessioned), its L0 root routed to the anchor runner.
	// Budget comes from the applied bundle's cortex section or the compiled
	// default; a workspaces.json the plane cannot read means no child, never
	// a guessed root.
	cxRoots, err := cortex.Roots(cfg.stateDir, cfg.workspace)
	if err != nil {
		log.Error("mark1d: workspaces.json unreadable; cortexd not supervised", "err", err)
	}
	cx, err := cortex.New(cortex.Config{StateDir: cfg.stateDir, Roots: cxRoots, Budget: cortex.BudgetFrom(bc.Cortex()), Ranker: bc.Cortex().LearnedRanker, Log: log})
	if err != nil {
		_ = sp.Close()
		return err
	}

	// The verdict plane (04 §2.3), always on — with no bundle, no anchor vote
	// and no cache entry it answers every gate with allow, which is a normal
	// state and not an error. blocks is shared by exactly two writers: the
	// gate handler (RecordBlock) and the Engine's publish (ResetTask, D-Y).
	matrices := bc.Matrices()
	if cfg.matrices != nil {
		matrices = *cfg.matrices
	}
	blocks := verdict.NewBlocks()
	eng := verdict.NewEngine(matrices, blocks, nil)
	var routeSeq atomic.Uint64
	routeSeq.Store(matrices.Seq)
	var routeMatrices atomic.Pointer[verdict.BundleMatrices]
	routeMatrices.Store(&matrices)
	// The anchor plane (04 §2.2) is the SOURCE half of the verdict plane: with
	// no runner nothing ever produces an AnchorVote, so the cache is never
	// written and every gate answers M1E-5001 allow. The catalog is locally
	// derived and user-consented; no worktree, no consent or no sandbox all
	// reduce to the same posture — run nothing, stay fail-open. Derivation and
	// consent are reconcileAnchors' job below (they change while the daemon
	// runs); here only the sandbox exists.
	// The scratch root must EXIST before the first run: the sandbox mkdtemps a
	// per-run HOME inside it, and a missing root fails every run — including
	// derivation's version sniff, which silently empties ToolVersion and drifts
	// the entry out of consent.
	scratch := filepath.Join(cfg.stateDir, "anchor-scratch")
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		_ = sp.Close()
		return err
	}
	sb := anchors.NewSandbox(scratch)
	// The anchor→fusion tee. It wraps the ONE Admitter, so a vote reaches
	// fusion through the same door it reaches the spool through — no second
	// transport, no second vote shape (04 §2.3's recompute loop).
	votes := anchors.NewVotes(adm, eng, nil)

	// task_seg.v1 (ADR-0002): the daemon is the party that mints task ids, so
	// the segmenter sits on the admission path the events arrive on, and D-AA's
	// resolver is the one channel by which a gate query or a vote acquires one.
	segKey, err := taskseg.DeriveKey(tenantRoot)
	if err != nil {
		_ = sp.Close()
		return err
	}
	seg := taskseg.New(segKey)
	votes.TaskFor = seg.TaskFor
	eng.SessionFor = func(t verdict.TaskID) ([16]byte, bool) { return seg.SessionFor(t) }

	// 04 §2.7's single door, on the same admission path and the same tenant
	// path key as the segmenter — so a workspace has ONE digest across the
	// estate and a coverage row joins to a task row.
	cov := coverage.New(adm.Admit, segKey)
	var sessionCwd sync.Map // session → the hook process's cwd (Hello.cwd), for SessionStart.workspace_id; sessions are few and short, never swept

	// Site: the 95%-disk hard stop (07 §6 / NFR-FOOTPRINT-002). Both edges are
	// receipted, and the close carries the window length so the server can
	// file it as bypass_end rather than a second bypass_start.
	var hardStopAt atomic.Int64
	sp.SetHardStopHook(func(entered bool) {
		ctl.SetHardStop(entered)
		var window time.Duration
		if entered {
			hardStopAt.Store(time.Now().UnixNano())
		} else if t0 := hardStopAt.Swap(0); t0 != 0 {
			// Zero would read as a START on the wire (sidefx.coverageKind
			// distinguishes them on duration alone), so a sub-millisecond
			// window is rounded UP to 1 ms rather than reported as reopening.
			if window = time.Since(time.Unix(0, t0)); window < time.Millisecond {
				window = time.Millisecond
			}
		}
		err := cov.Transition(ctx, m1pv1.CoverageKind_COVERAGE_KIND_BYPASS,
			coverage.DeviceWide(), coverage.ReasonDiskHardStop, window)
		if err != nil {
			// Expected on the `entered` edge and NOT survivable here: a
			// coverage record is diagnostic class, so the hard stop sheds the
			// very event that reports it. The shed is accounted in the drop
			// ledger, so it is not silent — but the row does not exist, and
			// promoting coverage to billing-grade is refused by
			// intelligence.proto ("a backpressure contract 07 never
			// authorized"). Named here so it is a known hole, not a surprise.
			log.Error("COVERAGE BYPASS NOT RECEIPTED — this is a gap, not a warning",
				"reason_code", coverage.ReasonDiskHardStop, "entered", entered, "err", err)
			return
		}
		log.Warn("mark1d: disk hard-stop coverage window receipted", "entered", entered, "window", window)
	})
	// D-AR: the streak resets on close as well as on publish. Without this a task
	// reopened under the same id (R3) inherits its pre-close streak, and a streak
	// at the cap short-circuits the next gate query to ALLOW *before* the cache
	// read — the new attempt runs entirely ungated on the old attempt's state.
	mem, err := memory.New(memory.Config{
		StateDir: cfg.stateDir, BaseURL: cfg.policyURL, Token: cfg.deviceToken, EdgeVersion: version, Log: log,
		Admit: adm.Admit, TaskFor: seg.TaskFor, Verdict: seg.Verdict, PackTokensMax: bc.Memory().PackTokensMax,
	})
	if err != nil {
		_ = sp.Close()
		return err
	}
	seg.OnClose = func(t taskseg.TaskID) { blocks.ResetTask(verdict.TaskID(t)); mem.OnClose(t) }
	// D-AS: at close, a verdict at ANY stage resolves the task. Without this the
	// denominator is 100% unresolved on every install with no consented SLOW
	// anchor, since REVISED is the only stage anything else produces.
	seg.Verdict = func(t taskseg.TaskID) (*m1pv1.VerdictEvent, bool) {
		c, ok := eng.Reader().Get(verdict.TaskID(t))
		if !ok {
			return nil, false
		}
		return c.Verdict, true
	}
	// D-AM(R3): an adjudicated verdict becomes an Event here, which is the only
	// way a task ever closes RESOLUTION_VERDICT instead of aging out unresolved.
	// The verdict is admitted BEFORE the segmenter sees it: capture mints its
	// event_id, so the TaskClose can name it in final_verdict_id.
	eng.Emit = func(ctx context.Context, ve *m1pv1.VerdictEvent, task verdict.TaskID) {
		sid, ok := seg.SessionFor(task)
		if !ok {
			return // no session owns it: no scope to admit under (R4)
		}
		ev := &m1pv1.Event{
			SessionId: sid[:], TaskId: task[:],
			OccurredAt: timestamppb.Now(),
			Body:       &m1pv1.Event_VerdictEvent{VerdictEvent: ve},
		}
		if err := adm.Admit(ctx, ev); err != nil && !perEventLoss(err) {
			log.Error("verdict admit", "err", err)
			return
		}
		for _, te := range seg.Observe(ev, nil) {
			if err := adm.Admit(ctx, te); err != nil && !perEventLoss(err) {
				log.Error("task close admit", "err", err)
			}
		}
	}
	// Started only once Emit is wired: a recompute goroutine that outran the
	// wiring would publish adjudicated verdicts nobody records.
	engDone := make(chan struct{})
	go func() {
		defer close(engDone)
		eng.Run(ctx)
	}()
	// Policy apply, wired only once the Engine exists and never when a test
	// pinned the matrices: SetBundle is the atomic.Pointer swap the recompute
	// goroutine loads per job, so an applied bundle reaches fusion without a
	// restart. Started after Apply is set — the client publishes on its first
	// freshness tick, and a publish into a nil Apply would be lost.
	if cfg.matrices == nil {
		bc.Apply = func(m verdict.BundleMatrices) { routeSeq.Store(m.Seq); routeMatrices.Store(&m); eng.SetBundle(m) }
	}
	bc.ApplyRanker = cx.SetRanker
	// The gate exists before Run so a bundle fetched after boot (enrollment) arms or opens it live; its other seams are wired below.
	gate := fabric.NewGate(eng.Reader(), blocks, cfg.stateDir)
	gate.AgentFor = ctl.Hub().AgentFor
	if cfg.matrices == nil {
		bc.ApplyGates = gate.ApplyGates
	}
	jr, err := judge.New(judge.Config{
		StateDir: cfg.stateDir, TenantRoot: tenantRoot, Log: log,
		TaskFor: seg.TaskFor, Verdict: seg.Verdict, Evidence: votes.Evidence, Admit: adm.Admit,
	})
	if err != nil {
		_ = sp.Close()
		return err
	}
	bc.OnJudgeRequest = jr.Handle
	router := &route.Emitter{Next: adm.Admit, Seq: routeSeq.Load, Matrices: routeMatrices.Load, Verdicts: eng.Reader()}
	bundleDone := make(chan struct{})
	go func() {
		defer close(bundleDone)
		bc.Run(ctx)
	}()
	memDone := make(chan struct{})
	go func() {
		defer close(memDone)
		mem.Run(ctx)
	}()

	// The runner emits through the tee, so its vote lands in the spool AND in
	// fusion by the one path. outputHMACKey stays nil without a tenant root:
	// EvidenceRecord.output_hmac degrades to absent, never to an unkeyed hash.
	// The scheduler always exists — empty it schedules nothing — so a consent
	// that lands mid-session (approvals.jsonl) arms it without a restart.
	var outKey []byte
	if len(tenantRoot) > 0 {
		if outKey, err = anchors.DeriveOutputHMACKey(tenantRoot); err != nil {
			_ = sp.Close()
			return err
		}
	}
	runner := anchors.NewRunner(sb, votes, outKey, false)
	runner.StateDir = cfg.stateDir
	runner.CacheRoot = filepath.Join(scratch, "cache") // the compilers' build caches: warm go vet is 0.8 s, cold 28 s (measured)
	runner.OnDropped = func(string) { adm.AccountDropped(dropE1ConsentAbsent, spool.ClassDiagnostic, 1) }
	if runner.Evidence, err = evidence.Open(cfg.stateDir); err != nil {
		_ = sp.Close()
		return err
	}
	for _, root := range cxRoots {
		root := root
		cx.OnRoot(root, func(h []byte) { runner.SetL0RootFor(root, h) })
	}
	sched := anchors.NewScheduler(runner, nil, anchors.ConsentPath(cfg.stateDir), "", log)
	sched.WorktreeFor = func(session [16]byte) string {
		if cwd, ok := sessionCwd.Load(session); ok {
			if root, ok := enabledRootFor(cfg.stateDir, cfg.workspace, cwd.(string)); ok {
				if wt := anchors.GitTop(realPath(cwd.(string))); sched.Known(wt) {
					return wt
				}
				return root
			}
		}
		return ""
	}
	sched.Start(ctx)
	// The consent surface (anchors/candidates.go): derive for every enabled
	// root, apply the CLI's approvals, publish candidates.json, arm the plane.
	// The first step runs HERE, synchronously, so the boot derivation precedes
	// the first ToolUse the fabric can deliver; watchAnchors re-runs it on
	// workspaces.json / approvals.jsonl change and on the tick.
	// the repositories sessions have been seen in below an enabled root, each its own worktree for derivation
	seenWorktrees := func(roots []string) []string {
		set := map[string]bool{}
		sessionCwd.Range(func(_, v any) bool {
			cwd := realPath(v.(string))
			for _, root := range roots {
				if anchors.Within(root, cwd) {
					if wt := anchors.GitTop(cwd); wt != root && !set[wt] {
						set[wt] = true
					}
					break
				}
			}
			return true
		})
		return slices.Sorted(maps.Keys(set))
	}
	anchorStep := reconcileAnchors(log, cfg, sb, sched, votes, seenWorktrees)
	var stepMu sync.Mutex
	step := func() { stepMu.Lock(); defer stepMu.Unlock(); anchorStep() }
	step()
	ctl.SetReconcile(step)
	anchorsDone := make(chan struct{})
	go func() {
		defer close(anchorsDone)
		watchAnchors(ctx, log, cfg.stateDir, step)
	}()

	// Spill keypair + drain (04 §5.4): the daemon mints the device X25519
	// keypair — private half in its own custody, public half materialized for
	// the shim — and replays the ring through the same admission path on
	// startup and every tick. Daemon-down capture is not lost, it is late.
	drainer, err := spill.Open(cfg.stateDir, adm)
	if err != nil {
		_ = sp.Close()
		return err
	}
	drainer.Health = health
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		drainer.Run(ctx, spillDrainEvery, func(err error) {
			log.Error("spill drain", "err", err)
		})
	}()

	l, err := fabric.Listen(cfg.socket)
	if err != nil {
		cancel() // stop the drain loop before its spool goes away
		<-drainDone
		<-engDone
		<-bundleDone
		<-memDone
		<-anchorsDone
		_ = sp.Close()
		return err
	}
	srv := fabric.NewServer(func(ctx context.Context, payload []byte) error {
		ev := &m1pv1.Event{}
		if err := proto.Unmarshal(payload, ev); err != nil {
			// Capture owns the quarantine ledger for an undecodable payload;
			// re-entering through its own door keeps that accounting single-site.
			return adm.AdmitBytes(ctx, payload)
		}
		// The cortex plane watches every decoded event: session start/end
		// publishes or retires the session file cortexd Hellos with, and an
		// admitted CortexInjection's root_hash reaches the anchor runner.
		cx.Observe(ev)
		// SessionStart.workspace_id (events.proto): the shim sends it empty — the tenant path key is the daemon's — and the daemon stamps it from the Hello's cwd when that cwd sits inside an enabled workspace; the app names the project from the same HMAC (GET /v1/projects). A session started outside every enabled root stays unattributed, honestly.
		if ss := ev.GetSessionStart(); ss != nil && len(ss.GetWorkspaceId()) == 0 && len(ev.GetSessionId()) == 16 {
			var sid [16]byte
			copy(sid[:], ev.GetSessionId())
			if cwd, ok := sessionCwd.Load(sid); ok {
				if root, ok := enabledRootFor(cfg.stateDir, cfg.workspace, cwd.(string)); ok {
					ss.WorkspaceId = cov.WorkspaceID(root)
				}
			}
		}
		// Segmentation runs BEFORE admission so a vote or gate query riding the
		// same connection already resolves to the task this event opened, and
		// TaskOpen precedes the event that opened it in the spool.
		// ponytail: nil files — no wire body carries tool paths into the daemon
		// (ToolUse has no path field), so R2's overlap predicate cannot fire yet.
		for _, te := range seg.Observe(ev, nil) {
			if err := adm.Admit(ctx, te); err != nil && !perEventLoss(err) {
				return err
			}
		}
		// The PostToolUse trigger (04 §2.2), keyed by the task the segmenter
		// just resolved: a run whose vote could not be filed against a real
		// task would be evidence D-AA drops on arrival, so an unresolved
		// session schedules nothing rather than running an anchor for nobody.
		if ev.GetToolUse() != nil && len(ev.GetSessionId()) == 16 {
			var sid [16]byte
			copy(sid[:], ev.GetSessionId())
			if task, ok := seg.TaskFor(sid, [16]byte{}); ok {
				sched.NoteToolUse(sid, task)
			}
		}
		if ev.GetModelRequest() != nil {
			return router.Emit(ctx, ev)
		}
		return votes.Admit(ctx, ev)
	}, perEventLoss)
	// The GateQuery route is constructed with eng.Reader() — a verdict.Reader,
	// the only verdict surface with no method that computes (04 §2.3).
	gate.Evidence = votes.Evidence // FR-VERIFY-011: evidence_ref on BLOCK
	gate.Corrections = eng.TakeCorrections
	// The verify plane's decisions land in the ledger with their savings estimate (policy.proto GuardDecision): the app's arrests, blocks and tokens-saved read from these rows and from nothing else.
	decided := func(session, task [16]byte, outcome m1pv1.GuardOutcome, reason string, attempt uint32, saved uint64) {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := adm.Admit(ctx, &m1pv1.Event{
				SessionId: session[:], TaskId: task[:], OccurredAt: timestamppb.Now(),
				Body: &m1pv1.Event_GuardDecision{GuardDecision: &m1pv1.GuardDecision{
					Outcome: outcome, SampleRate: 1, ReasonCode: reason, TokensSavedEstimate: saved, Attempt: attempt,
				}},
			}); err != nil && !perEventLoss(err) {
				log.Warn("gate: decision not recorded", "reason", reason, "err", err)
			}
		}()
	}
	gate.OnBlock = func(session, task [16]byte, k verdict.KneeState, _ string) {
		decided(session, task, m1pv1.GuardOutcome_GUARD_OUTCOME_BLOCKED, "stop_gate_block", uint32(k.N), ctl.Hub().EstimateBlock(session)) //nolint:gosec // G115: attempts are small
	}
	gate.OnArrest = func(session, task [16]byte, k verdict.KneeState, evidenceRef string) {
		ctl.Hub().Arrest(session, task, k, evidenceRef)
		decided(session, task, m1pv1.GuardOutcome_GUARD_OUTCOME_ARRESTED, "knee_arrest", uint32(k.N), ctl.Hub().EstimateArrest(task, uint32(k.N))) //nolint:gosec // G115: attempts are small
	}
	if cfg.matrices == nil {
		gate.ApplyGates(bc.Gates())
	}
	gate.TaskFor = seg.TaskFor
	gate.Settle = sched.Settle
	gate.OnDropped = func(string) { adm.AccountDropped(dropGateTimeout, spool.ClassDiagnostic, 1) }
	gate.Health = health
	srv.Health = health
	srv.Sync = sp.Sync // FlushAck attests to fsynced records (NFR-DURABILITY-004)
	srv.OnHello = func(session [16]byte, cwd string) {
		if cwd != "" {
			prev, _ := sessionCwd.Swap(session, cwd)
			ctl.Hub().SetCwd(session, cwd)
			// a repository this daemon has not derived yet: wake the reconcile so its anchors arm now, not at the next tick
			if wt := anchors.GitTop(realPath(cwd)); (prev == nil || anchors.GitTop(realPath(prev.(string))) != wt) && !sched.Known(wt) {
				go step()
			}
		}
	}
	ctl.WorkspaceID = cov.WorkspaceID
	srv.SetGate(gate)
	srv.SetContextHandler(fabric.ContextChain{gate, mem})
	srv.SetContaminationHandler(contaminationRollback{log: log, stateDir: cfg.stateDir, adm: adm})
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, l) }()
	log.Info("mark1d up", "version", version, "epoch", adm.Epoch(), "socket", cfg.socket, "spool", cfg.spoolDir)

	// fail tears down a half-built session in dependency order: listener,
	// then the drain loop (it admits into the spool), then the spool.
	fail := func(err error) error {
		_ = l.Close()
		cancel()
		<-drainDone
		<-engDone
		<-bundleDone
		<-memDone
		<-anchorsDone
		_ = sp.Close()
		return err
	}

	// Uplink drain (04 §2.5) — inside the session, so an OFF daemon uploads
	// nothing (08 §7.6): while parked at run()'s loop head no Uplink exists.
	var up *uplink.Uplink
	upDone := make(chan error, 1)
	if cfg.ingestURL != "" {
		if cfg.deviceToken == "" {
			return fail(errors.New("mark1d: an ingest URL needs a device token — enrollment.json's device_token or --device-token (08 §3.1)"))
		}
		tokens := &docTokens{stateDir: cfg.stateDir, current: cfg.deviceToken}
		// The quarantine seal key is the device spill public half spill.Open
		// just materialized (04 §2.5: encrypted with the device spill key §5.4).
		spillPub, err := os.ReadFile(filepath.Join(cfg.stateDir, "spill", "spill.pub"))
		if err != nil {
			return fail(err)
		}
		// Advisory only: the per-session truth is SessionStart.agent (chproj stamps from it);
		// this single string is the fallback for a session whose SessionStart missed both the
		// batch and the read window, so it names an agent only when exactly one is armed.
		agent := ""
		if armed := armedAgents(idemKey, cfg.stateDir); len(armed) == 1 {
			agent = armed[0]
		}
		// Receipt sealing (07's checkpoint model) fails SOFT and by design:
		// capture is the product, so a device with no enrolled identity turns
		// sealing off with one line at boot rather than taking the daemon —
		// and therefore capture — down to protect a receipt. A MALFORMED flag
		// is the other case entirely: an explicit operator ask that cannot be
		// honored fails the boot, exactly as --workspace does above.
		keyPath := filepath.Join(cfg.stateDir, "device.key")
		var checkpoint func(context.Context, [][]byte)
		var origin *uplink.Origin
		switch key, kerr := receipt.OpenKey(keyPath); {
		case cfg.tenantID == "" || cfg.deviceID == "":
			log.Warn("mark1d: receipts NOT sealed — no tenant_id/device_id (enrollment.json or --tenant-id/--device-id); uploads land but carry no chain evidence (08 §3.1)")
		case kerr != nil:
			log.Warn("mark1d: receipts NOT sealed — no usable enrolled device key; uploads land but carry no chain evidence",
				"path", keyPath, "err", kerr)
		default:
			// Canonicalized, not merely validated: controld rebuilds the signed
			// payload from uuid.String() off verified claims, so any other
			// rendering of the same id signs different bytes and every
			// checkpoint refuses bad_signature.
			tid, terr := uuid.Parse(cfg.tenantID)
			did, derr := uuid.Parse(cfg.deviceID)
			if terr != nil || derr != nil {
				return fail(errors.New("mark1d: tenant_id and device_id must be UUIDs (enrollment.json or --tenant-id/--device-id)"))
			}
			headURL, herr := receipt.HeadURL(cfg.ingestURL)
			if herr != nil {
				return fail(herr)
			}
			sealer, serr := receipt.New(receipt.Config{
				Key: key, TenantID: tid.String(), DeviceID: did.String(),
				HeadURL:  headURL,
				Token:    tokens.Token,
				Admit:    adm.Admit,
				Log:      log,
				StateDir: cfg.stateDir,
			})
			if serr != nil {
				return fail(serr)
			}
			checkpoint = sealer.Seal
			origin = &uplink.Origin{Key: key, TenantID: tid.String(), DeviceID: did.String()}
			runner.SetSigner(key)
			log.Info("mark1d: receipt sealing armed", "key_id", key.KeyID(), "head", headURL)
		}

		bootMono := time.Now()
		up, err = uplink.New(uplink.Config{
			Store:         sp,
			Checkpoint:    checkpoint,
			Origin:        origin,
			Admit:         adm.Admit, // the QuarantineDeletion record rides the ledger (NFR-OPERABILITY-003)
			Drops:         []uplink.DropSource{sp, adm},
			NetworkChange: uplink.WakeSignal(ctx, 30*time.Second, time.Now, func() time.Duration { return time.Since(bootMono) }, time.After),
			Tokens:        tokens,
			Endpoint:      cfg.ingestURL,
			EdgeVersion:   version,
			Health:        health,
			SDK: &m1pv1.SdkInfo{
				Name: "mark1d", Version: version,
				Os: runtime.GOOS, Arch: runtime.GOARCH, Agent: agent,
			},
			QuarantineDir: filepath.Join(cfg.stateDir, "quarantine"),
			Seal:          func(p []byte) ([]byte, error) { return spill.Seal(spillPub, p, time.Now()) },
			Log:           log,
		})
		if err != nil {
			return fail(err)
		}
		go func() { upDone <- up.Run(ctx) }()
	} else {
		upDone <- nil
	}

	// Child supervision (04 §1.2, §2.8). Inside the session for the same reason
	// everything else is: an OFF daemon runs no proxy either (08 §7.6), and the
	// session's cancel is what stops it. Started after the last fail() call
	// site, so the half-built teardown above never has to join it.
	supDone := make(chan struct{})
	go func() {
		defer close(supDone)
		superviseProxy(ctx, log, cfg, cov)
	}()
	cxDone := make(chan struct{})
	go func() {
		defer close(cxDone)
		cx.Supervise(ctx)
	}()

	// Sites: `mark1 enable` and `mark1 off`. The CLI cannot sign — 08 §7.6
	// requires both to work with the daemon down and holds no device key — so
	// it journals the window and this drains that journal into the receipted
	// path. Drained on a tick rather than on fsnotify because a transition
	// written while the daemon was DOWN has no event to notice, and the cursor
	// makes a re-read cheap.
	covDone := make(chan struct{})
	go func() {
		defer close(covDone)
		drainCoverageJournal(ctx, log, cov, cfg.stateDir)
	}()

	tailDone := make(chan error, 1)
	if idemKey != nil {
		go func() { tailDone <- tailWorkspaces(ctx, log, cfg, idemKey, adm, cov, router, seg) }()
	} else {
		// Ingest rejects a Usage without idem_key (422, 08 §2.4) — refusing to
		// tail beats spooling events the server will bounce. Enable-file
		// entries degrade with a visible warning instead of failing the boot:
		// the fabric capture path must stay up.
		if roots, err := tailers.LoadWorkspacesFile(filepath.Join(cfg.stateDir, "workspaces.json")); err == nil && len(roots) > 0 {
			log.Warn("mark1d: workspaces enabled but no --tenant-salt; transcripts not tailed until enrollment delivers the root (08 §2.4)")
		}
		tailDone <- nil
	}

	<-ctx.Done()
	// Shutdown drain, 07 §6: stop intake, flush pending tails, force the
	// fsync, then the upload attempt — Close runs the full fsync drain
	// regardless of cadence, and uplink.Flush is the attempt half. The same
	// drain serves `mark1 off` (08 §7.6 step 3: tailers stopped) and signal,
	// except that off skips the upload half (see the Flush gate below).
	_ = l.Close()
	srv.Close()
	<-serveDone
	if err := <-tailDone; err != nil {
		log.Error("tail drain", "err", err)
	}
	<-drainDone  // ctx is done; the ring drain stops before its spool closes
	<-engDone    // the fusion goroutine holds no resource; joined so it cannot outlive the session
	<-bundleDone // same: the policy client owns only its own HTTP client
	<-memDone
	<-anchorsDone // same: the consent reconcile owns a watcher and files, no spool
	ctl.SetReconcile(nil)
	// Joined before the spool closes, and joined at all because the join is what
	// makes the proxy's stop ORDERED: Supervisor.Run returns only once the child
	// has been signalled, reaped, and its proxy.port removed. A daemon that
	// exited without waiting would leave a live proxy and a file naming its port
	// — the exact pair the stale-port control exists to prevent.
	<-supDone
	<-cxDone
	// Joined BEFORE the spool closes and before the uplink's final Flush, so
	// the shutdown drain's `mark1 off` disable window is admitted in time to
	// ride the same batch out. Unjoined, it would race the close and the
	// window would wait for the next boot.
	<-covDone
	if err := <-upDone; err != nil {
		log.Error("uplink", "err", err)
	}
	if up != nil {
		// Flush only after Run returned (uplink is single-owner) and after a
		// forced fsync so the final records are durable, hence readable. The
		// fsync half runs on EVERY teardown; the upload half is gated on the
		// kill switch: once the OFF marker landed, "an OFF daemon uploads
		// nothing" (08 §7.6) includes the drain — the spooled bytes stay
		// durable and upload on the next on-window. Only a signal-triggered
		// exit (daemon stopping, user not off) keeps the full Flush.
		if err := sp.Sync(); err == nil && !off.Off(cfg.stateDir) {
			flushCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
			up.Flush(flushCtx)
			done()
		}
	}
	return sp.Close()
}

// superviseProxy runs 04 :81's spawn rule: the sidecar exists for exactly one
// reason, an enabled adapter reporting Detect()==apikey, and CON-001 is why the
// trigger is that and not "always". A subscription install must never have a
// proxy to point at, so the absence of the process is the first of the two
// structural halves (the second is baseurl.go refusing to write the pointer).
//
// The regime is read once, at session start. That is not a poll and does not
// pretend to be: a key that appears mid-session takes effect at the next
// `mark1 off`/`on` cycle or daemon restart, both of which re-enter session().
// drainCoverageJournal receipts `mark1 enable`/`off`/`on` windows, including
// every one journalled while this daemon was not running — hence the drain at
// entry, before the first tick.
func drainCoverageJournal(ctx context.Context, log *slog.Logger, cov *coverage.Emitter, stateDir string) {
	drain := func() {
		n, err := cov.DrainJournal(ctx, stateDir)
		if n > 0 {
			log.Info("mark1d: coverage transitions receipted from the CLI journal", "count", n)
		}
		if err != nil {
			// The cursor did not advance past a transient failure, so this
			// retries next tick. Worded as a gap because an unreceipted
			// enable/off window reads downstream as full coverage.
			log.Error("COVERAGE TRANSITION NOT RECEIPTED — this is a gap, not a warning",
				"journal", coverage.JournalPath(stateDir), "receipted_this_pass", n, "err", err)
		}
	}
	drain()
	t := time.NewTicker(coverageDrainEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// One last pass: `mark1 off` writes its journal line and then the
			// off-watcher cancels this context, so the shutdown path is the
			// LIKELIEST place to strand a disable window.
			drain()
			return
		case <-t.C:
			drain()
		}
	}
}

func superviseProxy(ctx context.Context, log *slog.Logger, cfg config, cov *coverage.Emitter) {
	cc := &claudecode.Adapter{StateDir: cfg.stateDir}
	d, err := cc.Detect()
	if cfg.gateway == nil && (err != nil || d.Regime != adapters.RegimeAPIKey) {
		log.Info("mark1d: mark1-proxy not supervised — 04 §1.2 spawns it only for Detect()==apikey",
			"apikey", d.Regime == adapters.RegimeAPIKey, "installed", d.Installed, "err", err)
		return
	}
	child, err := supervise.ProxyChild(proxyChildConfig(cfg, log, cov))
	if err != nil {
		// Legible, and at ERROR: without the binary no port is ever published,
		// so `mark1 enable` refuses the base-URL fragment on every run and the
		// enablement path reads as broken rather than as not-installed (D-CM).
		log.Error("mark1d: mark1-proxy not supervised", "err", err)
		return
	}
	s := supervise.New(log)
	s.Add(child)
	s.Run(ctx)
}

// proxyChildConfig is the daemon's hand-off to the proxy supervisor, a named
// function only so a test can read what superviseProxy actually passes. The
// field that needs it is Coverage: ProxyConfig documents nil as a tolerated
// degradation, so dropping it here compiles, supervises, reverts the base-URL
// fragment on FAILED exactly as before, and silently stops receipting the
// bypass window — which downstream is indistinguishable from full coverage.
func proxyChildConfig(cfg config, log *slog.Logger, cov *coverage.Emitter) supervise.ProxyConfig {
	return supervise.ProxyConfig{StateDir: cfg.stateDir, Log: log, Coverage: cov, Gateway: cfg.gateway}
}

// perEventLoss names the two admission outcomes that are an accounted loss of
// ONE event rather than a failure of the path that carried it: the connection
// (or the publish that produced it) lives on.
func perEventLoss(err error) bool {
	return errors.Is(err, capture.ErrShed) || errors.Is(err, capture.ErrQuarantined)
}

// enabledRoots is the live workspace set the anchor catalog derives for: the
// --workspace flag first, then <state>/workspaces.json, canonicalized the way
// tailWorkspaces does (04 §11) and deduplicated in that order.
func enabledRoots(cfg config) []string {
	var roots []string
	if cfg.workspace != "" {
		roots = append(roots, cfg.workspace)
	}
	// Unreadable ⇒ the flag root alone: the same "keep the last good set"
	// posture the tailer reconcile takes, degraded to what is still known.
	if file, err := tailers.LoadWorkspacesFile(filepath.Join(cfg.stateDir, "workspaces.json")); err == nil {
		roots = append(roots, file...)
	}
	seen := map[string]bool{}
	var canon []string
	for _, r := range roots {
		abs, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			abs = resolved
		}
		if !seen[abs] {
			seen[abs] = true
			canon = append(canon, abs)
		}
	}
	return canon
}

// anchorRederiveEvery paces catalog re-derivation between workspace changes: a
// tool upgrade changes the exec_hash, which drifts the entry out of consent
// (04 §2.2) and must reach candidates.json without a restart. Derivation is
// five sandboxed `--version` execs per workspace — fine at this cadence, not
// at wsReloadTick.
// ten minutes, not one: every seen worktree re-sniffs its tools each pass (a tester hopping between repos would spawn dozens of sandboxed execs a minute); a new root or worktree re-derives at once regardless
const anchorRederiveEvery = 10 * time.Minute

// reconcileAnchors returns the one idempotent step behind the consent surface
// (anchors/candidates.go): re-read the enabled roots, re-derive when they
// changed or the re-derive interval passed, apply new approvals.jsonl lines,
// and — when any of that changed something — publish candidates.json and hand
// the Enabled set to the scheduler and the vote tee. State lives in the
// closure exactly as tailWorkspaces keeps its manager map.
//
// ponytail: one scheduler over the first enabled root — nothing on the wire
// says which workspace a session belongs to, so a per-workspace scheduler would
// have no way to pick between them; revisit when Hello carries a cwd. The
// candidates file, unlike the scheduler, is per workspace already.
func reconcileAnchors(log *slog.Logger, cfg config, sb anchors.Sandbox, sched *anchors.Scheduler, votes *anchors.Votes, worktrees func([]string) []string) func() {
	consentPath := anchors.ConsentPath(cfg.stateDir)
	approvalsPath := anchors.ApprovalsPath(cfg.stateDir)
	candidatesPath := anchors.CandidatesPath(cfg.stateDir)
	derived := map[string][]anchors.CatalogEntry{}
	looked := map[string][]anchors.Miss{}
	var lastRoots []string
	var lastDerive time.Time
	var approvalsOffset int64
	published := false
	return func() {
		roots := enabledRoots(cfg)
		// every enabled root, plus each repository a session has been seen working in below one (a parent folder enabled over many repos derives nothing at its own top)
		all := roots
		if worktrees != nil {
			all = append(append([]string{}, roots...), worktrees(roots)...)
		}
		rederived := !slices.Equal(all, lastRoots) || time.Since(lastDerive) >= anchorRederiveEvery
		if rederived {
			next, nextLooked := map[string][]anchors.CatalogEntry{}, map[string][]anchors.Miss{}
			for _, root := range all {
				d, err := anchors.Explain(sb, root)
				if err != nil {
					log.Error("mark1d: anchor derivation failed; workspace publishes no candidates", "worktree", root, "err", err)
					continue
				}
				next[root], nextLooked[root] = d.Entries, d.Looked
			}
			derived, looked, lastRoots, lastDerive = next, nextLooked, all, time.Now()
		}
		off, approved, err := anchors.ApplyApprovals(consentPath, approvalsPath, approvalsOffset, derived, time.Now(), log)
		if err != nil {
			log.Error("mark1d: anchor approvals not applied", "path", approvalsPath, "err", err)
		}
		approvalsOffset = off
		if published && !rederived && !approved {
			return
		}
		consented, err := anchors.LoadConsent(consentPath)
		if err != nil {
			// An unreadable consent store must never read as consent
			// (consent.go): candidates publish as unconsented, nothing runs.
			log.Error("mark1d: anchor consent store unreadable; no anchor will run", "err", err)
			consented = nil
		}
		if err := anchors.PublishCandidates(candidatesPath, consented, derived, looked, sb.Status()); err != nil {
			log.Error("mark1d: anchor candidates not published; `mark1 enable` cannot offer consent", "path", candidatesPath, "err", err)
		} else {
			published = true
		}
		// Every enabled root is armed with its own catalog; a session runs the one its hook cwd sits in (sched.WorktreeFor), the first root when it sits in none. Before this only roots[0] ever verified anything — a tester's second project ran no anchors at all.
		catalogs := map[string][]anchors.CatalogEntry{}
		var union []anchors.CatalogEntry
		for _, root := range all {
			enabled := anchors.Reconcile(derived[root], consented).Enabled
			catalogs[root] = enabled
			union = append(union, enabled...)
			if len(enabled) > 0 {
				log.Info("mark1d: anchor plane armed", "worktree", root, "anchors", len(enabled))
			}
		}
		def := ""
		if len(roots) > 0 {
			def = roots[0]
		}
		sched.SetCatalogs(def, catalogs)
		votes.SetCatalog(union)
	}
}

// watchAnchors re-runs step on every workspaces.json / approvals.jsonl change
// and on the tick — the tailWorkspaces shape: the tick is the correctness
// path, the watch is latency. Two directories, because the CLI renames
// workspaces.json into <state> and appends approvals.jsonl under
// <state>/anchors; the daemon's own writes there (candidates.json,
// catalog.json) are filtered by name so a publish never re-triggers a step.
func watchAnchors(ctx context.Context, log *slog.Logger, stateDir string, step func()) {
	anchorsDir := filepath.Join(stateDir, "anchors")
	_ = os.MkdirAll(anchorsDir, 0o700) // watchable before the first approval
	w, werr := fsnotify.NewWatcher()
	var events chan fsnotify.Event
	if werr == nil {
		defer func() { _ = w.Close() }()
		_ = w.Add(stateDir)
		_ = w.Add(anchorsDir)
		events = make(chan fsnotify.Event)
		go func() {
			defer close(events)
			for {
				select {
				case ev, ok := <-w.Events:
					if !ok {
						return
					}
					select {
					case events <- ev:
					case <-ctx.Done():
						return
					}
				case _, ok := <-w.Errors:
					if !ok {
						return
					}
				}
			}
		}()
	} else {
		log.Warn("mark1d: fsnotify unavailable for anchor consent files, polling only", "err", werr)
	}
	tick := time.NewTicker(wsReloadTick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			if name := filepath.Base(ev.Name); name == "workspaces.json" || name == "approvals.jsonl" {
				step()
			}
		case <-tick.C:
			if w != nil {
				_ = w.Add(stateDir) // idempotent; re-arms after dir churn
				_ = w.Add(anchorsDir)
			}
			step()
		}
	}
}

// wsReloadTick paces the workspaces.json reconcile between fsnotify events —
// the tick is the correctness path, the watch is latency (the tailers'
// Manager pattern: watcher loss only degrades to polling, 04 §2.1).
const wsReloadTick = 2 * time.Second

// tailWorkspaces runs the tailer fleet over the LIVE workspace allow-list:
// <state>/workspaces.json (written atomically by `mark1 enable`; the CLI owns
// the format) plus the --workspace flag as an additive override. The file is
// reloaded on fsnotify change and every tick, so an enable while the daemon
// runs starts its tailer without a restart; a disable narrows the LiveSet
// oracle FIRST and then stops the manager, so the containment check never
// lags the file (04 §0.3 invariant 3: workspaces are DATA, not processes).
// ponytail: re-runs the bounded --version sniffs tailWorkspaces also runs (double sniff at boot); pass the set in if it ever matters.
func armedAgents(idemKey []byte, stateDir string) []string {
	if idemKey == nil {
		return nil
	}
	var out []string
	cc := &claudecode.Adapter{StateDir: stateDir}
	if d, err := cc.Detect(); err == nil {
		if c, _ := cc.Compatibility(d.Version); c.Admits() {
			out = append(out, "claudecode")
		}
	}
	cx := &codex.Adapter{StateDir: stateDir}
	if d, err := cx.Detect(); err == nil && d.Installed {
		if c, _ := cx.Compatibility(d.Version); c.Admits() {
			out = append(out, "codex")
		}
	}
	gm, oc, cp := &gemini.Adapter{StateDir: stateDir}, &opencode.Adapter{StateDir: stateDir}, &copilot.Adapter{StateDir: stateDir}
	for _, a := range []struct {
		name   string
		det    func() (adapters.Detection, error)
		compat func(string) (adapters.Compat, error)
	}{
		{"gemini", gm.Detect, gm.Compatibility},
		{"opencode", oc.Detect, oc.Compatibility},
		{"copilot", cp.Detect, cp.Compatibility},
	} {
		if d, err := a.det(); err == nil && d.Installed {
			if c, _ := a.compat(d.Version); c.Admits() {
				out = append(out, a.name)
			}
		}
	}
	return out
}

func tailWorkspaces(ctx context.Context, log *slog.Logger, cfg config, idemKey []byte, adm *capture.Admitter, cov *coverage.Emitter, router *route.Emitter, seg *taskseg.Segmenter) error {
	wsPath := filepath.Join(cfg.stateDir, "workspaces.json")
	live := tailers.NewLiveSet()
	cc := &claudecode.Adapter{StateDir: cfg.stateDir}
	// The other three adapters each read ONE shared vendor tree with per-stream cwd containment, so one manager per adapter serves every enabled root.
	type shared struct {
		key   string
		ok    bool
		start func(root string) (*tailers.Manager, error)
	}
	cx, gm, oc, cp := &codex.Adapter{StateDir: cfg.stateDir}, &gemini.Adapter{StateDir: cfg.stateDir}, &opencode.Adapter{StateDir: cfg.stateDir}, &copilot.Adapter{StateDir: cfg.stateDir}
	// The probe form: a shape-checked version tails with a receipted unsupported_agent_version bypass, exactly as claudecode does below.
	sniffCompat := func(name string, det func() (adapters.Detection, error), compat func(string) (adapters.Compat, error)) bool {
		d, err := det()
		if err != nil || !d.Installed {
			return false
		}
		c, why := compat(d.Version)
		if !c.Admits() {
			log.Info("mark1d: agent not tailed", "agent", name, "version", d.Version, "compat", c.String(), "probe", why)
			return false
		}
		if c == adapters.CompatibleUnpinned {
			log.Warn("mark1d: transcript capture UNVERIFIED — no conformance corpus for this version; its artifact shape passed the structural probe, capture proceeds and this window is receipted as unsupported_agent_version", "agent", name, "version", d.Version)
			if cerr := cov.TransitionFor(ctx, name, m1pv1.CoverageKind_COVERAGE_KIND_BYPASS, coverage.DeviceWide(), coverage.ReasonUnsupportedAgentVersion, 0); cerr != nil {
				log.Error("COVERAGE BYPASS NOT RECEIPTED — this is a gap, not a warning", "reason_code", coverage.ReasonUnsupportedAgentVersion, "err", cerr)
			}
		}
		return true
	}
	var singles []shared
	// FR-AGENT-002, before a single line is read: version-sniff, and refuse the
	// whole surface when the sniff lands outside the fixture set. Returning nil
	// is the same refusal shape the idem_key branch at the call site already
	// uses — the daemon stays up and every other capture path keeps running.
	//
	// This costs one bounded `claude --version` exec per daemon start.
	d, err := cc.Detect()
	compat, why := cc.Compatibility(d.Version)
	if err != nil || !compat.Admits() {
		adm.AccountDropped(dropUnsupportedAgentVersion, spool.ClassBilling, 1)
		log.Error("mark1d: transcript capture DISABLED — no conformance fixture pins this Claude Code version and its transcript shape failed the structural probe (D-EE), and the tailer's field names are compiled, so parsing it could report token counts that are silently wrong",
			"version", d.Version, "installed", d.Installed, "err", err, "probe", why,
			"fix", "put the `claude` binary on the daemon's PATH, or land a conformance/hooks/claudecode/v<version>/ fixture set and add the version to claudecode.SupportedVersions")
		// The Dropped row says one SURFACE was refused; it cannot say how many
		// events were lost, precisely because refusing is what stops us
		// counting them (FR-AGENT-002's third `partial:` clause names this and
		// points at exactly this transition for the honest number). Capture
		// never arms for this daemon's life, so this is a bypass window that
		// opens here and closes at restart — a START, bounded by whatever
		// transition follows it.
		if cerr := cov.TransitionFor(ctx, "claudecode", m1pv1.CoverageKind_COVERAGE_KIND_BYPASS,
			coverage.DeviceWide(), coverage.ReasonUnsupportedAgentVersion, 0); cerr != nil {
			log.Error("COVERAGE BYPASS NOT RECEIPTED — this is a gap, not a warning",
				"reason_code", coverage.ReasonUnsupportedAgentVersion, "err", cerr)
		}
		return nil
	}
	if compat == claudecode.CompatibleUnpinned {
		// D-EE: capture proceeds, UNVERIFIED — the same receipted window as
		// the refusal (the seven-code vocabulary has no `unpinned` code), so
		// the band never counts an unproven parser as verified coverage.
		log.Warn("mark1d: transcript capture UNVERIFIED — Claude Code version has no conformance corpus; its transcript shape passed the structural probe, capture proceeds and this window is receipted as unsupported_agent_version",
			"version", d.Version, "fix", "record a corpus: `mark1 corpus record`, then add the version to claudecode.SupportedVersions")
		if cerr := cov.TransitionFor(ctx, "claudecode", m1pv1.CoverageKind_COVERAGE_KIND_BYPASS,
			coverage.DeviceWide(), coverage.ReasonUnsupportedAgentVersion, 0); cerr != nil {
			log.Error("COVERAGE BYPASS NOT RECEIPTED — this is a gap, not a warning",
				"reason_code", coverage.ReasonUnsupportedAgentVersion, "err", cerr)
		}
	}
	tcfg := claudecode.TailConfig{
		StateDir:       filepath.Join(cfg.stateDir, "cursors"),
		UsageIdemKey:   idemKey,
		Emit:           off.Unless(cfg.stateDir, "claudecode", router.Emit),
		Observe:        func(ev *m1pv1.Event) { seg.Observe(ev, nil) },
		Log:            log,
		BackfillWindow: cfg.backfillWindow,
	}
	singles = []shared{
		{"\x00codex", sniffCompat("codex", cx.Detect, cx.Compatibility), func(root string) (*tailers.Manager, error) {
			return cx.StartTail(adapters.Workspace{Root: root}, live, codex.TailConfig{StateDir: tcfg.StateDir, UsageIdemKey: idemKey, Emit: off.Unless(cfg.stateDir, "codex", router.Emit), Observe: tcfg.Observe, Log: log})
		}},
		{"\x00gemini", sniffCompat("gemini", gm.Detect, gm.Compatibility), func(root string) (*tailers.Manager, error) {
			return gm.StartTail(adapters.Workspace{Root: root}, live, gemini.TailConfig{StateDir: tcfg.StateDir, UsageIdemKey: idemKey, Emit: off.Unless(cfg.stateDir, "gemini", router.Emit), Observe: tcfg.Observe, Log: log})
		}},
		{"\x00opencode", sniffCompat("opencode", oc.Detect, oc.Compatibility), func(root string) (*tailers.Manager, error) {
			return oc.StartTail(adapters.Workspace{Root: root}, live, opencode.TailConfig{StateDir: tcfg.StateDir, UsageIdemKey: idemKey, Emit: off.Unless(cfg.stateDir, "opencode", router.Emit), Observe: tcfg.Observe, Log: log})
		}},
		{"\x00copilot", sniffCompat("copilot", cp.Detect, cp.Compatibility), func(root string) (*tailers.Manager, error) {
			return cp.StartTail(adapters.Workspace{Root: root}, live, copilot.TailConfig{StateDir: tcfg.StateDir, UsageIdemKey: idemKey, Emit: off.Unless(cfg.stateDir, "copilot", router.Emit), Observe: tcfg.Observe, Log: log})
		}},
	}
	type mgrRun struct {
		cancel context.CancelFunc
		done   chan error
	}
	mgrs := map[string]*mgrRun{}
	// ponytail: a root whose StartTail failed stays parked for the session
	// (one log line, no 2 s retry spam); disable/enable or a daemon restart
	// re-tries it.
	failed := map[string]bool{}

	reconcile := func() {
		roots, err := tailers.LoadWorkspacesFile(wsPath)
		if err != nil {
			// Unreadable input must neither widen nor narrow the oracle: keep
			// the last good set and say so.
			log.Error("mark1d: workspaces.json unreadable; keeping last good set", "err", err)
			return
		}
		if cfg.workspace != "" {
			roots = append(roots, cfg.workspace)
		}
		desired := map[string]bool{}
		var canon []string
		for _, r := range roots {
			// Same canonicalization as the LiveSet applies (04 §11): map keys
			// must equal oracle roots or start/stop diffs drift.
			abs, aerr := filepath.Abs(r)
			if aerr != nil {
				log.Error("mark1d: workspace root unresolvable", "root", r, "err", aerr)
				continue
			}
			if resolved, rerr := filepath.EvalSymlinks(abs); rerr == nil {
				abs = resolved
			}
			if !desired[abs] {
				desired[abs] = true
				canon = append(canon, abs)
			}
		}
		if err := live.SetRoots(canon); err != nil {
			log.Error("mark1d: workspace set swap failed; keeping last good set", "err", err)
			return
		}
		for _, a := range singles {
			desired[a.key] = a.ok && len(canon) > 0
		}
		for root, m := range mgrs {
			if desired[root] {
				continue
			}
			m.cancel() // Manager.Run drains (CloseFlush) on cancellation
			if err := <-m.done; err != nil {
				log.Error("mark1d: tailer drain", "root", root, "err", err)
			}
			delete(mgrs, root)
			delete(failed, root)
			log.Info("mark1d: workspace disabled, tailer stopped", "root", root)
		}
		for _, root := range canon {
			if mgrs[root] != nil || failed[root] {
				continue
			}
			mgr, serr := cc.StartTail(adapters.Workspace{Root: root}, live, tcfg)
			if serr != nil {
				// Fail-open per workspace (the Sweep posture, 04 §2.1): one bad
				// root logs and never blocks siblings.
				failed[root] = true
				log.Error("mark1d: tailer start failed", "root", root, "err", serr)
				continue
			}
			mctx, mcancel := context.WithCancel(ctx)
			m := &mgrRun{cancel: mcancel, done: make(chan error, 1)}
			go func() { m.done <- mgr.Run(mctx) }()
			mgrs[root] = m
			log.Info("mark1d: tailing workspace", "root", root)
		}
		for _, a := range singles {
			if !desired[a.key] || mgrs[a.key] != nil || failed[a.key] {
				continue
			}
			mgr, serr := a.start(canon[0])
			if serr != nil {
				failed[a.key] = true
				log.Error("mark1d: tailer start failed", "agent", a.key[1:], "err", serr)
				continue
			}
			mctx, mcancel := context.WithCancel(ctx)
			m := &mgrRun{cancel: mcancel, done: make(chan error, 1)}
			go func() { m.done <- mgr.Run(mctx) }()
			mgrs[a.key] = m
			log.Info("mark1d: tailing every enabled root", "agent", a.key[1:])
		}
	}

	w, werr := fsnotify.NewWatcher()
	var events chan fsnotify.Event
	if werr == nil {
		defer func() { _ = w.Close() }()
		_ = w.Add(cfg.stateDir) // the CLI renames into the dir; watch the dir, not the file
		events = make(chan fsnotify.Event)
		go func() {
			defer close(events)
			for {
				select {
				case ev, ok := <-w.Events:
					if !ok {
						return
					}
					select {
					case events <- ev:
					case <-ctx.Done():
						return
					}
				case _, ok := <-w.Errors:
					if !ok {
						return
					}
					// Watcher trouble (overflow included) is latency, not
					// loss: the tick below still reconciles everything.
				}
			}
		}()
	} else {
		log.Warn("mark1d: fsnotify unavailable for workspaces.json, polling only", "err", werr)
	}

	reconcile()
	tick := time.NewTicker(wsReloadTick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			// Session drain: every manager flushes pending tails and persists
			// cursors (07 §6) before the caller syncs the spool.
			var firstErr error
			for _, m := range mgrs {
				m.cancel()
				if err := <-m.done; err != nil && firstErr == nil {
					firstErr = err
				}
			}
			return firstErr
		case ev := <-events:
			if filepath.Base(ev.Name) == "workspaces.json" {
				reconcile()
			}
		case <-tick.C:
			if w != nil {
				_ = w.Add(cfg.stateDir) // idempotent; re-arms after dir churn
			}
			reconcile()
		}
	}
}

// contaminationRollback is the daemon half of the CON-001 P0 kill path
// (D-AI, 04 §3.1 step 6). The proxy half already refuses the NEXT request on
// its own authority — router.rs:123-134 consults the kill set before the guard
// runs — so this half is not what stops the contaminated traffic. It is what
// makes the detachment outlive the kill set: the base-URL fragment is reverted,
// so a relaunched agent is not pointed at the proxy at all. That is the layer
// that still holds if the kill file is deleted (router.rs:320-322 reads an
// absent file as "no kills", D-CV) — with the pointer gone there is no proxy in
// the path to re-admit. Only the base-URL fragment: tearing out hooks would end
// capture and leave the pointer standing.
type contaminationRollback struct {
	log      *slog.Logger
	stateDir string
	adm      *capture.Admitter
}

func (c contaminationRollback) OnContamination(session [16]byte, credRef, reasonCode string) {
	rollback := "reverted: the agent will not point at the proxy once relaunched"
	res, err := claudecode.RevertBaseURL(c.stateDir)
	if _, cerr := copilot.RevertEnvPointer(c.stateDir); cerr != nil && err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		rollback = "FAILED: " + err.Error()
	case len(res.Retained) > 0:
		// The one outcome that must never read as success. The revert could not
		// verify our own block, so it wrote nothing and kept the manifest (D-CR):
		// the agent stays pointed at the proxy indefinitely, and the only thing
		// still refusing its traffic is the kill set — one file, whose deletion
		// this branch has left nothing behind. Hence "by hand", at ERROR.
		rollback = "FAILED: still pointing at the proxy — " + strings.Join(res.Retained, ", ") +
			" in " + res.Target + " could not be verified as ours and were left in place; remove them by hand"
	case res.Kind == "not-provisioned":
		rollback = "nothing to revert: no base-URL fragment is provisioned"
	}
	// Stays at ERROR on success: a P0 legal event is reportable because it
	// happened, not because recovery failed. operator_action stays too — the
	// vendor does not unset an env var in an already-running session, so a live
	// agent can keep the stale base URL until it is relaunched.
	c.log.Error("OAUTH CONTAMINATION — P0",
		"code", "M1E-8002",
		"session", hex.EncodeToString(session[:]),
		"cred_ref", credRef,
		"reason", reasonCode,
		"rollback", rollback,
		"operator_action", "restart this agent; a running session keeps ANTHROPIC_BASE_URL until relaunch",
		"record", c.record(session, reasonCode))
}

// record admits the GuardDecision the log line above is only a human rendering
// of. Until this landed, the single P0 legal event the whole CON-001 control
// exists to produce lived exclusively in a local slog line — deletable, not
// orderable, not uploadable, and provable to nobody. 07 §11 gives
// `guard_contamination` its own receipt class keyed on `subject_id` = this
// event's event_id, so an event that is never admitted is a receipt that can
// never be minted: this is the record the receipt will attach to, and it has to
// exist first.
//
// DIAGNOSTIC class, deliberately. 07 §6 closes billing-grade at exactly
// {usage, verdict_event, receipt_checkpoint} and states that receipted and
// block-on-full are independent properties — CoverageTransition is the worked
// example. Widening the set is a m1p.v2 conversation, not a decision to take
// here, and a shed here is still a `Dropped{}` row rather than a silence.
//
// cred_fingerprint is left unset and that is not an oversight: 07 §3 defines it
// as HMAC_tenant(fingerprint), the tenant key is a SERVER-side secret (tenancy
// is stamped from verified token claims at ingest, 07 §2), and credRef is a
// provisioning handle rather than a fingerprint. Stamping the handle into a
// field the schema defines as a keyed digest would put an unkeyed, low-entropy,
// cross-tenant-joinable value in the one place 07 §4 exists to keep them out of.
func (c contaminationRollback) record(session [16]byte, reasonCode string) string {
	if c.adm == nil {
		return "NOT RECORDED: no admitter wired"
	}
	// Bounded and detached: OnContamination runs on the connection's reader
	// goroutine (fabric/session.go:72) and must not block on anything slow. A
	// diagnostic-class admit sheds rather than blocks, so the deadline only
	// covers the spool mutex being held by a billing-grade append that is
	// itself blocked on a full spool — the one path that could stall this.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := c.adm.Admit(ctx, &m1pv1.Event{
		SessionId:  session[:],
		OccurredAt: timestamppb.Now(),
		Body: &m1pv1.Event_GuardDecision{GuardDecision: &m1pv1.GuardDecision{
			Outcome: m1pv1.GuardOutcome_GUARD_OUTCOME_REFUSED,
			// 1.0 and not the guard's configured rate: 07 §3 carries sample_rate
			// so honest rates reconstruct, and contamination is not sampled —
			// every one is reported. A refusal sample of 1.0 is what lets the
			// compliance surface speak about refusals rather than about a
			// sample of them.
			SampleRate: 1,
			ReasonCode: reasonCode,
		}},
	})
	switch {
	case err == nil:
		return "admitted"
	case errors.Is(err, capture.ErrShed):
		return "SHED: spool full, accounted as a Dropped{} row"
	default:
		return "NOT RECORDED: " + err.Error()
	}
}
