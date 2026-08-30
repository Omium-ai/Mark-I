// mark1d — the edge daemon. C8 wires the capture path: fabric UDS listener →
// capture admission → spool (single writer), plus the claudecode transcript
// tailer for one enabled workspace, plus the uplink drain (04 §2.5) when an
// ingest endpoint is configured. Supervision of children, anchors, verdict
// and policy remain their own rows (04 §2); nothing here fakes them.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spill"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/uplink"
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

type config struct {
	stateDir  string
	spoolDir  string
	socket    string
	workspace string
	saltHex   string
	// ingestURL/deviceToken switch the uplink drain on. The token flag is a
	// DEV SEAM exactly like --tenant-salt: enrollment (08 §3.1) delivers real
	// ≤24 h device tokens into identity custody when it lands (04 §2.9).
	ingestURL   string
	deviceToken string
	// offPoll paces the 08 §7.6 marker checks; a test seam only — the check
	// itself has no off switch.
	offPoll time.Duration
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	stateDefault := ""
	if home, err := os.UserHomeDir(); err == nil {
		stateDefault = filepath.Join(home, ".omium", "mark1")
	}
	var cfg config
	flag.StringVar(&cfg.stateDir, "state-dir", stateDefault, "mark1d state root (epoch counter, tailer cursors, OFF marker)")
	flag.StringVar(&cfg.spoolDir, "spool-dir", "", "spool directory (default <state-dir>/spool)")
	flag.StringVar(&cfg.socket, "socket", "", "fabric UDS path (default per 07 §5: $XDG_RUNTIME_DIR/omium-mark1/m1p.sock, else ~/.omium/mark1/m1p.sock)")
	flag.StringVar(&cfg.workspace, "workspace", "", "additive workspace root to tail besides <state-dir>/workspaces.json (mark1 enable writes the file)")
	flag.StringVar(&cfg.saltHex, "tenant-salt", "", "hex tenant HMAC root for Usage idem_key derivation; DEV SEAM — enrollment delivers the real root into identity custody (04 §2.9)")
	flag.StringVar(&cfg.ingestURL, "ingest-url", "", "full URL of POST /m1p/v1/ingest; empty leaves the uplink off (capture-local-only)")
	flag.StringVar(&cfg.deviceToken, "device-token", "", "bearer device token for ingest; DEV SEAM — enrollment issues the real one (08 §3.1)")
	flag.Parse()
	cfg.offPoll = time.Second

	if err := run(log, cfg); err != nil {
		log.Error("mark1d exiting", "err", err)
		os.Exit(1)
	}
}

// run is the off-gated daemon loop (invariant 2, 08 §7.6): the marker and
// MARK1_DISABLE are checked BEFORE any spool, fabric, or tailer I/O — and the
// gate re-arms across `mark1 off`/`mark1 on` cycles, because the supervisor's
// KeepAlive/Restart=on-failure restarts this process while the user has
// Mark 1 off, and a restart that captures anyway circumvents the kill switch.
func run(log *slog.Logger, cfg config) error {
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for {
		if off.Off(cfg.stateDir) {
			log.Info("mark1d off (08 §7.6): parked — no spool, no fabric, no tailers")
		}
		if err := off.Wait(ctx, cfg.stateDir, cfg.offPoll); err != nil {
			return nil // signal while parked: clean exit
		}
		if err := session(ctx, log, cfg); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		// `mark1 off` mid-run: everything above drained and closed; park
		// until `mark1 on` clears the marker (step 3 of 08 §7.6, kept true
		// across supervisor restarts by the loop head).
	}
}

// session runs one on-window of capture: from off-marker clear to off-marker
// set (or signal), ending in the full 07 §6 shutdown drain either way.
func session(parent context.Context, log *slog.Logger, cfg config) error {
	// off-watch wraps everything the session owns, so `mark1 off` tears the
	// listener, tailers, and drain down through the one cancellation path.
	ctx, cancel := off.WatchCtx(parent, cfg.stateDir, cfg.offPoll)
	defer cancel()

	// The tenant usage-idem key gates tailing (ingest 422s a Usage without
	// idem_key, 08 §2.4) — flag-validated up front, before any I/O.
	var idemKey []byte
	if cfg.saltHex != "" {
		salt, err := hex.DecodeString(cfg.saltHex)
		if err != nil || len(salt) == 0 {
			return errors.New("mark1d: --tenant-salt must be non-empty hex")
		}
		idemKey, err = tailers.DeriveUsageIdemKey(salt)
		if err != nil {
			return err
		}
	}
	if cfg.workspace != "" && idemKey == nil {
		// An explicit flag ask that cannot be honored fails the boot; the
		// enable-file path below degrades instead (a CLI write must not brick
		// the running capture session).
		return errors.New("mark1d: --workspace requires --tenant-salt (non-empty hex) until enrollment delivers the root")
	}

	sp, err := spool.Open(spool.Config{Dir: cfg.spoolDir})
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

	// Spill keypair + drain (04 §5.4): the daemon mints the device X25519
	// keypair — private half in its own custody, public half materialized for
	// the shim — and replays the ring through the same admission path on
	// startup and every tick. Daemon-down capture is not lost, it is late.
	drainer, err := spill.Open(cfg.stateDir, adm)
	if err != nil {
		_ = sp.Close()
		return err
	}
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
		_ = sp.Close()
		return err
	}
	srv := fabric.NewServer(adm.AdmitBytes, func(err error) bool {
		return errors.Is(err, capture.ErrShed) || errors.Is(err, capture.ErrQuarantined)
	})
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, l) }()
	log.Info("mark1d up", "version", version, "epoch", adm.Epoch(), "socket", cfg.socket, "spool", cfg.spoolDir)

	// fail tears down a half-built session in dependency order: listener,
	// then the drain loop (it admits into the spool), then the spool.
	fail := func(err error) error {
		_ = l.Close()
		cancel()
		<-drainDone
		_ = sp.Close()
		return err
	}

	// Uplink drain (04 §2.5) — inside the session, so an OFF daemon uploads
	// nothing (08 §7.6): while parked at run()'s loop head no Uplink exists.
	var up *uplink.Uplink
	upDone := make(chan error, 1)
	if cfg.ingestURL != "" {
		if cfg.deviceToken == "" {
			return fail(errors.New("mark1d: --ingest-url requires --device-token until enrollment lands (08 §3.1)"))
		}
		// The quarantine seal key is the device spill public half spill.Open
		// just materialized (04 §2.5: encrypted with the device spill key §5.4).
		spillPub, err := os.ReadFile(filepath.Join(cfg.stateDir, "spill", "spill.pub"))
		if err != nil {
			return fail(err)
		}
		// Advisory: claudecode is the only adapter this daemon can run, and it
		// runs iff the tail subsystem is armed (idem key present).
		agent := ""
		if idemKey != nil {
			agent = "claudecode"
		}
		up, err = uplink.New(uplink.Config{
			Store:       sp,
			Drops:       []uplink.DropSource{sp, adm},
			Tokens:      uplink.StaticToken(cfg.deviceToken),
			Endpoint:    cfg.ingestURL,
			EdgeVersion: version,
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

	tailDone := make(chan error, 1)
	if idemKey != nil {
		go func() { tailDone <- tailWorkspaces(ctx, log, cfg, idemKey, adm) }()
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
	<-drainDone // ctx is done; the ring drain stops before its spool closes
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
func tailWorkspaces(ctx context.Context, log *slog.Logger, cfg config, idemKey []byte, adm *capture.Admitter) error {
	wsPath := filepath.Join(cfg.stateDir, "workspaces.json")
	live := tailers.NewLiveSet()
	cc := &claudecode.Adapter{}
	tcfg := claudecode.TailConfig{
		StateDir:     filepath.Join(cfg.stateDir, "cursors"),
		UsageIdemKey: idemKey,
		Emit:         adm.Admit,
		Log:          log,
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
	}

	w, werr := fsnotify.NewWatcher()
	var events chan fsnotify.Event
	if werr == nil {
		defer w.Close()
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
