// mark1d — the edge daemon. C8 wires the capture path: fabric UDS listener →
// capture admission → spool (single writer), plus the claudecode transcript
// tailer for one enabled workspace. Supervision of children, uplink, anchors,
// verdict and policy remain their own rows (04 §2); nothing here fakes them.
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
	"syscall"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spill"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
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
	flag.StringVar(&cfg.workspace, "workspace", "", "enabled workspace root to tail claudecode transcripts for (optional)")
	flag.StringVar(&cfg.saltHex, "tenant-salt", "", "hex tenant HMAC root for Usage idem_key derivation; DEV SEAM — enrollment delivers the real root into identity custody (04 §2.9)")
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
	tailDone := make(chan error, 1)
	if cfg.workspace != "" {
		salt, err := hex.DecodeString(cfg.saltHex)
		if err != nil || len(salt) == 0 {
			// Ingest rejects a Usage without idem_key (422, 08 §2.4) — refusing
			// to tail beats spooling events the server will bounce.
			return fail(errors.New("mark1d: --workspace requires --tenant-salt (non-empty hex) until enrollment delivers the root"))
		}
		idemKey, err := tailers.DeriveUsageIdemKey(salt)
		if err != nil {
			return fail(err)
		}
		set, err := tailers.NewWorkspaceSet(cfg.workspace)
		if err != nil {
			return fail(err)
		}
		cc := &claudecode.Adapter{}
		mgr, err := cc.StartTail(adapters.Workspace{Root: cfg.workspace}, set, claudecode.TailConfig{
			StateDir:     filepath.Join(cfg.stateDir, "cursors"),
			UsageIdemKey: idemKey,
			Emit:         adm.Admit,
			Log:          log,
		})
		if err != nil {
			return fail(err)
		}
		go func() { tailDone <- mgr.Run(ctx) }()
	} else {
		tailDone <- nil
	}

	<-ctx.Done()
	// Shutdown drain, 07 §6: stop intake, flush pending tails, then the
	// forced fsync — Close runs the full drain regardless of cadence. The
	// upload attempt half of the drain barrier is uplink's row. The same
	// drain serves `mark1 off` (08 §7.6 step 3: tailers stopped) and signal.
	_ = l.Close()
	srv.Close()
	<-serveDone
	if err := <-tailDone; err != nil {
		log.Error("tail drain", "err", err)
	}
	<-drainDone // ctx is done; the ring drain stops before its spool closes
	return sp.Close()
}
