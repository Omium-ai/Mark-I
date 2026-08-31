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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/bundle"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spill"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
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

// dropGateTimeout is m1p.v1.DROP_REASON_GATE_TIMEOUT (envelope.proto = 5),
// numbered here for the same reason capture numbers LOCAL_QUARANTINE locally:
// spool.DropReason mirrors the proto enum and only names the rows it raises
// itself. Class is diagnostic — a fail-open gate answer loses no billable
// event, it loses a decision (11 §2.3's ledger line).
const dropGateTimeout spool.DropReason = 5

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
	// policyURL/policyChannel drive the 08 §3.2 bundle client. An empty URL
	// leaves fetching off — the daemon still loads its persisted
	// last-known-good and still ages it out at max_age, which is the whole of
	// FR-POLICY-005's blackhole case.
	policyURL     string
	policyChannel string
	// offPoll paces the 08 §7.6 marker checks; a test seam only — the check
	// itself has no off switch.
	offPoll time.Duration
	// matrices overrides the policy-apply seam for the verdict plane (04
	// §9.4): the verify+route slice of the applied bundle. Set, it pins the
	// boot matrices and the bundle client publishes nothing over them — a test
	// seam. Unset (the shipped path) the bundle client owns this: it boots on
	// last-known-good, or on verdict.Builtins() when there is none, which is
	// the fail-static posture (gates allow, verdicts flagged stale_cert
	// M1E-3006) and not an error state.
	matrices *verdict.BundleMatrices
}

func main() {
	// Anchor-sandbox re-exec hook (04 §2.2): when mark1d is spawned as its own
	// sandbox helper this call applies rlimits + Landlock and execs the anchor,
	// never returning. It MUST precede flags, logging, everything — the helper
	// carries its spec in one env var and must touch no daemon state.
	anchors.MaybeRunHelper()
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
	flag.StringVar(&cfg.deviceToken, "device-token", "", "bearer device token for ingest and policy; DEV SEAM — enrollment issues the real one (08 §3.1)")
	flag.StringVar(&cfg.policyURL, "policy-url", "", "control-plane ORIGIN for policy distribution (08 §3.2/§3.5 hang /api/v1/policy/{bundle,stream,ack} and /.well-known/mark1-keys off it); empty leaves fetching off, last-known-good still runs")
	flag.StringVar(&cfg.policyChannel, "policy-channel", "stable", "policy rollout channel (08 §3.2)")
	flag.Parse()
	cfg.offPoll = time.Second

	// The signal set lives here, not in run(): a test that drives the daemon
	// needs a stopper that is not a process-wide SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, log, cfg); err != nil {
		log.Error("mark1d exiting", "err", err)
		os.Exit(1)
	}
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
	var idemKey, tenantRoot []byte
	if cfg.saltHex != "" {
		root, err := hex.DecodeString(cfg.saltHex)
		if err != nil || len(root) == 0 {
			return errors.New("mark1d: --tenant-salt must be non-empty hex")
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

	// The bundle client (04 §9.4, FR-POLICY-004) — constructed INSIDE the
	// session so an OFF daemon fetches no policy either (08 §7.6), and
	// constructed here because its boot posture is the verdict plane's boot
	// argument. New does disk custody only: a control plane that is down (or
	// absent) costs the daemon nothing at boot.
	bc, err := bundle.New(bundle.Config{
		StateDir:    cfg.stateDir,
		BaseURL:     cfg.policyURL,
		Channel:     cfg.policyChannel,
		Token:       cfg.deviceToken,
		EdgeVersion: version,
		Log:         log,
	})
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
	// The anchor plane (04 §2.2) is the SOURCE half of the verdict plane: with
	// no runner nothing ever produces an AnchorVote, so the cache is never
	// written and every gate answers M1E-5001 allow. The catalog is locally
	// derived and user-consented; no worktree, no consent or no sandbox all
	// reduce to the same posture — run nothing, stay fail-open.
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
	worktree := anchorWorktree(cfg)
	var enabled []anchors.CatalogEntry
	if worktree != "" {
		rep, derr := anchors.Doctor(sb, worktree, anchors.ConsentPath(cfg.stateDir))
		if derr != nil {
			// An unreadable consent store must never read as consent
			// (consent.go), so the catalog stays empty and nothing runs.
			log.Error("mark1d: anchor catalog unavailable; no anchor will run", "worktree", worktree, "err", derr)
		} else {
			enabled = rep.Enabled
		}
	}
	// The anchor→fusion tee. It wraps the ONE Admitter, so a vote reaches
	// fusion through the same door it reaches the spool through — no second
	// transport, no second vote shape (04 §2.3's recompute loop).
	votes := anchors.NewVotes(adm, eng, enabled)

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
	// D-AR: the streak resets on close as well as on publish. Without this a task
	// reopened under the same id (R3) inherits its pre-close streak, and a streak
	// at the cap short-circuits the next gate query to ALLOW *before* the cache
	// read — the new attempt runs entirely ungated on the old attempt's state.
	seg.OnClose = func(t taskseg.TaskID) { blocks.ResetTask(verdict.TaskID(t)) }
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
		bc.Apply = eng.SetBundle
	}
	bundleDone := make(chan struct{})
	go func() {
		defer close(bundleDone)
		bc.Run(ctx)
	}()

	// The runner emits through the tee, so its vote lands in the spool AND in
	// fusion by the one path. outputHMACKey stays nil without a tenant root:
	// EvidenceRecord.output_hmac degrades to absent, never to an unkeyed hash.
	var sched *anchors.Scheduler
	if len(enabled) > 0 {
		var outKey []byte
		if len(tenantRoot) > 0 {
			if outKey, err = anchors.DeriveOutputHMACKey(tenantRoot); err != nil {
				_ = sp.Close()
				return err
			}
		}
		runner := anchors.NewRunner(sb, votes, outKey, false)
		sched = anchors.NewScheduler(runner, enabled, anchors.ConsentPath(cfg.stateDir), worktree, log)
		sched.Start(ctx)
		log.Info("mark1d: anchor plane armed", "worktree", worktree, "anchors", len(enabled))
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
		<-engDone
		<-bundleDone
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
		if sched != nil && ev.GetToolUse() != nil && len(ev.GetSessionId()) == 16 {
			var sid [16]byte
			copy(sid[:], ev.GetSessionId())
			if task, ok := seg.TaskFor(sid, [16]byte{}); ok {
				sched.NoteToolUse(sid, task)
			}
		}
		return votes.Admit(ctx, ev)
	}, perEventLoss)
	// The GateQuery route is constructed with eng.Reader() — a verdict.Reader,
	// the only verdict surface with no method that computes (04 §2.3).
	gate := fabric.NewGate(eng.Reader(), blocks, cfg.stateDir)
	gate.TaskFor = seg.TaskFor
	gate.OnDropped = func(string) { adm.AccountDropped(dropGateTimeout, spool.ClassDiagnostic, 1) }
	srv.SetGate(gate)
	srv.SetContaminationHandler(contaminationRollback{log: log})
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
	<-drainDone  // ctx is done; the ring drain stops before its spool closes
	<-engDone    // the fusion goroutine holds no resource; joined so it cannot outlive the session
	<-bundleDone // same: the policy client owns only its own HTTP client
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

// perEventLoss names the two admission outcomes that are an accounted loss of
// ONE event rather than a failure of the path that carried it: the connection
// (or the publish that produced it) lives on.
func perEventLoss(err error) bool {
	return errors.Is(err, capture.ErrShed) || errors.Is(err, capture.ErrQuarantined)
}

// anchorWorktree picks the one worktree the anchor catalog is derived from.
// ponytail: one scheduler over the first enabled root — nothing on the wire
// says which workspace a session belongs to, so a per-workspace scheduler would
// have no way to pick between them; revisit when Hello carries a cwd.
func anchorWorktree(cfg config) string {
	if cfg.workspace != "" {
		return cfg.workspace
	}
	roots, err := tailers.LoadWorkspacesFile(filepath.Join(cfg.stateDir, "workspaces.json"))
	if err != nil || len(roots) == 0 {
		return ""
	}
	return roots[0]
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
// (D-AI, 04 §3.1 step 6). The proxy has already closed the session and already
// refuses every later request for it; the daemon's one job is the config
// rollback, so the agent's NEXT request bypasses the proxy entirely.
//
// It does not roll anything back, and that is the honest state, not an
// oversight (D-BC). Step 6 reverts "the base-URL fragment" — the fenced
// ANTHROPIC_BASE_URL fragment that points an agent at the proxy. Nothing in
// this repo writes that fragment yet: `adapters/claudecode` provisions the
// HOOKS fragment (provisioned/claudecode/hooks.manifest.json) and nothing
// else. Calling the hooks revert here would tear out capture while leaving the
// proxy pointer — which does not exist — untouched: a rollback that undoes the
// wrong thing, in the wrong direction, on the one path where being wrong is a
// legal event rather than a bug.
//
// So this logs, loudly and attributably, and the gap stays visible. That is a
// deliberate choice over the two alternatives: leaving the handler nil (the
// frame is accepted and vanishes — a P0 that arrives and is silently discarded)
// and wiring the wrong revert. When base-URL fragment provisioning lands, the
// revert call goes here and this comment goes away.
type contaminationRollback struct{ log *slog.Logger }

func (c contaminationRollback) OnContamination(session [16]byte, credRef, reasonCode string) {
	c.log.Error("OAUTH CONTAMINATION — P0",
		"code", "M1E-8002",
		"session", hex.EncodeToString(session[:]),
		"cred_ref", credRef,
		"reason", reasonCode,
		"rollback", "UNAVAILABLE: no base-URL fragment is provisioned (D-BC)",
		"operator_action", "unset ANTHROPIC_BASE_URL for this agent before its next request")
}
