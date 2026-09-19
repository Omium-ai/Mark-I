//! End-to-end suite for the shim binary: replay of every committed hook
//! fixture (`conformance/hooks/claudecode@2.1.251`, 12 §3.2), the off-check
//! (invariant 2), the deadline/spill path (04 §5 step 4 + §5.4), the
//! sanitized-spill roundtrip (F-10), maps-as-data override (FR-AGENT-001),
//! and the ≤50 ms end-to-end wall bound (08 §5 rule 5).

// clippy.toml's allow-*-in-tests exempts #[test] fns; the helpers here are
// plain fns, so the exemption is restated at file scope (house style).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(unix)]

use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use m1p_wire::pb;
use m1p_wire::FrameDecoder;
use sha2::Sha256;

const SESSION: &str = "3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55";
/// Deterministic device spill keypair for the tests — the private half never
/// exists in the shim, mirroring mark1d.identity custody (04 §5.4).
const DEVICE_SEED: [u8; 32] = [7u8; 32];
const SEAL_LABEL: &[u8] = b"m1p.spill.seal.v1";

/// How late `Mode::SlowVerdict` answers, past the deadline the shim stated.
/// Wide on purpose: a debug-build fail-open costs ~0.5 s of wall (spawn plus
/// the redact ruleset compile the release profile collapses), so the gap
/// between "the deadline fired" and "the shim waited" has to clear that noise
/// for the wall assertion to mean anything.
const LATE_BY: Duration = Duration::from_secs(3);

/// Everything a fail-open invocation costs that is NOT waiting on the fabric:
/// process spawn, map load, the debug-build redact ruleset compile, and the
/// sealed spill write. Measured 280-475 ms with the whole suite running in
/// parallel on one box; 900 ms is roughly 2x the worst of that, which is the
/// slack a loaded CI runner gets. It is a FIXED cost, so it is added to the
/// deadline rather than being the whole ceiling — the old flat 1.5 s against a
/// 50 ms deadline was 30x headroom, and an injected 1 s stall passed it.
///
/// ponytail: a constant, not a per-run calibration. If it ever goes flaky,
/// measure it in-test with one daemon-absent spill run and add the deadline
/// to THAT.
const FAIL_OPEN_OVERHEAD: Duration = Duration::from_millis(900);

/// The wall a fail-open is allowed: the deadline the shim itself stated, plus
/// that fixed overhead. Spending the stated deadline twice (once on the
/// handshake read, again on a freshly-timed verdict read) must land above it.
fn fail_open_ceiling(deadline_ms: u64) -> Duration {
    FAIL_OPEN_OVERHEAD + Duration::from_millis(deadline_ms)
}

/// Scheduler slack for the gate path's OWN timer (`hookshim.gate_elapsed_ms`,
/// `MARK1_HOOKSHIM_TIMING=1`): this window never spawns a process, loads a
/// map, or compiles the redact ruleset, so it can stay tight under load where
/// `fail_open_ceiling`'s process-wall number cannot (measured: 20/20 runs of
/// `gate_deadline_exceeded_allows_within_budget` + `gate_mute_daemon_allows_within_budget`
/// blew fail_open_ceiling under 24x CPU oversubscription, 666ms-3.45s wall,
/// while this internal timer is the shim's own `Instant` arithmetic).
const GATE_TIMER_SLACK_MS: u64 = 300;

/// The property: the fail-open branch fired within the shim's OWN deadline
/// (never early past a lower bound the map states, never late past this
/// slack) — a property of `gate.rs`'s timer, not of the OS scheduler.
fn assert_gate_timer_honored_deadline(elapsed_ms: u64, deadline_ms: u64) {
    assert!(
        elapsed_ms + 5 >= deadline_ms,
        "fail-open fired before its own deadline: {elapsed_ms}ms < {deadline_ms}ms"
    );
    assert!(
        elapsed_ms <= deadline_ms + GATE_TIMER_SLACK_MS,
        "the shim's own timer overran its deadline: {elapsed_ms}ms (budget {deadline_ms}ms, slack {GATE_TIMER_SLACK_MS}ms)"
    );
}

/// A loose wall-clock sanity net, 5x the process-overhead ceiling: catches an
/// actual hang (the fail-open branch never firing at all), not scheduler
/// noise. The precise property lives in `assert_gate_timer_honored_deadline`.
fn loose_wall_ceiling(deadline_ms: u64) -> Duration {
    5 * fail_open_ceiling(deadline_ms)
}

/// The deadline the SHIPPED map makes the shim state for `Stop`: its 20 s
/// gate budget (the anchors the task owes run at Stop, 04 §2.2) minus 08 §4.4's
/// 10 ms margin. Spelled out here so a silent map edit cannot move it in
/// either direction.
const STOP_DEADLINE_MS: u64 = 19_990;

/// What a mute daemon may cost the agent at Stop: the gate handshake's own bound
/// (`fabric::HANDSHAKE_MS`), never the budget above.
const STOP_HANDSHAKE_MS: u64 = 250;

/// The SessionEnd drain barrier's budget (`main::FLUSH_DEADLINE_MS`): the
/// vendor's 1.5 s SessionEnd default (08 §5.1) minus 08 §4.4's 10 ms margin.
/// Spelled out here for the same reason as `STOP_DEADLINE_MS`.
const FLUSH_DEADLINE_MS: u64 = 1_490;

/// How long `Mode::SlowFlushAck` sits on the Flush before acking: past
/// `FAIL_OPEN_OVERHEAD`, so a shim that fired the Flush and left without
/// waiting cannot hide inside the harness's own slack — and inside
/// `FLUSH_DEADLINE_MS`, so a shim that waited gets its receipt.
const FLUSH_ACK_DELAY: Duration = Duration::from_millis(1_000);

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/hooks/claudecode/v2.1.251/hooks")
        .join(format!("{name}.json"));
    std::fs::read(path).unwrap()
}

struct TestEnv {
    home: tempfile::TempDir,
    xdg: tempfile::TempDir,
}

impl TestEnv {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            xdg: tempfile::tempdir().unwrap(),
        }
    }

    fn sock_path(&self) -> PathBuf {
        self.xdg.path().join("omium-mark1/m1p.sock")
    }

    fn ring_path(&self) -> PathBuf {
        self.home.path().join(".omium/mark1/spill/hookshim.ring")
    }

    /// The fail-open gate ledger (04 §5.4 shape): one byte per allowed-by-
    /// timeout gate, so the file's LENGTH is the count.
    fn gate_timeouts(&self) -> u64 {
        self.sidecar("hookshim.gate_timeout")
    }

    /// The M1E-4003 ledger: one byte per handshake mark1d refused, so a bad
    /// rollout is countable instead of just a fleet full of spill rings.
    fn handshake_refusals(&self) -> u64 {
        self.sidecar("hookshim.handshake_refused")
    }

    /// The missed-FlushAck ledger (NFR-DURABILITY-004): one byte per
    /// SessionEnd whose drain the daemon never receipted.
    fn flush_timeouts(&self) -> u64 {
        self.sidecar("hookshim.flush_timeout")
    }

    fn sidecar(&self, name: &str) -> u64 {
        std::fs::metadata(self.home.path().join(".omium/mark1/spill").join(name))
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// A `MARK1_HOOKSHIM_TIMING=1` sidecar `spill::record_timing` writes: the
    /// named path's own millis for its most recent fail-open (gate deadline,
    /// observer abandon budget/elapsed, flush deadline).
    fn timing_ms(&self, name: &str) -> u64 {
        let raw = std::fs::read(self.home.path().join(".omium/mark1/spill").join(name)).unwrap();
        u64::from_le_bytes(raw[..8].try_into().unwrap())
    }

    /// The shipped map with only the Stop gate's budget shrunk, pushed the way
    /// mark1d would (FR-AGENT-001). The deadline paths are then provable in
    /// milliseconds instead of the fragment's 30 s — and because the map is
    /// derived from the committed file rather than retyped, the gate under
    /// test stays the shipped one.
    fn install_short_gate_map(&self, budget_ms: u32) {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("maps/claudecode.json");
        let shipped = std::fs::read_to_string(src).unwrap();
        let map = shipped.replace(
            "\"budget_ms\": 20000",
            &format!("\"budget_ms\": {budget_ms}"),
        );
        assert_ne!(map, shipped, "the shipped Stop budget moved; retarget this");
        let dir = self.home.path().join(".omium/mark1/maps");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("claudecode.bin"), map).unwrap();
    }

    /// Materialize the device spill public key the way mark1d would.
    fn install_spill_pubkey(&self) {
        let device = x25519_dalek::StaticSecret::from(DEVICE_SEED);
        let device_pub = x25519_dalek::PublicKey::from(&device);
        let dir = self.home.path().join(".omium/mark1/spill");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("spill.pub"), device_pub.as_bytes()).unwrap();
    }

    /// Fake daemon speaking the real dialect (D-U + 08 §4.3): Hello in,
    /// HelloAck out, then events and gate round-trips.
    fn listen(&self) -> Daemon {
        self.listen_as(Mode::Allow)
    }

    fn listen_as(&self, mode: Mode) -> Daemon {
        std::fs::create_dir_all(self.sock_path().parent().unwrap()).unwrap();
        let listener = UnixListener::bind(self.sock_path()).unwrap();
        let (conn_tx, connected) = mpsc::channel();
        let (ev_tx, events) = mpsc::channel();
        let (q_tx, queries) = mpsc::channel();
        let (f_tx, frames) = mpsc::channel();
        std::thread::spawn(move || {
            while let Ok((stream, _addr)) = listener.accept() {
                let _ = conn_tx.send(());
                serve(stream, mode, &ev_tx, &q_tx, &f_tx);
            }
        });
        Daemon {
            connected,
            events,
            queries,
            frames,
        }
    }

    /// Run the shim with the given stdin; returns (exit ok, stdout+stderr,
    /// wall time).
    fn run(&self, stdin_bytes: &[u8], envs: &[(&str, &str)]) -> (bool, Vec<u8>, Duration) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mark1-hookshim"));
        cmd.env_remove("MARK1_DISABLE")
            .env("HOME", self.home.path())
            .env("XDG_RUNTIME_DIR", self.xdg.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        Self::finish(cmd, stdin_bytes)
    }

    /// `mark1-hookshim statusline` with the given stdin (the status-line JSON).
    fn statusline(&self, stdin_bytes: &[u8], envs: &[(&str, &str)]) -> (bool, Vec<u8>, Duration) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mark1-hookshim"));
        cmd.arg("statusline")
            .env_remove("MARK1_DISABLE")
            .env("HOME", self.home.path())
            .env("XDG_RUNTIME_DIR", self.xdg.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        Self::finish(cmd, stdin_bytes)
    }

    fn ratelimits_path(&self) -> PathBuf {
        self.home
            .path()
            .join(".omium/mark1/claude/ratelimits.jsonl")
    }

    /// The adapter's sidecar: the user's own statusLine entry, verbatim.
    fn install_statusline_prev(&self, command: &str) {
        let dir = self.home.path().join(".omium/mark1/claude");
        std::fs::create_dir_all(&dir).unwrap();
        let entry = serde_json::json!({"type": "command", "command": command, "padding": 2});
        std::fs::write(dir.join("statusline.prev.json"), entry.to_string()).unwrap();
    }

    /// Like `run`, but with no resolvable home at all: the off-marker is then
    /// unreachable and `off()` must fail closed (08 §7.6).
    fn run_homeless(&self, stdin_bytes: &[u8]) -> (bool, Vec<u8>, Duration) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mark1-hookshim"));
        cmd.env_remove("MARK1_DISABLE")
            .env_remove("HOME")
            .env_remove("USERPROFILE")
            .env("XDG_RUNTIME_DIR", self.xdg.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Self::finish(cmd, stdin_bytes)
    }

    fn finish(mut cmd: Command, stdin_bytes: &[u8]) -> (bool, Vec<u8>, Duration) {
        let started = Instant::now();
        let mut child = cmd.spawn().unwrap();
        // The shim's off/fail-closed paths exit BEFORE reading stdin (main.rs:
        // off-check precedes everything, 08 §7.6), so this write can race the
        // child's exit and get EPIPE. That pipe error IS the behavior under
        // test, not a harness fault; any other write error is still fatal.
        if let Err(e) = child.stdin.take().unwrap().write_all(stdin_bytes) {
            assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "stdin write: {e}");
        }
        let out = child.wait_with_output().unwrap();
        let wall = started.elapsed();
        let mut chatter = out.stdout;
        chatter.extend_from_slice(&out.stderr);
        (out.status.success(), chatter, wall)
    }
}

/// What the fake daemon does once a connection is up. Every mode answers the
/// handshake honestly except `RefuseHello` and `Mute`, which are the two ways
/// a daemon can leave a writer believing a completed `write_all` was a
/// delivery (the F2 silence).
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// HelloAck{accepted}, GateQuery answered ALLOW.
    Allow,
    /// HelloAck{accepted}, GateQuery answered BLOCK.
    Block,
    /// HelloAck{accepted}, GateQuery answered ALLOW at the knee: `system_message` set.
    Knee,
    /// HelloAck{accepted}, ContextQuery answered with a queued correction.
    Correction,
    /// HelloAck{accepted}, then the verdict arrives well past the deadline
    /// the shim stated in the query.
    SlowVerdict,
    /// HelloAck{accepted: false} — 08 §4.3 step 3's mid-upgrade refusal.
    RefuseHello,
    /// Reads the Hello and closes without acking — 08 §4.3 step 2's bare
    /// M1E-4003 close, which reaches the shim as EOF rather than a frame.
    CloseOnHello,
    /// Accepts the connection and says nothing, ever. Before the handshake
    /// this was indistinguishable from a healthy daemon.
    Mute,
    /// HelloAck late but inside the deadline, then silence. The shape that
    /// billed the shim its whole budget twice: once on the handshake read,
    /// then again on a freshly-timed verdict read.
    SlowHello,
    /// HelloAck{accepted}, FlushAck `FLUSH_ACK_DELAY` late but inside the
    /// deadline — provable only by a shim that actually waits for it.
    SlowFlushAck,
    /// HelloAck{accepted}, then the Flush is read and never answered, the
    /// connection held open so the shim sees silence, not EOF.
    NoFlushAck,
}

/// What mark1d says at the knee (fabric/gate.go) and on a queued correction (Gate.Context), verbatim.
const KNEE_MESSAGE: &str = "mark1 stop-gate: retry loop arrested at the knee — verdict violated; knee governor: stop at attempt 3 — p̂_LCB 0.150 · V 10.00 ≤ c(n) 2.00 under usd; evidence: cargo-check-warm:E0001 errors=1 warnings=0 files=1";
const CORRECTION_TEXT: &str = "[mark1 correction] a slow verifier finished after the last verdict: violated was revised to satisfied";

/// How long `Mode::SlowHello` sits on the handshake before acking. Bigger than
/// `FAIL_OPEN_OVERHEAD`, so the double-spend it provokes cannot hide inside
/// the ceiling's slack.
const HELLO_DELAY: Duration = Duration::from_millis(1_500);

/// A daemon that never accepts, with a starved backlog so the shim's connect
/// BLOCKS rather than queueing: listen(fd, 0) plus saturating dummy connects.
/// `UnixStream::connect` has no timeout, so nothing inside the syscall ever
/// unparks it — only the shim's own deadline can.
fn starve_backlog(env: &TestEnv) -> UnixListener {
    std::fs::create_dir_all(env.sock_path().parent().unwrap()).unwrap();
    let listener = UnixListener::bind(env.sock_path()).unwrap();
    unsafe {
        use std::os::unix::io::AsRawFd;
        assert_eq!(libc::listen(listener.as_raw_fd(), 0), 0);
    }
    for _ in 0..8 {
        let path = env.sock_path();
        std::thread::spawn(move || {
            let _ = std::os::unix::net::UnixStream::connect(path);
        });
    }
    std::thread::sleep(Duration::from_millis(50));
    listener
}

struct Daemon {
    connected: mpsc::Receiver<()>,
    events: mpsc::Receiver<pb::Event>,
    queries: mpsc::Receiver<pb::GateQuery>,
    /// Every frame the shim wrote, in arrival order — the only witness a
    /// same-connection ordering claim can have.
    frames: mpsc::Receiver<pb::fabric_frame::Kind>,
}

impl Daemon {
    /// The frames written so far, labelled by arm (events by body), in order.
    fn frame_log(&self) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(k) = self.frames.recv_timeout(Duration::from_millis(300)) {
            out.push(match k {
                pb::fabric_frame::Kind::Event(ev) => match ev.body {
                    Some(pb::event::Body::SessionEnd(_)) => "Event(SessionEnd)".to_owned(),
                    other => format!("Event({other:?})"),
                },
                pb::fabric_frame::Kind::Hello(_) => "Hello".to_owned(),
                pb::fabric_frame::Kind::Flush(_) => "Flush".to_owned(),
                other => format!("{other:?}"),
            });
        }
        out
    }
    fn event(&self) -> pb::Event {
        self.events.recv_timeout(Duration::from_secs(2)).unwrap()
    }
    fn no_event(&self) -> bool {
        self.events
            .recv_timeout(Duration::from_millis(300))
            .is_err()
    }
    fn query(&self) -> pb::GateQuery {
        self.queries.recv_timeout(Duration::from_secs(2)).unwrap()
    }
    fn no_query(&self) -> bool {
        self.queries
            .recv_timeout(Duration::from_millis(300))
            .is_err()
    }
}

fn write_frame(stream: &mut std::os::unix::net::UnixStream, kind: pb::fabric_frame::Kind) {
    let mut out = Vec::new();
    m1p_wire::encode_control(&pb::FabricFrame { kind: Some(kind) }, &mut out).unwrap();
    let _ = stream.write_all(&out);
}

fn serve(
    mut stream: std::os::unix::net::UnixStream,
    mode: Mode,
    events: &mpsc::Sender<pb::Event>,
    queries: &mpsc::Sender<pb::GateQuery>,
    frames: &mpsc::Sender<pb::fabric_frame::Kind>,
) {
    if mode == Mode::Mute {
        // Hold the connection open so the shim sees silence, not EOF.
        std::thread::sleep(Duration::from_secs(30));
        return;
    }
    let mut dec = FrameDecoder::new();
    let mut buf = [0u8; 4096];
    // Mirrors mark1d TODAY (fabric/session.go `ss.drained`): events admitted
    // on this connection since Hello, echoed back in FlushAck. No Sync sits
    // behind it yet — that is the daemon's half of NFR-DURABILITY-004.
    let mut drained = 0u64;
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let frames_in = match dec.feed_frames(&buf[..n]) {
            Ok(f) => f,
            Err(e) => panic!("the daemon could not decode what the shim wrote: {e}"),
        };
        for frame in frames_in {
            let kind = frame.kind.unwrap();
            let _ = frames.send(kind.clone());
            match kind {
                pb::fabric_frame::Kind::Hello(h) => {
                    if mode == Mode::SlowHello {
                        std::thread::sleep(HELLO_DELAY);
                    }
                    assert_eq!(h.component, "mark1-hookshim");
                    assert!(h.pid > 0, "Hello must name the writer's pid");
                    assert!(!h.version.is_empty(), "Hello must carry the crate version");
                    if mode == Mode::CloseOnHello {
                        return;
                    }
                    write_frame(
                        &mut stream,
                        pb::fabric_frame::Kind::HelloAck(pb::HelloAck {
                            accepted: mode != Mode::RefuseHello,
                            max_frame: m1p_wire::M1PL_MAX_FRAME,
                            want_ver: 0,
                        }),
                    );
                    if mode == Mode::RefuseHello {
                        return;
                    }
                }
                pb::fabric_frame::Kind::Event(ev) => {
                    drained += 1;
                    let _ = events.send(ev);
                }
                pb::fabric_frame::Kind::Flush(_) => {
                    if mode == Mode::NoFlushAck {
                        std::thread::sleep(Duration::from_secs(30));
                        return;
                    }
                    if mode == Mode::SlowFlushAck {
                        std::thread::sleep(FLUSH_ACK_DELAY);
                    }
                    write_frame(
                        &mut stream,
                        pb::fabric_frame::Kind::FlushAck(pb::FlushAck { drained }),
                    );
                }
                pb::fabric_frame::Kind::GateQuery(q) => {
                    let _ = queries.send(q.clone());
                    if mode == Mode::SlowHello {
                        // Whatever is LEFT of the deadline is all the shim may
                        // spend here — not a fresh copy of it.
                        std::thread::sleep(Duration::from_secs(30));
                        return;
                    }
                    if mode == Mode::SlowVerdict {
                        std::thread::sleep(
                            Duration::from_millis(u64::from(q.deadline_ms)) + LATE_BY,
                        );
                    }
                    write_frame(
                        &mut stream,
                        pb::fabric_frame::Kind::GateVerdict(pb::GateVerdict {
                            decision: if mode == Mode::Block {
                                pb::GateDecision::Block as i32
                            } else {
                                pb::GateDecision::Allow as i32
                            },
                            verdict: pb::Verdict::Violated as i32,
                            posterior: vec![0.02, 0.95, 0.02, 0.01],
                            reason: "two anchors report the build is broken".into(),
                            evidence_ref: "evidence/abc123".into(),
                            system_message: if mode == Mode::Knee {
                                KNEE_MESSAGE.into()
                            } else {
                                String::new()
                            },
                        }),
                    );
                }
                pb::fabric_frame::Kind::ContextQuery(_) => {
                    write_frame(
                        &mut stream,
                        pb::fabric_frame::Kind::ContextReply(pb::ContextReply {
                            additional_context: if mode == Mode::Correction {
                                CORRECTION_TEXT.into()
                            } else {
                                String::new()
                            },
                        }),
                    );
                }
                other => panic!("the shim sent an arm no writer may send: {other:?}"),
            }
        }
    }
}

fn decode_one_event(frame_bytes: &[u8]) -> pb::Event {
    let mut dec = FrameDecoder::new();
    let mut events = dec.feed(frame_bytes).unwrap();
    assert_eq!(events.len(), 1, "expected exactly one frame");
    events.remove(0)
}

/// Common envelope stamps for every emitted event (04 §5 step 3 + R-4).
fn assert_envelope(ev: &pb::Event) {
    assert_eq!(ev.event_id.len(), 16);
    // UUIDv7: version nibble in byte 6.
    assert_eq!(ev.event_id[6] >> 4, 7, "event_id must be UUIDv7");
    let session = uuid::Uuid::parse_str(SESSION).unwrap();
    assert_eq!(ev.session_id, session.as_bytes().to_vec());
    // seq and session_epoch are mark1d's to assign at admission (R-4).
    assert_eq!(ev.seq, 0);
    assert_eq!(ev.session_epoch, 0);
    assert!(ev.task_id.is_empty());
    assert!(ev.tenant_id.is_empty(), "server band must be unset (07 §2)");
    assert!(ev.occurred_at.is_some());
}

fn unseal_ring(env: &TestEnv) -> Vec<Vec<u8>> {
    let raw = std::fs::read(env.ring_path()).unwrap();
    let device = x25519_dalek::StaticSecret::from(DEVICE_SEED);
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < raw.len() {
        let len_bytes: [u8; 4] = raw[off..off + 4].try_into().unwrap();
        let record_len = u32::from_le_bytes(len_bytes) as usize;
        let rec = &raw[off + 4..off + 4 + record_len];
        off += 4 + record_len;
        assert_eq!(rec[0], 1, "record version");
        let eph: [u8; 32] = rec[9..41].try_into().unwrap();
        let nonce: [u8; 12] = rec[41..53].try_into().unwrap();
        let shared = device.diffie_hellman(&x25519_dalek::PublicKey::from(eph));
        let mut kdf = <Hmac<Sha256> as Mac>::new_from_slice(shared.as_bytes()).unwrap();
        kdf.update(SEAL_LABEL);
        let key: [u8; 32] = kdf.finalize().into_bytes().into();
        let cipher = ChaCha20Poly1305::new((&key).into());
        out.push(cipher.decrypt((&nonce).into(), &rec[53..]).unwrap());
    }
    out
}

// ---- fixture replay (12 §3.2: conf_hooks_claudecode_2.1.251_replay) ----

#[test]
fn conf_hooks_claudecode_2_1_251_replay() {
    for name in [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "Stop",
        "SubagentStop",
        "SessionEnd",
    ] {
        let env = TestEnv::new();
        let d = env.listen();
        let (ok, chatter, _wall) = env.run(&fixture(name), &[]);
        assert!(ok, "{name}: shim must exit 0");
        assert!(
            chatter.is_empty(),
            "{name}: an allowed gate and an observer event both produce no output"
        );
        let ev = d.event();
        assert_envelope(&ev);
        match (name, ev.body.unwrap()) {
            ("SessionStart", pb::event::Body::SessionStart(b)) => {
                assert_eq!(b.agent, "claudecode");
                assert_eq!(b.agent_version, "2.1.251");
                assert_eq!(b.capture_paths, vec![pb::CapturePath::Hooks as i32]);
                assert!(b.workspace_id.is_empty(), "unkeyed digests never emit");
            }
            ("UserPromptSubmit", pb::event::Body::Turn(b)) => {
                assert_eq!(b.initiator, pb::Initiator::Human as i32);
            }
            ("PreToolUse", pb::event::Body::ToolUse(b)) => {
                assert_eq!(b.tool_name, "Bash");
                assert_eq!(b.tool_use_id, "toolu_01SynthFixtureTTTTTTTT");
                assert_eq!(b.status, pb::ToolStatus::Unspecified as i32);
                assert_eq!(b.duration_ms, 0);
            }
            ("PostToolUse", pb::event::Body::ToolUse(b)) => {
                assert_eq!(b.status, pb::ToolStatus::Ok as i32);
                assert_eq!(b.duration_ms, 4180);
            }
            ("PostToolUseFailure", pb::event::Body::ToolUse(b)) => {
                assert_eq!(b.tool_use_id, "toolu_01SynthFixtureUUUUUUUU");
                assert_eq!(b.status, pb::ToolStatus::Error as i32);
                assert_eq!(b.duration_ms, 2930);
            }
            ("Stop" | "SubagentStop", pb::event::Body::Turn(b)) => {
                assert_eq!(b.initiator, pb::Initiator::Agent as i32);
            }
            ("SessionEnd", pb::event::Body::SessionEnd(b)) => {
                assert_eq!(b.reason, pb::EndReason::Exit as i32);
            }
            (name, other) => panic!("{name}: unexpected body {other:?}"),
        }
    }
}

#[test]
fn conf_hooks_precompact_emits_nothing() {
    // PreCompact maps to kind "none": no committed m1p.v1 body exists for a
    // compaction boundary, and the adapter never guesses (08 §5 rule 2).
    let env = TestEnv::new();
    let d = env.listen();
    let (ok, chatter, _wall) = env.run(&fixture("PreCompact"), &[]);
    assert!(ok);
    assert!(chatter.is_empty());
    assert!(d.no_event(), "PreCompact must not reach the fabric");
    assert!(!env.ring_path().exists(), "and must not spill");
}

// ---- off-check (invariant 2, 08 §7.6) ----

#[test]
fn off_env_var_is_a_silent_noop() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let d = env.listen();
    let (ok, chatter, _wall) = env.run(&fixture("PreToolUse"), &[("MARK1_DISABLE", "1")]);
    assert!(ok, "off must exit 0");
    assert!(
        chatter.is_empty(),
        "byte-identical agent behavior: no output"
    );
    assert!(
        d.connected
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "off must produce zero fabric I/O — not even a connect"
    );
    assert!(
        !env.ring_path().exists(),
        "off must produce zero spill bytes"
    );
}

#[test]
fn off_marker_file_is_a_silent_noop() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let marker_dir = env.home.path().join(".omium/mark1");
    std::fs::create_dir_all(&marker_dir).unwrap();
    std::fs::write(marker_dir.join("OFF"), b"").unwrap();
    let d = env.listen();
    let (ok, chatter, _wall) = env.run(&fixture("PreToolUse"), &[]);
    assert!(ok);
    assert!(chatter.is_empty());
    assert!(d
        .connected
        .recv_timeout(Duration::from_millis(300))
        .is_err());
    assert!(!env.ring_path().exists());
}

#[test]
fn no_home_fails_closed_silent_noop() {
    // HOME/USERPROFILE unset ⇒ the off-marker cannot be checked ⇒ OFF
    // (fail-closed, matching mark1d's off.Off): the fabric socket is still
    // resolvable via XDG_RUNTIME_DIR, so capturing here would circumvent
    // `mark1 off` for any agent launched without a home.
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let d = env.listen();
    let (ok, chatter, _wall) = env.run_homeless(&fixture("PreToolUse"));
    assert!(ok, "off must exit 0");
    assert!(chatter.is_empty());
    assert!(
        d.connected
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "no home ⇒ no capture: the marker check must fail closed"
    );
}

#[test]
fn unreadable_marker_dir_fails_closed() {
    use std::os::unix::fs::PermissionsExt;
    // Root ignores directory modes; the EACCES this test needs never happens.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let dir = env.home.path().join(".omium/mark1");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let d = env.listen();
    let (ok, chatter, _wall) = env.run(&fixture("PreToolUse"), &[]);
    // Restore before asserting so tempdir cleanup can delete the tree.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(ok);
    assert!(chatter.is_empty());
    assert!(
        d.connected
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "a stat error on the marker must read as OFF, exactly like mark1d"
    );
    assert!(!env.ring_path().exists(), "and must not spill");
}

// ---- deadline + spill (04 §5 step 4, §5.4) ----

#[test]
fn deadline_blocked_fabric_spills_within_budget() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    // This is the stall the 45 ms abandon timer exists for.
    let listener = starve_backlog(&env);

    let (ok, chatter, wall) = env.run(&fixture("PreToolUse"), &[("MARK1_HOOKSHIM_TIMING", "1")]);
    assert!(ok, "a blocked fabric must still exit 0");
    assert!(chatter.is_empty());
    // Only the 45 ms abandon timer can unblock this shim: the connect is
    // parked on a starved backlog with nothing to time it out, so ANY exit
    // proves the timer fired. The property is the shim's own timer: the
    // budget it handed the abandon wait is what was LEFT of 45 ms after
    // startup, and the wait ended on that budget — not the process wall,
    // which the debug-build ruleset compile and the scheduler own.
    let budget = env.timing_ms("hookshim.observe_budget_ms");
    assert!(
        budget <= 45,
        "abandon budget exceeds 04 §5's 45 ms: {budget}ms"
    );
    assert_gate_timer_honored_deadline(env.timing_ms("hookshim.observe_elapsed_ms"), budget);
    assert!(wall < loose_wall_ceiling(45), "took {wall:?}");
    let entries = unseal_ring(&env);
    assert_eq!(entries.len(), 1, "the abandoned event must be in the ring");
    let ev = decode_one_event(&entries[0]);
    assert_envelope(&ev);
    match ev.body.unwrap() {
        pb::event::Body::ToolUse(b) => assert_eq!(b.tool_name, "Bash"),
        other => panic!("unexpected body {other:?}"),
    }
    drop(listener);
}

/// F2, the observer half: a completed `write_all` against a socket the daemon
/// is closing is NOT a delivery. The gate path has the verdict read as its own
/// evidence; the fire-and-forget path has only the HelloAck (08 §4.3 step 4 —
/// there is no per-event ack), so without it every observer event was lost
/// with `Ok(())` returned, nothing spilled, and no `Dropped{}` ever emitted.
#[test]
fn observer_event_spills_when_the_handshake_is_refused() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let _d = env.listen_as(Mode::RefuseHello);
    let (ok, chatter, _wall) = env.run(&fixture("PreToolUse"), &[]);
    assert!(ok);
    assert!(chatter.is_empty());
    assert_eq!(unseal_ring(&env).len(), 1, "a refused writer must spill");
    assert_eq!(env.handshake_refusals(), 1, "M1E-4003 must be counted");
}

/// 08 §4.3 step 2's other shape: the daemon closes instead of acking, so the
/// refusal arrives as EOF. Same spill, same count — otherwise a rollout that
/// refuses every handshake is a silent fleet-wide outage.
#[test]
fn handshake_closed_without_ack_is_counted() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let _d = env.listen_as(Mode::CloseOnHello);
    let (ok, chatter, _wall) = env.run(&fixture("PreToolUse"), &[]);
    assert!(ok);
    assert!(chatter.is_empty());
    assert_eq!(unseal_ring(&env).len(), 1);
    assert_eq!(env.handshake_refusals(), 1, "M1E-4003 must be counted");
}

#[test]
fn observer_event_spills_when_the_daemon_goes_mute() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    // Connection accepted, never a byte back — the shape that is
    // indistinguishable from a healthy daemon until you wait for an ack.
    let _d = env.listen_as(Mode::Mute);
    let (ok, chatter, _wall) = env.run(&fixture("PreToolUse"), &[]);
    assert!(ok);
    assert!(chatter.is_empty());
    assert_eq!(
        unseal_ring(&env).len(),
        1,
        "silence must not lose the event"
    );
}

/// Regenerates `go/mark1d/internal/spill/testdata/hookshim.ring` from THIS
/// build of the shim:
///
///     cargo test -p mark1-hookshim --test shim_e2e -- --ignored regenerate
///
/// Ignored because it writes into the source tree. The Go drain test that
/// consumes the file is the only place the two languages meet on the ring's
/// payload, so a fixture that drifts from the encoder turns that test into a
/// test of nothing — which is what happened: the committed ring predated
/// `encode_frame`'s FabricFrame wrap and still held a bare Event, and neither
/// side noticed, because tag 1 wiretype 2 means an Event and the frame around
/// it are indistinguishable to a decoder that is handed the wrong one.
#[test]
#[ignore = "writes into the source tree; run deliberately after a frame change"]
fn regenerate_go_spill_fixture() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    // No listener at all: connect fails fast and the event takes the spill path.
    let (ok, chatter, _wall) = env.run(&fixture("PostToolUse"), &[]);
    assert!(ok);
    assert!(chatter.is_empty());
    assert_eq!(
        unseal_ring(&env).len(),
        1,
        "expected exactly one ring entry"
    );
    let dest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../go/mark1d/internal/spill/testdata/hookshim.ring");
    std::fs::write(&dest, std::fs::read(env.ring_path()).unwrap()).unwrap();
}

#[test]
fn spill_roundtrip_redacts_before_sealing() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    // No listener at all: connect fails fast, the event takes the spill
    // path. The payload carries a planted secret where the map reads a
    // string, so the pre-image would reach the ring if the admit axis were
    // skippable — which is exactly what may never happen (invariant 5).
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let payload = String::from_utf8(fixture("PreToolUse"))
        .unwrap()
        .replace("toolu_01SynthFixtureTTTTTTTT", secret);
    let (ok, chatter, _wall) = env.run(payload.as_bytes(), &[]);
    assert!(ok);
    assert!(chatter.is_empty());

    // The ring itself never holds the secret, even ciphertext-wrapped
    // plaintext is post-redaction — check the UNSEALED bytes.
    let entries = unseal_ring(&env);
    assert_eq!(entries.len(), 1);
    let plain = &entries[0];
    let needle = secret.as_bytes();
    assert!(
        !plain.windows(needle.len()).any(|w| w == needle),
        "planted secret survived into the spill ring (CON-008)"
    );
    let token = "\u{27e8}redacted:api_key:".as_bytes();
    assert!(
        plain.windows(token.len()).any(|w| w == token),
        "expected a redaction token in the sanitized entry"
    );
}

#[test]
fn spill_overflow_is_counted_not_silent() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    // Pre-fill the ring to its 64 MiB writer cap (a sparse set_len is enough —
    // the writer's check is metadata().len()), so the next spill must shed.
    let ring = env.ring_path();
    std::fs::create_dir_all(ring.parent().unwrap()).unwrap();
    let f = std::fs::File::create(&ring).unwrap();
    f.set_len(64 * 1024 * 1024).unwrap();
    drop(f);

    // No daemon at all: the event takes the spill path and hits the cap.
    let shed = ring.with_file_name("hookshim.ring.shed");
    for want in 1..=2u64 {
        let (ok, chatter, _wall) = env.run(&fixture("PreToolUse"), &[]);
        assert!(ok, "a full ring must still exit 0");
        assert!(chatter.is_empty());
        // The Dropped religion (07 §3): the shed is counted in the sidecar —
        // one byte per refused event — for mark1d's drain to convert to
        // Dropped{RING_EVICTED} with this exact quantity (04 §5.4).
        assert_eq!(
            std::fs::metadata(&shed).unwrap().len(),
            want,
            "shed counter must grow by one per refused event"
        );
    }
    assert_eq!(
        std::fs::metadata(&ring).unwrap().len(),
        64 * 1024 * 1024,
        "the writer must refuse to grow the ring past the cap"
    );
}

// ---- the stop-gate (04 §5 step 5; 08 §5.1's `Stop` row) ----
//
// Every failure mode below must answer ALLOW, and every fail-open answer must
// be counted: an uncounted fail-open is indistinguishable from a product that
// silently does nothing (08 §4.4).

#[test]
fn gate_allow_is_silent_and_states_the_deadline() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let d = env.listen_as(Mode::Allow);
    let (ok, chatter, _wall) = env.run(&fixture("Stop"), &[]);
    assert!(ok);
    // 08 §5.1's Stop row: at the knee ⇒ "exit 0 with no decision".
    assert!(chatter.is_empty(), "an allowed gate returns no JSON at all");

    let q = d.query();
    assert_eq!(q.gate, pb::GateKind::Stop as i32);
    // 08 §4.4: the SHIM owns the agent-facing deadline — the map's gate budget
    // minus 10 ms. Never 0, which D-Y(c) reserves for unspecified.
    assert_eq!(u64::from(q.deadline_ms), STOP_DEADLINE_MS);
    // Stop is both the gate and a Turn{AGENT} observer event, on one
    // connection (08 §4.3 step 4).
    match d.event().body.unwrap() {
        pb::event::Body::Turn(b) => assert_eq!(b.initiator, pb::Initiator::Agent as i32),
        other => panic!("unexpected body {other:?}"),
    }
    assert!(
        !env.ring_path().exists(),
        "a delivered event must not spill"
    );
    assert_eq!(env.gate_timeouts(), 0, "a real verdict is not a fail-open");
}

#[test]
fn gate_block_emits_the_vendor_block_json() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let d = env.listen_as(Mode::Block);
    let (ok, chatter, _wall) = env.run(&fixture("Stop"), &[]);
    // 08 §5.1: exit 0 + JSON stdout is the only mode; exit 2 is never used.
    assert!(ok, "a block is exit 0 with JSON, never a nonzero exit");
    let out: serde_json::Value = serde_json::from_slice(&chatter).unwrap();
    assert_eq!(out["decision"], "block");
    let reason = out["reason"].as_str().unwrap();
    // "<verdict + failure evidence as continuation reason>" — the daemon's
    // reason, carrying its evidence pointer.
    assert!(reason.contains("two anchors report the build is broken"));
    assert!(reason.contains("evidence/abc123"));
    assert!(
        out.get("continue").is_none(),
        "never `continue:false` (08 §5.1)"
    );
    assert_eq!(u64::from(d.query().deadline_ms), STOP_DEADLINE_MS);
    assert!(!env.ring_path().exists());
    assert_eq!(env.gate_timeouts(), 0);
}

#[test]
fn gate_knee_exits_zero_with_system_message() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let d = env.listen_as(Mode::Knee);
    let (ok, chatter, _wall) = env.run(&fixture("Stop"), &[]);
    assert!(ok, "at the knee the shim exits 0 (08 §5.1: Claude stops)");
    // 08 §5.1's Stop row at the knee: no `decision`, and `systemMessage` — the
    // vendor's human-facing field — carrying the daemon's verdict + evidence
    // byte for byte. Nothing else: an extra key is a contract Claude Code did
    // not sign.
    let want = serde_json::to_vec(&serde_json::json!({ "systemMessage": KNEE_MESSAGE })).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&chatter),
        String::from_utf8_lossy(&want)
    );
    assert_eq!(u64::from(d.query().deadline_ms), STOP_DEADLINE_MS);
    match d.event().body.unwrap() {
        pb::event::Body::Turn(b) => assert_eq!(b.initiator, pb::Initiator::Agent as i32),
        other => panic!("unexpected body {other:?}"),
    }
    assert!(!env.ring_path().exists());
    assert_eq!(env.gate_timeouts(), 0);
}

#[test]
fn post_tool_use_pulls_the_next_turn_correction() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let d = env.listen_as(Mode::Correction);
    let (ok, chatter, _wall) = env.run(&fixture("PostToolUse"), &[]);
    assert!(ok);
    // 08 §5.1 PostToolUse row: additionalContext only when a REVISED verdict
    // was queued since the last turn — rendered under the vendor's event name.
    let want = serde_json::to_vec(&serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": CORRECTION_TEXT,
        }
    }))
    .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&chatter),
        String::from_utf8_lossy(&want)
    );
    // One connection: Hello, the ToolUse observer event, then the pull with
    // channel CORRECTION under the pack's budget and nothing of the payload.
    let log = d.frame_log();
    assert_eq!(log.len(), 3, "{log:?}");
    assert_eq!(log[0], "Hello");
    assert!(log[1].starts_with("Event(Some(ToolUse("), "{}", log[1]);
    assert_eq!(
        log[2],
        format!(
            "{:?}",
            pb::fabric_frame::Kind::ContextQuery(pb::ContextQuery {
                channel: pb::InjectionChannel::Correction as i32,
                deadline_ms: 240,
                ..Default::default()
            })
        )
    );
    assert!(
        !env.ring_path().exists(),
        "a delivered event must not spill"
    );
    assert_eq!(env.sidecar("hookshim.context_timeout"), 0);
}

#[test]
fn post_tool_use_with_nothing_queued_prints_nothing() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let d = env.listen_as(Mode::Allow);
    let (ok, chatter, _wall) = env.run(&fixture("PostToolUse"), &[]);
    assert!(ok);
    assert!(
        chatter.is_empty(),
        "an empty ContextReply is no output at all, not an empty additionalContext"
    );
    let log = d.frame_log();
    assert!(
        log.iter().any(|f| f.starts_with("ContextQuery(")),
        "the pull must still happen: {log:?}"
    );
    assert!(!env.ring_path().exists());
    assert_eq!(env.sidecar("hookshim.context_timeout"), 0);
}

#[test]
fn gate_deadline_exceeded_allows_within_budget() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    env.install_short_gate_map(60);
    let d = env.listen_as(Mode::SlowVerdict);
    let (ok, chatter, wall) = env.run(&fixture("Stop"), &[("MARK1_HOOKSHIM_TIMING", "1")]);
    assert!(ok);
    assert!(chatter.is_empty(), "a blown deadline is allow, not block");
    assert_eq!(d.query().deadline_ms, 50, "60 ms budget − 08 §4.4's 10 ms");
    // The daemon answers LATE_BY past the deadline; the shim's own timer, not
    // the OS scheduler, is what must have answered before.
    assert_gate_timer_honored_deadline(env.timing_ms("hookshim.gate_elapsed_ms"), 50);
    assert!(wall < loose_wall_ceiling(50), "took {wall:?}");
    // The daemon never answered, so it never accounted the event either.
    assert_eq!(unseal_ring(&env).len(), 1, "the event must reach the ring");
    assert_eq!(env.gate_timeouts(), 1, "the fail-open must be counted");
}

#[test]
fn gate_handshake_refused_allows_and_spills() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    // HelloAck{accepted: false} — 08 §4.3 step 3's mid-upgrade refusal. A
    // completed write_all is NOT a delivery; only the ack says so.
    let d = env.listen_as(Mode::RefuseHello);
    let (ok, chatter, _wall) = env.run(&fixture("Stop"), &[]);
    assert!(ok);
    assert!(chatter.is_empty());
    assert!(
        d.no_query(),
        "a refused handshake never carries a GateQuery"
    );
    assert_eq!(unseal_ring(&env).len(), 1);
    assert_eq!(env.gate_timeouts(), 1);
    assert_eq!(env.handshake_refusals(), 1, "M1E-4003 must be counted");
}

#[test]
fn gate_daemon_absent_allows_and_spills() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    // No listener bound at all: connect fails outright.
    let (ok, chatter, _wall) = env.run(&fixture("Stop"), &[]);
    assert!(ok, "Mark 1's absence must never block a developer");
    assert!(chatter.is_empty());
    assert_eq!(unseal_ring(&env).len(), 1);
    assert_eq!(env.gate_timeouts(), 1);
}

#[test]
fn gate_mute_daemon_allows_within_budget() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    env.install_short_gate_map(60);
    // Connection accepted, then silence forever — the F2 shape: before the
    // handshake this was indistinguishable from a healthy daemon and the
    // event vanished with Ok(()) returned and nothing spilled.
    let _d = env.listen_as(Mode::Mute);
    let (ok, chatter, wall) = env.run(&fixture("Stop"), &[("MARK1_HOOKSHIM_TIMING", "1")]);
    assert!(ok);
    assert!(chatter.is_empty());
    assert_gate_timer_honored_deadline(env.timing_ms("hookshim.gate_elapsed_ms"), 50);
    assert!(wall < loose_wall_ceiling(50), "took {wall:?}");
    assert_eq!(
        unseal_ring(&env).len(),
        1,
        "silence must not lose the event"
    );
    assert_eq!(env.gate_timeouts(), 1);
    assert_eq!(
        env.handshake_refusals(),
        0,
        "a mute daemon is a timeout, not a refusal"
    );
}

/// The shipped budget, measured against the shape that abuses it worst: a
/// daemon that accepts the connection and then says nothing, forever. Every
/// other gate test installs a short map, so the number developers actually run
/// went unmeasured — and at the fragment's 30 s it cost 31.4 s per turn end
/// against 217 ms for a daemon that was not running at all. A wedged Mark 1
/// 145x worse than an absent Mark 1 is worse than no product; this is the test
/// that holds the shipped value to the same promise the short maps prove.
#[test]
fn shipped_stop_budget_bounds_a_wedged_daemon() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    // Deliberately NO install_short_gate_map: the map under test is the one in
    // the binary.
    let _d = env.listen_as(Mode::Mute);
    let (ok, chatter, wall) = env.run(&fixture("Stop"), &[("MARK1_HOOKSHIM_TIMING", "1")]);
    assert!(ok);
    assert!(chatter.is_empty(), "silence is allow, not block");
    assert_gate_timer_honored_deadline(
        env.timing_ms("hookshim.gate_elapsed_ms"),
        STOP_HANDSHAKE_MS,
    );
    assert!(
        wall < loose_wall_ceiling(STOP_HANDSHAKE_MS),
        "took {wall:?}"
    );
    assert_eq!(
        unseal_ring(&env).len(),
        1,
        "silence must not lose the event"
    );
    assert_eq!(env.gate_timeouts(), 1, "the fail-open must be counted");
}

/// The connect itself. `UnixStream::connect` against a starved backlog never
/// returns, so before the shared deadline the gate path had NO bound at all:
/// this test did not fail, it hung, and the agent's hook timeout killed it.
#[test]
fn gate_blocked_connect_allows_within_budget() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    env.install_short_gate_map(510);
    let listener = starve_backlog(&env);
    let (ok, chatter, wall) = env.run(&fixture("Stop"), &[("MARK1_HOOKSHIM_TIMING", "1")]);
    assert!(ok, "a parked connect must still exit 0");
    assert!(chatter.is_empty());
    // a connect that never lands is the handshake bound's business (250 ms), not the 500 ms budget's
    assert_gate_timer_honored_deadline(
        env.timing_ms("hookshim.gate_elapsed_ms"),
        STOP_HANDSHAKE_MS,
    );
    assert!(
        wall < loose_wall_ceiling(STOP_HANDSHAKE_MS),
        "took {wall:?}"
    );
    assert_eq!(unseal_ring(&env).len(), 1);
    assert_eq!(env.gate_timeouts(), 1);
    drop(listener);
}

/// A handshake that takes 1500 ms of a 2000 ms budget is a wedged daemon, not a
/// slow one: the shim gives up at the handshake bound (250 ms) and never
/// spends the budget on it — the budget is for a daemon that is there and
/// running the task's anchors.
#[test]
fn gate_silence_after_slow_handshake_costs_the_handshake_bound() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    env.install_short_gate_map(2_010);
    let _d = env.listen_as(Mode::SlowHello);
    let (ok, chatter, wall) = env.run(&fixture("Stop"), &[("MARK1_HOOKSHIM_TIMING", "1")]);
    assert!(ok);
    assert!(chatter.is_empty());
    assert_gate_timer_honored_deadline(
        env.timing_ms("hookshim.gate_elapsed_ms"),
        STOP_HANDSHAKE_MS,
    );
    assert!(
        wall < loose_wall_ceiling(STOP_HANDSHAKE_MS),
        "took {wall:?}"
    );
    assert!(
        wall < HELLO_DELAY,
        "the slow handshake was waited out instead of bounded: {wall:?}"
    );
    assert_eq!(unseal_ring(&env).len(), 1);
    assert_eq!(env.gate_timeouts(), 1);
}

#[test]
fn gate_off_short_circuits_before_any_socket_io() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    // Invariant 2: the off-check precedes ANY gate evaluation, which on the
    // gate path means before the connect. A listener is bound and would
    // announce any connection, so silence on `connected` is the proof.
    let d = env.listen_as(Mode::Block);
    let (ok, chatter, _wall) = env.run(&fixture("Stop"), &[("MARK1_DISABLE", "1")]);
    assert!(ok);
    assert!(chatter.is_empty(), "off must never emit a block decision");
    assert!(
        d.connected
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "off must produce zero fabric I/O — not even a connect"
    );
    assert!(!env.ring_path().exists());
    assert_eq!(env.gate_timeouts(), 0, "off is not a fail-open, it is off");
}

// ---- the SessionEnd drain barrier (NFR-DURABILITY-004; 08 §4.2 Flush row) ----

/// Event ordering IS the property: the Flush must follow the SessionEnd event
/// on the same connection, or the daemon's drain does not cover it. And the
/// ack must be waited for — a Flush fired on the way out the door is not a
/// barrier — which only a late ack can prove.
#[test]
fn session_end_forces_a_flush_after_the_event_and_awaits_the_ack() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let d = env.listen_as(Mode::SlowFlushAck);
    let (ok, chatter, wall) = env.run(&fixture("SessionEnd"), &[]);
    assert!(ok);
    assert!(
        chatter.is_empty(),
        "SessionEnd has nothing returnable (08 §5.1)"
    );
    assert_eq!(
        d.frame_log(),
        ["Hello", "Event(SessionEnd)", "Flush"],
        "the Flush must ride the same connection, after the SessionEnd event"
    );
    assert!(
        wall > FLUSH_ACK_DELAY,
        "the FlushAck was not actually waited on: {wall:?}"
    );
    assert!(wall < fail_open_ceiling(FLUSH_DEADLINE_MS), "took {wall:?}");
    assert!(
        !env.ring_path().exists(),
        "a receipted drain must not spill"
    );
    assert_eq!(env.flush_timeouts(), 0, "a receipted drain is not a miss");
}

/// The daemon reads the Flush and never answers: the shim must return inside
/// its stated deadline — a durability barrier is still never allowed to hold
/// the agent past its budget (08 §4.4) — and the miss must be counted and the
/// event spilled, because an unreceipted drain is exactly a lost SessionEnd.
#[test]
fn session_end_flush_unacked_returns_within_deadline_and_is_counted() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let d = env.listen_as(Mode::NoFlushAck);
    let (ok, chatter, wall) = env.run(&fixture("SessionEnd"), &[("MARK1_HOOKSHIM_TIMING", "1")]);
    assert!(ok, "a mute drain must still exit 0");
    assert!(chatter.is_empty());
    assert_eq!(d.frame_log(), ["Hello", "Event(SessionEnd)", "Flush"]);
    // The shim's own flush timer waited the whole stated deadline and no
    // longer; the wall is only a hang net.
    assert_gate_timer_honored_deadline(
        env.timing_ms("hookshim.flush_elapsed_ms"),
        FLUSH_DEADLINE_MS,
    );
    assert!(
        wall < loose_wall_ceiling(FLUSH_DEADLINE_MS),
        "took {wall:?}"
    );
    let entries = unseal_ring(&env);
    assert_eq!(entries.len(), 1, "an unreceipted SessionEnd must spill");
    match decode_one_event(&entries[0]).body.unwrap() {
        pb::event::Body::SessionEnd(_) => {}
        other => panic!("unexpected body {other:?}"),
    }
    assert_eq!(env.flush_timeouts(), 1, "the missed ack must be counted");
    assert_eq!(
        env.gate_timeouts(),
        0,
        "a missed drain is not a gate fail-open"
    );
}

// ---- maps as data (FR-AGENT-001) ----

#[test]
fn map_file_overrides_builtin_without_binary_change() {
    let env = TestEnv::new();
    let maps_dir = env.home.path().join(".omium/mark1/maps");
    std::fs::create_dir_all(&maps_dir).unwrap();
    // A vendor rename of every field the PreToolUse path reads, fixed
    // purely by map data (08 §5 rule 1).
    std::fs::write(
        maps_dir.join("claudecode.bin"),
        r#"{
          "map_version": 1,
          "agent": "claudecode",
          "agent_version": "9.9.9",
          "event_field": "hookName",
          "session_id_field": "sid",
          "events": {
            "ToolWillRun": {
              "kind": "tool_open",
              "fields": { "tool_name": "toolTitle", "tool_use_id": "invocationId" }
            }
          }
        }"#,
    )
    .unwrap();
    let renamed = format!(
        r#"{{"hookName":"ToolWillRun","sid":"{SESSION}","toolTitle":"Bash","invocationId":"inv_42"}}"#
    );
    let d = env.listen();
    let (ok, _chatter, _wall) = env.run(renamed.as_bytes(), &[]);
    assert!(ok);
    match d.event().body.unwrap() {
        pb::event::Body::ToolUse(b) => {
            assert_eq!(b.tool_name, "Bash");
            assert_eq!(b.tool_use_id, "inv_42");
        }
        other => panic!("unexpected body {other:?}"),
    }
}

#[test]
fn unmapped_hook_emits_nothing_speculative() {
    let env = TestEnv::new();
    let d = env.listen();
    let body = format!(r#"{{"hook_event_name":"BrandNewVendorHook","session_id":"{SESSION}"}}"#);
    let (ok, chatter, _wall) = env.run(body.as_bytes(), &[]);
    assert!(ok);
    assert!(chatter.is_empty());
    assert!(d.no_event());
}

// ---- the wall budget (04 §5: total ≤50 ms, timer-enforced) ----

#[test]
fn cold_start_end_to_end_under_50ms() {
    let env = TestEnv::new();
    let d = env.listen();
    // One warm-up spawn so the very first exec's page-cache misses don't
    // bill this measurement; the budget is per-invocation steady state.
    let _ = env.run(&fixture("SessionEnd"), &[("MARK1_DISABLE", "1")]);
    let (ok, _chatter, wall) = env.run(&fixture("PreToolUse"), &[]);
    assert!(ok);
    assert!(
        d.events.recv_timeout(Duration::from_secs(2)).is_ok(),
        "happy path must reach the fabric"
    );
    assert!(
        wall < Duration::from_millis(50),
        "observer budget blown: {wall:?} (04 §5 step 4)"
    );
}

// ---- statusline mode: the sanctioned plan-usage feed ----

/// A status-line stdin document in the vendor's published shape, with the fields the feed must drop.
const STATUSLINE_STDIN: &str = r#"{"cwd":"/home/u/secret-repo","session_id":"abc","transcript_path":"/home/u/.claude/projects/x/abc.jsonl","model":{"id":"claude-opus-5","display_name":"Opus"},"cost":{"total_cost_usd":0.5},"context_window":{"used_percentage":8,"context_window_size":200000},"prompt_cache":{"warm":true,"hit_ratio":0.91},"rate_limits":{"five_hour":{"used_percentage":23.5,"resets_at":1738425600},"seven_day":{"used_percentage":41.2,"resets_at":1738857600}}}"#;

#[test]
fn statusline_files_the_rate_limit_slice_and_nothing_else() {
    let env = TestEnv::new();
    let d = env.listen();
    let (ok, chatter, _wall) = env.statusline(STATUSLINE_STDIN.as_bytes(), &[]);
    assert!(ok);
    let line = String::from_utf8_lossy(&chatter);
    assert!(
        line.starts_with("Mark 1 · ") && line.contains("5h ") && line.contains("7d "),
        "no previous command ⇒ Mark 1's own one-liner (model + both windows), got {line:?}"
    );
    assert!(d.no_event(), "statusline mode never touches the fabric");
    let log = std::fs::read_to_string(env.ratelimits_path()).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 1);
    let rec: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let keys: Vec<&str> = rec
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "context_window",
            "model",
            "prompt_cache",
            "rate_limits",
            "received_at"
        ]
    );
    assert_eq!(rec["rate_limits"]["five_hour"]["used_percentage"], 23.5);
    assert_eq!(rec["model"]["id"], "claude-opus-5");
    assert!(rec["received_at"].as_u64().unwrap() > 1_700_000_000);
    assert!(!log.contains("secret-repo") && !log.contains("transcript") && !log.contains("cost"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(env.ratelimits_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn statusline_replays_stdin_to_the_previous_command() {
    let env = TestEnv::new();
    env.install_statusline_prev("printf 'prev:%s' \"$(cat)\"");
    let (ok, chatter, _wall) = env.statusline(b"{\"rate_limits\":{}}", &[]);
    assert!(ok);
    assert_eq!(chatter, b"prev:{\"rate_limits\":{}}");
    assert!(env.ratelimits_path().exists());
}

#[test]
fn statusline_off_still_chains_but_records_nothing() {
    let env = TestEnv::new();
    env.install_statusline_prev("printf theirs");
    let (ok, chatter, _wall) =
        env.statusline(STATUSLINE_STDIN.as_bytes(), &[("MARK1_DISABLE", "1")]);
    assert!(ok);
    assert_eq!(
        chatter, b"theirs",
        "the user's display must not depend on Mark 1 being on"
    );
    assert!(!env.ratelimits_path().exists());
}

#[test]
fn statusline_off_marker_prints_nothing_of_ours_but_still_records() {
    let env = TestEnv::new();
    let dir = env.home.path().join(".omium/mark1/claude");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("statusline.off"), b"off\n").unwrap();
    let (ok, chatter, _wall) = env.statusline(STATUSLINE_STDIN.as_bytes(), &[]);
    assert!(ok);
    assert!(
        chatter.is_empty(),
        "the app's switch keeps Mark 1's own line out of the footer, got {:?}",
        String::from_utf8_lossy(&chatter)
    );
    assert!(
        env.ratelimits_path().exists(),
        "the plan feed is not what the switch turns off"
    );
    env.install_statusline_prev("printf theirs");
    let (_, chatter, _) = env.statusline(STATUSLINE_STDIN.as_bytes(), &[]);
    assert_eq!(
        chatter, b"theirs",
        "their own line is never the switch's business"
    );
}

#[test]
fn statusline_keeps_the_newest_2000_lines() {
    let env = TestEnv::new();
    let dir = env.home.path().join(".omium/mark1/claude");
    std::fs::create_dir_all(&dir).unwrap();
    let old: String = (0..2005)
        .map(|i| format!("{{\"received_at\":{i}}}\n"))
        .collect();
    std::fs::write(env.ratelimits_path(), old).unwrap();
    let (ok, _chatter, _wall) = env.statusline(STATUSLINE_STDIN.as_bytes(), &[]);
    assert!(ok);
    let log = std::fs::read_to_string(env.ratelimits_path()).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 2000);
    assert_eq!(lines[0], "{\"received_at\":6}", "the oldest lines go first");
    assert!(
        lines[1999].contains("claude-opus-5"),
        "the new record is the newest line"
    );
    assert!(!dir.join("ratelimits.jsonl.tmp").exists());
}

#[test]
fn statusline_garbage_stdin_is_a_silent_noop() {
    let env = TestEnv::new();
    let (ok, chatter, _wall) = env.statusline(b"not json", &[]);
    assert!(ok);
    assert_eq!(
        String::from_utf8_lossy(&chatter),
        "Mark 1",
        "garbage stdin ⇒ the bare label, nothing filed"
    );
    assert!(!env.ratelimits_path().exists());
}
