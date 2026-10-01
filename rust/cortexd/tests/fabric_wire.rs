//! cortexd's M1PL client half against a listener enforcing mark1d's real
//! handshake rules (go/mark1d/internal/fabric/session.go): the first frame
//! must be a FabricFrame carrying Hello (08 §4.3 step 2), and a Hello without
//! a 16-byte non-zero `session_id` is refused with the M1E-4003 close (D-AT).
//!
//! cortexd has no session of its own; it Hellos with the one mark1d publishes
//! for its workspace (`--session-file`, go/mark1d/internal/cortex). What these
//! pin: with a published session the handshake is ACCEPTED and the event lands
//! carrying that session; without one nothing connects and nothing is counted
//! (held is not dropped); and a refusal the daemon does answer with (a
//! mid-upgrade `accepted:false`) is counted instead of reported as success —
//! the old client sent a bare event, never handshook, and returned `Ok(())`
//! for every one of them.

// clippy.toml's allow-*-in-tests exempts #[test] fns; the helpers here are
// plain fns, so the exemption is restated at file scope (house style).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use m1p_wire::pb;

/// The one session this stub daemon answers `accepted:false` to — 08 §4.3
/// step 3's mid-upgrade refusal, keyed on a session id only so one listener
/// can serve every test in this binary. A test knob, not daemon behaviour.
const REFUSED_SESSION: [u8; 16] = [0xEE; 16];

struct Daemon {
    /// Every frame each connection carried, in order, or why the daemon could
    /// not read one.
    frames: Mutex<mpsc::Receiver<Result<pb::FabricFrame, String>>>,
    /// One test at a time on the shared channel: cargo runs tests in parallel
    /// and interleaved connections would interleave frames.
    serial: Mutex<()>,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

/// One listener for the whole test binary: `fabric::endpoints()` reads
/// process-global env, so a socket per test would race on it. `get_or_init`
/// blocks the second test until the env is set, and nothing in this binary
/// reads those vars before it.
fn daemon() -> &'static Daemon {
    static DAEMON: OnceLock<Daemon> = OnceLock::new();
    DAEMON.get_or_init(|| {
        let xdg = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", xdg.path());
        std::env::set_var("HOME", home.path());

        let sock = xdg.path().join("omium-mark1/m1p.sock");
        std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&sock).unwrap();
        let (tx, frames) = mpsc::channel();
        std::thread::spawn(move || {
            while let Ok((stream, _addr)) = listener.accept() {
                serve(stream, &tx);
            }
        });
        Daemon {
            frames: Mutex::new(frames),
            serial: Mutex::new(()),
            _dirs: (xdg, home),
        }
    })
}

/// mark1d's `session.frame` path, verbatim in behaviour: record every frame,
/// demand Hello first, demand a 16-byte non-zero session_id, close without an
/// ack when either fails, ack otherwise and keep reading until the writer
/// hangs up.
fn serve(mut stream: UnixStream, out: &mpsc::Sender<Result<pb::FabricFrame, String>>) {
    let mut dec = m1p_wire::FrameDecoder::new();
    let mut buf = [0u8; 4096];
    let mut helloed = false;
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) if helloed => return,
            Ok(0) => return send(out, Err("writer closed before any frame".to_owned())),
            Err(e) => return send(out, Err(format!("read: {e}"))),
            Ok(n) => n,
        };
        let frames = match dec.feed_frames(&buf[..n]) {
            Ok(f) => f,
            Err(e) => return send(out, Err(format!("undecodable FabricFrame: {e}"))),
        };
        for frame in frames {
            send(out, Ok(frame.clone()));
            if helloed {
                continue;
            }
            let Some(pb::fabric_frame::Kind::Hello(h)) = frame.kind else {
                return; // M1E-4003: first frame is not Hello.
            };
            if h.session_id.len() != 16 || h.session_id.iter().all(|b| *b == 0) {
                return; // M1E-4003: D-AT — no session is not a session.
            }
            let refused = h.session_id == REFUSED_SESSION;
            let mut ack = Vec::new();
            m1p_wire::encode_control(
                &pb::FabricFrame {
                    kind: Some(pb::fabric_frame::Kind::HelloAck(pb::HelloAck {
                        accepted: !refused,
                        max_frame: m1p_wire::M1PL_MAX_FRAME,
                        want_ver: u32::from(refused),
                        session_id: Vec::new(),
                    })),
                },
                &mut ack,
            )
            .unwrap();
            let _ = stream.write_all(&ack);
            if refused {
                return;
            }
            helloed = true;
        }
    }
}

fn send(tx: &mpsc::Sender<Result<pb::FabricFrame, String>>, msg: Result<pb::FabricFrame, String>) {
    let _ = tx.send(msg);
}

fn next_frame(d: &Daemon) -> pb::FabricFrame {
    d.frames
        .lock()
        .unwrap()
        .recv_timeout(Duration::from_secs(5))
        .expect("cortexd never connected")
        .unwrap_or_else(|e| panic!("mark1d could not read cortexd's frame: {e}"))
}

/// A `Shared` whose session file names `sid` — what mark1d writes at
/// `<state>/run/sessions/<ws>.json` once the workspace has a live session.
fn shared_with_session(sid: [u8; 16]) -> (Arc<cortexd::session::Shared>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ws.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"session_id_hex":"{}","started_at":"2026-09-15T10:00:00Z"}}"#,
            sid.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ),
    )
    .unwrap();
    let shared = Arc::new(cortexd::session::Shared::new(
        PathBuf::from("."),
        PathBuf::from("."),
        2_000,
    ));
    shared.session_file.set(path).unwrap();
    (shared, dir)
}

fn event() -> pb::Event {
    cortexd::fabric::cortex_injection_event([1u8; 32], 7, 0, 0, pb::InjectionChannel::Unspecified)
}

fn settle(counter: &std::sync::atomic::AtomicU64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(5);
    while counter.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    counter.load(Ordering::Relaxed)
}

/// Multi-thread flavour on purpose: `spawn_push` puts the work on the ambient
/// runtime, and a current-thread runtime blocked on `recv_timeout` would never
/// poll it.
#[tokio::test(flavor = "multi_thread")]
async fn first_frame_is_the_hello_mark1d_demands() {
    let d = daemon();
    let _serial = d.serial.lock().unwrap_or_else(|e| e.into_inner());
    let sid = [0x11u8; 16];
    let (shared, _dir) = shared_with_session(sid);
    cortexd::fabric::spawn_push(&shared, event());
    match next_frame(d).kind {
        Some(pb::fabric_frame::Kind::Hello(h)) => {
            assert_eq!(h.component, "cortexd");
            assert!(h.pid > 0, "Hello must name the writer's pid");
            assert!(!h.version.is_empty(), "Hello must carry the crate version");
            assert_eq!(
                h.session_id, sid,
                "Hello carries the daemon-published session (D-AT)"
            );
        }
        other => panic!("first frame is not Hello, so mark1d closes M1E-4003: {other:?}"),
    }
    // Drain the event so the shared channel is clean for the next test.
    let _ = next_frame(d);
}

/// D-AV's clause, closed from the daemon side: a Hello carrying the session
/// the daemon published is admitted, and the CortexInjection lands under it.
#[tokio::test(flavor = "multi_thread")]
async fn sessioned_hello_is_accepted() {
    let d = daemon();
    let _serial = d.serial.lock().unwrap_or_else(|e| e.into_inner());
    let sid = [0x22u8; 16];
    let (shared, _dir) = shared_with_session(sid);
    cortexd::fabric::spawn_root_push(&shared, [9u8; 32], 3);
    let hello = next_frame(d);
    assert!(matches!(hello.kind, Some(pb::fabric_frame::Kind::Hello(_))));
    match next_frame(d).kind {
        Some(pb::fabric_frame::Kind::Event(ev)) => {
            assert_eq!(
                ev.session_id, sid,
                "the record says what the connection attributes"
            );
            match ev.body {
                Some(pb::event::Body::CortexInjection(ci)) => {
                    assert_eq!(ci.root_hash, [9u8; 32]);
                    assert_eq!(ci.index_clock, 3);
                }
                other => panic!("not a root push: {other:?}"),
            }
        }
        other => panic!("no event followed the accepted Hello: {other:?}"),
    }
    // Nothing was lost and nothing was refused.
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(shared.fabric_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(shared.fabric_handshake_refused.load(Ordering::Relaxed), 0);
}

/// No session published ⇒ nothing connects, nothing is counted: a held push
/// is not a drop. The flush lands it once the daemon publishes one.
#[tokio::test(flavor = "multi_thread")]
async fn no_session_holds_the_push_until_one_is_published() {
    let d = daemon();
    let _serial = d.serial.lock().unwrap_or_else(|e| e.into_inner());
    let shared = Arc::new(cortexd::session::Shared::new(
        PathBuf::from("."),
        PathBuf::from("."),
        2_000,
    ));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ws.json");
    shared.session_file.set(path.clone()).unwrap();

    cortexd::fabric::spawn_root_push(&shared, [4u8; 32], 1);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        shared.fabric_dropped.load(Ordering::Relaxed),
        0,
        "held is not dropped"
    );
    assert_eq!(shared.fabric_handshake_refused.load(Ordering::Relaxed), 0);
    assert!(
        d.frames.lock().unwrap().try_recv().is_err(),
        "a session-less cortexd must not connect at all"
    );

    // mark1d publishes the workspace's session: the held root lands under it.
    let sid = [0x33u8; 16];
    std::fs::write(
        &path,
        format!(
            r#"{{"session_id_hex":"{}","started_at":"2026-09-15T10:00:00Z"}}"#,
            sid.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ),
    )
    .unwrap();
    cortexd::fabric::flush(&shared);
    let hello = next_frame(d);
    match hello.kind {
        Some(pb::fabric_frame::Kind::Hello(h)) => assert_eq!(h.session_id, sid),
        other => panic!("{other:?}"),
    }
    match next_frame(d).kind {
        Some(pb::fabric_frame::Kind::Event(ev)) => assert_eq!(ev.session_id, sid),
        other => panic!("{other:?}"),
    }
}

/// The refusal that still exists — the daemon answering `accepted:false`
/// (08 §4.3 step 3) — is counted, never reported as success.
#[tokio::test(flavor = "multi_thread")]
async fn refused_handshake_is_counted_and_is_not_success() {
    let d = daemon();
    let _serial = d.serial.lock().unwrap_or_else(|e| e.into_inner());
    let (shared, _dir) = shared_with_session(REFUSED_SESSION);
    cortexd::fabric::spawn_push(&shared, event());
    let _ = next_frame(d); // the Hello the stub refuses
    assert_eq!(
        settle(&shared.fabric_handshake_refused),
        1,
        "the daemon refused our Hello; a push that reports success there is the 100% silent loss D-AV closed"
    );
    assert_eq!(
        shared.fabric_dropped.load(Ordering::Relaxed),
        0,
        "a refusal is not an unreachable daemon — separate facts, separate counters"
    );
}
