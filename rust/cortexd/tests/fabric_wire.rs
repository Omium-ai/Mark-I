//! cortexd's M1PL client half against a listener enforcing mark1d's real
//! handshake rules (go/mark1d/internal/fabric/session.go): the first frame
//! must be a FabricFrame carrying Hello (08 §4.3 step 2), and a Hello without
//! a 16-byte non-zero `session_id` is refused with the M1E-4003 close (D-AT).
//!
//! cortexd has no session identity, so the refusal IS the expected outcome
//! until Phase 2 (D-AV). What these pin is that cortexd speaks the protocol
//! at all, and that the refusal is counted instead of reported as success —
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

struct Daemon {
    /// Each connection's first frame, or why the daemon could not read one.
    first: Mutex<mpsc::Receiver<Result<pb::FabricFrame, String>>>,
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
        let (tx, first) = mpsc::channel();
        std::thread::spawn(move || {
            while let Ok((stream, _addr)) = listener.accept() {
                serve(stream, &tx);
            }
        });
        Daemon {
            first: Mutex::new(first),
            _dirs: (xdg, home),
        }
    })
}

/// mark1d's `session.frame` first-frame path, verbatim in behaviour: record
/// the frame, demand Hello, demand a 16-byte non-zero session_id, and close
/// without an ack when either fails.
fn serve(mut stream: UnixStream, first: &mpsc::Sender<Result<pb::FabricFrame, String>>) {
    let mut dec = m1p_wire::FrameDecoder::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => return send(first, Err("writer closed before any frame".to_owned())),
            Err(e) => return send(first, Err(format!("read: {e}"))),
            Ok(n) => n,
        };
        let frames = match dec.feed_frames(&buf[..n]) {
            Ok(f) => f,
            Err(e) => return send(first, Err(format!("undecodable FabricFrame: {e}"))),
        };
        let Some(frame) = frames.into_iter().next() else {
            continue;
        };
        send(first, Ok(frame.clone()));
        let Some(pb::fabric_frame::Kind::Hello(h)) = frame.kind else {
            return; // M1E-4003: first frame is not Hello.
        };
        if h.session_id.len() != 16 || h.session_id.iter().all(|b| *b == 0) {
            return; // M1E-4003: D-AT — no session is not a session.
        }
        let mut out = Vec::new();
        m1p_wire::encode_control(
            &pb::FabricFrame {
                kind: Some(pb::fabric_frame::Kind::HelloAck(pb::HelloAck {
                    accepted: true,
                    max_frame: m1p_wire::M1PL_MAX_FRAME,
                    want_ver: 0,
                })),
            },
            &mut out,
        )
        .unwrap();
        let _ = stream.write_all(&out);
        return;
    }
}

fn send(tx: &mpsc::Sender<Result<pb::FabricFrame, String>>, msg: Result<pb::FabricFrame, String>) {
    let _ = tx.send(msg);
}

fn shared() -> Arc<cortexd::session::Shared> {
    Arc::new(cortexd::session::Shared::new(
        PathBuf::from("."),
        PathBuf::from("."),
        2_000,
    ))
}

fn event() -> pb::Event {
    cortexd::fabric::cortex_injection_event([1u8; 32], 7, 0, 0, pb::InjectionChannel::Unspecified)
}

/// Multi-thread flavour on purpose: `spawn_push` puts the work on the ambient
/// runtime, and a current-thread runtime blocked on `recv_timeout` would never
/// poll it.
#[tokio::test(flavor = "multi_thread")]
async fn first_frame_is_the_hello_mark1d_demands() {
    let d = daemon();
    cortexd::fabric::spawn_push(&shared(), event());
    let got = d
        .first
        .lock()
        .unwrap()
        .recv_timeout(Duration::from_secs(5))
        .expect("cortexd never connected");
    let frame = got.unwrap_or_else(|e| panic!("mark1d could not read cortexd's first frame: {e}"));
    match frame.kind {
        Some(pb::fabric_frame::Kind::Hello(h)) => {
            assert_eq!(h.component, "cortexd");
            assert!(h.pid > 0, "Hello must name the writer's pid");
            assert!(!h.version.is_empty(), "Hello must carry the crate version");
        }
        other => panic!("first frame is not Hello, so mark1d closes M1E-4003: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_handshake_is_counted_and_is_not_success() {
    daemon();
    let shared = shared();
    cortexd::fabric::spawn_push(&shared, event());
    let deadline = Instant::now() + Duration::from_secs(5);
    while shared.fabric_handshake_refused.load(Ordering::Relaxed) == 0 && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        shared.fabric_handshake_refused.load(Ordering::Relaxed),
        1,
        "the daemon closed on our session-less Hello; a push that reports success there is the 100% silent loss D-AV closed"
    );
    assert_eq!(
        shared.fabric_dropped.load(Ordering::Relaxed),
        0,
        "a refusal is not an unreachable daemon — separate facts, separate counters"
    );
}
