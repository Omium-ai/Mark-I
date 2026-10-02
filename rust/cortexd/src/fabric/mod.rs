//! M1PL client → mark1d (04 §6 `fabric.rs`): CortexInjection events + L0 root
//! pushes. Deadlines per 08 §4.4 — 100 ms connect, then 250 ms for the whole
//! post-connect exchange. cortexd's pushes are DROPPABLE by contract
//! (08 §4.4): recomputable, counted, never blocking an index pass or an MCP
//! answer.
//!
//! EVERY connection opens with `Hello` and waits for `HelloAck` (08 §4.3
//! steps 2-3), the same shape the hookshim sibling ships. Not ceremony:
//! mark1d closes any connection whose first frame is not Hello (M1E-4003),
//! and `write_all` completes into the kernel buffer of a socket the daemon is
//! about to close — so without the handshake every push returned `Ok(())`,
//! nothing was delivered, and `fabric_dropped` read zero. There is no
//! per-event ack (08 §4.3 step 4), so the HelloAck is the only delivery
//! evidence this fabric has.
//!
//! THE SESSION. D-AT requires a 16-byte non-zero `session_id` from every
//! writer and D-AV struck cortexd's exemption. cortexd is a per-WORKSPACE
//! daemon with no session of its own, so the identity comes from the party
//! that has one: mark1d publishes the workspace's live agent session at the
//! `--session-file` path (go/mark1d/internal/cortex) and every push here
//! reads it first. A push with a session Hellos with it and stamps it on the
//! event; a push without one is HELD — kept in `Shared::pending`, delivered
//! by `flush` the moment a session appears — and counts nothing, because a
//! held push is not a drop. A synthetic id was never an option: it would
//! attribute every event to a session that does not exist, which is the lie
//! D-AT exists to end.

#[cfg(unix)]
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use m1p_wire::pb;

use crate::session::{Shared, PENDING_CAP};

/// 08 §4.4 deadlines, verbatim.
const CONNECT_DEADLINE: Duration = Duration::from_millis(100);
const WRITE_DEADLINE: Duration = Duration::from_millis(250);

/// How often `flush_loop` re-reads the session file while pushes are held.
/// Only while: with nothing pending the loop reads nothing.
pub const FLUSH_EVERY: Duration = Duration::from_secs(1);

/// Endpoint per the hookshim sibling: `$XDG_RUNTIME_DIR/omium-mark1/m1p.sock`,
/// fallback `~/.omium/mark1/m1p.sock`.
#[cfg(unix)]
fn endpoints() -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(2);
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        out.push(PathBuf::from(xdg).join("omium-mark1/m1p.sock"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        out.push(PathBuf::from(home).join(".omium/mark1/m1p.sock"));
    }
    out
}

/// Build the one event shape cortexd emits. `CortexInjection` carries both
/// serve accounting (04 §6.4) and the bare root push (04 §6.7) — 07 defines
/// no dedicated root-push message, and `root_hash` + `index_clock` are
/// exactly what `mark1d.anchors` stamps into `AnchorIntegrity`.
pub fn cortex_injection_event(
    root_hash: [u8; 32],
    index_clock: u64,
    token_budget: u32,
    tokens_used: u32,
    channel: pb::InjectionChannel,
) -> pb::Event {
    envelope(pb::event::Body::CortexInjection(pb::CortexInjection {
        root_hash: root_hash.to_vec(),
        index_clock,
        token_budget,
        tokens_used,
        channel: channel as i32,
    }))
}

/// 08 §6.6 / FR-REMEMBER-005: one per served `memory_recall`, exactly the ids served.
pub fn memory_injection_event(artifact_ids: Vec<Vec<u8>>, tokens_used: u32) -> pb::Event {
    envelope(pb::event::Body::MemoryInjection(pb::MemoryInjection {
        artifact_ids,
        channel: pb::InjectionChannel::McpPull as i32,
        tokens_used,
    }))
}

fn envelope(body: pb::event::Body) -> pb::Event {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    pb::Event {
        event_id: uuid::Uuid::now_v7().into_bytes().to_vec(),
        // seq/session_epoch are assigned by mark1d at admission (07 §2).
        // session_id is stamped at delivery from the daemon-published live
        // session (`spawn_push`); it is empty here because the event may be
        // held until one exists, and the session it lands under is the one
        // live THEN.
        seq: 0,
        session_id: Vec::new(),
        task_id: Vec::new(),
        occurred_at: Some(m1p_wire::google::protobuf::Timestamp {
            seconds: now.as_secs() as i64,
            nanos: now.subsec_nanos() as i32,
        }),
        session_epoch: 0,
        tenant_id: Vec::new(), // SERVER-STAMPED band: must be unset on the wire
        device_id: Vec::new(),
        received_at: None,
        clock_skew_ms: 0,
        body: Some(body),
    }
}

/// Why a push did not land. Two facts, two counters (D-AV): `Unavailable` is
/// nobody listening; `HandshakeRefused` is mark1d answering M1E-4003.
#[derive(Debug, thiserror::Error)]
pub enum PushError {
    #[error("fabric unavailable: {0}")]
    Unavailable(#[from] std::io::Error),
    #[error("M1E-4003: mark1d refused the handshake")]
    HandshakeRefused,
}

/// The 04 §6.7 root push, as distinct from 04 §6.4 serve accounting: a held
/// root push is superseded by the next one (only the newest root is true),
/// where held serve events are each a record and queue.
fn is_root_push(ev: &pb::Event) -> bool {
    matches!(
        ev.body,
        Some(pb::event::Body::CortexInjection(ref ci))
            if ci.channel == pb::InjectionChannel::Unspecified as i32
    )
}

/// Fire-and-forget push. With a live session the event is delivered under
/// it (after anything held); without one it is held. Errors are counted,
/// never raised: a cortexd push is recomputable by definition (08 §4.4).
pub fn spawn_push(shared: &Arc<Shared>, event: pb::Event) {
    if is_root_push(&event) {
        // A newer root supersedes a held one — flushing the old one after
        // this would hand the daemon a root the tree has moved past.
        pending(shared).retain(|e| !is_root_push(e));
    }
    let Some(sid) = shared.live_session() else {
        hold(shared, event);
        return;
    };
    flush_under(shared, sid);
    spawn_deliver(shared, sid, event);
}

fn pending(shared: &Shared) -> std::sync::MutexGuard<'_, Vec<pb::Event>> {
    shared.pending.lock().unwrap_or_else(|e| e.into_inner())
}

/// Keep an event for the next session. Bounded: past PENDING_CAP the oldest
/// serve record is dropped and counted in `fabric_dropped`, because at that
/// point it IS a loss — a held push is not, and holding is not counted. The
/// root push is never the one evicted: it is the anchors' integrity input
/// (04 §6.7), and there is only ever one held.
fn hold(shared: &Arc<Shared>, event: pb::Event) {
    let mut p = pending(shared);
    if p.len() >= PENDING_CAP {
        if let Some(i) = p.iter().position(|e| !is_root_push(e)) {
            p.remove(i);
            shared.fabric_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    p.push(event);
}

/// Deliver everything held, in order, under the session that just appeared.
/// Public so `flush_loop` and the tests can drive it; `spawn_push` calls it
/// first so a held root never lands after a fresh one.
pub fn flush(shared: &Arc<Shared>) {
    if let Some(sid) = shared.live_session() {
        flush_under(shared, sid);
    }
}

fn flush_under(shared: &Arc<Shared>, sid: [u8; 16]) {
    let held = std::mem::take(&mut *pending(shared));
    for ev in held {
        spawn_deliver(shared, sid, ev);
    }
}

/// The hold's other half: once a session exists, held pushes must not wait
/// for the next index settle or tool call to be noticed. Spawned once from
/// main.rs; reads the session file only while something is held.
pub async fn flush_loop(shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(FLUSH_EVERY);
    loop {
        tick.tick().await;
        if !pending(&shared).is_empty() {
            flush(&shared);
        }
    }
}

fn spawn_deliver(shared: &Arc<Shared>, sid: [u8; 16], mut event: pb::Event) {
    event.session_id = sid.to_vec();
    let shared = Arc::clone(shared);
    // Called from both the writer thread and MCP tasks; use the ambient
    // runtime when present, else count the drop (daemon shutting down).
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        shared.fabric_dropped.fetch_add(1, Ordering::Relaxed);
        return;
    };
    handle.spawn(async move {
        if let Err(e) = push(sid, &event).await {
            let counter = match e {
                PushError::HandshakeRefused => &shared.fabric_handshake_refused,
                PushError::Unavailable(_) => &shared.fabric_dropped,
            };
            let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::debug!(error = %e, total = n, "fabric push lost (DIAGNOSTIC)");
        }
    });
}

/// Root push on every index-clock bump (04 §6.7). Spawned from the writer
/// thread — it holds a runtime handle via `spawn_push`'s ambient lookup, so
/// the writer thread must be spawned from within the runtime (main.rs does).
pub fn spawn_root_push(shared: &Arc<Shared>, root_hash: [u8; 32], index_clock: u64) {
    let ev = cortex_injection_event(
        root_hash,
        index_clock,
        0,
        0,
        pb::InjectionChannel::Unspecified,
    );
    spawn_push(shared, ev);
}

async fn push(sid: [u8; 16], event: &pb::Event) -> Result<(), PushError> {
    let mut frame = Vec::new();
    m1p_wire::encode_frame(event, &mut frame)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let stream = connect().await?;
    // Handshake and event share ONE budget. Re-spending the write
    // deadline per step is how the hookshim sibling overran the
    // deadline it had itself stated.
    tokio::time::timeout(WRITE_DEADLINE, deliver(stream, sid, &frame))
        .await
        .unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into()))
}

#[cfg(unix)]
async fn connect() -> std::io::Result<tokio::net::UnixStream> {
    let mut last = std::io::Error::from(std::io::ErrorKind::NotFound);
    for path in endpoints() {
        let connect = tokio::net::UnixStream::connect(&path);
        match tokio::time::timeout(CONNECT_DEADLINE, connect).await {
            // A daemon that answered is the daemon; a refusal from it is an
            // answer, not a reason to try the fallback endpoint.
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last = e,
            Err(_) => last = std::io::Error::from(std::io::ErrorKind::TimedOut),
        }
    }
    Err(last)
}

/// 07 §5's named pipe. ERROR_PIPE_BUSY is the daemon between accepts (go-winio
/// listens only while an Accept is pending), retried inside the connect budget.
#[cfg(windows)]
async fn connect() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    open_pipe(&mark1_harden::fabric_pipe_name()?).await
}

#[cfg(windows)]
async fn open_pipe(
    name: &str,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    let deadline = tokio::time::Instant::now() + CONNECT_DEADLINE;
    loop {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(name) {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {}
            r => return r,
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// Hello → HelloAck → event on one connection (08 §4.3 steps 2-4).
async fn deliver<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    sid: [u8; 16],
    event_frame: &[u8],
) -> Result<(), PushError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut hello = Vec::new();
    m1p_wire::encode_control(
        &pb::FabricFrame {
            kind: Some(pb::fabric_frame::Kind::Hello(pb::Hello {
                component: "cortexd".to_owned(),
                pid: std::process::id(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                // The daemon-published live session (D-AT): the same id the
                // event carries, so what the connection attributes and what
                // the record says agree.
                cwd: String::new(),
                session_id: sid.to_vec(),
                host_correlation_id: String::new(),
                host_manifest: None,
            })),
        },
        &mut hello,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    stream.write_all(&hello).await?;

    let mut dec = m1p_wire::FrameDecoder::new();
    // A HelloAck frames to ~20 bytes; nothing else arrives before it.
    let mut buf = [0u8; 64];
    loop {
        // 0 bytes is mark1d's M1E-4003 close reaching us as EOF (08 §4.3
        // step 2) — the refusal carries no frame, so EOF IS the answer, and
        // it must never look like a delivery.
        let n = match stream.read(&mut buf).await? {
            0 => return Err(PushError::HandshakeRefused),
            n => n,
        };
        let frames = dec
            .feed_frames(&buf[..n])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let Some(f) = frames.into_iter().next() else {
            continue;
        };
        return match f.kind {
            Some(pb::fabric_frame::Kind::HelloAck(ack)) if ack.accepted => {
                stream.write_all(event_frame).await.map_err(PushError::from)
            }
            // accepted = false is 08 §4.3 step 3's mid-upgrade version refusal.
            Some(pb::fabric_frame::Kind::HelloAck(_)) => Err(PushError::HandshakeRefused),
            // Any other arm is a daemon speaking a dialect this client does not.
            _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidData).into()),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn event_frames_as_a_fabric_frame_event_arm() {
        let ev = cortex_injection_event([9u8; 32], 42, 2000, 1234, pb::InjectionChannel::McpPull);
        assert_eq!(ev.event_id.len(), 16);
        assert!(ev.tenant_id.is_empty(), "server-stamped band must be unset");
        let mut frame = Vec::new();
        m1p_wire::encode_frame(&ev, &mut frame).unwrap();
        assert_eq!(&frame[..4], b"M1PL");
        // D-U: what mark1d's `unwrap` reads as FabricFrame field 1 must be the
        // Event arm. A bare Event on the wire would put `event_id` in that slot.
        let mut dec = m1p_wire::FrameDecoder::new();
        let frames = dec.feed_frames(&frame).unwrap();
        match frames.first().and_then(|f| f.kind.as_ref()) {
            Some(pb::fabric_frame::Kind::Event(got)) => assert_eq!(got.event_id, ev.event_id),
            other => panic!("payload is not a FabricFrame Event arm: {other:?}"),
        }
    }

    /// No session ⇒ held, not dropped: the counters stay at zero, the newest
    /// root supersedes an older held one, and serve accounting queues up to
    /// the cap — past it the oldest IS a counted loss.
    #[tokio::test]
    async fn pushes_without_a_session_are_held_not_dropped() {
        let shared = Arc::new(Shared::new(PathBuf::from("."), PathBuf::from("."), 2_000));
        spawn_root_push(&shared, [1u8; 32], 1);
        spawn_root_push(&shared, [2u8; 32], 2);
        {
            let p = pending(&shared);
            assert_eq!(p.len(), 1, "a held root is superseded, never queued");
            assert!(
                matches!(&p[0].body, Some(pb::event::Body::CortexInjection(ci)) if ci.root_hash == [2u8; 32])
            );
        }
        for i in 0..PENDING_CAP as u32 + 4 {
            spawn_push(
                &shared,
                cortex_injection_event([0u8; 32], 3, 2000, i, pb::InjectionChannel::McpPull),
            );
        }
        let p = pending(&shared);
        assert_eq!(p.len(), PENDING_CAP);
        assert!(
            p.iter().any(is_root_push),
            "the root push is never the one evicted"
        );
        drop(p);
        assert_eq!(
            shared.fabric_dropped.load(Ordering::Relaxed),
            5,
            "5 serve records past the cap"
        );
        assert_eq!(shared.fabric_handshake_refused.load(Ordering::Relaxed), 0);
    }

    /// 07 §5's Windows endpoint: Hello, HelloAck, then the CortexInjection lands on a
    /// byte-mode pipe, decoded server-side with the production decoder.
    #[cfg(windows)]
    #[tokio::test]
    async fn deliver_lands_on_a_named_pipe() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::windows::named_pipe::ServerOptions;

        let name = format!(r"\\.\pipe\omium-mark1-test-{}", uuid::Uuid::now_v7());
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        let srv = tokio::spawn(async move {
            server.connect().await.unwrap();
            let mut server = server;
            let mut dec = m1p_wire::FrameDecoder::new();
            let mut buf = [0u8; 1024];
            let mut got = Vec::new();
            while got.len() < 2 {
                let n = server.read(&mut buf).await.unwrap();
                assert_ne!(n, 0);
                for f in dec.feed_frames(&buf[..n]).unwrap() {
                    got.push(f);
                    if got.len() == 1 {
                        let mut ack = Vec::new();
                        m1p_wire::encode_control(
                            &pb::FabricFrame {
                                kind: Some(pb::fabric_frame::Kind::HelloAck(pb::HelloAck {
                                    accepted: true,
                                    max_frame: m1p_wire::M1PL_MAX_FRAME,
                                    want_ver: 1,
                                    session_id: Vec::new(),
                                })),
                            },
                            &mut ack,
                        )
                        .unwrap();
                        server.write_all(&ack).await.unwrap();
                    }
                }
            }
            got
        });
        let ev = cortex_injection_event([4u8; 32], 9, 2000, 10, pb::InjectionChannel::McpPull);
        let mut frame = Vec::new();
        m1p_wire::encode_frame(&ev, &mut frame).unwrap();
        deliver(open_pipe(&name).await.unwrap(), [6u8; 16], &frame)
            .await
            .unwrap();
        let got = srv.await.unwrap();
        assert!(
            matches!(&got[0].kind, Some(pb::fabric_frame::Kind::Hello(h)) if h.component == "cortexd" && h.session_id == [6u8; 16])
        );
        assert!(
            matches!(&got[1].kind, Some(pb::fabric_frame::Kind::Event(e)) if e.event_id == ev.event_id)
        );
    }

    /// Nobody listening on the pipe is Unavailable within the budget, the counted drop.
    #[cfg(windows)]
    #[tokio::test]
    async fn absent_pipe_is_a_counted_drop_not_a_hang() {
        let started = std::time::Instant::now();
        let absent = format!(r"\\.\pipe\omium-mark1-test-{}", uuid::Uuid::now_v7());
        assert_eq!(
            open_pipe(&absent).await.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::NotFound)
        );
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn absent_daemon_is_a_counted_drop_not_a_hang() {
        // Point both endpoints at an empty dir so a mark1d actually running on
        // the dev box cannot turn this into the refusal case instead.
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", dir.path());
        std::env::set_var("HOME", dir.path());
        let started = std::time::Instant::now();
        let ev = cortex_injection_event([0u8; 32], 1, 0, 0, pb::InjectionChannel::Unspecified);
        // Unavailable, NOT HandshakeRefused: nobody is listening, which is the
        // fact `fabric_dropped` is for.
        assert!(matches!(
            push([7u8; 16], &ev).await,
            Err(PushError::Unavailable(_))
        ));
        // Both endpoints refused/absent within the connect deadline each.
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}
