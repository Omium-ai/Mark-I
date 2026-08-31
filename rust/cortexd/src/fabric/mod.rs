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
//! That handshake is REFUSED today, deliberately. D-AT requires a 16-byte
//! non-zero `session_id` from every writer; cortexd is a per-WORKSPACE daemon
//! with no session identity anywhere, and giving it one means the MCP surface
//! must carry a session per call — an 08 §6 protocol change sequenced for
//! Phase 2 (D-AV). So cortexd cannot deliver until then. What changes here is
//! that the loss is a number (`Shared::fabric_handshake_refused`) instead of
//! a silent success. It is kept apart from `fabric_dropped` on purpose:
//! "no daemon is listening" and "the daemon refused our identity" are
//! different facts, and one counter would say neither.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use m1p_wire::pb;

use crate::session::Shared;

/// 08 §4.4 deadlines, verbatim.
const CONNECT_DEADLINE: Duration = Duration::from_millis(100);
const WRITE_DEADLINE: Duration = Duration::from_millis(250);

/// Endpoint per the hookshim sibling: `$XDG_RUNTIME_DIR/omium-mark1/m1p.sock`,
/// fallback `~/.omium/mark1/m1p.sock`.
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    pb::Event {
        event_id: uuid::Uuid::now_v7().into_bytes().to_vec(),
        // seq/session_epoch are assigned by mark1d at admission (07 §2).
        // session_id stays empty because cortexd has none to put there — the
        // same gap that gets its Hello refused (D-AV). Not a licence: a
        // synthetic id would attribute every one of these to a session that
        // never existed, which is the lie D-AT exists to end.
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
        body: Some(pb::event::Body::CortexInjection(pb::CortexInjection {
            root_hash: root_hash.to_vec(),
            index_clock,
            token_budget,
            tokens_used,
            channel: channel as i32,
        })),
    }
}

/// Why a push did not land. Two facts, two counters (D-AV): `Unavailable` is
/// nobody listening; `HandshakeRefused` is mark1d answering M1E-4003, which
/// until Phase 2 means D-AT rejecting cortexd's session-less Hello.
#[derive(Debug, thiserror::Error)]
pub enum PushError {
    #[error("fabric unavailable: {0}")]
    Unavailable(#[from] std::io::Error),
    #[error("M1E-4003: mark1d refused the handshake")]
    HandshakeRefused,
}

/// Fire-and-forget push. Errors are counted, never raised: a cortexd push is
/// recomputable by definition (08 §4.4).
pub fn spawn_push(shared: &Arc<Shared>, event: pb::Event) {
    let shared = Arc::clone(shared);
    // Called from both the writer thread and MCP tasks; use the ambient
    // runtime when present, else count the drop (daemon shutting down).
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        shared.fabric_dropped.fetch_add(1, Ordering::Relaxed);
        return;
    };
    handle.spawn(async move {
        if let Err(e) = push(&event).await {
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

#[cfg(unix)]
async fn push(event: &pb::Event) -> Result<(), PushError> {
    let mut frame = Vec::new();
    m1p_wire::encode_frame(event, &mut frame)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let mut last = std::io::Error::from(std::io::ErrorKind::NotFound);
    for path in endpoints() {
        let connect = tokio::net::UnixStream::connect(&path);
        match tokio::time::timeout(CONNECT_DEADLINE, connect).await {
            // A daemon that answered is the daemon; a refusal from it is an
            // answer, not a reason to try the fallback endpoint.
            Ok(Ok(stream)) => {
                // Handshake and event share ONE budget. Re-spending the write
                // deadline per step is how the hookshim sibling overran the
                // deadline it had itself stated.
                return tokio::time::timeout(WRITE_DEADLINE, deliver(stream, &frame))
                    .await
                    .unwrap_or_else(|_| {
                        Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into())
                    });
            }
            Ok(Err(e)) => last = e,
            Err(_) => last = std::io::Error::from(std::io::ErrorKind::TimedOut),
        }
    }
    Err(last.into())
}

/// Hello → HelloAck → event on one connection (08 §4.3 steps 2-4).
#[cfg(unix)]
async fn deliver(mut stream: tokio::net::UnixStream, event_frame: &[u8]) -> Result<(), PushError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut hello = Vec::new();
    m1p_wire::encode_control(
        &pb::FabricFrame {
            kind: Some(pb::fabric_frame::Kind::Hello(pb::Hello {
                component: "cortexd".to_owned(),
                pid: std::process::id(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                // Empty until Phase 2 gives cortexd a session (D-AV). D-AT
                // refuses it, which is the point: a refusal we count beats a
                // fabricated session id that would misattribute every event.
                session_id: Vec::new(),
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

/// Windows has no fabric yet, so every push takes the counted-drop path, which
/// is exactly the specified degraded state (fabric_unavailable, DIAGNOSTIC).
/// The deferral is unsanctioned: 04 §11.1 assigns no phase and 02:613 makes
/// NFR-PORTABILITY-002 Phase-1 green-required (D-CA/D-CD).
#[cfg(not(unix))]
async fn push(_event: &pb::Event) -> Result<(), PushError> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported).into())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(matches!(push(&ev).await, Err(PushError::Unavailable(_))));
        // Both endpoints refused/absent within the connect deadline each.
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}
