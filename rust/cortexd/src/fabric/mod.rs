//! M1PL client → mark1d (04 §6 `fabric.rs`): CortexInjection events + L0 root
//! pushes. Deadlines per 08 §4.4 — 100 ms connect, 250 ms write. cortexd's
//! pushes are DROPPABLE by contract (08 §4.4): recomputable, counted as
//! `Dropped{fabric_unavailable, DIAGNOSTIC}`, never blocking an index pass or
//! an MCP answer.
//!
//! No Hello handshake is sent: m1p-wire's frozen framing surface (04 §7.4)
//! encodes/decodes `pb::Event` only — the same shape the hookshim sibling
//! ships (`mark1-hookshim/src/fabric.rs`). The 08 §4.3 Hello-first rule is a
//! flagged contradiction for the lead pass, not something to improvise around.

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
        // seq/session_epoch are assigned by mark1d at admission (07 §2);
        // session_id is empty for the session-less cortexd writer (07 Hello doc).
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

/// Fire-and-forget push. Errors are counted (`fabric_dropped`), never raised:
/// a cortexd push is recomputable by definition (08 §4.4).
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
            let n = shared.fabric_dropped.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::debug!(error = %e, dropped_total = n,
                "fabric push dropped (fabric_unavailable, DIAGNOSTIC)");
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
async fn push(event: &pb::Event) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut frame = Vec::new();
    m1p_wire::encode_frame(event, &mut frame)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let mut last = std::io::Error::from(std::io::ErrorKind::NotFound);
    for path in endpoints() {
        let connect = tokio::net::UnixStream::connect(&path);
        match tokio::time::timeout(CONNECT_DEADLINE, connect).await {
            Ok(Ok(mut stream)) => {
                // No per-event ack on the fabric (08 §4.3): a completed write
                // is a completed send; durability is the spool's job.
                return tokio::time::timeout(WRITE_DEADLINE, stream.write_all(&frame))
                    .await
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?;
            }
            Ok(Err(e)) => last = e,
            Err(_) => last = std::io::Error::from(std::io::ErrorKind::TimedOut),
        }
    }
    Err(last)
}

/// Windows named-pipe fabric is a Phase-2 platform lane (04 §11.1); until it
/// lands every push takes the counted-drop path, which is exactly the
/// specified degraded state (fabric_unavailable, DIAGNOSTIC).
#[cfg(not(unix))]
async fn push(_event: &pb::Event) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_shape_is_wire_legal() {
        let ev = cortex_injection_event([9u8; 32], 42, 2000, 1234, pb::InjectionChannel::McpPull);
        assert_eq!(ev.event_id.len(), 16);
        assert!(ev.tenant_id.is_empty(), "server-stamped band must be unset");
        assert!(ev.session_id.is_empty(), "cortexd is a session-less writer");
        let mut frame = Vec::new();
        m1p_wire::encode_frame(&ev, &mut frame).unwrap();
        assert_eq!(&frame[..4], b"M1PL");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn absent_daemon_is_a_counted_drop_not_a_hang() {
        let started = std::time::Instant::now();
        let ev = cortex_injection_event([0u8; 32], 1, 0, 0, pb::InjectionChannel::Unspecified);
        assert!(push(&ev).await.is_err());
        // Both endpoints refused/absent within the connect deadline each.
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}
