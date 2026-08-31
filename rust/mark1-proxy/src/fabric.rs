//! M1PL client, emit-only — 04 §5 client half, D-AI.
//!
//! Two frames leave this binary: `Event{GuardDecision}` (§3.1 step 3, sampled per D-AJ) and
//! `ContaminationAlert` (§3.1 step 6, oneof arm 10, never sampled).
//!
//! **Nothing here is on the request path.** [`Fabric::emit`] spawns and returns; the caller
//! never awaits delivery. D-AI is explicit about why for the alert — "a P0 kill that blocks
//! on a daemon round-trip is a P0 kill that a hung daemon can veto" — and the same reasoning
//! makes a guard decision unable to add latency to a forward.
//!
//! The `Hello`/`HelloAck` handshake *is* awaited, inside the detached task. That is not a
//! contradiction of "one-way": mark1d closes any connection whose first frame is not `Hello`
//! (M1E-4003), so a bare write without it is not a delivery, it is a silent loss. The
//! handshake is what makes the failure observable, and the failure's answer is the spill ring,
//! never a wait on the hot path.

use std::path::{Path, PathBuf};
use std::time::Duration;

use m1p_wire::pb;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::tee::spill;

/// 08 §4.4.
const CONNECT_DEADLINE: Duration = Duration::from_millis(100);
const WRITE_DEADLINE: Duration = Duration::from_millis(250);
const ACK_DEADLINE: Duration = Duration::from_millis(250);

#[derive(Clone)]
pub struct Fabric {
    base: PathBuf,
    /// 16-byte session UUIDv7. D-AT requires it non-zero in `Hello`.
    session_id: [u8; 16],
}

impl Fabric {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Fabric {
            base: base.into(),
            session_id: *uuid::Uuid::now_v7().as_bytes(),
        }
    }

    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    /// §3.1 step 3 — the refusal record that D-AJ calls "the evidence for the legal claim".
    pub fn guard_decision(&self, decision: pb::GuardDecision) {
        let event = pb::Event {
            event_id: uuid::Uuid::now_v7().as_bytes().to_vec(),
            session_id: self.session_id.to_vec(),
            occurred_at: Some(now()),
            body: Some(pb::event::Body::GuardDecision(decision)),
            // seq / session_epoch are stamped by mark1d at admission (R-4).
            ..Default::default()
        };
        let mut frame = Vec::new();
        if m1p_wire::encode_frame(&event, &mut frame).is_ok() {
            self.emit(frame);
        }
    }

    /// §3.1 step 6 / D-AI. The proxy has already killed the session by the time this is
    /// called; the frame is notification, not permission.
    pub fn contamination_alert(&self, cred_ref: &str) {
        let alert = pb::FabricFrame {
            kind: Some(pb::fabric_frame::Kind::ContaminationAlert(
                pb::ContaminationAlert {
                    session_id: self.session_id.to_vec(),
                    cred_ref: cred_ref.to_owned(),
                    reason_code: crate::guard::REASON_OAUTH_MARKER.to_owned(),
                },
            )),
        };
        let mut frame = Vec::new();
        if m1p_wire::encode_control(&alert, &mut frame).is_ok() {
            self.emit(frame);
        }
    }

    /// Detached delivery. Returns immediately; failure spills.
    fn emit(&self, frame: Vec<u8>) {
        // No reactor (unit tests, `main` before the runtime starts): spill directly rather
        // than drop. An alert lost because of where it was raised is still lost.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            spill::append(&self.base, frame);
            return;
        };
        let base = self.base.clone();
        let session = self.session_id;
        handle.spawn(async move {
            if send(&base, &session, &frame).await.is_err() {
                // ponytail: the seal + append runs inline on a runtime worker (~100 µs of
                // X25519 and file I/O), not on `spawn_blocking`. It was on `spawn_blocking`,
                // and `benches/latency.rs` caught what that costs: with the daemon down and
                // D-AJ's unsampled refusal arm emitting on every request, tokio grew a
                // blocking thread per emit — 240 threads and 2.5 GB RSS over 300 requests,
                // against a 35 MB budget. Upgrade path if the daemon-down path ever becomes
                // steady state: one dedicated spill thread behind an unbounded channel, still
                // never the request path.
                spill::append(&base, frame);
            }
        });
    }
}

#[cfg(unix)]
async fn send(base: &Path, session_id: &[u8; 16], frame: &[u8]) -> std::io::Result<()> {
    use tokio::net::UnixStream;

    let mut last = std::io::Error::from(std::io::ErrorKind::NotFound);
    let mut stream = None;
    for path in endpoints(base) {
        match tokio::time::timeout(CONNECT_DEADLINE, UnixStream::connect(&path)).await {
            Ok(Ok(s)) => {
                stream = Some(s);
                break;
            }
            Ok(Err(e)) => last = e,
            Err(_) => last = std::io::Error::from(std::io::ErrorKind::TimedOut),
        }
    }
    let Some(mut stream) = stream else {
        return Err(last);
    };

    let mut hello = Vec::new();
    m1p_wire::encode_control(
        &pb::FabricFrame {
            kind: Some(pb::fabric_frame::Kind::Hello(pb::Hello {
                component: "mark1-proxy".to_owned(),
                pid: std::process::id(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                session_id: session_id.to_vec(),
            })),
        },
        &mut hello,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    tokio::time::timeout(WRITE_DEADLINE, stream.write_all(&hello))
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;

    if !accepted(&mut stream).await? {
        return Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
    }
    tokio::time::timeout(WRITE_DEADLINE, stream.write_all(frame))
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
}

#[cfg(unix)]
async fn accepted(stream: &mut tokio::net::UnixStream) -> std::io::Result<bool> {
    let mut dec = m1p_wire::FrameDecoder::new();
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + ACK_DEADLINE;
    loop {
        match dec.next_frame() {
            m1p_wire::Outcome::Accept { payload, .. } => {
                let frame = m1p_wire::decode_payload(&payload).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                })?;
                return Ok(matches!(
                    frame.kind,
                    Some(pb::fabric_frame::Kind::HelloAck(ack)) if ack.accepted
                ));
            }
            m1p_wire::Outcome::Incomplete { .. } => {}
            m1p_wire::Outcome::Reject(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                ))
            }
        }
        let n = tokio::time::timeout_at(deadline, stream.read(&mut buf))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        dec.push(&buf[..n]);
    }
}

/// Windows has no fabric yet, so every frame takes the spill path — portable, and already a
/// fully-specified state. What is NOT true is that this is scheduled: 04 §11.1 specifies the
/// named pipe as a peer of UDS and assigns it no phase, and §11's own preamble says CI runs on
/// all three "from day one". 02 §9.6 scopes NFR-PORTABILITY-002 to **Phase 1** and lists it
/// green-required at 02:613. This deferral is unsanctioned by any document (D-CA, D-CD) and is
/// a founder decision, not a lane.
#[cfg(not(unix))]
async fn send(_base: &Path, _session_id: &[u8; 16], _frame: &[u8]) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// 07 §5: `$XDG_RUNTIME_DIR/omium-mark1/m1p.sock`, fallback `<base>/m1p.sock`.
fn endpoints(base: &Path) -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(2);
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        out.push(PathBuf::from(xdg).join("omium-mark1/m1p.sock"));
    }
    out.push(base.join("m1p.sock"));
    out
}

fn now() -> m1p_wire::google::protobuf::Timestamp {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => m1p_wire::google::protobuf::Timestamp {
            seconds: d.as_secs() as i64,
            nanos: d.subsec_nanos() as i32,
        },
        Err(_) => m1p_wire::google::protobuf::Timestamp {
            seconds: 0,
            nanos: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D-AT: a zero session id is refused by mark1d's handshake, so it must never be what
    /// the proxy introduces itself with.
    #[test]
    fn session_id_is_a_nonzero_uuidv7() {
        let f = Fabric::new("/nonexistent");
        assert_ne!(f.session_id(), &[0u8; 16]);
        assert_eq!(uuid::Uuid::from_bytes(*f.session_id()).get_version_num(), 7);
    }

    /// Emitting with no daemon and no reactor must not panic and must not block. The frame
    /// is lost (no `spill.pub` in a nonexistent home) but the caller returns.
    #[test]
    fn emit_without_a_daemon_is_a_no_op_for_the_caller() {
        let tmp = tempfile::tempdir().unwrap();
        let f = Fabric::new(tmp.path());
        f.contamination_alert("cred-ref-1");
        f.guard_decision(pb::GuardDecision {
            outcome: pb::GuardOutcome::Refused as i32,
            cred_fingerprint: vec![0; 32],
            sample_rate: 1.0,
            reason_code: crate::guard::REASON_UNPROVISIONED.to_owned(),
        });
    }
}
