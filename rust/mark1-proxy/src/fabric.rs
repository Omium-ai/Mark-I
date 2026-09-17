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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
        self.event(pb::event::Body::GuardDecision(decision));
    }

    /// 04 §4's transport-level pair for one observed request, built only from the tee's allow-list.
    pub fn tee_report(&self, r: &crate::tee::TeeReport) {
        let requested = r.request.requested_model.clone().unwrap_or_default();
        self.event(pb::event::Body::ModelRequest(pb::ModelRequest {
            request_id: r.response.request_id.clone(),
            served_model: r
                .request
                .served_model
                .clone()
                .unwrap_or_else(|| requested.clone()),
            model: requested,
            stream: r.response.stream,
            request_bytes: r.response.request_bytes,
        }));
        let stop_reason = r
            .observations
            .iter()
            .find_map(|o| match o {
                mark1_frames::WireObservation::ResponseEnd { stop_reason } => {
                    Some(stop_reason.clone())
                }
                _ => None,
            })
            .unwrap_or_default();
        self.event(pb::event::Body::ModelResponse(pb::ModelResponse {
            request_id: r.response.request_id.clone(),
            status_code: u32::from(r.response.status),
            ttfb_ms: r.response.ttfb_micros / 1000,
            duration_ms: r.response.elapsed_micros / 1000,
            response_bytes: r.response.response_bytes,
            stop_reason,
        }));
    }

    /// One `Event` under this proxy's session; seq / session_epoch are stamped by mark1d (R-4).
    pub fn event(&self, body: pb::event::Body) {
        let event = pb::Event {
            event_id: uuid::Uuid::now_v7().as_bytes().to_vec(),
            session_id: self.session_id.to_vec(),
            occurred_at: Some(now()),
            body: Some(body),
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

async fn send(base: &Path, session_id: &[u8; 16], frame: &[u8]) -> std::io::Result<()> {
    deliver(connect(base).await?, session_id, frame).await
}

/// Hello, HelloAck, then the frame, on any stream (08 §4.3 steps 2-4).
async fn deliver<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    session_id: &[u8; 16],
    frame: &[u8],
) -> std::io::Result<()> {
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
async fn connect(base: &Path) -> std::io::Result<tokio::net::UnixStream> {
    use tokio::net::UnixStream;

    let mut last = std::io::Error::from(std::io::ErrorKind::NotFound);
    for path in endpoints(base) {
        match tokio::time::timeout(CONNECT_DEADLINE, UnixStream::connect(&path)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = e,
            Err(_) => last = std::io::Error::from(std::io::ErrorKind::TimedOut),
        }
    }
    Err(last)
}

/// 07 §5's named pipe. ERROR_PIPE_BUSY is the daemon between accepts (go-winio
/// listens only while an Accept is pending), retried inside the connect budget.
#[cfg(windows)]
async fn connect(
    _base: &Path,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
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

async fn accepted<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> std::io::Result<bool> {
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

/// 07 §5: `$XDG_RUNTIME_DIR/omium-mark1/m1p.sock`, fallback `<base>/m1p.sock`.
#[cfg(unix)]
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

    /// 07 §5's Windows endpoint, end to end: the frame lands on a byte-mode pipe after the
    /// handshake, decoded server-side with the production decoder.
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
        let sid = [5u8; 16];
        let mut frame = Vec::new();
        m1p_wire::encode_frame(
            &pb::Event {
                session_id: sid.to_vec(),
                ..Default::default()
            },
            &mut frame,
        )
        .unwrap();
        deliver(open_pipe(&name).await.unwrap(), &sid, &frame)
            .await
            .unwrap();
        let got = srv.await.unwrap();
        assert!(
            matches!(&got[0].kind, Some(pb::fabric_frame::Kind::Hello(h)) if h.component == "mark1-proxy" && h.session_id == sid)
        );
        assert!(matches!(
            &got[1].kind,
            Some(pb::fabric_frame::Kind::Event(_))
        ));
    }

    /// The one instance is held: ERROR_PIPE_BUSY is retried inside the connect budget, and
    /// nobody listening is NotFound, not a hang.
    #[cfg(windows)]
    #[tokio::test]
    async fn busy_pipe_is_retried_and_absent_pipe_is_not_found() {
        use tokio::net::windows::named_pipe::ServerOptions;

        let name = format!(r"\\.\pipe\omium-mark1-test-{}", uuid::Uuid::now_v7());
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .max_instances(1)
            .create(&name)
            .unwrap();
        let first = open_pipe(&name).await.unwrap();
        server.connect().await.unwrap();
        let name2 = name.clone();
        let second = tokio::spawn(async move {
            let started = tokio::time::Instant::now();
            (open_pipe(&name2).await.map(|_| ()), started.elapsed())
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        drop(first);
        server.disconnect().unwrap();
        let relisten = tokio::spawn(async move { server.connect().await });
        let (r, waited) = tokio::time::timeout(Duration::from_secs(2), second)
            .await
            .expect("second open never returned")
            .unwrap();
        r.unwrap();
        assert!(
            waited >= Duration::from_millis(25),
            "did not wait: {waited:?}"
        );
        relisten.await.unwrap().unwrap();

        let absent = format!(r"\\.\pipe\omium-mark1-test-{}", uuid::Uuid::now_v7());
        assert_eq!(
            open_pipe(&absent).await.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::NotFound)
        );
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
