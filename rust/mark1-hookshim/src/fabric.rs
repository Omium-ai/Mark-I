//! M1PL client half (04 §5 `fabric.rs`): connect the local fabric, shake
//! hands, hand over frames. Deadlines per 08 §4.4 — write ≤250 ms at the
//! socket; everything else is bounded by ONE `Instant` computed at the public
//! entry point and threaded through connect, handshake and read. A `Duration`
//! threaded instead spends itself once per wait, so the round trip cost
//! `connect + budget + budget`, and `UnixStream::connect` against a listening
//! socket with a starved backlog has no bound at all — the shim outran its
//! stated gate deadline by 2-3x and the agent's hook timeout killed it.
//!
//! EVERY connection opens with `Hello` and waits for `HelloAck` (08 §4.3
//! steps 2-3). That is not ceremony: mark1d closes any connection whose first
//! frame is not Hello (M1E-4003), and a bare `write_all` succeeds against a
//! socket the daemon is about to close — so before the handshake a completed
//! write was indistinguishable from a delivered event and every hook event
//! was lost with `Ok(())` returned and nothing spilled. The HelloAck is the
//! only delivery evidence this fire-and-forget fabric has (there is no
//! per-event ack, 08 §4.3 step 4), so it is what makes loss observable.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use m1p_wire::pb;

/// Endpoint per 07 §5 (R-2 side): `$XDG_RUNTIME_DIR/omium-mark1/m1p.sock`,
/// fallback `~/.omium/mark1/m1p.sock`. Reached only from the `#[cfg(unix)]`
/// connector, so it carries the same gate -- a dead fn is a `-D warnings`
/// error on the Windows leg.
#[cfg(unix)]
fn endpoints() -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(2);
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        out.push(PathBuf::from(xdg).join("omium-mark1/m1p.sock"));
    }
    if let Some(home) = crate::home() {
        out.push(home.join(".omium/mark1/m1p.sock"));
    }
    out
}

/// Hand one already-framed event to the daemon (04 §5 step 4). Err ⇒ the
/// caller spills; a handshake that never completes is an Err, which is the
/// whole point of the handshake.
pub fn send(frame: &[u8], session_id: &[u8], budget: Duration) -> Result<(), std::io::Error> {
    let mut conn = Conn::open(session_id, Instant::now() + budget)?;
    conn.write_frame(frame)
}

/// The gate round-trip (04 §5 step 5) on ONE connection: Hello, the observer
/// event frame, GateQuery, GateVerdict. One connection because 08 §4.3 step 4
/// makes a handshaken connection an event stream *plus* request-reply, and
/// because a second connect inside the gate's budget buys nothing.
pub fn gate_query(
    event_frame: &[u8],
    query: pb::GateQuery,
    session_id: &[u8],
    budget: Duration,
) -> Result<pb::GateVerdict, std::io::Error> {
    // One instant for the whole round trip. The budget is what the shim told
    // the agent in `GateQuery.deadline_ms`; spending it again per wait is how
    // the shim overran it.
    let deadline = Instant::now() + budget;
    let mut conn = Conn::open(session_id, deadline)?;
    conn.write_frame(event_frame)?;
    conn.write_control(&pb::fabric_frame::Kind::GateQuery(query))?;
    match conn.read_frame(deadline)?.kind {
        Some(pb::fabric_frame::Kind::GateVerdict(v)) => Ok(v),
        // Any other arm is the daemon speaking a dialect this shim does not:
        // treated exactly like a timeout, because the caller's only two
        // answers are the verdict and fail-open allow.
        _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
    }
}

/// The SessionEnd drain barrier (08 §4.2's `Flush` row) on ONE connection:
/// Hello, the SessionEnd event frame, `Flush`, `FlushAck`. The Flush goes
/// AFTER the event on the same connection so the daemon's drain covers it;
/// Ok is the daemon's receipt, Err (timeout, refusal, EOF, a foreign arm) is
/// the caller's cue to spill — the ack is the only delivery evidence there is.
pub fn flush(
    event_frame: &[u8],
    session_id: &[u8],
    budget: Duration,
) -> Result<(), std::io::Error> {
    let deadline = Instant::now() + budget;
    let mut conn = Conn::open(session_id, deadline)?;
    conn.write_frame(event_frame)?;
    conn.write_control(&pb::fabric_frame::Kind::Flush(pb::Flush {}))?;
    match conn.read_frame(deadline)?.kind {
        Some(pb::fabric_frame::Kind::FlushAck(_)) => Ok(()),
        _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
    }
}

#[cfg(unix)]
mod imp {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    use m1p_wire::pb;

    /// 08 §4.4: event write deadline, bounded by the writer.
    const WRITE_DEADLINE: Duration = Duration::from_millis(250);

    /// setsockopt reads a zero timeout as "block forever", so a budget that
    /// has rounded below a millisecond is floored rather than passed through.
    const MIN_READ_TIMEOUT: Duration = Duration::from_millis(1);

    pub struct Conn {
        stream: UnixStream,
        dec: m1p_wire::FrameDecoder,
    }

    /// Off the hot path by construction — only a refusal reaches it.
    fn refused() {
        crate::spill::count_handshake_refused(crate::home().as_deref());
    }

    /// `UnixStream` has no `connect_timeout` (only `TcpStream` does), and a
    /// connect to a listening socket whose backlog is full parks with nothing
    /// to time it out. So the bound comes from outside the syscall: the same
    /// worker-plus-`recv_timeout` shape `main::observe` already uses, and the
    /// abandoned worker dies with this per-exec process.
    fn connect(deadline: Instant) -> Result<UnixStream, std::io::Error> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut last = std::io::Error::from(std::io::ErrorKind::NotFound);
            for path in super::endpoints() {
                match UnixStream::connect(&path) {
                    Ok(stream) => {
                        let _ = tx.send(Ok(stream));
                        return;
                    }
                    Err(e) => last = e,
                }
            }
            let _ = tx.send(Err(last));
        });
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut)))
    }

    impl Conn {
        pub fn open(session_id: &[u8], deadline: Instant) -> Result<Self, std::io::Error> {
            let stream = connect(deadline)?;
            stream.set_write_timeout(Some(WRITE_DEADLINE))?;
            let mut conn = Self {
                stream,
                dec: m1p_wire::FrameDecoder::new(),
            };
            conn.hello(session_id, deadline)?;
            Ok(conn)
        }

        fn hello(&mut self, session_id: &[u8], deadline: Instant) -> Result<(), std::io::Error> {
            self.write_control(&pb::fabric_frame::Kind::Hello(pb::Hello {
                component: "mark1-hookshim".to_owned(),
                pid: std::process::id(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                session_id: session_id.to_vec(),
            }))?;
            let ack = match self.read_frame(deadline) {
                Ok(f) => f,
                // EOF before any ack is the M1E-4003 close of 08 §4.3 step 2.
                // A timeout is not: that is a mute or slow daemon, already
                // counted as a gate timeout.
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        refused();
                    }
                    return Err(e);
                }
            };
            match ack.kind {
                // accepted = false is a version mismatch mid-upgrade (08 §4.3
                // step 3) — refused, not retried, and the event spills.
                Some(pb::fabric_frame::Kind::HelloAck(ack)) if ack.accepted => Ok(()),
                Some(pb::fabric_frame::Kind::HelloAck(_)) => {
                    refused();
                    Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
                }
                _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
            }
        }

        pub fn write_frame(&mut self, frame: &[u8]) -> Result<(), std::io::Error> {
            self.stream.write_all(frame)
        }

        pub fn write_control(
            &mut self,
            kind: &pb::fabric_frame::Kind,
        ) -> Result<(), std::io::Error> {
            let mut out = Vec::new();
            m1p_wire::encode_control(
                &pb::FabricFrame {
                    kind: Some(kind.clone()),
                },
                &mut out,
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            self.write_frame(&out)
        }

        /// Blocking read bounded by a wall deadline: a socket read timeout,
        /// recomputed each pass so a peer dripping one byte at a time cannot
        /// extend the total past the deadline. Never a busy-wait.
        pub fn read_frame(&mut self, deadline: Instant) -> Result<pb::FabricFrame, std::io::Error> {
            let mut buf = [0u8; 4096];
            loop {
                match self.dec.next_frame() {
                    m1p_wire::Outcome::Accept { payload, .. } => {
                        return m1p_wire::decode_payload(&payload).map_err(|e| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                        })
                    }
                    m1p_wire::Outcome::Incomplete { .. } => {}
                    m1p_wire::Outcome::Reject(e) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e.to_string(),
                        ))
                    }
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
                }
                self.stream
                    .set_read_timeout(Some(left.max(MIN_READ_TIMEOUT)))?;
                // 0 bytes = the daemon closed on us. On the first read that is
                // the M1E-4003 close (08 §4.3 step 2) arriving as EOF, which
                // must reach the spill path as a failure, never as a success.
                match self.stream.read(&mut buf) {
                    Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
                    Ok(n) => self.dec.push(&buf[..n]),
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

/// Windows has no fabric yet (07 §5's named pipe), so every event takes the
/// spill path — portable, and unreachable-daemon is already a fully-specified,
/// receipted state. The deferral itself is unsanctioned: 04 §11.1 assigns no
/// phase and 02:613 makes NFR-PORTABILITY-002 Phase-1 green-required. See
/// D-CA/D-CD — founder decision owed, not a scheduled lane.
#[cfg(not(unix))]
mod imp {
    use std::time::Instant;

    use m1p_wire::pb;

    pub struct Conn;

    impl Conn {
        pub fn open(_session_id: &[u8], _deadline: Instant) -> Result<Self, std::io::Error> {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }
        pub fn write_frame(&mut self, _frame: &[u8]) -> Result<(), std::io::Error> {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }
        pub fn write_control(
            &mut self,
            _kind: &pb::fabric_frame::Kind,
        ) -> Result<(), std::io::Error> {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }
        pub fn read_frame(
            &mut self,
            _deadline: Instant,
        ) -> Result<pb::FabricFrame, std::io::Error> {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }
    }
}

use imp::Conn;
