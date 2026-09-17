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

#[cfg(unix)] // only endpoints() names it, and that is unix-gated
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

/// The D-AE context pull, the gate's shape on one connection; raw payloads both ways because the committed gen has no arms 8/9 yet (context.rs).
pub fn context_query(
    event_frame: &[u8],
    query_payload: &[u8],
    session_id: &[u8],
    budget: Duration,
) -> Result<Vec<u8>, std::io::Error> {
    let deadline = Instant::now() + budget;
    let mut conn = Conn::open(session_id, deadline)?;
    conn.write_frame(event_frame)?;
    conn.write_payload(query_payload)?;
    conn.read_payload(deadline)
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

/// setsockopt reads a zero timeout as "block forever", so a budget that
/// has rounded below a millisecond is floored rather than passed through.
const MIN_READ_TIMEOUT: Duration = Duration::from_millis(1);

/// One M1PL connection: the transport is per platform (`imp::Stream`), everything above it is not.
struct Conn {
    stream: imp::Stream,
    dec: m1p_wire::FrameDecoder,
}

/// Off the hot path by construction — only a refusal reaches it.
fn refused() {
    crate::spill::count_handshake_refused(crate::home().as_deref());
}

impl Conn {
    fn open(session_id: &[u8], deadline: Instant) -> Result<Self, std::io::Error> {
        let stream = imp::connect(deadline)?;
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

    fn write_frame(&mut self, frame: &[u8]) -> Result<(), std::io::Error> {
        self.stream.write_all(frame)
    }

    /// One M1PL frame (07 §5 header) around a raw FabricFrame payload.
    fn write_payload(&mut self, payload: &[u8]) -> Result<(), std::io::Error> {
        let len = u32::try_from(payload.len())
            .ok()
            .filter(|n| *n > 0 && *n <= m1p_wire::M1PL_MAX_FRAME)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        let mut out = Vec::with_capacity(m1p_wire::framing::HEADER_LEN + payload.len());
        out.extend_from_slice(&m1p_wire::framing::MAGIC);
        out.push(m1p_wire::framing::VERSION);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(payload);
        self.write_frame(&out)
    }

    fn write_control(&mut self, kind: &pb::fabric_frame::Kind) -> Result<(), std::io::Error> {
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

    /// Blocking read bounded by a wall deadline: a per-pass read timeout,
    /// recomputed each pass so a peer dripping one byte at a time cannot
    /// extend the total past the deadline. Never a busy-wait.
    fn read_frame(&mut self, deadline: Instant) -> Result<pb::FabricFrame, std::io::Error> {
        let payload = self.read_payload(deadline)?;
        m1p_wire::decode_payload(&payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    /// One raw M1PL payload under the same wall deadline as `read_frame`.
    fn read_payload(&mut self, deadline: Instant) -> Result<Vec<u8>, std::io::Error> {
        loop {
            match self.dec.next_frame() {
                m1p_wire::Outcome::Accept { payload, .. } => return Ok(payload),
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
            // 0 bytes = the daemon closed on us. On the first read that is
            // the M1E-4003 close (08 §4.3 step 2) arriving as EOF, which
            // must reach the spill path as a failure, never as a success.
            let chunk = self.stream.read_chunk(left.max(MIN_READ_TIMEOUT))?;
            if chunk.is_empty() {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            self.dec.push(&chunk);
        }
    }
}

#[cfg(unix)]
mod imp {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    /// 08 §4.4: event write deadline, bounded by the writer.
    const WRITE_DEADLINE: Duration = Duration::from_millis(250);

    pub struct Stream(UnixStream);

    /// `UnixStream` has no `connect_timeout` (only `TcpStream` does), and a
    /// connect to a listening socket whose backlog is full parks with nothing
    /// to time it out. So the bound comes from outside the syscall: the same
    /// worker-plus-`recv_timeout` shape `main::observe` already uses, and the
    /// abandoned worker dies with this per-exec process.
    pub fn connect(deadline: Instant) -> Result<Stream, std::io::Error> {
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
        let stream = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut)))?;
        stream.set_write_timeout(Some(WRITE_DEADLINE))?;
        Ok(Stream(stream))
    }

    impl Stream {
        pub fn write_all(&mut self, b: &[u8]) -> Result<(), std::io::Error> {
            self.0.write_all(b)
        }

        pub fn read_chunk(&mut self, timeout: Duration) -> Result<Vec<u8>, std::io::Error> {
            let mut buf = [0u8; 4096];
            self.0.set_read_timeout(Some(timeout))?;
            let n = self.0.read(&mut buf)?;
            Ok(buf[..n].to_vec())
        }
    }
}

/// 07 §5's named pipe, opened as a byte-mode file. A pipe handle has no read
/// timeout, so a reader thread owns a duplicate handle and the deadline is
/// `recv_timeout` on its channel — the same shape as the unix connect bound.
/// It reads only when asked: a synchronous pipe serialises I/O on the file
/// object, so a read parked in the kernel would block the next write.
#[cfg(windows)]
mod imp {
    use std::io::{Read, Write};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

    pub struct Stream {
        file: std::fs::File,
        ask: Sender<()>,
        rx: Receiver<Result<Vec<u8>, std::io::Error>>,
    }

    pub fn connect(deadline: Instant) -> Result<Stream, std::io::Error> {
        connect_to(&mark1_harden::fabric_pipe_name()?, deadline)
    }

    /// ERROR_PIPE_BUSY is the daemon between accepts (go-winio only listens
    /// while an Accept is pending); WaitNamedPipeW parks until an instance
    /// is free or the budget is spent, then the open is retried.
    pub fn connect_to(name: &str, deadline: Instant) -> Result<Stream, std::io::Error> {
        let file = loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(name)
            {
                Ok(f) => break f,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
                    }
                    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
                    let ms = u32::try_from(left.as_millis()).unwrap_or(u32::MAX).max(1);
                    // SAFETY: `wide` is NUL-terminated and outlives the call.
                    unsafe { WaitNamedPipeW(wide.as_ptr(), ms) };
                }
                Err(e) => return Err(e),
            }
        };
        let mut reader = file.try_clone()?;
        let (ask, asked) = mpsc::channel::<()>();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            while asked.recv().is_ok() {
                let mut buf = [0u8; 4096];
                let r = reader.read(&mut buf).map(|n| buf[..n].to_vec());
                let done = !matches!(&r, Ok(v) if !v.is_empty());
                if tx.send(r).is_err() || done {
                    return;
                }
            }
        });
        Ok(Stream { file, ask, rx })
    }

    impl Stream {
        // ponytail: no write deadline on the pipe (a File has none); the daemon reads eagerly and the agent's hook timeout is the backstop.
        pub fn write_all(&mut self, b: &[u8]) -> Result<(), std::io::Error> {
            self.file.write_all(b)
        }

        pub fn read_chunk(&mut self, timeout: Duration) -> Result<Vec<u8>, std::io::Error> {
            if self.ask.send(()).is_err() {
                return Ok(Vec::new());
            }
            match self.rx.recv_timeout(timeout) {
                Ok(r) => r,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => Ok(Vec::new()),
            }
        }
    }
}

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use std::io::{Read, Write};
    use std::os::windows::io::FromRawHandle;
    use std::time::{Duration, Instant};

    use m1p_wire::pb;
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    use super::{imp, Conn};

    fn test_name(tag: &str) -> String {
        format!(
            r"\\.\pipe\omium-mark1-test-{}-{}-{tag}",
            std::process::id(),
            uuid::Uuid::now_v7()
        )
    }

    struct Server(HANDLE);
    unsafe impl Send for Server {}

    impl Server {
        fn create(name: &str) -> Self {
            let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let h = unsafe {
                CreateNamedPipeW(
                    wide.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    1,
                    4096,
                    4096,
                    0,
                    std::ptr::null(),
                )
            };
            assert_ne!(
                h,
                INVALID_HANDLE_VALUE,
                "{}",
                std::io::Error::last_os_error()
            );
            Server(h)
        }

        fn accept(&self) {
            unsafe { ConnectNamedPipe(self.0, std::ptr::null_mut()) };
        }

        fn disconnect(&self) {
            unsafe { DisconnectNamedPipe(self.0) };
        }

        fn into_file(self) -> std::fs::File {
            unsafe { std::fs::File::from_raw_handle(self.0 as _) }
        }
    }

    fn read_one(f: &mut std::fs::File, dec: &mut m1p_wire::FrameDecoder) -> pb::FabricFrame {
        let mut buf = [0u8; 4096];
        loop {
            if let m1p_wire::Outcome::Accept { payload, .. } = dec.next_frame() {
                return m1p_wire::decode_payload(&payload).unwrap();
            }
            let n = f.read(&mut buf).unwrap();
            assert_ne!(n, 0, "client hung up early");
            dec.push(&buf[..n]);
        }
    }

    fn hello_ack(accepted: bool) -> Vec<u8> {
        let mut out = Vec::new();
        m1p_wire::encode_control(
            &pb::FabricFrame {
                kind: Some(pb::fabric_frame::Kind::HelloAck(pb::HelloAck {
                    accepted,
                    max_frame: m1p_wire::M1PL_MAX_FRAME,
                    want_ver: 1,
                })),
            },
            &mut out,
        )
        .unwrap();
        out
    }

    fn open(name: &str, budget: Duration) -> Result<Conn, std::io::Error> {
        let deadline = Instant::now() + budget;
        let mut conn = Conn {
            stream: imp::connect_to(name, deadline)?,
            dec: m1p_wire::FrameDecoder::new(),
        };
        conn.hello(&[3u8; 16], deadline)?;
        Ok(conn)
    }

    fn open_err(name: &str, budget: Duration) -> std::io::Error {
        match open(name, budget) {
            Ok(_) => panic!("connected and handshook against {name}"),
            Err(e) => e,
        }
    }

    /// Hello, HelloAck, one Event over a real byte-mode pipe, decoded by the server with the production decoder.
    #[test]
    fn pipe_round_trip() {
        let name = test_name("rt");
        let srv = Server::create(&name);
        let server = std::thread::spawn(move || {
            srv.accept();
            let mut f = srv.into_file();
            let mut dec = m1p_wire::FrameDecoder::new();
            let hello = read_one(&mut f, &mut dec);
            f.write_all(&hello_ack(true)).unwrap();
            let ev = read_one(&mut f, &mut dec);
            (hello, ev)
        });
        let mut conn = open(&name, Duration::from_secs(3)).unwrap();
        let mut frame = Vec::new();
        m1p_wire::encode_frame(
            &pb::Event {
                session_id: vec![3u8; 16],
                ..Default::default()
            },
            &mut frame,
        )
        .unwrap();
        conn.write_frame(&frame).unwrap();
        let (hello, ev) = server.join().unwrap();
        match hello.kind {
            Some(pb::fabric_frame::Kind::Hello(h)) => {
                assert_eq!(h.component, "mark1-hookshim");
                assert_eq!(h.session_id, vec![3u8; 16]);
            }
            other => panic!("first frame was not Hello: {other:?}"),
        }
        assert!(matches!(ev.kind, Some(pb::fabric_frame::Kind::Event(_))));
    }

    /// A daemon that accepts and says nothing: the reader-thread deadline holds, and it is TimedOut, not a hang.
    #[test]
    fn pipe_read_deadline_holds() {
        let name = test_name("mute");
        let srv = Server::create(&name);
        let (hold_tx, hold_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            srv.accept();
            let _ = hold_rx.recv();
            drop(srv.into_file());
        });
        let started = Instant::now();
        let err = open_err(&name, Duration::from_millis(150));
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
        let _ = hold_tx.send(());
        server.join().unwrap();
    }

    /// The M1E-4003 close before any ack arrives as EOF and is a refusal, never Ok.
    #[test]
    fn pipe_close_before_ack_is_refused() {
        let name = test_name("eof");
        let srv = Server::create(&name);
        let server = std::thread::spawn(move || {
            srv.accept();
            let mut f = srv.into_file();
            let mut dec = m1p_wire::FrameDecoder::new();
            let _ = read_one(&mut f, &mut dec);
            drop(f);
        });
        let err = open_err(&name, Duration::from_secs(3));
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        server.join().unwrap();
    }

    /// accepted=false is 08 §4.3 step 3's refusal.
    #[test]
    fn pipe_rejected_hello_is_connection_refused() {
        let name = test_name("nak");
        let srv = Server::create(&name);
        let server = std::thread::spawn(move || {
            srv.accept();
            let mut f = srv.into_file();
            let mut dec = m1p_wire::FrameDecoder::new();
            let _ = read_one(&mut f, &mut dec);
            f.write_all(&hello_ack(false)).unwrap();
            let _ = hold(&mut f);
        });
        let err = open_err(&name, Duration::from_secs(3));
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
        server.join().unwrap();
    }

    fn hold(f: &mut std::fs::File) -> std::io::Result<usize> {
        f.read(&mut [0u8; 1])
    }

    /// The one instance is held by another client: the open sees ERROR_PIPE_BUSY, waits, and lands once it frees.
    #[test]
    fn busy_pipe_is_waited_for_not_refused() {
        let name = test_name("busy");
        let srv = Server::create(&name);
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            srv.accept();
            let _ = release_rx.recv();
            srv.disconnect();
            srv.accept();
            let mut f = srv.into_file();
            let mut dec = m1p_wire::FrameDecoder::new();
            let _ = read_one(&mut f, &mut dec);
            f.write_all(&hello_ack(true)).unwrap();
            let _ = hold(&mut f);
        });
        let first = imp::connect_to(&name, Instant::now() + Duration::from_secs(3)).unwrap();
        let name2 = name.clone();
        let second = std::thread::spawn(move || {
            let started = Instant::now();
            let r = open(&name2, Duration::from_secs(3));
            (r.map(|_| ()), started.elapsed())
        });
        std::thread::sleep(Duration::from_millis(300));
        drop(first);
        let _ = release_tx.send(());
        let (r, waited) = second.join().unwrap();
        r.unwrap();
        assert!(
            waited >= Duration::from_millis(250),
            "did not wait: {waited:?}"
        );
        server.join().unwrap();
    }

    /// Nobody listening is NotFound within the budget, the cue to spill.
    #[test]
    fn absent_pipe_is_not_found() {
        let err = open_err(&test_name("none"), Duration::from_millis(200));
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }
}
