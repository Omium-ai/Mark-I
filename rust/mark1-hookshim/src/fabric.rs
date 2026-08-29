//! M1PL client half (04 §5 `fabric.rs`): connect the local fabric, write one
//! frame, done. Deadlines per 08 §4.4 — write ≤250 ms at the socket; the
//! connect bound is enforced by the caller's 45 ms observer budget (main.rs),
//! which is strictly tighter than the 100 ms fabric connect deadline, so no
//! separate non-blocking connect machinery is warranted on this path.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

/// 08 §4.4: event write deadline, bounded by the writer.
const WRITE_DEADLINE: Duration = Duration::from_millis(250);

/// Endpoint per 07 §5 (R-2 side): `$XDG_RUNTIME_DIR/omium-mark1/m1p.sock`,
/// fallback `~/.omium/mark1/m1p.sock`.
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

#[cfg(unix)]
pub fn send(frame: &[u8]) -> Result<(), std::io::Error> {
    use std::os::unix::net::UnixStream;
    let mut last = std::io::Error::from(std::io::ErrorKind::NotFound);
    for path in endpoints() {
        match UnixStream::connect(&path) {
            Ok(mut stream) => {
                stream.set_write_timeout(Some(WRITE_DEADLINE))?;
                stream.write_all(frame)?;
                // No per-event ack on the fabric (08 §4.3): a completed
                // write is a completed send; durability is the spool's job.
                return Ok(());
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Windows named-pipe fabric (07 §5) is a Phase-2 platform lane (04 §11.1);
/// until it lands every event takes the spill path, which is portable —
/// unreachable-daemon is already a fully-specified, receipted state.
#[cfg(not(unix))]
pub fn send(_frame: &[u8]) -> Result<(), std::io::Error> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}
