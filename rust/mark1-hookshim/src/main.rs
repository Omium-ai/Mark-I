//! mark1-hookshim — one static binary, per-agent maps as data (04 §5).
//!
//! Exec'd by the agent per hook event; must be boring: read stdin, map, hand
//! off, exit 0. Every exit is code 0 with no output — the agent's behavior is
//! byte-identical whether Mark 1 is present, broken, or off (invariant 2 +
//! 08 §5 rule 5: capture is fail-open for availability).
//!
//! Synchronous std only: an async runtime is startup cost with zero
//! concurrency to spend it on (04 §5, cold-start budget ≤10 ms).
//!
//! NOT here, and why: the gate path (`gate.rs`, GateQuery/GateVerdict) and
//! the `Hello` handshake — 08 §4.2 places those control messages in `m1p.v1`
//! (doc 07), but the committed proto gen carries no such messages and proto/
//! is frozen; the observer path is complete without them, and Stop is mapped
//! as an observer event, which is byte-identical to a gate that answers
//! allow (fail-open, 08 §5 rule 5). The gate path lands with the proto rev
//! that defines the control set.

use std::io::Read;
use std::time::{Duration, Instant};

mod emit;
mod fabric;
mod maps;
mod spill;

/// The observer wall budget (04 §5 step 4): at 45 ms the shim abandons the
/// fabric attempt and spills — the timer, not hope, is what bounds the total
/// at ≤50 ms.
const FABRIC_ABANDON_MS: u64 = 45;

/// Stdin bound: no hook body legitimately approaches the 4 MiB frame bound
/// (07 §5); reading past it can only be a hostile or broken agent.
const MAX_STDIN: u64 = 4 * 1024 * 1024;

fn main() {
    let started = Instant::now();
    // Off-check BEFORE everything — before stdin, maps, or any fabric I/O
    // (invariant 2, 08 §7.6): no output, no I/O beyond the marker stat.
    if off() {
        return;
    }
    // Every failure path is a deliberate no-op exit 0: an error the agent
    // can observe would violate the byte-identical contract (04 §5).
    run(started);
}

fn off() -> bool {
    if std::env::var("MARK1_DISABLE").is_ok_and(|v| v == "1") {
        return true;
    }
    match home() {
        // 08 §7.6: the off-marker file every gate/capture path checks first.
        Some(h) => h.join(".omium/mark1/OFF").exists(),
        None => false,
    }
}

/// `~` — $HOME (unix) / %USERPROFILE% (windows). No home ⇒ no marker, no
/// spill, no maps cache; the builtin map and the fabric still work.
fn home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
}

fn run(started: Instant) {
    let mut raw = Vec::new();
    // take() caps the read; a body at exactly the cap is indistinguishable
    // from a truncated one, so it is dropped rather than half-parsed.
    if std::io::stdin()
        .take(MAX_STDIN)
        .read_to_end(&mut raw)
        .is_err()
        || raw.len() as u64 >= MAX_STDIN
    {
        return;
    }
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return;
    };
    let map = maps::load(home().as_deref());
    // Unmapped hook name ⇒ emit nothing speculative (04 §5 step 2; adapters
    // never guess a field — 08 §5 rule 2).
    let Some(event) = emit::build(&map, &payload) else {
        return;
    };
    let mut frame = Vec::new();
    if m1p_wire::encode_frame(&event, &mut frame).is_err() {
        return;
    }

    // Fire-and-forget with the budget timer as the bound (04 §5 step 4):
    // the fabric attempt runs on a worker so a blocked connect/write can
    // never hold the agent; at the deadline the main thread spills and
    // exits, which tears the worker down with the process. A worker that
    // completes after the spill duplicates the event — event_id is the
    // server dedupe key (07 §2), so the duplicate collapses at admission.
    let worker_frame = frame.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(fabric::send(&worker_frame));
    });
    let budget = Duration::from_millis(FABRIC_ABANDON_MS).saturating_sub(started.elapsed());
    match rx.recv_timeout(budget) {
        Ok(Ok(())) => {}
        // Unreachable daemon or blown deadline: the event is not lost —
        // sanitized, sealed spill (04 §5.4), drained on next connect.
        _ => spill::append(home().as_deref(), frame),
    }
}
