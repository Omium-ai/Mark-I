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
//! Two dispatch paths, chosen by map data: observer hooks take the 50 ms
//! fire-and-forget path here, gate hooks take `gate.rs` on the main thread
//! (it owns the agent-facing deadline and answers on stdout).

use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

mod context;
mod emit;
mod fabric;
mod gate;
mod maps;
mod spill;
mod statusline;

/// The observer wall budget (04 §5 step 4): at 45 ms the shim abandons the
/// fabric attempt and spills — the timer, not hope, is what bounds the total
/// at ≤50 ms.
const FABRIC_ABANDON_MS: u64 = 45;

/// The SessionEnd drain barrier's wall budget (08 §4.2 `Flush` row, 07 §6):
/// the one place this fire-and-forget fabric is allowed to block, bounded
/// like the gate — the agent hook's own budget minus 08 §4.4's 10 ms margin.
/// The budget is the vendor's 1.5 s SessionEnd default (08 §5.1), not the
/// fragment's 30 s kill deadline: a wedged daemon costs the developer one
/// exit stall of at most this, never thirty seconds (see `maps::GateRule`).
const FLUSH_DEADLINE_MS: u64 = 1_500 - 10;

/// Stdin bound: no hook body legitimately approaches the 4 MiB frame bound
/// (07 §5); reading past it can only be a hostile or broken agent.
const MAX_STDIN: u64 = 4 * 1024 * 1024;

fn main() {
    let started = Instant::now();
    // `statusline` chains the user's own command even when Mark 1 is off, so their display never depends on us; only the recording is gated.
    if std::env::args().nth(1).as_deref() == Some("statusline") {
        let record = mark1_harden::apply().is_ok() && !off();
        statusline::run(home().as_deref(), record);
        return;
    }
    // Off-check BEFORE everything — before stdin, maps, or any fabric I/O
    // (invariant 2, 08 §7.6): no output, no I/O beyond the marker stat.
    if off() {
        return;
    }
    // Before stdin: the hook body is the only thing in this process worth a
    // core (04 §11.6, NFR-SECURITY-002). Two syscalls, no I/O, inside the
    // cold-start budget; `harden_order::shim_harden_precedes_stdin` pins it.
    // Cannot harden ⇒ capture nothing, the same fail-closed shape as off():
    // exit 0, no output.
    if mark1_harden::apply().is_err() {
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
    // 08 §7.6: the off-marker file every gate/capture path checks first. The
    // check FAILS CLOSED, mirroring mark1d's off.Off exactly: when we cannot
    // prove the user has not turned capture off — no resolvable home, or a
    // stat error other than not-exist (EACCES, stale mount, ENOTDIR) — the
    // answer is OFF. `exists()` would read every stat error as "on", and a
    // HOME-less or permission-broken environment would keep capturing while
    // the daemon (correctly parked) believes Mark 1 is off. symlink_metadata,
    // not metadata: like Lstat, the marker path itself is the fact — a
    // symlink planted there must not be followed anywhere.
    let Some(h) = home() else {
        return true;
    };
    match std::fs::symlink_metadata(h.join(".omium/mark1/OFF")) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// `~` — $HOME (unix) / %USERPROFILE% (windows). No home ⇒ the off-marker is
/// unresolvable, and `off()` fails closed on that (08 §7.6): a shim that
/// cannot find the kill switch must not capture.
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

    // A gate hook is a gate hook because the map says so (08 §5 rule 1), and
    // it carries the observer event on the same connection — Stop is both the
    // stop-gate and a Turn{AGENT} lifecycle event.
    if let Some((rule, gate)) = map
        .rule(&payload)
        .and_then(|r| r.gate.as_ref().map(|g| (r, g)))
    {
        gate::run(
            home().as_deref(),
            rule,
            gate,
            &payload,
            frame,
            &event.session_id,
        );
        return;
    }
    // 08 §5.1's additionalContext rows pull their injection on the observer event's connection (D-AE).
    if let Some(q) = map.rule(&payload).and_then(|r| context::plan(r, &payload)) {
        let name = payload
            .get(&map.event_field)
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        context::run(home().as_deref(), &q, frame, &event.session_id, name);
        return;
    }
    // SessionEnd forces the drain (NFR-DURABILITY-004): the Flush rides the
    // same connection AFTER the event, so the daemon's drain covers it.
    if matches!(event.body, Some(m1p_wire::pb::event::Body::SessionEnd(_))) {
        flush(home().as_deref(), frame, &event.session_id);
        return;
    }
    // What is LEFT of the 45 ms, not 45 ms from here: the abandon timer bounds
    // the whole invocation, startup included (04 §5 step 4).
    let budget = Duration::from_millis(FABRIC_ABANDON_MS).saturating_sub(started.elapsed());
    observe(home().as_deref(), frame, &event.session_id, budget);
}

/// The 50 ms fire-and-forget observer path (04 §5 step 4).
fn observe(home: Option<&Path>, frame: Vec<u8>, session_id: &[u8], budget: Duration) {
    // The budget timer is the bound: the fabric attempt runs on a worker so a
    // blocked connect/handshake can never hold the agent; at the deadline the
    // main thread spills and exits, which tears the worker down with the
    // process. A worker that completes after the spill duplicates the event —
    // event_id is the server dedupe key (07 §2), so it collapses at
    // admission.
    let worker_frame = frame.clone();
    let worker_session = session_id.to_vec();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(fabric::send(&worker_frame, &worker_session, budget));
    });
    let waited = Instant::now();
    match rx.recv_timeout(budget) {
        Ok(Ok(())) => {}
        // Unreachable daemon, refused handshake, or a blown deadline: the
        // event is not lost — sanitized, sealed spill (04 §5.4), drained on
        // next connect. Before the handshake existed this arm was
        // unreachable: write_all succeeded against a socket mark1d was
        // closing, so every event was lost with Ok(()) and no spill.
        _ => {
            let elapsed = waited.elapsed(); // before the spill: sealing is real work, not the budget
            spill::append(home, frame);
            spill::record_timing(home, "hookshim.observe_budget_ms", budget);
            spill::record_timing(home, "hookshim.observe_elapsed_ms", elapsed);
        }
    }
}

/// The mandatory drain barrier (08 §4.2): Hello, the SessionEnd event, Flush,
/// then wait for FlushAck — bounded, and fail-open past the bound exactly like
/// a gate: the daemon never acked, so it never accounted this event either;
/// spill it and count the missed ack.
fn flush(home: Option<&Path>, frame: Vec<u8>, session_id: &[u8]) {
    let budget = Duration::from_millis(FLUSH_DEADLINE_MS);
    let waited = Instant::now();
    if fabric::flush(&frame, session_id, budget).is_err() {
        let elapsed = waited.elapsed();
        spill::append(home, frame);
        spill::count_flush_timeout(home);
        spill::record_timing(home, "hookshim.flush_elapsed_ms", elapsed);
    }
}

/// NFR-SECURITY-002's ordering clause for the shim, which has no runtime: the harden call
/// precedes the stdin read that brings the hook body into memory. Comment lines are dropped
/// first so prose mentioning either cannot satisfy it.
#[cfg(test)]
mod harden_order {
    #[test]
    fn shim_harden_precedes_stdin() {
        let src: String = include_str!("main.rs")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        // Only the text above this module: its own string literals are not evidence.
        let src = &src[..src.find("mod harden_order").unwrap()];
        let harden = src
            .find("mark1_harden::apply()")
            .expect("main calls mark1_harden::apply()");
        let stdin = src.find("std::io::stdin()").expect("run reads stdin");
        assert!(harden < stdin, "harden at {harden}, stdin at {stdin}");
    }
}
