//! fuzz_m1pl_frame (12 §4): arbitrary bytes into the incremental decoder.
//! Seed corpus is `conformance/vectors/m1pl/` (13 §11 row C2) — `just fuzz`
//! passes it read-only so growth never dirties the frozen vectors.
//!
//! Properties beyond not-crashing, per 12 §4's fuzz row:
//! - a successful decode re-encodes to identical bytes;
//! - byte-at-a-time feeding agrees with single-shot feeding on every accept
//!   and on the terminal outcome (the split bug class, README §Split
//!   iteration, under arbitrary input);
//! - since D-U every payload is a `FabricFrame`, so the typed layer is driven
//!   too: arbitrary bytes into `feed_frames` (must never panic), and every
//!   oneof arm — Event AND each control arm — built from the same bytes must
//!   survive encode → decode identically. Fuzzing only the Event arm would
//!   leave the handshake and gate dialects, which are the arms an attacker
//!   reaches first on a fresh connection, untested.
#![no_main]

use libfuzzer_sys::fuzz_target;
use m1p_wire::framing::{FrameDecoder, Outcome, HEADER_LEN, MAGIC, VERSION};
use m1p_wire::pb;

// Terminal outcome + accepted frames, for cross-chunking comparison.
fn drain(dec: &mut FrameDecoder, accepts: &mut Vec<(Vec<u8>, usize)>) -> Option<String> {
    loop {
        match dec.next_frame() {
            Outcome::Accept { payload, consumed } => accepts.push((payload, consumed)),
            Outcome::Incomplete { .. } => return None,
            Outcome::Reject(e) => return Some(e.code().to_string()),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut single = FrameDecoder::new();
    single.push(data);
    let mut single_accepts = Vec::new();
    let single_end = drain(&mut single, &mut single_accepts);

    // 12 §4: a successful decode re-encodes to identical bytes.
    let mut off = 0usize;
    for (payload, consumed) in &single_accepts {
        assert_eq!(*consumed, HEADER_LEN + payload.len());
        let mut re = Vec::with_capacity(*consumed);
        re.extend_from_slice(&MAGIC);
        re.push(VERSION);
        re.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        re.extend_from_slice(payload);
        assert_eq!(&data[off..off + consumed], &re[..]);
        off += consumed;
    }

    let mut split = FrameDecoder::new();
    let mut split_accepts = Vec::new();
    let mut split_end = None;
    for b in data {
        split.push(std::slice::from_ref(b));
        split_end = drain(&mut split, &mut split_accepts);
        if split_end.is_some() {
            break;
        }
    }
    assert_eq!(single_accepts, split_accepts);
    assert_eq!(single_end, split_end);

    // The typed layer over the same bytes: never a panic, only a typed frame
    // or a FrameError.
    let _ = FrameDecoder::new().feed_frames(data);

    // Every arm, built from the fuzzer's bytes, must round-trip.
    let text = String::from_utf8_lossy(data).into_owned();
    for kind in [
        pb::fabric_frame::Kind::Event(pb::Event {
            event_id: data.to_vec(),
            body: Some(pb::event::Body::Turn(pb::Turn::default())),
            ..Default::default()
        }),
        pb::fabric_frame::Kind::Hello(pb::Hello {
            component: text.clone(),
            pid: data.len() as u32,
            version: text.clone(),
            session_id: data.to_vec(),
        }),
        pb::fabric_frame::Kind::HelloAck(pb::HelloAck {
            accepted: data.len() % 2 == 0,
            max_frame: m1p_wire::M1PL_MAX_FRAME,
            want_ver: data.first().copied().unwrap_or(0) as u32,
        }),
        pb::fabric_frame::Kind::GateQuery(pb::GateQuery {
            task_id: data.to_vec(),
            gate: (data.len() % 3) as i32,
            deadline_ms: data.len() as u32,
        }),
        pb::fabric_frame::Kind::GateVerdict(pb::GateVerdict {
            decision: (data.len() % 3) as i32,
            verdict: (data.len() % 5) as i32,
            posterior: data.iter().map(|b| f64::from(*b) / 255.0).collect(),
            reason: text.clone(),
            evidence_ref: text,
        }),
        pb::fabric_frame::Kind::Flush(pb::Flush {}),
        pb::fabric_frame::Kind::FlushAck(pb::FlushAck {
            drained: data.len() as u64,
        }),
    ] {
        let frame = pb::FabricFrame { kind: Some(kind) };
        let mut bytes = Vec::new();
        // Only the bound can refuse an arm; past it there is nothing to prove.
        if m1p_wire::encode_control(&frame, &mut bytes).is_err() {
            continue;
        }
        let got = FrameDecoder::new()
            .feed_frames(&bytes)
            .expect("a frame this encoder produced must decode");
        assert_eq!(got, vec![frame]);
    }
});
