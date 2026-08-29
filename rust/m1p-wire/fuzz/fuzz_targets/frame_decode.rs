//! fuzz_m1pl_frame (12 §4): arbitrary bytes into the incremental decoder.
//! Seed corpus is `conformance/vectors/m1pl/` (13 §11 row C2) — `just fuzz`
//! passes it read-only so growth never dirties the frozen vectors.
//!
//! Properties beyond not-crashing, per 12 §4's fuzz row:
//! - a successful decode re-encodes to identical bytes;
//! - byte-at-a-time feeding agrees with single-shot feeding on every accept
//!   and on the terminal outcome (the split bug class, README §Split
//!   iteration, under arbitrary input).
#![no_main]

use libfuzzer_sys::fuzz_target;
use m1p_wire::framing::{FrameDecoder, Outcome, HEADER_LEN, MAGIC, VERSION};

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
});
