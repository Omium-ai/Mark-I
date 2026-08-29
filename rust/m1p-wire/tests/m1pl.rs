//! Conformance + round-trip suite for the M1PL/1 codec.
//!
//! `conf_vectors_` prefixes are load-bearing: `conformance_crosslang.sh`
//! selects Rust tests by that filter and treats a filter matching nothing as
//! a FAILED run (12 §3.4).

// clippy.toml's allow-*-in-tests exempts #[test] fns; the vector-driver
// helpers here are plain fns, so the same exemption is restated at file scope.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use m1p_wire::framing::{FrameDecoder, Outcome, HEADER_LEN, MAGIC, VERSION};
use m1p_wire::pb::event::Body;
use m1p_wire::{encode_frame, pb};
use proptest::prelude::*;
use prost::Message;
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    // Path-relative to the crate so the test runs from any cwd (task C2);
    // the vectors are the frozen cross-language contract (12 §3.4).
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/m1pl")
}

fn load_manifest() -> serde_json::Map<String, Value> {
    let raw = fs::read_to_string(vectors_dir().join("manifest.json")).unwrap();
    serde_json::from_str::<Value>(&raw)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

/// Apply the decoder repeatedly against one vector, matching each manifest
/// outcome in order (README §Decoder model).
fn run_expectations(vector: &str, bytes: &[u8], expected: &[Value]) {
    let mut dec = FrameDecoder::new();
    dec.push(bytes);
    let mut total_consumed = 0usize;
    let last = expected.len() - 1;
    for (i, exp) in expected.iter().enumerate() {
        let want = exp["outcome"].as_str().unwrap();
        match dec.next_frame() {
            Outcome::Accept { payload, consumed } => {
                assert_eq!(want, "accept", "{vector}[{i}]");
                assert_eq!(
                    payload.len() as u64,
                    exp["payload_len"].as_u64().unwrap(),
                    "{vector}[{i}] payload_len"
                );
                assert_eq!(
                    consumed as u64,
                    exp["consumed"].as_u64().unwrap(),
                    "{vector}[{i}] consumed"
                );
                total_consumed += consumed;
            }
            Outcome::Incomplete { needed } => {
                assert_eq!(want, "incomplete", "{vector}[{i}]");
                assert!(
                    needed > 0,
                    "{vector}[{i}]: zero-byte hint can never progress"
                );
                assert_eq!(i, last, "{vector}: incomplete must be the final outcome");
            }
            Outcome::Reject(e) => {
                assert_eq!(want, "reject", "{vector}[{i}]: got reject {e}");
                assert_eq!(
                    e.code(),
                    exp["reject_code"].as_str().unwrap(),
                    "{vector}[{i}] reject code"
                );
                // Reject means close the connection — the manifest never
                // expects an outcome after one.
                assert_eq!(i, last, "{vector}: reject must be the final outcome");
            }
        }
    }
    // All-accept vectors must consume the whole file: leftover bytes would
    // mean the manifest and the decoder disagree on frame extents.
    if expected.iter().all(|e| e["outcome"] == "accept") {
        assert_eq!(total_consumed, bytes.len(), "{vector}: not fully consumed");
    }
}

#[test]
fn conf_vectors_m1pl_rust() {
    let manifest = load_manifest();
    // A run that executes zero vectors is a failed run, not an empty pass
    // (12 §3.4; conformance_crosslang.sh enforces the same at the CI layer).
    assert!(!manifest.is_empty(), "empty m1pl manifest");
    for (file, exp) in &manifest {
        let bytes = fs::read(vectors_dir().join(file))
            .unwrap_or_else(|e| panic!("{file}: vector missing: {e}"));
        let seq: Vec<Value> = match exp.get("sequence") {
            Some(s) => s.as_array().unwrap().clone(),
            None => vec![exp.clone()],
        };
        run_expectations(file, &bytes, &seq);
    }
}

/// README §Split iteration — the "header split across two socket reads" bug
/// class that single-shot vectors cannot see. Required of both languages.
#[test]
fn conf_vectors_m1pl_split_iteration() {
    let min = fs::read(vectors_dir().join("accept_min.bin")).unwrap();
    assert_eq!(min.len(), 10);
    for k in 1..=9 {
        let mut dec = FrameDecoder::new();
        dec.push(&min[..k]);
        assert!(
            matches!(dec.next_frame(), Outcome::Incomplete { .. }),
            "accept_min split at {k}: prefix must be incomplete"
        );
        dec.push(&min[k..]);
        match dec.next_frame() {
            Outcome::Accept { payload, consumed } => {
                assert_eq!(
                    (payload.len(), consumed),
                    (1, 10),
                    "accept_min split at {k}"
                );
            }
            other => panic!("accept_min split at {k}: {other:?}"),
        }
    }

    let two = fs::read(vectors_dir().join("accept_two_frames.bin")).unwrap();
    assert_eq!(two.len(), 22);
    for k in 1..=21 {
        let mut dec = FrameDecoder::new();
        let mut accepts = Vec::new();
        for chunk in [&two[..k], &two[k..]] {
            dec.push(chunk);
            loop {
                match dec.next_frame() {
                    Outcome::Accept { payload, consumed } => {
                        accepts.push((payload.len(), consumed));
                    }
                    Outcome::Incomplete { .. } => break,
                    Outcome::Reject(e) => panic!("two_frames split at {k}: reject {e}"),
                }
            }
        }
        // Cumulative sequence must be identical at every split point — no
        // split may produce a reject or a third outcome.
        assert_eq!(accepts, vec![(1, 10), (3, 12)], "two_frames split at {k}");
    }
}

/// Every `m1p.v1` event family survives encode → frame → decode with
/// byte-identical payloads (13 §11 row C2's "round-trips every event family").
#[test]
fn frame_roundtrip_every_event_family() {
    let bodies = vec![
        Body::SessionStart(Default::default()),
        Body::SessionEnd(Default::default()),
        Body::TaskOpen(Default::default()),
        Body::TaskClose(Default::default()),
        Body::Turn(Default::default()),
        Body::ToolUse(Default::default()),
        Body::ModelRequest(Default::default()),
        Body::ModelResponse(Default::default()),
        Body::Usage(Default::default()),
        Body::CoverageTransition(Default::default()),
        Body::GuardDecision(Default::default()),
        Body::ReceiptCheckpoint(Default::default()),
        Body::EdgeHealth(Default::default()),
        Body::AnchorVote(Default::default()),
        Body::JudgeVote(Default::default()),
        Body::RmScore(Default::default()),
        Body::ConsistencyVote(Default::default()),
        Body::VerdictEvent(Default::default()),
        Body::CortexInjection(Default::default()),
        Body::MemoryInjection(Default::default()),
        Body::ArtifactOutcome(Default::default()),
        Body::RouteDecision(Default::default()),
        Body::EvidenceExcerpt(Default::default()),
    ];
    for body in bodies {
        let ev = pb::Event {
            event_id: vec![7u8; 16],
            seq: 1,
            session_id: vec![9u8; 16],
            body: Some(body),
            ..Default::default()
        };
        let direct = ev.encode_to_vec();
        let mut framed = Vec::new();
        encode_frame(&ev, &mut framed).unwrap();
        assert_eq!(framed.len(), HEADER_LEN + direct.len());

        let mut dec = FrameDecoder::new();
        dec.push(&framed);
        match dec.next_frame() {
            Outcome::Accept { payload, consumed } => {
                assert_eq!(payload, direct, "payload bytes drifted through framing");
                assert_eq!(consumed, framed.len());
                let back = pb::Event::decode(payload.as_slice()).unwrap();
                assert_eq!(back, ev);
                assert_eq!(back.encode_to_vec(), direct, "re-encode not byte-identical");
            }
            other => panic!("round-trip did not accept: {other:?}"),
        }
    }
}

/// 12 §3.4 row 6 at the feed() surface (04 §7.4): frames accepted before a
/// later reject in the same buffer must reach the caller — the fabric has no
/// per-event ack (08 §4.3), so an Err that discards them is silent loss no
/// Dropped{} accounting can see. The vectors cannot pin this: they drive
/// next_frame, which hands each payload over before the reject.
#[test]
fn feed_accepted_events_survive_later_reject() {
    let ev = pb::Event {
        event_id: vec![7u8; 16],
        seq: 1,
        session_id: vec![9u8; 16],
        body: Some(Body::Usage(Default::default())),
        ..Default::default()
    };
    let mut bytes = Vec::new();
    encode_frame(&ev, &mut bytes).unwrap();
    // Same tail shape as accept_then_reject.bin: a full garbage header.
    bytes.extend_from_slice(b"XXXXXXXXX");

    let mut dec = FrameDecoder::new();
    let events = dec
        .feed(&bytes)
        .expect("accepted frame discarded by a later reject (12 §3.4 row 6)");
    assert_eq!(events, vec![ev]);
    // The deferred reject surfaces on the next call, and stays sticky: the
    // buffer is never resynchronized past the garbage (12 §3.4 row 1).
    assert_eq!(dec.feed(&[]).unwrap_err().code(), "M1E-4002");
    assert_eq!(dec.feed(&[]).unwrap_err().code(), "M1E-4002");

    // With nothing accepted first, the same tail errors immediately.
    let mut fresh = FrameDecoder::new();
    assert_eq!(fresh.feed(b"XXXXXXXXX").unwrap_err().code(), "M1E-4002");
}

/// The payload-error sibling of the case above: the bad frame is well-framed
/// (so next_frame consumed it) but its payload is not a decodable Event —
/// the one feed()-level error the sticky buffer alone cannot re-surface.
#[test]
fn feed_accepted_events_survive_later_payload_error() {
    let ev = pb::Event {
        event_id: vec![7u8; 16],
        seq: 1,
        session_id: vec![9u8; 16],
        body: Some(Body::VerdictEvent(Default::default())),
        ..Default::default()
    };
    let mut bytes = Vec::new();
    encode_frame(&ev, &mut bytes).unwrap();
    // 0xff = field 31, wire type 7: invalid in any m1p.v1.Event.
    bytes.extend_from_slice(&MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.push(0xff);

    let mut dec = FrameDecoder::new();
    let events = dec
        .feed(&bytes)
        .expect("accepted frame discarded by a later payload error (12 §3.4 row 6)");
    assert_eq!(events, vec![ev]);
    assert_eq!(dec.feed(&[]).unwrap_err().code(), "M1E-4002");
}

/// A default Event encodes to zero bytes, and len == 0 is a protocol error on
/// the wire (08 §4.2) — the encoder must refuse it rather than emit a frame
/// every conformant decoder will reject.
#[test]
fn encode_refuses_zero_length_event() {
    let mut out = Vec::new();
    let err = encode_frame(&pb::Event::default(), &mut out).unwrap_err();
    assert_eq!(err.code(), "M1E-4002");
    assert!(
        out.is_empty(),
        "refused encode must not leave partial header bytes"
    );
}

proptest! {
    /// Arbitrary payload bytes, arbitrary single split point: the decoder
    /// accepts exactly the framed payload with the same consumed count as the
    /// unsplit feed. Generalizes the golden split iteration beyond the two
    /// frozen vectors' tiny fixed payloads.
    #[test]
    fn prop_accept_any_payload_any_split(
        payload in proptest::collection::vec(any::<u8>(), 1..2048),
        split in any::<proptest::sample::Index>(),
    ) {
        let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
        frame.extend_from_slice(&MAGIC);
        frame.push(VERSION);
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);

        let k = split.index(frame.len() - 1) + 1; // 1..=len-1: a real split
        let mut dec = FrameDecoder::new();
        dec.push(&frame[..k]);
        // Bound to a bool first: prop_assert! embeds the stringified condition
        // in a format! call, where `{ .. }` is an invalid format spec.
        let prefix_incomplete = matches!(dec.next_frame(), Outcome::Incomplete { .. });
        prop_assert!(prefix_incomplete, "split at {}: prefix must be incomplete", k);
        dec.push(&frame[k..]);
        match dec.next_frame() {
            Outcome::Accept { payload: got, consumed } => {
                prop_assert_eq!(got, payload);
                prop_assert_eq!(consumed, frame.len());
            }
            other => return Err(TestCaseError::fail(format!("{other:?}"))),
        }
    }
}
