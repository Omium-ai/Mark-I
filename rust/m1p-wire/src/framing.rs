//! M1PL/1 framing. Byte layout is 07 §5, verbatim; the payload is one
//! `m1p.v1.FabricFrame` (D-U, 07 §5) — the oneof arm is the Event-vs-control
//! discriminator, so this module owns the header and the envelope but not the
//! frame's meaning. The len bound is 08 §4.2's
//! `M1PL_MAX_FRAME` (D-A). Decoder outcomes and reject codes are frozen by the
//! `conformance/vectors/m1pl/` manifest (12 §3.4) — accept / incomplete /
//! reject, nothing else, and reject means the caller closes the connection.

use prost::Message;

use crate::pb;

pub const MAGIC: [u8; 4] = *b"M1PL";
pub const VERSION: u8 = 0x01;
pub const HEADER_LEN: usize = 9;
/// 08 §4.2: the symbol, not a re-typed literal — 07 §6 derives the spool
/// record bound from this same constant.
pub const M1PL_MAX_FRAME: u32 = 4_194_304;

/// Reject taxonomy per the vector manifest and 08 §7: only bad-ver is
/// M1E-4003; every other framing violation is the M1E-4002 protocol error.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Full 4-byte compare — `reject_bad_magic.bin` flips only the last byte.
    #[error("M1E-4002: bad magic {0:02x?}")]
    BadMagic([u8; 4]),
    /// Shipped version set is exactly {0x01}; both ends ship together, so a
    /// mismatch is loud and mid-upgrade only (08 §9).
    #[error("M1E-4003: M1PL version {0:#04x} not in the shipped set {{0x01}}")]
    BadVersion(u8),
    /// Both halves of the bound: len == 0 is a desynchronized stream, not an
    /// empty Event; len > max caps hostile allocation at 4 MiB (08 §4.2).
    #[error("M1E-4002: frame len {0} outside 0 < len <= {M1PL_MAX_FRAME}")]
    BadLength(u32),
    /// A well-framed payload that is not a decodable FabricFrame means the
    /// writer is broken or the stream desynchronized on a frame boundary;
    /// 08 §7 pins no dedicated code, so it closes as the M1E-4002 protocol
    /// error.
    #[error("M1E-4002: payload is not a decodable m1p.v1.FabricFrame: {0}")]
    Payload(#[from] prost::DecodeError),
    /// A structurally decodable FabricFrame carrying the wrong thing: no
    /// oneof arm at all (D-U's discriminator missing — proto3 would otherwise
    /// let unknown fields pass as a silently-ignored frame), or a control arm
    /// where the reader is draining an event stream. Both are dialect
    /// breaches, so both close as M1E-4002 — the same answer mark1d's
    /// `unwrap` gives (go/mark1d/internal/fabric/session.go).
    #[error("M1E-4002: FabricFrame {0}")]
    Envelope(&'static str),
    /// Encode side of the same bound: a frame that encodes to len == 0 or
    /// len > max may never reach the wire (07 §5 — excerpts travel as
    /// multipart attachments, never over the fabric). len == 0 is reachable
    /// only from a FabricFrame with no oneof arm set.
    #[error("M1E-4002: frame encodes to {0} bytes, unframeable under 0 < len <= {M1PL_MAX_FRAME}")]
    Unframeable(usize),
    #[error("M1E-4002: encode failed: {0}")]
    Encode(#[from] prost::EncodeError),
}

impl FrameError {
    /// The refusal identity of 12 §3.4 — what Rust and Go must agree on
    /// without agreeing on message formatting.
    pub fn code(&self) -> &'static str {
        match self {
            FrameError::BadVersion(_) => "M1E-4003",
            _ => "M1E-4002",
        }
    }
}

/// The three-outcome decoder model the vector manifest is written against
/// (conformance/vectors/m1pl/README.md): accept consumes exactly
/// `9 + payload_len`, incomplete consumes 0, reject consumes 0 and the caller
/// closes — the decoder never resynchronizes on attacker-chosen bytes
/// (12 §3.4 row 1).
#[derive(Debug)]
pub enum Outcome {
    Accept {
        payload: Vec<u8>,
        consumed: usize,
    },
    /// `needed` is the minimum additional byte count before the next outcome
    /// can change — a read-sizing hint, never a promise of acceptance.
    Incomplete {
        needed: usize,
    },
    Reject(FrameError),
}

/// Incremental push-bytes decoder (04 §7.4). The internal buffer holds only
/// bytes actually received; nothing is ever allocated from the claimed `len`,
/// so a hostile length prefix cannot demand memory past the bound (08 §4.2).
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    /// An error hit by feed() after it already accepted frames in the same
    /// call, deferred one call (12 §3.4 row 6): the fabric has no per-event
    /// ack (08 §4.3), so returning Err instead would silently discard events
    /// the writer believes delivered — invisible to Dropped{} accounting.
    deferred: Option<FrameError>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// One decoder step over the unconsumed buffer. Reject leaves the buffer
    /// untouched, so re-polling re-rejects identically — sticky-by-buffer,
    /// matching "reject means close the connection" without a poison flag.
    pub fn next_frame(&mut self) -> Outcome {
        // <9 bytes is incomplete WITHOUT inspecting content — eager prefix
        // rejection is a conformance failure (README §Decoder model, rule 1).
        if self.buf.len() < HEADER_LEN {
            return Outcome::Incomplete {
                needed: HEADER_LEN - self.buf.len(),
            };
        }
        if self.buf[..4] != MAGIC {
            let mut got = [0u8; 4];
            got.copy_from_slice(&self.buf[..4]);
            return Outcome::Reject(FrameError::BadMagic(got));
        }
        if self.buf[4] != VERSION {
            return Outcome::Reject(FrameError::BadVersion(self.buf[4]));
        }
        let len = u32::from_le_bytes([self.buf[5], self.buf[6], self.buf[7], self.buf[8]]);
        // Checked from the 9-byte header BEFORE any payload allocation (07 §5,
        // 08 §4.2) — the payload Vec below can only ever be <= 4 MiB.
        if len == 0 || len > M1PL_MAX_FRAME {
            return Outcome::Reject(FrameError::BadLength(len));
        }
        let total = HEADER_LEN + len as usize;
        if self.buf.len() < total {
            return Outcome::Incomplete {
                needed: total - self.buf.len(),
            };
        }
        let payload = self.buf[HEADER_LEN..total].to_vec();
        // ponytail: drain memmoves the remainder — O(buffered) per frame, so a
        // single push holding many small frames degrades quadratically. A read
        // cursor + amortized compaction if the fabric ever batches like that.
        self.buf.drain(..total);
        Outcome::Accept {
            payload,
            consumed: total,
        }
    }

    /// 04 §7.4 surface: push bytes, drain every complete frame into decoded
    /// Events. Err ⇒ the caller closes the connection. An error reached after
    /// this call already accepted frames returns those events and defers the
    /// Err to the next call — 12 §3.4 row 6: accept frame 1, THEN error; the
    /// signature (frozen by 04 §7.4) cannot carry both at once, and dropping
    /// the events would be exactly the silent discard that row forbids. Frame
    /// rejects also leave the buffer as-is, so the reject stays sticky across
    /// calls rather than resyncing on attacker-chosen bytes (12 §3.4 row 1).
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<pb::Event>, FrameError> {
        self.feed_frames(bytes)?
            .into_iter()
            .map(|f| match f.kind {
                Some(pb::fabric_frame::Kind::Event(ev)) => Ok(ev),
                // A control arm reached a caller draining events: the fabric
                // is request-reply only for the component that asked (08
                // §4.3), so this is the peer speaking a dialect this reader
                // does not — close, exactly like mark1d's default arm.
                _ => Err(FrameError::Envelope("carries a control arm, not an Event")),
            })
            .collect()
    }

    /// The typed surface D-U makes possible: every payload is one
    /// `FabricFrame`, so the oneof arm IS the frame kind. Same accept /
    /// incomplete / reject model and same deferred-error rule as `feed`.
    pub fn feed_frames(&mut self, bytes: &[u8]) -> Result<Vec<pb::FabricFrame>, FrameError> {
        self.push(bytes);
        if let Some(e) = self.deferred.take() {
            return Err(e);
        }
        let mut frames = Vec::new();
        loop {
            let err = match self.next_frame() {
                Outcome::Accept { payload, .. } => match decode_payload(&payload) {
                    Ok(f) => {
                        frames.push(f);
                        continue;
                    }
                    Err(e) => e,
                },
                Outcome::Incomplete { .. } => return Ok(frames),
                Outcome::Reject(e) => e,
            };
            if frames.is_empty() {
                return Err(err);
            }
            self.deferred = Some(err);
            return Ok(frames);
        }
    }
}

/// One M1PL payload → the FabricFrame it must be (D-U). An arm-less frame is
/// an ERROR, not an empty frame: proto3 skips unknown fields, so without this
/// check a payload of nothing but unknown tags would decode "successfully"
/// into a frame that says nothing and be silently ignored.
pub fn decode_payload(payload: &[u8]) -> Result<pb::FabricFrame, FrameError> {
    let frame = pb::FabricFrame::decode(payload)?;
    if frame.kind.is_none() {
        return Err(FrameError::Envelope("carries no oneof arm"));
    }
    Ok(frame)
}

/// Encode one Event as an M1PL/1 frame appended to `out` (04 §7.4). Since D-U
/// the payload is the wrapping `FabricFrame`, not the bare Event — every
/// existing caller keeps this signature and gets the dialect mark1d requires.
pub fn encode_frame(ev: &pb::Event, out: &mut Vec<u8>) -> Result<(), FrameError> {
    // ponytail: one Event clone per frame to reach an owned oneof arm. The
    // shim encodes one event per process and Event is a flat ~536 B struct
    // with three small heap fields; hand-rolling the arm's tag+varint prefix
    // is the upgrade path if a batching writer ever measures it.
    encode_control(
        &pb::FabricFrame {
            kind: Some(pb::fabric_frame::Kind::Event(ev.clone())),
        },
        out,
    )
}

/// Encode any FabricFrame — the control arms (Hello/GateQuery/Flush and their
/// replies) have no hot path, so they pay the generic route. The encoder
/// enforces the same bound as the decoder so an unframeable frame fails at
/// the writer, not as a peer's connection close; an arm-less frame encodes to
/// zero bytes and is refused here, mirroring `decode_payload`.
pub fn encode_control(frame: &pb::FabricFrame, out: &mut Vec<u8>) -> Result<(), FrameError> {
    let len = frame.encoded_len();
    if len == 0 || len > M1PL_MAX_FRAME as usize {
        return Err(FrameError::Unframeable(len));
    }
    out.reserve(HEADER_LEN + len);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    // Cast is lossless: len <= M1PL_MAX_FRAME just above.
    out.extend_from_slice(&(len as u32).to_le_bytes());
    frame.encode(out)?;
    Ok(())
}
