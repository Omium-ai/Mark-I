//! m1p-wire — committed `m1p.v1` codegen + M1PL/1 framing (04 §7.4).
//!
//! Frame bytes are owned by 07 §5; the len bound by 08 §4.2 (D-A). This crate
//! is the reference M1PL implementation from C2 onward (12 §3.4): the Go
//! decoder in `mark1d/internal/fabric` must agree with it on every vector in
//! `conformance/vectors/m1pl/`, bit-identically.

// The committed gen references well-known types as
// `super::super::google::protobuf::*` (buf remote plugin output, 13 §5.2), so
// the include! must sit exactly two modules below this mapping — which is why
// the layout is `m1p::v1` re-exported as `pb`, not the flat `pub mod pb`
// sketch in 13 §2.4: that sketch cannot resolve `super::super` from crate
// depth 1. The consumer surface 13 §7 names (`m1p-wire::pb`) is preserved.
pub mod google {
    pub mod protobuf {
        pub use prost_types::Timestamp;
    }
}

pub mod m1p {
    // FabricFrame::Kind (D-U) is ~536 B because its Event arm is, and Event is
    // the overwhelming majority of frames — boxing it to satisfy
    // large_enum_variant would add a heap allocation to the hot path to shrink
    // the arms nobody sends. The lint measures the wrong thing for this shape.
    #[allow(clippy::large_enum_variant)]
    pub mod v1 {
        // Staged copy of proto/gen/rust/m1p.v1.rs — committed, no build.rs
        // (13 §2.4); gen_fresh.sh fails CI if it drifts from proto/gen.
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/gen/m1p.v1.rs"));
    }
}

pub use m1p::v1 as pb;

pub mod framing;

pub use framing::{
    decode_payload, encode_control, encode_frame, FrameDecoder, FrameError, Outcome, M1PL_MAX_FRAME,
};
