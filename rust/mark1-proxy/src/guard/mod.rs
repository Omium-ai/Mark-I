//! 04 §3.1 — the provenance guard and its shape tripwire.

pub mod provenance;
pub mod shape;

pub use provenance::{
    Cause, Decision, Enrollment, ForwardTicket, Guard, Outcome, Refusal, Sampling, CRED_REF_HEADER,
    DEFAULT_FORWARD_SAMPLE_RATE, REASON_OAUTH_MARKER, REASON_UNPROVISIONED, REFUSED_SAMPLE_RATE,
};
pub use shape::{Classifier, CredShape};
