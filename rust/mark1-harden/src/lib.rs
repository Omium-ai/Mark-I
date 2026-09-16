//! mark1-harden — core-dump / memory-disclosure suppression for every Rust edge process
//! (04 §3.3 and §11.6, 10 §4.1, NFR-SECURITY-002).
//!
//! One crate, three callers, one rule: [`apply`] is called before the runtime exists and before
//! any file that could hold key material or a hook body is opened. The proxy holds the upstream
//! credential; cortexd holds the loopback bearer and the workspace index; the hookshim holds the
//! hook payload. A core written from any of them after that point is the disclosure this
//! prevents, and nothing later in the process's lifetime can take it back.
//!
//! MANIFEST DECISION, taken here and recorded here. The proxy's original `harden.rs` refused to
//! start on Windows because `windows-sys` lacked the `Win32_System_ErrorReporting` feature and
//! said "a manifest decision the crate may not take". This crate takes it:
//! `[workspace.dependencies].windows-sys` now enables that feature so the §11.6 arm
//! (`WerAddExcludedApplication`) is a real call rather than a refusal. It is a feature on a
//! crate already in both token-path closures, not a new crate, so no closure grows by it.

mod harden;

pub use harden::apply;
