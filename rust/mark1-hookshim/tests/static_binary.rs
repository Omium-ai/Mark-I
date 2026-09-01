//! NFR-PORTABILITY-003: the shim ships as one binary per platform and may
//! assume nothing on the customer's machine beyond the platform's own libc.
//!
//! The regression this catches is a crate arriving in the shim's tree that
//! links a native library — `openssl-sys`, `libsqlite3-sys`, anything that
//! vendors a `.so`. Cargo.toml's "no tokio, no clap, no config crate" note is
//! a comment; this is the check. A shim that needs `libssl.so.3` breaks the
//! product claim on exactly the machines nobody tests on, and it breaks it at
//! the customer's first run, not in CI.
//!
//! ONE test name, branching on target inside, rather than a `#[cfg]`-gated test
//! per platform: `just trace-check` resolves evidence citations by asking the
//! host's test runner what exists, so a name that compiles away on the host is
//! a citation that cannot be checked — and an unresolvable citation is exactly
//! what check 2 fails the build over.
//!
//! Windows is deliberately uncovered: `dumpbin` / `link /dump` need the MSVC
//! toolchain on PATH, which the runner does not guarantee, and a test that
//! silently does nothing where its tool is missing converts an open gap into a
//! false green. That half is carried as a `partial:` on this row in
//! conformance/traceability.yaml rather than faked here.

// clippy.toml's allow-*-in-tests exempts #[test] fns; restated at file scope
// (house style, mirroring shim_e2e.rs).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(unix)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_mark1-hookshim");

#[test]
fn shim_needs_nothing_on_the_customer_machine_but_libc() {
    #[cfg(target_os = "linux")]
    audit_with_ldd();
    #[cfg(target_os = "macos")]
    audit_with_otool();
}

/// glibc's own objects, the loader, and the unwinder rustc always links. This
/// list IS "the platform libc contract" of 02 §9's acceptance column —
/// anything outside it is something the customer has to have installed.
#[cfg(target_os = "linux")]
const LIBC_CONTRACT: &[&str] = &[
    "linux-vdso.so.1",
    "ld-linux-x86-64.so.2",
    "ld-linux-aarch64.so.1",
    "libc.so.6",
    "libm.so.6",
    "libgcc_s.so.1",
    // Empty stubs since glibc 2.34, still emitted by older toolchains.
    "libdl.so.2",
    "libpthread.so.0",
    "librt.so.1",
];

#[cfg(target_os = "linux")]
fn audit_with_ldd() {
    let out = Command::new("ldd")
        .arg(BIN)
        .output()
        .expect("ldd is glibc's own tool — its absence is a broken toolchain, not a reason to skip a portability audit");
    assert!(
        out.status.success(),
        "ldd {BIN} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let text = String::from_utf8_lossy(&out.stdout);
    let seen: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("statically linked"))
        // "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x…)"
        // "/lib64/ld-linux-x86-64.so.2 (0x…)"
        .map(|l| {
            let first = l.split_whitespace().next().unwrap_or(l);
            first.rsplit('/').next().unwrap_or(first)
        })
        .filter(|s| !s.is_empty())
        .collect();

    // Anti-vacuity: "no foreign libraries" is also what a parser that reads
    // nothing reports. libc is on every glibc target, so seeing it is the proof
    // the audit ran rather than the proof it was silent.
    assert!(
        seen.contains(&"libc.so.6"),
        "ldd output parsed to {seen:?} with no libc in it — the audit saw nothing, so an empty foreign list would prove nothing"
    );

    let foreign: Vec<&&str> = seen.iter().filter(|s| !LIBC_CONTRACT.contains(s)).collect();
    assert!(
        foreign.is_empty(),
        "mark1-hookshim needs {foreign:?} present on the customer's machine. \
         NFR-PORTABILITY-003 allows the platform libc and nothing else: find the \
         crate that pulled a native library in and drop it, or the shim stops \
         being a binary you can copy onto a machine and run."
    );
}

/// macOS is audited by PATH PREFIX rather than by name: the system dylib set is
/// large and versioned, but its LOCATION is the invariant. `/opt/homebrew/…`,
/// `/usr/local/…` and any `@rpath/…` entry are all "something the customer has
/// to have installed", which is exactly what this row forbids.
#[cfg(target_os = "macos")]
fn audit_with_otool() {
    let out = Command::new("otool")
        .arg("-L")
        .arg(BIN)
        .output()
        .expect("otool ships with the Xcode command line tools — its absence is a broken toolchain, not a reason to skip a portability audit");
    assert!(
        out.status.success(),
        "otool -L {BIN} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let text = String::from_utf8_lossy(&out.stdout);
    let seen: Vec<&str> = text
        .lines()
        .skip(1) // line 1 is the binary's own path
        .map(|l| l.split(" (compatibility").next().unwrap_or(l).trim())
        .filter(|p| !p.is_empty())
        .collect();

    // Anti-vacuity, as above: libSystem is linked by every Mach-O rustc emits.
    assert!(
        seen.iter().any(|p| p.contains("libSystem")),
        "otool output parsed to {seen:?} with no libSystem in it — the audit saw nothing"
    );

    let foreign: Vec<&&str> = seen
        .iter()
        .filter(|p| !p.starts_with("/usr/lib/") && !p.starts_with("/System/Library/Frameworks/"))
        .collect();
    assert!(
        foreign.is_empty(),
        "mark1-hookshim needs {foreign:?} present on the customer's machine. \
         NFR-PORTABILITY-003 allows only system-owned locations (/usr/lib, \
         /System/Library/Frameworks); a Homebrew or @rpath dylib is a dependency \
         the customer does not have."
    );
}
