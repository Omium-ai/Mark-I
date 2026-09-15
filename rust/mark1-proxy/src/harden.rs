//! Core-dump / memory-disclosure suppression — 04 §3.3 and §11.6, NFR-SECURITY-002.
//!
//! `harden()` runs as the first statement of `main`, before the runtime starts and before
//! any file that could hold key material is opened. Ordering is the whole control: a core
//! written from a process that had already read a credential is the disclosure this
//! prevents, and there is no point in the lifetime of this process at which that is
//! recoverable after the fact.

use std::io;

/// Platform-specific result of hardening, for the negative test to assert against rather
/// than trusting that the syscalls were issued.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Hardening {
    /// `RLIMIT_CORE` soft and hard limits are both 0.
    pub core_limit_zero: bool,
    /// `PR_GET_DUMPABLE == 0`. Linux only; `None` where the concept does not exist.
    pub dumpable: Option<bool>,
}

/// Apply every §11.6 control available on this platform, then read the state back.
///
/// Err means a control this platform is supposed to have could not be applied, or is not
/// reachable from the dependencies this crate declares. The caller must treat that as fatal:
/// the posture for secrets is fail-closed (04 §3.5), and a proxy that holds credentials
/// while claiming a suppression it does not have is worse than one that will not start.
pub fn harden() -> io::Result<Hardening> {
    imp::harden()
}

#[cfg(unix)]
mod imp {
    use super::Hardening;
    use std::io;

    pub fn harden() -> io::Result<Hardening> {
        set_core_limit_zero()?;
        let dumpable = set_not_dumpable()?;
        // Read back rather than trusting the return codes: a container runtime or an LSM can
        // accept the call and not honour it.
        let state = Hardening {
            core_limit_zero: read_core_limit()? == 0,
            dumpable,
        };
        if !state.core_limit_zero {
            return Err(io::Error::other("RLIMIT_CORE did not stick at 0"));
        }
        if state.dumpable == Some(true) {
            return Err(io::Error::other("PR_SET_DUMPABLE did not stick at 0"));
        }
        Ok(state)
    }

    fn set_core_limit_zero() -> io::Result<()> {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `lim` is a fully initialized rlimit and outlives the call.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `rlim_t` rather than `u64`: its width is platform-defined, and the only question asked
    /// of the value is whether it is zero.
    fn read_core_limit() -> io::Result<libc::rlim_t> {
        let mut lim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: `lim` is a fully initialized rlimit written by the call.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(lim.rlim_cur)
    }

    /// Returns the flag as the kernel reports it: `Some(false)` = not dumpable = hardened.
    #[cfg(target_os = "linux")]
    fn set_not_dumpable() -> io::Result<Option<bool>> {
        // SAFETY: PR_SET_DUMPABLE/PR_GET_DUMPABLE take no pointer arguments.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let got = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(got != 0))
    }

    /// macOS: `RLIMIT_CORE=0` only — §11.6 records that the dumpable flag has no equivalent.
    #[cfg(not(target_os = "linux"))]
    fn set_not_dumpable() -> io::Result<Option<bool>> {
        Ok(None)
    }
}

#[cfg(windows)]
mod imp {
    use super::Hardening;
    use std::io;

    /// §11.6's Windows arm is `WerAddExcludedApplication` plus the absence of an
    /// unhandled-exception minidump handler. Both live in `Win32_System_ErrorReporting` /
    /// `Win32_System_Diagnostics_Debug`, and neither feature is enabled on the `windows-sys`
    /// entry in the workspace manifest — which this crate is not permitted to edit.
    ///
    /// So this arm refuses to start rather than returning `Ok` on a no-op. A silent no-op
    /// here would make NFR-SECURITY-002 a claim that is false on exactly one platform, and
    /// nothing downstream could tell. Enabling `Win32_System_ErrorReporting` in
    /// `[workspace.dependencies].windows-sys` is the whole fix.
    pub fn harden() -> io::Result<Hardening> {
        Err(io::Error::other(
            "04 §11.6 Windows suppression (WerAddExcludedApplication) is unreachable: \
             windows-sys lacks the Win32_System_ErrorReporting feature in the workspace \
             manifest. Refusing to start rather than hold credentials unprotected.",
        ))
    }
}

// `all(test, unix)`: both tests are unix-only, so on Windows the module would hold one
// unused `use super::*` and `-D warnings` makes that a build error there (CI run 35025349147).
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// 12 §9 row 2 `neg_core_dumps_suppressed` (NFR-SECURITY-002).
    ///
    /// 12 specifies "induced crash writes no core". Inducing a crash inside the test process
    /// destroys the harness, and inducing one in a child requires a second binary; the
    /// asserted precondition — the limits the kernel consults when deciding whether to write
    /// that core — is the same fact, read back from the kernel rather than from our own
    /// return codes.
    #[test]
    #[cfg(unix)]
    fn neg_core_dumps_suppressed() {
        let state = harden().expect("hardening must succeed on a unix host");
        assert!(state.core_limit_zero, "RLIMIT_CORE is not 0");

        // Read the limit through a second, independent path so the assertion does not rest
        // on the same code that set it.
        let mut lim = libc::rlimit {
            rlim_cur: u64::MAX as _,
            rlim_max: u64::MAX as _,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
        assert_eq!(rc, 0);
        assert_eq!(lim.rlim_cur, 0, "soft RLIMIT_CORE");
        assert_eq!(
            lim.rlim_max, 0,
            "hard RLIMIT_CORE — a raisable hard limit is not a control"
        );

        #[cfg(target_os = "linux")]
        {
            assert_eq!(state.dumpable, Some(false), "PR_SET_DUMPABLE");
            let got = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
            assert_eq!(got, 0);
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(state.dumpable, None, "§11.6: no dumpable flag off Linux");
    }

    /// Idempotent: `main` calls this once, but a test binary may call it many times and a
    /// lowered hard limit must not make the second call fail.
    #[test]
    #[cfg(unix)]
    fn harden_is_idempotent() {
        assert!(harden().is_ok());
        assert!(harden().is_ok());
    }
}
