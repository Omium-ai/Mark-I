//! The per-platform arms. Moved from `rust/mark1-proxy/src/harden.rs`, and the file keeps its
//! name so the libtest paths `harden::tests::*` that conformance/traceability.yaml cites for
//! NFR-SECURITY-002 stay resolvable.
//!
//! `apply()` runs as the first statement of `main`, before the runtime starts and before any
//! file that could hold key material is opened. Ordering is the whole control: a core written
//! from a process that had already read a credential is the disclosure this prevents, and there
//! is no point in the lifetime of this process at which that is recoverable after the fact.

use std::io;

/// Apply every §11.6 control available on this platform, then read the state back.
///
/// `Ok` means the controls were applied AND read back as applied — a container runtime or an
/// LSM can accept the call and not honour it, so the return codes alone are not the proof.
/// `Err` means a control this platform is supposed to have could not be applied. The caller
/// must treat that as fatal: the posture for secrets is fail-closed (04 §3.5), and a process
/// that holds credentials while claiming a suppression it does not have is worse than one that
/// will not start.
pub fn apply() -> io::Result<()> {
    imp::apply()
}

#[cfg(unix)]
mod imp {
    use std::io;

    pub fn apply() -> io::Result<()> {
        set_core_limit_zero()?;
        set_not_dumpable()?;
        if read_core_limit()? != 0 {
            return Err(io::Error::other("RLIMIT_CORE did not stick at 0"));
        }
        Ok(())
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

    /// Sets the flag and reads it back as the kernel reports it.
    #[cfg(target_os = "linux")]
    fn set_not_dumpable() -> io::Result<()> {
        // SAFETY: PR_SET_DUMPABLE/PR_GET_DUMPABLE take no pointer arguments.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let got = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        if got != 0 {
            return Err(io::Error::other("PR_SET_DUMPABLE did not stick at 0"));
        }
        Ok(())
    }

    /// macOS: `RLIMIT_CORE=0` only — §11.6 records that the dumpable flag has no equivalent.
    #[cfg(not(target_os = "linux"))]
    fn set_not_dumpable() -> io::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use std::io;
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::System::ErrorReporting::WerAddExcludedApplication;

    /// §11.6's Windows arm: `WerAddExcludedApplication` for this executable, per-user
    /// (`bAllUsers = FALSE` — HKLM needs admin, and a daemon that needs admin to start is a
    /// bigger hole than the one it closes), plus the absence of an unhandled-exception
    /// minidump handler, which is satisfied by registering none anywhere in the workspace.
    ///
    /// CEILING, documented rather than papered over: the exclusion tells Windows Error
    /// Reporting not to collect a user-mode dump for this exe name. It does not stop a kernel /
    /// complete-memory dump imaging the process, nor an administrator's debugger — 10 §4.2
    /// lists both as the accepted Windows residual. And there is no read-back API short of
    /// `Win32_System_Registry`, so the HRESULT is the only signal here; CI's Windows leg is the
    /// verdict on whether it takes on a real runner.
    ///
    /// The exe is passed by file name, not path: WER matches on the name, and `MAX_PATH` would
    /// otherwise bound where the binary may live.
    pub fn apply() -> io::Result<()> {
        let name = exe_name_wide()?;
        // SAFETY: `name` is NUL-terminated UTF-16 and outlives the call; the BOOL is by value.
        let hr = unsafe { WerAddExcludedApplication(name.as_ptr(), 0) };
        if hr < 0 {
            return Err(io::Error::other(format!(
                "WerAddExcludedApplication failed: HRESULT {hr:#010x}"
            )));
        }
        Ok(())
    }

    pub(super) fn exe_name_wide() -> io::Result<Vec<u16>> {
        let exe = std::env::current_exe()?;
        let name = exe
            .file_name()
            .ok_or_else(|| io::Error::other("current_exe has no file name"))?;
        Ok(name.encode_wide().chain(std::iter::once(0)).collect())
    }
}

// `all(test, unix)`: these tests are unix-only, so on Windows the module would hold one
// unused `use super::*` and `-D warnings` makes that a build error there (CI run 35025349147).
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// 12 §9 row 2 `neg_core_dumps_suppressed` (NFR-SECURITY-002): the limits the kernel
    /// consults when deciding whether to write a core, read back from the kernel through a
    /// second, independent path so the assertion does not rest on the code that set them.
    /// The induced-crash clause is `neg_induced_crash_writes_no_core` below.
    #[test]
    fn neg_core_dumps_suppressed() {
        apply().expect("hardening must succeed on a unix host");

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
            let got = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
            assert_eq!(got, 0, "PR_GET_DUMPABLE");
        }
    }

    /// Idempotent: `main` calls this once, but a test binary may call it many times and a
    /// lowered hard limit must not make the second call fail. Also the shape every supervised
    /// child sees: mark1d hardens first, and the child inherits {0,0} before applying its own.
    #[test]
    fn harden_is_idempotent() {
        assert!(apply().is_ok());
        assert!(apply().is_ok());
    }

    /// Env var that turns a re-run of this test binary into the crashing child. Set by the
    /// parent test only; unset, `induced_crash_child` is a no-op.
    #[cfg(target_os = "linux")]
    const CRASH_CHILD: &str = "MARK1_HARDEN_CRASH_CHILD";

    /// 12 §9 row 2's literal clause: "induced crash writes no core". The child is this test
    /// binary re-run on `induced_crash_child` alone in a fresh cwd: it applies hardening, reads
    /// RLIMIT_CORE back through getrlimit and writes it to a marker file, then `abort()`s. The
    /// marker is what keeps this non-vacuous on a runner whose `ulimit -c` is already 0 or
    /// whose core_pattern is a pipe: "no core file" is asserted alongside "the child itself saw
    /// {0,0}", and the exit status must be the SIGABRT it died of, not a clean exit that never
    /// reached the crash.
    ///
    /// Linux only: macOS writes cores to /cores rather than the cwd, and Windows has no core
    /// file — the Windows arm's verdict is the CI leg's `apply_takes_on_windows`.
    #[test]
    #[cfg(target_os = "linux")]
    fn neg_induced_crash_writes_no_core() {
        use std::os::unix::process::ExitStatusExt;

        let dir = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("induced_crash_child")
            .env(CRASH_CHILD, "1")
            .current_dir(dir.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(
            status.signal(),
            Some(libc::SIGABRT),
            "child must die of SIGABRT, got {status:?}"
        );
        let marker = std::fs::read_to_string(dir.path().join("rlimit_core"))
            .expect("child writes its RLIMIT_CORE read-back before aborting");
        assert_eq!(
            marker, "0 0",
            "RLIMIT_CORE {{soft hard}} as the child read it back"
        );

        let cores: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .filter(|n| n.to_string_lossy().starts_with("core"))
            .collect();
        assert!(cores.is_empty(), "induced crash wrote a core: {cores:?}");
    }

    /// The child half of the test above. A no-op unless spawned by it.
    #[test]
    #[cfg(target_os = "linux")]
    fn induced_crash_child() {
        if std::env::var_os(CRASH_CHILD).is_none() {
            return;
        }
        apply().unwrap();
        let mut lim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) }, 0);
        std::fs::write("rlimit_core", format!("{} {}", lim.rlim_cur, lim.rlim_max)).unwrap();
        // SAFETY: abort() has no preconditions; it never returns.
        unsafe { libc::abort() }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use windows_sys::Win32::System::ErrorReporting::WerRemoveExcludedApplication;

    /// The Windows verdict, taken on the CI leg: the exclusion call takes for this exe, and
    /// is removed again so a developer's HKCU is not left carrying every test binary hash.
    #[test]
    fn apply_takes_on_windows() {
        apply().expect("WerAddExcludedApplication must take for the current user");
        let name = imp::exe_name_wide().unwrap();
        // SAFETY: `name` is NUL-terminated UTF-16 and outlives the call.
        let hr = unsafe { WerRemoveExcludedApplication(name.as_ptr(), 0) };
        assert!(hr >= 0, "WerRemoveExcludedApplication: HRESULT {hr:#010x}");
    }
}
