//! 07 §5's Windows endpoint, `\\.\pipe\omium-mark1-<user-SID>`; the twin of go/mark1d/internal/fabric/listener_windows.go.

use std::io;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub fn fabric_pipe_name() -> io::Result<String> {
    Ok(format!(r"\\.\pipe\omium-mark1-{}", user_sid()?))
}

/// The process token's user as a string SID (S-1-5-21-...), the same call mark1d makes.
pub fn user_sid() -> io::Result<String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the pseudo-handle needs no close; `token` receives a real handle on success.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid = token_user_sid(token);
    // SAFETY: `token` was opened above and is not used after this.
    unsafe { CloseHandle(token) };
    sid
}

fn token_user_sid(token: HANDLE) -> io::Result<String> {
    let mut len = 0u32;
    // SAFETY: a zero-length query only writes `len`.
    unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    // u64-backed so the TOKEN_USER (a pointer + u32) inside is aligned.
    let mut buf = vec![0u64; len.div_ceil(8) as usize];
    // SAFETY: `buf` holds `len` bytes and outlives the call.
    if unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the buffer now holds a TOKEN_USER written by the OS; its Sid points into it.
    let psid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut wide: *mut u16 = ptr::null_mut();
    // SAFETY: `psid` is valid while `buf` lives; `wide` receives a LocalAlloc'd string.
    if unsafe { ConvertSidToStringSidW(psid, &mut wide) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut n = 0;
    // SAFETY: the string is NUL-terminated by the OS.
    while unsafe { *wide.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: `n` u16s were read as non-NUL above.
    let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(wide, n) });
    // SAFETY: `wide` came from ConvertSidToStringSidW and is freed exactly once.
    unsafe { LocalFree(wide.cast()) };
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_is_the_prefix_plus_a_string_sid() {
        let sid = user_sid().unwrap();
        assert!(sid.starts_with("S-1-"), "{sid}");
        assert!(sid.matches('-').count() >= 3, "{sid}");
        assert_eq!(
            fabric_pipe_name().unwrap(),
            format!(r"\\.\pipe\omium-mark1-{sid}")
        );
    }

    #[test]
    fn sid_is_stable_across_calls() {
        assert_eq!(user_sid().unwrap(), user_sid().unwrap());
    }
}
