//! End-to-end suite for the shim binary: replay of every committed hook
//! fixture (`conformance/hooks/claudecode@2.1.251`, 12 §3.2), the off-check
//! (invariant 2), the deadline/spill path (04 §5 step 4 + §5.4), the
//! sanitized-spill roundtrip (F-10), maps-as-data override (FR-AGENT-001),
//! and the ≤50 ms end-to-end wall bound (08 §5 rule 5).

// clippy.toml's allow-*-in-tests exempts #[test] fns; the helpers here are
// plain fns, so the exemption is restated at file scope (house style).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(unix)]

use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use m1p_wire::pb;
use m1p_wire::FrameDecoder;
use sha2::Sha256;

const SESSION: &str = "3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55";
/// Deterministic device spill keypair for the tests — the private half never
/// exists in the shim, mirroring mark1d.identity custody (04 §5.4).
const DEVICE_SEED: [u8; 32] = [7u8; 32];
const SEAL_LABEL: &[u8] = b"m1p.spill.seal.v1";

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/hooks/claudecode/v2.1.251/hooks")
        .join(format!("{name}.json"));
    std::fs::read(path).unwrap()
}

struct TestEnv {
    home: tempfile::TempDir,
    xdg: tempfile::TempDir,
}

impl TestEnv {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            xdg: tempfile::tempdir().unwrap(),
        }
    }

    fn sock_path(&self) -> PathBuf {
        self.xdg.path().join("omium-mark1/m1p.sock")
    }

    fn ring_path(&self) -> PathBuf {
        self.home.path().join(".omium/mark1/spill/hookshim.ring")
    }

    /// Materialize the device spill public key the way mark1d would.
    fn install_spill_pubkey(&self) {
        let device = x25519_dalek::StaticSecret::from(DEVICE_SEED);
        let device_pub = x25519_dalek::PublicKey::from(&device);
        let dir = self.home.path().join(".omium/mark1/spill");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("spill.pub"), device_pub.as_bytes()).unwrap();
    }

    /// Fake daemon: accept one connection, read to EOF, hand the bytes back.
    fn listen(&self) -> mpsc::Receiver<Vec<u8>> {
        std::fs::create_dir_all(self.sock_path().parent().unwrap()).unwrap();
        let listener = UnixListener::bind(self.sock_path()).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            if let Ok((mut stream, _addr)) = listener.accept() {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf);
                let _ = tx.send(buf);
            }
        });
        rx
    }

    /// Run the shim with the given stdin; returns (exit ok, stdout+stderr,
    /// wall time).
    fn run(&self, stdin_bytes: &[u8], envs: &[(&str, &str)]) -> (bool, Vec<u8>, Duration) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mark1-hookshim"));
        cmd.env_remove("MARK1_DISABLE")
            .env("HOME", self.home.path())
            .env("XDG_RUNTIME_DIR", self.xdg.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        Self::finish(cmd, stdin_bytes)
    }

    /// Like `run`, but with no resolvable home at all: the off-marker is then
    /// unreachable and `off()` must fail closed (08 §7.6).
    fn run_homeless(&self, stdin_bytes: &[u8]) -> (bool, Vec<u8>, Duration) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mark1-hookshim"));
        cmd.env_remove("MARK1_DISABLE")
            .env_remove("HOME")
            .env_remove("USERPROFILE")
            .env("XDG_RUNTIME_DIR", self.xdg.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Self::finish(cmd, stdin_bytes)
    }

    fn finish(mut cmd: Command, stdin_bytes: &[u8]) -> (bool, Vec<u8>, Duration) {
        let started = Instant::now();
        let mut child = cmd.spawn().unwrap();
        // The shim's off/fail-closed paths exit BEFORE reading stdin (main.rs:
        // off-check precedes everything, 08 §7.6), so this write can race the
        // child's exit and get EPIPE. That pipe error IS the behavior under
        // test, not a harness fault; any other write error is still fatal.
        if let Err(e) = child.stdin.take().unwrap().write_all(stdin_bytes) {
            assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "stdin write: {e}");
        }
        let out = child.wait_with_output().unwrap();
        let wall = started.elapsed();
        let mut chatter = out.stdout;
        chatter.extend_from_slice(&out.stderr);
        (out.status.success(), chatter, wall)
    }
}

fn decode_one_event(frame_bytes: &[u8]) -> pb::Event {
    let mut dec = FrameDecoder::new();
    let mut events = dec.feed(frame_bytes).unwrap();
    assert_eq!(events.len(), 1, "expected exactly one frame");
    events.remove(0)
}

/// Common envelope stamps for every emitted event (04 §5 step 3 + R-4).
fn assert_envelope(ev: &pb::Event) {
    assert_eq!(ev.event_id.len(), 16);
    // UUIDv7: version nibble in byte 6.
    assert_eq!(ev.event_id[6] >> 4, 7, "event_id must be UUIDv7");
    let session = uuid::Uuid::parse_str(SESSION).unwrap();
    assert_eq!(ev.session_id, session.as_bytes().to_vec());
    // seq and session_epoch are mark1d's to assign at admission (R-4).
    assert_eq!(ev.seq, 0);
    assert_eq!(ev.session_epoch, 0);
    assert!(ev.task_id.is_empty());
    assert!(ev.tenant_id.is_empty(), "server band must be unset (07 §2)");
    assert!(ev.occurred_at.is_some());
}

fn unseal_ring(env: &TestEnv) -> Vec<Vec<u8>> {
    let raw = std::fs::read(env.ring_path()).unwrap();
    let device = x25519_dalek::StaticSecret::from(DEVICE_SEED);
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < raw.len() {
        let len_bytes: [u8; 4] = raw[off..off + 4].try_into().unwrap();
        let record_len = u32::from_le_bytes(len_bytes) as usize;
        let rec = &raw[off + 4..off + 4 + record_len];
        off += 4 + record_len;
        assert_eq!(rec[0], 1, "record version");
        let eph: [u8; 32] = rec[9..41].try_into().unwrap();
        let nonce: [u8; 12] = rec[41..53].try_into().unwrap();
        let shared = device.diffie_hellman(&x25519_dalek::PublicKey::from(eph));
        let mut kdf = <Hmac<Sha256> as Mac>::new_from_slice(shared.as_bytes()).unwrap();
        kdf.update(SEAL_LABEL);
        let key: [u8; 32] = kdf.finalize().into_bytes().into();
        let cipher = ChaCha20Poly1305::new((&key).into());
        out.push(cipher.decrypt((&nonce).into(), &rec[53..]).unwrap());
    }
    out
}

// ---- fixture replay (12 §3.2: conf_hooks_claudecode_2.1.251_replay) ----

#[test]
fn conf_hooks_claudecode_2_1_251_replay() {
    for name in [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "Stop",
        "SubagentStop",
        "SessionEnd",
    ] {
        let env = TestEnv::new();
        let rx = env.listen();
        let (ok, chatter, _wall) = env.run(&fixture(name), &[]);
        assert!(ok, "{name}: shim must exit 0");
        assert!(
            chatter.is_empty(),
            "{name}: observer events produce no output"
        );
        let frame = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let ev = decode_one_event(&frame);
        assert_envelope(&ev);
        match (name, ev.body.unwrap()) {
            ("SessionStart", pb::event::Body::SessionStart(b)) => {
                assert_eq!(b.agent, "claudecode");
                assert_eq!(b.agent_version, "2.1.251");
                assert_eq!(b.capture_paths, vec![pb::CapturePath::Hooks as i32]);
                assert!(b.workspace_id.is_empty(), "unkeyed digests never emit");
            }
            ("UserPromptSubmit", pb::event::Body::Turn(b)) => {
                assert_eq!(b.initiator, pb::Initiator::Human as i32);
            }
            ("PreToolUse", pb::event::Body::ToolUse(b)) => {
                assert_eq!(b.tool_name, "Bash");
                assert_eq!(b.tool_use_id, "toolu_01SynthFixtureTTTTTTTT");
                assert_eq!(b.status, pb::ToolStatus::Unspecified as i32);
                assert_eq!(b.duration_ms, 0);
            }
            ("PostToolUse", pb::event::Body::ToolUse(b)) => {
                assert_eq!(b.status, pb::ToolStatus::Ok as i32);
                assert_eq!(b.duration_ms, 4180);
            }
            ("PostToolUseFailure", pb::event::Body::ToolUse(b)) => {
                assert_eq!(b.tool_use_id, "toolu_01SynthFixtureUUUUUUUU");
                assert_eq!(b.status, pb::ToolStatus::Error as i32);
                assert_eq!(b.duration_ms, 2930);
            }
            ("Stop" | "SubagentStop", pb::event::Body::Turn(b)) => {
                assert_eq!(b.initiator, pb::Initiator::Agent as i32);
            }
            ("SessionEnd", pb::event::Body::SessionEnd(b)) => {
                assert_eq!(b.reason, pb::EndReason::Exit as i32);
            }
            (name, other) => panic!("{name}: unexpected body {other:?}"),
        }
    }
}

#[test]
fn conf_hooks_precompact_emits_nothing() {
    // PreCompact maps to kind "none": no committed m1p.v1 body exists for a
    // compaction boundary, and the adapter never guesses (08 §5 rule 2).
    let env = TestEnv::new();
    let rx = env.listen();
    let (ok, chatter, _wall) = env.run(&fixture("PreCompact"), &[]);
    assert!(ok);
    assert!(chatter.is_empty());
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "PreCompact must not reach the fabric"
    );
    assert!(!env.ring_path().exists(), "and must not spill");
}

// ---- off-check (invariant 2, 08 §7.6) ----

#[test]
fn off_env_var_is_a_silent_noop() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let rx = env.listen();
    let (ok, chatter, _wall) = env.run(&fixture("PreToolUse"), &[("MARK1_DISABLE", "1")]);
    assert!(ok, "off must exit 0");
    assert!(
        chatter.is_empty(),
        "byte-identical agent behavior: no output"
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "off must produce zero fabric I/O"
    );
    assert!(
        !env.ring_path().exists(),
        "off must produce zero spill bytes"
    );
}

#[test]
fn off_marker_file_is_a_silent_noop() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let marker_dir = env.home.path().join(".omium/mark1");
    std::fs::create_dir_all(&marker_dir).unwrap();
    std::fs::write(marker_dir.join("OFF"), b"").unwrap();
    let rx = env.listen();
    let (ok, chatter, _wall) = env.run(&fixture("PreToolUse"), &[]);
    assert!(ok);
    assert!(chatter.is_empty());
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
    assert!(!env.ring_path().exists());
}

#[test]
fn no_home_fails_closed_silent_noop() {
    // HOME/USERPROFILE unset ⇒ the off-marker cannot be checked ⇒ OFF
    // (fail-closed, matching mark1d's off.Off): the fabric socket is still
    // resolvable via XDG_RUNTIME_DIR, so capturing here would circumvent
    // `mark1 off` for any agent launched without a home.
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let rx = env.listen();
    let (ok, chatter, _wall) = env.run_homeless(&fixture("PreToolUse"));
    assert!(ok, "off must exit 0");
    assert!(chatter.is_empty());
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "no home ⇒ no capture: the marker check must fail closed"
    );
}

#[test]
fn unreadable_marker_dir_fails_closed() {
    use std::os::unix::fs::PermissionsExt;
    // Root ignores directory modes; the EACCES this test needs never happens.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let env = TestEnv::new();
    env.install_spill_pubkey();
    let dir = env.home.path().join(".omium/mark1");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let rx = env.listen();
    let (ok, chatter, _wall) = env.run(&fixture("PreToolUse"), &[]);
    // Restore before asserting so tempdir cleanup can delete the tree.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(ok);
    assert!(chatter.is_empty());
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "a stat error on the marker must read as OFF, exactly like mark1d"
    );
    assert!(!env.ring_path().exists(), "and must not spill");
}

// ---- deadline + spill (04 §5 step 4, §5.4) ----

#[test]
fn deadline_blocked_fabric_spills_within_budget() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    // A daemon that never accepts, with a starved backlog so the shim's
    // connect BLOCKS instead of queueing: listen(fd, 0) + saturating dummy
    // connects. This is the stall the 45 ms abandon timer exists for.
    std::fs::create_dir_all(env.sock_path().parent().unwrap()).unwrap();
    let listener = UnixListener::bind(env.sock_path()).unwrap();
    unsafe {
        use std::os::unix::io::AsRawFd;
        assert_eq!(libc::listen(listener.as_raw_fd(), 0), 0);
    }
    for _ in 0..8 {
        let path = env.sock_path();
        std::thread::spawn(move || {
            let _ = std::os::unix::net::UnixStream::connect(path);
        });
    }
    std::thread::sleep(Duration::from_millis(50));

    let (ok, chatter, wall) = env.run(&fixture("PreToolUse"), &[]);
    assert!(ok, "a blocked fabric must still exit 0");
    assert!(chatter.is_empty());
    // Only the 45 ms abandon timer can unblock this shim: the connect is
    // parked on a starved backlog with nothing to time it out, so ANY exit
    // proves the timer fired. The margin above 45 ms is the spill path
    // itself — dominated by the debug-build ruleset compile, which the
    // release profile collapses to single-digit ms.
    assert!(wall < Duration::from_millis(500), "took {wall:?}");
    let entries = unseal_ring(&env);
    assert_eq!(entries.len(), 1, "the abandoned event must be in the ring");
    let ev = decode_one_event(&entries[0]);
    assert_envelope(&ev);
    match ev.body.unwrap() {
        pb::event::Body::ToolUse(b) => assert_eq!(b.tool_name, "Bash"),
        other => panic!("unexpected body {other:?}"),
    }
    drop(listener);
}

#[test]
fn spill_roundtrip_redacts_before_sealing() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    // No listener at all: connect fails fast, the event takes the spill
    // path. The payload carries a planted secret where the map reads a
    // string, so the pre-image would reach the ring if the admit axis were
    // skippable — which is exactly what may never happen (invariant 5).
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let payload = String::from_utf8(fixture("PreToolUse"))
        .unwrap()
        .replace("toolu_01SynthFixtureTTTTTTTT", secret);
    let (ok, chatter, _wall) = env.run(payload.as_bytes(), &[]);
    assert!(ok);
    assert!(chatter.is_empty());

    // The ring itself never holds the secret, even ciphertext-wrapped
    // plaintext is post-redaction — check the UNSEALED bytes.
    let entries = unseal_ring(&env);
    assert_eq!(entries.len(), 1);
    let plain = &entries[0];
    let needle = secret.as_bytes();
    assert!(
        !plain.windows(needle.len()).any(|w| w == needle),
        "planted secret survived into the spill ring (CON-008)"
    );
    let token = "\u{27e8}redacted:api_key:".as_bytes();
    assert!(
        plain.windows(token.len()).any(|w| w == token),
        "expected a redaction token in the sanitized entry"
    );
}

#[test]
fn spill_overflow_is_counted_not_silent() {
    let env = TestEnv::new();
    env.install_spill_pubkey();
    // Pre-fill the ring to its 64 MiB writer cap (a sparse set_len is enough —
    // the writer's check is metadata().len()), so the next spill must shed.
    let ring = env.ring_path();
    std::fs::create_dir_all(ring.parent().unwrap()).unwrap();
    let f = std::fs::File::create(&ring).unwrap();
    f.set_len(64 * 1024 * 1024).unwrap();
    drop(f);

    // No daemon at all: the event takes the spill path and hits the cap.
    let shed = ring.with_file_name("hookshim.ring.shed");
    for want in 1..=2u64 {
        let (ok, chatter, _wall) = env.run(&fixture("PreToolUse"), &[]);
        assert!(ok, "a full ring must still exit 0");
        assert!(chatter.is_empty());
        // The Dropped religion (07 §3): the shed is counted in the sidecar —
        // one byte per refused event — for mark1d's drain to convert to
        // Dropped{RING_EVICTED} with this exact quantity (04 §5.4).
        assert_eq!(
            std::fs::metadata(&shed).unwrap().len(),
            want,
            "shed counter must grow by one per refused event"
        );
    }
    assert_eq!(
        std::fs::metadata(&ring).unwrap().len(),
        64 * 1024 * 1024,
        "the writer must refuse to grow the ring past the cap"
    );
}

// ---- maps as data (FR-AGENT-001) ----

#[test]
fn map_file_overrides_builtin_without_binary_change() {
    let env = TestEnv::new();
    let maps_dir = env.home.path().join(".omium/mark1/maps");
    std::fs::create_dir_all(&maps_dir).unwrap();
    // A vendor rename of every field the PreToolUse path reads, fixed
    // purely by map data (08 §5 rule 1).
    std::fs::write(
        maps_dir.join("claudecode.bin"),
        r#"{
          "map_version": 1,
          "agent": "claudecode",
          "agent_version": "9.9.9",
          "event_field": "hookName",
          "session_id_field": "sid",
          "events": {
            "ToolWillRun": {
              "kind": "tool_open",
              "fields": { "tool_name": "toolTitle", "tool_use_id": "invocationId" }
            }
          }
        }"#,
    )
    .unwrap();
    let renamed = format!(
        r#"{{"hookName":"ToolWillRun","sid":"{SESSION}","toolTitle":"Bash","invocationId":"inv_42"}}"#
    );
    let rx = env.listen();
    let (ok, _chatter, _wall) = env.run(renamed.as_bytes(), &[]);
    assert!(ok);
    let frame = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let ev = decode_one_event(&frame);
    match ev.body.unwrap() {
        pb::event::Body::ToolUse(b) => {
            assert_eq!(b.tool_name, "Bash");
            assert_eq!(b.tool_use_id, "inv_42");
        }
        other => panic!("unexpected body {other:?}"),
    }
}

#[test]
fn unmapped_hook_emits_nothing_speculative() {
    let env = TestEnv::new();
    let rx = env.listen();
    let body = format!(r#"{{"hook_event_name":"BrandNewVendorHook","session_id":"{SESSION}"}}"#);
    let (ok, chatter, _wall) = env.run(body.as_bytes(), &[]);
    assert!(ok);
    assert!(chatter.is_empty());
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
}

// ---- the wall budget (04 §5: total ≤50 ms, timer-enforced) ----

#[test]
fn cold_start_end_to_end_under_50ms() {
    let env = TestEnv::new();
    let rx = env.listen();
    // One warm-up spawn so the very first exec's page-cache misses don't
    // bill this measurement; the budget is per-invocation steady state.
    let _ = env.run(&fixture("SessionEnd"), &[("MARK1_DISABLE", "1")]);
    let (ok, _chatter, wall) = env.run(&fixture("PreToolUse"), &[]);
    assert!(ok);
    assert!(
        rx.recv_timeout(Duration::from_secs(2)).is_ok(),
        "happy path must reach the fabric"
    );
    assert!(
        wall < Duration::from_millis(50),
        "observer budget blown: {wall:?} (04 §5 step 4)"
    );
}
