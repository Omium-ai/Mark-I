//! MCP loopback wall — the 08 §4.5 negative cases over a real socket:
//! wrong `Host` (M1E-4004), any `Origin` (M1E-4005), missing bearer
//! (M1E-1002) — plus the positive path serving the 08 §6 tools.

// clippy.toml's allow-*-in-tests exempts #[test] fns; the helpers here are
// plain fns, so the exemption is restated at file scope (house style).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture")
}

struct Server {
    addr: std::net::SocketAddr,
    host: String,
    token: String,
    _store: tempfile::TempDir,
}

async fn spawn_server() -> Server {
    let store = tempfile::tempdir().unwrap();
    // bootstrap owns store creation (0700 + mode refusal); hand it a fresh path.
    let (shared, cas) = cortexd::bootstrap(fixture(), store.path().join("store"), 2000).unwrap();
    cortexd::full_index(&shared, &cas).unwrap();
    let (listener, state) = cortexd::mcp::bind(Arc::clone(&shared)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = state.expected_host.clone();
    tokio::spawn(async move {
        let _ = axum::serve(listener, cortexd::mcp::router(state)).await;
    });
    Server {
        addr,
        host,
        token: shared.token.clone(),
        _store: store,
    }
}

/// Hand-rolled HTTP/1.1 so the test controls Host byte-for-byte (a client
/// library would helpfully rewrite it, defeating the point).
async fn raw_request(
    addr: std::net::SocketAddr,
    host: &str,
    origin: Option<&str>,
    bearer: Option<&str>,
    body: &str,
) -> String {
    let mut req = format!(
        "POST /mcp HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(o) = origin {
        req.push_str(&format!("Origin: {o}\r\n"));
    }
    if let Some(b) = bearer {
        req.push_str(&format!("Authorization: Bearer {b}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

const LIST: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;

#[tokio::test]
async fn wrong_host_is_403_m1e4004() {
    let s = spawn_server().await;
    // "localhost" resolves to the same interface but is NOT the bound literal.
    let port = s.addr.port();
    for host in [
        format!("localhost:{port}"),
        format!("127.0.0.1:{}", port.wrapping_add(1)),
        "evil.example".to_string(),
    ] {
        let resp = raw_request(s.addr, &host, None, Some(&s.token), LIST).await;
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "host {host} must be rejected, got: {resp}"
        );
        assert!(resp.contains("M1E-4004"));
    }
}

#[tokio::test]
async fn any_origin_is_403_m1e4005() {
    let s = spawn_server().await;
    // Even a loopback Origin is rejected: a legitimate caller is a local
    // process, never a browser page (08 §4.5).
    for origin in ["https://evil.example", &format!("http://{}", s.host)] {
        let resp = raw_request(s.addr, &s.host, Some(origin), Some(&s.token), LIST).await;
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "origin {origin} must be rejected"
        );
        assert!(resp.contains("M1E-4005"));
    }
}

#[tokio::test]
async fn missing_or_wrong_bearer_is_401_m1e1002() {
    let s = spawn_server().await;
    let resp = raw_request(s.addr, &s.host, None, None, LIST).await;
    assert!(resp.starts_with("HTTP/1.1 401"), "missing bearer: {resp}");
    assert!(resp.contains("M1E-1002"));

    let wrong = "0".repeat(s.token.len());
    let resp = raw_request(s.addr, &s.host, None, Some(&wrong), LIST).await;
    assert!(resp.starts_with("HTTP/1.1 401"), "wrong bearer: {resp}");
}

#[tokio::test]
async fn authed_caller_lists_and_calls_tools() {
    let s = spawn_server().await;
    let resp = raw_request(s.addr, &s.host, None, Some(&s.token), LIST).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "authed list: {resp}");
    for tool in [
        "repo_map",
        "find_definition",
        "find_references",
        "deps",
        "ranked_files",
        "memory_recall",
    ] {
        assert!(resp.contains(tool), "tools/list must expose {tool}");
    }

    let call = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_definition","arguments":{"symbol":"render"}}}"#;
    let resp = raw_request(s.addr, &s.host, None, Some(&s.token), call).await;
    assert!(resp.starts_with("HTTP/1.1 200"));
    assert!(resp.contains("web/render.ts"), "definition served: {resp}");
    assert!(resp.contains("blake3:"), "answers carry the L0 root");

    // Path scoping (08 §6): traversal out of the workspace refuses M1E-6402.
    let esc = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"deps","arguments":{"path":"../../../etc/passwd"}}}"#;
    let resp = raw_request(s.addr, &s.host, None, Some(&s.token), esc).await;
    assert!(resp.contains("M1E-6402"), "traversal must refuse: {resp}");
}

/// Store-dir + discovery-file boundary, mirroring mark1d's fabric listener
/// (go/mark1d/internal/fabric/listener.go): the store is created 0700, and
/// group/world bits on an existing store dir or mcp.json are REFUSED, never
/// silently chmod'd — the store holds index content and the bearer token.
#[cfg(unix)]
#[tokio::test]
async fn loose_store_or_discovery_modes_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let work = tempfile::tempdir().unwrap();
    std::fs::write(work.path().join("keep.py"), b"def f():\n    pass\n").unwrap();
    let holder = tempfile::tempdir().unwrap();

    // Fresh creation lands 0700, umask notwithstanding.
    let fresh = holder.path().join("parent/store");
    cortexd::bootstrap(work.path().to_path_buf(), fresh.clone(), 2000).unwrap();
    let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700, "store dir must be created 0700");

    // An existing dir with group/world bits refuses — no chmod-and-continue.
    let loose = holder.path().join("loose");
    std::fs::create_dir(&loose).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        cortexd::bootstrap(work.path().to_path_buf(), loose.clone(), 2000).is_err(),
        "group/world-readable store dir must refuse"
    );

    // A pre-existing group/world-readable mcp.json refuses: mode(0o600) only
    // holds on creation, and the token must never land in a looser file.
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (shared, _cas) =
        cortexd::bootstrap(work.path().to_path_buf(), loose.clone(), 2000).unwrap();
    let mcp_json = loose.join("mcp.json");
    std::fs::write(&mcp_json, "{}").unwrap();
    std::fs::set_permissions(&mcp_json, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        cortexd::mcp::bind(shared).await.is_err(),
        "group/world-readable mcp.json must refuse, not receive the token"
    );
}

/// Minimal indexed one-file workspace for direct `call_tool` tests (no socket).
fn scratch() -> (
    Arc<cortexd::session::Shared>,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let work = tempfile::tempdir().unwrap();
    std::fs::write(work.path().join("keep.py"), b"def f():\n    pass\n").unwrap();
    let store = tempfile::tempdir().unwrap();
    let (shared, cas) =
        cortexd::bootstrap(work.path().to_path_buf(), store.path().join("store"), 2000).unwrap();
    cortexd::full_index(&shared, &cas).unwrap();
    (shared, work, store)
}

/// An ignore file that EXISTS but cannot be read must refuse M1E-6402 —
/// falling back to an empty rule set would serve exactly the paths the user
/// wrote rules to exclude (fail-closed, 08 §6). Absent files stay an empty set.
#[cfg(unix)]
#[test]
fn unreadable_ignore_file_fails_closed_m1e6402() {
    use std::os::unix::fs::PermissionsExt;
    let (shared, work, _store) = scratch();
    let args = serde_json::json!({ "symbol": "f", "hint_path": "keep.py" });
    let out = cortexd::mcp::call_tool(&shared, "find_definition", &args).unwrap();
    assert_eq!(
        out["refused"],
        serde_json::json!(false),
        "no ignore file = empty set"
    );

    let ignore = work.path().join(".mark1ignore");
    std::fs::write(&ignore, "secret/\n").unwrap();
    std::fs::set_permissions(&ignore, std::fs::Permissions::from_mode(0o000)).unwrap();
    let out = cortexd::mcp::call_tool(&shared, "find_definition", &args).unwrap();
    assert_eq!(
        out["reason_code"],
        serde_json::json!("M1E-6402"),
        "unreadable ignore file must refuse, never silently ignore nothing"
    );
}

/// memory_recall obeys the common contract like its siblings (08 §6): every
/// non-refused result carries the preamble (refused/root_hash/index_clock/
/// budget), so call_tool books real token usage — latent only while the
/// artifact cache is the Phase-2 honest-empty stub.
#[test]
fn memory_recall_carries_preamble_and_budget() {
    let (shared, _work, _store) = scratch();
    let out = cortexd::mcp::call_tool(
        &shared,
        "memory_recall",
        &serde_json::json!({ "query": "auth retry pitfalls" }),
    )
    .unwrap();
    assert_eq!(out["refused"], serde_json::json!(false));
    assert!(out["root_hash"].as_str().unwrap().starts_with("blake3:"));
    assert!(out["index_clock"].is_u64());
    assert_eq!(out["artifacts"], serde_json::json!([]), "honest empty");
    let used = out["budget"]["used_tokens"]
        .as_u64()
        .expect("budget accounting present");
    assert!(
        used > 0,
        "the envelope itself costs tokens; zero means unbooked"
    );
}

/// FR-CORTEX-005 / 04 §6.4: every serve emits one `CortexInjection`, refusals
/// included. This `Shared` has no session file, so every emission is HELD
/// for the session mark1d will publish (D-AT/D-AV: nothing is sent without
/// one, and holding is not a drop) — `pending` is the per-call emission
/// witness; the event itself must carry the live L0 root and the current
/// index clock.
#[test]
fn every_tool_call_emits_one_cortex_injection() {
    use m1p_wire::pb::{event::Body, InjectionChannel};
    use std::sync::atomic::Ordering;
    let (shared, _work, _store) = scratch();
    let held = |shared: &cortexd::session::Shared| shared.pending.lock().unwrap().len() as u64;
    let before = held(&shared);
    let calls = [
        ("find_definition", serde_json::json!({ "symbol": "f" })),
        ("repo_map", serde_json::json!({})),
        ("memory_recall", serde_json::json!({ "query": "anything" })),
    ];
    for (name, args) in &calls {
        cortexd::mcp::call_tool(&shared, name, args).unwrap();
    }
    // A refusal is a serve too (emit_and wraps the M1E-6401 envelope).
    shared.stale.store(true, Ordering::SeqCst);
    let out = cortexd::mcp::call_tool(&shared, "repo_map", &serde_json::json!({})).unwrap();
    assert_eq!(out["reason_code"], serde_json::json!("M1E-6401"));
    assert_eq!(
        held(&shared) - before,
        calls.len() as u64 + 1,
        "one emission per call, refusals included"
    );
    assert_eq!(
        shared.fabric_dropped.load(Ordering::Relaxed),
        0,
        "held for a session is not a drop"
    );

    let ev = cortexd::mcp::injection_event(&shared, 2000, 10);
    let Some(Body::CortexInjection(ci)) = ev.body else {
        panic!("not a CortexInjection: {:?}", ev.body);
    };
    assert_ne!(
        ci.root_hash,
        vec![0u8; 32],
        "root is the live L0 root, never zero"
    );
    assert_eq!(ci.root_hash, shared.snapshot().merkle.root().to_vec());
    assert_eq!(ci.index_clock, shared.index_clock.load(Ordering::SeqCst));
    assert_eq!(ci.channel, InjectionChannel::McpPull as i32);
    assert_eq!((ci.token_budget, ci.tokens_used), (2000, 10));
}
