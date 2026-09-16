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
/// budget), so call_tool books real token usage; with no cache designated
/// (`--memory-file` unset) the answer is the honest empty.
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

/// RFC 3339 UTC for "now", the shape Go's `time.Time` marshals — the planted
/// cache must be fresh against the real clock `call_tool` reads.
fn rfc3339_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil from days (Hinnant), the inverse of the reader's days-from-civil.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.5Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

fn artifact(id: &str, kind: &str, trigger: &str, lcb: f64) -> serde_json::Value {
    serde_json::json!({
        "artifact_id": id, "kind": kind, "trigger": trigger,
        "guidance": format!("guidance for {id}"), "utility_lcb": lcb
    })
}

const ID_PIT: &str = "0190a1b2-c3d4-7000-8000-000000000001";
const ID_FIX: &str = "0190a1b2-c3d4-7000-8000-000000000002";
const ID_INV: &str = "0190a1b2-c3d4-7000-8000-000000000003";
const ID_PREF: &str = "0190a1b2-c3d4-7000-8000-000000000004";

/// A cache with every kind the DB enum has plus the two ways a row can be
/// unservable (unknown kind, non-UUID id) and one that does not match.
fn planted(synced_at: &str) -> String {
    serde_json::json!({
        "synced_at": synced_at,
        "artifacts": [
            artifact(ID_PIT, "pitfall", "TypeError: cannot read property of undefined", 0.2),
            artifact(ID_PREF, "preference", "typeerror", 0.9),
            artifact(ID_FIX, "fix_pattern", "  TypeError   in render ", 0.6),
            artifact("0190a1b2-c3d4-7000-8000-000000000005", "routing_hint", "typeerror", 0.9),
            artifact("not-a-uuid", "pitfall", "typeerror", 0.9),
            artifact(ID_INV, "invariant", "typeerror", 0.4),
            artifact("0190a1b2-c3d4-7000-8000-000000000006", "fix_pattern", "unrelated trigger", 0.9),
            artifact("0190a1b2-c3d4-7000-8000-000000000007", "invariant", "", 0.9),
        ]
    })
    .to_string()
}

fn plant(shared: &cortexd::session::Shared, dir: &Path, body: &str) {
    let file = dir.join("memory/artifacts.json");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, body).unwrap();
    let _ = shared.memory_file.set(file);
}

fn recall(shared: &Arc<cortexd::session::Shared>, args: serde_json::Value) -> serde_json::Value {
    cortexd::mcp::call_tool(shared, "memory_recall", &args).unwrap()
}

fn ids(out: &serde_json::Value) -> Vec<&str> {
    out["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["artifact_id"].as_str().unwrap())
        .collect()
}

/// FR-REMEMBER-004 at the pull surface (08 §6.6): only the edge allowlist
/// (pitfall, fix_pattern, invariant) is served — never `preference` (the
/// routing-hint class), unknown kinds, non-UUID ids or empty triggers — in
/// LCB order, matched by normalized substring on the trigger, and the 08
/// spelling of a kind filters as its m1_040 twin (06 §9.2).
#[test]
fn memory_recall_serves_the_allowlist_in_lcb_order() {
    let (shared, _work, store) = scratch();
    plant(&shared, store.path(), &planted(&rfc3339_now()));
    let out = recall(&shared, serde_json::json!({ "query": "TypeError" }));
    assert_eq!(out["refused"], serde_json::json!(false));
    assert_eq!(
        ids(&out),
        [ID_FIX, ID_INV, ID_PIT],
        "LCB desc, default limit 3"
    );
    let first = &out["artifacts"][0];
    assert_eq!(first["kind"], "fix_pattern");
    assert_eq!(first["body"], format!("guidance for {ID_FIX}"));
    assert_eq!(first["scope"], "tenant");
    assert_eq!(first["utility_lcb"], 0.6);
    // The query may carry the whole error: triggers inside it match, a
    // trigger that merely shares a word ("typeerror in render") does not.
    let out = recall(
        &shared,
        serde_json::json!({ "query": "Uncaught TypeError: cannot read property of undefined at x.js:1", "limit": 10 }),
    );
    assert_eq!(ids(&out), [ID_INV, ID_PIT]);
    assert_eq!(
        ids(&recall(
            &shared,
            serde_json::json!({ "query": "TypeError", "limit": 1 })
        )),
        [ID_FIX]
    );
    assert_eq!(
        ids(&recall(
            &shared,
            serde_json::json!({ "query": "typeerror", "kinds": ["pitfall_remedy"] })
        )),
        [ID_PIT]
    );
    assert_eq!(
        ids(&recall(
            &shared,
            serde_json::json!({ "query": "typeerror", "kinds": ["invariant", "workflow_template"] })
        )),
        [ID_FIX, ID_INV]
    );
    assert!(ids(&recall(
        &shared,
        serde_json::json!({ "query": "typeerror", "kinds": ["preference"] })
    ))
    .is_empty());
    assert!(ids(&recall(
        &shared,
        serde_json::json!({ "query": "no such trigger" })
    ))
    .is_empty());
    assert_eq!(
        shared
            .memory_unreadable
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

/// D-AF: a recall shares the session map budget under the 2 500-token
/// injection ceiling, never the 8k per-call cap; the reply's own estimate is
/// ceil(len/4) and shedding is from the LCB tail.
#[test]
fn memory_recall_is_budgeted_by_the_session_map_budget() {
    let (shared, _work, store) = scratch();
    let rows: Vec<serde_json::Value> = (0..10)
        .map(|i| {
            let mut a = artifact(
                &format!("0190a1b2-c3d4-7000-8000-0000000000{i:02}"),
                "invariant",
                "budget probe",
                1.0 - i as f64 / 100.0,
            );
            a["guidance"] = serde_json::json!("g".repeat(1_000));
            a
        })
        .collect();
    let body = serde_json::json!({ "synced_at": rfc3339_now(), "artifacts": rows }).to_string();
    plant(&shared, store.path(), &body);
    let out = recall(
        &shared,
        serde_json::json!({ "query": "budget probe", "limit": 10, "max_tokens": 8000 }),
    );
    let b = &out["budget"];
    assert_eq!(
        b["max_tokens"], 2000,
        "min(8000 asked, 2000 session map, 2500 D-AF)"
    );
    let used = b["used_tokens"].as_u64().unwrap();
    assert!(used <= 2000 && used > 1_000, "{used}");
    let payload = serde_json::json!({ "artifacts": out["artifacts"] }).to_string();
    assert_eq!(
        used,
        (payload.len() as u64).div_ceil(4),
        "own estimate is ceil(len/4)"
    );
    assert_eq!(b["truncated"], true);
    let served = ids(&out);
    assert!(!served.is_empty() && served.len() < 10, "{served:?}");
    assert!(
        served[0].ends_with("00"),
        "highest LCB survives, the tail is shed"
    );
    // The event attributes what was served, not what was shed.
    let held = shared.pending.lock().unwrap();
    let mi = held
        .iter()
        .find_map(|e| match &e.body {
            Some(m1p_wire::pb::event::Body::MemoryInjection(mi)) => Some(mi.clone()),
            _ => None,
        })
        .expect("a served recall emits a MemoryInjection");
    assert_eq!(mi.artifact_ids.len(), served.len());
}

/// Fail-open, counted: stale (>7 d) is the honest empty; unreadable or
/// malformed is the honest empty AND a count; absent is neither.
#[test]
fn memory_recall_stale_or_malformed_cache_is_empty_and_counted() {
    use std::sync::atomic::Ordering;
    let (shared, _work, store) = scratch();
    let unreadable = || shared.memory_unreadable.load(Ordering::Relaxed);
    let q = serde_json::json!({ "query": "typeerror" });
    plant(&shared, store.path(), &planted("2020-01-01T00:00:00Z"));
    assert!(
        ids(&recall(&shared, q.clone())).is_empty(),
        "stale sync serves nothing"
    );
    assert_eq!(unreadable(), 0, "stale is not malformed");
    let file = shared.memory_file.get().unwrap().clone();
    std::fs::write(&file, b"{not json").unwrap();
    assert!(ids(&recall(&shared, q.clone())).is_empty());
    assert_eq!(unreadable(), 1, "malformed is counted");
    std::fs::write(&file, planted("yesterday")).unwrap();
    assert!(ids(&recall(&shared, q.clone())).is_empty());
    assert_eq!(unreadable(), 2, "unparseable synced_at is malformed");
    std::fs::remove_file(&file).unwrap();
    assert!(ids(&recall(&shared, q.clone())).is_empty());
    assert_eq!(unreadable(), 2, "absent is the ordinary unsynced state");
    std::fs::write(&file, planted(&rfc3339_now())).unwrap();
    assert_eq!(
        ids(&recall(&shared, q.clone())).len(),
        3,
        "a fresh sync serves again"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(ids(&recall(&shared, q)).is_empty());
        assert_eq!(unreadable(), 3, "present but unreadable is counted");
    }
}

/// FR-REMEMBER-005 / FR-CORTEX-005 at the pull surface: a served recall
/// emits its CortexInjection like every call AND exactly one MemoryInjection
/// carrying the ids actually served (post-shedding), McpPull, with the
/// reply's token estimate; an empty recall emits no MemoryInjection. Held in
/// `pending` for the session mark1d will publish, as the sibling test proves.
/// A cortexd the daemon designated no cache for (another workspace) serves
/// nothing from the same file on disk.
#[test]
fn memory_recall_emits_one_memory_injection_per_served_call() {
    use m1p_wire::pb::{event::Body, InjectionChannel};
    let (shared, _work, store) = scratch();
    let pending = || shared.pending.lock().unwrap().clone();
    let before = pending().len();
    let out = recall(&shared, serde_json::json!({ "query": "typeerror" }));
    assert!(ids(&out).is_empty());
    assert_eq!(
        pending().len(),
        before + 1,
        "empty recall: the CortexInjection only"
    );

    plant(&shared, store.path(), &planted(&rfc3339_now()));
    let before = pending().len();
    let out = recall(
        &shared,
        serde_json::json!({ "query": "typeerror", "limit": 2 }),
    );
    assert_eq!(ids(&out), [ID_FIX, ID_INV]);
    let held = pending();
    assert_eq!(
        held.len(),
        before + 2,
        "one CortexInjection + one MemoryInjection"
    );
    let memory: Vec<_> = held[before..]
        .iter()
        .filter_map(|e| match &e.body {
            Some(Body::MemoryInjection(mi)) => Some(mi.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(memory.len(), 1);
    let want: Vec<Vec<u8>> = [ID_FIX, ID_INV]
        .iter()
        .map(|id| uuid::Uuid::parse_str(id).unwrap().into_bytes().to_vec())
        .collect();
    assert_eq!(
        memory[0].artifact_ids, want,
        "exactly the served ids, in served order"
    );
    assert_eq!(memory[0].channel, InjectionChannel::McpPull as i32);
    assert_eq!(
        u64::from(memory[0].tokens_used),
        out["budget"]["used_tokens"].as_u64().unwrap()
    );
    assert_eq!(
        held[before..]
            .iter()
            .filter(|e| matches!(e.body, Some(Body::CortexInjection(_))))
            .count(),
        1,
        "the per-call CortexInjection still lands"
    );

    // A one-artifact recall is a served recall too.
    let before = pending().len();
    let out = recall(
        &shared,
        serde_json::json!({ "query": "typeerror", "limit": 1 }),
    );
    assert_eq!(ids(&out), [ID_FIX]);
    let held = pending();
    assert_eq!(held.len(), before + 2);
    assert!(held[before..].iter().any(|e| matches!(&e.body,
        Some(Body::MemoryInjection(mi)) if mi.artifact_ids == want[..1])));

    // Another workspace's cortexd: same file on disk, no designation, nothing served.
    let (other, _w2, _s2) = scratch();
    let before = other.pending.lock().unwrap().len();
    let out = recall(&other, serde_json::json!({ "query": "typeerror" }));
    assert!(ids(&out).is_empty());
    assert_eq!(
        other.pending.lock().unwrap().len(),
        before + 1,
        "its CortexInjection only"
    );
}
