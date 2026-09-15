//! MCP server over the loopback rules (08 §4.5 + §6).
//!
//! Transport: JSON-RPC 2.0 over `POST /mcp` on `127.0.0.1:<random port>`.
//! The three walls run in 08 §4.5 order before any body parse:
//! 1. `Host` must be the exact bound literal — 403 M1E-4004
//! 2. ANY `Origin` header present — 403 M1E-4005
//! 3. `Authorization: Bearer <per-boot token>` required — 401 M1E-1002
//!
//! Tool-level failures are NOT errors: they are the 08 §6 refusal envelope,
//! a schema-conforming success — refusal beats fabrication.

use std::path::{Component, Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};

use crate::l0_merkle::IgnoreSet;
use crate::l2_graph::PPR_WALL_BUDGET;
use crate::map;
use crate::session::{Shared, MAX_CALL_TOKENS, MIN_CALL_TOKENS, TURN_BUDGET_TOKENS};
use crate::{fabric, l3_scip};

/// ponytail: turn-boundary heuristic — 08 §6's "per session turn" cap needs a
/// turn signal cortexd does not receive at Phase 2 (no mark1d hook feed); a
/// ≥30 s gap between calls resets the counter. Real turn edges arrive with
/// the mark1d session integration.
const TURN_GAP_MS: u64 = 30_000;

pub struct McpState {
    pub shared: Arc<Shared>,
    /// The exact bound literal `127.0.0.1:<port>` (08 §4.5 Host rule).
    pub expected_host: String,
}

/// Why a request was refused at the wall. Ordered checks — Host before
/// Origin before bearer, matching the 08 §4.5 listing.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthDenial {
    /// `Host` is not the bound literal (DNS-rebinding wall) — 403 M1E-4004.
    BadHost,
    /// An `Origin` header exists (browser wall) — 403 M1E-4005.
    OriginPresent,
    /// Bearer token missing or wrong — 401 M1E-1002.
    BadToken,
}

impl AuthDenial {
    pub fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            AuthDenial::BadHost => (StatusCode::FORBIDDEN, "M1E-4004"),
            AuthDenial::OriginPresent => (StatusCode::FORBIDDEN, "M1E-4005"),
            AuthDenial::BadToken => (StatusCode::UNAUTHORIZED, "M1E-1002"),
        }
    }
}

/// The 08 §4.5 wall, pure over headers so the negative tests need no socket.
pub fn check_auth(headers: &HeaderMap, expected_host: &str, token: &str) -> Result<(), AuthDenial> {
    // WHY literal Host (08 §4.5): DNS rebinding sends a browser to
    // attacker.example resolving to 127.0.0.1; the Host header then carries
    // the attacker's name. Literal matching makes rebinding structurally inert.
    let host_ok = headers
        .get(header::HOST)
        .is_some_and(|h| h.as_bytes() == expected_host.as_bytes());
    if !host_ok {
        return Err(AuthDenial::BadHost);
    }
    // A legitimate caller is a local process, never a browser page (08 §4.5).
    if headers.get(header::ORIGIN).is_some() {
        return Err(AuthDenial::OriginPresent);
    }
    let bearer_ok = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        // Constant-time compare — no timing oracle on the loopback.
        .is_some_and(|t| constant_time_eq::constant_time_eq(t.as_bytes(), token.as_bytes()));
    if !bearer_ok {
        return Err(AuthDenial::BadToken);
    }
    Ok(())
}

pub fn router(state: Arc<McpState>) -> Router {
    Router::new().route("/mcp", post(handle)).with_state(state)
}

/// Bind `127.0.0.1:0`, write the discovery file (0600, 08 §4.5 shape:
/// port + token), and return the listener plus ready state.
pub async fn bind(
    shared: Arc<Shared>,
) -> std::io::Result<(tokio::net::TcpListener, Arc<McpState>)> {
    // Never 0.0.0.0, never :: (08 §4.5).
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let state = Arc::new(McpState {
        expected_host: format!("127.0.0.1:{port}"),
        shared: shared.clone(),
    });
    write_discovery(&shared.store.join("mcp.json"), port, &shared.token)?;
    Ok((listener, state))
}

/// Discovery file: 0600 like mark1d's loopback.json — the token is the wall.
/// mode(0o600) only applies on CREATION, so a pre-existing file with any
/// group/world bit is REFUSED, never chmod'd — the fabric listener's posture
/// (go/mark1d/internal/fabric/listener.go): the threat model is other users.
fn write_discovery(path: &Path, port: u16, token: &str) -> std::io::Result<()> {
    let body = json!({ "port": port, "token": token }).to_string();
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        // Lstat: a planted symlink would redirect the token write — refuse it
        // too (a symlink's own mode carries group/world bits).
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(std::io::Error::other(format!(
                    "refusing existing {} with mode {:o} — it holds the loopback bearer token; 0600 required",
                    path.display(),
                    mode & 0o777
                )));
            }
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(body.as_bytes())
    }
    #[cfg(not(unix))]
    std::fs::write(path, body)
}

async fn handle(State(st): State<Arc<McpState>>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(denial) = check_auth(&headers, &st.expected_host, &st.shared.token) {
        let (status, code) = denial.status_and_code();
        return json_response(status, &json!({ "error": { "code": code } }));
    }
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &rpc_error(Value::Null, -32700, "parse error"),
            )
        }
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    // Notifications carry no id and get no body (MCP over HTTP: 202).
    if id.is_null() && method.starts_with("notifications/") {
        return StatusCode::ACCEPTED.into_response();
    }
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let reply = match method {
        "initialize" => rpc_ok(
            id,
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mark1-cortex", "version": env!("CARGO_PKG_VERSION") }
            }),
        ),
        "ping" => rpc_ok(id, json!({})),
        "tools/list" => rpc_ok(id, json!({ "tools": tool_list() })),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match call_tool(&st.shared, name, &args) {
                Ok(result) => {
                    // MCP result: one text content item; the JSON inside is the
                    // 08 §6 wire truth (refusals included — they are successes).
                    let text = serde_json::to_string(&result).unwrap_or_default();
                    rpc_ok(
                        id,
                        json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
                    )
                }
                Err(msg) => rpc_error(id, -32602, &msg),
            }
        }
        _ => rpc_error(id, -32601, "method not found"),
    };
    json_response(StatusCode::OK, &reply)
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn rpc_ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// 08 §6 refusal envelope — a valid SUCCESS result, never an MCP error.
fn refusal(code: &str, reason: &str, retry_after_ms: Option<u64>) -> Value {
    let mut v = json!({ "refused": true, "reason_code": code, "reason": reason });
    if let Some(ms) = retry_after_ms {
        v["retry_after_ms"] = json!(ms);
    }
    v
}

/// Tool dispatch. `Err` is a JSON-RPC invalid-params fault (schema violation);
/// every in-domain failure is a refusal envelope inside `Ok`.
pub fn call_tool(shared: &Arc<Shared>, name: &str, args: &Value) -> Result<Value, String> {
    // Index-state gates common to every tool (08 §6 refusal reasons).
    if shared.stale.load(Ordering::SeqCst) {
        return Ok(emit_and(
            shared,
            0,
            0,
            refusal(
                "M1E-6401",
                "index is behind the working tree; re-run after it settles",
                Some(1_500),
            ),
        ));
    }
    if shared.broken.load(Ordering::SeqCst) {
        return Ok(emit_and(
            shared,
            0,
            0,
            refusal(
                "M1E-6404",
                "graph shard corrupt; reindex in progress",
                Some(3_000),
            ),
        ));
    }
    let effective = effective_budget(shared, args);
    let out = match name {
        "repo_map" => repo_map(shared, args, effective),
        "find_definition" => find_definition(shared, args, effective),
        "find_references" => find_references(shared, args, effective),
        "deps" => deps(shared, args, effective),
        "ranked_files" => ranked_files(shared, args, effective),
        "memory_recall" => memory_recall(shared, args, effective),
        other => return Err(format!("unknown tool: {other}")),
    }?;
    let used = out
        .get("budget")
        .and_then(|b| b.get("used_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as u32;
    Ok(emit_and(shared, effective, used, out))
}

/// Every call emits a `CortexInjection`-family ledger event carrying
/// `root_hash` + `index_clock` (08 §6) — refusals included, with used = 0.
fn emit_and(shared: &Arc<Shared>, budget: u32, used: u32, out: Value) -> Value {
    shared.turn_used.fetch_add(used, Ordering::Relaxed);
    fabric::spawn_push(shared, injection_event(shared, budget, used));
    out
}

/// The per-call event (04 §6.4): the live L0 root and index clock, stamped
/// `McpPull`. Split from `emit_and` so a test can hold what the push drops.
pub fn injection_event(shared: &Shared, budget: u32, used: u32) -> m1p_wire::pb::Event {
    let (root, clock) = {
        let idx = shared.snapshot();
        (idx.merkle.root(), shared.index_clock.load(Ordering::SeqCst))
    };
    fabric::cortex_injection_event(
        root,
        clock,
        budget,
        used,
        m1p_wire::pb::InjectionChannel::McpPull,
    )
}

/// Per-call clamp (08 §6: 256..8000, default 2000) intersected with what is
/// left of the 8k session-turn budget.
fn effective_budget(shared: &Arc<Shared>, args: &Value) -> u32 {
    let requested = args
        .get("max_tokens")
        .and_then(Value::as_u64)
        .map(|v| (v as u32).clamp(MIN_CALL_TOKENS, MAX_CALL_TOKENS))
        .unwrap_or(shared.default_budget);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let last = shared.last_call_ms.swap(now_ms, Ordering::Relaxed);
    if now_ms.saturating_sub(last) >= TURN_GAP_MS {
        shared.turn_used.store(0, Ordering::Relaxed);
    }
    let remaining = TURN_BUDGET_TOKENS.saturating_sub(shared.turn_used.load(Ordering::Relaxed));
    // Exhausted turn ⇒ the caller gets a truncated (possibly empty) answer,
    // never a fabricated full one and never a schema break: the envelope only
    // names index-state refusal codes, so size pressure stays a truncation.
    requested.min(remaining)
}

fn preamble(shared: &Arc<Shared>, max_tokens: u32, used: u32, truncated: bool) -> Value {
    let idx = shared.snapshot();
    json!({
        "refused": false,
        "root_hash": format!("blake3:{}", idx.merkle.root_hex()),
        "index_clock": shared.index_clock.load(Ordering::SeqCst),
        "budget": { "max_tokens": max_tokens, "used_tokens": used, "truncated": truncated }
    })
}

/// Canonicalize a `path` argument inside the workspace root (08 §6 session
/// scoping): traversal, absolute paths outside the root, and `.mark1ignore`d
/// paths refuse M1E-6402 — never partially answered.
fn scope_path(shared: &Shared, raw: &str) -> Result<String, Value> {
    let denied = || refusal("M1E-6402", "path outside the session workspace", None);
    let joined = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        shared.root.join(raw)
    };
    // Symlink-resolving canonicalization when the file exists; lexical
    // normalization (no `..` escape) when it does not — both must land under
    // the canonicalized root.
    let resolved = match joined.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            let mut out = PathBuf::new();
            for c in joined.components() {
                match c {
                    Component::ParentDir => {
                        if !out.pop() {
                            return Err(denied());
                        }
                    }
                    Component::CurDir => {}
                    other => out.push(other),
                }
            }
            out
        }
    };
    let rel = resolved
        .strip_prefix(&shared.root)
        .map_err(|_| denied())?
        .to_str()
        .ok_or_else(denied)?
        .replace('\\', "/");
    // An ignore file that exists but cannot be read must refuse, not silently
    // ignore nothing: falling back to an empty rule set would serve exactly
    // the paths the user wrote rules to exclude (fail-closed, 08 §6 taxonomy
    // row M1E-6402). Absent files are a legitimate empty set inside load().
    let ignore = IgnoreSet::load(&shared.root)
        .map_err(|_| refusal("M1E-6402", "ignore rules unreadable; refusing", None))?;
    if rel.is_empty() || ignore.matches(&rel, false) {
        return Err(denied());
    }
    Ok(rel)
}

/// Serialize-and-shed: pop records off the named arrays (in order — first
/// array drains before the second) until the rendering fits the budget.
/// Ranked truncation, never mid-record cuts (08 §6).
fn fit_arrays(payload: &mut Value, arrays: &[&str], budget: u32) -> (u32, bool) {
    let mut truncated = false;
    loop {
        let used = map::estimate_tokens(&payload.to_string());
        if used <= budget {
            return (used, truncated);
        }
        let popped = arrays.iter().any(|field| {
            payload
                .get_mut(*field)
                .and_then(Value::as_array_mut)
                .is_some_and(|arr| arr.pop().is_some())
        });
        if !popped {
            return (used, truncated); // nothing left to shed; envelope overhead only
        }
        truncated = true;
    }
}

fn merge(mut pre: Value, payload: Value) -> Value {
    if let (Some(dst), Some(src)) = (pre.as_object_mut(), payload.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    pre
}

// --- 6.1 repo_map ----------------------------------------------------------

fn repo_map(shared: &Arc<Shared>, args: &Value, budget: u32) -> Result<Value, String> {
    let focus: Vec<String> = args
        .get("focus")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let idx = shared.snapshot();
    // Focus entries are file paths or symbol names (08 §6.1): resolve symbols
    // to their definition files; unresolvable entries are ignored.
    let mut seeds: Vec<String> = Vec::new();
    for f in &focus {
        if idx.graph.node_of.contains_key(f) {
            seeds.push(f.clone());
        } else if let Some(sites) = idx.graph.defs.get(f) {
            seeds.extend(sites.iter().map(|s| s.path.clone()));
        }
    }
    // ENG-09: a query-time PPR runs under the wall budget; exhaustion with no
    // global fallback is a time-budget refusal, not a silent degrade.
    let seed_nodes: Vec<_> = seeds
        .iter()
        .filter_map(|p| idx.graph.node_of.get(p).copied())
        .collect();
    if let Err(e) = idx.graph.ranks_for(&seed_nodes, PPR_WALL_BUDGET, 0) {
        return Ok(refusal(
            "M1E-6401",
            "ranking budget exhausted",
            Some(e.retry_after_ms),
        ));
    }
    let render = map::assemble(&idx, &seeds, budget);
    drop(idx);
    let pre = preamble(shared, budget, render.tokens_used, render.truncated);
    Ok(merge(
        pre,
        json!({ "map": render.text, "files_ranked": render.files_ranked }),
    ))
}

// --- 6.2 find_definition ---------------------------------------------------

fn find_definition(shared: &Arc<Shared>, args: &Value, budget: u32) -> Result<Value, String> {
    let symbol = args
        .get("symbol")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("symbol: required, minLength 1")?;
    let hint_rel = match args.get("hint_path").and_then(Value::as_str) {
        Some(h) => match scope_path(shared, h) {
            Ok(rel) => Some(rel),
            Err(refusal) => return Ok(refusal),
        },
        None => None,
    };
    let idx = shared.snapshot();
    let defs: Vec<Value> = idx
        .graph
        .defs
        .get(symbol)
        .map(|sites| {
            sites
                .iter()
                .filter(|s| hint_rel.as_deref().is_none_or(|h| s.path == h))
                .map(|s| {
                    json!({
                        "path": s.path, "line": s.line, "kind": s.kind,
                        "signature": s.signature, "confidence": l3_scip::CONFIDENCE
                    })
                })
                .collect()
        })
        // Empty means "indexed and absent" (08 §6.2) — an honest empty.
        .unwrap_or_default();
    drop(idx);
    let mut payload = json!({ "definitions": defs });
    let (used, truncated) = fit_arrays(&mut payload, &["definitions"], budget);
    Ok(merge(preamble(shared, budget, used, truncated), payload))
}

// --- 6.3 find_references ---------------------------------------------------

fn find_references(shared: &Arc<Shared>, args: &Value, budget: u32) -> Result<Value, String> {
    let symbol = args
        .get("symbol")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("symbol: required, minLength 1")?;
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map(|v| (v as usize).clamp(1, 200))
        .unwrap_or(50);
    let idx = shared.snapshot();
    let all = idx.graph.refs.get(symbol).cloned().unwrap_or_default();
    let total = all.len();
    let refs: Vec<Value> = all
        .iter()
        .take(limit)
        .map(|r| {
            // `context` is the referencing line, verbatim (08 §6.3) — read
            // best-effort from the worktree; a racing edit just drops it.
            let context = std::fs::read_to_string(shared.root.join(&r.path))
                .ok()
                .and_then(|src| {
                    src.lines()
                        .nth(r.line.saturating_sub(1) as usize)
                        .map(str::to_string)
                });
            let mut v = json!({
                "path": r.path, "line": r.line, "confidence": l3_scip::CONFIDENCE
            });
            if let Some(ctx) = context {
                v["context"] = json!(ctx);
            }
            v
        })
        .collect();
    drop(idx);
    let mut payload = json!({ "references": refs, "total": total });
    let (used, truncated) = fit_arrays(&mut payload, &["references"], budget);
    Ok(merge(preamble(shared, budget, used, truncated), payload))
}

// --- 6.4 deps ---------------------------------------------------------------

fn deps(shared: &Arc<Shared>, args: &Value, budget: u32) -> Result<Value, String> {
    use petgraph::Direction;
    let direction = args
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("both");
    let depth = args
        .get("depth")
        .and_then(Value::as_u64)
        .map(|v| (v as usize).clamp(1, 3))
        .unwrap_or(1);
    let path_arg = args.get("path").and_then(Value::as_str);
    let symbol_arg = args.get("symbol").and_then(Value::as_str);
    if path_arg.is_none() && symbol_arg.is_none() {
        return Err("deps: one of path|symbol is required".into());
    }
    let idx = shared.snapshot();
    // Start set: the file node, or every definition file of the symbol.
    let mut start = Vec::new();
    if let Some(p) = path_arg {
        let rel = match scope_path(shared, p) {
            Ok(rel) => rel,
            Err(refusal) => return Ok(refusal),
        };
        match idx.graph.node_of.get(&rel) {
            Some(n) => start.push(*n),
            // Indexed-but-untagged (no grammar) is an L1 miss (08 §6 refusal
            // taxonomy row M1E-6403), not an empty graph answer.
            None => {
                return Ok(refusal(
                    "M1E-6403",
                    "file has no L1 tags (grammar unavailable or not indexed)",
                    None,
                ))
            }
        }
    }
    if let Some(s) = symbol_arg {
        if let Some(sites) = idx.graph.defs.get(s) {
            start.extend(
                sites
                    .iter()
                    .filter_map(|d| idx.graph.node_of.get(&d.path))
                    .copied(),
            );
        }
    }
    // BFS out to `depth`, collecting the touched edge set.
    let mut frontier = start.clone();
    let mut seen: std::collections::BTreeSet<usize> = start.iter().map(|n| n.index()).collect();
    let mut edges: Vec<Value> = Vec::new();
    for _ in 0..depth {
        let mut next = Vec::new();
        for &node in &frontier {
            let dirs: &[Direction] = match direction {
                "out" => &[Direction::Outgoing],
                "in" => &[Direction::Incoming],
                _ => &[Direction::Outgoing, Direction::Incoming],
            };
            for dir in dirs {
                for edge in idx.graph.graph.edges_directed(node, *dir) {
                    use petgraph::visit::EdgeRef;
                    let (from, to) = (edge.source(), edge.target());
                    edges.push(json!({
                        "from": idx.graph.graph[from], "to": idx.graph.graph[to],
                        "kind": edge.weight().as_str()
                    }));
                    let far = if *dir == Direction::Outgoing {
                        to
                    } else {
                        from
                    };
                    if seen.insert(far.index()) {
                        next.push(far);
                    }
                }
            }
        }
        frontier = next;
    }
    edges.sort_by_key(|e| e.to_string());
    edges.dedup();
    let nodes: Vec<Value> = seen
        .iter()
        .map(|&i| {
            let path = &idx.graph.graph[petgraph::graph::NodeIndex::new(i)];
            json!({ "id": path, "path": path })
        })
        .collect();
    drop(idx);
    let mut payload = json!({ "nodes": nodes, "edges": edges });
    // Edges shed before nodes: a node list without some edges is still a
    // truthful (if coarser) neighborhood; edges without their nodes are not.
    let (used, truncated) = fit_arrays(&mut payload, &["edges", "nodes"], budget);
    Ok(merge(preamble(shared, budget, used, truncated), payload))
}

// --- 6.5 ranked_files --------------------------------------------------------

fn ranked_files(shared: &Arc<Shared>, args: &Value, budget: u32) -> Result<Value, String> {
    let query = args
        .get("query")
        .and_then(Value::as_str)
        .filter(|q| q.len() >= 3)
        .ok_or("query: required, minLength 3")?;
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map(|v| (v as usize).clamp(1, 30))
        .unwrap_or(10);
    let idx = shared.snapshot();
    // Graph-guided, not embeddings (08 §6.5 load-bearing note): tokenize the
    // task text, seed PPR at symbol-name and path matches + recent edits.
    let tokens: Vec<String> = query
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|t| t.len() >= 3)
        .map(str::to_lowercase)
        .collect();
    let mut seeds = Vec::new();
    let mut why: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for tok in &tokens {
        for (name, sites) in &idx.graph.defs {
            if name.to_lowercase() == *tok {
                for s in sites {
                    if let Some(n) = idx.graph.node_of.get(&s.path) {
                        seeds.push(*n);
                        why.entry(s.path.clone())
                            .or_default()
                            .push(format!("defines `{name}`"));
                    }
                }
            }
        }
        for (path, n) in &idx.graph.node_of {
            if path.to_lowercase().contains(tok) {
                seeds.push(*n);
                why.entry(path.clone())
                    .or_default()
                    .push(format!("path matches `{tok}`"));
            }
        }
    }
    for recent in &idx.recent_edits {
        if let Some(n) = idx.graph.node_of.get(recent) {
            seeds.push(*n);
            why.entry(recent.clone())
                .or_default()
                .push("recent-edit adjacency".to_string());
        }
    }
    seeds.sort_unstable();
    seeds.dedup();
    let ranks = match idx.graph.ranks_for(&seeds, PPR_WALL_BUDGET, 0) {
        Ok(r) => r,
        Err(e) => {
            return Ok(refusal(
                "M1E-6401",
                "ranking budget exhausted",
                Some(e.retry_after_ms),
            ))
        }
    };
    let max = ranks
        .scores
        .iter()
        .cloned()
        .fold(0f64, f64::max)
        .max(f64::MIN_POSITIVE);
    let mut scored: Vec<(String, f64)> = idx
        .graph
        .graph
        .node_indices()
        .map(|n| {
            (
                idx.graph.graph[n].clone(),
                ranks.scores.get(n.index()).copied().unwrap_or(0.0) / max,
            )
        })
        .collect();
    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });
    let files: Vec<Value> = scored
        .into_iter()
        .take(limit)
        .map(|(path, score)| {
            let evidence = why
                .get(&path)
                .map(|w| w.join("; "))
                .unwrap_or_else(|| "graph proximity to matched seeds".to_string());
            json!({ "path": path, "score": score, "why": evidence })
        })
        .collect();
    drop(idx);
    let mut payload = json!({ "files": files });
    let (used, truncated) = fit_arrays(&mut payload, &["files"], budget);
    Ok(merge(preamble(shared, budget, used, truncated), payload))
}

// --- 6.6 memory_recall -------------------------------------------------------

fn memory_recall(shared: &Arc<Shared>, args: &Value, budget: u32) -> Result<Value, String> {
    let query = args
        .get("query")
        .and_then(Value::as_str)
        .filter(|q| q.len() >= 3)
        .ok_or("query: required, minLength 3")?;
    let kinds: Vec<String> = args
        .get("kinds")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map(|v| (v as u32).clamp(1, 10))
        .unwrap_or(3);
    // Empty/unsynced cache is an honest empty, not a refusal (08 §6.6) — but
    // still under the common contract: preamble + budget accounting on every
    // non-refused result, hard-capped like the siblings, so call_tool books
    // real usage the day real artifacts land.
    let artifacts = crate::session::recall_artifacts(query, &kinds, limit);
    let mut payload = json!({ "artifacts": artifacts });
    let (used, truncated) = fit_arrays(&mut payload, &["artifacts"], budget);
    Ok(merge(preamble(shared, budget, used, truncated), payload))
}

// --- tools/list --------------------------------------------------------------

/// Schemas verbatim from 08 §6 — the wire truth in any implementation language.
fn tool_list() -> Vec<Value> {
    vec![
        json!({
            "name": "repo_map",
            "description": "Ranked, budgeted repository map computed from the local cortexd L2 graph (personalized PageRank); serves no network call.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "focus": { "type": "array", "items": { "type": "string" },
                               "description": "Optional file paths or symbol names to personalize PageRank toward" },
                    "max_tokens": { "type": "integer", "minimum": 256, "maximum": 8000, "default": 2000 }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "find_definition",
            "description": "Symbol definition lookup from the local L1/L2 index; empty result means indexed-and-absent.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "symbol": { "type": "string", "minLength": 1 },
                    "hint_path": { "type": "string", "description": "Optional path to disambiguate collisions" }
                },
                "required": ["symbol"], "additionalProperties": false
            }
        }),
        json!({
            "name": "find_references",
            "description": "Symbol reference lookup (inverse of find_definition) from the local index.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "symbol": { "type": "string", "minLength": 1 },
                    "defined_at": { "type": "object",
                        "properties": { "path": { "type": "string" }, "line": { "type": "integer" } },
                        "description": "Optional anchor from a prior find_definition result" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50 }
                },
                "required": ["symbol"], "additionalProperties": false
            }
        }),
        json!({
            "name": "deps",
            "description": "Dependency neighborhood of a file or symbol from the local L2 graph.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "symbol": { "type": "string" },
                    "direction": { "type": "string", "enum": ["out", "in", "both"], "default": "both" },
                    "depth": { "type": "integer", "minimum": 1, "maximum": 3, "default": 1 }
                },
                "oneOf": [ { "required": ["path"] }, { "required": ["symbol"] } ],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "ranked_files",
            "description": "Graph-guided ranked-file retrieval for a task description (PPR over L2, seeded by tag matches and recent edits — not embeddings).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "minLength": 3,
                               "description": "Natural-language task description or error text" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 30, "default": 10 }
                },
                "required": ["query"], "additionalProperties": false
            }
        }),
        json!({
            "name": "memory_recall",
            "description": "Typed experience artifacts from the locally-synced tenant cache; empty cache returns an honest empty, never a refusal.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "minLength": 3 },
                    "kinds": { "type": "array",
                        "items": { "type": "string", "enum": ["workflow_template", "pitfall_remedy", "invariant"] } },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 10, "default": 3 }
                },
                "required": ["query"], "additionalProperties": false
            }
        }),
    ]
}
