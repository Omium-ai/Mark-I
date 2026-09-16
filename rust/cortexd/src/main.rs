//! cortexd — workspace root bind; session/loopback token setup (04 §6 tree).
//!
//! Thin bind per 13 §1: parse flags, bootstrap the shared index state, start
//! the watcher + the single writer thread, then serve MCP on the loopback.
//! Crash isolation (04 §6.7): a cortexd death costs ranked maps, nothing else
//! — mark1d supervises and restarts; capture continues without us.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

#[derive(Parser)]
#[command(name = "cortexd", version)]
struct Args {
    /// Workspace root to index (the enrolled root).
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// Store directory; default ~/.omium/mark1/cortex/<workspace_id>/ (04 §6.2).
    #[arg(long)]
    store: Option<PathBuf>,
    /// Session-start map token budget (04 §6.4: default 2k, ceiling 8k).
    /// mark1d passes the bundle's `cortex.map_budget_tokens.max` here.
    #[arg(long, default_value_t = cortexd::session::DEFAULT_BUDGET_TOKENS)]
    budget: u32,
    /// Where mark1d publishes this workspace's live agent session
    /// (`<state>/run/sessions/<workspace-id>.json`, go/mark1d/internal/cortex).
    /// Every fabric push Hellos with the session read from here (D-AT); with
    /// none published, pushes are held until one is. Unset (hand-run) ⇒ held
    /// forever, which is the honest state for a cortexd nobody supervises.
    #[arg(long)]
    session_file: Option<PathBuf>,
    /// The tenant artifact cache mark1d syncs (`<state>/memory/artifacts.json`,
    /// go/mark1d/internal/memory). Unset ⇒ `memory_recall` is the honest empty.
    #[arg(long)]
    memory_file: Option<PathBuf>,
    /// The applied bundle's cortex `learned_ranker` as mark1d publishes it
    /// (`<state>/run/ranker.json`, go/mark1d/internal/cortex). Loaded at boot
    /// and on change; absent, malformed or out of range ⇒ PPR order.
    #[arg(long)]
    ranker_file: Option<PathBuf>,
}

/// 07 names workspace_id = HMAC_tenant(root path); no tenant key exists on an
/// unenrolled Phase-2 daemon, so the store key is a plain BLAKE3 of the
/// canonical root — same collision behavior, no tenant claim implied.
fn default_store(root: &std::path::Path) -> PathBuf {
    let id = blake3::hash(root.to_string_lossy().as_bytes()).to_hex();
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".omium/mark1/cortex").join(&id.as_str()[..16])
}

fn main() -> anyhow::Result<()> {
    // FIRST: before the runtime, before argv, before the store or the loopback bearer exist
    // (04 §11.6, NFR-SECURITY-002). A cortexd core is the workspace index plus the bearer;
    // `harden_order::cortexd_harden_precedes_runtime` pins this ordering. A plain `main`
    // rather than `#[tokio::main]`: the macro builds the runtime before the body's first
    // statement.
    mark1_harden::apply()?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve())
}

async fn serve() -> anyhow::Result<()> {
    // stdout belongs to hook replies estate-wide (root lints); logs to stderr.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let root = args.root.canonicalize()?;
    let store = args.store.unwrap_or_else(|| default_store(&root));
    // Store creation lives in bootstrap: 0700 + hard refusal of an existing
    // dir with group/world bits — a create_dir_all here would pre-create it
    // with umask modes and trip that refusal on first boot.
    let (shared, cas) = cortexd::bootstrap(root, store, args.budget)?;
    if let Some(p) = args.session_file {
        // First and only set; the OnceLock cannot already hold a value here.
        let _ = shared.session_file.set(p);
    }
    if let Some(p) = args.memory_file {
        let _ = shared.memory_file.set(p);
    }
    if let Some(p) = args.ranker_file {
        let _ = shared.ranker_file.set(p);
        tokio::spawn(cortexd::session::ranker_watch(
            Arc::clone(&shared),
            std::time::Duration::from_secs(5),
        ));
    }
    // Held pushes (no session yet) are delivered by this loop the moment
    // mark1d publishes one, rather than at the next settle or tool call.
    tokio::spawn(cortexd::fabric::flush_loop(Arc::clone(&shared)));

    // Watcher feeds the single writer task (04 §6.3) over a std channel; the
    // writer runs on its own OS thread at idle priority. `handle.enter()`
    // gives that thread the runtime context fabric pushes spawn onto.
    let (tx, rx) = std::sync::mpsc::channel();
    let watcher = cortexd::l0_merkle::start_watcher(&shared.root, tx)?;
    let handle = tokio::runtime::Handle::current();
    let writer_shared = Arc::clone(&shared);
    std::thread::spawn(move || {
        let _guard = handle.enter();
        cortexd::run_indexer(writer_shared, cas, rx);
    });

    let (listener, state) = cortexd::mcp::bind(Arc::clone(&shared)).await?;
    tracing::info!(
        host = %state.expected_host,
        root = %shared.root.display(),
        "cortexd serving MCP on the loopback"
    );
    axum::serve(listener, cortexd::mcp::router(state))
        .with_graceful_shutdown(async {
            // SIGINT only; mark1d stops us with SIGTERM→SIGKILL and every
            // durable artifact (CAS, shards, l0.merkle) is crash-safe by design.
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    drop(watcher); // keep the watcher alive for the daemon's whole life
    Ok(())
}

/// NFR-SECURITY-002's ordering clause, pinned rather than inspected: the harden call precedes
/// the runtime construction in this file's text, and no `#[tokio::main]` can build one earlier.
/// Comment lines are dropped first so prose mentioning either cannot satisfy it.
#[cfg(test)]
mod harden_order {
    #[test]
    fn cortexd_harden_precedes_runtime() {
        let src: String = include_str!("main.rs")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        // Only the text above this module: its own string literals are not evidence.
        let src = &src[..src.find("mod harden_order").unwrap()];
        let harden = src
            .find("mark1_harden::apply()")
            .expect("main calls mark1_harden::apply()");
        let runtime = src
            .find("tokio::runtime::Builder")
            .expect("main builds the runtime");
        assert!(harden < runtime, "harden at {harden}, runtime at {runtime}");
        assert!(
            !src.contains("#[tokio::main]"),
            "a #[tokio::main] runtime precedes main's first statement"
        );
    }
}
