//! mark1-proxy — API-key-only micro-proxy (04 §3).
//!
//! Startup order is load-bearing and is the reason this file is short: `harden()` is the
//! first statement, before the tokio runtime exists and before any path that could read the
//! guard key is opened (04 §3.3, §11.6, NFR-SECURITY-002). A core written by a process that
//! had already loaded a credential is not recoverable after the fact, so there is no ordering
//! here that "usually" works.

use std::net::SocketAddr;
use std::sync::Arc;

use mark1_proxy::guard::{Guard, Sampling};
use mark1_proxy::router::Proxy;
use mark1_proxy::{fabric, tee, upstream, Mode, ProxyConfig, Upstream};

fn main() -> std::process::ExitCode {
    // FIRST. Not after logging init, not after argv parsing.
    let hardening = match mark1_proxy::harden::harden() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("mark1-proxy: refusing to start: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    tracing::info!(
        target: "mark1_proxy",
        core_limit_zero = hardening.core_limit_zero,
        dumpable = ?hardening.dumpable,
        "hardened"
    );

    let cfg = match config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("mark1-proxy: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("mark1-proxy: runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cfg)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mark1-proxy: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(cfg: ProxyConfig) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    let bound = listener.local_addr()?;

    // Credentials are only loaded here — after hardening, after the listener exists, and
    // never before both.
    let guard = Arc::new(Guard::load(
        &cfg.base,
        Sampling::from_bundle(cfg.forward_sample_rate),
    ));
    let pool = Arc::new(upstream::Pool::new()?);
    let (tee, tee_rx) = tee::channel();
    let (reports_tx, reports_rx) = tokio::sync::mpsc::channel(256);
    spawn_tee_thread(tee_rx, reports_tx)?;
    tokio::spawn(drain_reports(reports_rx));

    let fabric = fabric::Fabric::new(cfg.base.clone());
    let cfg = Arc::new(cfg);
    // The bound port is the sidecar's per-boot secret (§3.4 "a random high port"): written
    // 0600 so the provisioner can point the agent's base URL at it.
    write_port(&cfg.base, bound);

    tracing::info!(target: "mark1_proxy", %bound, "listening");
    let proxy = Arc::new(Proxy::new(cfg, guard, pool, tee, fabric, bound));
    tokio::select! {
        () = Arc::clone(&proxy).serve(listener) => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
}

/// The tee task runs on its own thread with a current-thread runtime, not on the request
/// path's worker pool.
///
/// Forced, and then kept on purpose: `mark1_frames::Dialect::parser()` returns
/// `Box<dyn DialectParser>` with no `+ Send`, so the parser map cannot cross a
/// `tokio::spawn`. The alternative — pressing `mark1-frames` to add the bound — would have
/// put parser state on the same workers that carry client bytes. Here a pathological parser
/// can starve only itself, and the byte budget (D-AH) is what stops it growing.
fn spawn_tee_thread(
    rx: tee::TeeRx,
    reports: tokio::sync::mpsc::Sender<tee::TeeReport>,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("mark1-tee".to_owned())
        .spawn(
            move || match tokio::runtime::Builder::new_current_thread().build() {
                Ok(rt) => rt.block_on(tee::run(rx, reports)),
                Err(e) => tracing::error!(target: "mark1_proxy::tee", %e, "tee runtime"),
            },
        )?;
    Ok(())
}

/// The tee's reports terminate here this phase. Wiring them to `Event{ModelRequest/Usage}`
/// on the fabric is the ledger row, not this one; counting them is what keeps the tee task
/// from being unobservable in the meantime.
async fn drain_reports(mut rx: tokio::sync::mpsc::Receiver<tee::TeeReport>) {
    while let Some(report) = rx.recv().await {
        tracing::debug!(
            target: "mark1_proxy::tee",
            status = report.response.status,
            observations = report.observations.len(),
            degraded = report.degraded.is_some(),
            chunks_dropped = report.chunks_dropped,
            "tee report"
        );
    }
}

fn write_port(base: &std::path::Path, bound: SocketAddr) {
    use std::io::Write;
    let _ = std::fs::create_dir_all(base);
    let path = base.join("proxy.port");
    // The stale file is removed rather than truncated: `mode()` applies only when the file is
    // created, so rewriting a world-readable one in place leaves it world-readable — and this
    // used to be `std::fs::write`, which is 0644 & ~umask, against a call site that calls the
    // port a per-boot secret.
    let _ = std::fs::remove_file(&path);
    let Ok(mut f) = create_private(&path) else {
        return;
    };
    let _ = f.write_all(bound.port().to_string().as_bytes());
}

#[cfg(unix)]
fn create_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(all(test, unix))]
mod port_file_tests {
    use std::os::unix::fs::PermissionsExt;

    /// The call site calls the bound port a per-boot secret; this is the only thing that makes
    /// that true. It also covers the rewrite path, where an inherited 0644 mode survives a
    /// plain truncate.
    #[test]
    fn port_file_is_private_even_when_it_already_existed_world_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("proxy.port");
        std::fs::write(&path, "1").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        super::write_port(tmp.path(), "127.0.0.1:41337".parse().unwrap());

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "proxy.port must not be readable by other users"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "41337");
    }
}

/// argv/env only — there is no config file, and there is nothing here whose value could
/// widen what the proxy will carry. `--upstream` can only ever *narrow* the allow-list.
fn config() -> anyhow::Result<ProxyConfig> {
    let mut mode = Mode::Sidecar;
    let mut port = 0u16;
    let mut upstreams = Vec::new();
    let mut sample = mark1_proxy::guard::DEFAULT_FORWARD_SAMPLE_RATE;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .ok_or_else(|| anyhow::anyhow!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--mode" => {
                mode = match value()?.as_str() {
                    "sidecar" => Mode::Sidecar,
                    "gateway" => Mode::Gateway,
                    other => anyhow::bail!("unknown mode {other}"),
                }
            }
            "--port" => port = value()?.parse()?,
            // `host[:port][=dialect]`. The dialect suffix only selects the tee's parser; an
            // upstream that is not a vendor endpoint otherwise falls back to a guessed
            // grammar and reports confident wrong usage.
            "--upstream" => {
                let spec = value()?;
                let (spec, dialect) = match spec.split_once('=') {
                    Some((s, d)) => (
                        s.to_owned(),
                        Some(
                            mark1_proxy::parse_dialect(d)
                                .ok_or_else(|| anyhow::anyhow!("unknown dialect {d}"))?,
                        ),
                    ),
                    None => (spec, None),
                };
                let (host, tls_port) = match spec.split_once(':') {
                    Some((h, p)) => (h.to_owned(), p.parse()?),
                    None => (spec, 443u16),
                };
                let tls = tls_port == 443 || !is_loopback(&host);
                let up = Upstream::new(host, tls_port, tls)
                    .map_err(|_| anyhow::anyhow!("plaintext upstream must be loopback"))?;
                upstreams.push(match dialect {
                    Some(d) => up.with_dialect(d),
                    None => up,
                });
            }
            "--forward-sample-rate" => sample = value()?.parse()?,
            other => anyhow::bail!("unknown argument {other}"),
        }
    }

    if mode == Mode::Gateway {
        // Declared in §3.4, built in Phase 5. Refusing is the honest arm: the alternative is
        // binding a plaintext loopback listener while the operator believes they asked for
        // an mTLS listener on customer infra.
        anyhow::bail!("gateway mode is declared (04 §3.4) and not implemented; Phase 5");
    }
    if upstreams.is_empty() {
        upstreams.push(
            Upstream::new("api.anthropic.com", 443, true)
                .map_err(|_| anyhow::anyhow!("default upstream"))?,
        );
    }
    let base = mark1_proxy::home()
        .ok_or_else(|| anyhow::anyhow!("no HOME/USERPROFILE"))?
        .join(".omium/mark1");

    Ok(ProxyConfig {
        mode,
        bind: SocketAddr::from(([127, 0, 0, 1], port)),
        upstreams,
        forward_sample_rate: sample,
        base,
    })
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "[::1]" | "localhost")
}
