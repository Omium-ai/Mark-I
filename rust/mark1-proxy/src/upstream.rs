//! Upstream connections — 04 §3.4.
//!
//! **Pools are keyed `(upstream, credential-identity)`; no multiplexing, no identity
//! masking.** All three are structural here rather than enforced by review:
//!
//!   * the key's credential half is `ForwardTicket::cred_identity()`, and a `ForwardTicket`
//!     can only be minted by `guard::provenance` past all six steps of §3.1 — so
//!     [`Pool::connect`] has no callable form for an unverified credential;
//!   * ALPN offers `http/1.1` only and the client stack is `hyper::client::conn::http1`, so
//!     "no multiplexing, not even h2 streams" is a property of what was negotiated, not a
//!     runtime check that could be skipped;
//!   * nothing in this module rewrites, strips or substitutes the credential header, so the
//!     upstream always sees the true caller identity.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;

use crate::guard::ForwardTicket;
use crate::Upstream;

/// Bounded so a burst of distinct credentials cannot pin unbounded connection state against
/// the ≤35 MB RSS budget. Eviction is drop-the-newest: the pooled ones are warm.
const MAX_IDLE_PER_KEY: usize = 8;
// 0 would disable pooling and blow the latency budget; unbounded would blow the RSS one.
const _: () = assert!(MAX_IDLE_PER_KEY > 0 && MAX_IDLE_PER_KEY <= 32);

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Key {
    pub authority: String,
    /// HMAC fingerprint of the credential, never the credential.
    pub cred_identity: [u8; 32],
}

#[derive(Default)]
struct Idle {
    /// `Mutex<..>` and never held across an await — the pool is a lookup, not a lock the hot
    /// path can be parked on.
    conns: Mutex<HashMap<Key, Vec<SendRequest<Incoming>>>>,
}

pub struct Pool {
    tls: tokio_rustls::TlsConnector,
    idle: Arc<Idle>,
}

/// A connection checked out of the pool. Returned by [`Checkout::release`] once the response
/// body has been fully read — never before, because an http1 connection with an unread body
/// is not reusable, and never on a mid-stream abort, because it is not safe to.
pub struct Checkout {
    key: Key,
    sender: SendRequest<Incoming>,
    idle: Arc<Idle>,
}

impl Checkout {
    pub fn release(self) {
        let Ok(mut map) = self.idle.conns.lock() else {
            return;
        };
        let slot = map.entry(self.key).or_default();
        if slot.len() < MAX_IDLE_PER_KEY {
            slot.push(self.sender);
        }
    }
}

impl Pool {
    pub fn new() -> Result<Self, rustls::Error> {
        let config = client_config()?;
        Ok(Pool {
            tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
            idle: Arc::default(),
        })
    }

    /// Take a connection for `(upstream, ticket.cred_identity())`, opening one if none is
    /// idle. The `ticket` is the only way to name the credential half of the key.
    pub async fn connect(
        &self,
        up: &Upstream,
        ticket: &ForwardTicket,
    ) -> std::io::Result<Checkout> {
        let key = Key {
            authority: up.authority(),
            cred_identity: *ticket.cred_identity(),
        };

        loop {
            let pooled = self
                .idle
                .conns
                .lock()
                .ok()
                .and_then(|mut m| m.get_mut(&key).and_then(Vec::pop));
            let Some(mut sender) = pooled else { break };
            // `ready()` is what distinguishes a warm connection from one the peer closed
            // while it sat idle; a closed one is discarded and the loop tries the next.
            if std::future::poll_fn(|cx| sender.poll_ready(cx))
                .await
                .is_ok()
            {
                return Ok(Checkout {
                    key,
                    sender,
                    idle: Arc::clone(&self.idle),
                });
            }
        }

        let sender = self.dial(up).await?;
        Ok(Checkout {
            key,
            sender,
            idle: Arc::clone(&self.idle),
        })
    }

    async fn dial(&self, up: &Upstream) -> std::io::Result<SendRequest<Incoming>> {
        let tcp = tokio::net::TcpStream::connect((up.host.as_str(), up.port)).await?;
        // Nagle off: the request head is small and the next write is the body, so waiting for
        // a coalescing partner costs exactly the latency this component budgets in whole.
        let _ = tcp.set_nodelay(true);

        if up.tls {
            let name = rustls::pki_types::ServerName::try_from(up.host.clone())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let tls = self.tls.connect(name, tcp).await?;
            handshake(hyper_util::rt::TokioIo::new(tls)).await
        } else {
            // Reachable only for a loopback literal — `Upstream::new` refuses to build a
            // plaintext upstream for anything else, so there is no non-loopback path here.
            handshake(hyper_util::rt::TokioIo::new(tcp)).await
        }
    }
}

/// Webpki roots, TLS 1.2+1.3, and ALPN pinned to `http/1.1`.
fn client_config() -> Result<rustls::ClientConfig, rustls::Error> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    // The provider is passed explicitly rather than read from the process default: a library
    // that depends on `install_default()` having been called elsewhere fails at runtime, in
    // the request path, on the day someone reorders `main`.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // §3.4's "not even h2 streams" — enforced at negotiation, not by a later check.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

async fn handshake<I>(io: I) -> std::io::Result<SendRequest<Incoming>>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e))?;
    // The driver outlives this function and dies when the last `SendRequest` for it drops.
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender)
}

impl Checkout {
    /// Send the request. Splitting this from [`Pool::connect`] keeps the borrow of the pool
    /// out of the response's lifetime.
    pub async fn send(
        &mut self,
        req: http::Request<Incoming>,
    ) -> Result<http::Response<Incoming>, hyper::Error> {
        self.sender.send_request(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_key_separates_credentials_on_the_same_host() {
        let a = Key {
            authority: "api.anthropic.com".to_owned(),
            cred_identity: [1u8; 32],
        };
        let b = Key {
            authority: "api.anthropic.com".to_owned(),
            cred_identity: [2u8; 32],
        };
        assert_ne!(
            a, b,
            "same host, different credential must not share a pool slot"
        );
    }

    #[test]
    fn pool_key_separates_hosts_under_the_same_credential() {
        let a = Key {
            authority: "api.anthropic.com".to_owned(),
            cred_identity: [1u8; 32],
        };
        let b = Key {
            authority: "api.openai.com".to_owned(),
            cred_identity: [1u8; 32],
        };
        assert_ne!(a, b);
    }

    /// h2 offered in ALPN is h2 negotiated, and h2 is multiplexing — which §3.4 forbids
    /// across credentials. The client stack (`client::conn::http1`) cannot speak it either;
    /// this asserts we do not even advertise it, so no upstream is invited to try.
    #[test]
    fn alpn_offers_http1_only() {
        let cfg = client_config().unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
