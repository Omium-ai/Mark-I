//! Gateway mode (04 §3.3/§3.4): mTLS listener, credentials by reference, resolved per request into `Secret<T>` and dropped with it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use futures::future::BoxFuture;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;

use crate::Secret;

/// The customer's secret manager, one fetch per request; nothing here may cache or persist.
///
/// AWS Secrets Manager / Vault are deploy-time implementors behind this same trait (not in this crate: each is a new token-path dependency and a security review, NFR-SECURITY-008).
pub trait CredentialSource: Send + Sync {
    fn resolve<'a>(&'a self, cred_ref: &'a str) -> BoxFuture<'a, Option<Secret<Vec<u8>>>>;
}

/// In-memory source: the test double.
pub struct MemorySource {
    creds: HashMap<String, Vec<u8>>,
}

impl MemorySource {
    pub fn new(pairs: &[(&str, &[u8])]) -> Self {
        MemorySource {
            creds: pairs
                .iter()
                .map(|(r, c)| ((*r).to_owned(), c.to_vec()))
                .collect(),
        }
    }
}

impl CredentialSource for MemorySource {
    fn resolve<'a>(&'a self, cred_ref: &'a str) -> BoxFuture<'a, Option<Secret<Vec<u8>>>> {
        Box::pin(async move { self.creds.get(cred_ref).map(|c| Secret::new(c.clone())) })
    }
}

/// Dev source: `<dir>/<cred_ref>`, one credential per 0600 file, trailing newline trimmed.
pub struct FileSource {
    dir: PathBuf,
}

impl FileSource {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        FileSource { dir: dir.into() }
    }
}

/// A ref is a file *name*: one path component, no traversal.
fn is_plain_name(cred_ref: &str) -> bool {
    !cred_ref.is_empty()
        && cred_ref.len() <= 128
        && cred_ref
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        && !cred_ref.starts_with('.')
}

impl CredentialSource for FileSource {
    fn resolve<'a>(&'a self, cred_ref: &'a str) -> BoxFuture<'a, Option<Secret<Vec<u8>>>> {
        Box::pin(async move {
            if !is_plain_name(cred_ref) {
                return None;
            }
            let mut raw = tokio::fs::read(self.dir.join(cred_ref)).await.ok()?;
            while raw.last().is_some_and(u8::is_ascii_whitespace) {
                raw.pop();
            }
            (!raw.is_empty()).then(|| Secret::new(raw))
        })
    }
}

/// Listener identity plus the pinned client CA. Every field is a path to PEM on disk.
#[derive(Clone, Debug)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub client_ca: PathBuf,
}

/// rustls server config: TLS 1.2+1.3, client certificate REQUIRED and chained to `client_ca` only.
pub fn acceptor(paths: &TlsPaths) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let certs = CertificateDer::pem_slice_iter(&std::fs::read(&paths.cert)?)
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(&std::fs::read(&paths.key)?)?;
    let mut roots = rustls::RootCertStore::empty();
    for ca in CertificateDer::pem_slice_iter(&std::fs::read(&paths.client_ca)?) {
        roots.add(ca?)?;
    }
    if roots.is_empty() {
        anyhow::bail!("{}: no CA certificate", paths.client_ca.display());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// What `Proxy` holds in gateway mode.
pub struct Gateway {
    pub acceptor: tokio_rustls::TlsAcceptor,
    pub source: Arc<dyn CredentialSource>,
}

impl Gateway {
    pub fn new(acceptor: tokio_rustls::TlsAcceptor, source: Arc<dyn CredentialSource>) -> Self {
        Gateway { acceptor, source }
    }
}

/// Credential header name for an upstream: Anthropic grammar takes `x-api-key`, everything else a bearer.
/// ponytail: Gemini/Azure key headers (`x-goog-api-key`, `api-key`) are not readable by the guard; add when a non-bearer upstream is provisioned.
pub fn credential_header(dialect: mark1_frames::Dialect) -> http::header::HeaderName {
    if dialect == mark1_frames::Dialect::AnthropicSse {
        http::header::HeaderName::from_static("x-api-key")
    } else {
        http::header::AUTHORIZATION
    }
}

/// The one place a fetched credential becomes bytes on a request: a `sensitive` header value (never `Debug`-printed) that lives exactly as long as the forward.
pub fn credential_value(
    name: &http::header::HeaderName,
    secret: &Secret<Vec<u8>>,
) -> Option<http::HeaderValue> {
    let raw = secret.expose_for_upstream();
    let mut v = if *name == http::header::AUTHORIZATION {
        let mut b = b"Bearer ".to_vec();
        b.extend_from_slice(raw);
        http::HeaderValue::from_bytes(&b).ok()?
    } else {
        http::HeaderValue::from_bytes(raw).ok()?
    };
    v.set_sensitive(true);
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn file_source_resolves_plain_names_only() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("ref-1"), b"sk-ant-api03-x\n").unwrap();
        std::fs::write(tmp.path().join("empty"), b"\n").unwrap();
        let src = FileSource::new(tmp.path());
        assert_eq!(
            src.resolve("ref-1").await.unwrap().expose_for_upstream(),
            b"sk-ant-api03-x"
        );
        assert!(src.resolve("empty").await.is_none());
        assert!(src.resolve("missing").await.is_none());
        for traversal in ["../ref-1", "a/b", ".hidden", "", "x y"] {
            assert!(src.resolve(traversal).await.is_none(), "{traversal}");
        }
    }

    #[test]
    fn credential_values_are_sensitive_and_bearer_for_non_anthropic() {
        let s = Secret::new(b"sk-x".to_vec());
        let name = credential_header(mark1_frames::Dialect::AnthropicSse);
        let v = credential_value(&name, &s).unwrap();
        assert_eq!(name, "x-api-key");
        assert!(v.is_sensitive());
        assert_eq!(format!("{v:?}"), "Sensitive");
        let name = credential_header(mark1_frames::Dialect::OpenaiChat);
        assert_eq!(name, http::header::AUTHORIZATION);
        assert_eq!(
            credential_value(&name, &s).unwrap().as_bytes(),
            b"Bearer sk-x"
        );
    }
}
