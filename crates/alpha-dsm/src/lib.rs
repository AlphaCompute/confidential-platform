//! A client for a customer's own Fortanix Data Security Manager (PRD-06, I1): after its Alpha
//! attestation an Instance fetches data keys from the customer's DSM, authenticating with the
//! one-hour leaf the KMS issued it. The customer's DSM decides release, so AlphaCompute never
//! holds the key and never decides who gets it. Nothing here talks to the KMS.
//!
//! The DSM App must be bound to this App or this Revision, never to the KMS CA alone: the KMS CA
//! signs every organization's leaves and its own nodes' too, so a DSM App that trusted the CA
//! alone would release this App's keys to any of them. The leaf names its App and Revision as
//! DNS-name SANs a DSM trusted-CA App can match ([`Binding`]); before any request the client
//! checks that the leaf it is about to present carries the name the configured binding needs,
//! and it never presents one that a DSM could check only against the CA.
//!
//! TLS to the DSM is TLS 1.3 with the `X25519MLKEM768` hybrid only, as on every platform hop,
//! unless the tenant's measured compose says `"key_exchange": "classical-allowed"`; PRD-06
//! question F6 settles whether that setting survives.
//!
//! Wire calls, from the DSM REST API: `POST /sys/v1/session/auth` over mTLS with the App's
//! uuid as the basic-auth user gives a bearer token; `POST /crypto/v1/keys/export` with a
//! security-object descriptor (`{"kid": …}` or `{"name": …}`) returns the object, its `value`
//! in standard base64. The DSM-side policy must grant the App the EXPORT operation on each key.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alpha_client::tls;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use parking_lot::Mutex;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub mod own;
#[cfg(feature = "stand-in")]
pub mod stand_in;

pub use own::{OwnDsm, OwnDsmConfig, Wrapped};

/// A token is not reused this close to its expiry.
const TOKEN_MARGIN: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("dsm config: {0}")]
    Config(String),
    #[error("dsm: {0}")]
    Transport(String),
    /// DSM answered with an error status; `status` 401/403 means its policy refused this App.
    #[error("dsm refused ({status}): {message}")]
    Refused { status: u16, message: String },
    #[error("dsm reply: {0}")]
    Invalid(String),
    #[error("no customer key named {0:?} is declared")]
    Undeclared(String),
    /// The leaf does not name this App or Revision in the form the DSM App binds to, so the
    /// client refuses to present it: a DSM could only check it against the shared KMS CA.
    #[error("dsm binding: {0}")]
    Unbound(String),
}

/// The key exchange the client offers the DSM.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyExchange {
    /// TLS 1.3 with `X25519MLKEM768` only, the provider every platform hop uses. A DSM without
    /// the hybrid gets no handshake.
    #[default]
    Hybrid,
    /// The aws-lc-rs defaults: the hybrid preferred, classical groups and TLS 1.2 accepted. Only
    /// until F6 is answered, and only because the tenant wrote it into the measured compose.
    ClassicalAllowed,
}

/// Which of the leaf's DNS names the customer's DSM App matches, beside the KMS CA. There is no
/// CA-only choice (see the crate docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Binding {
    /// `<app id>.<org id>.app.alphacompute.invalid`: every Revision of this App the tenant
    /// signed gets the keys.
    App,
    /// `<hash hex 1-32>.<hash hex 33-64>.<app id>.<org id>.revision.alphacompute.invalid`, the
    /// compose hash split into two 32-hex labels ([`tls::revision_dns_name`]): this Revision
    /// only; the customer adds the next Revision's name to the DSM App before rolling it out.
    Revision,
}

impl std::fmt::Display for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::App => "app",
            Self::Revision => "revision",
        })
    }
}

/// Which security object to fetch, in DSM's descriptor shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum KeyRef {
    Kid(String),
    Name(String),
}

/// `ALPHACOMPUTE_DSM`, part of the measured compose so the tenant's Revision names which DSM,
/// which App, which CA to trust and which keys: an operator cannot point the Instance elsewhere.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsmConfig {
    /// `https://` base URL of the customer's DSM (SaaS cluster or on-prem).
    pub endpoint: String,
    /// The DSM App this Revision authenticates as.
    pub app_id: String,
    /// The CA(s) DSM's server certificate chains to, PEM; nothing else is trusted.
    pub ca_pem: String,
    /// Local name (a lowercase path segment, as for Secrets) to the DSM object.
    pub keys: BTreeMap<String, KeyRef>,
    /// Required: what the DSM App matches on the leaf. A config without it is refused at start.
    pub binding: Binding,
    /// Absent means [`KeyExchange::Hybrid`].
    #[serde(default)]
    pub key_exchange: KeyExchange,
}

impl DsmConfig {
    /// Unset declares no DSM.
    pub fn parse(text: Option<&str>) -> Result<Option<Self>, Error> {
        let Some(text) = text else {
            return Ok(None);
        };
        let refused = |m: String| Error::Config(format!("ALPHACOMPUTE_DSM: {m}"));
        let value = alpha_core::parse(text.as_bytes()).map_err(|e| refused(e.to_string()))?;
        let config: Self = serde_json::from_value(value).map_err(|e| refused(e.to_string()))?;
        if !config.endpoint.starts_with("https://") {
            return Err(refused("endpoint is not an https:// URL".into()));
        }
        if config.app_id.trim().is_empty() {
            return Err(refused("app_id is empty".into()));
        }
        if config.keys.is_empty() {
            return Err(refused("declares no keys".into()));
        }
        if let Some(name) = config.keys.keys().find(|n| !alpha_core::is_key_purpose(n)) {
            return Err(refused(format!(
                "key {name:?} is not a lowercase path segment"
            )));
        }
        roots(&config.ca_pem).map_err(|e| refused(e.to_string()))?;
        Ok(Some(config))
    }
}

fn roots(ca_pem: &str) -> Result<RootCertStore, Error> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        let cert = cert.map_err(|e| Error::Config(format!("ca_pem: {e}")))?;
        roots
            .add(cert)
            .map_err(|e| Error::Config(format!("ca_pem: {e}")))?;
    }
    if roots.is_empty() {
        return Err(Error::Config("ca_pem holds no certificate".into()));
    }
    Ok(roots)
}

/// A key as DSM released it.
#[derive(Clone)]
pub struct CustomerKey {
    pub kid: Option<String>,
    pub name: Option<String>,
    pub obj_type: Option<String>,
    pub value: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for CustomerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomerKey")
            .field("kid", &self.kid)
            .field("name", &self.name)
            .field("obj_type", &self.obj_type)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Session {
    access_token: Zeroizing<String>,
    expires_in: u64,
}

#[derive(Deserialize)]
struct Exported {
    kid: Option<String>,
    name: Option<String>,
    obj_type: Option<String>,
    value: Option<Zeroizing<String>>,
}

/// One per Instance leaf: the leaf is the credential, so a renewal builds a new client.
pub struct Dsm {
    http: reqwest::Client,
    endpoint: String,
    app_id: String,
    keys: BTreeMap<String, KeyRef>,
    /// The DNS name the DSM App matches, or why the leaf carries none; checked before any request.
    bound: Result<String, String>,
    token: Mutex<Option<(Arc<Zeroizing<String>>, Instant)>>,
}

/// The name a DSM App bound by `binding` matches, if `leaf` carries it. It is computed from the
/// leaf's own URI SANs, so a leaf carrying another App's or Revision's DNS name fails as well.
fn bound_name(binding: Binding, leaf: Option<&[u8]>) -> Result<String, String> {
    let leaf = leaf.ok_or("the chain is empty")?;
    let id = tls::uri_sans(leaf)
        .and_then(|sans| tls::parse_instance_sans(&sans))
        .map_err(|e| format!("the leaf is not an Instance's: {e}"))?;
    let name = match binding {
        Binding::App => tls::app_dns_name(id.org_id, id.app_id),
        Binding::Revision => tls::revision_dns_name(id.org_id, id.app_id, id.compose_hash),
    };
    let carried = tls::dns_sans(leaf).map_err(|e| format!("the leaf: {e}"))?;
    if carried.contains(&name) {
        Ok(name)
    } else {
        Err(format!(
            "the leaf does not carry {name}, the DNS name a DSM App bound to this {binding} \
             matches, so it is not presented: a DSM could check it only against the KMS CA, \
             which signs every organization's leaves"
        ))
    }
}

impl Dsm {
    /// `chain` is the Instance's `[leaf, kms ca]` in DER, `pkcs8` the runtime key.
    /// A leaf without the binding's name still builds a client, so Alpha attestation never
    /// waits on DSM; every [`Dsm::key`] then fails with [`Error::Unbound`] before any request.
    pub fn new(config: &DsmConfig, chain: Vec<Vec<u8>>, pkcs8: &[u8]) -> Result<Self, Error> {
        let bound = bound_name(config.binding, chain.first().map(Vec::as_slice));
        let versions = match config.key_exchange {
            KeyExchange::Hybrid => ClientConfig::builder_with_provider(tls::provider())
                .with_protocol_versions(&[&rustls::version::TLS13]),
            KeyExchange::ClassicalAllowed => ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions(),
        };
        let tls = versions
            .map_err(|e| Error::Config(format!("tls: {e}")))?
            .with_root_certificates(roots(&config.ca_pem)?)
            .with_client_auth_cert(
                chain.into_iter().map(CertificateDer::from).collect(),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec())),
            )
            .map_err(|e| Error::Config(format!("client identity: {e}")))?;
        // Environment variables are not measured, so no proxy they name and no redirect the
        // server answers moves a request off the measured endpoint.
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| Error::Config(format!("http client: {e}")))?;
        Ok(Self {
            http,
            endpoint: config.endpoint.trim_end_matches('/').to_owned(),
            app_id: config.app_id.clone(),
            keys: config.keys.clone(),
            bound,
            token: Mutex::new(None),
        })
    }

    pub fn declares(&self, name: &str) -> bool {
        self.keys.contains_key(name)
    }

    /// The DNS name the customer's DSM App must match for this leaf, or why there is none.
    pub fn bound_name(&self) -> Result<&str, Error> {
        self.bound
            .as_deref()
            .map_err(|why| Error::Unbound(why.clone()))
    }

    async fn token(&self) -> Result<Arc<Zeroizing<String>>, Error> {
        if let Some((token, until)) = self.token.lock().as_ref()
            && Instant::now() < *until
        {
            return Ok(token.clone());
        }
        let reply = self
            .http
            .post(format!("{}/sys/v1/session/auth", self.endpoint))
            .basic_auth(&self.app_id, Some(""))
            .send()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let session: Session = read(reply).await.map_err(|e| match e {
            // Name what the DSM App had to match, so the customer's admin can see why.
            Error::Refused { status, message } => Error::Refused {
                status,
                message: format!("{message} (session for the leaf named {})", self.name()),
            },
            other => other,
        })?;
        let token = Arc::new(session.access_token);
        let until = Instant::now()
            .checked_add(Duration::from_secs(session.expires_in).saturating_sub(TOKEN_MARGIN))
            .unwrap_or_else(Instant::now);
        *self.token.lock() = Some((token.clone(), until));
        Ok(token)
    }

    fn name(&self) -> &str {
        self.bound.as_deref().unwrap_or("nothing")
    }

    /// Drops `token` unless another call already replaced it.
    fn forget(&self, token: &Arc<Zeroizing<String>>) {
        let mut held = self.token.lock();
        if held.as_ref().is_some_and(|(t, _)| Arc::ptr_eq(t, token)) {
            *held = None;
        }
    }

    /// The declared key `name`, fetched from DSM now; the caller caches it with the leaf. Nothing
    /// is sent unless the leaf carries the binding's name.
    pub async fn key(&self, name: &str) -> Result<CustomerKey, Error> {
        let descriptor = self
            .keys
            .get(name)
            .ok_or_else(|| Error::Undeclared(name.to_owned()))?;
        self.bound_name()?;
        let mut retried = false;
        let reply = loop {
            let token = self.token().await?;
            let reply = self
                .http
                .post(format!("{}/crypto/v1/keys/export", self.endpoint))
                .bearer_auth(token.as_str())
                .json(descriptor)
                .send()
                .await
                .map_err(|e| Error::Transport(e.to_string()))?;
            if reply.status() != reqwest::StatusCode::UNAUTHORIZED {
                break reply;
            }
            // A token DSM no longer honours: drop it, then authenticate afresh and retry once,
            // so a token revoked before its expiry does not reach the App as a refusal.
            self.forget(&token);
            if retried {
                break reply;
            }
            retried = true;
        };
        let exported: Exported = read(reply).await?;
        let value = exported
            .value
            .ok_or_else(|| Error::Invalid(format!("{name}: no value; is EXPORT permitted?")))?;
        let value = Zeroizing::new(
            BASE64_STANDARD
                .decode(value.as_bytes())
                .map_err(|e| Error::Invalid(format!("{name}: value: {e}")))?,
        );
        Ok(CustomerKey {
            kid: exported.kid,
            name: exported.name,
            obj_type: exported.obj_type,
            value,
        })
    }
}

async fn read<T: serde::de::DeserializeOwned>(reply: reqwest::Response) -> Result<T, Error> {
    let status = reply.status();
    let bytes = reply
        .bytes()
        .await
        .map_err(|e| Error::Transport(e.to_string()))?;
    if !status.is_success() {
        // DSM's error bodies are plain text or JSON; only a bounded prefix is kept.
        let message: String = String::from_utf8_lossy(&bytes).chars().take(300).collect();
        return Err(Error::Refused {
            status: status.as_u16(),
            message,
        });
    }
    serde_json::from_slice(&bytes).map_err(|e| Error::Invalid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca_pem() -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem()
    }

    fn config(extra: &str) -> String {
        format!(
            r#"{{"endpoint":"https://dsm.example","app_id":"app-1","ca_pem":{},"keys":{{"data":{{"kid":"k-1"}},"index":{{"name":"idx"}}}},"binding":"revision"{extra}}}"#,
            serde_json::to_string(&ca_pem()).unwrap()
        )
    }

    #[test]
    fn parses_a_config_naming_keys_by_kid_or_name() {
        let c = DsmConfig::parse(Some(&config(""))).unwrap().unwrap();
        assert_eq!(c.keys["data"], KeyRef::Kid("k-1".into()));
        assert_eq!(c.keys["index"], KeyRef::Name("idx".into()));
        assert_eq!(c.binding, Binding::Revision);
        assert_eq!(c.key_exchange, KeyExchange::Hybrid);
        assert_eq!(DsmConfig::parse(None).unwrap(), None);
        let app = config("").replace(r#""binding":"revision""#, r#""binding":"app""#);
        assert_eq!(
            DsmConfig::parse(Some(&app)).unwrap().unwrap().binding,
            Binding::App
        );
    }

    #[test]
    fn classical_key_exchange_is_only_an_explicit_setting() {
        let explicit =
            |v: &str| DsmConfig::parse(Some(&config(&format!(r#","key_exchange":{v}"#))));
        assert_eq!(
            explicit(r#""hybrid""#).unwrap().unwrap().key_exchange,
            KeyExchange::Hybrid
        );
        assert_eq!(
            explicit(r#""classical-allowed""#)
                .unwrap()
                .unwrap()
                .key_exchange,
            KeyExchange::ClassicalAllowed
        );
        for bad in [r#""classical""#, r#""tls12""#, "true", "null"] {
            assert!(explicit(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn refuses_a_config_that_binds_to_the_kms_ca_alone() {
        let revision = r#","binding":"revision""#;
        for bad in [
            config("").replace(revision, ""),
            config("").replace(revision, r#","binding":"ca""#),
            config("").replace(revision, r#","binding":null"#),
        ] {
            assert!(DsmConfig::parse(Some(&bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn refuses_what_would_let_a_host_redirect_or_widen_it() {
        let ca = serde_json::to_string(&ca_pem()).unwrap();
        for bad in [
            config(r#","extra":1"#),
            format!(
                r#"{{"endpoint":"http://dsm.example","app_id":"a","ca_pem":{ca},"keys":{{"k":{{"kid":"1"}}}},"binding":"app"}}"#
            ),
            format!(
                r#"{{"endpoint":"https://d","app_id":" ","ca_pem":{ca},"keys":{{"k":{{"kid":"1"}}}},"binding":"app"}}"#
            ),
            format!(
                r#"{{"endpoint":"https://d","app_id":"a","ca_pem":{ca},"keys":{{}},"binding":"app"}}"#
            ),
            format!(
                r#"{{"endpoint":"https://d","app_id":"a","ca_pem":{ca},"keys":{{"../x":{{"kid":"1"}}}},"binding":"app"}}"#
            ),
            r#"{"endpoint":"https://d","app_id":"a","ca_pem":"nope","keys":{"k":{"kid":"1"}},"binding":"app"}"#
                .into(),
        ] {
            assert!(DsmConfig::parse(Some(&bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn key_ref_is_dsms_descriptor_shape() {
        assert_eq!(
            serde_json::to_string(&KeyRef::Kid("k".into())).unwrap(),
            r#"{"kid":"k"}"#
        );
        assert_eq!(
            serde_json::to_string(&KeyRef::Name("n".into())).unwrap(),
            r#"{"name":"n"}"#
        );
    }
}
