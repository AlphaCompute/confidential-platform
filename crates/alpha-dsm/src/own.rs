//! AlphaCompute's own on-prem Fortanix DSM (PRD-06 I3, HSM-backed Alpha roots). The customer
//! DSM client above releases a customer's keys to an Instance; this one lets AlphaCompute's
//! release ceremony and its KMS use keys that never leave our HSM:
//!
//! - [`OwnDsm::sign`]: the release-signing key held in DSM signs a platform document (`alpha sign
//!   --release-key-dsm`). The caller verifies the signature under the expected public key before
//!   it uses it, so a wrong key, algorithm or request shape fails closed.
//! - [`OwnDsm::encrypt`] / [`OwnDsm::decrypt`]: AES-256-GCM under a DSM key, which alpha-kms uses
//!   to hold a co-factor of its root KEK beside the custodians' shares, never instead of them.
//!
//! Authentication is a DSM App's API key (`Authorization: Basic <api key>` on `POST
//! /sys/v1/session/auth`, then the bearer token), as Fortanix documents in "App Authentication
//! with an API Key" (support.fortanix.com). The calls are `POST /crypto/v1/sign`, `/encrypt` and
//! `/decrypt` as in DSM's REST reference ("Sign with a private key…", "Encrypt data using a
//! symmetric or asymmetric key", "Decrypt data…"); their byte fields are standard base64.
//! TLS is TLS 1.3 with `X25519MLKEM768` only unless the config says `classical-allowed` (F6).

use std::sync::Arc;
use std::time::{Duration, Instant};

use alpha_client::tls;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use parking_lot::Mutex;
use rustls::ClientConfig;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{Error, KeyExchange, KeyRef, REQUEST_TIMEOUT, TOKEN_MARGIN, read, roots};

/// Where our DSM is and which security object to use. No secret: the API key is passed apart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnDsmConfig {
    /// `https://` base URL of the on-prem DSM.
    pub endpoint: String,
    /// The CA(s) the DSM's server certificate chains to, PEM; nothing else is trusted.
    pub ca_pem: String,
    /// The security object: an Ed25519 key with SIGN for release signing, an AES-256 key with
    /// ENCRYPT and DECRYPT for the KMS root co-factor.
    pub key: KeyRef,
    /// Absent means [`KeyExchange::Hybrid`].
    #[serde(default, skip_serializing_if = "is_hybrid")]
    pub key_exchange: KeyExchange,
}

fn is_hybrid(k: &KeyExchange) -> bool {
    *k == KeyExchange::Hybrid
}

impl OwnDsmConfig {
    pub fn parse(text: &str, what: &str) -> Result<Self, Error> {
        let refused = |m: String| Error::Config(format!("{what}: {m}"));
        let value = alpha_core::parse(text.as_bytes()).map_err(|e| refused(e.to_string()))?;
        let config: Self = serde_json::from_value(value).map_err(|e| refused(e.to_string()))?;
        config.check().map_err(|e| refused(e.to_string()))?;
        Ok(config)
    }

    pub fn check(&self) -> Result<(), Error> {
        if !self.endpoint.starts_with("https://") {
            return Err(Error::Config("endpoint is not an https:// URL".into()));
        }
        let empty = match &self.key {
            KeyRef::Kid(s) | KeyRef::Name(s) => s.trim().is_empty(),
        };
        if empty {
            return Err(Error::Config("key names no security object".into()));
        }
        roots(&self.ca_pem).map(|_| ())
    }
}

/// An AES-GCM ciphertext as DSM returned it, kept whole so decryption sends back exactly it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wrapped {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    pub cipher: String,
    pub iv: String,
    pub tag: String,
}

#[derive(Deserialize)]
struct Session {
    access_token: Zeroizing<String>,
    expires_in: u64,
}

pub struct OwnDsm {
    http: reqwest::Client,
    endpoint: String,
    key: KeyRef,
    api_key: Zeroizing<String>,
    token: Mutex<Option<(Arc<Zeroizing<String>>, Instant)>>,
}

impl std::fmt::Debug for OwnDsm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnDsm")
            .field("endpoint", &self.endpoint)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

const GCM_TAG_BITS: u32 = 128;

impl OwnDsm {
    pub fn new(config: &OwnDsmConfig, api_key: Zeroizing<String>) -> Result<Self, Error> {
        config.check()?;
        if api_key.trim().is_empty() {
            return Err(Error::Config("the DSM API key is empty".into()));
        }
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
            .with_no_client_auth();
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
            key: config.key.clone(),
            api_key: Zeroizing::new(api_key.trim().to_owned()),
            token: Mutex::new(None),
        })
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
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Basic {}", self.api_key.as_str()),
            )
            .send()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;
        let session: Session = read(reply).await?;
        let token = Arc::new(session.access_token);
        let until = Instant::now()
            .checked_add(Duration::from_secs(session.expires_in).saturating_sub(TOKEN_MARGIN))
            .unwrap_or_else(Instant::now);
        *self.token.lock() = Some((token.clone(), until));
        Ok(token)
    }

    /// One crypto call with the session token; a token DSM no longer honours is replaced and
    /// the call retried once.
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<T, Error> {
        let mut retried = false;
        loop {
            let token = self.token().await?;
            let reply = self
                .http
                .post(format!("{}{path}", self.endpoint))
                .bearer_auth(token.as_str())
                .json(body)
                .send()
                .await
                .map_err(|e| Error::Transport(e.to_string()))?;
            if reply.status() != reqwest::StatusCode::UNAUTHORIZED || retried {
                return read(reply).await;
            }
            let mut held = self.token.lock();
            if held.as_ref().is_some_and(|(t, _)| Arc::ptr_eq(t, &token)) {
                *held = None;
            }
            retried = true;
        }
    }

    /// The DSM key's signature over `message`, as DSM returns it. For an Ed25519 key DSM's
    /// algorithm table lists pure EdDSA ("standard") with SHA-512, so `message` goes as `data`
    /// with `hash_alg: SHA512`.
    // ponytail: PRD-06 I3 "verify Ed25519 support" — DSM's algorithm table lists EdDSA/Ed25519,
    // but its sign reference gives no Ed25519 example; this request shape is confirmed against
    // our DSM at the first ceremony. Callers verify the result, so a wrong shape fails closed.
    pub async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        #[derive(Deserialize)]
        struct Signed {
            signature: String,
        }
        let signed: Signed = self
            .call(
                "/crypto/v1/sign",
                &json!({
                    "key": self.key,
                    "hash_alg": "SHA512",
                    "data": BASE64_STANDARD.encode(message),
                }),
            )
            .await?;
        BASE64_STANDARD
            .decode(signed.signature.as_bytes())
            .map_err(|e| Error::Invalid(format!("signature: {e}")))
    }

    /// AES-GCM with a 128-bit tag under the DSM key; DSM picks the IV.
    pub async fn encrypt(&self, plain: &[u8], ad: &[u8]) -> Result<Wrapped, Error> {
        let wrapped: Wrapped = self
            .call(
                "/crypto/v1/encrypt",
                &json!({
                    "key": self.key,
                    "alg": "AES",
                    "mode": "GCM",
                    "plain": BASE64_STANDARD.encode(plain),
                    "ad": BASE64_STANDARD.encode(ad),
                    "tag_len": GCM_TAG_BITS,
                }),
            )
            .await?;
        Ok(wrapped)
    }

    pub async fn decrypt(&self, wrapped: &Wrapped, ad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        #[derive(Deserialize)]
        struct Plain {
            plain: Zeroizing<String>,
        }
        let plain: Plain = self
            .call(
                "/crypto/v1/decrypt",
                &json!({
                    "key": self.key,
                    "alg": "AES",
                    "mode": "GCM",
                    "cipher": wrapped.cipher,
                    "iv": wrapped.iv,
                    "tag": wrapped.tag,
                    "ad": BASE64_STANDARD.encode(ad),
                    "tag_len": GCM_TAG_BITS,
                }),
            )
            .await?;
        BASE64_STANDARD
            .decode(plain.plain.as_bytes())
            .map(Zeroizing::new)
            .map_err(|e| Error::Invalid(format!("plain: {e}")))
    }
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

    #[test]
    fn the_config_names_an_https_dsm_its_ca_and_one_object() {
        let ca = serde_json::to_string(&ca_pem()).unwrap();
        let good = format!(
            r#"{{"endpoint":"https://dsm.example","ca_pem":{ca},"key":{{"name":"release-ed25519"}}}}"#
        );
        let config = OwnDsmConfig::parse(&good, "release DSM").unwrap();
        assert_eq!(config.key, KeyRef::Name("release-ed25519".into()));
        assert_eq!(config.key_exchange, KeyExchange::Hybrid);
        for bad in [
            good.replace("https://", "http://"),
            good.replace("release-ed25519", " "),
            good.replace(r#""key""#, r#""extra":1,"key""#),
            r#"{"endpoint":"https://d","ca_pem":"nope","key":{"kid":"k"}}"#.to_string(),
            format!(
                r#"{{"endpoint":"https://d","ca_pem":{ca},"key":{{"kid":"k"}},"api_key":"s"}}"#
            ),
        ] {
            assert!(OwnDsmConfig::parse(&bad, "release DSM").is_err(), "{bad}");
        }
        assert!(OwnDsm::new(&config, Zeroizing::new(" ".into())).is_err());
    }
}
