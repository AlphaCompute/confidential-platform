//! The KBS admin API on loopback, as the feed alone calls it: an Ed25519 key generated in the TD
//! at start, whose public half the KBS's configuration names as its only identity provider
//! (`kbs/src/admin/authentication/bearer_jwt.rs`), and a token minted per call. The private key
//! never leaves this process, so no person, Rafay included, can administer the KBS.

use std::time::{Duration, UNIX_EPOCH};

use alpha_trustee::policy::DENY_ALL;
use alpha_trustee::wire;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use serde_json::json;

use crate::files::{ADMIN_AUDIENCE, ADMIN_ISSUER, ADMIN_ROLE, KBS_ADDR};
use crate::{Clock, Error};

/// A token lives as long as one call needs.
const TOKEN_LIFETIME: Duration = Duration::from_secs(120);
const TIMEOUT: Duration = Duration::from_secs(30);

pub struct Admin {
    http: reqwest::Client,
    base: String,
    key: SigningKey,
    clock: Clock,
}

impl Admin {
    /// A fresh key, for the KBS on loopback.
    pub fn generate(clock: Clock) -> Result<Self, Error> {
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|e| Error::Key(format!("rng: {e}")))?;
        Self::with_key(
            SigningKey::from_bytes(&seed),
            format!("http://{KBS_ADDR}"),
            clock,
        )
    }

    pub fn with_key(key: SigningKey, base: String, clock: Clock) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| Error::Kbs(format!("http client: {e}")))?;
        Ok(Self {
            http,
            base,
            key,
            clock,
        })
    }

    /// The public key as the KBS's `public_key_uri` file holds it.
    pub fn public_pem(&self) -> Result<String, Error> {
        self.key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::Key(format!("admin key: {e}")))
    }

    /// `{iss, aud, role, iat, exp}` signed EdDSA.
    pub fn token(&self) -> Result<String, Error> {
        use ed25519_dalek::Signer;
        let now = (self.clock)()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Key("clock before the epoch".into()))?;
        let exp = now
            .checked_add(TOKEN_LIFETIME)
            .ok_or_else(|| Error::Key("clock overflows".into()))?;
        let header = BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let claims = BASE64_URL_SAFE_NO_PAD.encode(
            json!({ "iss": ADMIN_ISSUER, "aud": ADMIN_AUDIENCE, "role": ADMIN_ROLE,
                    "iat": now.as_secs(), "exp": exp.as_secs() })
            .to_string(),
        );
        let input = format!("{header}.{claims}");
        let signature = BASE64_URL_SAFE_NO_PAD.encode(self.key.sign(input.as_bytes()).to_bytes());
        Ok(format!("{input}.{signature}"))
    }

    async fn post(&self, path: &str, body: String) -> Result<(), Error> {
        let response = self
            .http
            .post(format!("{}{path}", self.base))
            .bearer_auth(self.token()?)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| Error::Kbs(format!("POST {path}: {e}")))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(Error::Kbs(format!("POST {path}: {status}: {text}")));
        }
        Ok(())
    }

    pub async fn resource_policy(&self, rego: &str) -> Result<(), Error> {
        self.post(
            "/kbs/v0/resource-policy",
            json!({ "policy": BASE64_URL_SAFE_NO_PAD.encode(rego) }).to_string(),
        )
        .await
    }

    /// The appraisal policies and reference values first, the resource policy last, so a pod
    /// is never released to under a newer resource policy than the appraisal it went through.
    pub async fn install(&self, state: &wire::State) -> Result<(), Error> {
        for (id, rego) in &state.attestation_policies {
            self.post(
                "/kbs/v0/attestation-policy",
                json!({ "policy_id": id, "policy": BASE64_URL_SAFE_NO_PAD.encode(rego) })
                    .to_string(),
            )
            .await?;
        }
        self.post("/kbs/v0/reference-value", state.reference_values.clone())
            .await?;
        self.resource_policy(&state.resource_policy).await
    }

    pub async fn deny_all(&self) -> Result<(), Error> {
        self.resource_policy(DENY_ALL).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ed25519_dalek::Verifier;
    use serde_json::Value;

    use super::*;

    #[test]
    fn the_admin_token_is_an_eddsa_jwt_the_kbs_config_accepts() {
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let admin = Admin::with_key(
            SigningKey::from_bytes(&[3; 32]),
            "http://127.0.0.1:1".into(),
            Arc::new(move || now),
        )
        .unwrap();
        let token = admin.token().unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        let claims: Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], ADMIN_ISSUER);
        assert_eq!(claims["aud"], ADMIN_AUDIENCE);
        assert_eq!(claims["role"], ADMIN_ROLE);
        assert_eq!(claims["exp"], 1_800_000_120);
        let signature =
            ed25519_dalek::Signature::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[2]).unwrap())
                .unwrap();
        assert!(
            admin
                .key
                .verifying_key()
                .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
                .is_ok()
        );
        assert!(
            admin
                .public_pem()
                .unwrap()
                .starts_with("-----BEGIN PUBLIC KEY-----")
        );
    }
}
