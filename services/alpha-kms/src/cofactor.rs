//! PRD-06 I3, HSM-backed roots: a co-factor of the KMS root KEK held in AlphaCompute's own
//! on-prem Fortanix DSM, in addition to the custodians' 2-of-3 shares and never instead of them.
//!
//! Without `ALPHACOMPUTE_KMS_ROOT_DSM` nothing changes: the intermediates are wrapped under the
//! root the shares combine to. With it, bootstrap draws a 32-byte co-factor, has the DSM key
//! encrypt it (AES-256-GCM, the key never leaves the HSM), and wraps the intermediates under
//! `HKDF-SHA256(root ‖ co-factor)`. Unsealing then needs both: two custodian shares give the root,
//! which unwraps the DSM App's API key stored beside the co-factor, and the DSM decrypts the
//! co-factor. No DSM answer, no KMS: disabling the DSM key or App stops every unseal, and the DSM
//! logs every decryption. The DSM alone opens nothing, since the API key and the intermediates are
//! under the custodians' root.
//!
//! A node joining a serving node gets the intermediates from it and never asks the DSM.

use alpha_dsm::{OwnDsm, OwnDsmConfig, Wrapped};
use hkdf::Hkdf;
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::PgExecutor;
use zeroize::Zeroizing;

use crate::error::ApiError;
use crate::keys::{aead_open, aead_seal};
use crate::{Node, random};

pub const ROOT_DSM_ENV: &str = "ALPHACOMPUTE_KMS_ROOT_DSM";

/// What the DSM's AES-GCM binds the co-factor to, and the HKDF salt.
const COFACTOR_AD: &[u8] = b"alphacompute/kms-root-cofactor/v1";
const API_KEY_AAD: &[u8] = b"root-dsm-api-key";

pub type Key32 = Zeroizing<[u8; 32]>;

/// The KEK the intermediates are wrapped under when the root has a co-factor.
pub fn cofactor_kek(root: &[u8; 32], cofactor: &[u8; 32]) -> Result<Key32, ApiError> {
    let ikm = Zeroizing::new([root.as_slice(), cofactor.as_slice()].concat());
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(COFACTOR_AD), &ikm)
        .expand(b"intermediates kek", out.as_mut())
        .map_err(|e| ApiError::internal(format!("hkdf: {e}")))?;
    Ok(out)
}

fn dsm_error(e: alpha_dsm::Error) -> ApiError {
    ApiError::internal(format!("root DSM: {e}"))
}

/// The bootstrap's KEK and, with a DSM, the row that lets an unseal rebuild it.
pub struct Sealed {
    kek: Key32,
    row: Option<Row>,
}

struct Row {
    endpoint: String,
    key: Value,
    api_key_wrapped: Vec<u8>,
    cofactor: Value,
}

impl Sealed {
    pub fn kek(&self) -> &[u8; 32] {
        &self.kek
    }

    pub fn bound(&self) -> bool {
        self.row.is_some()
    }

    /// In the bootstrap's transaction, beside the intermediates it protects.
    pub async fn insert(&self, exec: impl PgExecutor<'_>) -> Result<(), ApiError> {
        let Some(row) = &self.row else {
            return Ok(());
        };
        sqlx::query!(
            "insert into root_cofactor (dsm_endpoint, dsm_key, api_key_wrapped, cofactor)
             values ($1, $2, $3, $4)",
            row.endpoint,
            row.key,
            row.api_key_wrapped,
            row.cofactor,
        )
        .execute(exec)
        .await?;
        Ok(())
    }
}

/// At bootstrap. The node's measured configuration decides whether there is a DSM; the
/// bootstrap body, sealed to the attested node, carries its API key.
pub async fn seal(
    config: Option<&OwnDsmConfig>,
    root: &[u8; 32],
    api_key: Option<&Zeroizing<String>>,
) -> Result<Sealed, ApiError> {
    let (config, api_key) = match (config, api_key) {
        (None, None) => {
            return Ok(Sealed {
                kek: Zeroizing::new(*root),
                row: None,
            });
        }
        (None, Some(_)) => {
            return Err(ApiError::malformed(format!(
                "the bootstrap body carries a root DSM API key, but the node has no {ROOT_DSM_ENV}"
            )));
        }
        (Some(_), None) => {
            return Err(ApiError::malformed(format!(
                "{ROOT_DSM_ENV} is set: the bootstrap body must carry root_dsm_api_key"
            )));
        }
        (Some(config), Some(api_key)) => (config, api_key),
    };
    let dsm = OwnDsm::new(config, api_key.clone()).map_err(dsm_error)?;
    let cofactor = Zeroizing::new(random::<32>()?);
    let wrapped = dsm
        .encrypt(cofactor.as_slice(), COFACTOR_AD)
        .await
        .map_err(dsm_error)?;
    // Proven before anything is stored: a co-factor the DSM cannot give back would leave the
    // custodians' shares unable to unseal anything.
    let back = dsm
        .decrypt(&wrapped, COFACTOR_AD)
        .await
        .map_err(dsm_error)?;
    if back.as_slice() != cofactor.as_slice() {
        return Err(ApiError::internal(
            "root DSM: the co-factor does not decrypt to itself",
        ));
    }
    Ok(Sealed {
        kek: cofactor_kek(root, &cofactor)?,
        row: Some(Row {
            endpoint: config.endpoint.clone(),
            key: json!(config.key),
            api_key_wrapped: aead_seal(root, API_KEY_AAD, api_key.as_bytes())?,
            cofactor: json!(wrapped),
        }),
    })
}

/// At unseal, once two shares combined to `root`: the KEK the intermediates are under.
pub async fn open(node: &Node, root: &[u8; 32]) -> Result<Key32, ApiError> {
    let row = sqlx::query!(
        "select dsm_endpoint, dsm_key, api_key_wrapped, cofactor from root_cofactor where one = 1"
    )
    .fetch_optional(&node.pool)
    .await?;
    let refused = |m: String| ApiError::malformed(m);
    let (row, config) = match (row, node.config.root_dsm.as_ref()) {
        (None, None) => return Ok(Zeroizing::new(*root)),
        (None, Some(_)) => {
            return Err(refused(format!(
                "{ROOT_DSM_ENV} is set, but this KMS's root was bootstrapped without a DSM co-factor"
            )));
        }
        (Some(_), None) => {
            return Err(refused(format!(
                "this KMS's root has a DSM co-factor: the node needs {ROOT_DSM_ENV}"
            )));
        }
        (Some(row), Some(config)) => (row, config),
    };
    if row.dsm_endpoint != config.endpoint || row.dsm_key != json!(config.key) {
        return Err(refused(format!(
            "{ROOT_DSM_ENV} names another DSM or key than the root's co-factor is held in"
        )));
    }
    let api_key = aead_open(root, API_KEY_AAD, &row.api_key_wrapped)
        .and_then(|k| String::from_utf8(k.to_vec()).ok())
        .map(Zeroizing::new)
        .ok_or_else(|| {
            refused("the root DSM's API key does not unwrap under these shares".into())
        })?;
    let wrapped: Wrapped = serde_json::from_value(row.cofactor)
        .map_err(|e| ApiError::internal(format!("root_cofactor: {e}")))?;
    let dsm = OwnDsm::new(config, api_key).map_err(dsm_error)?;
    let cofactor = dsm
        .decrypt(&wrapped, COFACTOR_AD)
        .await
        .map_err(dsm_error)?;
    let cofactor = <[u8; 32]>::try_from(cofactor.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| ApiError::internal("root DSM: the co-factor is not 32 bytes"))?;
    cofactor_kek(root, &cofactor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kek_needs_both_the_root_and_the_cofactor() {
        let kek = cofactor_kek(&[1; 32], &[2; 32]).unwrap();
        assert_ne!(*kek, [1; 32]);
        assert_ne!(*kek, *cofactor_kek(&[1; 32], &[3; 32]).unwrap());
        assert_ne!(*kek, *cofactor_kek(&[4; 32], &[2; 32]).unwrap());
        assert_eq!(*kek, *cofactor_kek(&[1; 32], &[2; 32]).unwrap());
    }

    #[tokio::test]
    async fn without_a_dsm_the_root_is_the_kek_and_a_half_configured_one_is_refused() {
        let sealed = seal(None, &[5; 32], None).await.unwrap();
        assert_eq!(*sealed.kek(), [5; 32]);
        assert!(!sealed.bound());
        let key = Zeroizing::new("k".to_owned());
        assert!(seal(None, &[5; 32], Some(&key)).await.is_err());
        let config = OwnDsmConfig {
            endpoint: "https://dsm.invalid".into(),
            ca_pem: String::new(),
            key: alpha_dsm::KeyRef::Name("k".into()),
            key_exchange: alpha_dsm::KeyExchange::Hybrid,
        };
        let refused = seal(Some(&config), &[5; 32], None).await.err().unwrap();
        assert!(
            refused.message.contains("root_dsm_api_key"),
            "{}",
            refused.message
        );
    }
}
