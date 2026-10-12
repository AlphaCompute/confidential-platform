//! A Kata pod as the CoCo attestation agent presents it to the KBS facade: the same pod as
//! `common::kata` (its init-data, Revision v2, GPUs and the quote its TD produces), but with the
//! agent's TEE key and the KBS protocol's runtime-data binding, and a client that opens resources
//! exactly as guest-components d4dce5ce's `TeeKeyPair::decrypt_response` does.

use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use aes_kw::KwAes256;
use alpha_attest::VerifiedQuote;
use alpha_kms::Clock;
use alpha_kms::error::ApiError;
use alpha_kms::kbs::{self, TeeKey, jwe};
use base64::Engine;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use p256::elliptic_curve::sec1::ToSec1Point;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha384};

use super::kata::{FakeGpu, Gpu, Pod, fresh_nonce, kata_document, publish};
use super::{Harness, KEYED, captured_at, harness_with_kbs, send};
use alpha_attest::GpuVerifier;
use alpha_attest::gpu::ccm::FortanixCcm;

pub const HOSTNAME: &str = "kbs.alpha.test";

/// [`super::kata::kata_harness`] with the KBS facade enabled under [`HOSTNAME`].
pub async fn kbs_harness(gpu: &Arc<FakeGpu>) -> Option<Harness> {
    let now = captured_at(KEYED);
    kbs_harness_with_clock(gpu, Arc::new(move || now)).await
}

/// [`kbs_harness`] on `clock`.
pub async fn kbs_harness_with_clock(gpu: &Arc<FakeGpu>, clock: Clock) -> Option<Harness> {
    let backends: Vec<Arc<dyn GpuVerifier>> = vec![
        gpu.clone(),
        Arc::new(FortanixCcm {
            endpoint: "https://ccm.example".into(),
        }),
    ];
    let h = harness_with_kbs(clock, backends, Some(HOSTNAME)).await?;
    publish(&h, kata_document(2)).await;
    Some(h)
}

/// The agent's default TEE key pair.
pub fn tee_secret(seed: u8) -> p256::SecretKey {
    p256::SecretKey::from_slice(&[seed; 32]).unwrap()
}

pub fn tee_key(secret: &p256::SecretKey) -> TeeKey {
    let point = secret.public_key().to_sec1_point(false);
    TeeKey {
        kty: "EC".into(),
        crv: jwe::CRV.into(),
        alg: jwe::ALG.into(),
        x: BASE64_URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        y: BASE64_URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    }
}

fn jcs(value: &Value) -> Vec<u8> {
    alpha_core::jcs(value).unwrap()
}

/// What the attestation agent sends to `POST /kbs/v0/attest`, and the quote its TD produced.
pub struct Exchange {
    pub body: Value,
    pub quote: VerifiedQuote,
}

impl Exchange {
    pub fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.body).unwrap()
    }

    pub async fn attest(&self, h: &Harness) -> Result<String, ApiError> {
        kbs::attest_verified(&h.node, &self.bytes(), self.quote.clone()).await
    }
}

/// A pod and the TEE key its attestation agent holds.
pub struct KbsPod {
    pub pod: Pod,
    pub tee: p256::SecretKey,
}

impl KbsPod {
    pub fn new(pod: Pod, seed: u8) -> Self {
        Self {
            pod,
            tee: tee_secret(seed),
        }
    }

    pub fn tee_key(&self) -> TeeKey {
        tee_key(&self.tee)
    }

    /// `get_composite_evidence` for the challenge `nonce` (base64, as `/auth` returns it): the
    /// NVIDIA attester's reports over the first 32 bytes of SHA-384(JCS({nonce, tee-pubkey})),
    /// then the TD quote over SHA-384(JCS({tee-pubkey, nonce, additional-evidence})).
    pub fn exchange(&self, nonce: &str) -> Exchange {
        let key = json!(self.tee_key());
        let device = jcs(&json!({ "nonce": nonce, "tee-pubkey": key }));
        let gpu_nonce: [u8; 32] = Sha384::digest(device)[..32].try_into().unwrap();
        let additional = if self.pod.gpus.is_empty() {
            String::new()
        } else {
            let list: Vec<Value> = self
                .pod
                .gpus
                .iter()
                .map(|gpu| {
                    let report = serde_json::to_vec(&Gpu {
                        nonce: Some(gpu.nonce.unwrap_or(gpu_nonce)),
                        ..gpu.clone()
                    })
                    .unwrap();
                    json!({ "arch": "BLACKWELL", "uuid": "unknown",
                            "evidence": BASE64_STANDARD.encode(report),
                            "certificate": BASE64_STANDARD.encode(b"certificate") })
                })
                .collect();
            json!({ "nvidia": { "device_evidence_list": list } }).to_string()
        };
        let primary =
            jcs(&json!({ "tee-pubkey": key, "nonce": nonce, "additional-evidence": additional }));
        let mut report_data = [0u8; 64];
        report_data[..48].copy_from_slice(&Sha384::digest(primary));
        Exchange {
            body: json!({
                "init-data": { "format": "toml", "body": self.pod.initdata },
                "runtime-data": { "nonce": nonce, "tee-pubkey": key },
                "tee-evidence": {
                    "primary_evidence": { "cc_eventlog": null, "quote": BASE64_STANDARD.encode(b"synthetic quote") },
                    "additional_evidence": additional,
                },
            }),
            quote: Pod::quote_of(&self.pod.initdata, &self.pod.runtime_class, report_data),
        }
    }

    /// A fresh challenge nonce, minted as `/auth` mints it.
    pub fn nonce(h: &Harness) -> String {
        BASE64_STANDARD.encode(fresh_nonce(h))
    }

    /// The RCAR handshake against the node, its quote synthetic: the token.
    pub async fn attest(&self, h: &Harness) -> Result<String, ApiError> {
        self.exchange(&Self::nonce(h)).attest(h).await
    }
}

/// `GET /kbs/v0/resource/<path>` as CDH's token client sends it.
pub async fn get(h: &Harness, token: Option<&str>, path: &str) -> (StatusCode, Value) {
    let mut request = super::client().get(format!("{}/kbs/v0/resource/{path}", h.url));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    send(request).await
}

/// kbs-types' `ProtectedHeader`: `alg`, `enc`, everything else flattened after them.
#[derive(Serialize, Deserialize)]
struct ProtectedHeader {
    alg: String,
    enc: String,
    #[serde(flatten)]
    other_fields: Map<String, Value>,
}

fn b64(value: &Value) -> Vec<u8> {
    BASE64_URL_SAFE_NO_PAD
        .decode(value.as_str().unwrap())
        .unwrap()
}

/// guest-components' `decrypt_response` for an EC key: the header parsed and re-serialized for
/// the AAD, ECDH with `epk`, Concat KDF over `ECDH-ES+A256KW` with no party info, AES key unwrap,
/// AES-256-GCM. `None` if any step fails, as it does for anyone but the key's holder.
pub fn open(response: &Value, tee: &p256::SecretKey) -> Option<Vec<u8>> {
    let header: ProtectedHeader = serde_json::from_slice(&b64(&response["protected"])).ok()?;
    if (header.alg.as_str(), header.enc.as_str()) != (jwe::ALG, jwe::ENC) {
        return None;
    }
    let epk = header.other_fields.get("epk")?;
    if epk["crv"] != jwe::CRV {
        return None;
    }
    let sec1 = [vec![4u8], b64(&epk["x"]), b64(&epk["y"])].concat();
    let epk = p256::PublicKey::from_sec1_bytes(&sec1).ok()?;
    let z = p256::ecdh::diffie_hellman(tee.to_nonzero_scalar(), epk.as_affine());
    let kek = jwe::concat_kdf(z.raw_secret_bytes().as_slice(), jwe::ALG, &[], &[], 256);
    let wrapped = b64(&response["encrypted_key"]);
    let mut cek = vec![0u8; wrapped.len().checked_sub(8)?];
    KwAes256::new_from_slice(kek.as_slice())
        .ok()?
        .unwrap_key(&wrapped, &mut cek)
        .ok()?;
    let aad = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).ok()?);
    let sealed = [b64(&response["ciphertext"]), b64(&response["tag"])].concat();
    let iv: [u8; 12] = b64(&response["iv"]).try_into().ok()?;
    Aes256Gcm::new_from_slice(&cek)
        .ok()?
        .decrypt(
            &Nonce::from(iv),
            Payload {
                msg: &sealed,
                aad: aad.as_bytes(),
            },
        )
        .ok()
}

/// Asserts a refusal with `code` whose message names `reason`, and that the last `kbs.attest`
/// audit row records exactly that refusal.
pub async fn refused(h: &Harness, result: Result<String, ApiError>, code: &str, reason: &str) {
    let error = match result {
        Ok(token) => panic!("attested: {token}"),
        Err(error) => error,
    };
    assert_eq!(error.code, code, "{}", error.message);
    assert!(error.message.contains(reason), "{}", error.message);
    let (_, outcome, details) = h.audit("kbs.attest").await.pop().unwrap();
    assert_eq!(outcome, "denied");
    assert_eq!(details, json!({ "code": code, "message": error.message }));
}

/// Asserts that `GET` of `path` with `token` is refused with `status` and the KBS error `kind`,
/// and that the last `kbs.resource` audit row records a denial with `code`.
pub async fn denied(
    h: &Harness,
    token: Option<&str>,
    path: &str,
    status: StatusCode,
    kind: &str,
    code: &str,
) {
    let (got, reply) = get(h, token, path).await;
    assert_eq!(got, status, "{path}: {reply}");
    assert_eq!(
        reply["type"],
        format!("https://github.com/confidential-containers/kbs/errors/{kind}"),
        "{reply}"
    );
    assert!(reply.get("ciphertext").is_none());
    let (_, outcome, details) = h.audit("kbs.resource").await.pop().unwrap();
    assert_eq!(outcome, "denied", "{details}");
    assert_eq!(details["code"], code, "{details}");
}
