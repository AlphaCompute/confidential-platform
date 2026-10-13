//! A Kata confidential pod as the KMS sees it, over synthetic verified quotes: no B300 Kata capture
//! exists before M1, so DCAP is exercised by the route with the real Phala captures and these pods
//! go through `instance::attest_verified`, which runs every later step and writes the audit row. A
//! pod is its init-data and Revision v2, the quote a TD running that init-data produces, one
//! evidence entry per GPU, and [`FakeGpu`], a backend that reports what each entry says.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use alpha_attest::gpu::ccm::FortanixCcm;
use alpha_attest::gpu::{GpuFuture, gpu_nonce};
use alpha_attest::{
    AppraisalError, CpuEvidence, CpuKind, EVIDENCE_FORMAT_V2, EvidenceV2, GpuEvidence, GpuPolicy,
    GpuVerdict, GpuVerifier, GpuVerifierKind, Measured, Measurement, VerifiedGpu, VerifiedQuote,
    report_data,
};
use alpha_core::coco::{CPU_RUNTIME_CLASS, CocoRevision, GPU_RUNTIME_CLASS, InitData};
use alpha_core::{AppId, ComposeHash, KeyId, context};
use alpha_kms::error::ApiError;
use alpha_kms::instance::{self, AttestRequest};
use alpha_kms::{certs, platform};
use ed25519_dalek::SigningKey;
use p256::pkcs8::EncodePublicKey;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    Harness, KATA, KEYED, b64, captured_at, harness_on, harness_with, platform_document,
};

/// A baseline agent policy: exec and log reads denied.
pub const POLICY: &str = "package agent_policy\ndefault ExecProcessRequest := false\ndefault ReadStreamRequest := false\n";

pub fn m(byte: u8) -> Measurement {
    Measurement([byte; 48])
}

/// MRTD and RTMR0..2 of each runtime class's guest image, as [`kata_document`] lists them.
pub fn registers(class: &str) -> [Measurement; 4] {
    if class == CPU_RUNTIME_CLASS {
        [m(1), m(2), m(13), m(14)]
    } else {
        [m(1), m(2), m(3), m(4)]
    }
}

/// The init-data `alpha coco render` writes: the agent policy and our `alpha.json`.
pub fn initdata(app: AppId, class: &str, gpus: Option<u32>, policy: &str) -> String {
    let gpu = gpus
        .map(|n| format!("\"gpu\":{{\"count\":{n},\"model\":\"B300\"}},"))
        .unwrap_or_default();
    format!(
        "algorithm = \"sha384\"\nversion = \"0.1.0\"\n\n[data]\n\"policy.rego\" = '''\n{policy}'''\n\"alpha.json\" = '''{{\"app_id\":\"{app}\",\"format\":\"alphacompute-initdata/1\",{gpu}\"runtime_class\":\"{class}\"}}'''\n"
    )
}

/// A `kata-tdx` reference value for `class`'s guest image.
pub fn reference_value(name: &str, class: &str, registers: [Measurement; 4]) -> Value {
    let [mrtd, rtmr0, rtmr1, rtmr2] = registers;
    json!({ "name": name, "kind": "kata-tdx", "runtime_class": class,
            "values": { "mrtd": mrtd, "rtmr0": rtmr0, "rtmr1": rtmr1, "rtmr2": rtmr2 } })
}

/// The keyed capture's platform document as `version`, with a `kata-tdx` reference value for each
/// runtime class's guest and a `gpu_policy` allowing B300s that NRAS verifies.
pub fn kata_document(version: u64) -> Value {
    let mut doc = platform_document(KEYED);
    doc["version"] = json!(version);
    let values = doc["reference_values"].as_array_mut().unwrap();
    values.push(reference_value(
        "nvidia-uvm-tdx/b300x8",
        GPU_RUNTIME_CLASS,
        registers(GPU_RUNTIME_CLASS),
    ));
    values.push(reference_value(
        "kata-tdx/cpu-4c-8g",
        CPU_RUNTIME_CLASS,
        registers(CPU_RUNTIME_CLASS),
    ));
    doc["gpu_policy"] = json!({ "allowed_models": ["B300"], "verifiers": ["nras"] });
    doc
}

/// Signs and publishes `doc`, and has the node load it.
pub async fn publish(h: &Harness, doc: Value) {
    h.release.set(doc);
    platform::reload(&h.node).await.unwrap();
}

/// A Kata harness at the Kata capture's time, with Kata reference values and agent policy, for
/// init-data attestation tests that do not exercise GPU backends.
pub async fn kata_init_harness() -> Option<Harness> {
    let mut document = platform_document(KEYED);
    let kata = platform_document(KATA);
    document["kata_reference_values"] = kata["kata_reference_values"].clone();
    document["kata_policy"] = kata["kata_policy"].clone();
    let now = captured_at(KATA);
    harness_on(std::sync::Arc::new(move || now), KATA, document).await
}

/// A harness whose node runs `gpu` as its NRAS backend and the Fortanix CCM backend, under
/// [`kata_document`] version 2.
pub async fn kata_harness(gpu: &Arc<FakeGpu>) -> Option<Harness> {
    let now = captured_at(KEYED);
    let backends: Vec<Arc<dyn GpuVerifier>> = vec![
        gpu.clone(),
        Arc::new(FortanixCcm {
            endpoint: "https://ccm.example".into(),
        }),
    ];
    let h = harness_with(Arc::new(move || now), backends).await?;
    publish(&h, kata_document(2)).await;
    Some(h)
}

/// What a synthetic GPU report says about itself; a real one is an SPDM report the backend checks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Gpu {
    pub device: String,
    pub model: String,
    /// `cc`, `devtools` or `off`.
    pub mode: String,
    /// The nonce the report is over; `None` for the attestation's own GPU nonce.
    pub nonce: Option<[u8; 32]>,
}

impl Gpu {
    pub fn b300(device: u32) -> Self {
        Self {
            device: format!("ueid-{device}"),
            model: "B300".into(),
            mode: "cc".into(),
            nonce: None,
        }
    }
}

#[derive(Clone)]
pub struct Pod {
    pub app: AppId,
    pub initdata: String,
    pub runtime_class: String,
    pub gpus: Vec<Gpu>,
    pub key: p256::ecdsa::SigningKey,
}

impl Pod {
    /// A pod of `app` on the GPU class with `count` B300s in CC mode.
    pub fn gpu(app: AppId, count: u32) -> Self {
        Self {
            app,
            initdata: initdata(app, GPU_RUNTIME_CLASS, Some(count), POLICY),
            runtime_class: GPU_RUNTIME_CLASS.into(),
            gpus: (0..count).map(Gpu::b300).collect(),
            key: p256::ecdsa::SigningKey::from_bytes((&[9u8; 32]).into()).unwrap(),
        }
    }

    /// A CPU-only pod of `app` (KMS, broker, signer, guard, front, supervisor).
    pub fn cpu(app: AppId) -> Self {
        Self {
            initdata: initdata(app, CPU_RUNTIME_CLASS, None, POLICY),
            runtime_class: CPU_RUNTIME_CLASS.into(),
            gpus: Vec::new(),
            ..Self::gpu(app, 1)
        }
    }

    pub fn spki(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// The Revision v2 this pod's init-data stands for.
    pub fn revision(&self) -> CocoRevision {
        InitData::parse(self.initdata.as_bytes())
            .unwrap()
            .revision()
            .unwrap()
    }

    pub fn hash(&self) -> ComposeHash {
        self.revision().hash().unwrap()
    }

    pub fn report_data(&self, nonce: &[u8; 32]) -> [u8; 64] {
        report_data(&self.spki(), nonce, None)
    }

    /// The evidence this pod sends for `nonce`: its init-data, its claimed class, one entry per GPU.
    pub fn evidence(&self, nonce: &[u8; 32]) -> EvidenceV2 {
        let own = gpu_nonce(&self.report_data(nonce));
        EvidenceV2 {
            format: EVIDENCE_FORMAT_V2.into(),
            cpu: CpuEvidence {
                kind: CpuKind::Tdx,
                quote: b"synthetic quote".to_vec(),
                event_log: Vec::new(),
            },
            gpus: self
                .gpus
                .iter()
                .map(|gpu| GpuEvidence {
                    arch: "BLACKWELL".into(),
                    evidence: serde_json::to_vec(&Gpu {
                        nonce: Some(gpu.nonce.unwrap_or(own)),
                        ..gpu.clone()
                    })
                    .unwrap(),
                    certificate: b"certificate".to_vec(),
                })
                .collect(),
            initdata: self.initdata.clone().into_bytes(),
            runtime_class: self.runtime_class.clone(),
        }
    }

    /// The quote a TD booted from `class`'s guest with `initdata` produces over `report_data`.
    pub fn quote_of(initdata: &str, class: &str, report_data: [u8; 64]) -> VerifiedQuote {
        let [mrtd, rtmr0, rtmr1, rtmr2] = registers(class);
        VerifiedQuote {
            report_data,
            measured: Measured {
                mrtd,
                rtmr0,
                rtmr1,
                rtmr2,
                rtmr3: m(5),
                mrconfigid: None,
            },
            mrconfigid: Measurement(InitData::parse(initdata.as_bytes()).unwrap().mrconfigid()),
            tcb_status: "UpToDate".into(),
            advisories: Vec::new(),
        }
    }

    /// The quote this pod's TD produces for `nonce`.
    pub fn quote(&self, nonce: &[u8; 32]) -> VerifiedQuote {
        Self::quote_of(&self.initdata, &self.runtime_class, self.report_data(nonce))
    }

    /// The request as `alpha-runtime` sends it (`alpha_client::AttestRequest`), as the KMS parses it.
    pub fn request(&self, nonce: &[u8; 32], evidence: EvidenceV2) -> AttestRequest {
        let wire = alpha_client::AttestRequest {
            runtime_pubkey: b64(&self.spki()),
            nonce: b64(nonce),
            evidence: evidence.into(),
        };
        serde_json::from_value(serde_json::to_value(&wire).unwrap()).unwrap()
    }

    /// Attests with a fresh nonce, this pod's evidence and the quote its TD produces.
    pub async fn attest(&self, h: &Harness) -> Result<Value, ApiError> {
        let nonce = fresh_nonce(h);
        attest(
            h,
            &self.request(&nonce, self.evidence(&nonce)),
            self.quote(&nonce),
        )
        .await
    }

    /// Registers this pod's Revision v2 through route 1, signed by `signer`.
    pub async fn register(&self, h: &Harness, signer: &(KeyId, SigningKey)) -> ComposeHash {
        let (status, reply) = h.post("/v1/revisions", self.registration(h, signer)).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        self.hash()
    }

    /// The route 1 body registering this pod's Revision v2, signed by `signer`.
    pub fn registration(&self, h: &Harness, signer: &(KeyId, SigningKey)) -> Value {
        let payload =
            json!({ "app_id": self.app, "compose": self.revision().canonical().unwrap() });
        h.signed(context::REVISION, payload, signer)
    }
}

pub fn fresh_nonce(h: &Harness) -> [u8; 32] {
    instance::mint_nonce(&h.node.nonce_key, h.now()).unwrap()
}

pub async fn attest(
    h: &Harness,
    request: &AttestRequest,
    quote: VerifiedQuote,
) -> Result<Value, ApiError> {
    instance::attest_verified(&h.node, request, quote).await
}

/// The leaf's URI SANs.
pub fn leaf_sans(reply: &Value) -> Vec<String> {
    let pem = reply["certificate_chain"][0].as_str().unwrap();
    let der =
        <rustls::pki_types::CertificateDer as rustls::pki_types::pem::PemObject>::from_pem_slice(
            pem.as_bytes(),
        )
        .unwrap();
    certs::uri_sans(&der).unwrap()
}

/// Asserts a refusal with `code` whose message names `reason`, and that the last `attest` audit
/// row records exactly that refusal.
pub async fn refused(h: &Harness, result: Result<Value, ApiError>, code: &str, reason: &str) {
    let error = match result {
        Ok(reply) => panic!("attested: {reply}"),
        Err(error) => error,
    };
    assert_eq!(error.code, code, "{}", error.message);
    assert!(error.message.contains(reason), "{}", error.message);
    let (_, outcome, details) = h.audit("attest").await.pop().unwrap();
    assert_eq!(outcome, "denied");
    assert_eq!(details, json!({ "code": code, "message": error.message }));
}

/// A GPU verifier backend standing in for NRAS: it reports every GPU as its report describes it,
/// the nonce it is over included. NRAS also refuses a report over another nonce itself; this one
/// does not, so the KMS's own checks are what refuse it.
#[derive(Default)]
pub struct FakeGpu {
    calls: AtomicUsize,
}

impl FakeGpu {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl GpuVerifier for FakeGpu {
    fn kind(&self) -> GpuVerifierKind {
        GpuVerifierKind::Nras
    }

    fn verify<'a>(
        &'a self,
        gpus: &'a [GpuEvidence],
        _nonce: &'a [u8; 32],
        _policy: &'a GpuPolicy,
    ) -> GpuFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let gpus = gpus
                .iter()
                .zip(0u32..)
                .map(|(entry, index)| {
                    let gpu: Gpu = serde_json::from_slice(&entry.evidence)
                        .map_err(|e| AppraisalError::Failed(format!("gpu report: {e}")))?;
                    Ok(VerifiedGpu {
                        index,
                        device_id: gpu.device,
                        model: gpu.model,
                        driver_version: "575.51.03".into(),
                        vbios_version: "97.00.9a.00.01".into(),
                        cc_mode: gpu.mode == "cc",
                        nonce: gpu.nonce.unwrap_or_default(),
                    })
                })
                .collect::<Result<Vec<_>, AppraisalError>>()?;
            Ok(GpuVerdict {
                gpus,
                token_sha256: [0xab; 32],
            })
        })
    }
}
