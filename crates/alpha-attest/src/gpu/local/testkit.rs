//! A synthetic NVIDIA world for the `local` backend's tests: a device PKI, GPUs with DICE leaf
//! certificates, signed SPDM reports, a RIM PKI with signed canonical RIMs, OCSP responses and a
//! complete `gpu_policy`. Shaped like NVIDIA's Blackwell samples (`testdata/gpu`) with the chip
//! named `GB110`.
//
// ponytail: G0-gpu-capture — the B300's chip string, BROM common name, TcbInfo, opaque data and
// measurement layout are assumed from NVIDIA's GB100 samples and the RIM service's GB110 RIM IDs;
// re-pin these tests against the first B300 capture.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use der::asn1::{Any, BitString, BitStringRef, GeneralizedTime, Null, OctetString, Utf8StringRef};
use der::{Decode, Encode};
use p384::ecdsa::signature::Signer;
use p384::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha384};
use x509_cert::Certificate;
use x509_cert::certificate::{TbsCertificate, Version};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspResponse, OcspResponseStatus, ResponderId,
    ResponseBytes, ResponseData, RevokedInfo, SingleResponse,
};

use super::cache::{CachedRim, RimCache};
use super::cert::{
    ECDSA_WITH_SHA384, Fwid, ID_EC_PUBLIC_KEY, SECP384R1, SHA384, TCG_DICE_TCB_INFO_BLACKWELL,
    TcbInfoAsn,
};
use super::policy::LocalPolicy;
use crate::gpu::{GpuEvidence, GpuPolicy, GpuVerifierKind};

pub const NOW: Duration = Duration::from_secs(1_800_000_000);
pub const NONCE: [u8; 32] = [0x4E; 32];
pub const CHIP: &str = "GB110";
pub const HWMODEL: &str = "GB110 A01 GSP BROM";
pub const DRIVER: &str = "595.58.03";
pub const VBIOS: &str = "97.00.88.00.0F";
/// `97.00.88.00.0F` as the opaque field's eight bytes.
pub const VBIOS_BYTES: [u8; 8] = [0x00, 0x88, 0x00, 0x97, 0x0F, 0, 0, 0];
pub const FWID: [u8; 48] = [0xF1; 48];
/// SPDM block 11 (RIM index 10) is one the driver RIM lists as inactive: measured, not compared.
pub const INACTIVE_BLOCK: u8 = 11;
/// RIM indices 0..=4 are the VBIOS's, 5..=9 the driver's, 10 inactive.
pub const BLOCKS: u8 = 11;
/// `Report::feature_flag` value meaning "the mode the pod's shape needs": SPT (1) for one GPU,
/// MPT (0) for several.
pub const POD_MODE: u64 = u64::MAX;

pub fn now() -> SystemTime {
    UNIX_EPOCH + NOW
}

pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 48]).unwrap()
}

/// The golden value of RIM index `i`.
pub fn golden(i: u32) -> Vec<u8> {
    vec![u8::try_from(i).unwrap() + 1; 48]
}

fn time(secs: u64) -> Time {
    Time::GeneralTime(GeneralizedTime::from_unix_duration(Duration::from_secs(secs)).unwrap())
}

fn sha384_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ECDSA_WITH_SHA384,
        parameters: None,
    }
}

pub struct Ca {
    pub cert: Certificate,
    pub key: SigningKey,
}

pub fn ext(oid: &str, critical: bool, value: Vec<u8>) -> Extension {
    Extension {
        extn_id: der::asn1::ObjectIdentifier::new_unwrap(oid),
        critical,
        extn_value: OctetString::new(value).unwrap(),
    }
}

pub fn ca_exts() -> Vec<Extension> {
    vec![
        ext(
            "2.5.29.19",
            true,
            BasicConstraints {
                ca: true,
                path_len_constraint: None,
            }
            .to_der()
            .unwrap(),
        ),
        ext(
            "2.5.29.15",
            true,
            KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
                .to_der()
                .unwrap(),
        ),
    ]
}

pub fn tcb_info_ext(fwid: [u8; 48], flags: &[u8]) -> Extension {
    let info = TcbInfoAsn {
        vendor: Some(Utf8StringRef::new("NVIDIA").unwrap()),
        model: Some(Utf8StringRef::new("GB110 A01 GSP").unwrap()),
        version: Some(Utf8StringRef::new("01").unwrap()),
        svn: Some(1),
        layer: Some(0),
        index: Some(0),
        fwids: Some(vec![Fwid {
            hash_alg: SHA384,
            digest: OctetString::new(fwid.to_vec()).unwrap(),
        }]),
        flags: Some(BitStringRef::new(0, flags).unwrap()),
        vendor_info: None,
        tcb_type: None,
        flags_mask: None,
        integrity_registers: None,
    };
    Extension {
        extn_id: TCG_DICE_TCB_INFO_BLACKWELL,
        critical: false,
        extn_value: OctetString::new(info.to_der().unwrap()).unwrap(),
    }
}

/// A certificate for `key` named `cn`, issued by `issuer` (self-signed when `None`).
pub fn issue(
    cn: &str,
    serial: &[u8],
    key: &SigningKey,
    issuer: Option<&Ca>,
    extensions: Vec<Extension>,
) -> Certificate {
    let subject = Name::from_str(&format!("CN={cn},O=NVIDIA Corporation")).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(serial).unwrap(),
        signature: sha384_alg(),
        issuer: issuer.map_or(subject.clone(), |i| i.cert.tbs_certificate.subject.clone()),
        validity: Validity {
            not_before: time(1_700_000_000),
            not_after: time(4_000_000_000),
        },
        subject,
        subject_public_key_info: SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some(Any::encode_from(&SECP384R1).unwrap()),
            },
            subject_public_key: BitString::from_bytes(point.as_bytes()).unwrap(),
        },
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let signer = issuer.map_or(key, |i| &i.key);
    let signature: Signature = signer.sign(&tbs.to_der().unwrap());
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sha384_alg(),
        signature: BitString::from_bytes(signature.to_der().as_bytes()).unwrap(),
    }
}

pub fn ca(cn: &str, seed: u8, issuer: Option<&Ca>) -> Ca {
    let key = key(seed);
    Ca {
        cert: issue(cn, &[seed], &key, issuer, ca_exts()),
        key,
    }
}

pub fn pem(certs: &[&Certificate]) -> Vec<u8> {
    let mut out = String::new();
    for c in certs {
        out.push_str("-----BEGIN CERTIFICATE-----\n");
        out.push_str(&BASE64_STANDARD.encode(c.to_der().unwrap()));
        out.push_str("\n-----END CERTIFICATE-----\n");
    }
    out.into_bytes()
}

/// An OCSP response about `cert`, signed by its issuer, `this_update` seconds before now.
pub fn ocsp_response(
    cert: &Certificate,
    issuer: &Ca,
    status: CertStatus,
    age: u64,
    nonce: Option<&[u8]>,
) -> Vec<u8> {
    let name = issuer.cert.tbs_certificate.subject.to_der().unwrap();
    let key = issuer
        .cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let gt = |secs: u64| {
        x509_ocsp::OcspGeneralizedTime(
            GeneralizedTime::from_unix_duration(Duration::from_secs(secs)).unwrap(),
        )
    };
    let this_update = NOW.as_secs() - age;
    let tbs = ResponseData {
        version: x509_ocsp::Version::V1,
        responder_id: ResponderId::ByName(issuer.cert.tbs_certificate.subject.clone()),
        produced_at: gt(this_update),
        responses: vec![SingleResponse {
            cert_id: CertId {
                hash_algorithm: AlgorithmIdentifierOwned {
                    oid: SHA384,
                    parameters: None,
                },
                issuer_name_hash: OctetString::new(Sha384::digest(&name).to_vec()).unwrap(),
                issuer_key_hash: OctetString::new(Sha384::digest(key).to_vec()).unwrap(),
                serial_number: cert.tbs_certificate.serial_number.clone(),
            },
            cert_status: status,
            this_update: gt(this_update),
            next_update: Some(gt(this_update + 86_400)),
            single_extensions: None,
        }],
        response_extensions: nonce.map(|n| {
            vec![ext(
                "1.3.6.1.5.5.7.48.1.2",
                false,
                OctetString::new(n.to_vec()).unwrap().to_der().unwrap(),
            )]
        }),
    };
    let signature: Signature = issuer.key.sign(&tbs.to_der().unwrap());
    let basic = BasicOcspResponse {
        tbs_response_data: tbs,
        signature_algorithm: sha384_alg(),
        signature: BitString::from_bytes(signature.to_der().as_bytes()).unwrap(),
        certs: None,
    };
    OcspResponse {
        response_status: OcspResponseStatus::Successful,
        response_bytes: Some(ResponseBytes {
            response_type: der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1"),
            response: OctetString::new(basic.to_der().unwrap()).unwrap(),
        }),
    }
    .to_der()
    .unwrap()
}

pub fn good() -> CertStatus {
    CertStatus::Good(Null)
}

pub fn revoked(reason: Option<x509_cert::ext::pkix::CrlReason>) -> CertStatus {
    CertStatus::Revoked(RevokedInfo {
        revocation_time: x509_ocsp::OcspGeneralizedTime(
            GeneralizedTime::from_unix_duration(NOW - Duration::from_secs(7200)).unwrap(),
        ),
        revocation_reason: reason,
    })
}

/// One golden measurement: RIM index, active, alternatives.
pub type Measurement = (u32, bool, Vec<Vec<u8>>);

/// A canonical SWID document in NVIDIA's shape.
pub fn rim_document(version: &str, platform: &str, measurements: &[Measurement]) -> String {
    let mut resources = String::new();
    for (index, active, alternatives) in measurements {
        let hashes: String = alternatives
            .iter()
            .enumerate()
            .map(|(n, v)| format!(" ns2:Hash{n}=\"{}\"", hex::encode(v)))
            .collect();
        resources.push_str(&format!(
            "\n        <ns0:Resource active=\"{}\" alternatives=\"{}\" index=\"{index}\" \
             name=\"Measurement_{index}\" size=\"48\" type=\"Measurement\"{hashes}></ns0:Resource>",
            if *active { "True" } else { "False" },
            alternatives.len(),
        ));
    }
    format!(
        "<SoftwareIdentity xmlns=\"{swid}\" xmlns:ns0=\"{swid}\" xmlns:ns2=\"{sha}\" \
         corpus=\"false\" name=\"{platform}\" patch=\"false\" supplemental=\"false\" tagId=\"t\" \
         tagVersion=\"0\" version=\"1.0\">\n    <ns0:Entity name=\"NVIDIA Corporation\" \
         role=\"softwareCreator tagCreator\"></ns0:Entity>\n    <ns0:Meta xmlns:ns1=\"{tcg}\" \
         colloquialVersion=\"{version}\" edition=\"GPU\" product=\"{platform}\" \
         ns1:PlatformModel=\"{platform}\"></ns0:Meta>\n    <ns0:Payload>{resources}\n    \
         </ns0:Payload>\n</SoftwareIdentity>",
        swid = super::rim::NS_SWID,
        sha = super::rim::NS_SHA384,
        tcg = super::rim::NS_TCG_RIM,
    )
}

/// A cache entry for `document`, signed by `signer` whose chain is `chain` (signer first).
pub fn rim_entry(
    id: &str,
    document: &str,
    signer: &SigningKey,
    chain: &[&Certificate],
) -> CachedRim {
    let digest = BASE64_STANDARD.encode(Sha384::digest(document.as_bytes()));
    let signed_info = format!(
        "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
         <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2006/12/xml-c14n11\">\
         </ds:CanonicalizationMethod><ds:SignatureMethod \
         Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384\"></ds:SignatureMethod>\
         <ds:Reference URI=\"\"><ds:Transforms><ds:Transform \
         Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform>\
         <ds:Transform Algorithm=\"http://www.w3.org/2006/12/xml-c14n11\"></ds:Transform>\
         </ds:Transforms><ds:DigestMethod \
         Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#sha384\"></ds:DigestMethod>\
         <ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
    );
    let signature: Signature = signer.sign(signed_info.as_bytes());
    CachedRim {
        id: id.into(),
        signed_info: signed_info.into_bytes(),
        document: document.as_bytes().to_vec(),
        signature: signature.to_bytes().to_vec(),
        certificates: chain.iter().map(|c| (*c).clone()).collect(),
    }
}

pub fn digest_key(document: &str) -> String {
    format!(
        "sha384:{}",
        hex::encode(Sha384::digest(document.as_bytes()))
    )
}

/// What a GPU reports; every field defaults to a production B300 matching the pinned RIMs.
#[derive(Clone)]
pub struct Report {
    pub nonce: [u8; 32],
    pub driver: String,
    pub vbios: [u8; 8],
    pub nvdec: u8,
    pub fwid: Option<[u8; 48]>,
    /// SPDM block index (1-based) to value.
    pub blocks: BTreeMap<u8, Vec<u8>>,
    pub feature_flag: Option<u64>,
}

impl Default for Report {
    fn default() -> Self {
        let mut blocks: BTreeMap<u8, Vec<u8>> = (0..u32::from(BLOCKS - 1))
            .map(|i| (u8::try_from(i + 1).unwrap(), golden(i)))
            .collect();
        blocks.insert(INACTIVE_BLOCK, vec![0xC0; 48]);
        Self {
            nonce: NONCE,
            driver: DRIVER.into(),
            vbios: VBIOS_BYTES,
            nvdec: 0x55,
            fwid: Some(FWID),
            blocks,
            feature_flag: Some(POD_MODE),
        }
    }
}

impl Report {
    /// The report's bytes, signed by `leaf`.
    pub fn sign(&self, leaf: &SigningKey) -> Vec<u8> {
        let mut opaque = Vec::new();
        let mut field = |kind: u16, data: &[u8]| {
            opaque.extend(kind.to_le_bytes());
            opaque.extend(u16::try_from(data.len()).unwrap().to_le_bytes());
            opaque.extend(data);
        };
        field(
            super::opaque::DRIVER_VERSION,
            format!("{}\0", self.driver).as_bytes(),
        );
        field(super::opaque::VBIOS_VERSION, &self.vbios);
        field(super::opaque::NVDEC0_STATUS, &[self.nvdec]);
        if let Some(fwid) = self.fwid {
            field(super::opaque::FWID, &fwid);
        }
        if let Some(flag) = self.feature_flag {
            field(super::opaque::OPAQUE_DATA_VERSION, &[1, 0]);
            field(super::opaque::FEATURE_FLAG, &flag.to_le_bytes()[..2]);
        }
        let mut record = Vec::new();
        for (index, value) in &self.blocks {
            record.push(*index);
            record.push(1);
            record.extend(u16::try_from(value.len() + 3).unwrap().to_le_bytes());
            record.push(1);
            record.extend(u16::try_from(value.len()).unwrap().to_le_bytes());
            record.extend(value);
        }
        let mut out = vec![0x11, 0xE0, 0x01, 0xFF];
        out.extend(self.nonce);
        out.push(0);
        out.extend([0x11, 0x60, 0, 0, u8::try_from(self.blocks.len()).unwrap()]);
        out.extend(&u32::try_from(record.len()).unwrap().to_le_bytes()[..3]);
        out.extend(record);
        out.extend([0x99; 32]);
        out.extend(u16::try_from(opaque.len()).unwrap().to_le_bytes());
        out.extend(opaque);
        let signature: Signature = leaf.sign(&out);
        out.extend(signature.to_bytes());
        out
    }
}

pub struct Gpu {
    pub brom: Ca,
    pub leaf: Ca,
}

/// Everything the backend sees, valid as built; tests break one piece at a time.
pub struct World {
    pub device_root: Ca,
    pub identity: Ca,
    pub ica: Ca,
    pub gpus: Vec<Gpu>,
    pub rim_root: Ca,
    pub rim_ca: Ca,
    pub rim_signer: Ca,
    pub rims: Vec<CachedRim>,
    pub ocsp: Vec<Vec<u8>>,
    pub policy: GpuPolicy,
}

pub fn driver_document() -> String {
    let mut m: Vec<Measurement> = (5..=9).map(|i| (i, true, vec![golden(i)])).collect();
    m.push((10, false, vec![vec![0; 48]]));
    rim_document(DRIVER, CHIP, &m)
}

pub fn vbios_document() -> String {
    let m: Vec<Measurement> = (0..=4).map(|i| (i, true, vec![golden(i)])).collect();
    rim_document(VBIOS, CHIP, &m)
}

impl World {
    pub fn new(count: u8) -> Self {
        let device_root = ca("Test Device Identity CA", 1, None);
        let identity = ca("Test GB110 Identity", 2, Some(&device_root));
        let ica = ca("Test GB110 Provisioner ICA", 3, Some(&identity));
        let gpus: Vec<Gpu> = (0..count)
            .map(|g| {
                let brom = Ca {
                    key: key(40 + g),
                    cert: issue(HWMODEL, &[40 + g], &key(40 + g), Some(&ica), ca_exts()),
                };
                let leaf_key = key(80 + g);
                let leaf = Ca {
                    cert: issue(
                        "GB110 A01 GSP FMC LF",
                        &[0x53, 80 + g],
                        &leaf_key,
                        Some(&brom),
                        vec![tcb_info_ext(FWID, &[0x80, 0, 0, 1])],
                    ),
                    key: leaf_key,
                };
                Gpu { brom, leaf }
            })
            .collect();
        let rim_root = ca("Test CoRIM signing Root CA", 10, None);
        let rim_ca = ca("Test Reference Value GB1XX CA", 11, Some(&rim_root));
        let signer_key = key(12);
        let rim_signer = Ca {
            cert: issue("RIM L4 Signer", &[12], &signer_key, Some(&rim_ca), vec![]),
            key: signer_key,
        };
        let chain = [&rim_signer.cert, &rim_ca.cert, &rim_root.cert];
        let rims = vec![
            rim_entry(
                "NV_GPU_CC_DRIVER_GB110_595.58.03",
                &driver_document(),
                &rim_signer.key,
                &chain,
            ),
            rim_entry(
                "NV_GPU_VBIOS_TEST_970088000F",
                &vbios_document(),
                &rim_signer.key,
                &chain,
            ),
        ];
        let mut ocsp = vec![
            ocsp_response(&ica.cert, &identity, good(), 3600, None),
            ocsp_response(&identity.cert, &device_root, good(), 3600, None),
            ocsp_response(&rim_signer.cert, &rim_ca, good(), 3600, None),
            ocsp_response(&rim_ca.cert, &rim_root, good(), 3600, None),
        ];
        for gpu in &gpus {
            ocsp.push(ocsp_response(&gpu.brom.cert, &ica, good(), 3600, None));
        }
        let der = |c: &Certificate| BASE64_STANDARD.encode(c.to_der().unwrap());
        let policy = GpuPolicy {
            allowed_models: vec!["B300".into()],
            min_driver_version: Some("580.0".into()),
            min_vbios_version: Some("97.00.00.00.00".into()),
            verifiers: vec![GpuVerifierKind::Local],
            nras_url: None,
            hwmodels: [(HWMODEL.to_owned(), "B300".to_owned())].into(),
            nras_keys: BTreeMap::new(),
            nras_cc_mode: None,
            local: Some(LocalPolicy {
                device_roots: vec![der(&device_root.cert)],
                rim_roots: vec![der(&rim_root.cert)],
                rims: [
                    (digest_key(&driver_document()), "driver".to_owned()),
                    (digest_key(&vbios_document()), "vbios".to_owned()),
                ]
                .into(),
                fwids: vec![format!("sha384:{}", hex::encode(FWID))],
                ocsp_max_age_secs: Some(86_400),
                ocsp_url: None,
                accept_certificate_hold: false,
            }),
        };
        Self {
            device_root,
            identity,
            ica,
            gpus,
            rim_root,
            rim_ca,
            rim_signer,
            rims,
            ocsp,
            policy,
        }
    }

    pub fn local_policy(&mut self) -> &mut LocalPolicy {
        self.policy.local.as_mut().unwrap()
    }

    pub fn cache(&self) -> RimCache {
        RimCache {
            rims: self.rims.clone(),
            ocsp: self
                .ocsp
                .iter()
                .map(|r| super::ocsp::parse(r).unwrap())
                .collect(),
        }
    }

    pub fn chain(&self, gpu: usize) -> Vec<u8> {
        let g = &self.gpus[gpu];
        pem(&[
            &g.leaf.cert,
            &g.brom.cert,
            &self.ica.cert,
            &self.identity.cert,
            &self.device_root.cert,
        ])
    }

    /// Every GPU's evidence, each from `report(index)`.
    pub fn evidence_with(&self, report: impl Fn(usize) -> Report) -> Vec<GpuEvidence> {
        let pod_mode = if self.gpus.len() == 1 { 1 } else { 0 };
        (0..self.gpus.len())
            .map(|i| {
                let mut r = report(i);
                if r.feature_flag == Some(POD_MODE) {
                    r.feature_flag = Some(pod_mode);
                }
                GpuEvidence {
                    arch: "BLACKWELL".into(),
                    evidence: r.sign(&self.gpus[i].leaf.key),
                    certificate: self.chain(i),
                }
            })
            .collect()
    }

    pub fn evidence(&self) -> Vec<GpuEvidence> {
        self.evidence_with(|_| Report::default())
    }

    pub fn appraise(
        &self,
        gpus: &[GpuEvidence],
    ) -> Result<crate::gpu::GpuVerdict, crate::AppraisalError> {
        super::appraise::appraise(gpus, &NONCE, &self.policy, &self.cache(), &[], now())
    }

    /// Replaces GPU `gpu`'s leaf with one certifying `fwid` with operational `flags`.
    pub fn reissue_leaf(&mut self, gpu: usize, fwid: [u8; 48], flags: &[u8]) {
        let g = &mut self.gpus[gpu];
        g.leaf.cert = issue(
            "GB110 A01 GSP FMC LF",
            &[0x53, 0x7F],
            &g.leaf.key,
            Some(&g.brom),
            vec![tcb_info_ext(fwid, flags)],
        );
    }
}

/// Decodes a certificate to check the builder's output parses like NVIDIA's.
pub fn roundtrip(cert: &Certificate) -> Certificate {
    Certificate::from_der(&cert.to_der().unwrap()).unwrap()
}
