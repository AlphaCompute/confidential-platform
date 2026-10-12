//! The `local` backend's decision, pure over its inputs: the pod's GPU evidence, our nonce, the
//! release-signed `gpu_policy`, the RIM cache, OCSP responses and the time. The steps and why
//! each exists are `docs/local-gpu-verifier.md`, "Appraisal, per GPU".

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256, Sha384};
use x509_cert::Certificate;

use super::cache::RimCache;
use super::cert::{self, OperationalFlag};
use super::opaque::{self, FeatureFlag};
use super::policy::{CcSource, Pinned};
use super::rim::{Rim, RimKind};
use super::{Refused, ocsp, rim, spdm};
use crate::AppraisalError;
use crate::gpu::{GpuEvidence, GpuPolicy, GpuVerdict, VerifiedGpu};

/// The architecture token this verifier appraises (the pod's word, checked for consistency; the
/// parse path comes from the certificate).
pub const ARCH: &str = "BLACKWELL";
/// The measurement index NVIDIA skips when NVDEC0 is disabled.
const NVDEC_MEASUREMENT: u32 = 35;
const NVDEC_ENABLED: u8 = 0xAA;
const NVDEC_DISABLED: u8 = 0x55;
const TOKEN_CONTEXT: &[u8] = b"alphacompute/gpu-local/v1";

/// Appraises every GPU; the first failure refuses the pod. `ocsp` holds responses beyond the
/// cache's (fetched online for this appraisal).
pub fn appraise(
    gpus: &[GpuEvidence],
    nonce: &[u8; 32],
    policy: &GpuPolicy,
    cache: &RimCache,
    ocsp: &[ocsp::Response],
    now: SystemTime,
) -> Result<GpuVerdict, AppraisalError> {
    let pinned = super::policy::pinned(policy.local.as_ref())?;
    let now = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let responses: Vec<&ocsp::Response> = cache.ocsp.iter().chain(ocsp).collect();
    let (rims, rejected) = usable_rims(cache, &pinned, &responses, now);

    let mut token = Sha256::new().chain_update(TOKEN_CONTEXT);
    let mut out = Vec::with_capacity(gpus.len());
    for (index, gpu) in gpus.iter().enumerate() {
        let i = u32::try_from(index).map_err(|_| AppraisalError::Failed("gpu index".into()))?;
        let (verified, driver, vbios) = appraise_gpu(
            i, gpu, nonce, policy, &pinned, &rims, &rejected, &responses, now,
        )
        .map_err(|e| AppraisalError::Failed(format!("local: GPU-{i}: {e}")))?;
        for part in [
            &gpu.evidence[..],
            &gpu.certificate[..],
            &driver[..],
            &vbios[..],
        ] {
            let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
            token.update(len.to_be_bytes());
            token.update(part);
        }
        out.push(verified);
    }
    Ok(GpuVerdict {
        gpus: out,
        token_sha256: token.finalize().into(),
    })
}

/// The certificate pairs (certificate, issuer) whose OCSP status the decision needs that no
/// cached response gives: device chains' CAs and the pinned RIMs' signing chains. The backend
/// queries the policy's OCSP endpoint for these, if it names one.
pub fn missing_statuses(
    gpus: &[GpuEvidence],
    pinned: &Pinned,
    cache: &RimCache,
    extra: &[ocsp::Response],
    now: SystemTime,
) -> Vec<(Certificate, Certificate)> {
    let now = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let mut pairs = Vec::new();
    for gpu in gpus {
        if let Ok(chain) = cert::parse_pem_chain(&gpu.certificate) {
            for pair in chain.get(1..).unwrap_or_default().windows(2) {
                if let [c, i] = pair {
                    pairs.push((c.clone(), i.clone()));
                }
            }
        }
    }
    for cached in &cache.rims {
        let digest: [u8; 48] = Sha384::digest(&cached.document).into();
        if pinned.rims.contains(&digest) {
            for pair in cached.certificates.windows(2) {
                if let [c, i] = pair {
                    pairs.push((c.clone(), i.clone()));
                }
            }
        }
    }
    let mut out: Vec<(Certificate, Certificate)> = Vec::new();
    for pair in pairs {
        if !out.contains(&pair)
            && ocsp::require_good(
                cache.ocsp.iter().chain(extra),
                &pair.0,
                &pair.1,
                now,
                pinned.ocsp,
            )
            .is_err()
        {
            out.push(pair);
        }
    }
    out
}

/// The pinned RIMs in the cache that verify now, and why the others did not.
fn usable_rims(
    cache: &RimCache,
    pinned: &Pinned,
    responses: &[&ocsp::Response],
    now: Duration,
) -> (Vec<Rim>, Vec<String>) {
    let mut usable = Vec::new();
    let mut rejected = Vec::new();
    for cached in &cache.rims {
        let digest: [u8; 48] = Sha384::digest(&cached.document).into();
        if !pinned.rims.contains(&digest) {
            continue;
        }
        let verified = (|| -> super::Result<Rim> {
            cert::verify_chain(&cached.certificates, &pinned.rim_roots, now)?;
            for pair in cached.certificates.windows(2) {
                if let [c, i] = pair {
                    ocsp::require_good(responses.iter().copied(), c, i, now, pinned.ocsp)?;
                }
            }
            let signer = cached
                .certificates
                .first()
                .ok_or_else(|| Refused("no signing certificate".into()))?;
            let signed = rim::verify_signed_info(
                &cached.signed_info,
                &cached.signature,
                &cert::p384_key(signer)?,
            )?;
            rim::parse_document(&cached.document, &signed)
        })();
        match verified {
            Ok(r) => usable.push(r),
            Err(e) => rejected.push(format!("{}: {e}", cached.id)),
        }
    }
    (usable, rejected)
}

#[allow(clippy::too_many_arguments)]
fn appraise_gpu(
    index: u32,
    gpu: &GpuEvidence,
    nonce: &[u8; 32],
    policy: &GpuPolicy,
    pinned: &Pinned,
    rims: &[Rim],
    rejected: &[String],
    responses: &[&ocsp::Response],
    now: Duration,
) -> super::Result<(VerifiedGpu, [u8; 48], [u8; 48])> {
    use super::refuse;
    if !gpu.arch.eq_ignore_ascii_case(ARCH) {
        return refuse(format!(
            "evidence is for architecture {:?}; only {ARCH} is appraised",
            gpu.arch
        ));
    }

    // 1. The device chain, to a pinned root.
    let chain = cert::parse_pem_chain(&gpu.certificate)?;
    cert::verify_chain(&chain, &pinned.device_roots, now)?;
    let (Some(leaf), Some(device)) = (chain.first(), chain.get(1)) else {
        return refuse("certificate chain is too short");
    };

    // 2. The certified hardware model; only the GSP responder carries a firmware identity.
    let hwmodel = cert::common_name(device)?;
    if hwmodel.split_whitespace().any(|w| w == "FSP") {
        return refuse(format!(
            "{hwmodel:?} is the FSP responder, which reports no driver or VBIOS identity; only \
             GSP evidence is appraised"
        ));
    }
    let model = policy
        .hwmodels
        .get(&hwmodel)
        .cloned()
        .ok_or_else(|| Refused(format!("hwmodel {hwmodel:?} is not in gpu_policy.hwmodels")))?;
    let chip = hwmodel
        .split_whitespace()
        .next()
        .ok_or_else(|| Refused("hwmodel is empty".into()))?;

    // 3. Revocation of every CA between the leaf (issued by the device) and the root.
    for pair in chain.get(1..).unwrap_or_default().windows(2) {
        if let [c, i] = pair {
            ocsp::require_good(responses.iter().copied(), c, i, now, pinned.ocsp)?;
        }
    }

    // 4. The certified firmware identity.
    let tcb = cert::tcb_info(leaf)?;
    let debug_state = [
        OperationalFlag::Debug,
        OperationalFlag::NotSecure,
        OperationalFlag::Recovery,
    ]
    .into_iter()
    .any(|flag| tcb.flag(flag));

    // 5. The signed report, over our nonce.
    let report = spdm::parse(&gpu.evidence)?;
    spdm::verify_signature(&report, &cert::p384_key(leaf)?)?;
    if report.nonce != *nonce {
        return refuse("report is not over this nonce");
    }

    // 6. Opaque data: the reported FWID is the certified one, and one the release accepts.
    let o = opaque::parse(report.opaque)?;
    if o.fwid() != Some(&tcb.fwid[..]) {
        return refuse("the report's FWID is not the one its certificate certifies");
    }
    if !pinned.fwids.contains(&tcb.fwid) {
        return refuse(format!(
            "FWID sha384:{} is not in gpu_policy.local.fwids",
            hex::encode(tcb.fwid)
        ));
    }
    let ppcie = o.feature_flag()? == Some(FeatureFlag::Ppcie);

    // 7. RIMs selected by what the GPU measures.
    let skip_nvdec = match o.nvdec0_status()? {
        NVDEC_DISABLED => true,
        NVDEC_ENABLED => false,
        other => {
            return refuse(format!(
                "NVDEC0 status {other:#04x} is neither 0xAA nor 0x55"
            ));
        }
    };
    let blocks: BTreeMap<u32, &[u8]> = report
        .blocks
        .iter()
        .map(|(i, b)| {
            let idx = u32::from(*i).checked_sub(1).ok_or_else(|| {
                Refused("block index 0 is not a valid SPDM measurement index".into())
            })?;
            Ok((idx, b.value.as_slice()))
        })
        .collect::<Result<_, Refused>>()?;
    let candidates: Vec<&Rim> = rims.iter().filter(|r| r.platform_model == chip).collect();
    let pick = |kind: RimKind| -> super::Result<&Rim> {
        let matched: Vec<&Rim> = candidates
            .iter()
            .copied()
            .filter(|r| r.kind == kind && matches(r, &blocks, skip_nvdec))
            .collect();
        let versions: BTreeSet<&str> = matched.iter().map(|r| r.version.as_str()).collect();
        match (matched.first(), versions.len()) {
            (Some(r), 1) => Ok(r),
            (Some(_), _) => refuse(format!(
                "the GPU's measurements match pinned {kind:?} RIMs of several versions \
                 ({versions:?})"
            )),
            (None, _) => refuse(format!(
                "no pinned {kind:?} RIM for {chip} in the cache matches the GPU's measurements \
                 ({} usable{})",
                candidates.iter().filter(|r| r.kind == kind).count(),
                if rejected.is_empty() {
                    String::new()
                } else {
                    format!("; not usable: {}", rejected.join("; "))
                }
            )),
        }
    };
    let driver = pick(RimKind::Driver)?;
    let vbios = pick(RimKind::Vbios)?;
    let active = |r: &Rim| -> BTreeSet<u32> {
        r.measurements
            .iter()
            .filter(|(_, g)| g.active)
            .map(|(i, _)| *i)
            .collect()
    };
    if let Some(i) = active(driver).intersection(&active(vbios)).next() {
        return refuse(format!(
            "measurement {i} is in both the driver and the VBIOS RIM"
        ));
    }
    if let Some(i) = blocks
        .keys()
        .find(|i| !driver.measurements.contains_key(i) && !vbios.measurements.contains_key(i))
    {
        return refuse(format!("measurement {i} is listed by neither RIM"));
    }
    let mut svn_types = BTreeSet::new();
    for record in driver.min_svns.iter().chain(&vbios.min_svns) {
        if !svn_types.insert(record.opaque_type) {
            return refuse(format!(
                "opaque record {} is in both the driver and the VBIOS RIM",
                record.opaque_type
            ));
        }
        match o.min_svn(record.opaque_type) {
            Some(svn) if u64::from(svn) >= record.min_svn => {}
            Some(svn) => {
                return refuse(format!(
                    "{} is {svn}, below the RIM's minimum {}",
                    record.name, record.min_svn
                ));
            }
            None => return refuse(format!("{} is not reported", record.name)),
        }
    }

    // 8. Versions from the signed RIMs; the firmware's own report must agree.
    let reported_driver = o.driver_version()?;
    if reported_driver != driver.version {
        return refuse(format!(
            "the GPU reports driver {reported_driver} but measures as {}",
            driver.version
        ));
    }
    let reported_vbios = o.vbios_version()?;
    if !reported_vbios.eq_ignore_ascii_case(&vbios.version) {
        return refuse(format!(
            "the GPU reports VBIOS {reported_vbios} but measures as {}",
            vbios.version
        ));
    }

    // 9. CC mode, from the signed indicator the release pins.
    let indicator: &[u8] = match pinned.cc_source {
        CcSource::Measurement => u8::try_from(pinned.cc_index)
            .ok()
            .and_then(|i| report.blocks.get(&i))
            .map(|b| b.value.as_slice())
            .ok_or_else(|| {
                Refused(format!(
                    "CC-mode measurement {} is missing",
                    pinned.cc_index
                ))
            })?,
        CcSource::Opaque => o
            .field(pinned.cc_index)
            .map(|f| f.data.as_slice())
            .ok_or_else(|| {
                Refused(format!(
                    "CC-mode opaque field {} is missing",
                    pinned.cc_index
                ))
            })?,
    };
    let production = pinned.cc_values.iter().any(|v| v.as_slice() == indicator);

    Ok((
        VerifiedGpu {
            index,
            device_id: cert::serial_decimal(leaf),
            model,
            driver_version: driver.version.clone(),
            vbios_version: vbios.version.clone(),
            cc_mode: production && !debug_state && !ppcie,
            nonce: report.nonce,
        },
        driver.digest,
        vbios.digest,
    ))
}

/// Every active golden value of `rim` is measured (NVDEC's measurement aside when disabled).
fn matches(rim: &Rim, blocks: &BTreeMap<u32, &[u8]>, skip_nvdec: bool) -> bool {
    rim.measurements
        .iter()
        .filter(|(i, g)| g.active && !(skip_nvdec && **i == NVDEC_MEASUREMENT))
        .all(|(i, g)| {
            blocks
                .get(i)
                .is_some_and(|v| g.alternatives.iter().any(|a| a.as_slice() == *v))
        })
}
