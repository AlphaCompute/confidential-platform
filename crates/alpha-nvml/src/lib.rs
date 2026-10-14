//! The confidential-computing attestation of NVIDIA GPUs through NVML, opened at run time from
//! the `libnvidia-ml` the NVIDIA container toolkit injects into a GPU container, so nothing links
//! against it and a CPU-only pod never loads it.

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

use std::ffi::{c_int, c_uint, c_void};
use std::path::Path;

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::{Serialize, Serializer};

/// Where the SPDM `GET_MEASUREMENTS` request that opens the report carries the requester's nonce.
const NONCE_OFFSET: usize = 4;
const NVML: &str = "libnvidia-ml.so.1";

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct GpuEvidence {
    /// The SPDM `GET_MEASUREMENTS` request and the GPU's signed response.
    #[serde(serialize_with = "base64url")]
    pub evidence: Vec<u8>,
    /// The device certificate chain as NVML returns it, PEM text ending in NVIDIA's root.
    #[serde(serialize_with = "base64url")]
    pub certificate_chain: Vec<u8>,
}

fn base64url<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&BASE64_URL_SAFE_NO_PAD.encode(bytes))
}

/// How many GPUs the pod was given: the toolkit injects `/dev/nvidia<N>` for each one.
pub fn count_devices(dev: &Path) -> Result<usize, String> {
    let entries = std::fs::read_dir(dev).map_err(|e| format!("{}: {e}", dev.display()))?;
    Ok(entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix("nvidia"))
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
        .count())
}

/// The first `size` bytes of an NVML output buffer, refused when NVML claims more than the
/// buffer holds or nothing at all.
fn filled(what: &str, buffer: &[u8], size: c_uint) -> Result<Vec<u8>, String> {
    usize::try_from(size)
        .ok()
        .filter(|&n| n > 0)
        .and_then(|n| buffer.get(..n))
        .map(<[u8]>::to_vec)
        .ok_or_else(|| {
            format!(
                "{what}: NVML reports {size} bytes in a {}-byte buffer",
                buffer.len()
            )
        })
}

/// One GPU's evidence out of NVML's buffers, refused unless the report opens with our nonce.
fn assemble(
    nonce: &[u8; 32],
    report: &[u8],
    report_size: c_uint,
    chain: &[u8],
    chain_size: c_uint,
) -> Result<GpuEvidence, String> {
    let evidence = filled("attestation report", report, report_size)?;
    let certificate_chain = filled("certificate chain", chain, chain_size)?;
    let echoed = NONCE_OFFSET
        .checked_add(nonce.len())
        .and_then(|end| evidence.get(NONCE_OFFSET..end));
    if echoed != Some(nonce.as_slice()) {
        return Err("attestation report is not over our nonce".into());
    }
    Ok(GpuEvidence {
        evidence,
        certificate_chain,
    })
}

// Layouts and entry points from `nvml.h` of NVML API 13, as shipped in CUDA 13.2.2
// (`cuda_nvml_dev` 13.2.86, driver 595.71.05), the header of the 595 driver branch.
const CERT_CHAIN_SIZE: usize = 0x1000;
const ATTESTATION_CERT_CHAIN_SIZE: usize = 0x1400;
const CEC_NONCE_SIZE: usize = 0x20;
const ATTESTATION_REPORT_SIZE: usize = 0x2000;
const CEC_ATTESTATION_REPORT_SIZE: usize = 0x1000;

/// `nvmlConfComputeGpuCertificate_t`.
#[repr(C)]
struct GpuCertificate {
    cert_chain_size: c_uint,
    attestation_cert_chain_size: c_uint,
    cert_chain: [u8; CERT_CHAIN_SIZE],
    attestation_cert_chain: [u8; ATTESTATION_CERT_CHAIN_SIZE],
}

/// `nvmlConfComputeGpuAttestationReport_t`; `nonce` is the input.
#[repr(C)]
struct GpuAttestationReport {
    is_cec_attestation_report_present: c_uint,
    attestation_report_size: c_uint,
    cec_attestation_report_size: c_uint,
    nonce: [u8; CEC_NONCE_SIZE],
    attestation_report: [u8; ATTESTATION_REPORT_SIZE],
    cec_attestation_report: [u8; CEC_ATTESTATION_REPORT_SIZE],
}

type Device = *mut c_void;
type Init = unsafe extern "C" fn() -> c_int;
type GetCount = unsafe extern "C" fn(*mut c_uint) -> c_int;
type GetHandle = unsafe extern "C" fn(c_uint, *mut Device) -> c_int;
type GetCertificate = unsafe extern "C" fn(Device, *mut GpuCertificate) -> c_int;
type GetReport = unsafe extern "C" fn(Device, *mut GpuAttestationReport) -> c_int;

/// NVML, loaded and initialized once for the life of the process.
pub struct Nvml {
    get_count: GetCount,
    get_handle: GetHandle,
    get_certificate: GetCertificate,
    get_report: GetReport,
    gpus: usize,
    // Owns the code the pointers above point into; dropped last.
    _library: libloading::Library,
}

fn check(call: &str, status: c_int) -> Result<(), String> {
    match status {
        0 => Ok(()),
        e => Err(format!("{call}: NVML error {e}")),
    }
}

impl Nvml {
    /// NVML for a container given `gpus` GPUs.
    pub fn open(gpus: usize) -> Result<Self, String> {
        // SAFETY: loading runs the library's initializers; libnvidia-ml is NVIDIA's own library,
        // injected by the container toolkit, and its initializers have no preconditions on us.
        let library =
            unsafe { libloading::Library::new(NVML) }.map_err(|e| format!("{NVML}: {e}"))?;
        let symbol = |e: libloading::Error| format!("{NVML}: {e}");
        // SAFETY: each type is the prototype `nvml.h` declares for the symbol named, and every
        // pointer is copied out only into `Nvml`, which keeps `library` loaded as long as it lives.
        let (init, nvml) = unsafe {
            let init = *library.get::<Init>(b"nvmlInit_v2\0").map_err(symbol)?;
            let nvml = Nvml {
                get_count: *library.get(b"nvmlDeviceGetCount_v2\0").map_err(symbol)?,
                get_handle: *library
                    .get(b"nvmlDeviceGetHandleByIndex_v2\0")
                    .map_err(symbol)?,
                get_certificate: *library
                    .get(b"nvmlDeviceGetConfComputeGpuCertificate\0")
                    .map_err(symbol)?,
                get_report: *library
                    .get(b"nvmlDeviceGetConfComputeGpuAttestationReport\0")
                    .map_err(symbol)?,
                gpus,
                _library: library,
            };
            (init, nvml)
        };
        // SAFETY: `nvmlInit_v2` takes no arguments, and `nvml` keeps the library loaded.
        check("nvmlInit_v2", unsafe { init() })?;
        Ok(nvml)
    }

    /// Evidence over `nonce` from every GPU, in NVML's index order; refused if NVML sees a
    /// different number of GPUs than the container was given.
    pub fn collect(&self, nonce: &[u8; 32]) -> Result<Vec<GpuEvidence>, String> {
        let mut count: c_uint = 0;
        // SAFETY: `count` is a valid, writable `unsigned int` for the duration of the call.
        check("nvmlDeviceGetCount_v2", unsafe {
            (self.get_count)(&mut count)
        })?;
        if usize::try_from(count).ok() != Some(self.gpus) {
            return Err(format!("NVML sees {count} GPUs, the pod has {}", self.gpus));
        }
        (0..count).map(|index| self.device(index, nonce)).collect()
    }

    fn device(&self, index: c_uint, nonce: &[u8; 32]) -> Result<GpuEvidence, String> {
        let mut device: Device = std::ptr::null_mut();
        // SAFETY: `device` is a valid, writable handle slot; `index` is below the device count.
        check("nvmlDeviceGetHandleByIndex_v2", unsafe {
            (self.get_handle)(index, &mut device)
        })?;
        let mut report = Box::new(GpuAttestationReport {
            is_cec_attestation_report_present: 0,
            attestation_report_size: 0,
            cec_attestation_report_size: 0,
            nonce: *nonce,
            attestation_report: [0; ATTESTATION_REPORT_SIZE],
            cec_attestation_report: [0; CEC_ATTESTATION_REPORT_SIZE],
        });
        // SAFETY: `device` came from NVML; `report` is an initialized struct of the header's
        // layout, exclusively borrowed for the call, which writes only within it.
        check("nvmlDeviceGetConfComputeGpuAttestationReport", unsafe {
            (self.get_report)(device, &mut *report)
        })?;
        let mut certificate = Box::new(GpuCertificate {
            cert_chain_size: 0,
            attestation_cert_chain_size: 0,
            cert_chain: [0; CERT_CHAIN_SIZE],
            attestation_cert_chain: [0; ATTESTATION_CERT_CHAIN_SIZE],
        });
        // SAFETY: as above, for the certificate struct.
        check("nvmlDeviceGetConfComputeGpuCertificate", unsafe {
            (self.get_certificate)(device, &mut *certificate)
        })?;
        assemble(
            nonce,
            &report.attestation_report,
            report.attestation_report_size,
            &certificate.attestation_cert_chain,
            certificate.attestation_cert_chain_size,
        )
        .map_err(|e| format!("GPU {index}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_over(nonce: &[u8; 32]) -> Vec<u8> {
        let mut report = vec![0x11, 0xe0, 0x01, 0xff];
        report.extend_from_slice(nonce);
        report.extend_from_slice(&[0xab; 64]);
        report
    }

    #[test]
    fn assembles_only_what_nvml_filled_over_our_nonce() {
        let nonce = [0x5a; 32];
        let mut report = report_over(&nonce);
        let size = report.len() as c_uint;
        report.resize(ATTESTATION_REPORT_SIZE, 0);
        let chain = b"-----BEGIN CERTIFICATE-----\0\0\0";
        let gpu = assemble(&nonce, &report, size, chain, 27).unwrap();
        assert_eq!(gpu.evidence, report_over(&nonce));
        assert_eq!(gpu.certificate_chain, &chain[..27]);

        let too_long = ATTESTATION_REPORT_SIZE as c_uint + 1;
        assert!(assemble(&nonce, &report, too_long, chain, 27).is_err());
        assert!(assemble(&nonce, &report, size, chain, 31).is_err());
        assert!(assemble(&nonce, &report, 0, chain, 27).is_err());
        assert!(assemble(&nonce, &report, size, chain, 0).is_err());
        assert!(assemble(&nonce, &report, 20, chain, 27).is_err());
        let error = assemble(&[0; 32], &report, size, chain, 27).unwrap_err();
        assert!(error.contains("nonce"), "{error}");
    }
}
