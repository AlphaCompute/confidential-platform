//! What a Kata confidential pod reads about itself, from inside one of its containers: a TDX quote
//! (on an SNP runtime class, an SEV-SNP attestation report and the VCEK the host attached) over our
//! `report_data`, the CCEL boot events when the source returns them, the init-data the pod booted
//! with, and one attestation report per passed-through GPU, which the CoCo attestation agent's
//! NVIDIA attester collects.
//!
//! Nothing here is trusted by the KMS. The quote is signed by the TD, the report by the chip's
//! VCEK; the init-data is checked against MRCONFIGID or HOST_DATA; GPU reports are verified by the
//! GPU backend. A source that lies only makes the attestation fail.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use alpha_attest::{CpuEvidence, CpuKind, EVIDENCE_FORMAT_V2, EvidenceV2, GpuEvidence};
use alpha_core::coco::{RuntimeClass, Tee};
use base64::Engine;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Error, boot_events, http_body};

/// The CoCo attestation agent's REST API (api-server-rest) inside the pod VM, reachable from
/// every container of the pod. Q11: every container is measured and pinned by the policy, so
/// pod-local access to it is acceptable.
pub const ATTESTATION_AGENT: &str = "127.0.0.1:8006";
/// The kernel's TSM report interface, the fallback when the agent's endpoint is off.
pub const TSM_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";
/// The pod's init-data annotation, projected into the runtime container by a downward-API volume
/// that `alpha coco render` declares. The host could put anything here; the KMS refuses anything
/// that is not the digest in MRCONFIGID.
pub const INITDATA_PATH: &str = "/run/alpha-pod/cc_init_data";
/// The key under which the attestation agent's additional evidence carries NVIDIA devices (the
/// `nvidia` TEE of guest-components' `kbs-types`).
pub const NVIDIA_TEE: &str = "nvidia";
/// The architecture token of an NVSwitch in NVIDIA's device evidence. Switches are not GPUs: they
/// are left out of the GPU count and not appraised yet (protected-PCIe mode is after Dec 1).
pub const NVSWITCH_ARCH: &str = "LS10";

const TIMEOUT: Duration = Duration::from_secs(30);

/// configfs-tsm's `provider` for an SEV-SNP guest.
pub const SEV_GUEST_PROVIDER: &str = "sev_guest";
/// The SNP attestation report's length and where its `report_data` sits.
const SNP_REPORT_LEN: usize = 0x4A0;
const SNP_REPORT_DATA: std::ops::Range<usize> = 0x50..0x90;
const SNP_KEY_INFO: std::ops::Range<usize> = 0x48..0x4C;
/// The certificate table GUIDs (GHCB specification, `MSG_REPORT_REQ` extended request) of the keys
/// that sign a report, in the byte order the host tooling (virtee's `sev` crate) writes them.
const VCEK_GUID: [u8; 16] = guid(
    0x63da758d,
    0xe664,
    0x4564,
    [0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd],
);
const VLEK_GUID: [u8; 16] = guid(
    0xa8074bc2,
    0xa25a,
    0x483e,
    [0xaa, 0xe6, 0x39, 0xc0, 0x45, 0xa0, 0xb8, 0xa1],
);

const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> [u8; 16] {
    let (a, b, c) = (a.to_be_bytes(), b.to_be_bytes(), c.to_be_bytes());
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6],
        d[7],
    ]
}

/// Where the TDX quote comes from; chosen by `ALPHACOMPUTE_QUOTE_SOURCE`, which the agent policy
/// pins with the rest of the runtime container's environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuoteSource {
    /// The attestation agent; `report_data` reaches the quote as hex SHA-256 of ours.
    AttestationAgent,
    /// configfs-tsm; `report_data` reaches the quote byte for byte.
    ConfigfsTsm,
}

/// One quote and, when the source has them, the CCEL boot events.
pub fn quote(
    source: QuoteSource,
    report_data: &[u8; 64],
) -> Result<(Vec<u8>, Vec<alpha_attest::EventLogEntry>), Error> {
    match source {
        QuoteSource::AttestationAgent => agent_quote(ATTESTATION_AGENT, report_data),
        QuoteSource::ConfigfsTsm => Ok((
            tsm_quote(Path::new(TSM_REPORT_DIR), report_data)?,
            Vec::new(),
        )),
    }
}

/// The runtime data the agent is given: 64 ASCII bytes, which its TDX attester places in
/// `report_data` as they are. The appraisal accepts exactly this form.
pub fn agent_runtime_data(report_data: &[u8; 64]) -> String {
    hex::encode(Sha256::digest(report_data))
}

#[derive(Deserialize)]
struct AgentTdxEvidence {
    quote: String,
    #[serde(default)]
    cc_eventlog: Option<String>,
}

fn agent_quote(
    addr: &str,
    report_data: &[u8; 64],
) -> Result<(Vec<u8>, Vec<alpha_attest::EventLogEntry>), Error> {
    let path = format!(
        "/aa/evidence?runtime_data={}",
        agent_runtime_data(report_data)
    );
    let body = tcp_get(addr, &path)?;
    let evidence: AgentTdxEvidence = serde_json::from_slice(&body)
        .map_err(|e| Error::Agent(format!("attestation agent evidence: {e}")))?;
    let quote = BASE64_STANDARD
        .decode(evidence.quote.trim())
        .map_err(|_| Error::Agent("attestation agent quote is not base64".into()))?;
    check_report_data(&quote, agent_runtime_data(report_data).as_bytes())?;
    let events = match evidence.cc_eventlog {
        Some(log) if !log.is_empty() => boot_events(
            &BASE64_STANDARD
                .decode(log.trim())
                .map_err(|_| Error::Agent("cc_eventlog is not base64".into()))?,
        )?,
        _ => Vec::new(),
    };
    Ok((quote, events))
}

/// Where a TDX quote's `report_data` sits. Every TDX quote starts with a 48-byte header (version
/// at 0, TEE type 0x81 at 4). Version 4 follows it with the TD report body, `report_data` at 520
/// in it. Version 5 (TDX 1.5) puts a body type and a body size between the two; its TD 1.0
/// (type 2) and TD 1.5 (type 3) bodies both keep `report_data` at 520.
fn report_data_offset(quote: &[u8]) -> Result<usize, Error> {
    // Header, then report_data at 520 in the body; v5 adds a 2-byte type and 4-byte size first.
    const V4: usize = 48 + 520;
    const V5: usize = 48 + 2 + 4 + 520;
    const TDX: u32 = 0x81;
    let le16 = |at: std::ops::Range<usize>| {
        quote
            .get(at)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map(u16::from_le_bytes)
    };
    let tee = quote
        .get(4..8)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_le_bytes);
    if tee != Some(TDX) {
        return Err(Error::Agent("the quote is not a TDX quote".into()));
    }
    match le16(0..2) {
        Some(4) => Ok(V4),
        Some(5) => match le16(48..50) {
            Some(2 | 3) => Ok(V5),
            other => Err(Error::Agent(format!(
                "TDX quote v5 body type {other:?} is not a TD report"
            ))),
        },
        other => Err(Error::Agent(format!(
            "TDX quote version {other:?} is not 4 or 5"
        ))),
    }
}

/// Checked here so a source that drops or reshapes our data fails at the pod, with a reason,
/// rather than as an opaque refusal at the KMS (which parses either quote version itself).
fn check_report_data(quote: &[u8], expected: &[u8]) -> Result<(), Error> {
    let offset = report_data_offset(quote)?;
    let quoted = quote
        .get(offset..offset.saturating_add(64))
        .ok_or_else(|| Error::Agent("the quote is too short for its version".into()))?;
    if quoted != expected {
        return Err(Error::Agent(
            "the quote's report_data is not the runtime data asked for".into(),
        ));
    }
    Ok(())
}

/// A fresh configfs-tsm entry name. Random, not the PID (1 for most container entrypoints), so
/// two containers of one pod VM never share an entry.
fn tsm_entry_name() -> Result<String, Error> {
    let mut id = [0u8; 8];
    getrandom::fill(&mut id).map_err(|e| Error::Agent(format!("configfs-tsm entry name: {e}")))?;
    Ok(format!("alpha-{}", hex::encode(id)))
}

/// One quote from an entry of our own, created for this report and removed after it; an entry
/// that already exists is never reused.
fn tsm_quote(dir: &Path, report_data: &[u8; 64]) -> Result<Vec<u8>, Error> {
    let (quote, _) = with_tsm_entry(dir, |entry| tsm_report(entry, report_data, false))?;
    check_report_data(&quote, report_data)?;
    Ok(quote)
}

fn with_tsm_entry<T>(
    dir: &Path,
    report: impl FnOnce(&Path) -> Result<T, Error>,
) -> Result<T, Error> {
    let entry = dir.join(tsm_entry_name()?);
    fs::create_dir(&entry).map_err(|e| Error::Io(entry.display().to_string(), e))?;
    let result = report(&entry);
    let _ = fs::remove_dir(&entry);
    result
}

/// Writes `inblob` and reads `outblob` (and with `aux`, `auxblob`) in an existing entry. The
/// kernel's `generation` counts writes to the entry: if it moved between our write and our last
/// read, someone else wrote to the entry and the report may answer their data, so it is refused.
fn tsm_report(
    entry: &Path,
    report_data: &[u8; 64],
    aux: bool,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let io = |what: &str| {
        let what = format!("{}/{what}", entry.display());
        move |e| Error::Io(what, e)
    };
    let generation = || -> Result<u64, Error> {
        fs::read_to_string(entry.join("generation"))
            .map_err(io("generation"))?
            .trim()
            .parse()
            .map_err(|_| Error::Agent("configfs-tsm generation is not a number".into()))
    };
    fs::write(entry.join("inblob"), report_data).map_err(io("inblob"))?;
    let written = generation()?;
    let out = fs::read(entry.join("outblob")).map_err(io("outblob"))?;
    // The host may attach no certificates; then the KMS fetches the VCEK from KDS.
    let auxblob = if aux {
        match fs::read(entry.join("auxblob")) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(io("auxblob")(e)),
        }
    } else {
        Vec::new()
    };
    if generation()? != written {
        return Err(Error::Agent(
            "the configfs-tsm entry was written to while the quote was read".into(),
        ));
    }
    Ok((out, auxblob))
}

/// An SEV-SNP report over `report_data` from configfs-tsm, and the VCEK or VLEK the host attached
/// to it (empty when it attached none), from an entry of our own.
pub fn snp_report(dir: &Path, report_data: &[u8; 64]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    with_tsm_entry(dir, |entry| snp_report_in(entry, report_data))
}

fn snp_report_in(entry: &Path, report_data: &[u8; 64]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let provider = fs::read_to_string(entry.join("provider"))
        .map_err(|e| Error::Io(format!("{}/provider", entry.display()), e))?;
    if provider.trim() != SEV_GUEST_PROVIDER {
        return Err(Error::Agent(format!(
            "configfs-tsm provider {:?} is not {SEV_GUEST_PROVIDER}: this is not an SEV-SNP guest",
            provider.trim()
        )));
    }
    let (report, auxblob) = tsm_report(entry, report_data, true)?;
    if report.len() != SNP_REPORT_LEN {
        return Err(Error::Agent(format!(
            "the SNP report is {} bytes, not {SNP_REPORT_LEN}",
            report.len()
        )));
    }
    if report.get(SNP_REPORT_DATA) != Some(report_data.as_slice()) {
        return Err(Error::Agent(
            "the SNP report's report_data is not the data asked for".into(),
        ));
    }
    // KEY_INFO bits 4:2 name the key that signed the report: 0 the VCEK, 1 the VLEK.
    let key_info = report
        .get(SNP_KEY_INFO)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_le_bytes)
        .unwrap_or_default();
    let guid = match (key_info >> 2) & 0b111 {
        0 => VCEK_GUID,
        1 => VLEK_GUID,
        other => {
            return Err(Error::Agent(format!(
                "the SNP report is signed by key {other}, not a VCEK or VLEK"
            )));
        }
    };
    let vek = cert_from_table(&auxblob, &guid)?;
    Ok((report, vek))
}

/// The certificate filed under `guid` in a certificate table, empty if none is: 24-byte entries
/// (GUID, then offset and length, little-endian and relative to the table) up to an all-zero one.
/// Untrusted: the KMS verifies whatever is sent under its pinned chain.
pub fn cert_from_table(table: &[u8], guid: &[u8; 16]) -> Result<Vec<u8>, Error> {
    let bad = |m: &str| Error::Agent(format!("SNP certificate table: {m}"));
    if table.is_empty() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    for entry in table.chunks(24) {
        let entry = <&[u8; 24]>::try_from(entry).map_err(|_| bad("truncated entry"))?;
        let (id, rest) = entry.split_at(16);
        if id.iter().all(|b| *b == 0) {
            return Ok(found);
        }
        if id != guid {
            continue;
        }
        let le32 = |at: usize| -> Option<usize> {
            rest.get(at..at.saturating_add(4))
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_le_bytes)
                .and_then(|v| usize::try_from(v).ok())
        };
        let (offset, length) = le32(0).zip(le32(4)).ok_or_else(|| bad("entry"))?;
        found = table
            .get(offset..offset.saturating_add(length))
            .ok_or_else(|| bad("an entry points outside the table"))?
            .to_vec();
    }
    Err(bad("no terminating entry"))
}

fn tcp_get(addr: &str, path: &str) -> Result<Vec<u8>, Error> {
    let io = |what: String| move |e| Error::Io(what.clone(), e);
    let mut stream = TcpStream::connect(addr).map_err(io(format!("connect {addr}")))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(io("timeout".into()))?;
    let request =
        format!("GET {path} HTTP/1.0\r\nHost: {addr}\r\nAccept: application/json\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(io("write to the attestation agent".into()))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(io("read from the attestation agent".into()))?;
    http_body(&response)
}

/// The init-data the pod booted with, from the annotation's projection: the annotation is
/// base64 of the gzip of the TOML document, as Kata reads it.
pub fn initdata(path: &Path) -> Result<Vec<u8>, Error> {
    let text = fs::read_to_string(path).map_err(|e| Error::Io(path.display().to_string(), e))?;
    decode_annotation(&text)
}

pub fn decode_annotation(text: &str) -> Result<Vec<u8>, Error> {
    let gz = BASE64_STANDARD
        .decode(text.trim())
        .map_err(|_| Error::Agent("init-data annotation is not base64".into()))?;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz.as_slice())
        .take((alpha_core::coco::MAX_INITDATA_BYTES as u64).saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| Error::Agent(format!("init-data annotation is not gzip: {e}")))?;
    if out.len() > alpha_core::coco::MAX_INITDATA_BYTES {
        return Err(Error::Agent("init-data is too large".into()));
    }
    Ok(out)
}

#[derive(Deserialize)]
struct NvidiaEvidence {
    device_evidence_list: Vec<NvidiaDevice>,
}

/// One device as the agent's NVIDIA attester reports it: NVIDIA's attestation SDK output, the
/// report and the certificate chain base64-encoded, as NRAS takes them.
#[derive(Deserialize)]
struct NvidiaDevice {
    arch: String,
    evidence: String,
    certificate: String,
}

/// One report per GPU over `nonce`, from the attestation agent's device evidence
/// (`GET /aa/additional-evidence`): the agent's NVIDIA attester asks every confidential GPU for a
/// report over the first 32 bytes of the runtime data, so the nonce is sent as the runtime data,
/// raw (`encoding=base64`). Exactly `count` GPUs, NVSwitches left out. Untrusted, like everything
/// here: the GPU backend verifies every report, and its nonce, at the KMS. A pod on the CPU class
/// (`kata-qemu-tdx`) has a Revision without GPUs, so `count` is 0 and the agent is not asked.
pub fn agent_gpu_evidence(
    addr: &str,
    nonce: &[u8; 32],
    count: usize,
) -> Result<Vec<GpuEvidence>, Error> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let path = format!(
        "/aa/additional-evidence?runtime_data={}&encoding=base64",
        BASE64_URL_SAFE_NO_PAD.encode(nonce)
    );
    let body = tcp_get(addr, &path)?;
    if body.iter().all(u8::is_ascii_whitespace) {
        return Err(Error::Agent(
            "the attestation agent has no device evidence; is its NVIDIA attester running?".into(),
        ));
    }
    let mut devices: serde_json::Map<String, Value> = serde_json::from_slice(&body)
        .map_err(|e| Error::Agent(format!("attestation agent device evidence: {e}")))?;
    let nvidia: NvidiaEvidence = devices
        .remove(NVIDIA_TEE)
        .ok_or_else(|| Error::Agent("the attestation agent reports no NVIDIA device".into()))
        .and_then(|v| {
            serde_json::from_value(v)
                .map_err(|e| Error::Agent(format!("NVIDIA device evidence: {e}")))
        })?;
    let decode = |what: &str, text: &str| {
        BASE64_STANDARD
            .decode(text.trim())
            .map_err(|_| Error::Agent(format!("NVIDIA device {what} is not base64")))
    };
    let gpus = nvidia
        .device_evidence_list
        .into_iter()
        .filter(|d| !d.arch.eq_ignore_ascii_case(NVSWITCH_ARCH))
        .map(|d| {
            Ok(GpuEvidence {
                evidence: decode("evidence", &d.evidence)?,
                certificate: decode("certificate", &d.certificate)?,
                arch: d.arch,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    if gpus.len() != count {
        return Err(Error::Agent(format!(
            "{} GPUs reported, the init-data expects {count}",
            gpus.len()
        )));
    }
    Ok(gpus)
}

/// Everything a pod sends: `alphacompute-evidence/2`. The quote comes from `quote`; GPU reports
/// always come from the attestation agent, whichever source gives the quote.
pub struct Source {
    pub quote: QuoteSource,
    pub initdata: Vec<u8>,
    pub runtime_class: String,
    pub gpu_count: usize,
}

impl Source {
    pub fn evidence(&self, report_data: &[u8; 64]) -> Result<EvidenceV2, Error> {
        let tee = RuntimeClass::from_name(&self.runtime_class)
            .map(RuntimeClass::tee)
            .ok_or_else(|| {
                Error::Agent(format!(
                    "runtime class {:?} is not supported",
                    self.runtime_class
                ))
            })?;
        let cpu = match (tee, self.quote) {
            (Tee::Tdx, source) => {
                let (quote, event_log) = quote(source, report_data)?;
                CpuEvidence {
                    kind: CpuKind::Tdx,
                    quote,
                    event_log,
                    vek: Vec::new(),
                }
            }
            (Tee::Snp, QuoteSource::ConfigfsTsm) => {
                let (report, vek) = snp_report(Path::new(TSM_REPORT_DIR), report_data)?;
                CpuEvidence {
                    kind: CpuKind::Snp,
                    quote: report,
                    event_log: Vec::new(),
                    vek,
                }
            }
            // ponytail: snp-capture — the attestation agent's SNP evidence (guest-components'
            // `SnpEvidence`, a serde rendering of the report) is read once an SNP pod shows its
            // exact shape on the pinned guest-components; until then SNP pods use configfs-tsm.
            (Tee::Snp, QuoteSource::AttestationAgent) => {
                return Err(Error::Agent(
                    "on SEV-SNP the report is read from configfs-tsm: set ALPHACOMPUTE_QUOTE_SOURCE=coco-tsm"
                        .into(),
                ));
            }
        };
        let gpus = agent_gpu_evidence(
            ATTESTATION_AGENT,
            &alpha_attest::gpu::gpu_nonce(report_data),
            self.gpu_count,
        )?;
        Ok(EvidenceV2 {
            format: EVIDENCE_FORMAT_V2.into(),
            cpu,
            gpus,
            initdata: self.initdata.clone(),
            runtime_class: self.runtime_class.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    use super::*;

    /// A TDX quote v4 shell over `report_data`.
    fn quote_with(report_data: &[u8]) -> Vec<u8> {
        let mut q = vec![0u8; 48 + 584 + 16];
        q[0..2].copy_from_slice(&4u16.to_le_bytes());
        q[4..8].copy_from_slice(&0x81u32.to_le_bytes());
        q[568..632].copy_from_slice(report_data);
        q
    }

    /// A TDX quote v5 shell (TD 1.5 body, type 3) over `report_data`.
    fn quote_v5_with(report_data: &[u8]) -> Vec<u8> {
        let mut q = vec![0u8; 48 + 6 + 648 + 16];
        q[0..2].copy_from_slice(&5u16.to_le_bytes());
        q[4..8].copy_from_slice(&0x81u32.to_le_bytes());
        q[48..50].copy_from_slice(&3u16.to_le_bytes());
        q[50..54].copy_from_slice(&648u32.to_le_bytes());
        q[574..638].copy_from_slice(report_data);
        q
    }

    #[test]
    fn asks_the_agent_for_evidence_over_hex_runtime_data() {
        let rd = [0x11u8; 64];
        let runtime_data = agent_runtime_data(&rd);
        let quote = quote_with(runtime_data.as_bytes());
        let body = format!(
            "{{\"quote\":\"{}\",\"cc_eventlog\":\"\"}}",
            BASE64_STANDARD.encode(&quote)
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            tx.send(line).unwrap();
            (&stream)
                .write_all(format!("HTTP/1.1 200 OK\r\n\r\n{body}").as_bytes())
                .unwrap();
        });
        let (got, events) = agent_quote(&addr, &rd).unwrap();
        assert_eq!(got, quote);
        assert!(events.is_empty());
        let request = rx.recv().unwrap();
        assert!(
            request.starts_with(&format!("GET /aa/evidence?runtime_data={runtime_data} ")),
            "{request}"
        );
    }

    #[test]
    fn refuses_a_quote_over_other_data() {
        let error = check_report_data(&quote_with(&[0; 64]), &[1; 64]).unwrap_err();
        assert!(error.to_string().contains("report_data"));
        assert!(check_report_data(&[0; 100], &[0; 64]).is_err());
    }

    #[test]
    fn reads_report_data_from_quote_v4_and_v5() {
        let rd = [0x44u8; 64];
        assert!(check_report_data(&quote_with(&rd), &rd).is_ok());
        let v5 = quote_v5_with(&rd);
        assert!(check_report_data(&v5, &rd).is_ok());
        // TD 1.0 body in a v5 quote: same place.
        let mut td10 = v5.clone();
        td10[48..50].copy_from_slice(&2u16.to_le_bytes());
        assert!(check_report_data(&td10, &rd).is_ok());
        // The v4 place in a v5 quote is not report_data.
        let mut misplaced = quote_v5_with(&[0; 64]);
        misplaced[568..632].copy_from_slice(&rd);
        assert!(check_report_data(&misplaced, &rd).is_err());
        // An SGX enclave body, another version, another TEE.
        let mut sgx = v5.clone();
        sgx[48..50].copy_from_slice(&1u16.to_le_bytes());
        assert!(
            check_report_data(&sgx, &rd)
                .unwrap_err()
                .to_string()
                .contains("body type")
        );
        let mut v6 = quote_with(&rd);
        v6[0..2].copy_from_slice(&6u16.to_le_bytes());
        assert!(
            check_report_data(&v6, &rd)
                .unwrap_err()
                .to_string()
                .contains("version")
        );
        let mut sev = quote_with(&rd);
        sev[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert!(
            check_report_data(&sev, &rd)
                .unwrap_err()
                .to_string()
                .contains("not a TDX")
        );
    }

    #[test]
    fn configfs_tsm_writes_inblob_and_reads_outblob() {
        // A directory standing in for one TSM report entry: outblob already holds the quote.
        let entry = std::env::temp_dir().join(format!("alpha-tsm-cfg-{}", std::process::id()));
        fs::create_dir_all(&entry).unwrap();
        let rd = [0x22u8; 64];
        fs::write(entry.join("outblob"), quote_with(&rd)).unwrap();
        fs::write(entry.join("generation"), "7\n").unwrap();
        let (quote, _) = tsm_report(&entry, &rd, false).unwrap();
        assert_eq!(fs::read(entry.join("inblob")).unwrap(), rd);
        assert_eq!(quote, quote_with(&rd));
        fs::write(entry.join("outblob"), quote_with(&[0; 64])).unwrap();
        let (other, _) = tsm_report(&entry, &rd, false).unwrap();
        assert!(check_report_data(&other, &rd).is_err());
        fs::remove_file(entry.join("generation")).unwrap();
        assert!(tsm_report(&entry, &rd, false).is_err());
        let _ = fs::remove_dir_all(&entry);
    }

    #[test]
    fn configfs_tsm_entries_are_fresh_and_random() {
        let (a, b) = (tsm_entry_name().unwrap(), tsm_entry_name().unwrap());
        assert_ne!(a, b);
        assert!(
            a.starts_with("alpha-") && a.len() == "alpha-".len() + 16,
            "{a}"
        );
        // An entry that already exists is not reused: a fresh one is made in the report tree.
        let dir = std::env::temp_dir().join(format!("alpha-tsm-tree-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        // The stand-in tree has no kernel behind it, so the report itself fails.
        assert!(tsm_quote(&dir, &[0; 64]).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decodes_the_initdata_annotation() {
        let toml = b"algorithm = \"sha384\"\nversion = \"0.1.0\"\n";
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(toml).unwrap();
        let annotation = BASE64_STANDARD.encode(gz.finish().unwrap());
        assert_eq!(decode_annotation(&format!("{annotation}\n")).unwrap(), toml);
        assert!(decode_annotation("!!").is_err());
        assert!(decode_annotation(&BASE64_STANDARD.encode(b"plain")).is_err());
    }

    /// A stand-in attestation agent that answers one request with `body` and hands back the
    /// request line.
    fn agent_once(body: String) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            // The caller may not want the request line.
            let _ = tx.send(line);
            (&stream)
                .write_all(format!("HTTP/1.1 200 OK\r\n\r\n{body}").as_bytes())
                .unwrap();
        });
        (addr, rx)
    }

    #[test]
    fn gpu_reports_come_from_the_agents_nvidia_attester_over_the_gpu_nonce() {
        let nonce = [0x33u8; 32];
        let device = |arch: &str, evidence: &[u8]| {
            format!(
                "{{\"arch\":\"{arch}\",\"uuid\":\"unknown\",\"evidence\":\"{}\",\"certificate\":\"{}\"}}",
                BASE64_STANDARD.encode(evidence),
                BASE64_STANDARD.encode(b"chain")
            )
        };
        // Two GPUs and an NVSwitch, which is not counted.
        let body = format!(
            "{{\"nvidia\":{{\"device_evidence_list\":[{},{},{}]}}}}",
            device("BLACKWELL", &[1]),
            device("LS10", &[9]),
            device("BLACKWELL", &[2])
        );
        let (addr, request) = agent_once(body.clone());
        let gpus = agent_gpu_evidence(&addr, &nonce, 2).unwrap();
        assert_eq!(
            gpus.iter()
                .map(|g| (g.arch.as_str(), g.evidence.as_slice()))
                .collect::<Vec<_>>(),
            [("BLACKWELL", &[1u8][..]), ("BLACKWELL", &[2u8][..])]
        );
        assert_eq!(gpus[0].certificate, b"chain");
        let request = request.recv().unwrap();
        let expected = format!(
            "GET /aa/additional-evidence?runtime_data={}&encoding=base64 ",
            BASE64_URL_SAFE_NO_PAD.encode(nonce)
        );
        assert!(request.starts_with(&expected), "{request}");

        // Fewer or more GPUs than the init-data expects, no NVIDIA device, no device at all.
        let (addr, _) = agent_once(body);
        let error = agent_gpu_evidence(&addr, &nonce, 8)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("2 GPUs reported, the init-data expects 8"),
            "{error}"
        );
        let (addr, _) = agent_once("{\"sample\":{}}".into());
        let error = agent_gpu_evidence(&addr, &nonce, 1)
            .unwrap_err()
            .to_string();
        assert!(error.contains("no NVIDIA device"), "{error}");
        let (addr, _) = agent_once(String::new());
        let error = agent_gpu_evidence(&addr, &nonce, 1)
            .unwrap_err()
            .to_string();
        assert!(error.contains("NVIDIA attester"), "{error}");
        // A CPU-only pod asks for nothing.
        assert!(
            agent_gpu_evidence("127.0.0.1:1", &nonce, 0)
                .unwrap()
                .is_empty()
        );
    }
    /// A certificate table: the entries, then the all-zero one, then the data.
    fn cert_table(certs: &[([u8; 16], &[u8])]) -> Vec<u8> {
        let header = 24 * (certs.len() + 1);
        let mut table = Vec::new();
        let mut data = Vec::new();
        for (guid, cert) in certs {
            table.extend_from_slice(guid);
            table.extend_from_slice(&((header + data.len()) as u32).to_le_bytes());
            table.extend_from_slice(&(cert.len() as u32).to_le_bytes());
            data.extend_from_slice(cert);
        }
        table.extend_from_slice(&[0; 24]);
        table.extend_from_slice(&data);
        table
    }

    const ASK_GUID: [u8; 16] = guid(
        0x4ab7b379,
        0xbbac,
        0x4fe4,
        [0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7, 0x82],
    );

    /// An SNP report shell over `report_data`, signed by `key` (0 VCEK, 1 VLEK).
    fn snp_report_with(report_data: &[u8; 64], key: u32) -> Vec<u8> {
        let mut r = vec![0u8; SNP_REPORT_LEN];
        r[0..4].copy_from_slice(&3u32.to_le_bytes());
        r[0x48..0x4C].copy_from_slice(&(key << 2).to_le_bytes());
        r[SNP_REPORT_DATA].copy_from_slice(report_data);
        r
    }

    fn snp_entry(name: &str) -> std::path::PathBuf {
        let entry =
            std::env::temp_dir().join(format!("alpha-tsm-snp-{name}-{}", std::process::id()));
        fs::create_dir_all(&entry).unwrap();
        fs::write(entry.join("provider"), "sev_guest\n").unwrap();
        fs::write(entry.join("generation"), "1\n").unwrap();
        entry
    }

    #[test]
    fn configfs_tsm_gives_the_snp_report_and_the_vek_that_signed_it() {
        let rd = [0x5au8; 64];
        let entry = snp_entry("vcek");
        fs::write(entry.join("outblob"), snp_report_with(&rd, 0)).unwrap();
        fs::write(
            entry.join("auxblob"),
            cert_table(&[
                (ASK_GUID, b"ask"),
                (VCEK_GUID, b"vcek"),
                (VLEK_GUID, b"vlek"),
            ]),
        )
        .unwrap();
        let (report, vek) = snp_report_in(&entry, &rd).unwrap();
        assert_eq!(report, snp_report_with(&rd, 0));
        assert_eq!(vek, b"vcek");
        assert_eq!(fs::read(entry.join("inblob")).unwrap(), rd);

        // A VLEK-signed report takes the VLEK.
        fs::write(entry.join("outblob"), snp_report_with(&rd, 1)).unwrap();
        assert_eq!(snp_report_in(&entry, &rd).unwrap().1, b"vlek");
        // No certificates from the host: the KMS fetches the VCEK.
        fs::remove_file(entry.join("auxblob")).unwrap();
        fs::write(entry.join("outblob"), snp_report_with(&rd, 0)).unwrap();
        assert!(snp_report_in(&entry, &rd).unwrap().1.is_empty());

        // Over other data, unsigned, the wrong length, not an SNP guest.
        for (outblob, why) in [
            (snp_report_with(&[0; 64], 0), "report_data"),
            (snp_report_with(&rd, 7), "signed by key 7"),
            (snp_report_with(&rd, 0)[..1000].to_vec(), "1000 bytes"),
        ] {
            fs::write(entry.join("outblob"), outblob).unwrap();
            let error = snp_report_in(&entry, &rd).unwrap_err().to_string();
            assert!(error.contains(why), "{why}: {error}");
        }
        fs::write(entry.join("provider"), "tdx_guest\n").unwrap();
        let error = snp_report_in(&entry, &rd).unwrap_err().to_string();
        assert!(error.contains("not an SEV-SNP guest"), "{error}");
        let _ = fs::remove_dir_all(&entry);
    }

    #[test]
    fn certificate_tables_are_bounded() {
        let table = cert_table(&[(VCEK_GUID, b"vcek")]);
        assert_eq!(cert_from_table(&table, &VCEK_GUID).unwrap(), b"vcek");
        assert!(cert_from_table(&table, &VLEK_GUID).unwrap().is_empty());
        assert!(cert_from_table(&[], &VCEK_GUID).unwrap().is_empty());
        let error = cert_from_table(&table[..30], &VLEK_GUID)
            .unwrap_err()
            .to_string();
        assert!(error.contains("truncated"), "{error}");
        let mut outside = table.clone();
        outside[20..24].copy_from_slice(&1000u32.to_le_bytes());
        let error = cert_from_table(&outside, &VCEK_GUID)
            .unwrap_err()
            .to_string();
        assert!(error.contains("outside the table"), "{error}");
        let error = cert_from_table(&table[..24], &VLEK_GUID)
            .unwrap_err()
            .to_string();
        assert!(error.contains("no terminating entry"), "{error}");
    }

    #[test]
    fn an_snp_pod_reads_its_report_from_configfs_tsm_only() {
        let source = |quote| Source {
            quote,
            initdata: Vec::new(),
            runtime_class: alpha_core::coco::SNP_CPU_RUNTIME_CLASS.into(),
            gpu_count: 0,
        };
        let error = source(QuoteSource::AttestationAgent)
            .evidence(&[0; 64])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("ALPHACOMPUTE_QUOTE_SOURCE=coco-tsm"),
            "{error}"
        );
        // No TSM tree here: configfs-tsm fails at the pod.
        assert!(source(QuoteSource::ConfigfsTsm).evidence(&[0; 64]).is_err());
        let mut unknown = source(QuoteSource::ConfigfsTsm);
        unknown.runtime_class = "kata-qemu-sev".into();
        let error = unknown.evidence(&[0; 64]).unwrap_err().to_string();
        assert!(error.contains("not supported"), "{error}");
    }
}
