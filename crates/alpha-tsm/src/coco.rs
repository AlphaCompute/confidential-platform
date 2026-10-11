//! What a Kata confidential pod reads about itself, from inside one of its containers: a TDX quote
//! over our `report_data`, the CCEL boot events when the source returns them, the init-data the
//! pod booted with, and one attestation report per passed-through GPU.
//!
//! Nothing here is trusted by the KMS. The quote is signed by the TD; the init-data is checked
//! against MRCONFIGID; GPU reports are verified by the GPU backend. A source that lies only makes
//! the attestation fail.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use alpha_attest::{CpuEvidence, CpuKind, EVIDENCE_FORMAT_V2, EvidenceV2, GpuEvidence};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::Deserialize;
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
/// Prints `[{arch, evidence, certificate}]` for every GPU in the pod for `--nonce <hex>`, through
/// NVIDIA's attestation SDK (NVML confidential-compute report and certificate). Shipped in the
/// runtime image for GPU pods.
// ponytail: M-B — replace with the attestation agent's composite GPU evidence if the pinned
// guest-components build exposes it on the REST API; the evidence shape stays the same.
pub const GPU_EVIDENCE_HELPER: &str = "/usr/local/bin/alpha-gpu-evidence";

const TIMEOUT: Duration = Duration::from_secs(30);

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

/// TDX quote v4: a 48-byte header, then the TD report whose `report_data` sits at offset 520.
/// Checked here so a source that drops or reshapes our data fails at the pod, with a reason,
/// rather than as an opaque refusal at the KMS.
fn check_report_data(quote: &[u8], expected: &[u8]) -> Result<(), Error> {
    const OFFSET: usize = 48 + 520;
    let quoted = quote
        .get(OFFSET..OFFSET.saturating_add(64))
        .ok_or_else(|| Error::Agent("quote is too short for a TDX v4 quote".into()))?;
    if quoted != expected {
        return Err(Error::Agent(
            "the quote's report_data is not the runtime data asked for".into(),
        ));
    }
    Ok(())
}

fn tsm_quote(dir: &Path, report_data: &[u8; 64]) -> Result<Vec<u8>, Error> {
    let io = |what: String| move |e| Error::Io(what.clone(), e);
    let entry = dir.join(format!("alpha-{}", std::process::id()));
    match fs::create_dir(&entry) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io(entry.display().to_string())(e)),
    }
    let result = (|| {
        fs::write(entry.join("inblob"), report_data).map_err(io("inblob".into()))?;
        let quote = fs::read(entry.join("outblob")).map_err(io("outblob".into()))?;
        check_report_data(&quote, report_data)?;
        Ok(quote)
    })();
    let _ = fs::remove_dir(&entry);
    result
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

/// One report per GPU over `nonce`, from [`GPU_EVIDENCE_HELPER`]; exactly `count` of them.
pub fn gpu_evidence(
    helper: &Path,
    nonce: &[u8; 32],
    count: usize,
) -> Result<Vec<GpuEvidence>, Error> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let output = Command::new(helper)
        .arg("--nonce")
        .arg(hex::encode(nonce))
        .output()
        .map_err(|e| Error::Io(helper.display().to_string(), e))?;
    if !output.status.success() {
        return Err(Error::Agent(format!(
            "{}: {}: {}",
            helper.display(),
            output.status,
            String::from_utf8_lossy(output.stderr.get(..400).unwrap_or(&output.stderr))
        )));
    }
    let gpus: Vec<GpuEvidence> = serde_json::from_slice(&output.stdout)
        .map_err(|e| Error::Agent(format!("GPU evidence: {e}")))?;
    if gpus.len() != count {
        return Err(Error::Agent(format!(
            "{} GPUs reported, the init-data expects {count}",
            gpus.len()
        )));
    }
    Ok(gpus)
}

/// Everything a pod sends: `alphacompute-evidence/2`.
pub struct Source {
    pub quote: QuoteSource,
    pub initdata: Vec<u8>,
    pub runtime_class: String,
    pub gpu_count: usize,
    pub gpu_helper: PathBuf,
}

impl Source {
    pub fn evidence(&self, report_data: &[u8; 64]) -> Result<EvidenceV2, Error> {
        let (quote, event_log) = quote(self.quote, report_data)?;
        let gpus = gpu_evidence(
            &self.gpu_helper,
            &alpha_attest::gpu::gpu_nonce(report_data),
            self.gpu_count,
        )?;
        Ok(EvidenceV2 {
            format: EVIDENCE_FORMAT_V2.into(),
            cpu: CpuEvidence {
                kind: CpuKind::Tdx,
                quote,
                event_log,
            },
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
    use std::os::unix::fs::PermissionsExt;
    use std::sync::mpsc;
    use std::thread;

    use super::*;

    fn quote_with(report_data: &[u8]) -> Vec<u8> {
        let mut q = vec![0u8; 48 + 584 + 16];
        q[568..632].copy_from_slice(report_data);
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
    fn configfs_tsm_writes_inblob_and_reads_outblob() {
        // A directory standing in for the TSM report tree: outblob already holds the quote.
        let dir = std::env::temp_dir().join(format!("alpha-tsm-cfg-{}", std::process::id()));
        let entry = dir.join(format!("alpha-{}", std::process::id()));
        fs::create_dir_all(&entry).unwrap();
        let rd = [0x22u8; 64];
        fs::write(entry.join("outblob"), quote_with(&rd)).unwrap();
        // remove_dir fails on a non-empty dir in the stand-in, which tsm_quote ignores.
        let quote = tsm_quote(&dir, &rd).unwrap();
        assert_eq!(fs::read(entry.join("inblob")).unwrap(), rd);
        assert_eq!(quote, quote_with(&rd));
        fs::write(entry.join("outblob"), quote_with(&[0; 64])).unwrap();
        assert!(tsm_quote(&dir, &rd).is_err());
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

    #[test]
    fn gpu_helper_must_report_every_expected_gpu() {
        let helper = std::env::temp_dir().join(format!("alpha-gpu-{}.sh", std::process::id()));
        fs::write(
            &helper,
            "#!/bin/sh\n[ \"$1\" = --nonce ] || exit 2\necho '[{\"arch\":\"BLACKWELL\",\"evidence\":\"AQ\",\"certificate\":\"Ag\"}]'\n",
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let gpus = gpu_evidence(&helper, &[0; 32], 1).unwrap();
        assert_eq!(gpus[0].evidence, [1]);
        assert!(
            gpu_evidence(&helper, &[0; 32], 8)
                .unwrap_err()
                .to_string()
                .contains("expects 8")
        );
        assert!(
            gpu_evidence(Path::new("/nonexistent"), &[0; 32], 0)
                .unwrap()
                .is_empty()
        );
        let _ = fs::remove_file(&helper);
    }
}
