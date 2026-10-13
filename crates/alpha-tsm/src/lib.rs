//! What a TD reads about itself: a TDX quote — from the dstack guest agent's socket in a dstack
//! CVM, from configfs-tsm in a Kata pod — and the event log that replays its RTMRs: the
//! boot-time events from the CCEL ACPI table and dstack's own runtime events under
//! `/run/log/dstack`.

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

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use alpha_attest::EventLogEntry;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use dcap_qvl::quote::Quote;
use serde::Deserialize;

/// The dstack guest agent, which quotes the TD for us: Phala's guest image carries no
/// configfs-tsm (`/sys/kernel/config` is an empty configfs there, so `TSM_REPORT_DIR` never
/// existed). The agent cannot forge a quote — the TD signs it — and the appraisal checks that
/// it is over our `report_data`, so this is a different source, not weaker evidence.
pub const DSTACK_SOCKET: &str = "/var/run/dstack.sock";
/// The host's `/sys/firmware/acpi/tables/data/CCEL`, bind-mounted outside `/sys`: a container
/// does not see a file mounted under `/sys/firmware`, and a dstack node running this path failed
/// to start with the table missing.
pub const CCEL_PATH: &str = "/ccel";
pub const RUNTIME_EVENTS_PATH: &str = "/run/log/dstack/runtime_events.log";
/// The guest kernel's quote interface in a Kata TDX pod, which has no dstack guest agent.
pub const TSM_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";

const DSTACK_RUNTIME_EVENT_TYPE: u32 = 0x0800_0001;
const TEE_TYPE_TDX: u32 = 0x81;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}: {1}")]
    Io(String, std::io::Error),
    #[error("guest agent: {0}")]
    Agent(String),
    #[error("CCEL: {0}")]
    Ccel(&'static str),
    #[error("runtime event log: {0}")]
    RuntimeEvents(String),
    #[error("configfs-tsm: {0}")]
    Tsm(String),
    #[error("quote: {0}")]
    Quote(String),
}

#[derive(Deserialize)]
struct QuoteReply {
    quote: String,
}

/// One quote over `report_data`: from the guest agent's `GetQuote` when its socket exists,
/// otherwise from configfs-tsm when the report directory exists, otherwise the agent's
/// connect error.
pub fn quote(report_data: &[u8; 64]) -> Result<Vec<u8>, Error> {
    let socket = Path::new(DSTACK_SOCKET);
    let tsm = Path::new(TSM_REPORT_DIR);
    if !socket.exists() && tsm.is_dir() {
        tsm_quote(tsm, report_data)
    } else {
        quote_from(socket, report_data)
    }
}

/// A configfs-tsm report entry, removed however the request ends.
struct TsmEntry(PathBuf);

impl Drop for TsmEntry {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

/// Unique across threads by the counter and, nearly always, across processes by pid and time:
/// containers in one Kata pod share the guest kernel's configfs but may each have their own pid
/// namespace, so `tsm_quote` retries a name that is already taken.
fn tsm_entry_name() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("alpha-{}-{nanos}-{n}", std::process::id())
}

/// One quote over `report_data` from a fresh entry under the configfs-tsm `root`, checked to be
/// a TDX quote over exactly that `report_data`.
fn tsm_quote(root: &Path, report_data: &[u8; 64]) -> Result<Vec<u8>, Error> {
    let io = |what: &Path| {
        let what = what.display().to_string();
        move |e| Error::Io(what, e)
    };
    let mut attempts = 0u8;
    let dir = loop {
        let dir = root.join(tsm_entry_name());
        match fs::create_dir(&dir) {
            Ok(()) => break dir,
            Err(e) if e.kind() == ErrorKind::AlreadyExists && attempts < 3 => {
                attempts = attempts.saturating_add(1);
            }
            Err(e) => return Err(io(&dir)(e)),
        }
    };
    let entry = TsmEntry(dir);
    let attr = |name: &str| entry.0.join(name);

    let provider = fs::read_to_string(attr("provider")).map_err(io(&attr("provider")))?;
    if provider.trim() != "tdx_guest" {
        return Err(Error::Tsm(format!("provider is {:?}", provider.trim())));
    }
    fs::write(attr("inblob"), report_data).map_err(io(&attr("inblob")))?;
    // Another writer on our entry is caught by `check_quote`: the quote then carries its
    // report_data, not ours.
    let quote = fs::read(attr("outblob")).map_err(io(&attr("outblob")))?;
    drop(entry);
    check_quote(&quote, report_data)?;
    Ok(quote)
}

/// The quote is a v4 or v5 TDX quote whose TD report carries `report_data`.
fn check_quote(quote: &[u8], report_data: &[u8; 64]) -> Result<(), Error> {
    let parsed = Quote::parse(quote).map_err(|e| Error::Quote(format!("{e:#}")))?;
    // dcap-qvl takes a v5 TD report from the body type alone, without the header's TEE type.
    let report = parsed
        .report
        .as_td10()
        .filter(|_| parsed.header.tee_type == TEE_TYPE_TDX)
        .ok_or_else(|| Error::Quote("not a TDX quote".into()))?;
    if &report.report_data != report_data {
        return Err(Error::Quote("report_data is not ours".into()));
    }
    Ok(())
}

fn quote_from(socket: &Path, report_data: &[u8; 64]) -> Result<Vec<u8>, Error> {
    let body = get(
        socket,
        &format!("/GetQuote?report_data=0x{}", hex(report_data)),
    )?;
    let reply: QuoteReply =
        serde_json::from_slice(&body).map_err(|e| Error::Agent(format!("GetQuote reply: {e}")))?;
    unhex(reply.quote.trim().trim_start_matches("0x"))
}

#[derive(Deserialize)]
struct InfoReply {
    /// A JSON document inside the JSON reply.
    tcb_info: String,
}

#[derive(Deserialize)]
struct TcbInfo {
    app_compose: String,
}

/// The `app-compose.json` this CVM was booted from, exactly as measured, from the guest
/// agent's `Info`.
pub fn app_compose() -> Result<String, Error> {
    app_compose_from(Path::new(DSTACK_SOCKET))
}

fn app_compose_from(socket: &Path) -> Result<String, Error> {
    let body = get(socket, "/Info")?;
    let reply: InfoReply =
        serde_json::from_slice(&body).map_err(|e| Error::Agent(format!("Info reply: {e}")))?;
    let tcb: TcbInfo = serde_json::from_str(&reply.tcb_info)
        .map_err(|e| Error::Agent(format!("Info tcb_info: {e}")))?;
    Ok(tcb.app_compose)
}

fn get(socket: &Path, path: &str) -> Result<Vec<u8>, Error> {
    let io = |what: String| move |e| Error::Io(what.clone(), e);
    let mut stream =
        UnixStream::connect(socket).map_err(io(format!("connect {}", socket.display())))?;
    // HTTP/1.0: the agent then answers without chunked framing and closes, which is the whole
    // protocol we need. `handle` reads a GET's query as the request body and replies in JSON.
    let request =
        format!("GET {path} HTTP/1.0\r\nHost: dstack\r\nAccept: application/json\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(io("write to the guest agent".into()))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(io("read from the guest agent".into()))?;
    http_body(&response)
}

/// The body of a `200` response, chunked or not.
fn http_body(response: &[u8]) -> Result<Vec<u8>, Error> {
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Error::Agent("response has no header".into()))?;
    let (head, rest) = response.split_at(end);
    let body = rest.get(4..).unwrap_or_default();
    let head = String::from_utf8_lossy(head);
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.contains(" 200") {
        return Err(Error::Agent(format!(
            "{status}: {}",
            String::from_utf8_lossy(body.get(..200).unwrap_or(body))
        )));
    }
    let chunked = lines.any(|line| {
        let line = line.to_ascii_lowercase();
        line.starts_with("transfer-encoding:") && line.contains("chunked")
    });
    if chunked {
        dechunk(body)
    } else {
        Ok(body.to_vec())
    }
}

fn dechunk(mut body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    loop {
        let end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| Error::Agent("chunk header".into()))?;
        let header = String::from_utf8_lossy(body.get(..end).unwrap_or_default()).to_string();
        let size = usize::from_str_radix(header.split(';').next().unwrap_or_default().trim(), 16)
            .map_err(|_| Error::Agent("chunk size".into()))?;
        let rest = body.get(end.saturating_add(2)..).unwrap_or_default();
        if size == 0 {
            return Ok(out);
        }
        out.extend_from_slice(
            rest.get(..size)
                .ok_or_else(|| Error::Agent("chunk is short".into()))?,
        );
        body = rest.get(size.saturating_add(2)..).unwrap_or_default();
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Result<Vec<u8>, Error> {
    let bad = || Error::Agent("quote is not hex".into());
    if !text.len().is_multiple_of(2) || text.is_empty() {
        return Err(bad());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| bad())?;
            u8::from_str_radix(pair, 16).map_err(|_| bad())
        })
        .collect()
}

pub fn event_log() -> Result<Vec<EventLogEntry>, Error> {
    let ccel = fs::read(CCEL_PATH).map_err(|e| Error::Io(CCEL_PATH.into(), e))?;
    let runtime = match fs::read_to_string(RUNTIME_EVENTS_PATH) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(Error::Io(RUNTIME_EVENTS_PATH.into(), e)),
    };
    let mut log = boot_events(&ccel)?;
    log.extend(runtime_events(&runtime)?);
    Ok(log)
}

/// TCG PC Client event log (EFI TCG2): one SHA1-format spec-id header, then `TCG_PCR_EVENT2`
/// records until `0xFFFFFFFF` or the end of the table. Register index 1 is RTMR0, as in
/// dstack, and the payload is dropped the way the guest agent drops it.
pub fn boot_events(ccel: &[u8]) -> Result<Vec<EventLogEntry>, Error> {
    let mut input = ccel;
    let u32_at = |input: &mut &[u8]| -> Result<u32, Error> {
        let (head, rest) = input
            .split_first_chunk::<4>()
            .ok_or(Error::Ccel("truncated"))?;
        *input = rest;
        Ok(u32::from_le_bytes(*head))
    };
    let take = |input: &mut &[u8], n: usize| -> Result<Vec<u8>, Error> {
        if input.len() < n {
            return Err(Error::Ccel("truncated"));
        }
        let (head, rest) = input.split_at(n);
        *input = rest;
        Ok(head.to_vec())
    };

    // The header is a TCG_PCR_EVENT: index, type, a 20-byte digest, then the spec-id struct.
    u32_at(&mut input)?;
    u32_at(&mut input)?;
    take(&mut input, 20)?;
    let header_len = u32_at(&mut input)? as usize;
    take(&mut input, header_len)?;

    let mut events = Vec::new();
    while input.len() >= 4 {
        let index = u32_at(&mut input)?;
        if index == 0xFFFF_FFFF {
            break;
        }
        let event_type = u32_at(&mut input)?;
        let count = u32_at(&mut input)?;
        let mut digests = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (alg, rest) = input
                .split_first_chunk::<2>()
                .ok_or(Error::Ccel("truncated"))?;
            input = rest;
            let size = match u16::from_le_bytes(*alg) {
                0x0004 => 20,
                0x000b => 32,
                0x000c => 48,
                0x000d => 64,
                _ => return Err(Error::Ccel("unknown digest algorithm")),
            };
            digests.push(take(&mut input, size)?);
        }
        let event_len = u32_at(&mut input)? as usize;
        take(&mut input, event_len)?;
        let Some(imr) = index.checked_sub(1) else {
            continue;
        };
        let [digest] = <[Vec<u8>; 1]>::try_from(digests)
            .map_err(|_| Error::Ccel("expected exactly one digest per event"))?;
        events.push(EventLogEntry {
            imr,
            event_type,
            digest,
            event: String::new(),
            event_payload: Vec::new(),
        });
    }
    Ok(events)
}

#[derive(Deserialize)]
struct RuntimeEvent {
    event: String,
    payload: String,
}

/// dstack's `runtime_events.log`: one JSON object per line, payload base64; all into RTMR3
/// with an empty digest that the verifier recomputes.
pub fn runtime_events(text: &str) -> Result<Vec<EventLogEntry>, Error> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let RuntimeEvent { event, payload } =
                serde_json::from_str(line).map_err(|e| Error::RuntimeEvents(e.to_string()))?;
            let event_payload = BASE64_STANDARD
                .decode(payload)
                .map_err(|e| Error::RuntimeEvents(e.to_string()))?;
            Ok(EventLogEntry {
                imr: 3,
                event_type: DSTACK_RUNTIME_EVENT_TYPE,
                digest: Vec::new(),
                event,
                event_payload,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Event(u32, u32, u16, [u8; 48], &'static [u8]);

    fn tcg2(events: &[Event]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&3u32.to_le_bytes());
        out.extend_from_slice(&[0u8; 20]);
        let spec_id = b"Spec ID Event03\0";
        out.extend_from_slice(&(spec_id.len() as u32).to_le_bytes());
        out.extend_from_slice(spec_id);
        for Event(index, ty, alg, digest, payload) in events {
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(&ty.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(&alg.to_le_bytes());
            out.extend_from_slice(digest);
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
        }
        out
    }

    #[test]
    fn boot_events_follow_the_tcg2_layout() {
        let d = [0xabu8; 48];
        let log = tcg2(&[
            Event(0, 0x8000_0001, 0x000c, [0x11; 48], b"mrtd, dropped"),
            Event(1, 0x8000_000b, 0x000c, d, b"boot"),
            Event(3, 0x0000_0006, 0x000c, d, b""),
        ]);
        let events = boot_events(&log).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!((events[0].imr, events[0].event_type), (0, 0x8000_000b));
        assert_eq!(events[0].digest, d);
        assert!(events[0].event.is_empty() && events[0].event_payload.is_empty());
        assert_eq!(events[1].imr, 2);

        let mut terminated = log.clone();
        terminated.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        terminated.extend_from_slice(b"garbage");
        assert_eq!(boot_events(&terminated).unwrap().len(), 2);

        assert!(boot_events(&log[..log.len() - 3]).is_err());
        assert!(boot_events(&tcg2(&[Event(1, 1, 0x0099, [0; 48], b"")])).is_err());
    }

    #[test]
    fn runtime_events_are_rtmr3_with_empty_digest() {
        let text = "{\"event\":\"compose-hash\",\"payload\":\"AQID\"}\n\n{\"event\":\"system-ready\",\"payload\":\"\"}\n";
        let events = runtime_events(text).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].imr, 3);
        assert_eq!(events[0].event_type, 0x0800_0001);
        assert_eq!(events[0].event, "compose-hash");
        assert_eq!(events[0].event_payload, [1, 2, 3]);
        assert!(events[0].digest.is_empty());
        assert!(runtime_events("{\"event\":1}").is_err());
    }

    /// A configfs-tsm outblob read by an unprivileged container in a Kata TDX pod on a B300
    /// host, over `KATA_REPORT_DATA`.
    const KATA_QUOTE: &[u8] = include_bytes!("../testdata/kata-tdx-quote.bin");
    const KATA_REPORT_DATA: &str = "a1ff0080c0fe414c5048412d54534d2d554e505249560b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f8";

    #[test]
    fn accepts_a_kata_quote_only_over_our_report_data() {
        let ours: [u8; 64] = unhex(KATA_REPORT_DATA).unwrap().try_into().unwrap();
        check_quote(KATA_QUOTE, &ours).unwrap();
        let mut other = ours;
        other[63] ^= 1;
        let error = check_quote(KATA_QUOTE, &other).unwrap_err().to_string();
        assert!(error.contains("not ours"), "{error}");
    }

    #[test]
    fn refuses_what_is_not_a_tdx_quote() {
        let ours: [u8; 64] = unhex(KATA_REPORT_DATA).unwrap().try_into().unwrap();
        assert!(check_quote(&KATA_QUOTE[..600], &ours).is_err());
        assert!(check_quote(&[], &ours).is_err());
        let mut garbled = KATA_QUOTE.to_vec();
        garbled[0] = 9;
        assert!(check_quote(&garbled, &ours).is_err());
        let mut sgx = KATA_QUOTE.to_vec();
        sgx[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert!(check_quote(&sgx, &ours).is_err());
    }

    #[test]
    fn tsm_entries_are_unique_and_removed_on_error() {
        let root = std::env::temp_dir().join(format!("alpha-tsm-{}", tsm_entry_name()));
        fs::create_dir(&root).unwrap();
        let names: std::collections::HashSet<String> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        assert!(matches!(tsm_quote(&root, &[0; 64]), Err(Error::Io(..))));
                        (0..100).map(|_| tsm_entry_name()).collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap())
                .collect()
        });
        assert_eq!(names.len(), 800);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(&root).unwrap();
    }
}

#[cfg(test)]
mod agent_tests {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread;

    use super::*;

    /// A guest agent that answers one request with `response` and reports the request line.
    fn fake_agent(response: &'static str) -> (PathBuf, mpsc::Receiver<String>) {
        let path = std::env::temp_dir().join(format!(
            "alpha-tsm-{}-{:?}.sock",
            std::process::id(),
            thread::current().id()
        ));
        let _ = fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            tx.send(line).unwrap();
            (&stream).write_all(response.as_bytes()).unwrap();
        });
        (path, rx)
    }

    #[test]
    fn asks_the_agent_for_a_quote_over_report_data() {
        let (path, requests) = fake_agent(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"quote\":\"0xdeadBEEF\",\"event_log\":\"[]\"}",
        );
        let quote = quote_from(&path, &[0x2a; 64]).unwrap();
        let _ = fs::remove_file(&path);
        assert_eq!(quote, [0xde, 0xad, 0xbe, 0xef]);
        let request = requests.recv().unwrap();
        assert!(
            request.starts_with("GET /GetQuote?report_data=0x"),
            "{request}"
        );
        assert!(request.contains(&"2a".repeat(64)), "{request}");
    }

    #[test]
    fn reads_a_chunked_reply_and_refuses_a_failure() {
        let (path, _requests) = fake_agent(
            "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nc\r\n{\"quote\":\"aa\r\n4\r\nbb\"}\r\n0\r\n\r\n",
        );
        let quote = quote_from(&path, &[0; 64]).unwrap();
        let _ = fs::remove_file(&path);
        assert_eq!(quote, [0xaa, 0xbb]);

        let (path, _requests) = fake_agent("HTTP/1.1 500 Internal Server Error\r\n\r\nno tdx");
        let error = quote_from(&path, &[0; 64]).unwrap_err().to_string();
        let _ = fs::remove_file(&path);
        assert!(error.contains("500") && error.contains("no tdx"), "{error}");

        let (path, _requests) = fake_agent("HTTP/1.1 200 OK\r\n\r\n{\"quote\":\"zz\"}");
        let error = quote_from(&path, &[0; 64]).unwrap_err().to_string();
        let _ = fs::remove_file(&path);
        assert!(error.contains("not hex"), "{error}");
    }
    #[test]
    fn reads_the_measured_compose_from_info() {
        let (path, requests) = fake_agent(concat!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n",
            include_str!("../../../testdata/attest/phala-dev-0.5.9-keyed/info.json")
        ));
        let compose = app_compose_from(&path).unwrap();
        let _ = fs::remove_file(&path);
        assert!(requests.recv().unwrap().starts_with("GET /Info HTTP/1.0"));
        assert_eq!(
            alpha_core::compose_hash(&compose).to_string(),
            "sha256:1924b5252dd9b8075c610b2a855569064835c151048b672fc9c3a7fa01fbc61a"
        );

        let (path, _requests) = fake_agent("HTTP/1.1 500 Internal Server Error\r\n\r\nboom");
        let error = app_compose_from(&path).unwrap_err().to_string();
        let _ = fs::remove_file(&path);
        assert!(error.contains("500"), "{error}");

        let (path, _requests) = fake_agent("HTTP/1.1 200 OK\r\n\r\n{\"app_id\":\"x\"}");
        let error = app_compose_from(&path).unwrap_err().to_string();
        let _ = fs::remove_file(&path);
        assert!(error.contains("tcb_info"), "{error}");
    }
}

#[cfg(test)]
mod capture_tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    /// The raw CCEL table and runtime event file of a real Phala CVM must rebuild the event
    /// log its guest agent returned from `GetQuote`.
    #[test]
    fn rebuilds_the_guest_agents_event_log() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/attest/phala-0.5.9-1c-2g-keyed");
        let ccel = fs::read(dir.join("ccel.bin")).unwrap();
        let runtime = fs::read_to_string(dir.join("runtime_events.log")).unwrap();
        let mut log = boot_events(&ccel).unwrap();
        log.extend(runtime_events(&runtime).unwrap());
        let expected: Vec<EventLogEntry> =
            serde_json::from_slice(&fs::read(dir.join("event_log.json")).unwrap()).unwrap();
        assert_eq!(log, expected);
    }
}
