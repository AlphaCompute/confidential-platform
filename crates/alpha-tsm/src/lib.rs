//! What a dstack CVM reads about itself: a TDX quote through configfs-tsm and the event log
//! that replays its RTMRs — the boot-time events from the CCEL ACPI table and dstack's own
//! runtime events under `/run/log/dstack`. No guest-agent socket is involved.

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
use std::path::Path;

use alpha_attest::EventLogEntry;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::Deserialize;

pub const TSM_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";
/// The host's `/sys/firmware/acpi/tables/data/CCEL`, bind-mounted outside `/sys`: a container
/// does not see a file mounted under `/sys/firmware`, and a dstack node running this path failed
/// to start with the table missing.
pub const CCEL_PATH: &str = "/ccel";
pub const RUNTIME_EVENTS_PATH: &str = "/run/log/dstack/runtime_events.log";

const DSTACK_RUNTIME_EVENT_TYPE: u32 = 0x0800_0001;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}: {1}")]
    Io(String, std::io::Error),
    #[error("CCEL: {0}")]
    Ccel(&'static str),
    #[error("runtime event log: {0}")]
    RuntimeEvents(String),
}

/// One quote over `report_data`: a fresh entry under configfs-tsm, `inblob` in, `outblob` out.
pub fn quote(report_data: &[u8; 64]) -> Result<Vec<u8>, Error> {
    let entry = Path::new(TSM_REPORT_DIR).join(format!("alpha-{}", std::process::id()));
    let io = |what: &str| {
        let what = what.to_owned();
        move |e| Error::Io(what, e)
    };
    fs::create_dir(&entry).map_err(io("create tsm entry"))?;
    let result = fs::write(entry.join("inblob"), report_data)
        .map_err(io("write inblob"))
        .and_then(|()| fs::read(entry.join("outblob")).map_err(io("read outblob")));
    let _ = fs::remove_dir(&entry);
    let quote = result?;
    if quote.is_empty() {
        return Err(Error::Io(
            "read outblob".into(),
            std::io::Error::other("empty outblob"),
        ));
    }
    Ok(quote)
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
