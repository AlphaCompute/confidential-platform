use alpha_core::ComposeHash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

use crate::Measurement;

/// One entry of the dstack event log, with dstack's field names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventLogEntry {
    pub imr: u32,
    pub event_type: u32,
    #[serde(with = "hex::serde")]
    pub digest: Vec<u8>,
    pub event: String,
    #[serde(with = "hex::serde")]
    pub event_payload: Vec<u8>,
}

/// dstack's own runtime events (`compose-hash`, `app-id`, …) are extended into RTMR3 under
/// this event type; the guest leaves their `digest` empty and the verifier recomputes it.
const DSTACK_RUNTIME_EVENT_TYPE: u32 = 0x0800_0001;

pub const COMPOSE_HASH_EVENT: &str = "compose-hash";

impl EventLogEntry {
    fn digest(&self) -> Vec<u8> {
        if self.event_type != DSTACK_RUNTIME_EVENT_TYPE {
            return self.digest.clone();
        }
        // ponytail: dstack's V1 preimage only; V2 (`version: "v2"`, digest over canonical JSON
        // {"name","type","payload"}) is not emitted by Phala's guest image yet and replays as a
        // mismatch, which is fail-closed. Add the V2 branch when the field appears in a capture.
        let mut hasher = Sha384::new();
        hasher.update(DSTACK_RUNTIME_EVENT_TYPE.to_le_bytes());
        hasher.update(b":");
        hasher.update(self.event.as_bytes());
        hasher.update(b":");
        hasher.update(&self.event_payload);
        hasher.finalize().to_vec()
    }
}

/// Replays rtmr0..3 from the log: every register starts at zero and is extended with
/// `SHA-384(register ‖ digest)` by each of its events in order.
pub fn replay(event_log: &[EventLogEntry]) -> [Measurement; 4] {
    let mut registers = [[0u8; 48]; 4];
    for entry in event_log.iter().filter(|e| (e.imr as usize) < 4) {
        let register = &mut registers[entry.imr as usize];
        let mut hasher = Sha384::new();
        hasher.update(*register);
        hasher.update(entry.digest());
        *register = hasher.finalize().into();
    }
    registers.map(Measurement)
}

pub fn compose_hash(event_log: &[EventLogEntry]) -> Option<ComposeHash> {
    let payload = &event_log
        .iter()
        .find(|e| {
            e.imr == 3 && e.event_type == DSTACK_RUNTIME_EVENT_TYPE && e.event == COMPOSE_HASH_EVENT
        })?
        .event_payload;
    Some(ComposeHash::from(
        <[u8; 32]>::try_from(payload.as_slice()).ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime(event: &str, payload: &[u8]) -> EventLogEntry {
        EventLogEntry {
            imr: 3,
            event_type: DSTACK_RUNTIME_EVENT_TYPE,
            digest: vec![],
            event: event.into(),
            event_payload: payload.to_vec(),
        }
    }

    #[test]
    fn runtime_event_digest_is_dstack_v1_preimage() {
        let entry = runtime("app-id", &[0xde, 0xad, 0xbe, 0xef]);
        let expected = Sha384::digest(b"\x01\x00\x00\x08:app-id:\xde\xad\xbe\xef");
        assert_eq!(entry.digest(), expected.to_vec());
        let [_, _, _, rtmr3] = replay(&[entry]);
        let mut extend = Sha384::new();
        extend.update([0u8; 48]);
        extend.update(expected);
        assert_eq!(rtmr3.0, <[u8; 48]>::from(extend.finalize()));
    }

    #[test]
    fn compose_hash_needs_a_32_byte_payload_in_rtmr3() {
        assert_eq!(compose_hash(&[]), None);
        assert_eq!(compose_hash(&[runtime(COMPOSE_HASH_EVENT, &[1; 31])]), None);
        let mut wrong_imr = runtime(COMPOSE_HASH_EVENT, &[1; 32]);
        wrong_imr.imr = 2;
        assert_eq!(compose_hash(&[wrong_imr]), None);
        assert_eq!(
            compose_hash(&[
                runtime("app-id", &[2; 20]),
                runtime(COMPOSE_HASH_EVENT, &[1; 32])
            ]),
            Some(ComposeHash::from([1; 32]))
        );
    }
}
