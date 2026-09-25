#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::SystemTime;

use alpha_channel::cert::{pem_to_der, spki_sha256};
use alpha_channel::handshake::{Expected, Initiator, Responder};
use alpha_core::{AppId, OrgId};

const CA: &str = include_str!("../../../testdata/channel/ca.pem");
const LEAF: &str = include_str!("../../../testdata/channel/leaf.pem");
const LEAF_KEY: &str = include_str!("../../../testdata/channel/leaf-key.pem");
const COMPOSE: &str = include_str!("../../../testdata/channel/app-compose.json");

const ORG: &str = "01920000-0000-7000-8000-000000000001";
const APP: &str = "01920000-0000-7000-8000-000000000002";

fn at(rfc3339: &str) -> SystemTime {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .unwrap()
        .into()
}

fn leaf_key() -> Vec<u8> {
    x509_parser::pem::parse_x509_pem(LEAF_KEY.as_bytes())
        .unwrap()
        .1
        .contents
}

fn responder(leaf: &str) -> Responder {
    Responder::new(vec![leaf.into(), CA.into()], &leaf_key(), COMPOSE.into()).unwrap()
}

fn expected() -> Expected {
    Expected {
        org_id: ORG.parse::<OrgId>().unwrap(),
        app_id: APP.parse::<AppId>().unwrap(),
        revisions: vec![alpha_core::compose_hash(COMPOSE)],
    }
}

#[test]
fn a_responder_and_an_initiator_share_a_channel() {
    let now = at("2026-06-01T00:00:00Z");
    let (initiator, client_hello) = Initiator::new().unwrap();
    let (server_hello, mut server) = responder(LEAF).respond(&client_hello, now).unwrap();
    let (mut client, verified) = initiator
        .finish(&server_hello, CA, &expected(), now)
        .unwrap();

    assert_eq!(verified.org_id.to_string(), ORG);
    assert_eq!(verified.app_id.to_string(), APP);
    assert_eq!(verified.compose_hash, alpha_core::compose_hash(COMPOSE));
    assert_eq!(verified.compose, COMPOSE);
    assert_eq!(Some(verified.aud), spki_sha256(&pem_to_der(LEAF).unwrap()));
    assert_eq!(verified.now, now);
    assert_eq!(client.id(), server.id());

    let request = client
        .seal_request("POST", "/sessions", br#"{"hello":1}"#)
        .unwrap();
    let (seq, body) = server.open_request(&request, "POST", "/sessions").unwrap();
    assert_eq!(body.as_slice(), br#"{"hello":1}"#);

    let first = server.seal_response(seq, 0, false, b"one").unwrap();
    let last = server.seal_response(seq, 1, true, b"two").unwrap();
    let mut reader = client.response(seq);
    assert!(reader.finish().is_err());
    assert_eq!(
        reader.open_line(&first).unwrap().unwrap().as_slice(),
        b"one"
    );
    assert_eq!(reader.open_line(&last).unwrap().unwrap().as_slice(), b"two");
    reader.finish().unwrap();
}
