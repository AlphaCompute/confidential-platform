#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::SystemTime;

use alpha_channel::frame::{Channel, MAX_REQUESTS, RequestFrame};
use alpha_channel::handshake::{Expected, Initiator, Responder};

const CA: &str = include_str!("../../../testdata/channel/ca.pem");
const LEAF: &str = include_str!("../../../testdata/channel/leaf.pem");
const LEAF_KEY: &str = include_str!("../../../testdata/channel/leaf-key.pem");
const COMPOSE: &str = include_str!("../../../testdata/channel/app-compose.json");

/// (initiator's channel, responder's channel) after one handshake.
fn pair() -> (Channel, Channel) {
    let now: SystemTime = chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
        .unwrap()
        .into();
    let key = x509_parser::pem::parse_x509_pem(LEAF_KEY.as_bytes())
        .unwrap()
        .1
        .contents;
    let responder = Responder::new(vec![LEAF.into(), CA.into()], &key, COMPOSE.into()).unwrap();
    let (initiator, hello) = Initiator::new().unwrap();
    let (reply, server) = responder.respond(&hello, now).unwrap();
    let expected = Expected {
        org_id: "01920000-0000-7000-8000-000000000001".parse().unwrap(),
        app_id: "01920000-0000-7000-8000-000000000002".parse().unwrap(),
        revisions: vec![alpha_core::compose_hash(COMPOSE)],
    };
    let (client, _) = initiator.finish(&reply, CA, &expected, now).unwrap();
    (client, server)
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_request_opened_twice_is_replayed() {
    let (mut client, mut server) = pair();
    let frame = client.seal_request("POST", "/sessions", b"{}").unwrap();
    server.open_request(&frame, "POST", "/sessions").unwrap();
    let err = server
        .open_request(&frame, "POST", "/sessions")
        .unwrap_err();
    assert_eq!(err.code(), "replayed");
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn requests_open_out_of_order_but_each_only_once() {
    let (mut client, mut server) = pair();
    let first = client.seal_request("POST", "/a", b"1").unwrap();
    let second = client.seal_request("POST", "/b", b"2").unwrap();
    assert_eq!(
        server
            .open_request(&second, "POST", "/b")
            .unwrap()
            .as_slice(),
        b"2"
    );
    assert_eq!(
        server
            .open_request(&first, "POST", "/a")
            .unwrap()
            .as_slice(),
        b"1"
    );
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_body_moved_to_another_path_or_method_does_not_open() {
    let (mut client, mut server) = pair();
    let frame = client
        .seal_request("POST", "/sessions/x/turns", b"{\"text\":\"hi\"}")
        .unwrap();
    let moved = server.open_request(&frame, "POST", "/sessions/x/lease");
    assert_eq!(moved.unwrap_err().code(), "open");
    let method = server.open_request(&frame, "DELETE", "/sessions/x/turns");
    assert_eq!(method.unwrap_err().code(), "open");
    server
        .open_request(&frame, "POST", "/sessions/x/turns")
        .unwrap();
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_frame_from_another_channel_does_not_open() {
    let (mut client, _) = pair();
    let (_, mut server) = pair();
    let frame = client.seal_request("POST", "/sessions", b"{}").unwrap();
    let err = server
        .open_request(&frame, "POST", "/sessions")
        .unwrap_err();
    assert_eq!(err.code(), "open");
    let relabelled = RequestFrame {
        channel: server.id().to_owned(),
        ..frame
    };
    let err = server
        .open_request(&relabelled, "POST", "/sessions")
        .unwrap_err();
    assert_eq!(err.code(), "open");
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_sequence_number_past_the_cap_is_exhausted() {
    let (mut client, mut server) = pair();
    let frame = client.seal_request("POST", "/sessions", b"{}").unwrap();
    let past = RequestFrame {
        seq: MAX_REQUESTS,
        ..frame
    };
    let err = server.open_request(&past, "POST", "/sessions").unwrap_err();
    assert_eq!(err.code(), "exhausted");
}

/// A channel pair with request 0 already opened by the responder.
fn opened() -> (Channel, Channel) {
    let (mut client, mut server) = pair();
    let frame = client.seal_request("GET", "/", b"").unwrap();
    server.open_request(&frame, "GET", "/").unwrap();
    (client, server)
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn response_frames_read_out_of_order_do_not_open() {
    let (client, mut server) = opened();
    let first = server.seal_response(0, false, b"one").unwrap();
    let second = server.seal_response(0, true, b"two").unwrap();
    let mut reader = client.response(0);
    assert_eq!(reader.open_line(&second).unwrap_err().code(), "open");
    let mut reader = client.response(0);
    reader.open_line(&first).unwrap();
    assert_eq!(reader.open_line(&first).unwrap_err().code(), "open");
    let mut other_request = client.response(1);
    assert_eq!(other_request.open_line(&first).unwrap_err().code(), "open");
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_response_that_stops_before_its_end_frame_is_truncated() {
    let (client, mut server) = opened();
    let mut reader = client.response(0);
    let more = server.seal_response(0, false, b"one").unwrap();
    reader.open_line(&more).unwrap();
    assert_eq!(reader.finish().unwrap_err().code(), "truncated");
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_line_after_the_end_frame_is_refused() {
    let (client, mut server) = opened();
    let mut reader = client.response(0);
    let end = server.seal_response(0, true, b"done").unwrap();
    reader.open_line(&end).unwrap();
    assert_eq!(reader.open_line(&end).unwrap_err().code(), "open");
    reader.finish().unwrap();
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_response_is_sealed_only_for_an_opened_request_and_not_after_its_end() {
    let (mut client, mut server) = pair();
    assert_eq!(
        server.seal_response(0, false, b"x").unwrap_err().code(),
        "seal"
    );
    let frame = client.seal_request("POST", "/a", b"1").unwrap();
    assert!(server.open_request(&frame, "POST", "/b").is_err());
    assert_eq!(
        server.seal_response(0, false, b"x").unwrap_err().code(),
        "seal"
    );
    server.open_request(&frame, "POST", "/a").unwrap();
    server.seal_response(0, true, b"done").unwrap();
    assert_eq!(
        server.seal_response(0, false, b"x").unwrap_err().code(),
        "seal"
    );
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_blank_line_carries_nothing() {
    let (client, _) = pair();
    assert!(client.response(0).open_line("  \n").unwrap().is_none());
}
