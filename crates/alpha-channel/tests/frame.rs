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

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_request_opened_twice_is_replayed() {
    let (mut client, mut server) = pair();
    let frame = client.seal_request("POST", "/sessions", b"{}").unwrap();
    server.open_request(&frame, "POST", "/sessions").unwrap();
    let err = server
        .open_request(&frame, "POST", "/sessions")
        .unwrap_err();
    assert_eq!(err.code(), "replayed");
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn requests_open_out_of_order_but_each_only_once() {
    let (mut client, mut server) = pair();
    let first = client.seal_request("POST", "/a", b"1").unwrap();
    let second = client.seal_request("POST", "/b", b"2").unwrap();
    assert_eq!(server.open_request(&second, "POST", "/b").unwrap().0, 1);
    assert_eq!(server.open_request(&first, "POST", "/a").unwrap().0, 0);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
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

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
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

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
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

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn response_frames_read_out_of_order_do_not_open() {
    let (client, server) = pair();
    let first = server.seal_response(0, 0, false, b"one").unwrap();
    let second = server.seal_response(0, 1, true, b"two").unwrap();
    let mut reader = client.response(0);
    assert_eq!(reader.open_line(&second).unwrap_err().code(), "open");
    let mut reader = client.response(0);
    reader.open_line(&first).unwrap();
    assert_eq!(reader.open_line(&first).unwrap_err().code(), "open");
    let mut other_request = client.response(1);
    assert_eq!(other_request.open_line(&first).unwrap_err().code(), "open");
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_response_that_stops_before_its_end_frame_is_truncated() {
    let (client, server) = pair();
    let mut reader = client.response(0);
    let more = server.seal_response(0, 0, false, b"one").unwrap();
    reader.open_line(&more).unwrap();
    assert_eq!(reader.finish().unwrap_err().code(), "truncated");
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_line_after_the_end_frame_is_refused() {
    let (client, server) = pair();
    let mut reader = client.response(0);
    let end = server.seal_response(0, 0, true, b"done").unwrap();
    let extra = server.seal_response(0, 1, false, b"more").unwrap();
    reader.open_line(&end).unwrap();
    assert_eq!(reader.open_line(&extra).unwrap_err().code(), "open");
    reader.finish().unwrap();
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_blank_line_carries_nothing() {
    let (client, _) = pair();
    assert!(client.response(0).open_line("  \n").unwrap().is_none());
}
