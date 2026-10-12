#![no_main]
//! The SignedInfo profile check (after the signature, in production).
use alpha_attest::gpu::local::rim;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rim::signed_digest(data);
});
