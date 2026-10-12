#![no_main]
//! The canonical SWID document parser, reached as if the input's digest were signed.
use alpha_attest::gpu::local::rim;
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha384};

fuzz_target!(|data: &[u8]| {
    let digest: [u8; 48] = Sha384::digest(data).into();
    let _ = rim::parse_document(data, &digest);
});
