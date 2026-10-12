#![no_main]
//! The SPDM report parser and the opaque data inside it.
use alpha_attest::gpu::local::{opaque, spdm};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(report) = spdm::parse(data) {
        let _ = opaque::parse(report.opaque);
    }
});
