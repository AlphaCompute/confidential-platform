#![no_main]
//! OCSP responses, checked against NVIDIA's Blackwell sample chain.
use std::sync::OnceLock;
use std::time::Duration;

use alpha_attest::gpu::local::{cert, ocsp};
use libfuzzer_sys::fuzz_target;

static CHAIN: OnceLock<Vec<x509_cert::Certificate>> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let chain = CHAIN.get_or_init(|| {
        cert::parse_pem_chain(include_bytes!(
            "../../testdata/gpu/nvidia/blackwellCertChain.txt"
        ))
        .unwrap_or_default()
    });
    if let Ok(response) = ocsp::parse(data) {
        let _ = response.nonce();
        if let [_, cert, issuer, ..] = chain.as_slice() {
            let _ = response.is_about(cert, issuer);
            let _ = response.check(
                cert,
                issuer,
                Duration::from_secs(1_791_781_200),
                ocsp::Freshness {
                    max_age: Duration::from_secs(86_400),
                    accept_certificate_hold: false,
                },
            );
        }
    }
});
