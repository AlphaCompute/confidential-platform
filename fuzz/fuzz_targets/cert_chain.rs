#![no_main]
//! PEM chains, DER certificates, their extensions and the DICE TcbInfo.
use std::time::Duration;

use alpha_attest::gpu::local::cert;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let certs = cert::parse_pem_chain(data)
        .or_else(|_| cert::parse_der(data).map(|c| vec![c]))
        .unwrap_or_default();
    for c in &certs {
        let _ = cert::extensions(c);
        let _ = cert::tcb_info(c);
        let _ = cert::common_name(c);
        let _ = cert::serial_decimal(c);
        let _ = cert::p384_key(c);
    }
    let _ = cert::verify_chain(&certs, &[], Duration::from_secs(1_800_000_000));
});
