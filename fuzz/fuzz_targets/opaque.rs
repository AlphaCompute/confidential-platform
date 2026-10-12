#![no_main]
//! NVIDIA's opaque data and every typed accessor the appraisal uses.
use alpha_attest::gpu::local::opaque;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(o) = opaque::parse(data) {
        let _ = o.driver_version();
        let _ = o.vbios_version();
        let _ = o.nvdec0_status();
        let _ = o.feature_flag();
        let _ = o.fwid();
        let _ = o.min_svn(0x30);
    }
});
