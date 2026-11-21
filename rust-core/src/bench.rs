//! Real Pure Safe Rust Micro-Benchmarks (Hardware Catalog, EFI config.plist Synthesis,
//! Root-Patch Planner & FIPS 180-4 SHA-256 Verification).

use crate::efi_builder::{EfiBuildOptions, synthesize_config_plist};
use crate::json::{JsonValue, jnum, jstr, obj};
use crate::probe::probe_host;
use crate::security::sha256_hex;
use crate::sys_patch::build_root_patch_plan;
use std::time::Instant;

pub fn run_benchmarks() -> JsonValue {
    // 1. OpenCore 1.0.6 Tahoe config.plist Synthesis (1000 iterations)
    let opts = EfiBuildOptions {
        smbios: "MacPro5,1".to_string(),
        target_macos_major: 26,
        ..Default::default()
    };
    let t0 = Instant::now();
    let mut last_len = 0usize;
    for _ in 0..1000 {
        if let Ok(art) = synthesize_config_plist(&opts) {
            last_len = art.plist_xml.len();
        }
    }
    let plist_us = t0.elapsed().as_secs_f64() * 1_000_000.0 / 1000.0;

    // 2. Root-Patch Planner (1000 iterations)
    let probe = probe_host(Some("MacPro7,1-Vega20-KVM"), Some(26)).expect("sim probe");
    let t1 = Instant::now();
    let mut steps_count = 0usize;
    for _ in 0..1000 {
        let plan = build_root_patch_plan(&probe);
        steps_count = plan.patch_steps.len();
    }
    let plan_us = t1.elapsed().as_secs_f64() * 1_000_000.0 / 1000.0;

    // 3. FIPS 180-4 SHA-256 throughput on 4 MiB payload buffer
    let buf = vec![0xA5u8; 4 * 1024 * 1024];
    let t2 = Instant::now();
    let digest = sha256_hex(&buf);
    let sha_ms = t2.elapsed().as_secs_f64() * 1000.0;
    let sha_mb_s = 4.0 / (sha_ms / 1000.0).max(1e-6);

    obj(vec![
        ("engine", jstr("nala-oclp-rs")),
        ("version", jstr(crate::VERSION)),
        ("plist_synthesis_us_per_op", jnum((plist_us * 100.0).round() / 100.0)),
        ("plist_sample_bytes", jnum(last_len as f64)),
        ("root_patch_plan_us_per_op", jnum((plan_us * 100.0).round() / 100.0)),
        ("root_patch_sample_steps", jnum(steps_count as f64)),
        ("sha256_4mib_ms", jnum((sha_ms * 100.0).round() / 100.0)),
        ("sha256_throughput_mib_s", jnum((sha_mb_s * 10.0).round() / 10.0)),
        ("sha256_canary_prefix", jstr(&digest[..16])),
    ])
}
