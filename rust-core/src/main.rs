#![forbid(unsafe_code)]

use nala_oclp_rs::bench::run_benchmarks;
use nala_oclp_rs::catalog::catalog_as_json;
use nala_oclp_rs::dream_rsi::{compile_ide_prompt, dream_evolution_proposals, execute_2click_gate};
use nala_oclp_rs::efi_builder::{
    EfiBuildOptions, synthesize_config_plist, verify_plist_file, write_efi_staging,
};
use nala_oclp_rs::json::{JsonValue, jbool, jnum, jstr, obj};
use nala_oclp_rs::mcp::run_stdio_mcp_server;
use nala_oclp_rs::probe::probe_host;
use nala_oclp_rs::security::{audit_directory_pii, validate_safe_rel_path};
use nala_oclp_rs::server::serve_http;
use nala_oclp_rs::sys_patch::{build_root_patch_plan, create_ncsp_snapshot};
use nala_oclp_rs::upstream_sync::check_upstream_sync;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || matches!(args[1].as_str(), "-h" | "--help" | "help") {
        print_help();
        return ExitCode::SUCCESS;
    }

    match run_cli(&args[1..]) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[NALA-oclp-rs ERROR] {}", e);
            ExitCode::FAILURE
        }
    }
}

fn run_cli(args: &[String]) -> Result<(), String> {
    match args[0].as_str() {
        "--version" | "-V" | "version" => {
            println!(
                "nala-oclp-rs {} (upstream OCLP {}, OpenCore {}, PatcherSupportPkg {}, 100% Pure Safe Rust, 0 Crates, 0% Python)",
                nala_oclp_rs::VERSION,
                nala_oclp_rs::UPSTREAM_OCLP_TAG,
                nala_oclp_rs::UPSTREAM_OPENCORE_VERSION,
                nala_oclp_rs::UPSTREAM_PATCHER_SUPPORT_PKG
            );
            Ok(())
        }
        "detect" => {
            let sim = flag_value(args, "--simulate");
            let target_os = flag_value(args, "--target-macos").and_then(|s| s.parse::<u32>().ok());
            let probe = probe_host(sim.as_deref(), target_os)?;
            println!("{}", probe.to_json().to_json_pretty());
            Ok(())
        }
        "catalog" => {
            println!("{}", catalog_as_json().to_json_pretty());
            Ok(())
        }
        "build-efi" => {
            let smbios = flag_value(args, "--smbios").unwrap_or_else(|| "MacPro5,1".to_string());
            let target_macos = flag_value(args, "--target-macos")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(26);
            let verbose = has_flag(args, "--verbose");
            let vega20 = has_flag(args, "--vega20-proxmox");
            let out_dir = flag_value(args, "--out");

            let art = synthesize_config_plist(&EfiBuildOptions {
                smbios,
                target_macos_major: target_macos,
                enable_verbose_boot: verbose,
                vega20_proxmox_mode: vega20,
                ..Default::default()
            })?;

            if let Some(dir) = out_dir {
                let path = PathBuf::from(&dir);
                let plist_path = write_efi_staging(&path, &art)?;
                let mut meta = art.to_json(false);
                if let JsonValue::Object(ref mut m) = meta {
                    m.insert("written_plist".to_string(), jstr(plist_path));
                }
                println!("{}", meta.to_json_pretty());
            } else {
                println!("{}", art.to_json(has_flag(args, "--print-xml")).to_json_pretty());
            }
            Ok(())
        }
        "verify-plist" => {
            let path = args.get(1).ok_or("Usage: nala-oclp-rs verify-plist <path/to/config.plist>")?;
            let res = verify_plist_file(&PathBuf::from(path))?;
            println!("{}", res.to_json_pretty());
            if res.get("overall_pass").and_then(|v| v.as_bool()) != Some(true) {
                return Err("Plist verification failed".to_string());
            }
            Ok(())
        }
        "plan-patch" => {
            let sim = flag_value(args, "--simulate");
            let target_os = flag_value(args, "--target-macos").and_then(|s| s.parse::<u32>().ok());
            let probe = probe_host(sim.as_deref(), target_os)?;
            let plan = build_root_patch_plan(&probe);
            println!("{}", plan.to_json().to_json_pretty());
            Ok(())
        }
        "sync-upstream" => {
            let live = has_flag(args, "--live");
            let rep = check_upstream_sync(live);
            println!("{}", rep.to_json().to_json_pretty());
            Ok(())
        }
        "ncsp-snapshot" => {
            let label = flag_value(args, "--label").unwrap_or_else(|| "manual".to_string());
            let out_base = flag_value(args, "--out").unwrap_or_else(|| ".ncsp_backups".to_string());
            let safe = validate_safe_rel_path(&out_base)?;
            let (dir, sha) = create_ncsp_snapshot(&safe, &label, "CLI NCSP v2.5 snapshot")?;
            let out = obj(vec![
                ("snapshot_dir", jstr(dir.to_string_lossy().to_string())),
                ("inventory_sha256", jstr(sha)),
            ]);
            println!("{}", out.to_json_pretty());
            Ok(())
        }
        "dream" => {
            if let Some(ide) = flag_value(args, "--compile-prompt") {
                let id = flag_value(args, "--proposal")
                    .unwrap_or_else(|| "OCLP-SYNC-01-UPSTREAM-3X-MANIFEST-COMPILER".to_string());
                let res = compile_ide_prompt(&ide, &id)?;
                println!("{}", res.get("prompt").and_then(|v| v.as_str()).unwrap_or(""));
                return Ok(());
            }
            if let Some(id) = flag_value(args, "--apply") {
                let confirm = has_flag(args, "--confirm-step2");
                let res = execute_2click_gate(&id, confirm, &PathBuf::from(".ncsp_backups"))?;
                println!("{}", res.to_json_pretty());
                return Ok(());
            }
            let list = dream_evolution_proposals()
                .into_iter()
                .map(|p| p.to_json())
                .collect();
            println!(
                "{}",
                obj(vec![
                    ("council", jstr("Grand NALAtheON + Grand NEOP + Grand TheGremium (3-7 Rounds)")),
                    ("proposals", JsonValue::Array(list)),
                ])
                .to_json_pretty()
            );
            Ok(())
        }
        "bench" => {
            println!("{}", run_benchmarks().to_json_pretty());
            Ok(())
        }
        "audit-pii" => {
            let dir = args.get(1).map(|s| s.as_str()).unwrap_or(".");
            let (scanned, findings) = audit_directory_pii(&PathBuf::from(dir))?;
            let items: Vec<JsonValue> = findings
                .iter()
                .map(|f| {
                    obj(vec![
                        ("file", jstr(&f.file)),
                        ("line", jnum(f.line as f64)),
                        ("rule", jstr(f.rule)),
                    ])
                })
                .collect();
            let out = obj(vec![
                ("files_scanned", jnum(scanned as f64)),
                ("pii_findings_count", jnum(findings.len() as f64)),
                ("pass", jbool(findings.is_empty())),
                ("findings", JsonValue::Array(items)),
            ]);
            println!("{}", out.to_json_pretty());
            if !findings.is_empty() {
                return Err(format!("sHeriFF Zero-PII audit found {} violation(s)", findings.len()));
            }
            Ok(())
        }
        "doctor" => {
            let probe = probe_host(None, None)?;
            let bench = run_benchmarks();
            let sim_efi = synthesize_config_plist(&EfiBuildOptions {
                smbios: "MacPro5,1".to_string(),
                target_macos_major: 26,
                ..Default::default()
            })?;
            let out = obj(vec![
                ("status", jstr("HEALTHY")),
                ("version", jstr(nala_oclp_rs::VERSION)),
                ("upstream_oclp", jstr(nala_oclp_rs::UPSTREAM_OCLP_TAG)),
                ("opencore_version", jstr(nala_oclp_rs::UPSTREAM_OPENCORE_VERSION)),
                ("rust_safety", jstr("#![forbid(unsafe_code)] · 0 Crates · 0% Python")),
                ("host_probe", probe.to_json()),
                ("tahoe_macpro51_self_test_sha256", jstr(sim_efi.plist_sha256)),
                ("benchmarks", bench),
            ]);
            println!("{}", out.to_json_pretty());
            Ok(())
        }
        "serve" => {
            let bind = flag_value(args, "--bind").unwrap_or_else(|| "127.0.0.1:18796".to_string());
            serve_http(&bind)
        }
        "mcp" => run_stdio_mcp_server(),
        other => Err(format!("Unknown subcommand '{}'. Run with --help.", other)),
    }
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn print_help() {
    println!(
        "NALA-oclp-rs {} — 100% Native Pure Safe Rust OpenCore Legacy Patcher v3.x Control-Plane\n\n\
         USAGE:\n\
           nala-oclp-rs detect [--simulate <SMBIOS>] [--target-macos <11..15|26>]\n\
           nala-oclp-rs catalog\n\
           nala-oclp-rs build-efi --smbios <SMBIOS> [--target-macos 26] [--vega20-proxmox] [--verbose] [--out <dir>] [--print-xml]\n\
           nala-oclp-rs verify-plist <path/to/config.plist>\n\
           nala-oclp-rs plan-patch [--simulate <SMBIOS>] [--target-macos 26]\n\
           nala-oclp-rs sync-upstream [--live]\n\
           nala-oclp-rs ncsp-snapshot [--label <name>] [--out <rel_dir>]\n\
           nala-oclp-rs dream [--apply <ID> [--confirm-step2]] [--compile-prompt <Codex|Antigravity|ZCode|OpenCode> --proposal <ID>]\n\
           nala-oclp-rs bench\n\
           nala-oclp-rs doctor\n\
           nala-oclp-rs audit-pii [dir]\n\
           nala-oclp-rs serve [--bind 127.0.0.1:18796]\n\
           nala-oclp-rs mcp\n",
        nala_oclp_rs::VERSION
    );
}
