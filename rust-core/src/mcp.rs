//! 12-Tool Stdio JSON-RPC 2.0 MCP Server (`nala-oclp-rs mcp`)
//! Enables NALA, Antigravity, Codex, ZCode, and OpenCode to drive OCLP v3.x natively.

use crate::bench::run_benchmarks;
use crate::catalog::catalog_as_json;
use crate::dream_rsi::{compile_ide_prompt, dream_evolution_proposals, execute_2click_gate};
use crate::efi_builder::{EfiBuildOptions, synthesize_config_plist, verify_plist_file};
use crate::json::{JsonValue, jbool, jnum, jstr, obj, parse_json};
use crate::probe::probe_host;
use crate::security::{audit_directory_pii, validate_safe_rel_path};
use crate::sys_patch::{build_root_patch_plan, create_ncsp_snapshot};
use crate::upstream_sync::check_upstream_sync;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

pub fn tool_definitions() -> JsonValue {
    let tools = vec![
        tool_spec("oclp_status", "Return NALA-oclp-rs version, upstream 3.x sync baseline, and Zero-Python/Zero-Crate security posture."),
        tool_spec("oclp_probe_hardware", "Probe live macOS/Linux host or simulate a legacy Mac SMBIOS (e.g. MacPro5,1, MacPro7,1-Vega20-KVM) for target macOS 11..26 Tahoe."),
        tool_spec("oclp_catalog_v3", "Return the full OCLP 3.0.0 (dortania/main) binary payload table (OpenCore 1.0.6, PatcherSupportPkg 2.0.5, Acidanthera Kexts) and supported Mac SMBIOS models."),
        tool_spec("oclp_plan_root_patch", "Generate a Dry-Run Root-Volume Patch Plan (Metal 31001/3802, Non-Metal, Tahoe Wireless, T1, USB 1.1, APFS Seal) + NCSP rollback command."),
        tool_spec("oclp_build_efi", "Synthesize a deterministic OpenCore 1.0.6 config.plist XML + SHA-256 for any legacy Mac SMBIOS and macOS target (11..26 Tahoe)."),
        tool_spec("oclp_verify_plist", "Verify an OpenCore config.plist via structural XML + Tahoe CryptexFixup MaxKernel bug check + native plutil -lint."),
        tool_spec("oclp_sync_upstream_check", "Check drift between Master-MD/NALA-OpenCore-Legacy-Patcher and official dortania/OpenCore-Legacy-Patcher 3.x main/releases."),
        tool_spec("oclp_ncsp_snapshot", "Create an atomic NCSP v2.5 snapshot with NCSP_INVENTORY.json, SHA256SUMS.txt, and rollback.sh."),
        tool_spec("oclp_audit_pii", "Run the sHeriFF Zero-PII & secret static audit on a target directory."),
        tool_spec("oclp_dream_proposals", "List all 3-7 Round Triple-Council Dream / Software-Pearls / REA / RSI proposals with Solution & Delta Matrix."),
        tool_spec("oclp_dream_apply_2click", "Execute the strict 2-Click approval gate (Step 1 prompts 'Wollen Sie wirklich?', Step 2 creates NCSP snapshot + rollback.sh)."),
        tool_spec("oclp_compile_ide_prompt", "Compile a ready-to-paste prompt for Codex, Antigravity, ZCode, or OpenCode ending verbatim with the mandatory TheStandart footer."),
    ];
    JsonValue::Array(tools)
}

fn tool_spec(name: &str, desc: &str) -> JsonValue {
    obj(vec![
        ("name", jstr(name)),
        ("description", jstr(desc)),
        (
            "inputSchema",
            obj(vec![
                ("type", jstr("object")),
                ("properties", obj(vec![])),
            ]),
        ),
    ])
}

pub fn run_stdio_mcp_server() -> Result<(), String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let raw = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req = match parse_json(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err_resp = obj(vec![
                    ("jsonrpc", jstr("2.0")),
                    ("id", JsonValue::Null),
                    (
                        "error",
                        obj(vec![("code", jnum(-32700.0)), ("message", jstr(e))]),
                    ),
                ]);
                let _ = writeln!(out, "{}", err_resp.to_json_string());
                let _ = out.flush();
                continue;
            }
        };

        let id = req.get("id").cloned().unwrap_or(JsonValue::Null);
        let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or_else(|| obj(vec![]));

        let resp = match method {
            "initialize" => obj(vec![
                ("jsonrpc", jstr("2.0")),
                ("id", id),
                (
                    "result",
                    obj(vec![
                        ("protocolVersion", jstr("2024-11-05")),
                        ("capabilities", obj(vec![("tools", obj(vec![]))])),
                        (
                            "serverInfo",
                            obj(vec![
                                ("name", jstr("nala-oclp-rs")),
                                ("version", jstr(crate::VERSION)),
                            ]),
                        ),
                    ]),
                ),
            ]),
            "tools/list" => obj(vec![
                ("jsonrpc", jstr("2.0")),
                ("id", id),
                ("result", obj(vec![("tools", tool_definitions())])),
            ]),
            "tools/call" => {
                let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| obj(vec![]));
                match dispatch_tool(name, &args) {
                    Ok(val) => obj(vec![
                        ("jsonrpc", jstr("2.0")),
                        ("id", id),
                        (
                            "result",
                            obj(vec![(
                                "content",
                                JsonValue::Array(vec![obj(vec![
                                    ("type", jstr("text")),
                                    ("text", jstr(val.to_json_pretty())),
                                ])]),
                            )]),
                        ),
                    ]),
                    Err(e) => obj(vec![
                        ("jsonrpc", jstr("2.0")),
                        ("id", id),
                        (
                            "result",
                            obj(vec![
                                ("isError", jbool(true)),
                                (
                                    "content",
                                    JsonValue::Array(vec![obj(vec![
                                        ("type", jstr("text")),
                                        ("text", jstr(e)),
                                    ])]),
                                ),
                            ]),
                        ),
                    ]),
                }
            }
            "notifications/initialized" => continue,
            _ => obj(vec![
                ("jsonrpc", jstr("2.0")),
                ("id", id),
                (
                    "error",
                    obj(vec![
                        ("code", jnum(-32601.0)),
                        ("message", jstr(format!("Method not found: {}", method))),
                    ]),
                ),
            ]),
        };

        writeln!(out, "{}", resp.to_json_string()).map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn dispatch_tool(name: &str, args: &JsonValue) -> Result<JsonValue, String> {
    match name {
        "oclp_status" => Ok(obj(vec![
            ("engine", jstr("nala-oclp-rs")),
            ("version", jstr(crate::VERSION)),
            ("upstream_oclp", jstr(crate::UPSTREAM_OCLP_TAG)),
            ("opencore_version", jstr(crate::UPSTREAM_OPENCORE_VERSION)),
            ("patcher_support_pkg", jstr(crate::UPSTREAM_PATCHER_SUPPORT_PKG)),
            ("rust_edition", jstr("2024")),
            ("unsafe_code", jstr("FORBIDDEN")),
            ("external_crates", jnum(0.0)),
            ("python_runtime", jbool(false)),
            ("bench_snapshot", run_benchmarks()),
        ])),
        "oclp_probe_hardware" => {
            let sim = args.get("simulate").and_then(|v| v.as_str());
            let target_os = args.get("target_macos").and_then(|v| v.as_u64()).map(|n| n as u32);
            Ok(probe_host(sim, target_os)?.to_json())
        }
        "oclp_catalog_v3" => Ok(catalog_as_json()),
        "oclp_plan_root_patch" => {
            let sim = args.get("simulate").and_then(|v| v.as_str());
            let target_os = args.get("target_macos").and_then(|v| v.as_u64()).map(|n| n as u32);
            let p = probe_host(sim, target_os)?;
            Ok(build_root_patch_plan(&p).to_json())
        }
        "oclp_build_efi" => {
            let smbios = args
                .get("smbios")
                .and_then(|v| v.as_str())
                .unwrap_or("MacPro5,1")
                .to_string();
            let target_macos_major = args
                .get("target_macos")
                .and_then(|v| v.as_u64())
                .unwrap_or(26) as u32;
            let vega20 = args
                .get("vega20_proxmox")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let include_xml = args
                .get("include_xml")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let art = synthesize_config_plist(&EfiBuildOptions {
                smbios,
                target_macos_major,
                vega20_proxmox_mode: vega20,
                ..Default::default()
            })?;
            Ok(art.to_json(include_xml))
        }
        "oclp_verify_plist" => {
            let rel = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or("Missing 'path' argument")?;
            let safe = validate_safe_rel_path(rel)?;
            verify_plist_file(&safe)
        }
        "oclp_sync_upstream_check" => {
            let live = args.get("live").and_then(|v| v.as_bool()).unwrap_or(false);
            Ok(check_upstream_sync(live).to_json())
        }
        "oclp_ncsp_snapshot" => {
            let label = args
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("manual");
            let summary = args
                .get("summary")
                .and_then(|v| v.as_str())
                .unwrap_or("MCP NCSP snapshot");
            let base = PathBuf::from(".ncsp_backups");
            let (dir, sha) = create_ncsp_snapshot(&base, label, summary)?;
            Ok(obj(vec![
                ("snapshot_dir", jstr(dir.to_string_lossy().to_string())),
                ("inventory_sha256", jstr(sha)),
            ]))
        }
        "oclp_audit_pii" => {
            let dir = args.get("dir").and_then(|v| v.as_str()).unwrap_or(".");
            let (scanned, findings) = audit_directory_pii(&PathBuf::from(dir))?;
            Ok(obj(vec![
                ("files_scanned", jnum(scanned as f64)),
                ("pii_findings_count", jnum(findings.len() as f64)),
                ("pass", jbool(findings.is_empty())),
            ]))
        }
        "oclp_dream_proposals" => {
            let items = dream_evolution_proposals()
                .into_iter()
                .map(|p| p.to_json())
                .collect();
            Ok(obj(vec![
                ("count", jnum(5.0)),
                ("proposals", JsonValue::Array(items)),
            ]))
        }
        "oclp_dream_apply_2click" => {
            let id = args
                .get("proposal_id")
                .and_then(|v| v.as_str())
                .ok_or("Missing 'proposal_id'")?;
            let step2 = args
                .get("confirm_step2")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            execute_2click_gate(id, step2, &PathBuf::from(".ncsp_backups"))
        }
        "oclp_compile_ide_prompt" => {
            let ide = args
                .get("ide")
                .and_then(|v| v.as_str())
                .unwrap_or("Antigravity");
            let id = args
                .get("proposal_id")
                .and_then(|v| v.as_str())
                .unwrap_or("OCLP-SYNC-01-UPSTREAM-3X-MANIFEST-COMPILER");
            compile_ide_prompt(ide, id)
        }
        _ => Err(format!("Unknown MCP tool '{}'", name)),
    }
}
