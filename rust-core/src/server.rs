//! Hardened Offline HTTP/1.1 Server (`127.0.0.1:18796`) & AAA Precision Boot-Engineering Cockpit.
//! Anti-AI-Slop Design: Dieter-Rams / Apple Hardware-Lab / Porsche-Telemetry Graphite Precision UI
//! (Zero CDN, Zero Telemetry, Strict 2-Click Confirmation Modal, Multi-IDE Prompt Studio).

use crate::bench::run_benchmarks;
use crate::catalog::catalog_as_json;
use crate::dream_rsi::{compile_ide_prompt, dream_evolution_proposals, execute_2click_gate};
use crate::efi_builder::{EfiBuildOptions, synthesize_config_plist};
use crate::json::{JsonValue, jbool, jnum, jstr, obj, parse_json};
use crate::probe::probe_host;
use crate::security::{MAX_HTTP_BODY_BYTES, RateLimiter, security_headers};
use crate::sys_patch::build_root_patch_plan;
use crate::upstream_sync::check_upstream_sync;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

pub fn serve_http(bind_addr: &str) -> Result<(), String> {
    let listener = TcpListener::bind(bind_addr)
        .map_err(|e| format!("Failed to bind {}: {}", bind_addr, e))?;
    println!(
        "[NALA-oclp-rs v{}] Offline AAA Cockpit listening on http://{}/ (SEC-01..05 active, 0% Python)",
        crate::VERSION,
        bind_addr
    );
    let mut limiter = RateLimiter::new(Duration::from_secs(60), 240);

    for stream in listener.incoming() {
        if let Ok(mut conn) = stream {
            let peer = conn
                .peer_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            if !limiter.allow(&peer) {
                let _ = write_response(
                    &mut conn,
                    429,
                    "Too Many Requests",
                    "application/json",
                    "{\"error\":\"SEC-04 rate limit exceeded\"}",
                );
                continue;
            }
            let _ = handle_connection(&mut conn);
        }
    }
    Ok(())
}

fn handle_connection(stream: &mut TcpStream) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let mut header_end = None;
    let mut content_length = 0usize;

    loop {
        let n = match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_HTTP_BODY_BYTES + 16384 {
            write_response(
                stream,
                413,
                "Payload Too Large",
                "application/json",
                "{\"error\":\"SEC-04 body exceeds 10 MiB cap\"}",
            )?;
            return Ok(());
        }
        if header_end.is_none()
            && let Some(pos) = find_subsequence(&buf, b"\r\n\r\n")
        {
            header_end = Some(pos + 4);
            let hdr_str = String::from_utf8_lossy(&buf[..pos]);
            for line in hdr_str.lines() {
                if let Some((k, v)) = line.split_once(':')
                    && k.trim().eq_ignore_ascii_case("content-length")
                {
                    content_length = v.trim().parse::<usize>().unwrap_or(0);
                    if content_length > MAX_HTTP_BODY_BYTES {
                        write_response(
                            stream,
                            413,
                            "Payload Too Large",
                            "application/json",
                            "{\"error\":\"SEC-04 Content-Length exceeds 10 MiB\"}",
                        )?;
                        return Ok(());
                    }
                }
            }
        }
        if let Some(end) = header_end
            && buf.len() >= end + content_length
        {
            break;
        }
    }

    let Some(h_end) = header_end else {
        return Ok(());
    };
    let head = String::from_utf8_lossy(&buf[..h_end]);
    let first_line = head.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let raw_path = parts.next().unwrap_or("/");
    let (path, query) = raw_path.split_once('?').unwrap_or((raw_path, ""));
    let body = String::from_utf8_lossy(&buf[h_end..buf.len().min(h_end + content_length)]);

    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            write_response(stream, 200, "OK", "text/html; charset=utf-8", COCKPIT_HTML)?;
        }
        ("GET", "/health") => {
            let h = obj(vec![
                ("status", jstr("ok")),
                ("engine", jstr("nala-oclp-rs")),
                ("version", jstr(crate::VERSION)),
                ("upstream_oclp", jstr(crate::UPSTREAM_OCLP_TAG)),
                ("opencore_version", jstr(crate::UPSTREAM_OPENCORE_VERSION)),
                ("python_runtime", jbool(false)),
            ]);
            write_response(stream, 200, "OK", "application/json", &h.to_json_string())?;
        }
        ("GET", "/api/catalog") => {
            write_response(
                stream,
                200,
                "OK",
                "application/json",
                &catalog_as_json().to_json_string(),
            )?;
        }
        ("GET", "/api/probe") => {
            let sim = query_param(query, "simulate");
            let target_os = query_param(query, "target_macos").and_then(|s| s.parse::<u32>().ok());
            match probe_host(sim.as_deref(), target_os) {
                Ok(p) => {
                    let plan = build_root_patch_plan(&p);
                    let resp = obj(vec![("probe", p.to_json()), ("root_patch_plan", plan.to_json())]);
                    write_response(stream, 200, "OK", "application/json", &resp.to_json_string())?;
                }
                Err(e) => write_json_error(stream, 400, &e)?,
            }
        }
        ("POST", "/api/build-efi") => {
            let parsed = parse_json(&body).unwrap_or_else(|_| obj(vec![]));
            let smbios = parsed
                .get("smbios")
                .and_then(|v| v.as_str())
                .unwrap_or("MacPro5,1")
                .to_string();
            let target_macos_major = parsed
                .get("target_macos")
                .and_then(|v| v.as_u64())
                .unwrap_or(26) as u32;
            let vega20 = parsed
                .get("vega20_proxmox")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let verbose = parsed
                .get("verbose")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            match synthesize_config_plist(&EfiBuildOptions {
                smbios,
                target_macos_major,
                enable_verbose_boot: verbose,
                vega20_proxmox_mode: vega20,
                ..Default::default()
            }) {
                Ok(art) => write_response(
                    stream,
                    200,
                    "OK",
                    "application/json",
                    &art.to_json(true).to_json_string(),
                )?,
                Err(e) => write_json_error(stream, 400, &e)?,
            }
        }
        ("GET", "/api/upstream-sync") => {
            let live = query_param(query, "live").as_deref() == Some("1");
            let rep = check_upstream_sync(live);
            write_response(
                stream,
                200,
                "OK",
                "application/json",
                &rep.to_json().to_json_string(),
            )?;
        }
        ("GET", "/api/bench") => {
            write_response(
                stream,
                200,
                "OK",
                "application/json",
                &run_benchmarks().to_json_string(),
            )?;
        }
        ("GET", "/api/dream/proposals") => {
            let items = dream_evolution_proposals()
                .into_iter()
                .map(|p| p.to_json())
                .collect();
            let res = obj(vec![
                ("council", jstr("Grand NALAtheON + Grand NEOP + Grand TheGremium (3-7 Rounds)")),
                ("count", jnum(5.0)),
                ("proposals", JsonValue::Array(items)),
            ]);
            write_response(stream, 200, "OK", "application/json", &res.to_json_string())?;
        }
        ("POST", "/api/dream/apply") => {
            let parsed = match parse_json(&body) {
                Ok(v) => v,
                Err(e) => {
                    write_json_error(stream, 400, &e)?;
                    return Ok(());
                }
            };
            let id = parsed
                .get("proposal_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let step2 = parsed
                .get("confirm_step2")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            match execute_2click_gate(id, step2, &PathBuf::from(".ncsp_backups")) {
                Ok(res) => write_response(stream, 200, "OK", "application/json", &res.to_json_string())?,
                Err(e) => write_json_error(stream, 400, &e)?,
            }
        }
        ("POST", "/api/dream/compile-prompt") => {
            let parsed = match parse_json(&body) {
                Ok(v) => v,
                Err(e) => {
                    write_json_error(stream, 400, &e)?;
                    return Ok(());
                }
            };
            let ide = parsed
                .get("ide")
                .and_then(|v| v.as_str())
                .unwrap_or("Antigravity");
            let id = parsed
                .get("proposal_id")
                .and_then(|v| v.as_str())
                .unwrap_or("OCLP-SYNC-01-UPSTREAM-3X-MANIFEST-COMPILER");
            match compile_ide_prompt(ide, id) {
                Ok(res) => write_response(stream, 200, "OK", "application/json", &res.to_json_string())?,
                Err(e) => write_json_error(stream, 400, &e)?,
            }
        }
        _ => write_json_error(stream, 404, "Endpoint not found")?,
    }
    Ok(())
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
            && !v.is_empty()
        {
            return Some(v.replace("%2C", ",").replace("%2c", ","));
        }
    }
    None
}

fn write_json_error(stream: &mut TcpStream, code: u16, msg: &str) -> Result<(), String> {
    let payload = obj(vec![("error", jstr(msg))]).to_json_string();
    write_response(stream, code, "Error", "application/json", &payload)
}

fn write_response(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    content_type: &str,
    body: &str,
) -> Result<(), String> {
    let hdrs = security_headers();
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n{}",
        code,
        reason,
        content_type,
        body.len(),
        hdrs,
        body
    );
    stream
        .write_all(resp.as_bytes())
        .map_err(|e| format!("write error: {}", e))?;
    let _ = stream.flush();
    Ok(())
}

/// AAA Anti-AI-Slop Offline Precision Hardware-Lab Cockpit HTML.
/// Zero external fonts/scripts/CDNs; machined graphite instrument styling,
/// strict 2-click confirmation dialog ("Wollen Sie wirklich?"), and 1-click Multi-IDE Prompt Studio.
const COCKPIT_HTML: &str = r##"<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NALA-OCLP-RS v3.0.0 — Precision Boot & Tahoe Engineering Cockpit</title>
<style>
:root{
  --bg:#0b0d10;--surface:#11151b;--surface-2:#161c24;--border:rgba(255,255,255,0.08);
  --border-hi:rgba(255,255,255,0.16);--ink:#edf1f7;--muted:#8b96a6;--dim:#5b6574;
  --ok:#00d084;--warn:#f59e0b;--danger:#ef4444;--accent:#d8dee9;
  --mono:"SF Mono","JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"SF Pro Display","Inter",system-ui,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
.shell{max-width:1360px;margin:0 auto;padding:24px 28px 64px}
header{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;padding-bottom:18px;border-bottom:1px solid var(--border);margin-bottom:22px;flex-wrap:wrap}
.brand-kicker{font-family:var(--mono);font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--ok);margin-bottom:4px}
h1{font-size:22px;font-weight:600;letter-spacing:-0.02em}
.sub{color:var(--muted);font-size:13px;margin-top:3px}
.pills{display:flex;gap:8px;flex-wrap:wrap}
.pill{font-family:var(--mono);font-size:11px;padding:4px 9px;border:1px solid var(--border-hi);background:var(--surface);border-radius:4px;color:var(--accent)}
.pill.ok{border-color:rgba(0,208,132,0.35);color:var(--ok)}
.nav{display:flex;gap:4px;border-bottom:1px solid var(--border);margin-bottom:22px;flex-wrap:wrap}
.tab{background:transparent;color:var(--muted);border:none;border-bottom:2px solid transparent;padding:10px 16px;font-size:13px;font-weight:500;cursor:pointer;transition:color .15s,border-color .15s}
.tab:hover{color:var(--ink)}
.tab.active{color:var(--ink);border-bottom-color:var(--ok)}
.panel{display:none}.panel.active{display:block}
.grid-4{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-bottom:20px}
.grid-2{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:16px;margin-bottom:20px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:16px 18px}
.card h2{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--muted);margin-bottom:12px;font-family:var(--mono)}
.metric-label{font-family:var(--mono);font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:0.06em}
.metric-val{font-family:var(--mono);font-size:20px;font-weight:600;margin-top:4px;font-variant-numeric:tabular-nums}
.metric-note{font-size:12px;color:var(--dim);margin-top:4px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
select,button{font-family:var(--sans);font-size:13px;border-radius:4px}
select{background:var(--surface-2);color:var(--ink);border:1px solid var(--border-hi);padding:7px 10px}
.btn{background:var(--surface-2);color:var(--ink);border:1px solid var(--border-hi);padding:7px 13px;cursor:pointer;font-weight:500}
.btn:hover{border-color:var(--ink)}
.btn-primary{background:var(--ok);color:#06120c;border-color:var(--ok);font-weight:600}
.btn-primary:hover{filter:brightness(1.08)}
.btn-danger{background:var(--danger);color:#fff;border-color:var(--danger);font-weight:600}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:var(--muted);font-weight:500}
.mono{font-family:var(--mono);font-variant-numeric:tabular-nums}
.tag{display:inline-block;font-family:var(--mono);font-size:10.5px;padding:2px 6px;border-radius:3px;border:1px solid var(--border-hi);background:var(--surface-2)}
.tag.ok{color:var(--ok);border-color:rgba(0,208,132,0.35)}
.tag.warn{color:var(--warn);border-color:rgba(245,158,11,0.35)}
pre{background:#080a0d;border:1px solid var(--border);border-radius:4px;padding:12px;overflow:auto;font-family:var(--mono);font-size:11.5px;line-height:1.45;max-height:420px;color:#d6dde8;white-space:pre-wrap;word-break:break-word}
.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,0.72);display:none;align-items:center;justify-content:center;padding:20px;z-index:99}
.modal-backdrop.open{display:flex}
.modal{background:var(--surface);border:1px solid var(--border-hi);border-radius:8px;max-width:540px;width:100%;padding:22px}
.modal h3{font-size:16px;margin-bottom:8px;color:var(--warn)}
.modal p{color:var(--muted);font-size:13px;margin-bottom:14px}
.modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:16px}
.toast{font-family:var(--mono);font-size:12px;padding:10px 12px;border-radius:4px;border:1px solid rgba(0,208,132,0.4);background:rgba(0,208,132,0.08);color:var(--ok);margin-top:12px;display:none}
</style>
</head>
<body>
<div class="shell">
  <header>
    <div>
      <div class="brand-kicker">NALA-OS PRECISION BOOT INSTRUMENT // 100% PURE SAFE RUST</div>
      <h1>NALA-OCLP-RS v3.0.0-nala.6.6.6</h1>
      <div class="sub">Zero-Python Control-Plane, Deterministic OpenCore 1.0.6 EFI Builder, Upstream Dortania 3.x Sync &amp; NCSP v2.5 Rollback Guardian</div>
    </div>
    <div class="pills">
      <span class="pill ok">#![forbid(unsafe_code)]</span>
      <span class="pill ok">0 CRATES · 0% PYTHON</span>
      <span class="pill">UPSTREAM 3.0.0-rc.5+</span>
      <span class="pill">OPENCORE 1.0.6</span>
      <span class="pill">PATCHERSUPPORTPKG 2.0.5</span>
    </div>
  </header>

  <nav class="nav">
    <button class="tab active" onclick="showTab('hw',this)">1. Hardware &amp; Tahoe 3.x Telemetry</button>
    <button class="tab" onclick="showTab('efi',this)">2. OpenCore 1.0.6 EFI Studio</button>
    <button class="tab" onclick="showTab('sync',this)">3. Upstream 3.x Sync &amp; Payloads</button>
    <button class="tab" onclick="showTab('dream',this)">4. Dream / REA / RSI 2-Klick &amp; Prompt Studio</button>
  </nav>

  <section id="tab-hw" class="panel active">
    <div class="row">
      <label class="mono" style="color:var(--muted)">Target / Simulator:</label>
      <select id="sim-select" onchange="loadProbe()">
        <option value="">Live Host Probe (Current Machine)</option>
        <option value="MacPro5,1" selected>Simulate: MacPro5,1 (2010-2012 Dual Xeon Non-AVX2)</option>
        <option value="MacPro7,1-Vega20-KVM">Simulate: MacPro7,1 Proxmox KVM + Radeon Pro VII Vega 20</option>
        <option value="MacBookPro11,5">Simulate: MacBookPro11,5 (Haswell Metal 3802)</option>
        <option value="MacBookPro13,3">Simulate: MacBookPro13,3 (Skylake + T1 Tahoe)</option>
        <option value="MacBookPro8,2">Simulate: MacBookPro8,2 (2011 Non-Metal TeraScale 2)</option>
        <option value="iMac14,2">Simulate: iMac14,2 (Kepler Metal 3802)</option>
      </select>
      <select id="os-select" onchange="loadProbe()">
        <option value="26" selected>macOS 26 Tahoe (Darwin 25)</option>
        <option value="15">macOS 15 Sequoia (Darwin 24)</option>
        <option value="14">macOS 14 Sonoma (Darwin 23)</option>
        <option value="13">macOS 13 Ventura (Darwin 22)</option>
      </select>
      <button class="btn" onclick="loadProbe()">Re-Probe</button>
    </div>
    <div class="grid-4" id="hw-metrics"></div>
    <div class="card">
      <h2>Dry-Run Root-Volume Patch Plan &amp; NCSP Rollback Anchor</h2>
      <div id="patch-plan-box">Loading...</div>
    </div>
  </section>

  <section id="tab-efi" class="panel">
    <div class="card" style="margin-bottom:16px">
      <h2>Deterministic OpenCore 1.0.6 config.plist Synthesizer</h2>
      <div class="row">
        <select id="efi-smbios">
          <option value="MacPro5,1">MacPro5,1 (Non-AVX2 + USB 1.1 + Polaris/GCN)</option>
          <option value="MacPro7,1-Vega20-KVM">MacPro7,1-Vega20-KVM (Proxmox 3440x1440 + agdpmod=pikera)</option>
          <option value="MacBookPro11,5">MacBookPro11,5 (Metal 3802)</option>
          <option value="MacBookPro13,3">MacBookPro13,3 (T1 Security Enclave Tahoe)</option>
          <option value="MacBookPro8,2">MacBookPro8,2 (Non-Metal 3.0.0)</option>
        </select>
        <select id="efi-os">
          <option value="26">macOS 26 Tahoe (Darwin 25)</option>
          <option value="15">macOS 15 Sequoia (Darwin 24)</option>
        </select>
        <label class="mono" style="font-size:12px"><input type="checkbox" id="efi-verbose"> Verbose (-v)</label>
        <button class="btn btn-primary" onclick="buildEfi()">Synthesize OpenCore 1.0.6 config.plist</button>
      </div>
      <div id="efi-summary" class="mono" style="font-size:12px;color:var(--ok);margin-bottom:10px"></div>
      <pre id="efi-xml">Click "Synthesize OpenCore 1.0.6 config.plist" to generate a SHA-256 verified Apple Property List.</pre>
    </div>
  </section>

  <section id="tab-sync" class="panel">
    <div class="grid-2">
      <div class="card">
        <h2>Upstream Dortania 3.x vs Fork Drift</h2>
        <div class="row">
          <button class="btn" onclick="loadSync(false)">Offline Baseline</button>
          <button class="btn btn-primary" onclick="loadSync(true)">Live GitHub API Check</button>
        </div>
        <div id="sync-info">Loading...</div>
      </div>
      <div class="card">
        <h2>Rust Control-Plane vs Upstream Binary Payloads (Architectural Truth)</h2>
        <p style="color:var(--muted);font-size:12.5px;margin-bottom:10px">
          100% of the Patcher App, Hardware Scanner, EFI Builder, Root-Patch Orchestrator, NCSP Rollback Guardian, MCP Server &amp; UI runs in Pure Safe Rust.
          UEFI Bootloaders &amp; XNU Mach-O Kernel Extensions remain authentic upstream binaries verified via FIPS 180-4 SHA-256.
        </p>
        <div id="payload-table"></div>
      </div>
    </div>
  </section>

  <section id="tab-dream" class="panel">
    <div class="card" style="margin-bottom:16px">
      <h2>Dream / Software-Pearls / REA / RSI — Lösungsmatrix &amp; Delta-Übersichts-Matrix (3–7 Runden Triple-Council)</h2>
      <div id="dream-table">Loading proposals...</div>
      <div id="dream-toast" class="toast"></div>
    </div>
    <div class="card">
      <h2>1-Klick Multi-IDE Prompt-Compiler (Codex · Antigravity · ZCode · OpenCode)</h2>
      <div class="row">
        <select id="prompt-ide">
          <option value="Antigravity">Antigravity</option>
          <option value="Codex">Codex</option>
          <option value="ZCode">ZCode</option>
          <option value="OpenCode">OpenCode</option>
        </select>
        <select id="prompt-proposal"></select>
        <button class="btn btn-primary" onclick="compilePrompt()">Generate Prompt</button>
        <button class="btn" onclick="copyPrompt()">Copy to Clipboard</button>
      </div>
      <pre id="prompt-output">Select an IDE and proposal to compile a ready-to-paste prompt with the verbatim mandatory TheStandart footer.</pre>
    </div>
  </section>
</div>

<div class="modal-backdrop" id="confirm-modal">
  <div class="modal">
    <h3>2. Klick Sicherheits-Bestätigung (NCSP v2.5)</h3>
    <p id="modal-msg">Wollen Sie wirklich?</p>
    <div class="mono" id="modal-meta" style="font-size:11.5px;background:#080a0d;padding:10px;border-radius:4px;border:1px solid var(--border);color:var(--accent)"></div>
    <div class="modal-actions">
      <button class="btn" onclick="closeModal()">Abbrechen</button>
      <button class="btn btn-danger" onclick="confirmStep2()">AUSFÜHREN (NCSP Snapshot + Apply)</button>
    </div>
  </div>
</div>

<script>
let pendingProposal = null;
function showTab(id, btn){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+id).classList.add('active');
  btn.classList.add('active');
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

async function loadProbe(){
  const sim = document.getElementById('sim-select').value;
  const os = document.getElementById('os-select').value;
  const q = sim ? `?simulate=${encodeURIComponent(sim)}&target_macos=${os}` : '';
  const r = await fetch('/api/probe'+q);
  const d = await r.json();
  const p = d.probe, pl = d.root_patch_plan;
  document.getElementById('hw-metrics').innerHTML = `
    <div class="card"><div class="metric-label">SMBIOS Target</div><div class="metric-val">${esc(p.smbios)}</div><div class="metric-note">${p.simulated?'Simulated Profile':'Live Host ('+esc(p.arch)+')'}</div></div>
    <div class="card"><div class="metric-label">macOS / Darwin</div><div class="metric-val">${esc(p.macos_marketing)}</div><div class="metric-note">Darwin ${p.darwin_major} · Build ${esc(p.macos_build)}</div></div>
    <div class="card"><div class="metric-label">CPU AVX2 / GPU Class</div><div class="metric-val">${p.cpu_has_avx2?'AVX2':'NON-AVX2'}</div><div class="metric-note">${esc(p.gpu_class)} · Wi-Fi: ${esc(p.wifi_class)}</div></div>
    <div class="card"><div class="metric-label">Root-Patch Steps</div><div class="metric-val">${pl.patch_steps.length}</div><div class="metric-note">Dry-Run Default · SIP: ${esc(p.sip_status)}</div></div>
  `;
  let html = `<p style="color:var(--muted);margin-bottom:10px">${esc(p.notes)}</p>`;
  if(pl.blockers.length){
    html += `<div style="color:var(--warn);margin-bottom:10px" class="mono">BLOCKERS: ${pl.blockers.map(esc).join(' | ')}</div>`;
  }
  html += `<table><thead><tr><th>Step ID</th><th>Category</th><th>Description</th><th>Upstream Payload / macOS System Tool</th></tr></thead><tbody>`;
  for(const s of pl.patch_steps){
    html += `<tr><td class="mono">${esc(s.id)}</td><td><span class="tag">${esc(s.category)}</span></td><td>${esc(s.description)}</td><td class="mono">${esc(s.upstream_source)}<br><span style="color:var(--dim)">${esc(s.macos_system_tool)}</span></td></tr>`;
  }
  html += `</tbody></table><div class="mono" style="margin-top:10px;font-size:11.5px;color:var(--ok)">NCSP Rollback Anchor: ${esc(pl.ncsp_rollback_command)}</div>`;
  document.getElementById('patch-plan-box').innerHTML = html;
}

async function buildEfi(){
  const smbios = document.getElementById('efi-smbios').value;
  const target_macos = Number(document.getElementById('efi-os').value);
  const verbose = document.getElementById('efi-verbose').checked;
  const vega20_proxmox = smbios.includes('Vega20');
  const r = await fetch('/api/build-efi',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({smbios,target_macos,verbose,vega20_proxmox})});
  const d = await r.json();
  document.getElementById('efi-summary').textContent = `SHA-256: ${d.plist_sha256} | Bytes: ${d.plist_bytes} | CSR: 0x${d.csr_active_config_hex} | Kexts: ${d.kexts_included.length} | Guards: ${d.guards_enforced.join(' ; ')}`;
  document.getElementById('efi-xml').textContent = d.plist_xml;
}

async function loadSync(live){
  const r = await fetch('/api/upstream-sync'+(live?'?live=1':''));
  const d = await r.json();
  document.getElementById('sync-info').innerHTML = `
    <div class="mono" style="font-size:12px;margin-bottom:10px">
      Upstream: <b>${esc(d.upstream_repo)}</b> (${esc(d.upstream_latest_release)} @ ${esc(d.upstream_main_sha)})<br>
      Fork: <b>${esc(d.fork_repo)}</b> (@ ${esc(d.fork_main_sha)})<br>
      Drift: <span class="tag warn">${d.commits_behind} commits behind · ${d.files_changed_upstream} files changed</span>
    </div>
    <p style="color:var(--muted);font-size:12.5px;margin-bottom:10px">${esc(d.notes)}</p>
    <pre>${esc(d.safe_sync_commands.join('\n'))}</pre>
  `;
}

async function loadCatalog(){
  const r = await fetch('/api/catalog');
  const d = await r.json();
  let h = `<table><thead><tr><th>Payload</th><th>v3.x Ver</th><th>Format</th><th>Rust?</th></tr></thead><tbody>`;
  for(const p of d.payloads){
    h += `<tr><td class="mono">${esc(p.name)}</td><td class="mono">${esc(p.version)}</td><td>${esc(p.binary_format)}</td><td><span class="tag warn">UPSTREAM BIN (SHA-256)</span></td></tr>`;
  }
  h += `</tbody></table>`;
  document.getElementById('payload-table').innerHTML = h;
}

async function loadDream(){
  const r = await fetch('/api/dream/proposals');
  const d = await r.json();
  let h = `<table><thead><tr><th>Proposal / Source</th><th>Council</th><th>Δ Performance</th><th>Δ Features</th><th>Δ Sicherheit</th><th>2-Klick Gate</th></tr></thead><tbody>`;
  const sel = document.getElementById('prompt-proposal');
  sel.innerHTML = '';
  for(const p of d.proposals){
    sel.innerHTML += `<option value="${esc(p.id)}">${esc(p.id)} — ${esc(p.title)}</option>`;
    h += `<tr>
      <td><div class="mono" style="font-weight:600">${esc(p.id)}</div><div>${esc(p.title)}</div><span class="tag">${esc(p.source)}</span> <span class="tag ok">${esc(p.ncsp_risk)}</span></td>
      <td class="mono">${p.council_rounds} Runden<br>Δ=${p.convergence_delta_pct}%</td>
      <td>${esc(p.delta_performance)}</td>
      <td>${esc(p.delta_features)}</td>
      <td>${esc(p.delta_security)}</td>
      <td><button class="btn btn-primary" onclick="clickStep1('${esc(p.id)}')">1. Klick: Installieren / Umsetzen</button></td>
    </tr>`;
  }
  h += `</tbody></table>`;
  document.getElementById('dream-table').innerHTML = h;
}

async function clickStep1(id){
  const r = await fetch('/api/dream/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proposal_id:id,confirm_step2:false})});
  const d = await r.json();
  pendingProposal = id;
  document.getElementById('modal-msg').textContent = d.prompt_question || 'Wollen Sie wirklich?';
  document.getElementById('modal-meta').textContent = `Proposal: ${d.proposal_id}\nTitel: ${d.title}\nNCSP Risiko: ${d.ncsp_risk}\nRollback: ${d.rollback_strategy}`;
  document.getElementById('confirm-modal').classList.add('open');
}
function closeModal(){document.getElementById('confirm-modal').classList.remove('open');pendingProposal=null;}
async function confirmStep2(){
  if(!pendingProposal)return;
  const id = pendingProposal;
  closeModal();
  const r = await fetch('/api/dream/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proposal_id:id,confirm_step2:true})});
  const d = await r.json();
  const t = document.getElementById('dream-toast');
  t.style.display='block';
  t.textContent = `[NCSP v2.5 EXECUTED] ${d.proposal_id} | Snapshot: ${d.ncsp_snapshot_dir} | SHA-256: ${d.ncsp_inventory_sha256} | Rollback: ${d.rollback_script}`;
}
async function compilePrompt(){
  const ide = document.getElementById('prompt-ide').value;
  const proposal_id = document.getElementById('prompt-proposal').value;
  const r = await fetch('/api/dream/compile-prompt',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ide,proposal_id})});
  const d = await r.json();
  document.getElementById('prompt-output').textContent = d.prompt;
}
function copyPrompt(){navigator.clipboard.writeText(document.getElementById('prompt-output').textContent);}

loadProbe();loadSync(false);loadCatalog();loadDream();
</script>
</body>
</html>
"##;
