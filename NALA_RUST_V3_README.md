# NALA-OpenCore-Legacy-Patcher v3.0.0 + `rust-core/` (`NALA-oclp-rs v3.0.0-nala.6.6.6`)

This repository combines:
1. **Fresh Upstream Dortania OpenCore Legacy Patcher `v3.x` (`main` / `3.0.0-rc.5+` — macOS 26 Tahoe)** synced cleanly via fast-forward (`upstream-3x-clean` branch preserves pure upstream `dortania/OpenCore-Legacy-Patcher` for zero-conflict future updates; `backup-v2.5.0-pre-v3` tag preserves the original `v2.5.0` fork state).
2. **`rust-core/` — `NALA-oclp-rs` (`v3.0.0-nala.6.6.6`)**: 100% Native Pure Safe Rust (`Edition 2024`, `#![forbid(unsafe_code)]`, **0 external crates**, **0% Python**) Control-Plane, Deterministic OpenCore `1.0.6` EFI `config.plist` Builder, Dry-Run Root-Volume Patch Planner, NCSP v2.5 APFS Snapshot/Rollback Guardian, 12-Tool Stdio MCP Server, and Offline AAA Precision Cockpit (`127.0.0.1:18796`) with 2-Click Dream/REA/RSI Evolution & Multi-IDE Prompt Compiler.

## Build & Run `rust-core/` (Zero Python)
```bash
cd rust-core
./install.sh
nala-oclp-rs doctor
nala-oclp-rs serve --bind 127.0.0.1:18796
```

## Architectural Note
All control-plane logic, hardware probing, `config.plist` synthesis, verification, MCP tooling, and UI run in 100% Pure Safe Rust (`~540 KB` binary). Authentic UEFI/XNU Mach-O binary payloads (`OpenCorePkg 1.0.6`, `PatcherSupportPkg 2.0.5`, Acidanthera `.kext`s, Apple `KDK`) remain official upstream binaries verified via FIPS 180-4 SHA-256.
