# NALA-oclp-rs (`v3.0.0-nala.6.6.6`)

100% Native Pure Safe Rust (`Edition 2024`, `#![forbid(unsafe_code)]`, **0 external crates**, **0% Python**) Control-Plane, Deterministic OpenCore `1.0.6` EFI Synthesizer, Upstream `dortania/OpenCore-Legacy-Patcher` `v3.x` (`3.0.0-rc.5+` / macOS 26 Tahoe) Sync Engine, NCSP v2.5 APFS Snapshot/Rollback Guardian, 12-Tool Stdio MCP Server, and Offline AAA Precision Cockpit (`127.0.0.1:18796`).

## Architectural Truth: What Is 100% Rust vs. What Stays Upstream Binary

| Layer | Implementation | Why |
| :--- | :--- | :--- |
| **App, CLI, Hardware Probe, EFI `config.plist` Builder, Root-Patch Planner, NCSP Snapshot/Rollback, MCP Server & AAA Cockpit** | **100% Pure Safe Rust (`std`-only, `< 1 MB` binary)** | Eliminates ~738 MB PyInstaller/wxPython runtime, `< 40 ms` cold start, zero Xcode-CLT shim traps, deterministic SHA-256 verification. |
| **UEFI Bootloader & XNU Kernel Payloads (`OpenCorePkg 1.0.6`, `Lilu 1.7.2`, `WhateverGreen 1.7.1`, `CryptexFixup 1.0.5`, `PatcherSupportPkg 2.0.5`, Apple `KDK`)** | **Official Upstream Binaries (SHA-256 Verified)** | Apple's UEFI firmware, XNU IOKit C++ ABI, and Metal 31001/3802 / Non-Metal shaders strictly require original Mach-O / PE32+ binaries from Dortania, Acidanthera, and Apple. |

## Quickstart

```bash
# Build & install to ~/bin/nala-oclp-rs (symlink ~/bin/oclp-rs)
./install.sh

# Self-test, benchmarks & sHeriFF Zero-PII audit
nala-oclp-rs doctor
nala-oclp-rs bench
nala-oclp-rs audit-pii .

# Plan macOS 26 Tahoe (Darwin 25) for MacPro5,1 or Proxmox Vega 20 KVM
nala-oclp-rs detect --simulate MacPro5,1 --target-macos 26
nala-oclp-rs plan-patch --simulate MacPro7,1-Vega20-KVM --target-macos 26
nala-oclp-rs build-efi --smbios MacPro5,1 --target-macos 26 --out ./staging_efi
nala-oclp-rs verify-plist ./staging_efi/EFI/OC/config.plist

# Compare Master-MD fork vs official dortania/OpenCore-Legacy-Patcher 3.x
nala-oclp-rs sync-upstream --live

# Offline AAA Precision Cockpit + 2-Click Dream/REA/RSI & Multi-IDE Prompt Studio
nala-oclp-rs serve --bind 127.0.0.1:18796

# 12-Tool Stdio MCP Server
nala-oclp-rs mcp
```

## Attribution & License
Licensed under **BSD-3-Clause**. Includes architectural compatibility with **Dortania OpenCore Legacy Patcher (`3.0.0`)**, **Acidanthera OpenCorePkg (`1.0.6`)**, and **PatcherSupportPkg (`2.0.5`)**. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
