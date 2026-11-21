# Third-Party Notices & Upstream Attribution

This project is an independent 100% Pure Safe Rust control-plane, EFI synthesizer,
root-patch planner, NCSP v2.5 snapshot/rollback guardian, and MCP/UI cockpit
designed to interoperate with authentic upstream binary payloads from:

1. **OpenCore Legacy Patcher (`dortania/OpenCore-Legacy-Patcher`, v3.0.0 / 3.x)**
   - Authors: Dhinak G, Mykola Grymalyuk, EduCovas, ASentientBot, Jazzzny & contributors
   - License: BSD-3-Clause
   - Role: Upstream `3.x` dataset definitions, macOS 26 Tahoe support specs, and `AutoPkg-Assets.pkg`

2. **OpenCorePkg (`acidanthera/OpenCorePkg`, v1.0.6+)**
   - License: BSD-3-Clause
   - Role: UEFI Bootloader `.efi` binaries (fetched directly from official releases, never rewritten in Rust)

3. **Acidanthera Kernel Extensions (`Lilu 1.7.2`, `WhateverGreen 1.7.1`, `CryptexFixup 1.0.5`, `RestrictEvents 1.1.7`, `FeatureUnlock 1.1.8`, `NVMeFix 1.1.3`, `BlueToolFixup 2.7.2`, `AirPortBrcmFixup 2.2.1`)**
   - License: BSD-3-Clause
   - Role: Native XNU Mach-O `.kext` binaries required by Apple's IOKit ABI

4. **PatcherSupportPkg (`dortania/PatcherSupportPkg`, v2.0.5+)**
   - Role: Upstream legacy macOS Metal / Non-Metal / Wireless binary support packages
