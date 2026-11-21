//! Authentic Upstream OCLP v3.0.0 (`dortania/OpenCore-Legacy-Patcher` main / `3.0.0-rc.5+` d7a3d94)
//! SSOT Component Catalog, Darwin 20..25 <-> macOS 11..26 Tahoe Version Mapper,
//! Supported Legacy Mac SMBIOS Registry & Hardware Patchset Rules.

use crate::json::{JsonValue, jbool, jnum, jstr, obj};

#[derive(Debug, Clone)]
pub struct UpstreamPayloadSpec {
    pub name: &'static str,
    pub version: &'static str,
    pub category: &'static str, // "BOOTLOADER" | "KEXT_ACIDANTHERA" | "KEXT_APPLE_LEGACY" | "SUPPORT_PKG"
    pub binary_format: &'static str,
    pub rust_rewriteable: bool,
    pub reason: &'static str,
    pub source_repo: &'static str,
}

#[derive(Debug, Clone)]
pub struct MacModelProfile {
    pub smbios: &'static str,
    pub family: &'static str,
    pub year: u16,
    pub cpu_has_avx2: bool,
    pub gpu_class: &'static str, // "METAL_3802" | "METAL_31001" | "NON_METAL" | "AMD_VEGA20" | "AMD_POLARIS_GCN" | "AMD_NAVI"
    pub wifi_class: &'static str, // "MODERN_BRCM" | "LEGACY_BRCM_TAHOE" | "LEGACY_ATHEROS_TAHOE" | "NONE"
    pub has_t1_chip: bool,
    pub needs_usb11_patch: bool,
    pub tahoe_supported_v3: bool,
    pub notes: &'static str,
}

/// Official OCLP 3.0.0 (`main` commit d7a3d94 / `3.0.0-rc.5+`) Binary Payload Matrix.
pub fn upstream_v3_payloads() -> Vec<UpstreamPayloadSpec> {
    vec![
        UpstreamPayloadSpec {
            name: "OpenCorePkg",
            version: "1.0.6",
            category: "BOOTLOADER",
            binary_format: "UEFI PE32+ (.efi)",
            rust_rewriteable: false,
            reason: "EDK2 UEFI firmware boot-services driver; fetched & SHA-256 verified directly from acidanthera/OpenCorePkg.",
            source_repo: "https://github.com/acidanthera/OpenCorePkg",
        },
        UpstreamPayloadSpec {
            name: "PatcherSupportPkg",
            version: "2.0.5",
            category: "SUPPORT_PKG",
            binary_format: "DMG / Universal-Binaries (Apple Mach-O)",
            rust_rewriteable: false,
            reason: "Contains signed/extracted Apple Metal 31001/3802, Non-Metal & AirPort legacy frameworks needed by WindowServer & dyld_shared_cache.",
            source_repo: "https://github.com/dortania/PatcherSupportPkg",
        },
        UpstreamPayloadSpec {
            name: "Lilu.kext",
            version: "1.7.2",
            category: "KEXT_ACIDANTHERA",
            binary_format: "XNU Mach-O Kernel Extension",
            rust_rewriteable: false,
            reason: "Core XNU kernel & kext patcher runtime (C++ IOKit ABI); mandatory for Darwin 25 (macOS 26 Tahoe).",
            source_repo: "https://github.com/acidanthera/Lilu",
        },
        UpstreamPayloadSpec {
            name: "WhateverGreen.kext",
            version: "1.7.1",
            category: "KEXT_ACIDANTHERA",
            binary_format: "XNU Mach-O Kernel Extension",
            rust_rewriteable: false,
            reason: "AMD/Intel/NVIDIA framebuffer, agdpmod=pikera & DRM patching on XNU kernel.",
            source_repo: "https://github.com/acidanthera/WhateverGreen",
        },
        UpstreamPayloadSpec {
            name: "CryptexFixup.kext",
            version: "1.0.5",
            category: "KEXT_ACIDANTHERA",
            binary_format: "XNU Mach-O Kernel Extension",
            rust_rewriteable: false,
            reason: "Mandatory for non-AVX2 CPUs (Xeon/Ivy/Sandy/Penryn) on Ventura..macOS 26 Tahoe; MaxKernel MUST be empty.",
            source_repo: "https://github.com/acidanthera/CryptexFixup",
        },
        UpstreamPayloadSpec {
            name: "RestrictEvents.kext",
            version: "1.1.7",
            category: "KEXT_ACIDANTHERA",
            binary_format: "XNU Mach-O Kernel Extension",
            rust_rewriteable: false,
            reason: "Handles revpatch/revblock, JavaScriptCore AVX fix, and MacPro memory/PCI notifications.",
            source_repo: "https://github.com/acidanthera/RestrictEvents",
        },
        UpstreamPayloadSpec {
            name: "FeatureUnlock.kext",
            version: "1.1.8",
            category: "KEXT_ACIDANTHERA",
            binary_format: "XNU Mach-O Kernel Extension",
            rust_rewriteable: false,
            reason: "Enables Sidecar, AirPlay to Mac, Universal Control & Night Shift on legacy SMBIOS.",
            source_repo: "https://github.com/acidanthera/FeatureUnlock",
        },
        UpstreamPayloadSpec {
            name: "NVMeFix.kext",
            version: "1.1.3",
            category: "KEXT_ACIDANTHERA",
            binary_format: "XNU Mach-O Kernel Extension",
            rust_rewriteable: false,
            reason: "Autonomous Power State Transition (APST) and third-party NVMe stability.",
            source_repo: "https://github.com/acidanthera/NVMeFix",
        },
        UpstreamPayloadSpec {
            name: "BlueToolFixup.kext",
            version: "2.7.2",
            category: "KEXT_ACIDANTHERA",
            binary_format: "XNU Mach-O Kernel Extension",
            rust_rewriteable: false,
            reason: "Legacy Bluetooth HCI controller initialization for Monterey..Tahoe.",
            source_repo: "https://github.com/acidanthera/BrcmPatchRAM",
        },
        UpstreamPayloadSpec {
            name: "AirPortBrcmFixup.kext",
            version: "2.2.1",
            category: "KEXT_ACIDANTHERA",
            binary_format: "XNU Mach-O Kernel Extension",
            rust_rewriteable: false,
            reason: "Legacy Broadcom Wi-Fi support (paired with Tahoe wireless root patches in OCLP 3.0.0).",
            source_repo: "https://github.com/acidanthera/AirPortBrcmFixup",
        },
        UpstreamPayloadSpec {
            name: "NoAVXFSCompressionTypeZlib (Tahoe)",
            version: "26.7",
            category: "KEXT_APPLE_LEGACY",
            binary_format: "XNU Mach-O Kernel Extension",
            rust_rewriteable: false,
            reason: "Prevents APFS zlib AVX2 illegal-instruction panic on Penryn/Westmere/Sandy/Ivy CPUs in macOS 26 Tahoe.",
            source_repo: "https://github.com/dortania/OpenCore-Legacy-Patcher",
        },
        UpstreamPayloadSpec {
            name: "AppleKeyStore (T1 Tahoe)",
            version: "1.2.0",
            category: "KEXT_APPLE_LEGACY",
            binary_format: "XNU Mach-O Kernel Extension",
            rust_rewriteable: false,
            reason: "Restores Touch Bar / T1 security enclave & FileVault 2 compatibility on macOS 26 Tahoe.",
            source_repo: "https://github.com/dortania/OpenCore-Legacy-Patcher",
        },
    ]
}

/// Curated representative & high-priority Legacy Mac + Workstation SMBIOS catalog
/// synced with Dortania OCLP 3.0.0 (`model_array.py`).
pub fn model_catalog() -> Vec<MacModelProfile> {
    vec![
        MacModelProfile {
            smbios: "MacPro5,1",
            family: "Mac Pro (2010-2012 Cheesegrater / Dual Xeon)",
            year: 2012,
            cpu_has_avx2: false,
            gpu_class: "AMD_POLARIS_GCN",
            wifi_class: "LEGACY_BRCM_TAHOE",
            has_t1_chip: false,
            needs_usb11_patch: true,
            tahoe_supported_v3: true,
            notes: "Requires CryptexFixup 1.0.5 (MaxKernel=''), NoAVXFSCompressionTypeZlib 26.7, USB 1.1 UHCI/OHCI, and Metal 31001/3802 or Polaris/Vega GPU.",
        },
        MacModelProfile {
            smbios: "MacPro4,1",
            family: "Mac Pro (2009 Nehalem / Flashed 5,1)",
            year: 2009,
            cpu_has_avx2: false,
            gpu_class: "AMD_POLARIS_GCN",
            wifi_class: "LEGACY_BRCM_TAHOE",
            has_t1_chip: false,
            needs_usb11_patch: true,
            tahoe_supported_v3: true,
            notes: "Firmware 5,1 flash recommended; non-AVX2 Xeon requires CryptexFixup 1.0.5 + USB 1.1 injector.",
        },
        MacModelProfile {
            smbios: "MacPro6,1",
            family: "Mac Pro (2013 Trashcan Dual FirePro)",
            year: 2013,
            cpu_has_avx2: false,
            gpu_class: "METAL_3802",
            wifi_class: "MODERN_BRCM",
            has_t1_chip: false,
            needs_usb11_patch: false,
            tahoe_supported_v3: true,
            notes: "Ivy Bridge-EP lacks AVX2; dual AMD FirePro D300/D500/D700 use Legacy GCN / Metal 3802 root patches.",
        },
        MacModelProfile {
            smbios: "MacPro7,1-Vega20-KVM",
            family: "MacPro7,1 Workstation VM (Non-AVX2 Xeon + AMD Radeon Pro VII Vega 20 1002:66a1)",
            year: 2019,
            cpu_has_avx2: false,
            gpu_class: "AMD_VEGA20",
            wifi_class: "NONE",
            has_t1_chip: false,
            needs_usb11_patch: false,
            tahoe_supported_v3: true,
            notes: "Never spoof PCI 0x66a1 to 0x66af; keep AppleVirtualGraphics unblocked; inject patched 64 KB ATOM VBIOS via ATY,bin_image; KDK + Universal-Binaries root patch resolves Rosetta dyld_shared_cache missing AMDRadeonX5000MTLDriver.",
        },
        MacModelProfile {
            smbios: "MacBookPro11,5",
            family: "MacBook Pro 15-inch (Mid 2015 Haswell + R9 M370X)",
            year: 2015,
            cpu_has_avx2: true,
            gpu_class: "METAL_3802",
            wifi_class: "MODERN_BRCM",
            has_t1_chip: false,
            needs_usb11_patch: false,
            tahoe_supported_v3: true,
            notes: "Haswell AVX2 native; Intel Iris Pro + AMD Legacy GCN require Metal 3802 + Tahoe wireless patches.",
        },
        MacModelProfile {
            smbios: "MacBookPro13,3",
            family: "MacBook Pro 15-inch (2016 Skylake + Touch Bar T1)",
            year: 2016,
            cpu_has_avx2: true,
            gpu_class: "AMD_POLARIS_GCN",
            wifi_class: "MODERN_BRCM",
            has_t1_chip: true,
            needs_usb11_patch: false,
            tahoe_supported_v3: true,
            notes: "Requires OCLP 3.0.0 T1 coprocessor & AppleKeyStore Tahoe 1.2.0 patches + FileVault 2 Tahoe restore.",
        },
        MacModelProfile {
            smbios: "MacBookPro14,3",
            family: "MacBook Pro 15-inch (2017 Kaby Lake + Touch Bar T1)",
            year: 2017,
            cpu_has_avx2: true,
            gpu_class: "AMD_POLARIS_GCN",
            wifi_class: "MODERN_BRCM",
            has_t1_chip: true,
            needs_usb11_patch: false,
            tahoe_supported_v3: true,
            notes: "Kaby Lake + Radeon Pro 555/560 + T1 security enclave patches in OCLP 3.0.0.",
        },
        MacModelProfile {
            smbios: "iMac14,2",
            family: "iMac 27-inch (Late 2013 Haswell + NVIDIA Kepler)",
            year: 2013,
            cpu_has_avx2: true,
            gpu_class: "METAL_3802",
            wifi_class: "MODERN_BRCM",
            has_t1_chip: false,
            needs_usb11_patch: false,
            tahoe_supported_v3: true,
            notes: "NVIDIA Kepler Metal 3802 + Modern Wireless root patch set.",
        },
        MacModelProfile {
            smbios: "iMac18,3",
            family: "iMac 27-inch Retina 5K (2017 Kaby Lake + Polaris)",
            year: 2017,
            cpu_has_avx2: true,
            gpu_class: "AMD_POLARIS_GCN",
            wifi_class: "MODERN_BRCM",
            has_t1_chip: false,
            needs_usb11_patch: false,
            tahoe_supported_v3: true,
            notes: "Kaby Lake + AMD Radeon Pro 570/575/580; high stability on Sequoia & Tahoe 3.0.0.",
        },
        MacModelProfile {
            smbios: "Macmini6,2",
            family: "Mac mini (Late 2012 Ivy Bridge Quad-Core)",
            year: 2012,
            cpu_has_avx2: false,
            gpu_class: "METAL_3802",
            wifi_class: "LEGACY_BRCM_TAHOE",
            has_t1_chip: false,
            needs_usb11_patch: false,
            tahoe_supported_v3: true,
            notes: "Ivy Bridge Intel HD 4000 Metal 3802 + CryptexFixup 1.0.5 (non-AVX2).",
        },
        MacModelProfile {
            smbios: "MacBookAir7,2",
            family: "MacBook Air 13-inch (2015-2017 Broadwell)",
            year: 2017,
            cpu_has_avx2: true,
            gpu_class: "METAL_3802",
            wifi_class: "MODERN_BRCM",
            has_t1_chip: false,
            needs_usb11_patch: false,
            tahoe_supported_v3: true,
            notes: "Intel HD 6000 Broadwell Metal 3802 + Broadcom BCM94360CS2 Tahoe wireless patches.",
        },
        MacModelProfile {
            smbios: "MacBookPro8,2",
            family: "MacBook Pro 15-inch (2011 Sandy Bridge + TeraScale 2)",
            year: 2011,
            cpu_has_avx2: false,
            gpu_class: "NON_METAL",
            wifi_class: "LEGACY_BRCM_TAHOE",
            has_t1_chip: false,
            needs_usb11_patch: true,
            tahoe_supported_v3: true,
            notes: "Non-Metal GPU acceleration restored in OCLP 3.0.0 (EduCovas); non-AVX2 requires CryptexFixup 1.0.5.",
        },
    ]
}

pub fn find_model(smbios: &str) -> Option<MacModelProfile> {
    model_catalog()
        .into_iter()
        .find(|m| m.smbios.eq_ignore_ascii_case(smbios))
}

/// Accurate Apple XNU Darwin <-> macOS marketing version mapper (including Apple's jump 15 -> 26 Tahoe).
pub fn darwin_to_macos(darwin_major: u32) -> (&'static str, &'static str) {
    match darwin_major {
        20 => ("11", "macOS Big Sur"),
        21 => ("12", "macOS Monterey"),
        22 => ("13", "macOS Ventura"),
        23 => ("14", "macOS Sonoma"),
        24 => ("15", "macOS Sequoia"),
        25 => ("26", "macOS Tahoe"),
        26 | 27 => ("27", "macOS 27 (Apple Silicon Host)"),
        _ => ("unknown", "Unsupported/Future macOS"),
    }
}

pub fn macos_to_darwin(macos_major: u32) -> Option<u32> {
    match macos_major {
        11 => Some(20),
        12 => Some(21),
        13 => Some(22),
        14 => Some(23),
        15 => Some(24),
        26 => Some(25),
        _ => None,
    }
}

pub fn catalog_as_json() -> JsonValue {
    let payloads = upstream_v3_payloads()
        .into_iter()
        .map(|p| {
            obj(vec![
                ("name", jstr(p.name)),
                ("version", jstr(p.version)),
                ("category", jstr(p.category)),
                ("binary_format", jstr(p.binary_format)),
                ("rust_rewriteable", jbool(p.rust_rewriteable)),
                ("reason", jstr(p.reason)),
                ("source_repo", jstr(p.source_repo)),
            ])
        })
        .collect();

    let models = model_catalog()
        .into_iter()
        .map(|m| {
            obj(vec![
                ("smbios", jstr(m.smbios)),
                ("family", jstr(m.family)),
                ("year", jnum(m.year as f64)),
                ("cpu_has_avx2", jbool(m.cpu_has_avx2)),
                ("gpu_class", jstr(m.gpu_class)),
                ("wifi_class", jstr(m.wifi_class)),
                ("has_t1_chip", jbool(m.has_t1_chip)),
                ("needs_usb11_patch", jbool(m.needs_usb11_patch)),
                ("tahoe_supported_v3", jbool(m.tahoe_supported_v3)),
                ("notes", jstr(m.notes)),
            ])
        })
        .collect();

    obj(vec![
        ("nala_oclp_rs_version", jstr(crate::VERSION)),
        ("upstream_oclp_version", jstr(crate::UPSTREAM_OCLP_VERSION)),
        ("upstream_oclp_tag", jstr(crate::UPSTREAM_OCLP_TAG)),
        ("opencore_version", jstr(crate::UPSTREAM_OPENCORE_VERSION)),
        ("patcher_support_pkg", jstr(crate::UPSTREAM_PATCHER_SUPPORT_PKG)),
        ("supported_macos_range", jstr("macOS 11 Big Sur (Darwin 20) .. macOS 26 Tahoe (Darwin 25)")),
        ("payloads", JsonValue::Array(payloads)),
        ("models", JsonValue::Array(models)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tahoe_darwin_mapping_exact() {
        assert_eq!(darwin_to_macos(25), ("26", "macOS Tahoe"));
        assert_eq!(macos_to_darwin(26), Some(25));
        assert_eq!(macos_to_darwin(15), Some(24));
    }

    #[test]
    fn catalog_contains_macpro51_and_vega20() {
        assert!(find_model("MacPro5,1").is_some());
        assert!(find_model("MacPro7,1-Vega20-KVM").is_some());
    }
}
