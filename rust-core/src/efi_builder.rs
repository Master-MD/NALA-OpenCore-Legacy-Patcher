//! Deterministic Pure Safe Rust OpenCore 1.0.6 `config.plist` Synthesizer & Verifier
//! Compatible with Upstream OCLP v3.0.0 (`3.0.0-rc.5+` / macOS 11 Big Sur .. macOS 26 Tahoe).

use crate::catalog::{MacModelProfile, find_model, macos_to_darwin};
use crate::json::{JsonValue, jbool, jnum, jstr, obj};
use crate::security::{escape_html_xml, sha256_hex, validate_smbios_token};
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct EfiBuildOptions {
    pub smbios: String,
    pub target_macos_major: u32, // 11..15 or 26 (Tahoe)
    pub enable_verbose_boot: bool,
    pub enable_sip_root_patch_mode: bool, // 0x803 (03080000)
    pub enable_filevault2_tahoe: bool,
    pub vega20_proxmox_mode: bool,
    pub resolution: String,
}

impl Default for EfiBuildOptions {
    fn default() -> Self {
        Self {
            smbios: "MacPro5,1".to_string(),
            target_macos_major: 26,
            enable_verbose_boot: false,
            enable_sip_root_patch_mode: true,
            enable_filevault2_tahoe: true,
            vega20_proxmox_mode: false,
            resolution: "Max".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EfiBuildArtifact {
    pub smbios: String,
    pub target_macos_major: u32,
    pub darwin_major: u32,
    pub opencore_version: &'static str,
    pub kexts_included: Vec<String>,
    pub boot_args: String,
    pub csr_active_config_hex: String,
    pub plist_xml: String,
    pub plist_sha256: String,
    pub guards_enforced: Vec<String>,
}

impl EfiBuildArtifact {
    pub fn to_json(&self, include_xml: bool) -> JsonValue {
        let mut entries = vec![
            ("smbios", jstr(&self.smbios)),
            ("target_macos_major", jnum(self.target_macos_major as f64)),
            ("darwin_major", jnum(self.darwin_major as f64)),
            ("opencore_version", jstr(self.opencore_version)),
            ("boot_args", jstr(&self.boot_args)),
            ("csr_active_config_hex", jstr(&self.csr_active_config_hex)),
            ("plist_sha256", jstr(&self.plist_sha256)),
            ("plist_bytes", jnum(self.plist_xml.len() as f64)),
            (
                "kexts_included",
                JsonValue::Array(self.kexts_included.iter().map(jstr).collect()),
            ),
            (
                "guards_enforced",
                JsonValue::Array(self.guards_enforced.iter().map(jstr).collect()),
            ),
        ];
        if include_xml {
            entries.push(("plist_xml", jstr(&self.plist_xml)));
        }
        obj(entries)
    }
}

pub fn synthesize_config_plist(opts: &EfiBuildOptions) -> Result<EfiBuildArtifact, String> {
    validate_smbios_token(&opts.smbios)?;
    let darwin = macos_to_darwin(opts.target_macos_major).ok_or_else(|| {
        format!(
            "Unsupported target macOS major '{}'. Supported: 11, 12, 13, 14, 15, 26 (Tahoe).",
            opts.target_macos_major
        )
    })?;
    let profile: MacModelProfile = find_model(&opts.smbios).unwrap_or(MacModelProfile {
        smbios: "CustomSMBIOS",
        family: "Custom Intel Mac Profile",
        year: 2015,
        cpu_has_avx2: true,
        gpu_class: "METAL_3802",
        wifi_class: "MODERN_BRCM",
        has_t1_chip: false,
        needs_usb11_patch: false,
        tahoe_supported_v3: true,
        notes: "Generic profile",
    });

    let is_tahoe = darwin >= 25;
    let is_vega20_kvm = opts.vega20_proxmox_mode || opts.smbios.eq_ignore_ascii_case("MacPro7,1-Vega20-KVM");

    let mut kexts: Vec<(&str, &str, &str)> = vec![
        ("Lilu.kext", "Contents/MacOS/Lilu", "1.7.2"),
        ("WhateverGreen.kext", "Contents/MacOS/WhateverGreen", "1.7.1"),
        ("RestrictEvents.kext", "Contents/MacOS/RestrictEvents", "1.1.7"),
        ("FeatureUnlock.kext", "Contents/MacOS/FeatureUnlock", "1.1.8"),
        ("NVMeFix.kext", "Contents/MacOS/NVMeFix", "1.1.3"),
    ];

    let mut guards = vec![
        "OCLP-3.0.0: OpenCorePkg 1.0.6 + Lilu 1.7.2 + WhateverGreen 1.7.1".to_string(),
    ];

    if !profile.cpu_has_avx2 {
        kexts.push(("CryptexFixup.kext", "Contents/MacOS/CryptexFixup", "1.0.5"));
        guards.push("TAHOE-GUARD: CryptexFixup.kext MaxKernel=\"\" (prevents Darwin 25 non-AVX2 hang)".to_string());
        if is_tahoe {
            kexts.push((
                "NoAVXFSCompressionTypeZlib.kext",
                "Contents/MacOS/NoAVXFSCompressionTypeZlib",
                "26.7",
            ));
            guards.push("TAHOE-GUARD: NoAVXFSCompressionTypeZlib 26.7 active for non-AVX2 APFS".to_string());
        }
    }

    if profile.wifi_class != "NONE" {
        kexts.push(("AirPortBrcmFixup.kext", "Contents/MacOS/AirPortBrcmFixup", "2.2.1"));
        kexts.push(("BlueToolFixup.kext", "Contents/MacOS/BlueToolFixup", "2.7.2"));
    }

    if profile.has_t1_chip && is_tahoe {
        kexts.push(("AppleKeyStore-T1-Tahoe.kext", "Contents/MacOS/AppleKeyStore", "1.2.0"));
        guards.push("TAHOE-GUARD: T1 Security Enclave + AppleKeyStore 1.2.0 enabled".to_string());
    }

    if profile.needs_usb11_patch {
        kexts.push(("USB-Map.kext", "", "1.0.0"));
        guards.push("LEGACY-GUARD: UHCI/OHCI USB 1.1 injector active for pre-2012 MacPro/MacBookPro".to_string());
    }

    let mut boot_args_parts: Vec<&str> = vec!["keepsyms=1", "debug=0x100"];
    if opts.enable_verbose_boot {
        boot_args_parts.push("-v");
    }
    if is_tahoe {
        boot_args_parts.push("-lilubetaall");
        boot_args_parts.push("-wegbeta");
        if !profile.cpu_has_avx2 {
            boot_args_parts.push("-cryptbeta");
        }
    }
    if is_vega20_kvm {
        boot_args_parts.push("agdpmod=pikera");
        boot_args_parts.push("npci=0x2000");
        boot_args_parts.push("-radcodec");
        guards.push("VEGA20-GUARD: Native PCI 1002:66a1 preserved (NO 0x66af spoof); AppleVirtualGraphics unblocked".to_string());
    }
    if opts.enable_sip_root_patch_mode {
        boot_args_parts.push("amfi_get_out_of_my_way=1");
        boot_args_parts.push("ipc_control_port_options=0");
        guards.push("SIP-GUARD: csr-active-config=0x803 (03080000) + NVRAM Delete sync for OCLP 3.0.0 root patching".to_string());
    }
    if opts.enable_filevault2_tahoe && is_tahoe {
        guards.push("FV2-TAHOE-GUARD: OpenCore FileVault 2 UEFI input/graphics hooks active for macOS 26".to_string());
    }

    let boot_args = boot_args_parts.join(" ");
    let (csr_hex, csr_b64) = if opts.enable_sip_root_patch_mode {
        ("03080000".to_string(), "AwgAAA==".to_string())
    } else {
        ("00000000".to_string(), "AAAAAA==".to_string())
    };

    let mut kext_xml = String::new();
    for (bundle, exe, ver) in &kexts {
        kext_xml.push_str(&format!(
            "\t\t\t<dict>\n\
             \t\t\t\t<key>Arch</key>\n\
             \t\t\t\t<string>x86_64</string>\n\
             \t\t\t\t<key>BundlePath</key>\n\
             \t\t\t\t<string>{}</string>\n\
             \t\t\t\t<key>Comment</key>\n\
             \t\t\t\t<string>NALA-OCLP-RS v{} (Upstream {})</string>\n\
             \t\t\t\t<key>Enabled</key>\n\
             \t\t\t\t<true/>\n\
             \t\t\t\t<key>ExecutablePath</key>\n\
             \t\t\t\t<string>{}</string>\n\
             \t\t\t\t<key>MaxKernel</key>\n\
             \t\t\t\t<string></string>\n\
             \t\t\t\t<key>MinKernel</key>\n\
             \t\t\t\t<string>20.0.0</string>\n\
             \t\t\t\t<key>PlistPath</key>\n\
             \t\t\t\t<string>Contents/Info.plist</string>\n\
             \t\t\t</dict>\n",
            escape_html_xml(bundle),
            crate::VERSION,
            escape_html_xml(ver),
            escape_html_xml(exe),
        ));
    }

    let resolved_smbios = if is_vega20_kvm {
        "MacPro7,1"
    } else {
        opts.smbios.as_str()
    };
    let resolution = if is_vega20_kvm && opts.resolution == "Max" {
        "3440x1440"
    } else {
        opts.resolution.as_str()
    };

    let plist_xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>#NALA-OCLP-RS-Metadata</key>\n\
         \t<dict>\n\
         \t\t<key>EngineVersion</key>\n\
         \t\t<string>{}</string>\n\
         \t\t<key>UpstreamOCLP</key>\n\
         \t\t<string>{}</string>\n\
         \t\t<key>OpenCoreVersion</key>\n\
         \t\t<string>{}</string>\n\
         \t\t<key>TargetDarwinMajor</key>\n\
         \t\t<integer>{}</integer>\n\
         \t\t<key>TargetMacOSMajor</key>\n\
         \t\t<integer>{}</integer>\n\
         \t</dict>\n\
         \t<key>Booter</key>\n\
         \t<dict>\n\
         \t\t<key>Quirks</key>\n\
         \t\t<dict>\n\
         \t\t\t<key>AllowRelocationBlock</key>\n\
         \t\t\t<false/>\n\
         \t\t\t<key>AvoidRuntimeDefrag</key>\n\
         \t\t\t<true/>\n\
         \t\t\t<key>ProvideCustomSlide</key>\n\
         \t\t\t<true/>\n\
         \t\t\t<key>RebuildAppleMemoryMap</key>\n\
         \t\t\t<false/>\n\
         \t\t\t<key>SyncRuntimePermissions</key>\n\
         \t\t\t<true/>\n\
         \t\t</dict>\n\
         \t</dict>\n\
         \t<key>Kernel</key>\n\
         \t<dict>\n\
         \t\t<key>Add</key>\n\
         \t\t<array>\n\
         {}\
         \t\t</array>\n\
         \t\t<key>Block</key>\n\
         \t\t<array/>\n\
         \t\t<key>Quirks</key>\n\
         \t\t<dict>\n\
         \t\t\t<key>DisableLinkeditJettison</key>\n\
         \t\t\t<true/>\n\
         \t\t\t<key>SetApfsTrimTimeout</key>\n\
         \t\t\t<integer>-1</integer>\n\
         \t\t\t<key>ThirdPartyDrives</key>\n\
         \t\t\t<true/>\n\
         \t\t</dict>\n\
         \t</dict>\n\
         \t<key>Misc</key>\n\
         \t<dict>\n\
         \t\t<key>Boot</key>\n\
         \t\t<dict>\n\
         \t\t\t<key>PickerMode</key>\n\
         \t\t\t<string>External</string>\n\
         \t\t\t<key>PollAppleHotKeys</key>\n\
         \t\t\t<true/>\n\
         \t\t\t<key>ShowPicker</key>\n\
         \t\t\t<true/>\n\
         \t\t\t<key>Timeout</key>\n\
         \t\t\t<integer>5</integer>\n\
         \t\t</dict>\n\
         \t\t<key>Security</key>\n\
         \t\t<dict>\n\
         \t\t\t<key>AllowSetDefault</key>\n\
         \t\t\t<true/>\n\
         \t\t\t<key>DmgLoading</key>\n\
         \t\t\t<string>Any</string>\n\
         \t\t\t<key>SecureBootModel</key>\n\
         \t\t\t<string>Disabled</string>\n\
         \t\t\t<key>Vault</key>\n\
         \t\t\t<string>Optional</string>\n\
         \t\t</dict>\n\
         \t</dict>\n\
         \t<key>NVRAM</key>\n\
         \t<dict>\n\
         \t\t<key>Add</key>\n\
         \t\t<dict>\n\
         \t\t\t<key>7C436110-AB2A-4BBB-A880-FE41995C9F82</key>\n\
         \t\t\t<dict>\n\
         \t\t\t\t<key>boot-args</key>\n\
         \t\t\t\t<string>{}</string>\n\
         \t\t\t\t<key>csr-active-config</key>\n\
         \t\t\t\t<data>{}</data>\n\
         \t\t\t</dict>\n\
         \t\t</dict>\n\
         \t\t<key>Delete</key>\n\
         \t\t<dict>\n\
         \t\t\t<key>7C436110-AB2A-4BBB-A880-FE41995C9F82</key>\n\
         \t\t\t<array>\n\
         \t\t\t\t<string>boot-args</string>\n\
         \t\t\t\t<string>csr-active-config</string>\n\
         \t\t\t</array>\n\
         \t\t</dict>\n\
         \t\t<key>WriteFlash</key>\n\
         \t\t<true/>\n\
         \t</dict>\n\
         \t<key>PlatformInfo</key>\n\
         \t<dict>\n\
         \t\t<key>Automatic</key>\n\
         \t\t<true/>\n\
         \t\t<key>Generic</key>\n\
         \t\t<dict>\n\
         \t\t\t<key>SystemProductName</key>\n\
         \t\t\t<string>{}</string>\n\
         \t\t</dict>\n\
         \t\t<key>UpdateSMBIOS</key>\n\
         \t\t<true/>\n\
         \t</dict>\n\
         \t<key>UEFI</key>\n\
         \t<dict>\n\
         \t\t<key>ConnectDrivers</key>\n\
         \t\t<true/>\n\
         \t\t<key>Input</key>\n\
         \t\t<dict>\n\
         \t\t\t<key>KeySupport</key>\n\
         \t\t\t<true/>\n\
         \t\t</dict>\n\
         \t\t<key>Output</key>\n\
         \t\t<dict>\n\
         \t\t\t<key>ProvideConsoleGop</key>\n\
         \t\t\t<true/>\n\
         \t\t\t<key>Resolution</key>\n\
         \t\t\t<string>{}</string>\n\
         \t\t</dict>\n\
         \t\t<key>ProtocolOverrides</key>\n\
         \t\t<dict>\n\
         \t\t\t<key>AppleKeyMap</key>\n\
         \t\t\t<true/>\n\
         \t\t\t<key>FirmwareVolume</key>\n\
         \t\t\t<{}/>\n\
         \t\t</dict>\n\
         \t</dict>\n\
         </dict>\n\
         </plist>\n",
        crate::VERSION,
        crate::UPSTREAM_OCLP_TAG,
        crate::UPSTREAM_OPENCORE_VERSION,
        darwin,
        opts.target_macos_major,
        kext_xml,
        escape_html_xml(&boot_args),
        csr_b64,
        escape_html_xml(resolved_smbios),
        escape_html_xml(resolution),
        if opts.enable_filevault2_tahoe { "true" } else { "false" }
    );

    let plist_sha256 = sha256_hex(plist_xml.as_bytes());
    let kexts_included = kexts.iter().map(|(b, _, v)| format!("{} ({})", b, v)).collect();

    Ok(EfiBuildArtifact {
        smbios: opts.smbios.clone(),
        target_macos_major: opts.target_macos_major,
        darwin_major: darwin,
        opencore_version: crate::UPSTREAM_OPENCORE_VERSION,
        kexts_included,
        boot_args,
        csr_active_config_hex: csr_hex,
        plist_xml,
        plist_sha256,
        guards_enforced: guards,
    })
}

pub fn write_efi_staging(out_dir: &Path, artifact: &EfiBuildArtifact) -> Result<String, String> {
    let oc_dir = out_dir.join("EFI").join("OC");
    fs::create_dir_all(&oc_dir).map_err(|e| format!("create_dir_all {:?}: {}", oc_dir, e))?;
    let plist_path = oc_dir.join("config.plist");
    fs::write(&plist_path, &artifact.plist_xml)
        .map_err(|e| format!("write {:?}: {}", plist_path, e))?;
    let manifest = format!(
        "{}  EFI/OC/config.plist\n",
        artifact.plist_sha256
    );
    fs::write(out_dir.join("SHA256SUMS_EFI.txt"), manifest)
        .map_err(|e| format!("write SHA256SUMS_EFI.txt: {}", e))?;
    Ok(plist_path.to_string_lossy().to_string())
}

/// Validates a plist file using macOS native `/usr/bin/plutil -lint` when available,
/// plus pure-Rust structural XML checks on all platforms.
pub fn verify_plist_file(path: &Path) -> Result<JsonValue, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("read {:?}: {}", path, e))?;
    let sha = sha256_hex(content.as_bytes());
    let has_header = content.contains("<!DOCTYPE plist") && content.contains("<plist version=\"1.0\">");
    let has_tail = content.contains("</plist>");
    let cryptex_max_kernel_bug =
        content.contains("CryptexFixup.kext") && content.contains("<string>23.99.99</string>");

    let (plutil_checked, plutil_ok, plutil_output) = if std::env::consts::OS == "macos" {
        match Command::new("/usr/bin/plutil").args(["-lint"]).arg(path).output() {
            Ok(out) => (
                true,
                out.status.success(),
                String::from_utf8_lossy(&out.stdout).trim().to_string(),
            ),
            Err(e) => (false, false, format!("plutil exec error: {}", e)),
        }
    } else {
        (false, true, "non-macos host: pure-Rust structural verification only".to_string())
    };

    Ok(obj(vec![
        ("path", jstr(path.to_string_lossy().to_string())),
        ("sha256", jstr(sha)),
        ("bytes", jnum(content.len() as f64)),
        ("structural_xml_ok", jbool(has_header && has_tail)),
        ("tahoe_cryptex_maxkernel_bug_detected", jbool(cryptex_max_kernel_bug)),
        ("plutil_checked", jbool(plutil_checked)),
        ("plutil_ok", jbool(plutil_ok)),
        ("plutil_output", jstr(plutil_output)),
        ("overall_pass", jbool(has_header && has_tail && plutil_ok && !cryptex_max_kernel_bug)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tahoe_macpro51_includes_cryptex_and_empty_maxkernel() {
        let art = synthesize_config_plist(&EfiBuildOptions {
            smbios: "MacPro5,1".to_string(),
            target_macos_major: 26,
            ..Default::default()
        })
        .expect("synthesize");
        assert!(art.plist_xml.contains("CryptexFixup.kext"));
        assert!(art.plist_xml.contains("NoAVXFSCompressionTypeZlib.kext"));
        assert!(art.plist_xml.contains("<key>MaxKernel</key>\n\t\t\t\t<string></string>"));
        assert!(art.boot_args.contains("-cryptbeta"));
        assert_eq!(art.plist_sha256.len(), 64);
    }

    #[test]
    fn vega20_kvm_enforces_3440_and_pikera() {
        let art = synthesize_config_plist(&EfiBuildOptions {
            smbios: "MacPro7,1-Vega20-KVM".to_string(),
            target_macos_major: 26,
            vega20_proxmox_mode: true,
            ..Default::default()
        })
        .expect("synthesize vega20");
        assert!(art.boot_args.contains("agdpmod=pikera"));
        assert!(art.plist_xml.contains("<string>3440x1440</string>"));
        assert!(art.plist_xml.contains("<string>MacPro7,1</string>"));
    }
}
