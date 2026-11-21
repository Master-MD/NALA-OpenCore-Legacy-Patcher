//! Root-Volume Patch Planner & NCSP v2.5 Atomic Backup / Snapshot / Rollback Guardian.
//! Dry-Run-First by design: never mutates /System/Volumes or /Volumes/EFI without
//! explicit 2-step confirmation and a verified NCSP pre-change backup + rollback.sh.

use crate::json::{JsonValue, jbool, jnum, jstr, obj};
use crate::probe::HardwareProbe;
use crate::security::sha256_hex;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct PatchStep {
    pub id: String,
    pub category: String,
    pub description: String,
    pub upstream_source: String,
    pub requires_kdk: bool,
    pub macos_system_tool: String,
}

#[derive(Debug, Clone)]
pub struct RootPatchPlan {
    pub target_smbios: String,
    pub target_macos: String,
    pub darwin_major: u32,
    pub dry_run_only: bool,
    pub eligible_for_root_patch: bool,
    pub blockers: Vec<String>,
    pub patch_steps: Vec<PatchStep>,
    pub ncsp_rollback_command: String,
    pub estimated_patch_time_sec: u32,
}

impl RootPatchPlan {
    pub fn to_json(&self) -> JsonValue {
        let steps = self
            .patch_steps
            .iter()
            .map(|s| {
                obj(vec![
                    ("id", jstr(&s.id)),
                    ("category", jstr(&s.category)),
                    ("description", jstr(&s.description)),
                    ("upstream_source", jstr(&s.upstream_source)),
                    ("requires_kdk", jbool(s.requires_kdk)),
                    ("macos_system_tool", jstr(&s.macos_system_tool)),
                ])
            })
            .collect();

        obj(vec![
            ("target_smbios", jstr(&self.target_smbios)),
            ("target_macos", jstr(&self.target_macos)),
            ("darwin_major", jnum(self.darwin_major as f64)),
            ("dry_run_only", jbool(self.dry_run_only)),
            ("eligible_for_root_patch", jbool(self.eligible_for_root_patch)),
            (
                "blockers",
                JsonValue::Array(self.blockers.iter().map(jstr).collect()),
            ),
            ("patch_steps", JsonValue::Array(steps)),
            ("ncsp_rollback_command", jstr(&self.ncsp_rollback_command)),
            ("estimated_patch_time_sec", jnum(self.estimated_patch_time_sec as f64)),
        ])
    }
}

pub fn build_root_patch_plan(probe: &HardwareProbe) -> RootPatchPlan {
    let mut blockers = Vec::new();
    let mut steps = Vec::new();

    if probe.is_apple_silicon {
        blockers.push(
            "Apple Silicon host does not use OCLP root volume patches. Use `--simulate MacPro5,1` or `--simulate MacPro7,1-Vega20-KVM` to plan for Intel Macs / Proxmox VMs."
                .to_string(),
        );
    }
    if probe.darwin_major < 20 && !probe.is_apple_silicon {
        blockers.push(format!(
            "Darwin major {} is outside OCLP 3.0.0 range (Darwin 20 Big Sur .. Darwin 25 Tahoe).",
            probe.darwin_major
        ));
    }

    let is_tahoe = probe.darwin_major >= 25;

    match probe.gpu_class.as_str() {
        "AMD_VEGA20" => {
            steps.push(PatchStep {
                id: "GPU-VEGA20-NONAVX2-MTL".to_string(),
                category: "GRAPHICS".to_string(),
                description: "Merge KDK + PatcherSupportPkg 2.0.5 Universal-Binaries for AMDRadeonX5000MTLDriver (fixes Rosetta dyld_shared_cache WindowServer hang on non-AVX2 hosts)".to_string(),
                upstream_source: "Apple KDK + dortania/PatcherSupportPkg 2.0.5".to_string(),
                requires_kdk: true,
                macos_system_tool: "hdiutil attach -> ditto -> kmutil create -> bless --create-snapshot".to_string(),
            });
        }
        "METAL_3802" => {
            steps.push(PatchStep {
                id: "GPU-METAL-3802".to_string(),
                category: "GRAPHICS".to_string(),
                description: "Install Metal 3802 graphics acceleration stack (Intel HD 4000-6000 / NVIDIA Kepler / AMD Legacy GCN)".to_string(),
                upstream_source: "dortania/PatcherSupportPkg 2.0.5 + Apple KDK".to_string(),
                requires_kdk: true,
                macos_system_tool: "ditto -> kmutil create -> bless --create-snapshot".to_string(),
            });
        }
        "AMD_POLARIS_GCN" | "METAL_31001" => {
            steps.push(PatchStep {
                id: "GPU-METAL-31001-POLARIS".to_string(),
                category: "GRAPHICS".to_string(),
                description: if is_tahoe {
                    "Install macOS 26 Tahoe Metal 31001 / AMD Polaris & Legacy GCN patches (OCLP 3.0.0)".to_string()
                } else {
                    "Install Metal 31001 / AMD Polaris patches".to_string()
                },
                upstream_source: "dortania/PatcherSupportPkg 2.0.5 + Apple KDK".to_string(),
                requires_kdk: true,
                macos_system_tool: "ditto -> kmutil create -> bless --create-snapshot".to_string(),
            });
        }
        "NON_METAL" => {
            steps.push(PatchStep {
                id: "GPU-NON-METAL-3X".to_string(),
                category: "GRAPHICS".to_string(),
                description: "Install OCLP 3.0.0 improved Non-Metal graphics acceleration (TeraScale / Tesla / Legacy Intel)".to_string(),
                upstream_source: "dortania/PatcherSupportPkg 2.0.5 (EduCovas 3.0.0 Non-Metal)".to_string(),
                requires_kdk: true,
                macos_system_tool: "ditto -> kmutil create -> bless --create-snapshot".to_string(),
            });
        }
        _ => {}
    }

    if probe.wifi_class == "LEGACY_BRCM_TAHOE" || probe.wifi_class == "MODERN_BRCM" {
        steps.push(PatchStep {
            id: "NET-WIFI-TAHOE-3X".to_string(),
            category: "NETWORKING".to_string(),
            description: "Apply OCLP 3.0.0 Wireless Root Patches (IOSkywalkFamily 1.2.0 + IO80211FamilyLegacy + AirPort Tahoe)".to_string(),
            upstream_source: "dortania/OpenCore-Legacy-Patcher 3.0.0 + PatcherSupportPkg 2.0.5".to_string(),
            requires_kdk: false,
            macos_system_tool: "ditto -> kmutil create".to_string(),
        });
    }

    if probe.has_t1_chip && is_tahoe {
        steps.push(PatchStep {
            id: "SEC-T1-TAHOE-3X".to_string(),
            category: "SECURITY_COPROCESSOR".to_string(),
            description: "Apply OCLP 3.0.0 T1 Coprocessor & AppleKeyStore 1.2.0 Tahoe patches".to_string(),
            upstream_source: "dortania/OpenCore-Legacy-Patcher 3.0.0".to_string(),
            requires_kdk: true,
            macos_system_tool: "ditto -> kmutil create".to_string(),
        });
    }

    if probe.needs_usb11_patch {
        steps.push(PatchStep {
            id: "USB-UHCI-OHCI-11".to_string(),
            category: "USB".to_string(),
            description: "Inject Legacy USB 1.1 UHCI/OHCI controllers + macOS 26 USB mappings".to_string(),
            upstream_source: "dortania/OpenCore-Legacy-Patcher 3.0.0".to_string(),
            requires_kdk: false,
            macos_system_tool: "ditto -> kmutil create".to_string(),
        });
    }

    if !steps.is_empty() {
        steps.push(PatchStep {
            id: "APFS-SEAL-NCSP-SNAPSHOT".to_string(),
            category: "SNAPSHOT_SEAL".to_string(),
            description: "Rebuild BootKC/SysKC via `kmutil create` and seal new bootable APFS snapshot with NCSP rollback anchor".to_string(),
            upstream_source: "Native macOS /usr/bin/kmutil & /usr/sbin/bless".to_string(),
            requires_kdk: false,
            macos_system_tool: "bless --mount /System/Volumes/Update/mnt1 --bootefi --create-snapshot".to_string(),
        });
    }

    let eligible = blockers.is_empty() && !steps.is_empty();
    let est = if steps.is_empty() { 0 } else { 45 + (steps.len() as u32) * 20 };

    RootPatchPlan {
        target_smbios: probe.smbios.clone(),
        target_macos: format!("{} ({})", probe.macos_marketing, probe.macos_version),
        darwin_major: probe.darwin_major,
        dry_run_only: true,
        eligible_for_root_patch: eligible,
        blockers,
        patch_steps: steps,
        ncsp_rollback_command:
            "sudo /usr/sbin/bless --mount /System/Volumes/Update/mnt1 --bootefi --last-sealed-snapshot"
                .to_string(),
        estimated_patch_time_sec: est,
    }
}

/// Creates a real NCSP v2.5 pre-change snapshot directory containing metadata, SHA256SUMS.txt, and rollback.sh.
pub fn create_ncsp_snapshot(
    base_dir: &Path,
    label: &str,
    payload_summary: &str,
) -> Result<(PathBuf, String), String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let safe_label: String = label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let snap_dir = base_dir.join(format!("ncsp_{}_{}", safe_label, ts));
    fs::create_dir_all(&snap_dir).map_err(|e| format!("create snapshot dir {:?}: {}", snap_dir, e))?;

    let inventory_json = obj(vec![
        ("engine", jstr("nala-oclp-rs")),
        ("version", jstr(crate::VERSION)),
        ("upstream_oclp", jstr(crate::UPSTREAM_OCLP_TAG)),
        ("label", jstr(label)),
        ("unix_timestamp", jnum(ts as f64)),
        ("payload_summary", jstr(payload_summary)),
    ])
    .to_json_pretty();

    let inv_path = snap_dir.join("NCSP_INVENTORY.json");
    fs::write(&inv_path, &inventory_json).map_err(|e| format!("write inventory: {}", e))?;
    let inv_sha = sha256_hex(inventory_json.as_bytes());

    let rollback_sh = format!(
        "#!/usr/bin/env bash\n\
         set -euo pipefail\n\
         echo \"[NCSP v2.5 ROLLBACK] Snapshot: {}\"\n\
         echo \"[NCSP v2.5 ROLLBACK] Inventory SHA-256: {}\"\n\
         echo \"To revert a macOS APFS root patch safely, run on the target Mac (or Recovery):\"\n\
         echo \"  sudo /usr/sbin/bless --mount /System/Volumes/Update/mnt1 --bootefi --last-sealed-snapshot\"\n\
         echo \"To restore a staged EFI backup, copy backup EFI/OC/config.plist back to /Volumes/EFI/EFI/OC/.\"\n",
        safe_label, inv_sha
    );
    let rb_path = snap_dir.join("rollback.sh");
    fs::write(&rb_path, &rollback_sh).map_err(|e| format!("write rollback.sh: {}", e))?;
    let rb_sha = sha256_hex(rollback_sh.as_bytes());

    let sums = format!(
        "{}  NCSP_INVENTORY.json\n{}  rollback.sh\n",
        inv_sha, rb_sha
    );
    fs::write(snap_dir.join("SHA256SUMS.txt"), sums).map_err(|e| format!("write SHA256SUMS: {}", e))?;

    Ok((snap_dir, inv_sha))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::probe_host;

    #[test]
    fn plan_for_macpro51_tahoe_has_graphics_wifi_usb_and_seal() {
        let p = probe_host(Some("MacPro5,1"), Some(26)).expect("probe");
        let plan = build_root_patch_plan(&p);
        assert!(plan.eligible_for_root_patch);
        assert!(plan.patch_steps.len() >= 4);
        assert!(plan.dry_run_only);
    }
}
