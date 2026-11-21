//! Native Safe Rust Host & Simulated Hardware Prober (macOS / Linux).
//! Never invokes `/usr/bin/python3` or Xcode CLT shims; reads safe OS utilities directly.

use crate::catalog::{darwin_to_macos, find_model};
use crate::json::{JsonValue, jbool, jnum, jstr, obj};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct HardwareProbe {
    pub simulated: bool,
    pub os_family: String,
    pub arch: String,
    pub smbios: String,
    pub cpu_brand: String,
    pub cpu_has_avx2: bool,
    pub ram_gb: u64,
    pub darwin_major: u32,
    pub macos_version: String,
    pub macos_build: String,
    pub macos_marketing: String,
    pub sip_status: String,
    pub gpu_class: String,
    pub wifi_class: String,
    pub has_t1_chip: bool,
    pub needs_usb11_patch: bool,
    pub is_apple_silicon: bool,
    pub apfs_snapshot_count: usize,
    pub notes: String,
}

impl HardwareProbe {
    pub fn to_json(&self) -> JsonValue {
        obj(vec![
            ("simulated", jbool(self.simulated)),
            ("os_family", jstr(&self.os_family)),
            ("arch", jstr(&self.arch)),
            ("smbios", jstr(&self.smbios)),
            ("cpu_brand", jstr(&self.cpu_brand)),
            ("cpu_has_avx2", jbool(self.cpu_has_avx2)),
            ("ram_gb", jnum(self.ram_gb as f64)),
            ("darwin_major", jnum(self.darwin_major as f64)),
            ("macos_version", jstr(&self.macos_version)),
            ("macos_build", jstr(&self.macos_build)),
            ("macos_marketing", jstr(&self.macos_marketing)),
            ("sip_status", jstr(&self.sip_status)),
            ("gpu_class", jstr(&self.gpu_class)),
            ("wifi_class", jstr(&self.wifi_class)),
            ("has_t1_chip", jbool(self.has_t1_chip)),
            ("needs_usb11_patch", jbool(self.needs_usb11_patch)),
            ("is_apple_silicon", jbool(self.is_apple_silicon)),
            ("apfs_snapshot_count", jnum(self.apfs_snapshot_count as f64)),
            ("notes", jstr(&self.notes)),
        ])
    }
}

pub fn probe_host(simulate_smbios: Option<&str>, target_macos: Option<u32>) -> Result<HardwareProbe, String> {
    if let Some(sim) = simulate_smbios {
        let profile = find_model(sim).ok_or_else(|| {
            format!(
                "Unknown simulated SMBIOS '{}'. Run `nala-oclp-rs catalog` to list supported profiles.",
                sim
            )
        })?;
        let target_os = target_macos.unwrap_or(26);
        let darwin = crate::catalog::macos_to_darwin(target_os).unwrap_or(25);
        let (ver, mkt) = darwin_to_macos(darwin);
        return Ok(HardwareProbe {
            simulated: true,
            os_family: "macos-simulated".to_string(),
            arch: "x86_64".to_string(),
            smbios: profile.smbios.to_string(),
            cpu_brand: if profile.cpu_has_avx2 {
                "Intel Core/Xeon (AVX2 Capable - Simulated)".to_string()
            } else {
                "Intel Xeon/Core (Non-AVX2 Legacy - Simulated)".to_string()
            },
            cpu_has_avx2: profile.cpu_has_avx2,
            ram_gb: if profile.smbios.starts_with("MacPro") { 64 } else { 16 },
            darwin_major: darwin,
            macos_version: format!("{}.0", ver),
            macos_build: if darwin == 25 { "25G332".to_string() } else { "24F74".to_string() },
            macos_marketing: mkt.to_string(),
            sip_status: "Simulated (Requires 0x803 for Root-Patching)".to_string(),
            gpu_class: profile.gpu_class.to_string(),
            wifi_class: profile.wifi_class.to_string(),
            has_t1_chip: profile.has_t1_chip,
            needs_usb11_patch: profile.needs_usb11_patch,
            is_apple_silicon: false,
            apfs_snapshot_count: 1,
            notes: profile.notes.to_string(),
        });
    }

    let arch = std::env::consts::ARCH.to_string();
    let os_family = std::env::consts::OS.to_string();
    let is_apple_silicon = os_family == "macos" && arch == "aarch64";

    if os_family != "macos" {
        return Ok(HardwareProbe {
            simulated: false,
            os_family,
            arch,
            smbios: "Non-Mac-Host".to_string(),
            cpu_brand: "Generic Host CPU".to_string(),
            cpu_has_avx2: true,
            ram_gb: 16,
            darwin_major: 0,
            macos_version: "N/A".to_string(),
            macos_build: "N/A".to_string(),
            macos_marketing: "Non-macOS Host (Use --simulate <SMBIOS> for EFI planning)".to_string(),
            sip_status: "N/A".to_string(),
            gpu_class: "NONE".to_string(),
            wifi_class: "NONE".to_string(),
            has_t1_chip: false,
            needs_usb11_patch: false,
            is_apple_silicon: false,
            apfs_snapshot_count: 0,
            notes: "Cross-platform mode: build OpenCore 1.0.6 EFI configs for any Intel Mac SMBIOS safely.".to_string(),
        });
    }

    let smbios = run_cmd("/usr/sbin/sysctl", &["-n", "hw.model"]).unwrap_or_else(|| "UnknownMac".to_string());
    let cpu_brand = run_cmd("/usr/sbin/sysctl", &["-n", "machdep.cpu.brand_string"])
        .unwrap_or_else(|| "Apple Silicon / Unknown".to_string());
    let mem_bytes: u64 = run_cmd("/usr/sbin/sysctl", &["-n", "hw.memsize"])
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let ram_gb = mem_bytes / (1024 * 1024 * 1024);
    let macos_version = run_cmd("/usr/bin/sw_vers", &["-productVersion"]).unwrap_or_else(|| "0.0".to_string());
    let macos_build = run_cmd("/usr/bin/sw_vers", &["-buildVersion"]).unwrap_or_else(|| "unknown".to_string());
    let darwin_str = run_cmd("/usr/bin/uname", &["-r"]).unwrap_or_else(|| "0.0.0".to_string());
    let darwin_major: u32 = darwin_str
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (_, mkt) = darwin_to_macos(darwin_major);
    let sip_status = run_cmd("/usr/bin/csrutil", &["status"])
        .map(|s| s.lines().next().unwrap_or("unknown").trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let avx2_flag = run_cmd("/usr/sbin/sysctl", &["-n", "hw.optional.avx2_0"])
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    let snap_out = run_cmd("/usr/sbin/diskutil", &["apfs", "listSnapshots", "/"]).unwrap_or_default();
    let apfs_snapshot_count = snap_out.matches("Snapshot UUID:").count();

    let (gpu_class, wifi_class, has_t1_chip, needs_usb11_patch, notes) =
        if let Some(known) = find_model(&smbios) {
            (
                known.gpu_class.to_string(),
                known.wifi_class.to_string(),
                known.has_t1_chip,
                known.needs_usb11_patch,
                known.notes.to_string(),
            )
        } else if is_apple_silicon {
            (
                "APPLE_SILICON_NATIVE".to_string(),
                "APPLE_NATIVE".to_string(),
                false,
                false,
                "Apple Silicon host detected: OCLP root patching is NOT required on Apple Silicon; use this Mac as a blazing-fast Rust EFI Builder, Upstream 3.x Sync & USB Installer station for Intel Macs / Proxmox VMs.".to_string(),
            )
        } else {
            (
                "INTEL_GENERIC".to_string(),
                "MODERN_BRCM".to_string(),
                false,
                false,
                "Live Intel Mac detected; verify GPU & Wi-Fi PCI IDs before root patching.".to_string(),
            )
        };

    Ok(HardwareProbe {
        simulated: false,
        os_family,
        arch,
        smbios,
        cpu_brand,
        cpu_has_avx2: avx2_flag,
        ram_gb,
        darwin_major,
        macos_version,
        macos_build,
        macos_marketing: mkt.to_string(),
        sip_status,
        gpu_class,
        wifi_class,
        has_t1_chip,
        needs_usb11_patch,
        is_apple_silicon,
        apfs_snapshot_count,
        notes,
    })
}

fn run_cmd(bin: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(bin).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulated_macpro51_probe_works() {
        let p = probe_host(Some("MacPro5,1"), Some(26)).expect("simulated probe");
        assert!(p.simulated);
        assert_eq!(p.darwin_major, 25);
        assert_eq!(p.macos_marketing, "macOS Tahoe");
        assert!(!p.cpu_has_avx2);
        assert!(p.needs_usb11_patch);
    }
}
