#![forbid(unsafe_code)]

//! NALA-oclp-rs: 100% Native Pure Safe Rust (Edition 2024, 0 External Crates, Zero-Python)
//! OpenCore Legacy Patcher v3.x (macOS 11 Big Sur - macOS 26 Tahoe) Control-Plane,
//! Deterministic OpenCore 1.0.6 EFI Builder, Upstream Dortania 3.x Sync,
//! NCSP v2.5 APFS Snapshot/Rollback Guardian, 12-Tool MCP Server & AAA 2-Click Cockpit.

pub const VERSION: &str = "3.0.0-nala.6.6.6";
pub const UPSTREAM_OCLP_VERSION: &str = "3.0.0";
pub const UPSTREAM_OCLP_TAG: &str = "3.0.0-rc.5+main-d7a3d94";
pub const UPSTREAM_OPENCORE_VERSION: &str = "1.0.6";
pub const UPSTREAM_PATCHER_SUPPORT_PKG: &str = "2.0.5";

pub mod bench;
pub mod catalog;
pub mod dream_rsi;
pub mod efi_builder;
pub mod json;
pub mod mcp;
pub mod probe;
pub mod security;
pub mod server;
pub mod sys_patch;
pub mod upstream_sync;
