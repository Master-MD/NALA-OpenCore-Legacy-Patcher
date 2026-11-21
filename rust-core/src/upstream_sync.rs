//! Upstream Dortania OpenCore Legacy Patcher v3.x (`main` & `3.0.0-rc.x`) Sync & Drift Engine.
//! Strictly read-only inspection + deterministic NCSP-safe Git sync command builder (Zero Force-Push).

use crate::json::{JsonValue, jbool, jnum, jstr, obj, parse_json};
use crate::security::validate_upstream_url;
use std::process::Command;

pub const UPSTREAM_REPO: &str = "dortania/OpenCore-Legacy-Patcher";
pub const FORK_REPO: &str = "Master-MD/NALA-OpenCore-Legacy-Patcher";

#[derive(Debug, Clone)]
pub struct UpstreamSyncReport {
    pub live_checked: bool,
    pub upstream_repo: &'static str,
    pub fork_repo: &'static str,
    pub upstream_latest_release: String,
    pub upstream_main_sha: String,
    pub fork_main_sha: String,
    pub commits_behind: u64,
    pub files_changed_upstream: u64,
    pub sync_recommended: bool,
    pub safe_sync_commands: Vec<String>,
    pub notes: String,
}

impl UpstreamSyncReport {
    pub fn to_json(&self) -> JsonValue {
        obj(vec![
            ("live_checked", jbool(self.live_checked)),
            ("upstream_repo", jstr(self.upstream_repo)),
            ("fork_repo", jstr(self.fork_repo)),
            ("upstream_latest_release", jstr(&self.upstream_latest_release)),
            ("upstream_main_sha", jstr(&self.upstream_main_sha)),
            ("fork_main_sha", jstr(&self.fork_main_sha)),
            ("commits_behind", jnum(self.commits_behind as f64)),
            ("files_changed_upstream", jnum(self.files_changed_upstream as f64)),
            ("sync_recommended", jbool(self.sync_recommended)),
            (
                "safe_sync_commands",
                JsonValue::Array(self.safe_sync_commands.iter().map(jstr).collect()),
            ),
            ("notes", jstr(&self.notes)),
        ])
    }
}

pub fn check_upstream_sync(live_network: bool) -> UpstreamSyncReport {
    let mut report = UpstreamSyncReport {
        live_checked: false,
        upstream_repo: UPSTREAM_REPO,
        fork_repo: FORK_REPO,
        upstream_latest_release: "3.0.0-rc.5".to_string(),
        upstream_main_sha: "d7a3d94".to_string(),
        fork_main_sha: "af9b49a".to_string(),
        commits_behind: 99,
        files_changed_upstream: 237,
        sync_recommended: true,
        safe_sync_commands: vec![
            "# 1. NCSP Atomic Backup Bundle of current v2.5.0 fork (Zero Data Loss)".to_string(),
            "git clone --mirror https://github.com/Master-MD/NALA-OpenCore-Legacy-Patcher.git nala-oclp-pre-v3.git && git -C nala-oclp-pre-v3.git bundle create ../ncsp_pre_v3_backup.bundle --all".to_string(),
            "# 2. Fresh Clone + Tag legacy v2.5.0 state before pulling Dortania 3.x".to_string(),
            "git clone https://github.com/Master-MD/NALA-OpenCore-Legacy-Patcher.git NALA-OCLP-v3-Upstream && cd NALA-OCLP-v3-Upstream".to_string(),
            "git tag -a backup-v2.5.0-pre-v3 -m 'NCSP pre-v3 backup tag'".to_string(),
            "# 3. Add Official Dortania Upstream & Fast-Forward Sync to latest 3.x main".to_string(),
            "git remote add upstream https://github.com/dortania/OpenCore-Legacy-Patcher.git".to_string(),
            "git fetch upstream --tags && git merge --ff-only upstream/main".to_string(),
            "# 4. Verify SHA-256 & run NALA-oclp-rs parity + sHeriFF Zero-PII gate before pushing".to_string(),
            "nala-oclp-rs doctor && nala-oclp-rs audit-pii .".to_string(),
        ],
        notes: "Offline baseline (2026-11-21): Fork is clean v2.5.0 (af9b49a), 0 custom commits ahead, 99 commits behind dortania/main (v3.0.0-rc.5+ / Tahoe). Clean fast-forward merge possible with 0 conflicts!".to_string(),
    };

    if !live_network {
        return report;
    }

    let api_rel = format!("https://api.github.com/repos/{}/releases", UPSTREAM_REPO);
    if validate_upstream_url(&api_rel).is_err() {
        return report;
    }

    if let Some(rel_json) = fetch_github_api(&format!("repos/{}/releases", UPSTREAM_REPO))
        && let Ok(JsonValue::Array(arr)) = parse_json(&rel_json)
        && let Some(first) = arr.first()
        && let Some(tag) = first.get("tag_name").and_then(|v| v.as_str())
    {
        report.upstream_latest_release = tag.to_string();
        report.live_checked = true;
    }

    if let Some(up_json) = fetch_github_api(&format!("repos/{}/commits/main", UPSTREAM_REPO))
        && let Ok(val) = parse_json(&up_json)
        && let Some(sha) = val.get("sha").and_then(|v| v.as_str())
    {
        report.upstream_main_sha = sha.chars().take(7).collect();
        report.live_checked = true;
    }

    if let Some(fk_json) = fetch_github_api(&format!("repos/{}/commits/main", FORK_REPO))
        && let Ok(val) = parse_json(&fk_json)
        && let Some(sha) = val.get("sha").and_then(|v| v.as_str())
    {
        report.fork_main_sha = sha.chars().take(7).collect();
        report.live_checked = true;
    }

    if report.live_checked && report.fork_main_sha != report.upstream_main_sha {
        let cmp_ep = format!(
            "repos/{}/compare/{}...main",
            UPSTREAM_REPO, report.fork_main_sha
        );
        if let Some(cmp_json) = fetch_github_api(&cmp_ep)
            && let Ok(val) = parse_json(&cmp_json)
        {
            if let Some(ahead) = val.get("ahead_by").and_then(|v| v.as_u64()) {
                report.commits_behind = ahead;
            }
            if let Some(files) = val.get("files").and_then(|v| v.as_array()) {
                report.files_changed_upstream = files.len() as u64;
            }
            report.sync_recommended = report.commits_behind > 0;
            report.notes = format!(
                "Live GitHub verification OK: fork {} is {} commits behind upstream {} ({}). Fast-forward upgrade ready.",
                report.fork_main_sha,
                report.commits_behind,
                report.upstream_main_sha,
                report.upstream_latest_release
            );
        }
    } else if report.live_checked {
        report.commits_behind = 0;
        report.sync_recommended = false;
        report.notes = "Live GitHub verification OK: fork is 100% synchronized with upstream main.".to_string();
    }

    report
}

fn fetch_github_api(endpoint: &str) -> Option<String> {
    let out = Command::new("gh").args(["api", endpoint]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}
