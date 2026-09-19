use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct LimitsSpec {
    pub memory_high_bytes: u64,
    pub memory_max_bytes: u64,
    pub cpu_quota_percent: u32,
}

impl LimitsSpec {
    pub fn is_empty(&self) -> bool {
        self.memory_high_bytes == 0 && self.memory_max_bytes == 0 && self.cpu_quota_percent == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMeta {
    pub name: String,
    /// Human-readable origin, e.g. "distrobox:arch".
    pub source: String,
    pub created_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodMeta {
    pub name: String,
    pub image: String,
    pub created_unix: u64,
    #[serde(default)]
    pub limits: LimitsSpec,
    #[serde(default)]
    pub ephemeral: bool,
    #[serde(default)]
    pub private_users: bool,
    #[serde(default)]
    pub started: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub images: BTreeMap<String, ImageMeta>,
    pub pods: BTreeMap<String, PodMeta>,
}

pub fn load(path: &Path) -> State {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Atomic-ish write: tmp file + rename.
pub fn save(path: &Path, st: &State) -> Result<()> {
    let tmp = path.with_file_name("state.json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(st)?)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename naar {}", path.display()))?;
    Ok(())
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
