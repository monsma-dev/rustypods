//! Pod/image-state als per-entiteit TOML-confs:
//!   <data>/conf/pods/<name>.conf   en   <data>/conf/images/<name>.conf
//! Leesbaar voor sysadmins (limits als "10G"), hand-edits inleesbaar via
//! `rustypods reload <pod>`. state.json wordt eenmalig gemigreerd.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rustypods_proto::{fmt_bytes, parse_bytes};

#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(into = "LimitsToml")]
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

/// TOML-vorm van LimitsSpec: `memory_high = "10G"` (of een kale int),
/// `cpu_quota_percent = 400`. Leeg/0 = geen cap.
#[derive(Serialize)]
struct LimitsToml {
    memory_high: String,
    memory_max: String,
    cpu_quota_percent: u32,
}

impl From<LimitsSpec> for LimitsToml {
    fn from(l: LimitsSpec) -> Self {
        Self {
            memory_high: if l.memory_high_bytes == 0 {
                String::new()
            } else {
                fmt_bytes(l.memory_high_bytes)
            },
            memory_max: if l.memory_max_bytes == 0 {
                String::new()
            } else {
                fmt_bytes(l.memory_max_bytes)
            },
            cpu_quota_percent: l.cpu_quota_percent,
        }
    }
}

/// Accepteert "10G", 10737418240, en de legacy *_bytes sleutels.
#[derive(Deserialize, Default)]
struct LimitsTomlIn {
    #[serde(default)]
    memory_high: Option<toml::Value>,
    #[serde(default)]
    memory_max: Option<toml::Value>,
    #[serde(default)]
    memory_high_bytes: Option<u64>,
    #[serde(default)]
    memory_max_bytes: Option<u64>,
    #[serde(default)]
    cpu_quota_percent: Option<u32>,
}

fn val_to_bytes(v: &toml::Value, key: &str) -> std::result::Result<u64, String> {
    match v {
        toml::Value::String(s) if s.is_empty() => Ok(0),
        toml::Value::String(s) => parse_bytes(s).map_err(|e| format!("{key}: {e:#}")),
        toml::Value::Integer(i) if *i >= 0 => Ok(*i as u64),
        other => Err(format!("{key}: ongeldige waarde {other}")),
    }
}

impl<'de> Deserialize<'de> for LimitsSpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = LimitsTomlIn::deserialize(d)?;
        let conv = |v: Option<toml::Value>, b: Option<u64>, key: &str| {
            v.map(|v| val_to_bytes(&v, key))
                .transpose()
                .map(|x| x.or(b).unwrap_or(0))
                .map_err(serde::de::Error::custom)
        };
        Ok(Self {
            memory_high_bytes: conv(raw.memory_high, raw.memory_high_bytes, "memory_high")?,
            memory_max_bytes: conv(raw.memory_max, raw.memory_max_bytes, "memory_max")?,
            cpu_quota_percent: raw.cpu_quota_percent.unwrap_or(0),
        })
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

#[derive(Debug, Default)]
pub struct State {
    pub images: BTreeMap<String, ImageMeta>,
    pub pods: BTreeMap<String, PodMeta>,
}

pub fn pods_conf_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("conf").join("pods")
}
pub fn images_conf_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("conf").join("images")
}
fn pod_conf(data_dir: &Path, name: &str) -> PathBuf {
    pods_conf_dir(data_dir).join(format!("{name}.conf"))
}
fn image_conf(data_dir: &Path, name: &str) -> PathBuf {
    images_conf_dir(data_dir).join(format!("{name}.conf"))
}

/// Atomic-ish write: tmp file + rename.
fn write_conf(path: &Path, body: &str) -> Result<()> {
    let tmp = path.with_extension("conf.tmp");
    std::fs::write(&tmp, body).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename naar {}", path.display()))?;
    Ok(())
}

pub fn save_pod(data_dir: &Path, m: &PodMeta) -> Result<()> {
    std::fs::create_dir_all(pods_conf_dir(data_dir))?;
    write_conf(&pod_conf(data_dir, &m.name), &toml::to_string_pretty(m)?)
}
pub fn save_image(data_dir: &Path, m: &ImageMeta) -> Result<()> {
    std::fs::create_dir_all(images_conf_dir(data_dir))?;
    write_conf(&image_conf(data_dir, &m.name), &toml::to_string_pretty(m)?)
}
pub fn remove_pod(data_dir: &Path, name: &str) {
    let _ = std::fs::remove_file(pod_conf(data_dir, name));
}
pub fn remove_image(data_dir: &Path, name: &str) {
    let _ = std::fs::remove_file(image_conf(data_dir, name));
}

/// Eén conf inlezen (hand-edit → `rustypods reload <pod>`).
pub fn load_pod(data_dir: &Path, name: &str) -> Result<PodMeta> {
    let p = pod_conf(data_dir, name);
    let s = std::fs::read_to_string(&p).with_context(|| format!("lees {}", p.display()))?;
    toml::from_str(&s).with_context(|| format!("parse {}", p.display()))
}

fn scan<T: for<'de> Deserialize<'de>>(dir: &Path, out: &mut BTreeMap<String, T>, name_of: fn(&T) -> &str) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("conf") {
            continue;
        }
        match std::fs::read_to_string(&p)
            .ok()
            .and_then(|s| toml::from_str::<T>(&s).ok())
        {
            Some(m) => {
                out.insert(name_of(&m).to_string(), m);
            }
            None => tracing::warn!("conf {} overgeslagen (parse-fout)", p.display()),
        }
    }
}

pub fn load(data_dir: &Path) -> State {
    migrate_json(data_dir);
    let mut st = State::default();
    scan(&pods_conf_dir(data_dir), &mut st.pods, |m: &PodMeta| m.name.as_str());
    scan(&images_conf_dir(data_dir), &mut st.images, |m: &ImageMeta| {
        m.name.as_str()
    });
    st
}

// --- eenmalige migratie van centrale state.json ------------------------------

#[derive(Deserialize, Default)]
struct LegacyLimits {
    #[serde(default)]
    memory_high_bytes: u64,
    #[serde(default)]
    memory_max_bytes: u64,
    #[serde(default)]
    cpu_quota_percent: u32,
}
#[derive(Deserialize)]
struct LegacyPod {
    name: String,
    image: String,
    #[serde(default)]
    created_unix: u64,
    #[serde(default)]
    limits: LegacyLimits,
    #[serde(default)]
    ephemeral: bool,
    #[serde(default)]
    private_users: bool,
}
#[derive(Deserialize)]
struct LegacyImage {
    name: String,
    source: String,
    #[serde(default)]
    created_unix: u64,
}
#[derive(Deserialize)]
struct LegacyState {
    #[serde(default)]
    images: BTreeMap<String, LegacyImage>,
    #[serde(default)]
    pods: BTreeMap<String, LegacyPod>,
}

fn migrate_json(data_dir: &Path) {
    let f = data_dir.join("state.json");
    let Ok(s) = std::fs::read_to_string(&f) else { return };
    let Ok(old) = serde_json::from_str::<LegacyState>(&s) else {
        tracing::warn!("state.json onparseerbaar — laat staan, start met lege state");
        return;
    };
    for (name, i) in &old.images {
        let m = ImageMeta {
            name: i.name.clone(),
            source: i.source.clone(),
            created_unix: i.created_unix,
        };
        if let Err(e) = save_image(data_dir, &m) {
            tracing::warn!("migratie image {name}: {e:#}");
        }
    }
    for (name, p) in &old.pods {
        let m = PodMeta {
            name: p.name.clone(),
            image: p.image.clone(),
            created_unix: p.created_unix,
            limits: LimitsSpec {
                memory_high_bytes: p.limits.memory_high_bytes,
                memory_max_bytes: p.limits.memory_max_bytes,
                cpu_quota_percent: p.limits.cpu_quota_percent,
            },
            ephemeral: p.ephemeral,
            private_users: p.private_users,
            // started is vluchtig; running wordt live via machined bepaald.
            started: false,
        };
        if let Err(e) = save_pod(data_dir, &m) {
            tracing::warn!("migratie pod {name}: {e:#}");
        }
    }
    let _ = std::fs::rename(&f, f.with_extension("json.migrated"));
    tracing::info!("state.json → conf/*.conf gemigreerd");
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
