//! Pod/image state as per-entity TOML confs:
//!   <data>/conf/pods/<name>.conf   and   <data>/conf/images/<name>.conf
//! Human-readable (limits as "10G"), hand-edits load via
//! `rustypods reload <pod>`. A legacy state.json is migrated once.

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

/// TOML shape of LimitsSpec: `memory_high = "10G"` (or a bare int),
/// `cpu_quota_percent = 400`. Empty/0 = no cap.
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

/// Accepts "10G", 10737418240, and the legacy *_bytes keys.
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
        other => Err(format!("{key}: invalid value {other}")),
    }
}

/// Serde module for standalone duration fields (seconds): writes `"7d"`,
/// reads a duration string or a bare integer.
pub(crate) mod duration_field {
    use rustypods_proto::{fmt_duration, parse_duration};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        if *v == 0 {
            "".serialize(s)
        } else {
            fmt_duration(*v).serialize(s)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let v = toml::Value::deserialize(d)?;
        match v {
            toml::Value::String(s) if s.is_empty() => Ok(0),
            toml::Value::String(s) => parse_duration(&s).map_err(serde::de::Error::custom),
            toml::Value::Integer(i) if i >= 0 => Ok(i as u64),
            other => Err(serde::de::Error::custom(format!("invalid duration {other}"))),
        }
    }
}

/// Serde module for standalone byte fields: writes `"20G"`, reads str or int.
pub(crate) mod bytes_field {
    use rustypods_proto::{fmt_bytes, parse_bytes};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        if *v == 0 {
            "".serialize(s)
        } else {
            fmt_bytes(*v).serialize(s)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let v = toml::Value::deserialize(d)?;
        match v {
            toml::Value::String(s) if s.is_empty() => Ok(0),
            toml::Value::String(s) => parse_bytes(&s).map_err(serde::de::Error::custom),
            toml::Value::Integer(i) if i >= 0 => Ok(i as u64),
            other => Err(serde::de::Error::custom(format!("invalid size {other}"))),
        }
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
    /// Human-readable origin, e.g. "distrobox:arch" or "oci:busybox:latest".
    pub source: String,
    pub created_unix: u64,
    /// OCI image config — empty for distrobox imports. Pods on images with
    /// an entrypoint/cmd run non-boot (no systemd inside OCI images).
    #[serde(default)]
    pub entrypoint: Vec<String>,
    #[serde(default)]
    pub cmd: Vec<String>,
    /// OCI env, "K=V" entries → nspawn --setenv.
    #[serde(default)]
    pub env: Vec<String>,
    /// OCI working dir → nspawn --chdir (non-boot only).
    #[serde(default)]
    pub working_dir: String,
}

/// One hostname→pod-port ingress rule, persisted in the pod conf.
/// Hostnames are unique across ALL pods — enforced server-side at
/// create/config/apply time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngressSpec {
    pub host: String,
    pub pod_port: u16,
}

/// A missing `private_users` key must mean ON: serde's default(false)
/// would silently drop userns isolation on a hand-edited conf. Explicit
/// `private_users = false` (stack members, desktop pods) still parses.
fn default_true() -> bool {
    true
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
    #[serde(default = "default_true")]
    pub private_users: bool,
    #[serde(default)]
    pub started: bool,
    /// Btrfs qgroup cap on the pod rootfs; 0 = none.
    /// Serialized as `storage_max = "20G"`.
    #[serde(default, with = "bytes_field")]
    pub storage_max_bytes: u64,
    /// "hostPort:podPort" — imply private netns (--network-veth).
    /// Only applied at start; changing them requires a pod restart.
    #[serde(default)]
    pub ports: Vec<String>,
    /// Hostname-based ingress rules (see proto IngressRule); imply private
    /// networking and a net_index like ports do.
    #[serde(default)]
    pub ingress: Vec<IngressSpec>,
    /// Index into the 10.220.<idx>.0/30 pool for veth addressing; 0 = none.
    /// Allocated at first start when ports are configured, or at apply
    /// time for stack members (one index shared by the whole stack).
    #[serde(default)]
    pub net_index: u32,
    /// Stack membership ("" = standalone). Members share one named netns:
    /// rustypods-<stack>, joined via nspawn --network-namespace-path.
    #[serde(default)]
    pub stack: String,
    /// "host[:pod][:ro]" bind mounts, applied at start.
    #[serde(default)]
    pub binds: Vec<String>,
    /// Per-pod payload override: replaces the image's entrypoint+cmd and
    /// forces non-boot mode, even on boot-capable images.
    #[serde(default)]
    pub cmd: Vec<String>,
    /// Snapshot GC: keep at most this many commits (0 = unlimited).
    #[serde(default)]
    pub snap_keep_last: u32,
    /// Snapshot GC: drop commits older than this (0 = unlimited).
    /// Serialized as `snap_max_age = "7d"`.
    #[serde(rename = "snap_max_age", default, with = "duration_field")]
    pub snap_max_age_secs: u64,
    /// This pod is the managed ingress gateway (rustypods-ingress proxy).
    /// Only set via InitIngress — conf misuse is checked at load().
    #[serde(default)]
    pub ingress_gateway: bool,
    /// Boot with the daemon: serve() start_pod's every flagged pod after
    /// the state scan (failures are logged, never fatal).
    #[serde(default)]
    pub autostart: bool,
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

/// Atomic-ish write: tmp file + fsync + rename (+ dir sync so the rename
/// itself survives a crash).
fn write_conf(path: &Path, body: &str) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("conf.tmp");
    {
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(body.as_bytes())
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    // Best-effort dir fsync: on some filesystems a rename isn't durable
    // without it. Failure is non-fatal (e.g. read-only dirs in tests).
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
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

/// Conf sanity beyond TOML parsing — applied at boot (scan) and on
/// `reload` (load_pod). `stem` is the conf filename without ".conf"; the
/// embedded name must match it so a copied/stale file can't register a
/// pod under a name its filename doesn't claim.
///
/// `check_binds` gates the validate_bind pass: it canonicalizes the host
/// path, which requires it to exist — at boot a conf's bind (e.g.
/// /run/user/<uid>) may legitimately not exist yet, and dropping the pod
/// from state would hide its rootfs entirely. start_pod re-validates
/// binds anyway, so boot-time skips are fail-safe.
fn check_pod_meta(m: &PodMeta, stem: &str, check_binds: bool) -> Result<()> {
    rustypods_proto::validate_name(&m.name)?;
    if m.name != stem {
        anyhow::bail!("conf name '{}' does not match filename '{}.conf'", m.name, stem);
    }
    if m.net_index > 255 {
        anyhow::bail!("net_index {} out of range (pool is 1..=255)", m.net_index);
    }
    // The stack name feeds netns/veth names that get truncated at BYTE
    // 12 (net::stack_peer/veth_name) — a multibyte value would panic
    // mid-char. validate_name is ASCII-only.
    if !m.stack.is_empty() {
        rustypods_proto::validate_name(&m.stack)
            .with_context(|| format!("invalid stack name '{}'", m.stack))?;
    }
    for spec in &m.ports {
        rustypods_proto::validate_port(spec)
            .with_context(|| format!("invalid port '{spec}'"))?;
    }
    // Ingress rules: full grammar check + no duplicate hosts within a pod
    // (global uniqueness across pods needs live state — the server does it).
    {
        let mut hosts = std::collections::BTreeSet::new();
        for i in &m.ingress {
            let rule = rustypods_proto::rpc::IngressRule {
                host: i.host.clone(),
                pod_port: i.pod_port as u32,
            };
            rustypods_proto::validate_ingress_rule(&rule)
                .with_context(|| format!("invalid ingress '{}:{}'", i.host, i.pod_port))?;
            if !hosts.insert(&i.host) {
                anyhow::bail!("duplicate ingress host '{}'", i.host);
            }
        }
    }
    if check_binds {
        for spec in &m.binds {
            rustypods_proto::validate_bind(spec)
                .with_context(|| format!("invalid bind '{spec}'"))?;
        }
    }
    if !m.cmd.is_empty() {
        rustypods_proto::validate_argv(&m.cmd).context("invalid cmd")?;
    }
    Ok(())
}

/// Read a single conf (hand edit → `rustypods reload <pod>`). Unlike the
/// boot-time scan this also checks bind specs — a reload is explicit and
/// its error surfaces to the user, while the in-memory state is kept.
pub fn load_pod(data_dir: &Path, name: &str) -> Result<PodMeta> {
    let p = pod_conf(data_dir, name);
    let s = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
    let m: PodMeta = toml::from_str(&s).with_context(|| format!("parse {}", p.display()))?;
    check_pod_meta(&m, name, true).with_context(|| format!("invalid {}", p.display()))?;
    Ok(m)
}

fn scan<T: for<'de> Deserialize<'de>>(
    dir: &Path,
    out: &mut BTreeMap<String, T>,
    name_of: fn(&T) -> &str,
    check: fn(&T, &str) -> Result<()>,
) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("conf") {
            continue;
        }
        let stem = p
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        match std::fs::read_to_string(&p)
            .ok()
            .and_then(|s| toml::from_str::<T>(&s).ok())
        {
            Some(m) => {
                if let Err(e) = check(&m, &stem) {
                    tracing::warn!("conf {} skipped ({e:#})", p.display());
                    continue;
                }
                out.insert(name_of(&m).to_string(), m);
            }
            None => tracing::warn!("conf {} skipped (parse error)", p.display()),
        }
    }
}

fn check_image_meta(m: &ImageMeta, stem: &str) -> Result<()> {
    rustypods_proto::validate_name(&m.name)?;
    if m.name != stem {
        anyhow::bail!("conf name '{}' does not match filename '{}.conf'", m.name, stem);
    }
    Ok(())
}

pub fn load(data_dir: &Path) -> Result<State> {
    migrate_json(data_dir);
    let mut st = State::default();
    scan(
        &pods_conf_dir(data_dir),
        &mut st.pods,
        |m: &PodMeta| m.name.as_str(),
        |m, stem| check_pod_meta(m, stem, false),
    );
    scan(
        &images_conf_dir(data_dir),
        &mut st.images,
        |m: &ImageMeta| m.name.as_str(),
        check_image_meta,
    );
    // Ingress hostnames are globally unique — a hand-edited conf pair
    // claiming the same host would silently split traffic between pods,
    // so a cross-conf collision aborts startup (fail closed). A single
    // malformed conf is still just skipped+warned above.
    let mut claimed: BTreeMap<&str, &str> = BTreeMap::new();
    for m in st.pods.values() {
        for i in &m.ingress {
            if let Some(other) = claimed.insert(i.host.as_str(), m.name.as_str()) {
                anyhow::bail!(
                    "ingress host '{}' is claimed by both pod {} and pod {}",
                    i.host,
                    other,
                    m.name
                );
            }
        }
    }
    // Exactly one managed ingress gateway may exist, and only under the
    // reserved name — a hand-edited conf claiming the flag elsewhere
    // would hijack the managed role, so abort startup (fail closed).
    let gateways: Vec<&str> = st
        .pods
        .values()
        .filter(|m| m.ingress_gateway)
        .map(|m| m.name.as_str())
        .collect();
    for name in &gateways {
        if *name != rustypods_proto::INGRESS_POD {
            anyhow::bail!(
                "pod {name} claims ingress_gateway but only {} may hold it",
                rustypods_proto::INGRESS_POD
            );
        }
    }
    if gateways.len() > 1 {
        anyhow::bail!("multiple pods claim ingress_gateway ({})", gateways.join(", "));
    }
    // …and the reserved name may ONLY be the gateway: an ordinary pod
    // conf squatting on it would shadow the managed one.
    if let Some(m) = st.pods.get(rustypods_proto::INGRESS_POD) {
        if !m.ingress_gateway {
            anyhow::bail!(
                "pod {} must be the managed ingress gateway (ingress_gateway = true) — the name is reserved",
                rustypods_proto::INGRESS_POD
            );
        }
    }
    Ok(st)
}

// --- one-time migration from the central state.json ---------------------------

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
    // Same fail-open as PodMeta: absent = userns on, never silently off.
    #[serde(default = "default_true")]
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
        tracing::warn!("state.json unparseable — left in place, starting with empty state");
        return;
    };
    for (name, i) in &old.images {
        // The name lands in a filename — never trust it unvalidated.
        if rustypods_proto::validate_name(&i.name).is_err() {
            tracing::warn!("migrate: skipping image '{name}' — invalid name '{}'", i.name);
            continue;
        }
        let m = ImageMeta {
            name: i.name.clone(),
            source: i.source.clone(),
            created_unix: i.created_unix,
            entrypoint: vec![],
            cmd: vec![],
            env: vec![],
            working_dir: String::new(),
        };
        if let Err(e) = save_image(data_dir, &m) {
            tracing::warn!("migrate image {name}: {e:#}");
        }
    }
    for (name, p) in &old.pods {
        if rustypods_proto::validate_name(&p.name).is_err() {
            tracing::warn!("migrate: skipping pod '{name}' — invalid name '{}'", p.name);
            continue;
        }
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
            // started is volatile; running state comes from machined live.
            started: false,
            storage_max_bytes: 0,
            ports: vec![],
            ingress: vec![],
            net_index: 0,
            stack: String::new(),
            binds: vec![],
            cmd: vec![],
            snap_keep_last: 0,
            snap_max_age_secs: 0,
            autostart: false,
            ingress_gateway: false,
        };
        if let Err(e) = save_pod(data_dir, &m) {
            tracing::warn!("migrate pod {name}: {e:#}");
        }
    }
    let _ = std::fs::rename(&f, f.with_extension("json.migrated"));
    tracing::info!("state.json migrated to conf/*.conf");
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(name: &str, host: &str) -> PodMeta {
        PodMeta {
            name: name.into(),
            image: "img".into(),
            created_unix: 0,
            limits: LimitsSpec::default(),
            ephemeral: false,
            private_users: true,
            started: false,
            storage_max_bytes: 0,
            ports: vec![],
            ingress: vec![IngressSpec {
                host: host.into(),
                pod_port: 80,
            }],
            net_index: 0,
            stack: String::new(),
            binds: vec![],
            cmd: vec![],
            snap_keep_last: 0,
            snap_max_age_secs: 0,
            autostart: false,
            ingress_gateway: false,
        }
    }

    /// A cross-conf ingress collision is the one state error that must
    /// abort daemon startup — hand edits could otherwise silently split
    /// one hostname across two pods.
    #[test]
    fn load_fails_closed_on_global_ingress_collision() {
        let dir = std::env::temp_dir().join(format!("rp-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        save_pod(&dir, &meta("a", "a.rustypods.localhost")).unwrap();
        assert!(load(&dir).is_ok(), "distinct hosts must load");
        save_pod(&dir, &meta("b", "a.rustypods.localhost")).unwrap();
        let e = load(&dir).expect_err("shared host must abort load");
        assert!(e.to_string().contains("a.rustypods.localhost"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reserved gateway name and the flag are a two-way lock: a
    /// gateway under any other name, more than one gateway, or an
    /// ordinary pod squatting on the reserved name all abort startup —
    /// none of them can be auto-corrected safely.
    #[test]
    fn load_enforces_gateway_invariants() {
        let dir = std::env::temp_dir().join(format!("rp-gw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Legit gateway loads.
        let mut gw = meta("rustypods-ingress", "");
        gw.ingress.clear();
        gw.ingress_gateway = true;
        save_pod(&dir, &gw).unwrap();
        save_pod(&dir, &meta("a", "a.rustypods.localhost")).unwrap();
        assert!(load(&dir).is_ok(), "single gateway under reserved name");

        // Flag on the wrong name → fail.
        let mut bad = meta("evil", "");
        bad.ingress.clear();
        bad.ingress_gateway = true;
        save_pod(&dir, &bad).unwrap();
        assert!(load(&dir).is_err(), "gateway flag on wrong name");
        std::fs::remove_file(dir.join("conf/pods/evil.conf")).unwrap();

        // Reserved name without the flag → fail.
        let mut squatter = meta("rustypods-ingress", "");
        squatter.ingress.clear();
        save_pod(&dir, &squatter).unwrap();
        assert!(load(&dir).is_err(), "reserved name without gateway flag");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
