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

/// On-disk conf schema this binary writes for pods, images and volumes.
/// Older files omit `format` and load as 1. A newer `format` is loaded
/// but never rewritten: serde would drop unknown fields on save.
pub const CONF_FORMAT: u32 = 1;

/// `mesh.conf` schema. 2 stored `cluster_token` and `MeshPeerConf.name`.
/// 3 adds `cluster_token_prev`, the previous token still accepted
/// during rotation. Saves stamp this value so an older daemon refuses
/// to rewrite the file and therefore cannot drop the grace token.
pub const MESH_CONF_FORMAT: u32 = 3;

fn default_format() -> u32 {
    CONF_FORMAT
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(into = "LimitsToml")]
pub struct LimitsSpec {
    pub memory_high_bytes: u64,
    pub memory_max_bytes: u64,
    pub cpu_quota_percent: u32,
    /// systemd TasksMax on the pod scope. 0 = unset (existing pods).
    /// New pods created by the daemon get [`DEFAULT_TASKS_MAX`].
    pub tasks_max: u64,
}

/// Applied to every newly created pod unless the request already set one.
pub const DEFAULT_TASKS_MAX: u64 = 4096;

impl LimitsSpec {
    pub fn is_empty(&self) -> bool {
        self.memory_high_bytes == 0
            && self.memory_max_bytes == 0
            && self.cpu_quota_percent == 0
            && self.tasks_max == 0
    }

    /// Fill defaults for a pod that does not exist on disk yet. Explicit
    /// non-zero limits win. MemoryMax and CPUQuota are applied only when
    /// `RUSTYPODS_DEFAULT_MEMORY_MAX` / `RUSTYPODS_DEFAULT_CPU` are set
    /// (typically via `/etc/rustypods/daemon.env`). A set value that does
    /// not parse is an error. TasksMax is always set.
    pub fn with_create_defaults(mut self) -> Result<Self> {
        if self.tasks_max == 0 {
            self.tasks_max = DEFAULT_TASKS_MAX;
        }
        let env = crate::envcfg::DaemonEnv::from_env()?;
        if self.memory_max_bytes == 0 {
            if let Some(b) = env.default_memory_max {
                self.memory_max_bytes = b;
            }
        }
        if self.cpu_quota_percent == 0 {
            if let Some(n) = env.default_cpu_percent {
                self.cpu_quota_percent = n;
            }
        }
        Ok(self)
    }
}

/// TOML shape of LimitsSpec: `memory_high = "10G"` (or a bare int),
/// `cpu_quota_percent = 400`. Empty/0 = no cap.
#[derive(Serialize)]
struct LimitsToml {
    memory_high: String,
    memory_max: String,
    cpu_quota_percent: u32,
    tasks_max: u64,
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
            tasks_max: l.tasks_max,
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
    #[serde(default)]
    tasks_max: Option<u64>,
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
            other => Err(serde::de::Error::custom(format!(
                "invalid duration {other}"
            ))),
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
            tasks_max: raw.tasks_max.unwrap_or(0),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMeta {
    #[serde(default = "default_format")]
    pub format: u32,
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
pub const DEFAULT_STOP_TIMEOUT_SECS: u64 = 8;

fn default_stop_timeout() -> u64 {
    DEFAULT_STOP_TIMEOUT_SECS
}

/// Poweroff grace for a conf value. 0 means the historical 8s default.
pub fn stop_grace(secs: u64) -> std::time::Duration {
    std::time::Duration::from_secs(if secs == 0 {
        DEFAULT_STOP_TIMEOUT_SECS
    } else {
        secs
    })
}

/// A missing `private_users` key must mean ON: serde's default(false)
/// would silently drop userns isolation on a hand-edited conf. Explicit
/// `private_users = false` (stack members, desktop pods) still parses.
fn default_true() -> bool {
    true
}

/// Liveness probe config, persisted in the pod conf. `kind` "" =
/// disabled — a pod with only a restart policy still gets death-watch
/// restarts on leader death.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthSpec {
    /// "" | "exec" | "tcp" | "http".
    #[serde(default)]
    pub kind: String,
    /// tcp: ":port" | "host:port"; http: "/path" | "http://…"; exec: unused.
    #[serde(default)]
    pub target: String,
    /// exec probe argv.
    #[serde(default)]
    pub argv: Vec<String>,
    #[serde(default)]
    pub interval_secs: u32,
    #[serde(default)]
    pub timeout_secs: u32,
    #[serde(default)]
    pub retries: u32,
    /// exec probe identity (image passwd name or numeric uid). "" = pod
    /// root in userns pods, nobody/65534 in pods without a user namespace
    /// (root there is HOST root — set `user = "root"` explicitly to accept).
    /// Conf-only for now; survives `config --healthcheck` updates.
    #[serde(default)]
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodMeta {
    #[serde(default = "default_format")]
    pub format: u32,
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
    /// User asked the pod to stay down (`rustypods stop`). Distinct from
    /// `started`, which only means "was ever started" and drives the
    /// Created/Stopped display. Survives daemon restart: the supervisor
    /// and autostart leave the pod stopped until an explicit start
    /// (unless-stopped). Absent in older confs → false.
    #[serde(default)]
    pub stopped_by_user: bool,
    /// How long `stop` waits after SIGRTMIN+3 before TerminateMachine.
    /// 0 and older confs use [`DEFAULT_STOP_TIMEOUT_SECS`] (8s).
    #[serde(default = "default_stop_timeout")]
    pub stop_timeout_secs: u64,
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
    /// Restart policy: "" | "no" | "on-failure" | "always" — "" == "no".
    /// The supervisor restarts on leader death ("on-failure"/"always")
    /// or sustained probe failure ("always" only).
    #[serde(default)]
    pub restart: String,
    /// Liveness probe spec; kind "" = disabled.
    #[serde(default)]
    pub healthcheck: HealthSpec,
    /// Pod-level env "KEY=value", merged over the image's OCI env at
    /// start (pod wins per key). Visible via /proc/<pid>/environ.
    #[serde(default)]
    pub env: Vec<String>,
    /// Named-volume mounts "name:/pod/path[:ro]"; volumes are btrfs
    /// subvols under volumes/ that outlive the pod.
    #[serde(default)]
    pub volumes: Vec<String>,
    /// Allow this pod to open new connections to host-local addresses
    /// (including 127.0.0.1). Default false: pod root can otherwise
    /// reach host loopback services via the veth (route_localnet).
    #[serde(default)]
    pub host_access: bool,
    /// Drop forwarded traffic between this pod and other pod veths.
    /// Pod egress to the outside and published ports still work.
    #[serde(default)]
    pub isolated: bool,
    /// Exec sessions skip NO_NEW_PRIVS, so sudo/su work. In a pod without a
    /// user namespace that means any process as the pod user can reach
    /// HOST root through a setuid binary (distrobox sudoers is often
    /// NOPASSWD). Conf-only: set it in the root-owned conf and `reload`.
    /// Probes keep NO_NEW_PRIVS. Userns pods never set it.
    #[serde(default)]
    pub allow_setuid: bool,
}

/// A named volume: a btrfs subvolume under volumes/<name> that pods
/// bind-mount by name. Persisted as conf/volumes/<name>.conf so the
/// registry survives daemon restarts even when the fs doesn't.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMeta {
    #[serde(default = "default_format")]
    pub format: u32,
    pub name: String,
    pub created_unix: u64,
}

/// A conf the daemon refused to serve. Its name and net_index stay
/// reserved so a later pod cannot reuse them.
#[derive(Debug, Clone)]
pub struct QuarantinedConf {
    pub name: String,
    pub reason: String,
    /// 0 when the file did not yield an index.
    pub net_index: u32,
    /// Volume specs when the file parsed far enough; empty otherwise.
    pub volumes: Vec<String>,
}

#[derive(Debug, Default)]
pub struct State {
    pub images: BTreeMap<String, ImageMeta>,
    pub pods: BTreeMap<String, PodMeta>,
    pub volumes: BTreeMap<String, VolumeMeta>,
    /// Pod confs excluded from serving (parse error, invariant breach).
    pub quarantined: Vec<QuarantinedConf>,
    /// net_index values owned by quarantined or unparsable pod confs.
    pub reserved_net: std::collections::BTreeSet<u32>,
}

/// Lowest free index in 1..=255, treating `reserved` as taken. Mirrors
/// `net::alloc_index` so a quarantined conf's /30 cannot be reissued
/// without changing the net module's signature.
pub fn alloc_net_index(
    pods: &BTreeMap<String, PodMeta>,
    reserved: &std::collections::BTreeSet<u32>,
) -> u32 {
    let mut used: std::collections::BTreeSet<u32> = pods
        .values()
        .map(|p| p.net_index)
        .filter(|i| *i > 0)
        .collect();
    used.extend(reserved.iter().copied().filter(|i| *i > 0 && *i <= 255));
    (1..=255).find(|i| !used.contains(i)).unwrap_or(0)
}

/// Best-effort `net_index = N` from a conf that did not parse as PodMeta.
pub fn peek_net_index(text: &str) -> Option<u32> {
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("net_index") else {
            continue;
        };
        let rest = rest.trim_start().strip_prefix('=')?.trim();
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return None;
        }
        return digits.parse().ok();
    }
    None
}

/// Conf directories are 0700. The CLI and GUI talk to the daemon over
/// gRPC; nothing non-root reads these files directly. Pod confs contain
/// env, mesh.conf contains the WireGuard private key.
pub fn secure_conf_dirs(data_dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dirs = [
        rustypods_proto::conf_dir(data_dir),
        pods_conf_dir(data_dir),
        images_conf_dir(data_dir),
        volumes_conf_dir(data_dir),
    ];
    for d in dirs {
        std::fs::create_dir_all(&d).with_context(|| format!("mkdir {}", d.display()))?;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", d.display()))?;
    }
    Ok(())
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
/// itself survives a crash). The temp file is created mode 0600 — confs
/// hold pod env — so a crash window is not world-readable either. Mode is
/// set at open time, not via a later chmod.
fn write_conf(path: &Path, body: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("conf.tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
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

fn volumes_conf_dir(data_dir: &Path) -> std::path::PathBuf {
    rustypods_proto::conf_dir(data_dir).join("volumes")
}
fn volume_conf(data_dir: &Path, name: &str) -> std::path::PathBuf {
    volumes_conf_dir(data_dir).join(format!("{name}.conf"))
}

pub fn save_volume(data_dir: &Path, m: &VolumeMeta) -> Result<()> {
    secure_conf_dirs(data_dir)?;
    let path = volume_conf(data_dir, &m.name);
    refuse_newer_conf(&path)?;
    if m.format > CONF_FORMAT {
        anyhow::bail!(
            "{} format {} is newer than supported {CONF_FORMAT}; refusing to overwrite",
            path.display(),
            m.format
        );
    }
    let mut m = m.clone();
    m.format = canonical_format(m.format)?;
    write_conf(&path, &toml::to_string_pretty(&m)?)
}
pub fn remove_volume(data_dir: &Path, name: &str) -> Result<()> {
    remove_conf(&volume_conf(data_dir, name))
}

pub fn save_pod(data_dir: &Path, m: &PodMeta) -> Result<()> {
    secure_conf_dirs(data_dir)?;
    let path = pod_conf(data_dir, &m.name);
    refuse_newer_conf(&path)?;
    if m.format > CONF_FORMAT {
        anyhow::bail!(
            "{} format {} is newer than supported {CONF_FORMAT}; refusing to overwrite",
            path.display(),
            m.format
        );
    }
    let mut m = m.clone();
    m.format = canonical_format(m.format)?;
    write_conf(&path, &toml::to_string_pretty(&m)?)
}
/// Multi-host mesh config (Wave I): the host's WG identity + static
/// peers. One TOML file — not per-entity confs — because it's a single
/// daemon-scoped object, not a registry.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct MeshConf {
    #[serde(default = "default_format")]
    pub format: u32,
    /// base64 x25519 private key; "" = mesh not initialized.
    #[serde(default)]
    pub private_key: String,
    /// UDP listen port for WireGuard datagrams.
    #[serde(default = "default_mesh_port")]
    pub listen_port: u16,
    /// Shared secret gating the mesh-RPC listener on fd<host>::1:5306.
    /// Generated on `mesh init`; joining hosts adopt the introducer's
    /// token via `mesh init --token`.
    #[serde(default)]
    pub cluster_token: String,
    /// Previous cluster token. Still accepted by mesh-RPC and gossip
    /// until `retire-token` clears it. Empty means no grace window.
    #[serde(default)]
    pub cluster_token_prev: String,
    #[serde(default)]
    pub peers: Vec<MeshPeerConf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPeerConf {
    /// "ip:port" the peer's daemon listens on.
    pub endpoint: String,
    /// base64 x25519 pubkey — also derives the peer's ULA /48.
    pub pubkey: String,
    /// Optional alias for `--host <name>` resolution.
    #[serde(default)]
    pub name: Option<String>,
}

fn default_mesh_port() -> u16 {
    51820
}

impl std::fmt::Debug for MeshConf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshConf")
            .field("format", &self.format)
            .field("private_key", &"<redacted>")
            .field("cluster_token", &"<redacted>")
            .field("cluster_token_prev", &"<redacted>")
            .field("listen_port", &self.listen_port)
            .field("peers", &self.peers)
            .finish()
    }
}

fn mesh_conf_path(data_dir: &Path) -> std::path::PathBuf {
    rustypods_proto::conf_dir(data_dir).join("mesh.conf")
}

/// Load the host mesh identity.
///
/// `Ok(None)` — no file, or a parsed file with an empty key (never
/// initialized). `Err` — the file exists but cannot be read or parsed.
/// Callers must not treat that as "no mesh" and mint a new key: the
/// /48 is sha256(pubkey), so a fresh key silently breaks every peer.
pub fn load_mesh(data_dir: &Path) -> Result<Option<MeshConf>> {
    let p = mesh_conf_path(data_dir);
    let s = match std::fs::read_to_string(&p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read {}", p.display())),
    };
    let m: MeshConf = toml::from_str(&s).with_context(|| {
        format!(
            "{} is corrupt; fix or remove it before mesh init (a new key would change this host's /48 and break every peer)",
            p.display()
        )
    })?;
    if m.private_key.is_empty() {
        return Ok(None);
    }
    Ok(Some(m))
}

pub fn save_mesh(data_dir: &Path, m: &MeshConf) -> Result<()> {
    secure_conf_dirs(data_dir)?;
    // 0600 comes from write_conf — the file holds the host's WG private key.
    let path = mesh_conf_path(data_dir);
    refuse_newer_than(&path, MESH_CONF_FORMAT)?;
    if m.format > MESH_CONF_FORMAT {
        anyhow::bail!(
            "{} format {} is newer than supported {MESH_CONF_FORMAT}; refusing to overwrite",
            path.display(),
            m.format
        );
    }
    let mut m = m.clone();
    // Always stamp the current mesh format. Keeping a loaded older
    // number would let a daemon that does not know `cluster_token_prev`
    // rewrite the file and drop the grace token.
    m.format = MESH_CONF_FORMAT;
    write_conf(&path, &toml::to_string_pretty(&m)?)
}

/// `mesh deinit` — drop the persisted identity+peers so a daemon
/// restart does not resurrect the mesh.
pub fn remove_mesh(data_dir: &Path) -> Result<()> {
    match std::fs::remove_file(mesh_conf_path(data_dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub fn save_image(data_dir: &Path, m: &ImageMeta) -> Result<()> {
    secure_conf_dirs(data_dir)?;
    let path = image_conf(data_dir, &m.name);
    refuse_newer_conf(&path)?;
    if m.format > CONF_FORMAT {
        anyhow::bail!(
            "{} format {} is newer than supported {CONF_FORMAT}; refusing to overwrite",
            path.display(),
            m.format
        );
    }
    let mut m = m.clone();
    m.format = canonical_format(m.format)?;
    write_conf(&path, &toml::to_string_pretty(&m)?)
}

fn canonical_format(format: u32) -> Result<u32> {
    if format > CONF_FORMAT {
        anyhow::bail!(
            "conf format {format} is newer than supported {CONF_FORMAT}; refusing to overwrite"
        );
    }
    Ok(if format == 0 { CONF_FORMAT } else { format })
}

/// A conf written by a newer daemon stays on disk untouched.
fn refuse_newer_conf(path: &Path) -> Result<()> {
    refuse_newer_than(path, CONF_FORMAT)
}

fn refuse_newer_than(path: &Path, supported: u32) -> Result<()> {
    let Ok(s) = std::fs::read_to_string(path) else {
        return Ok(());
    };
    let Ok(v) = toml::from_str::<toml::Value>(&s) else {
        return Ok(());
    };
    let fmt = v.get("format").and_then(|x| x.as_integer()).unwrap_or(1);
    if fmt > supported as i64 {
        anyhow::bail!(
            "{} format {fmt} is newer than supported {supported}; refusing to overwrite (loaded read-only)",
            path.display()
        );
    }
    Ok(())
}
pub fn remove_pod(data_dir: &Path, name: &str) -> Result<()> {
    remove_conf(&pod_conf(data_dir, name))
}
pub fn remove_image(data_dir: &Path, name: &str) -> Result<()> {
    remove_conf(&image_conf(data_dir, name))
}

fn remove_conf(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => {
            tracing::error!("failed to remove {}: {e}", path.display());
            Err(e).with_context(|| format!("remove {}", path.display()))
        }
    }
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
pub(crate) fn check_pod_meta(m: &PodMeta, stem: &str, check_binds: bool) -> Result<()> {
    rustypods_proto::validate_name(&m.name)?;
    if m.name != stem {
        anyhow::bail!(
            "conf name '{}' does not match filename '{}.conf'",
            m.name,
            stem
        );
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
        rustypods_proto::validate_port(spec).with_context(|| format!("invalid port '{spec}'"))?;
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
    rustypods_proto::validate_env(&m.env).context("invalid env")?;
    for spec in &m.volumes {
        rustypods_proto::parse_volume_spec(spec)
            .with_context(|| format!("invalid volume '{spec}'"))?;
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
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
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
        let text = match std::fs::read_to_string(&p) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("conf {} skipped (read error: {e})", p.display());
                continue;
            }
        };
        match toml::from_str::<T>(&text) {
            Ok(m) => {
                if let Err(e) = check(&m, &stem) {
                    tracing::warn!("conf {} skipped ({e:#})", p.display());
                    continue;
                }
                out.insert(name_of(&m).to_string(), m);
            }
            Err(e) => tracing::warn!("conf {} skipped (parse error: {e})", p.display()),
        }
    }
}

fn check_volume_meta(m: &VolumeMeta, stem: &str) -> Result<()> {
    rustypods_proto::validate_name(&m.name)?;
    if m.name != stem {
        anyhow::bail!(
            "conf name '{}' does not match filename '{}.conf'",
            m.name,
            stem
        );
    }
    Ok(())
}

fn check_image_meta(m: &ImageMeta, stem: &str) -> Result<()> {
    rustypods_proto::validate_name(&m.name)?;
    if m.name != stem {
        anyhow::bail!(
            "conf name '{}' does not match filename '{}.conf'",
            m.name,
            stem
        );
    }
    Ok(())
}

pub fn load(data_dir: &Path) -> Result<State> {
    migrate_json(data_dir);
    let mut st = State::default();
    scan_pods(data_dir, &mut st);
    scan(
        &images_conf_dir(data_dir),
        &mut st.images,
        |m: &ImageMeta| m.name.as_str(),
        check_image_meta,
    );
    scan(
        &volumes_conf_dir(data_dir),
        &mut st.volumes,
        |m: &VolumeMeta| m.name.as_str(),
        check_volume_meta,
    );
    // Ingress hostnames are globally unique. A colliding conf is
    // quarantined (not served) instead of aborting startup — a restart
    // loop helps nobody, and the name/net_index stay reserved.
    let mut claimed: BTreeMap<String, String> = BTreeMap::new();
    let mut drop_pods: Vec<(String, String)> = Vec::new();
    for m in st.pods.values() {
        for i in &m.ingress {
            if let Some(other) = claimed.get(&i.host) {
                drop_pods.push((
                    m.name.clone(),
                    format!("ingress host '{}' is also claimed by pod {other}", i.host),
                ));
                break;
            }
            claimed.insert(i.host.clone(), m.name.clone());
        }
    }
    for (name, reason) in drop_pods {
        quarantine_pod(&mut st, &name, reason);
    }
    // Exactly one managed ingress gateway, and only under the reserved
    // name. Offenders are quarantined; a valid gateway stays up.
    let bad_gateways: Vec<String> = st
        .pods
        .values()
        .filter(|m| m.ingress_gateway && m.name != rustypods_proto::INGRESS_POD)
        .map(|m| m.name.clone())
        .collect();
    for name in bad_gateways {
        quarantine_pod(
            &mut st,
            &name,
            format!(
                "claims ingress_gateway but only {} may hold it",
                rustypods_proto::INGRESS_POD
            ),
        );
    }
    if let Some(m) = st.pods.get(rustypods_proto::INGRESS_POD) {
        if !m.ingress_gateway {
            quarantine_pod(
                &mut st,
                rustypods_proto::INGRESS_POD,
                "name is reserved for the managed ingress gateway".into(),
            );
        }
    }
    Ok(st)
}

fn quarantine_pod(st: &mut State, name: &str, reason: String) {
    let Some(m) = st.pods.remove(name) else {
        return;
    };
    if m.net_index > 0 {
        st.reserved_net.insert(m.net_index);
    }
    tracing::error!("quarantine pod {}: {reason}", m.name);
    st.quarantined.push(QuarantinedConf {
        name: m.name,
        reason,
        net_index: m.net_index,
        volumes: m.volumes,
    });
}

/// Pod confs: a parse or check failure quarantines the file (name and
/// net_index reserved) instead of treating its /30 as free.
fn scan_pods(data_dir: &Path, st: &mut State) {
    let dir = pods_conf_dir(data_dir);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return;
    };
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
        let Ok(text) = std::fs::read_to_string(&p) else {
            tracing::error!("quarantine pod {stem}: unreadable {}", p.display());
            hold_unparsed(st, &stem, 0, format!("unreadable {}", p.display()));
            continue;
        };
        match toml::from_str::<PodMeta>(&text) {
            Ok(m) => match check_pod_meta(&m, &stem, false) {
                Ok(()) => {
                    st.pods.insert(m.name.clone(), m);
                }
                Err(err) => {
                    let idx = m.net_index;
                    let volumes = m.volumes.clone();
                    let name = if m.name.is_empty() {
                        stem.clone()
                    } else {
                        m.name.clone()
                    };
                    tracing::error!("quarantine pod {name}: {err:#}");
                    if idx > 0 {
                        st.reserved_net.insert(idx);
                    }
                    st.quarantined.push(QuarantinedConf {
                        name,
                        reason: format!("{err:#}"),
                        net_index: idx,
                        volumes,
                    });
                }
            },
            Err(err) => {
                let idx = peek_net_index(&text).unwrap_or(0);
                tracing::error!("quarantine pod {stem}: parse error: {err}");
                hold_unparsed(st, &stem, idx, format!("parse error: {err}"));
            }
        }
    }
}

fn hold_unparsed(st: &mut State, name: &str, net_index: u32, reason: String) {
    if net_index > 0 && net_index <= 255 {
        st.reserved_net.insert(net_index);
    }
    if !name.is_empty() {
        st.quarantined.push(QuarantinedConf {
            name: name.to_string(),
            reason,
            net_index,
            volumes: vec![],
        });
    }
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
    let Ok(s) = std::fs::read_to_string(&f) else {
        return;
    };
    let Ok(old) = serde_json::from_str::<LegacyState>(&s) else {
        tracing::warn!("state.json unparseable — left in place, starting with empty state");
        return;
    };
    for (name, i) in &old.images {
        // The name lands in a filename — never trust it unvalidated.
        if rustypods_proto::validate_name(&i.name).is_err() {
            tracing::warn!(
                "migrate: skipping image '{name}' — invalid name '{}'",
                i.name
            );
            continue;
        }
        let m = ImageMeta {
            format: CONF_FORMAT,
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
            format: CONF_FORMAT,
            name: p.name.clone(),
            image: p.image.clone(),
            created_unix: p.created_unix,
            limits: LimitsSpec {
                memory_high_bytes: p.limits.memory_high_bytes,
                memory_max_bytes: p.limits.memory_max_bytes,
                cpu_quota_percent: p.limits.cpu_quota_percent,
                tasks_max: 0,
            },
            ephemeral: p.ephemeral,
            private_users: p.private_users,
            // started is volatile; running state comes from machined live.
            started: false,
            stopped_by_user: false,
            stop_timeout_secs: 0,
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
            restart: String::new(),
            healthcheck: Default::default(),
            env: vec![],
            volumes: vec![],
            host_access: false,
            isolated: false,
            allow_setuid: false,
        };
        if let Err(e) = save_pod(data_dir, &m) {
            tracing::warn!("migrate pod {name}: {e:#}");
        }
    }
    let _ = std::fs::rename(&f, f.with_extension("json.migrated"));
    tracing::info!("state.json migrated to conf/*.conf");
}

/// What startup should do with one name under the pods directory.
/// Deletes are only planned for trees that are no longer the sole copy
/// (spent `.rollback-old` after the live rootfs is back, or `.rollback-new`
/// staging once a rootfs exists).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootfsAction {
    Rename {
        from: String,
        to: String,
    },
    Delete {
        name: String,
    },
    /// Logged, data left in place.
    Report {
        message: String,
    },
}

/// Plan startup repair from directory basenames plus the set of pod names
/// that have a loadable conf. `.import-*` / `.export-*` are ignored (the
/// transfer path owns them). `.rollback-old` is restored when it is the
/// only rootfs, and never deleted until a live rootfs exists.
pub fn plan_rootfs_reconcile(
    entries: &[String],
    conf_names: &std::collections::BTreeSet<String>,
) -> Vec<RootfsAction> {
    let mut present: std::collections::BTreeSet<String> = entries.iter().cloned().collect();
    let mut actions = Vec::new();
    let olds: Vec<String> = present
        .iter()
        .filter(|n| n.ends_with(".rollback-old"))
        .cloned()
        .collect();
    for old in olds {
        let stem = old.trim_end_matches(".rollback-old").to_string();
        if stem.is_empty() || present.contains(&stem) {
            actions.push(RootfsAction::Delete { name: old.clone() });
        } else {
            actions.push(RootfsAction::Rename {
                from: old.clone(),
                to: stem.clone(),
            });
            present.insert(stem);
        }
        present.remove(&old);
    }
    let news: Vec<String> = present
        .iter()
        .filter(|n| n.ends_with(".rollback-new"))
        .cloned()
        .collect();
    for staging in news {
        let stem = staging.trim_end_matches(".rollback-new").to_string();
        if stem.is_empty() || present.contains(&stem) {
            actions.push(RootfsAction::Delete {
                name: staging.clone(),
            });
        } else {
            // A lone staging tree may be a half-finished clone (the
            // reflink fallback copies file by file); never promote it
            // to the live rootfs unattended.
            actions.push(RootfsAction::Report {
                message: format!(
                    "'{staging}' has no live rootfs next to it — possibly an interrupted rollback clone; left in place, inspect and rename to '{stem}' by hand"
                ),
            });
        }
        present.remove(&staging);
    }
    let mut orphans: Vec<String> = present
        .iter()
        .filter(|n| {
            !n.starts_with(".import-")
                && !n.starts_with(".export-")
                && !n.ends_with(".orphan")
                && !n.contains(".orphan-")
                && !conf_names.contains(n.as_str())
        })
        .cloned()
        .collect();
    orphans.sort();
    for name in orphans {
        let mut dest = format!("{name}.orphan");
        if present.contains(&dest) {
            dest = format!("{name}.orphan-{}", now_unix());
        }
        if present.contains(&dest) {
            actions.push(RootfsAction::Report {
                message: format!(
                    "orphan rootfs '{name}' left in place — quarantine name '{dest}' is taken"
                ),
            });
        } else {
            actions.push(RootfsAction::Rename {
                from: name.clone(),
                to: dest.clone(),
            });
            present.insert(dest);
        }
        present.remove(&name);
    }
    let mut missing: Vec<&String> = conf_names
        .iter()
        .filter(|n| !present.contains(*n))
        .collect();
    missing.sort();
    for name in missing {
        actions.push(RootfsAction::Report {
            message: format!("pod '{name}' has a conf but no rootfs"),
        });
    }
    actions
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

    #[test]
    fn unparsable_conf_reserves_net_index() {
        let dir = std::env::temp_dir().join(format!("rp-q-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(pods_conf_dir(&dir)).unwrap();
        std::fs::write(
            pods_conf_dir(&dir).join("broken.conf"),
            "name = \"broken\"\nimage = \"img\"\ncreated_unix = 1\nnet_index = 7\nthis is not toml\n",
        )
        .unwrap();
        assert_eq!(peek_net_index("net_index = 7\n"), Some(7));
        let st = load(&dir).unwrap();
        assert!(st.pods.is_empty());
        assert!(st.reserved_net.contains(&7));
        assert!(st.quarantined.iter().any(|q| q.name == "broken"));
        let mut pods = BTreeMap::new();
        pods.insert(
            "ok".into(),
            PodMeta {
                format: CONF_FORMAT,
                name: "ok".into(),
                image: "img".into(),
                created_unix: 0,
                limits: Default::default(),
                ephemeral: false,
                private_users: true,
                started: false,
                stopped_by_user: false,
                stop_timeout_secs: 0,
                storage_max_bytes: 0,
                ports: vec![],
                ingress: vec![],
                net_index: 1,
                stack: String::new(),
                binds: vec![],
                cmd: vec![],
                snap_keep_last: 0,
                snap_max_age_secs: 0,
                autostart: false,
                ingress_gateway: false,
                restart: String::new(),
                healthcheck: Default::default(),
                env: vec![],
                volumes: vec![],
                host_access: false,
                isolated: false,
                allow_setuid: false,
            },
        );
        assert_ne!(alloc_net_index(&pods, &st.reserved_net), 7);
        assert_ne!(alloc_net_index(&pods, &st.reserved_net), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn volume_meta_roundtrip_and_adoption() {
        let dir = std::env::temp_dir().join(format!("rustypods-vol-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let v = VolumeMeta {
            format: CONF_FORMAT,
            name: "pgdata".into(),
            created_unix: 42,
        };
        save_volume(&dir, &v).unwrap();
        let st = load(&dir).unwrap();
        assert_eq!(st.volumes["pgdata"].created_unix, 42);
        remove_volume(&dir, "pgdata").unwrap();
        let st = load(&dir).unwrap();
        assert!(st.volumes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pod_env_volumes_roundtrip_and_legacy() {
        let dir = std::env::temp_dir().join(format!("rustypods-env-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // A minimal legacy conf (pre-Wave-E) must load with env/volumes
        // defaulting to empty.
        let mut pod = PodMeta {
            format: CONF_FORMAT,
            name: "legacy".into(),
            image: "img".into(),
            created_unix: 0,
            limits: Default::default(),
            ephemeral: false,
            storage_max_bytes: 0,
            ports: vec![],
            stack: String::new(),
            net_index: 0,
            binds: vec![],
            private_users: false,
            snap_keep_last: 0,
            snap_max_age_secs: 0,
            autostart: false,
            cmd: vec![],
            started: false,
            stopped_by_user: false,
            stop_timeout_secs: 0,
            ingress: vec![],
            ingress_gateway: false,
            restart: String::new(),
            healthcheck: Default::default(),
            env: vec!["A=1".into(), "B=two=parts".into()],
            volumes: vec!["data:/data".into(), "cfg:/etc/app:ro".into()],
            host_access: false,
            isolated: false,
            allow_setuid: false,
        };
        save_pod(&dir, &pod).unwrap();
        let st = load(&dir).unwrap();
        let m = &st.pods["legacy"];
        assert_eq!(m.env, pod.env);
        assert_eq!(m.volumes, pod.volumes);
        // Bad env / bad volume specs in a hand-edited conf are rejected
        // by the boot-time scan too.
        let bad = PodMeta {
            format: CONF_FORMAT,
            env: vec!["NOEQ".into()],
            ..pod.clone()
        };
        save_pod(&dir, &bad).unwrap();
        let st = load(&dir).unwrap();
        assert!(st.pods.is_empty(), "invalid env must be skipped");
        // A true pre-Wave-E conf — no env=/volumes= keys at all — loads
        // with both defaulting empty (serde defaults).
        save_pod(&dir, &pod).unwrap();
        std::fs::write(
            pod_conf(&dir, "old"),
            "name = \"old\"\nimage = \"img\"\ncreated_unix = 1\n",
        )
        .unwrap();
        let st = load(&dir).unwrap();
        assert!(st.pods["old"].env.is_empty());
        assert!(st.pods["old"].volumes.is_empty());
        assert!(!st.pods["old"].stopped_by_user);
        pod.stopped_by_user = true;
        save_pod(&dir, &pod).unwrap();
        let st = load(&dir).unwrap();
        assert!(st.pods["legacy"].stopped_by_user);
        assert_eq!(st.pods["old"].stop_timeout_secs, DEFAULT_STOP_TIMEOUT_SECS);
        assert_eq!(stop_grace(0).as_secs(), 8);
        assert_eq!(stop_grace(30).as_secs(), 30);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn meta(name: &str, host: &str) -> PodMeta {
        PodMeta {
            format: CONF_FORMAT,
            name: name.into(),
            image: "img".into(),
            created_unix: 0,
            limits: LimitsSpec::default(),
            ephemeral: false,
            private_users: true,
            started: false,
            stopped_by_user: false,
            stop_timeout_secs: 0,
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
            restart: String::new(),
            healthcheck: Default::default(),
            env: vec![],
            volumes: vec![],
            host_access: false,
            isolated: false,
            allow_setuid: false,
        }
    }

    /// restart + healthcheck survive a save→load roundtrip, and confs
    /// written before the fields existed still load with defaults.
    #[test]
    fn health_and_restart_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rp-health-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut m = meta("hc", "hc.rustypods.localhost");
        m.restart = "always".into();
        m.healthcheck = HealthSpec {
            kind: "http".into(),
            target: "/healthz".into(),
            argv: vec![],
            interval_secs: 15,
            timeout_secs: 2,
            retries: 5,
            user: String::new(),
        };
        save_pod(&dir, &m).unwrap();
        let back = load_pod(&dir, "hc").unwrap();
        assert_eq!(back.restart, "always");
        assert_eq!(back.healthcheck.kind, "http");
        assert_eq!(back.healthcheck.target, "/healthz");
        assert_eq!(back.healthcheck.interval_secs, 15);
        assert_eq!(back.healthcheck.retries, 5);
        // A pre-Wave-D conf (no restart/healthcheck keys) loads as "".
        let legacy = dir.join("conf").join("pods").join("legacy.conf");
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        std::fs::write(
            &legacy,
            "name = 'legacy'\nimage = 'img'\ncreated_unix = 0\n",
        )
        .unwrap();
        let old = load_pod(&dir, "legacy").unwrap();
        assert_eq!(old.restart, "");
        assert_eq!(old.healthcheck.kind, "");
        // A [healthcheck] table written before `user` existed loads with
        // "" (→ probe identity chosen by userns mode), and an explicit
        // user round-trips.
        let pre_user = dir.join("conf").join("pods").join("preuser.conf");
        std::fs::write(
            &pre_user,
            "name = 'preuser'\nimage = 'img'\ncreated_unix = 0\n\
             [healthcheck]\nkind = 'exec'\nargv = ['true']\n",
        )
        .unwrap();
        let pu = load_pod(&dir, "preuser").unwrap();
        assert_eq!(pu.healthcheck.kind, "exec");
        assert_eq!(pu.healthcheck.user, "");
        m.healthcheck.user = "nobody".into();
        save_pod(&dir, &m).unwrap();
        assert_eq!(load_pod(&dir, "hc").unwrap().healthcheck.user, "nobody");
        let _ = std::fs::remove_dir_all(&dir);
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
        let st = load(&dir).expect("collision quarantines, does not abort");
        assert!(st.pods.contains_key("a"));
        assert!(!st.pods.contains_key("b"));
        assert!(st.quarantined.iter().any(|q| q.name == "b"));
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
        let st = load(&dir).unwrap();
        assert!(st.pods.contains_key("rustypods-ingress"));
        assert!(
            !st.pods.contains_key("evil"),
            "wrong-name gateway is quarantined"
        );
        std::fs::remove_file(dir.join("conf/pods/evil.conf")).unwrap();

        // Reserved name without the flag → quarantine, daemon still loads.
        let mut squatter = meta("rustypods-ingress", "");
        squatter.ingress.clear();
        save_pod(&dir, &squatter).unwrap();
        let st = load(&dir).unwrap();
        assert!(!st.pods.contains_key("rustypods-ingress"));
        assert!(st.quarantined.iter().any(|q| q.name == "rustypods-ingress"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mesh_conf_roundtrip_and_mode() {
        let dir = std::env::temp_dir().join(format!("rp-mesh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Absent file → None (mesh never initialized).
        assert!(load_mesh(&dir).unwrap().is_none());
        let conf = MeshConf {
            format: CONF_FORMAT,
            private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            listen_port: 51820,
            cluster_token: "deadbeef".into(),
            cluster_token_prev: "prevtoken".into(),
            peers: vec![MeshPeerConf {
                endpoint: "192.0.2.1:51820".into(),
                pubkey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".into(),
                name: Some("s2".into()),
            }],
        };
        save_mesh(&dir, &conf).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("conf/mesh.conf"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "mesh.conf holds a private key");
        let raw = std::fs::read_to_string(dir.join("conf/mesh.conf")).unwrap();
        assert!(
            raw.contains("format = 3"),
            "mesh save must stamp format 3, got {raw}"
        );
        assert!(raw.contains("deadbeef"));
        assert!(raw.contains("prevtoken"));
        assert!(raw.contains("name = \"s2\""));
        let back = load_mesh(&dir).unwrap().unwrap();
        assert_eq!(back.format, MESH_CONF_FORMAT);
        assert_eq!(back.private_key, conf.private_key);
        assert_eq!(back.cluster_token, "deadbeef");
        assert_eq!(back.cluster_token_prev, "prevtoken");
        assert_eq!(back.peers.len(), 1);
        assert_eq!(back.peers[0].endpoint, "192.0.2.1:51820");
        assert_eq!(back.peers[0].name.as_deref(), Some("s2"));
        // Format 2 has no grace token. It still loads; the field defaults empty.
        let legacy = "format = 2\nprivate_key = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\ncluster_token = \"old\"\nlisten_port = 51820\npeers = []\n";
        std::fs::write(dir.join("conf/mesh.conf"), legacy).unwrap();
        let legacy_conf = load_mesh(&dir).unwrap().unwrap();
        assert_eq!(legacy_conf.cluster_token, "old");
        assert!(legacy_conf.cluster_token_prev.is_empty());
        // A file this binary does not understand stays byte-for-byte.
        let future = "format = 9\nprivate_key = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\ncluster_token = \"keep-me\"\n";
        std::fs::write(dir.join("conf/mesh.conf"), future).unwrap();
        let err = save_mesh(&dir, &conf).unwrap_err();
        assert!(err.to_string().contains("refusing to overwrite"), "{err:#}");
        let kept = std::fs::read_to_string(dir.join("conf/mesh.conf")).unwrap();
        assert!(kept.contains("keep-me"));
        assert!(kept.contains("format = 9"));
        std::fs::write(dir.join("conf/mesh.conf"), &raw).unwrap();
        // Empty key = uninitialized even if the file exists.
        save_mesh(&dir, &MeshConf::default()).unwrap();
        assert!(load_mesh(&dir).unwrap().is_none());
        // Debug must not leak the private key.
        let shown = format!("{:?}", conf);
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains(&conf.private_key));
        assert!(!shown.contains(&conf.cluster_token));
        assert!(!shown.contains(&conf.cluster_token_prev));
        // A truncated file is an error, not "uninitialized".
        std::fs::write(dir.join("conf/mesh.conf"), "private_key = \"abc\n").unwrap();
        let err = load_mesh(&dir).unwrap_err();
        assert!(err.to_string().contains("corrupt"), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_defaults_explicit_override_and_newer_format_is_readonly() {
        std::env::set_var("RUSTYPODS_DEFAULT_MEMORY_MAX", "64M");
        std::env::set_var("RUSTYPODS_DEFAULT_CPU", "50%");
        let d = LimitsSpec::default().with_create_defaults().unwrap();
        assert_eq!(d.tasks_max, DEFAULT_TASKS_MAX);
        assert_eq!(d.memory_max_bytes, 64 << 20);
        assert_eq!(d.cpu_quota_percent, 50);
        let custom = LimitsSpec {
            memory_max_bytes: 1,
            cpu_quota_percent: 10,
            tasks_max: 3,
            ..LimitsSpec::default()
        }
        .with_create_defaults()
        .unwrap();
        assert_eq!(custom.memory_max_bytes, 1);
        assert_eq!(custom.cpu_quota_percent, 10);
        assert_eq!(custom.tasks_max, 3);
        std::env::remove_var("RUSTYPODS_DEFAULT_MEMORY_MAX");
        std::env::remove_var("RUSTYPODS_DEFAULT_CPU");
        let bare = LimitsSpec::default().with_create_defaults().unwrap();
        assert_eq!(bare.tasks_max, DEFAULT_TASKS_MAX);
        assert_eq!(bare.memory_max_bytes, 0);
        assert_eq!(bare.cpu_quota_percent, 0);

        let dir = std::env::temp_dir().join(format!("rp-fmt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(pods_conf_dir(&dir)).unwrap();
        std::fs::write(
            pod_conf(&dir, "old"),
            "name = \"old\"\nimage = \"img\"\ncreated_unix = 1\n",
        )
        .unwrap();
        let st = load(&dir).unwrap();
        assert_eq!(st.pods["old"].format, CONF_FORMAT);
        assert_eq!(st.pods["old"].limits.tasks_max, 0);
        std::fs::write(
            pod_conf(&dir, "new"),
            "format = 9\nname = \"new\"\nimage = \"img\"\ncreated_unix = 1\nextra_future = true\n",
        )
        .unwrap();
        let st = load(&dir).unwrap();
        assert_eq!(st.pods["new"].format, 9);
        let err = save_pod(&dir, &st.pods["new"]).unwrap_err();
        assert!(err.to_string().contains("refusing to overwrite"), "{err:#}");
        let raw = std::fs::read_to_string(pod_conf(&dir, "new")).unwrap();
        assert!(raw.contains("extra_future"));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(pods_conf_dir(&dir))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rootfs_reconcile_restores_rollback_and_quarantines_orphans() {
        let conf = ["web".to_string(), "ghost".to_string()]
            .into_iter()
            .collect();
        let entries = vec![
            "web.rollback-old".into(),
            "web.rollback-new".into(),
            "db".into(),
            ".import-abc".into(),
            ".export-xyz".into(),
        ];
        let actions = plan_rootfs_reconcile(&entries, &conf);
        assert!(actions.iter().any(|a| matches!(
            a,
            RootfsAction::Rename { from, to }
                if from == "web.rollback-old" && to == "web"
        )));
        assert!(actions.iter().any(|a| matches!(
            a,
            RootfsAction::Delete { name } if name == "web.rollback-new"
        )));
        assert!(actions.iter().any(|a| matches!(
            a,
            RootfsAction::Rename { from, to } if from == "db" && to == "db.orphan"
        )));
        assert!(actions.iter().any(|a| matches!(
            a,
            RootfsAction::Report { message } if message.contains("ghost")
        )));
        assert!(!actions.iter().any(|a| format!("{a:?}").contains("import")));
        assert!(!actions.iter().any(|a| format!("{a:?}").contains("export")));
        // Both the live rootfs and the backup: do not delete the live tree.
        let both = plan_rootfs_reconcile(&["web".into(), "web.rollback-old".into()], &conf);
        assert!(both.iter().any(|a| matches!(
            a,
            RootfsAction::Delete { name } if name == "web.rollback-old"
        )));
        assert!(!both.iter().any(|a| matches!(
            a,
            RootfsAction::Delete { name } if name == "web"
        )));
        let lone = plan_rootfs_reconcile(&["web.rollback-new".into()], &conf);
        assert!(lone.iter().any(|a| matches!(
            a,
            RootfsAction::Report { message } if message.contains("web.rollback-new")
        )));
        assert!(!lone
            .iter()
            .any(|a| matches!(a, RootfsAction::Rename { .. } | RootfsAction::Delete { .. })));
    }
}
