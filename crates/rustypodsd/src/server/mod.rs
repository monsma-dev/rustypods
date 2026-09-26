//! tonic server on a Unix socket. Peer credentials gate access:
//! uid 0 or Config::allowed_uid may mutate; uids in
//! `Config::read_only_uids` may connect for the read RPCs only.
//! Everyone else is dropped. Mutating calls are appended to `audit.log`.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::{Command as SyncCommand, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::{transport::Server, Request, Response, Status};

use rustypods_proto::rpc::pod_control_server::{PodControl, PodControlServer};
use rustypods_proto::rpc::*;
use rustypods_proto::{self as proto};

use crate::agent::{self, ListenerMap, MetricsMap};
use crate::oci;
use crate::runtime::{RuntimeEngine, StartSpec};
use crate::state::{self, ImageMeta, IngressSpec, LimitsSpec, PodMeta, State, VolumeMeta};
use crate::storage::StorageDriver;
use crate::{ingress, mesh, net, pki, runtime, storage, transfer, Config};

mod access;
mod svc;
use svc::transfer::import_distrobox;

/// (generation, routes) last committed to the ingress gateway.
type IngressPush = (u64, Vec<ActiveIngressRoute>);

/// Cluster-plane listener state: stop signal + task handle.
type MeshRpcStop = Arc<
    std::sync::Mutex<
        Option<(
            tokio::sync::watch::Sender<bool>,
            tokio::task::JoinHandle<()>,
        )>,
    >,
>;

#[derive(Clone)]
pub struct Svc {
    cfg: Config,
    st: Arc<Mutex<State>>,
    metrics: MetricsMap,
    listeners: ListenerMap,
    /// How pods are booted/stopped — systemd-nspawn+machined today; the
    /// trait leaves room for an OCI runtime on systemd-less systems.
    engine: Arc<dyn RuntimeEngine>,
    /// How rootfs trees are cloned/capped — btrfs CoW or reflink fallback.
    storage: Arc<dyn StorageDriver>,
    /// Per-pod op serializer: start/stop/destroy/commit/clone/rollback and
    /// stack member ops must never interleave on the same pod name. A slot
    /// is removed only when its Arc is unreferenced, so a waiter cannot
    /// race a new caller on a freshly inserted mutex.
    ops: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    /// Mutating RPCs in flight. Shutdown waits for this to hit zero.
    inflight: Arc<Inflight>,
    /// Monotonic snapshot counter handed to the ingress gateway — the ACK
    /// must echo it back so a stale push can never look applied.
    ingress_generation: Arc<AtomicU64>,
    /// Serializes snapshot BUILD+PUSH+ACK: every push opens its own UDS
    /// connection, so two concurrent pushes could be reordered on the
    /// wire — a stale snapshot landing after a newer one would resurrect
    /// a route whose net_index was already freed. Holding this mutex
    /// across build+push makes every applied snapshot reflect state at
    /// push time; the gateway itself accepts any generation (a daemon
    /// restart resets the counter).
    ingress_mu: Arc<Mutex<()>>,
    /// Last periodic-reconcile error string — identical failures are logged
    /// once, recovery once, instead of every 2s tick.
    ingress_last_err: Arc<Mutex<Option<String>>>,
    /// Last successfully-pushed (generation, routes): lets steady-state
    /// syncs verify the gateway still holds our table via a cheap
    /// GetStatus instead of committing an identical snapshot every 2s
    /// (each commit logs on the dataplane). `None` after daemon restart
    /// always forces a push — clearing whatever the gateway kept.
    ingress_last_push: Arc<Mutex<Option<IngressPush>>>,
    /// Per-pod supervisor state for liveness probes and restarts.
    /// Entries exist only while a pod is under supervision (running
    /// with a restart policy or a configured probe).
    health: Arc<Mutex<HashMap<String, PodHealth>>>,
    /// Wave I mesh: None until `mesh init`/startup-restore, Some while
    /// up, back to None after `mesh deinit`. std RwLock — mesh_prefix
    /// feeds the sync to_pod path, so a tokio lock won't do.
    mesh: Arc<std::sync::RwLock<Option<Arc<mesh::Mesh>>>>,
    /// The cluster-plane listener's stop signal + task handle — the
    /// handle lets `stop` wait for the port to free up and lets `spawn`
    /// respawn if the task died.
    mesh_rpc_stop: MeshRpcStop,
    /// Serializes mesh_up vs mesh_down — a racing pair could otherwise
    /// delete a fresh conf or have the old teardown kill the new TUN.
    mesh_lifecycle: Arc<Mutex<()>>,
    /// In-memory mirror of `PodMeta.stopped_by_user`, set before the conf
    /// write so a racing supervisor tick cannot restart a pod mid-stop.
    /// The conf is the source of truth across daemon restarts.
    stop_intent: Arc<Mutex<BTreeSet<String>>>,
}

/// Supervisor bookkeeping for one pod. `status` is surfaced on Pod as
/// "starting" | "healthy" | "unhealthy" | "dead".
struct PodHealth {
    status: &'static str,
    fails: u32,
    last_probe: std::time::Instant,
    /// Exponential restart backoff: 2^n seconds, capped at 60s, counted
    /// by restart_count. Reset when the pod stays healthy ≥60s.
    restart_count: u32,
    backoff_until: Option<std::time::Instant>,
    /// When the pod last passed a probe or was freshly started — used
    /// to decay restart_count after stability.
    healthy_since: std::time::Instant,
}

/// Hard cap on a single SHM segment — the file lives on /dev/shm (tmpfs),
/// so an unbounded set_len is a RAM DoS.
const SHM_MAX_BYTES: u64 = 4 << 30;
/// How many pods the supervisor may probe or restart at once.
const SUPERVISE_PARALLEL: usize = 8;

/// Count of detached mutating RPCs. Dropping the handler future (client
/// gone, tonic timeout) must not cancel the task that holds the guard.
struct Inflight {
    n: std::sync::atomic::AtomicUsize,
    notify: tokio::sync::Notify,
}

struct InflightGuard {
    inner: Arc<Inflight>,
}

impl Inflight {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            n: std::sync::atomic::AtomicUsize::new(0),
            notify: tokio::sync::Notify::new(),
        })
    }

    fn enter(self: &Arc<Self>) -> InflightGuard {
        self.n.fetch_add(1, Ordering::SeqCst);
        InflightGuard {
            inner: Arc::clone(self),
        }
    }

    async fn drained(&self) {
        loop {
            // Register before checking: notify_waiters() only wakes
            // already-registered waiters, so a guard dropping between the
            // check and the await would otherwise be missed.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.n.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.inner.n.fetch_sub(1, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }
}

/// Run `fut` on a task that outlives the RPC handler. The handler awaits
/// the join; if tonic drops the handler, the task keeps running and
/// shutdown waits for it (bounded).
async fn drive<T: Send + 'static>(
    inflight: &Arc<Inflight>,
    fut: impl std::future::Future<Output = Result<T, Status>> + Send + 'static,
) -> Result<T, Status> {
    let inflight = Arc::clone(inflight);
    let handle = tokio::spawn(async move {
        let _guard = inflight.enter();
        fut.await
    });
    match handle.await {
        Ok(r) => r,
        Err(e) => Err(Status::internal(format!("operation task ended: {e}"))),
    }
}

/// Critical background task: a panic or a clean return exits the process
/// so systemd restarts the daemon. Pods are nspawn children and survive.
fn spawn_critical<F>(name: &'static str, fut: F) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let name = name;
        let result = tokio::spawn(fut).await;
        match result {
            Ok(()) => tracing::error!("{name} exited"),
            Err(e) => tracing::error!("{name} panicked: {e}"),
        }
        std::process::exit(1);
    })
}

/// Non-critical loop: log and restart with exponential backoff.
fn spawn_restarting<F, Fut>(name: &'static str, mut make: F)
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut delay = 1u64;
        loop {
            let result = tokio::spawn(make()).await;
            match result {
                Ok(()) => tracing::error!("{name} exited; restarting"),
                Err(e) => tracing::error!("{name} panicked: {e}; restarting"),
            }
            tokio::time::sleep(Duration::from_secs(delay)).await;
            delay = (delay * 2).min(30);
        }
    });
}

/// Atomically swap two directory entries on the same mount.
/// `RENAME_EXCHANGE` is the only way a crash cannot observe "neither
/// name exists". Returns the raw io error so the caller can fall back.
pub(crate) fn exchange_rename(a: &Path, b: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let ca = CString::new(a.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let cb = CString::new(b.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: both pointers are NUL-terminated CStrings live for the call.
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            ca.as_ptr(),
            libc::AT_FDCWD,
            cb.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn bad(e: impl Into<anyhow::Error>) -> Status {
    Status::invalid_argument(format!("{:#}", e.into()))
}
fn int(e: impl Into<anyhow::Error>) -> Status {
    Status::internal(format!("{:#}", e.into()))
}

fn to_image(m: &ImageMeta, path: &Path) -> Image {
    Image {
        name: m.name.clone(),
        path: path.display().to_string(),
        source: m.source.clone(),
        created_unix: m.created_unix,
        entrypoint: m.entrypoint.clone(),
        cmd: m.cmd.clone(),
    }
}

fn to_pod(
    m: &PodMeta,
    rootfs: &Path,
    leader: Option<u32>,
    health: &str,
    mesh_prefix: Option<std::net::Ipv6Addr>,
) -> Pod {
    Pod {
        name: m.name.clone(),
        image: m.image.clone(),
        rootfs: rootfs.display().to_string(),
        state: if leader.is_some() {
            PodState::Running
        } else if m.started {
            PodState::Stopped
        } else {
            PodState::Created
        } as i32,
        leader_pid: leader.unwrap_or(0),
        created_unix: m.created_unix,
        limits: Some(Limits {
            memory_high_bytes: m.limits.memory_high_bytes,
            memory_max_bytes: m.limits.memory_max_bytes,
            cpu_quota_percent: m.limits.cpu_quota_percent,
        }),
        ephemeral: m.ephemeral,
        storage_max_bytes: m.storage_max_bytes,
        ports: m.ports.clone(),
        stack: m.stack.clone(),
        binds: m.binds.clone(),
        private_users: m.private_users,
        snap_keep_last: m.snap_keep_last,
        snap_max_age_secs: m.snap_max_age_secs,
        autostart: m.autostart,
        cmd: m.cmd.clone(),
        ingress: ingress_to_proto(&m.ingress),
        ingress_gateway: m.ingress_gateway,
        health: health.into(),
        restart: m.restart.clone(),
        volumes: volumes_to_proto(&m.volumes),
        env: m.env.clone(),
        // Derived, never persisted: mesh addr follows host prefix + idx.
        mesh_ip: match (mesh_prefix, m.net_index) {
            (Some(p), idx) if idx > 0 => mesh::mesh_ip(p, idx).to_string(),
            _ => String::new(),
        },
        notes: Vec::new(),
        allow_setuid: m.allow_setuid,
    }
}

/// Persisted "name:/path[:ro]" specs → proto mounts. Specs reaching here
/// were validated at write/reload time; unparseable hand edits drop out
/// rather than fail the whole pod view.
fn volumes_to_proto(specs: &[String]) -> Vec<VolumeMount> {
    specs
        .iter()
        .filter_map(|s| proto::parse_volume_spec(s).ok())
        .map(|v| VolumeMount {
            name: v.name,
            target: v.target,
            ro: v.ro,
        })
        .collect()
}

/// Captured output of a finished non-tty exec (REST exec endpoint).
/// Output is lossy UTF-8; each stream caps at max_bytes — further
/// bytes are dropped and `truncated` flips.
#[derive(Debug, Default)]
pub(crate) struct ExecOutcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub truncated: bool,
}

impl ExecOutcome {
    fn push_stdout(&mut self, b: Vec<u8>, max: usize) {
        push_capped(&mut self.stdout, b, max, &mut self.truncated);
    }
    fn push_stderr(&mut self, b: Vec<u8>, max: usize) {
        push_capped(&mut self.stderr, b, max, &mut self.truncated);
    }
}

fn push_capped(buf: &mut Vec<u8>, b: Vec<u8>, max: usize, truncated: &mut bool) {
    let room = max.saturating_sub(buf.len());
    if room >= b.len() {
        buf.extend_from_slice(&b);
    } else {
        buf.extend_from_slice(&b[..room]);
        *truncated = true;
    }
}

/// Remove an export/import staging dir: each entry may be a btrfs
/// subvolume, so they go through the storage driver, then the dir.
async fn clean_staging(dir: &Path, storage: &Arc<dyn StorageDriver>) {
    let storage = storage.clone();
    let dir = dir.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || clean_staging_sync(&dir, storage.as_ref())).await;
}

fn clean_staging_sync(dir: &Path, storage: &dyn StorageDriver) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let _ = storage.delete_rootfs(&e.path());
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Deletes the staging dir on drop unless disarmed after a successful commit.
/// Drop only enqueues the path: a Btrfs subvolume walk must not run on the
/// tokio worker that is tearing the request down.
struct StagingGuard {
    dir: PathBuf,
    storage: Arc<dyn StorageDriver>,
    armed: bool,
}

struct StagingJob {
    dir: PathBuf,
    storage: Arc<dyn StorageDriver>,
}

fn enqueue_staging(dir: PathBuf, storage: Arc<dyn StorageDriver>) {
    use std::sync::mpsc::{sync_channel, TrySendError};
    use std::sync::OnceLock;
    static TX: OnceLock<std::sync::mpsc::SyncSender<StagingJob>> = OnceLock::new();
    let tx = TX.get_or_init(|| {
        let (tx, rx) = sync_channel::<StagingJob>(32);
        std::thread::spawn(move || {
            while let Ok(job) = rx.recv() {
                clean_staging_sync(&job.dir, job.storage.as_ref());
            }
        });
        tx
    });
    match tx.try_send(StagingJob { dir, storage }) {
        Ok(()) => {}
        Err(TrySendError::Full(job) | TrySendError::Disconnected(job)) => {
            std::thread::spawn(move || clean_staging_sync(&job.dir, job.storage.as_ref()));
        }
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        enqueue_staging(std::mem::take(&mut self.dir), Arc::clone(&self.storage));
    }
}

/// Writes `0` back to cgroup.freeze, retrying. A failed unfreeze is logged
/// at error — the pod would otherwise stay paused with no signal.
struct FreezeGuard {
    path: Option<PathBuf>,
}

impl Drop for FreezeGuard {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else {
            return;
        };
        if !transfer::unfreeze_cgroup(&path, 5) {
            tracing::error!(
                "FAILED to unfreeze {} after export — pod may stay frozen; write 0 to that cgroup.freeze file",
                path.display()
            );
        }
    }
}

fn ingress_to_proto(specs: &[IngressSpec]) -> Vec<IngressRule> {
    specs
        .iter()
        .map(|i| IngressRule {
            host: i.host.clone(),
            pod_port: i.pod_port as u32,
        })
        .collect()
}

fn ingress_from_proto(rules: &[IngressRule]) -> Vec<IngressSpec> {
    rules
        .iter()
        .map(|r| IngressSpec {
            host: r.host.clone(),
            pod_port: r.pod_port as u16,
        })
        .collect()
}

/// Payload (non-boot) pods: a conf-level cmd override always wins and
/// forces payload mode even on boot-capable images; otherwise an OCI
/// image's recorded entrypoint/cmd decides.
fn is_payload_pod(st: &State, m: &PodMeta) -> bool {
    !m.cmd.is_empty()
        || st
            .images
            .get(&m.image)
            .map(|im| !im.entrypoint.is_empty() || !im.cmd.is_empty())
            .unwrap_or(false)
}

fn limits_from(l: Option<Limits>) -> LimitsSpec {
    l.map(|l| LimitsSpec {
        memory_high_bytes: l.memory_high_bytes,
        memory_max_bytes: l.memory_max_bytes,
        cpu_quota_percent: l.cpu_quota_percent,
        tasks_max: 0,
    })
    .unwrap_or_default()
}

/// rpc::HealthCheck → persisted HealthSpec, validating first so a
/// malformed probe can never reach the conf. "none" normalizes to "".
fn health_from_proto(h: &HealthCheck) -> Result<state::HealthSpec> {
    proto::validate_healthcheck(h)?;
    let kind = if h.kind == "none" {
        ""
    } else {
        h.kind.as_str()
    };
    Ok(state::HealthSpec {
        kind: kind.into(),
        target: h.target.trim().into(),
        argv: h.argv.clone(),
        interval_secs: h.interval_secs,
        timeout_secs: h.timeout_secs,
        retries: h.retries,
        // Not on the wire yet — conf-only; config updates carry it over.
        user: String::new(),
    })
}

/// Effective restart policy: "" normalizes to "no"; the managed gateway
/// is always "always" regardless of what its conf says.
fn restart_policy(m: &PodMeta) -> &str {
    if m.ingress_gateway {
        return "always";
    }
    match m.restart.as_str() {
        "on-failure" | "always" => m.restart.as_str(),
        _ => "no",
    }
}

/// Pods the supervisor watches: explicit restart policy, a configured
/// probe, or the managed gateway.
fn supervised(m: &PodMeta) -> bool {
    restart_policy(m) != "no" || !m.healthcheck.kind.is_empty()
}

/// Death-watch stays idle when the pod was never started, or the user
/// stopped it. `stop_intent` covers the window before the conf write is
/// visible to a tick that already cloned its meta. A crash or a daemon
/// restart with `stopped_by_user == false` is still a restart candidate.
pub(crate) fn supervisor_idle(started: bool, stopped_by_user: bool, stop_intent: bool) -> bool {
    !started || stopped_by_user || stop_intent
}

/// Pods and quarantined confs whose volume specs mount `name`.
pub(crate) fn volume_refs(st: &State, name: &str) -> Vec<String> {
    let uses = |specs: &[String]| {
        specs.iter().any(|s| {
            proto::parse_volume_spec(s)
                .map(|v| v.name == name)
                .unwrap_or(false)
        })
    };
    let mut out: Vec<String> = st
        .pods
        .values()
        .filter(|m| uses(&m.volumes))
        .map(|m| m.name.clone())
        .collect();
    for q in &st.quarantined {
        if uses(&q.volumes) {
            out.push(q.name.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// True when the map's Arc is the only reference, so removing the slot
/// cannot split a waiter onto a different mutex.
pub(crate) fn op_slot_unreferenced(strong_count: usize) -> bool {
    strong_count <= 1
}

/// ":port" or a bare "port" → the pod's own veth address; "host:port"
/// (numeric) → verbatim. None when the pod has no private-net address
/// to probe.
fn probe_addr(m: &PodMeta, target: &str) -> Option<std::net::SocketAddr> {
    let t = target.trim();
    let bare = t.parse::<u16>().ok().map(|p| format!(":{p}"));
    let t = bare.as_deref().unwrap_or(t);
    match t.strip_prefix(':') {
        Some(p) if m.net_index > 0 => Some((net::pod_ip(m.net_index), p.parse().ok()?).into()),
        Some(_) => None,
        None => t.parse().ok(),
    }
}

/// "hostPort:podPort[/proto]" → (host_port, "tcp"|"udp"). Specs reach here
/// only after proto::validate_port, so both halves parse.
fn host_port_proto(spec: &str) -> (u16, &str) {
    let (ports, proto) = spec.split_once('/').unwrap_or((spec, "tcp"));
    let hp = ports
        .split(':')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (hp, if proto == "udp" { "udp" } else { "tcp" })
}

/// Server-side port policy on top of proto::validate_port's syntax check —
/// these need live state, so they can't live in the pure validator:
/// - host ports below 1024 are privileged — refused;
/// - a host port already bound on the host is refused;
/// - a host port claimed by another pod's conf conflicts. Pods in the same
///   stack share one netns+IP and are skipped (stack::parse dedups inside
///   the stack already).
fn validate_host_ports(
    st: &State,
    self_name: &str,
    self_stack: &str,
    ports: &[String],
) -> Result<(), Status> {
    for spec in ports {
        let (hp, proto) = host_port_proto(spec);
        if hp < 1024 {
            return Err(Status::invalid_argument(format!(
                "host port {hp} in '{spec}' is privileged — pick a port ≥1024"
            )));
        }
        for m in st.pods.values() {
            if m.name == self_name || (!m.stack.is_empty() && m.stack == self_stack) {
                continue;
            }
            for other in &m.ports {
                let (ohp, oproto) = host_port_proto(other);
                if ohp == hp && oproto == proto {
                    return Err(Status::already_exists(format!(
                        "host port {hp}/{proto} is already published by pod {}",
                        m.name
                    )));
                }
            }
        }
        // "Not in any pod conf" doesn't mean free — something outside
        // rustypods may hold it. A failed bind = unavailable.
        let taken = if proto == "udp" {
            std::net::UdpSocket::bind(("0.0.0.0", hp)).is_err()
        } else {
            std::net::TcpListener::bind(("0.0.0.0", hp)).is_err()
        };
        if taken {
            return Err(Status::already_exists(format!(
                "host port {hp}/{proto} is already in use on the host"
            )));
        }
    }
    Ok(())
}

/// Ingress hostnames are a global namespace: no duplicates inside one
/// request, and no host already claimed by another persisted pod — stopped
/// ones included (their rules survive until config clears them). Call ONLY
/// while holding the state lock, right before the insert/update.
fn validate_ingress_conflicts(
    st: &State,
    pod_name: &str,
    rules: &[IngressRule],
) -> Result<(), Status> {
    validate_ingress_conflicts_excluding(st, pod_name, rules, &std::collections::BTreeSet::new())
}

/// Same as validate_ingress_conflicts, but persisted pods named in
/// `ignore` are skipped — used by apply_stack, whose desired members are
/// all being rewritten atomically (their stale rules must not block a
/// swap) while anything OUTSIDE the desired set still counts as a racer.
fn validate_ingress_conflicts_excluding(
    st: &State,
    pod_name: &str,
    rules: &[IngressRule],
    ignore: &std::collections::BTreeSet<String>,
) -> Result<(), Status> {
    let mut seen = std::collections::BTreeSet::new();
    for r in rules {
        proto::validate_ingress_rule(r).map_err(bad)?;
        if !seen.insert(r.host.as_str()) {
            return Err(Status::invalid_argument(format!(
                "duplicate ingress host '{}' in request",
                r.host
            )));
        }
    }
    for m in st.pods.values() {
        if m.name == pod_name || ignore.contains(&m.name) {
            continue;
        }
        for i in &m.ingress {
            if seen.contains(i.host.as_str()) {
                return Err(Status::already_exists(format!(
                    "ingress host '{}' is already claimed by pod {}",
                    i.host, m.name
                )));
            }
        }
    }
    Ok(())
}

/// Order-insensitive ingress-set equality — rule order in the conf isn't
/// semantically meaningful, so a TOML reshuffle isn't a "change".
fn same_ingress(a: &[IngressSpec], b: &[IngressSpec]) -> bool {
    fn set(v: &[IngressSpec]) -> std::collections::BTreeSet<(&str, u16)> {
        v.iter().map(|i| (i.host.as_str(), i.pod_port)).collect()
    }
    set(a) == set(b)
}

impl Svc {
    fn save_pod(&self, m: &PodMeta) -> Result<()> {
        state::save_pod(&self.cfg.data_dir, m)
    }
    fn save_image(&self, m: &ImageMeta) -> Result<()> {
        state::save_image(&self.cfg.data_dir, m)
    }

    fn pod_rootfs(&self, name: &str) -> std::path::PathBuf {
        self.cfg.pods_dir().join(name)
    }

    /// The `create --desktop` preset: the user's home + /tmp rw, the runtime
    /// dir and GPU ro. Home/uid come from /etc/passwd for cfg.allowed_uid.
    fn desktop_binds(&self) -> Result<Vec<String>, Status> {
        let uid = self.cfg.allowed_uid;
        let passwd = std::fs::read_to_string("/etc/passwd").map_err(int)?;
        let home = passwd.lines().find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 6 && f[2].parse::<u32>().ok() == Some(uid)).then(|| f[5].to_string())
        });
        let Some(home) = home else {
            return Err(Status::failed_precondition(format!(
                "no /etc/passwd entry for uid {uid}"
            )));
        };
        // The whole user runtime dir goes in ro — that already covers
        // $SSH_AUTH_SOCK (unix-socket connect() works through a ro bind;
        // verified live), the session bus, pipewire, etc. On top of that,
        // give the rootless podman socket its own explicit ro bind for
        // containers-in-containers parity with distrobox — skipped when
        // podman.socket isn't running on the host.
        let mut v = vec![home, "/tmp".into(), format!("/run/user/{uid}:ro")];
        let podman_sock = format!("/run/user/{uid}/podman/podman.sock");
        if Path::new(&podman_sock).exists() {
            v.push(format!("{podman_sock}:ro"));
        }
        if Path::new("/dev/dri").exists() {
            v.push("/dev/dri:ro".into());
        }
        Ok(v)
    }

    /// Per-pod op lock, held for the whole duration of a stateful op on
    /// `name`. `stack:<name>` keys serialize stack-level apply/destroy.
    pub(crate) async fn pod_op(&self, name: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let m = {
            let mut ops = self.ops.lock().await;
            ops.entry(name.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        m.lock_owned().await
    }

    /// Limits + storage cap as stored, for a REST PATCH merge. Caller
    /// holds `pod_op` so the snapshot and the following write are one
    /// critical section.
    pub(crate) async fn pod_limit_snapshot(&self, name: &str) -> Option<(Limits, u64)> {
        let st = self.st.lock().await;
        let m = st.pods.get(name)?;
        Some((
            Limits {
                memory_high_bytes: m.limits.memory_high_bytes,
                memory_max_bytes: m.limits.memory_max_bytes,
                cpu_quota_percent: m.limits.cpu_quota_percent,
            },
            m.storage_max_bytes,
        ))
    }

    /// `/healthz`: state lock must be acquirable. A wedged critical
    /// section is an unhealthy daemon even if the process is up.
    pub(crate) async fn http_ready(&self) -> bool {
        if tokio::time::timeout(Duration::from_millis(200), self.st.lock())
            .await
            .is_err()
        {
            return false;
        }
        tokio::time::timeout(Duration::from_millis(200), self.engine.healthy())
            .await
            .unwrap_or(false)
    }

    /// Body of `update_pod_config`. Does not take `pod_op` — the caller
    /// holds it, so a REST read-modify-write can merge under the same lock.
    pub(crate) async fn apply_pod_config(
        &self,
        req: UpdatePodConfigRequest,
    ) -> Result<Pod, Status> {
        let name = proto::validate_name(&req.name).map_err(bad)?.to_string();
        {
            let st = self.st.lock().await;
            if !st.pods.contains_key(&name) {
                return Err(Status::not_found(format!("pod {name} not found")));
            }
        }
        // The gateway's identity is daemon-managed — its cmd, ports,
        // binds, ingress rules and supervision are provisioned by
        // InitIngress and must not be rewritable through the ordinary
        // config path. Resource limits and autostart stay tunable.
        {
            let st = self.st.lock().await;
            if st.pods.get(&name).is_some_and(|m| m.ingress_gateway)
                && (req.ports.is_some()
                    || req.binds.is_some()
                    || req.cmd.is_some()
                    || req.ingress.is_some()
                    || req.restart.is_some()
                    || req.healthcheck.is_some()
                    || req.env.is_some()
                    || req.volumes.is_some())
            {
                return Err(Status::failed_precondition(
                    "the ingress gateway is managed — cmd/ports/binds/ingress/restart/env/volumes are not configurable; re-run `rustypods ingress init`",
                ));
            }
        }
        let lim = limits_from(req.limits);
        if let Some(r) = &req.restart {
            proto::validate_restart(r).map_err(bad)?;
        }
        let new_hc = req
            .healthcheck
            .as_ref()
            .map(health_from_proto)
            .transpose()
            .map_err(bad)?;
        if let Some(el) = &req.env {
            proto::validate_env(&el.entries).map_err(bad)?;
        }
        if let Some(vl) = &req.volumes {
            for spec in &vl.specs {
                proto::parse_volume_spec(spec).map_err(bad)?;
            }
        }
        if let Some(pm) = &req.ports {
            for spec in &pm.ports {
                proto::validate_port(spec).map_err(bad)?;
            }
            let st = self.st.lock().await;
            let stack = st
                .pods
                .get(&name)
                .map(|m| m.stack.clone())
                .unwrap_or_default();
            validate_host_ports(&st, &name, &stack, &pm.ports)?;
        }
        if let Some(bl) = &req.binds {
            for spec in &bl.binds {
                proto::validate_bind(spec).map_err(bad)?;
            }
        }
        if let Some(cl) = &req.cmd {
            if !cl.argv.is_empty() {
                proto::validate_argv(&cl.argv).map_err(bad)?;
            }
        }
        // Ingress changes the pod's private-network identity — applying it
        // to a live pod would split persisted state from runtime state, so
        // it's only accepted on a stopped pod (takes effect next start).
        if req.ingress.is_some() && self.engine.running_pid(&name).await.is_some() {
            return Err(Status::failed_precondition(format!(
                "pod {name} is running — stop the pod before changing ingress"
            )));
        }
        let ports_changed = req.ports.is_some();
        let meta = {
            let mut st = self.st.lock().await;
            // Race-safe ingress policy: global hostname check happens under
            // THIS lock, immediately before the update below.
            if let Some(il) = &req.ingress {
                validate_ingress_conflicts(&st, &name, &il.rules)?;
            }
            let Some(m) = st.pods.get_mut(&name) else {
                return Err(Status::not_found(format!("pod {name} not found")));
            };
            m.limits = lim;
            m.storage_max_bytes = req.storage_max_bytes;
            if let Some(pm) = req.ports {
                m.ports = pm.ports;
            }
            // Applied at the next start, not live.
            if let Some(bl) = req.binds {
                m.binds = bl.binds;
            }
            // Same: payload override takes effect on the next start;
            // present-but-empty clears it.
            if let Some(cl) = req.cmd {
                m.cmd = cl.argv;
            }
            // Ingress: present (even empty) replaces the whole set.
            if let Some(il) = req.ingress {
                m.ingress = ingress_from_proto(&il.rules);
            }
            // Snapshot retention: persisted only — the GC sweep applies it.
            // Absent = keep, 0 clears.
            if let Some(k) = req.snap_keep_last {
                m.snap_keep_last = k;
            }
            if let Some(a) = req.snap_max_age_secs {
                m.snap_max_age_secs = a;
            }
            // Absent = keep the current boot flag.
            if let Some(a) = req.autostart {
                m.autostart = a;
            }
            // Restart policy + probe: applied by the supervisor's next
            // tick — no pod restart needed.
            if let Some(r) = req.restart {
                m.restart = r;
            }
            if let Some(t) = req.stop_timeout_secs {
                if t > 600 {
                    return Err(Status::invalid_argument(
                        "stop_timeout_secs must be 0 (default 8s) or 1..=600",
                    ));
                }
                m.stop_timeout_secs = t;
            }
            if let Some(mut h) = new_hc {
                // healthcheck.user is conf-only — keep it across proto updates.
                h.user = std::mem::take(&mut m.healthcheck.user);
                m.healthcheck = h;
            }
            if let Some(el) = req.env {
                m.env = el.entries;
            }
            if let Some(vl) = req.volumes {
                m.volumes = vl.specs;
            }
            let m = m.clone();
            self.save_pod(&m).map_err(int)?;
            m
        };
        // Volume mounts reference named subvols — create missing ones so
        // `volume ls` reflects the pod's config immediately.
        for spec in &meta.volumes {
            let v = proto::parse_volume_spec(spec).map_err(bad)?;
            self.ensure_volume(&v.name).await.map_err(int)?;
        }
        // Hot-apply while the pod runs — no restart needed.
        if self.engine.running_pid(&name).await.is_some() {
            self.engine
                .apply_limits(&name, &meta.limits)
                .await
                .map_err(int)?;
        }
        self.apply_storage_cap(&meta).await.map_err(int)?;
        if ports_changed {
            if let Err(e) = self.sync_nat().await {
                tracing::warn!("nft rebuild after {name} config failed: {e}");
            }
        }
        let leader = self.engine.running_pid(&name).await;
        Ok(to_pod(
            &meta,
            &self.pod_rootfs(&name),
            leader,
            &self.health_view(&name).await,
            self.mesh_prefix(),
        ))
    }

    /// Non-blocking pod_op — None while another op holds the lock. For GC:
    /// a busy pod is skipped this sweep rather than stalling the loop.
    async fn try_pod_op(&self, name: &str) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let m = {
            let mut ops = self.ops.lock().await;
            ops.entry(name.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        m.try_lock_owned().ok()
    }

    /// Drop an op-lock map entry only when nobody else still holds the
    /// Arc. Removing a referenced mutex lets a waiter and a new caller
    /// run on two different locks for the same name.
    async fn release_op_slot(&self, name: &str) {
        let mut ops = self.ops.lock().await;
        if ops
            .get(name)
            .is_some_and(|m| op_slot_unreferenced(Arc::strong_count(m)))
        {
            ops.remove(name);
        }
    }

    /// Storage/net helpers spawn subprocesses (btrfs, cp, rm, ip, nft) —
    /// never let them block the async executor; hop to the blocking pool.
    async fn blocking<T, F>(f: F) -> Result<T, Status>
    where
        F: FnOnce() -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        tokio::task::spawn_blocking(f)
            .await
            .map_err(|e| int(anyhow::anyhow!("blocking task: {e}")))?
            .map_err(int)
    }

    async fn st_create(&self, path: &Path) -> Result<(), Status> {
        let (s, p) = (self.storage.clone(), path.to_path_buf());
        Self::blocking(move || s.create_rootfs(&p)).await
    }
    async fn st_clone(&self, src: &Path, dst: &Path) -> Result<(), Status> {
        let (s, a, b) = (self.storage.clone(), src.to_path_buf(), dst.to_path_buf());
        Self::blocking(move || s.clone_rootfs(&a, &b)).await
    }
    /// Stop using the pod's configured grace (0 → historical 8s).
    async fn stop_engine(&self, name: &str) -> Result<(), Status> {
        let secs = {
            let st = self.st.lock().await;
            st.pods.get(name).map(|m| m.stop_timeout_secs).unwrap_or(0)
        };
        self.engine
            .stop(name, state::stop_grace(secs))
            .await
            .map_err(int)
    }

    async fn st_delete(&self, path: &Path) -> Result<(), Status> {
        let (s, p) = (self.storage.clone(), path.to_path_buf());
        Self::blocking(move || s.delete_rootfs(&p)).await
    }

    /// Whether the pod exists in persisted state (REST guards).
    pub(crate) async fn pod_exists(&self, name: &str) -> bool {
        self.st.lock().await.pods.contains_key(name)
    }

    /// The pod's live cgroup scope name, if registered and running.
    /// http.rs reads /sys/fs/cgroup/machine.slice/<unit>/ for stats.
    pub(crate) async fn pod_scope(&self, name: &str) -> Option<String> {
        self.engine.scope_name(name).await
    }

    /// Last `lines` log lines — journal for boot pods (same
    /// `journalctl -M` probe as stream_logs), the nspawn console log
    /// otherwise. Returned newest-last. The body is capped at
    /// [`LOG_TAIL_MAX`] so a multi-gigabyte line cannot OOM the daemon;
    /// `truncated` is set when the cap or a per-line cap fired.
    pub(crate) async fn pod_log_tail(&self, name: &str, lines: u32) -> Result<LogTail, Status> {
        if !self.pod_exists(name).await {
            return Err(Status::not_found(format!("pod {name} not found")));
        }
        let boot_pod = {
            let st = self.st.lock().await;
            st.pods.get(name).map(|m| is_payload_pod(&st, m)) == Some(false)
        };
        let n = lines.max(1);
        if boot_pod {
            let has_journal = tokio::process::Command::new("journalctl")
                .args(["-M", name, "-n", "1", "--no-pager"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false);
            if has_journal {
                let mut child = tokio::process::Command::new("journalctl")
                    .args(["-M", name, "-n", &n.to_string(), "-o", "cat", "--no-pager"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .kill_on_drop(true)
                    .spawn()
                    .map_err(int)?;
                let (buf, cut) = read_capped_stdout(&mut child, LOG_TAIL_MAX)
                    .await
                    .map_err(int)?;
                return Ok(split_log_tail(&buf, n as usize, cut));
            }
        }
        let log_path = self.cfg.logs_dir().join(format!("{name}.log"));
        match tokio::task::spawn_blocking(move || read_log_tail_file(&log_path, n as usize)).await {
            Ok(Ok(t)) => Ok(t),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(LogTail::default()),
            Ok(Err(e)) => Err(int(e)),
            Err(e) => Err(int(e)),
        }
    }

    /// Latest agent-pushed metric for a pod (REST /metrics). None when the
    /// agent never connected — a real sample always has ts_unix_ms > 0.
    pub(crate) async fn latest_metric(&self, pod: &str) -> Option<Metric> {
        self.metrics
            .lock()
            .await
            .get(pod)
            .map(|tx| *tx.borrow())
            .filter(|m| m.ts_unix_ms > 0)
    }

    /// Rebuild the nftables DNAT tables from current state (running pods
    /// only) — strict: an nft failure propagates; callers decide whether
    /// it unwinds a start or only warns on stop paths.
    async fn sync_nat(&self) -> Result<(), Status> {
        let pods: Vec<PodMeta> = {
            let st = self.st.lock().await;
            st.pods.values().cloned().collect()
        };
        let mut running = BTreeSet::new();
        for m in &pods {
            if self.engine.running_pid(&m.name).await.is_some() {
                running.insert(m.name.clone());
            }
        }
        // `nft -f -` is a subprocess — off the executor.
        Self::blocking(move || net::rebuild_nat(pods.iter(), &running)).await
    }
}

#[tonic::async_trait]
impl PodControl for Svc {
    async fn ping(&self, _req: Request<PingRequest>) -> Result<Response<DaemonInfo>, Status> {
        Ok(Response::new(DaemonInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            socket_path: self.cfg.socket.display().to_string(),
            data_dir: self.cfg.data_dir.display().to_string(),
            machined: self.engine.healthy().await,
            btrfs: self.storage.supports_quota(),
            storage_driver: self.storage.name().into(),
            runtime_engine: self.engine.name().into(),
            quarantined: self
                .st
                .lock()
                .await
                .quarantined
                .iter()
                .map(|q| format!("{}: {}", q.name, q.reason))
                .collect(),
        }))
    }

    /// Wave I: create (or reuse) this host's WG identity and bring the
    /// mesh up. Idempotent — calling init on a live mesh just returns
    /// status, and an existing conf/mesh.conf keeps its key so the /48
    /// (and every pod's mesh addr) survives daemon restarts.
    async fn mesh_init(
        &self,
        req: Request<MeshInitRequest>,
    ) -> Result<Response<MeshStatus>, Status> {
        let req = req.into_inner();
        Ok(Response::new(
            self.mesh_up(req.listen_port, &req.token).await?,
        ))
    }

    async fn get_mesh_status(&self, _req: Request<Empty>) -> Result<Response<MeshStatus>, Status> {
        match self.mesh() {
            Some(m) => Ok(Response::new(m.status().await)),
            None => {
                let conf_error = match state::load_mesh(&self.cfg.data_dir) {
                    Err(e) => e.to_string(),
                    Ok(_) => String::new(),
                };
                Ok(Response::new(MeshStatus {
                    enabled: false,
                    conf_error,
                    ..Default::default()
                }))
            }
        }
    }

    async fn mesh_add_peer(&self, req: Request<MeshPeer>) -> Result<Response<MeshStatus>, Status> {
        let p = req.into_inner();
        Ok(Response::new(
            self.apply_mesh_peer(&p.endpoint, &p.pubkey, &p.name)
                .await?,
        ))
    }

    async fn mesh_remove_peer(
        &self,
        req: Request<MeshPeer>,
    ) -> Result<Response<MeshStatus>, Status> {
        let p = req.into_inner();
        Ok(Response::new(self.drop_mesh_peer(&p.pubkey).await?))
    }

    async fn mesh_deinit(&self, _req: Request<Empty>) -> Result<Response<MeshStatus>, Status> {
        Ok(Response::new(self.mesh_down().await?))
    }

    async fn import_image(
        &self,
        req: Request<ImportImageRequest>,
    ) -> Result<Response<Image>, Status> {
        let req = req.into_inner();
        let name = proto::validate_name(&req.name).map_err(bad)?.to_string();
        proto::validate_container_ref(&req.distrobox).map_err(bad)?;
        let dest = self.cfg.images_dir().join(&name);
        if dest.exists() {
            return Err(Status::already_exists(format!(
                "image {name} already exists"
            )));
        }
        // runuser runs the export as this user — the request may only ever
        // name the configured import_user, never root or another account.
        let user = if req.import_user.is_empty() {
            self.cfg.import_user.clone()
        } else if req.import_user == self.cfg.import_user {
            req.import_user.clone()
        } else {
            return Err(Status::invalid_argument(format!(
                "import_user must be '{}' (the daemon's --import-user)",
                self.cfg.import_user
            )));
        };
        proto::validate_unix_user(&user).map_err(bad)?;
        self.st_create(&dest).await?;
        let d = dest.clone();
        let cont = req.distrobox.clone();
        let res = tokio::task::spawn_blocking(move || import_distrobox(&user, &cont, &d)).await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = self.st_delete(&dest).await;
                return Err(int(e));
            }
            Err(je) => {
                let _ = self.st_delete(&dest).await;
                return Err(int(anyhow::anyhow!("task: {je}")));
            }
        }
        sanitize_rootfs(&dest, &req.distrobox).map_err(int)?;
        let meta = ImageMeta {
            format: 1,
            name: name.clone(),
            source: format!("distrobox:{}", req.distrobox),
            created_unix: state::now_unix(),
            entrypoint: vec![],
            cmd: vec![],
            env: vec![],
            working_dir: String::new(),
        };
        let mut st = self.st.lock().await;
        st.images.insert(name.clone(), meta.clone());
        self.save_image(&meta).map_err(int)?;
        Ok(Response::new(to_image(&meta, &dest)))
    }

    /// `rustypods pull <ref>`: native OCI pull — manifest+config+layers
    /// straight from the registry, untarred into a fresh rootfs. Pulled
    /// images carry their entrypoint/cmd and run non-boot (no systemd).
    async fn pull_image(&self, req: Request<PullImageRequest>) -> Result<Response<Image>, Status> {
        let req = req.into_inner();
        let name = if req.name.is_empty() {
            oci::default_name(&req.reference).map_err(bad)?
        } else {
            proto::validate_name(&req.name).map_err(bad)?.to_string()
        };
        let dest = self.cfg.images_dir().join(&name);
        if dest.exists() {
            return Err(Status::already_exists(format!(
                "image {name} already exists"
            )));
        }
        self.st_create(&dest).await?;
        let cfg = match oci::pull(&req.reference, &dest, req.strip_setuid).await {
            Ok(c) => c,
            Err(e) => {
                let _ = self.st_delete(&dest).await;
                return Err(int(e));
            }
        };
        let meta = ImageMeta {
            format: 1,
            name: name.clone(),
            source: format!("oci:{}", req.reference),
            created_unix: state::now_unix(),
            entrypoint: cfg.entrypoint,
            cmd: cfg.cmd,
            env: cfg.env,
            working_dir: cfg.working_dir,
        };
        let mut st = self.st.lock().await;
        st.images.insert(name.clone(), meta.clone());
        self.save_image(&meta).map_err(int)?;
        Ok(Response::new(to_image(&meta, &dest)))
    }

    async fn list_images(
        &self,
        _req: Request<ListImagesRequest>,
    ) -> Result<Response<ImageList>, Status> {
        let st = self.st.lock().await;
        let mut out: Vec<Image> = st
            .images
            .values()
            .map(|m| to_image(m, &self.cfg.images_dir().join(&m.name)))
            .collect();
        // Reconcile: directories on disk the state file doesn't know about.
        if let Ok(rd) = std::fs::read_dir(self.cfg.images_dir()) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if e.path().is_dir() && !st.images.contains_key(&n) {
                    out.push(Image {
                        name: n,
                        path: e.path().display().to_string(),
                        source: "(on-disk)".into(),
                        created_unix: 0,
                        entrypoint: vec![],
                        cmd: vec![],
                    });
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Response::new(ImageList { images: out }))
    }

    async fn remove_image(&self, req: Request<ImageRef>) -> Result<Response<Empty>, Status> {
        let name = proto::validate_name(&req.into_inner().name)
            .map_err(bad)?
            .to_string();
        // Same key create_pod holds across the clone, so a remove cannot
        // delete the tree mid-copy.
        let _img = self.pod_op(&format!("image:{name}")).await;
        {
            let st = self.st.lock().await;
            if st.pods.values().any(|p| p.image == name) {
                return Err(Status::failed_precondition(format!(
                    "image {name} is still in use by a pod"
                )));
            }
        }
        self.st_delete(&self.cfg.images_dir().join(&name)).await?;
        let mut st = self.st.lock().await;
        st.images.remove(&name);
        state::remove_image(&self.cfg.data_dir, &name).map_err(int)?;
        Ok(Response::new(Empty {}))
    }

    async fn create_pod(&self, req: Request<CreatePodRequest>) -> Result<Response<Pod>, Status> {
        let svc = self.clone();
        let inflight = Arc::clone(&self.inflight);
        drive(&inflight, async move { svc.create_pod_work(req).await }).await
    }

    /// `rustypods clone <src> <dest>`: instant btrfs snapshot of the pod
    /// rootfs + a copied conf with fresh identity. Cloning a running pod is
    /// allowed (subvolume snapshot is atomic) but the runtime state is
    /// reset — the clone starts stopped.
    async fn clone_pod(&self, req: Request<ClonePodRequest>) -> Result<Response<Pod>, Status> {
        let svc = self.clone();
        let inflight = Arc::clone(&self.inflight);
        drive(&inflight, async move { svc.clone_pod_work(req).await }).await
    }

    /// `rustypods commit <pod> [label]`: atomic CoW snapshot of the live
    /// rootfs into snapshots/<pod>/<ts>[-label]. The live pod keeps running.
    async fn commit_pod(
        &self,
        req: Request<CommitPodRequest>,
    ) -> Result<Response<Snapshot>, Status> {
        let svc = self.clone();
        let inflight = Arc::clone(&self.inflight);
        drive(&inflight, async move { svc.commit_pod_work(req).await }).await
    }

    /// `rustypods rollback <pod> [--to <id>]`: swap the live rootfs for a
    /// commit. The pod is stopped first — rollback discards current state.
    /// The snapshot itself survives (it becomes the new live rootfs' source).
    async fn rollback_pod(
        &self,
        req: Request<RollbackPodRequest>,
    ) -> Result<Response<Pod>, Status> {
        let svc = self.clone();
        let inflight = Arc::clone(&self.inflight);
        drive(&inflight, async move { svc.rollback_pod_work(req).await }).await
    }

    async fn list_snapshots(&self, req: Request<PodRef>) -> Result<Response<SnapshotList>, Status> {
        let pod = proto::validate_name(&req.into_inner().name)
            .map_err(bad)?
            .to_string();
        {
            let st = self.st.lock().await;
            if !st.pods.contains_key(&pod) {
                return Err(Status::not_found(format!("pod {pod} not found")));
            }
        }
        Ok(Response::new(SnapshotList {
            snapshots: self.snapshots(&pod),
        }))
    }

    async fn delete_snapshot(&self, req: Request<SnapshotRef>) -> Result<Response<Empty>, Status> {
        let req = req.into_inner();
        let pod = proto::validate_name(&req.pod).map_err(bad)?.to_string();
        {
            let st = self.st.lock().await;
            if !st.pods.contains_key(&pod) {
                return Err(Status::not_found(format!("pod {pod} not found")));
            }
        }
        let _op = self.pod_op(&pod).await;
        proto::validate_snapshot_id(&req.id).map_err(bad)?;
        // Guard: the id may only ever resolve inside this pod's snap dir.
        let path = self.snaps_dir(&pod).join(&req.id);
        if !path.starts_with(self.snaps_dir(&pod)) || !path.exists() {
            return Err(Status::not_found(format!(
                "snapshot '{}' not found",
                req.id
            )));
        }
        self.st_delete(&path).await?;
        Ok(Response::new(Empty {}))
    }

    /// `rustypods apply stack.toml`: one shared netns for all members
    /// (they see each other on 127.0.0.1), one /30 + one net_index for the
    /// stack, members stored as pods named <stack>-<member>. Re-applying an
    /// existing stack is idempotent: confs update, rootfs is kept.
    async fn apply_stack(
        &self,
        req: Request<ApplyStackRequest>,
    ) -> Result<Response<ApplyStackResponse>, Status> {
        let svc = self.clone();
        let inflight = Arc::clone(&self.inflight);
        drive(&inflight, async move { svc.apply_stack_work(req).await }).await
    }

    /// `rustypods stack destroy <name>`: stop+delete every member, then
    /// tear down the shared netns and veth pair.
    async fn destroy_stack(&self, req: Request<PodRef>) -> Result<Response<Empty>, Status> {
        let name = proto::validate_name(&req.into_inner().name)
            .map_err(bad)?
            .to_string();
        // Cheap membership check before touching the append-only ops map.
        {
            let st = self.st.lock().await;
            if !st.pods.values().any(|m| m.stack == name) {
                return Err(Status::not_found(format!("stack {name} not found")));
            }
        }
        // Serialize against apply_stack and per-pod ops: take the stack key
        // FIRST — an in-flight apply must finish before we enumerate members
        // (a member added after listing would escape teardown).
        let _stack_op = self.pod_op(&format!("stack:{name}")).await;
        let members: Vec<String> = {
            let st = self.st.lock().await;
            st.pods
                .values()
                .filter(|m| m.stack == name)
                .map(|m| m.name.clone())
                .collect()
        };
        if members.is_empty() {
            return Err(Status::not_found(format!("stack {name} not found")));
        }
        // Every member's op lock too, in sorted order (ordered acquisition).
        let mut sorted = members.clone();
        sorted.sort();
        sorted.dedup();
        let mut _guards = Vec::with_capacity(sorted.len());
        for n in &sorted {
            _guards.push(self.pod_op(n).await);
        }
        for pname in &members {
            self.stop_engine(pname).await?;
            if self.engine.registered(pname).await.map_err(int)? {
                return Err(Status::failed_precondition(format!(
                    "pod {pname} is still registered with machined — refusing to destroy stack"
                )));
            }
            agent::stop_listener(&self.listeners, &self.metrics, pname).await;
            self.st_delete(&self.pod_rootfs(pname)).await?;
            state::remove_pod(&self.cfg.data_dir, pname).map_err(int)?;
            agent::cleanup_pod_dirs(
                &proto::run_dir(&self.cfg.data_dir, pname),
                &proto::shm_host_dir(pname),
            );
            let mut st = self.st.lock().await;
            st.pods.remove(pname);
        }
        let n = name.clone();
        let _ = Self::blocking(move || {
            net::teardown_stack_net(&n);
            Ok(())
        })
        .await;
        if let Err(e) = self.sync_nat().await {
            tracing::warn!("nft rebuild after stack destroy failed: {e}");
        }
        // Members carrying ingress rules are gone — drop their routes
        // promptly instead of waiting for the next reconcile tick (the
        // shared net_index is free for reuse now). Best-effort: an
        // unreachable gateway is healed by the reconciler.
        if let Err(e) = self.sync_ingress(None, false).await {
            tracing::warn!("ingress resync after stack {name} destroy failed: {e}");
        }
        // Evict op-lock entries for the destroyed members and the stack key —
        // the pods are gone, so ops stays bounded by live pod names. Held
        // guards keep working on their (now orphaned) Arc harmlessly.
        self.release_op_slot(&format!("stack:{name}")).await;
        for pname in &members {
            self.release_op_slot(pname).await;
        }
        Ok(Response::new(Empty {}))
    }

    async fn start_pod(&self, req: Request<StartPodRequest>) -> Result<Response<Pod>, Status> {
        let svc = self.clone();
        let inflight = Arc::clone(&self.inflight);
        drive(&inflight, async move { svc.start_pod_work(req).await }).await
    }

    async fn stop_pod(&self, req: Request<PodRef>) -> Result<Response<Pod>, Status> {
        let svc = self.clone();
        let inflight = Arc::clone(&self.inflight);
        drive(&inflight, async move { svc.stop_pod_work(req).await }).await
    }

    async fn list_pods(&self, _req: Request<ListPodsRequest>) -> Result<Response<PodList>, Status> {
        // Clone the metas and DROP the state lock before the machined
        // lookups — a D-Bus await under the global lock stalls every other
        // RPC touching state.
        let pods: Vec<PodMeta> = {
            let st = self.st.lock().await;
            st.pods.values().cloned().collect()
        };
        let hmap: HashMap<String, String> = {
            let h = self.health.lock().await;
            h.iter()
                .map(|(k, v)| (k.clone(), v.status.to_string()))
                .collect()
        };
        let mut out = Vec::new();
        for m in &pods {
            let leader = self.engine.running_pid(&m.name).await;
            // The supervisor keeps its last verdict after a stop; only
            // "dead" (gave up restarting) still means something then.
            let health = hmap
                .get(&m.name)
                .map(String::as_str)
                .filter(|s| leader.is_some() || *s == "dead")
                .unwrap_or("");
            out.push(to_pod(
                m,
                &self.pod_rootfs(&m.name),
                leader,
                health,
                self.mesh_prefix(),
            ));
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Response::new(PodList { pods: out }))
    }

    async fn destroy_pod(&self, req: Request<PodRef>) -> Result<Response<Empty>, Status> {
        let svc = self.clone();
        let inflight = Arc::clone(&self.inflight);
        drive(&inflight, async move { svc.destroy_pod_work(req).await }).await
    }

    /// `rustypods config`: update the conf + live-apply to the scope.
    async fn update_pod_config(
        &self,
        req: Request<UpdatePodConfigRequest>,
    ) -> Result<Response<Pod>, Status> {
        let svc = self.clone();
        let inflight = Arc::clone(&self.inflight);
        drive(
            &inflight,
            async move { svc.update_pod_config_work(req).await },
        )
        .await
    }

    /// `rustypods reload`: reread the conf from disk (hand edits) + apply.
    async fn reload_pod_config(&self, req: Request<PodRef>) -> Result<Response<Pod>, Status> {
        let name = proto::validate_name(&req.into_inner().name)
            .map_err(bad)?
            .to_string();
        {
            let st = self.st.lock().await;
            if !st.pods.contains_key(&name) {
                return Err(Status::not_found(format!("pod {name} not found")));
            }
        }
        let _op = self.pod_op(&name).await;
        let meta = state::load_pod(&self.cfg.data_dir, &name).map_err(int)?;
        // A hand-edited gateway conf must not smuggle in managed-field
        // changes — compare against the running identity and reject drift.
        {
            let st = self.st.lock().await;
            if let Some(cur) = st.pods.get(&name) {
                if cur.ingress_gateway
                    && (!meta.ingress_gateway
                        || meta.image != cur.image
                        || meta.cmd != cur.cmd
                        || !meta.ports.is_empty()
                        || !meta.ingress.is_empty()
                        || !meta.binds.is_empty()
                        || meta.stack != cur.stack
                        || meta.net_index != cur.net_index
                        || meta.private_users != cur.private_users
                        || meta.allow_setuid)
                {
                    return Err(Status::failed_precondition(
                        "the ingress gateway is managed — refusing conf drift on its managed fields",
                    ));
                }
            }
        }
        for spec in &meta.ports {
            proto::validate_port(spec).map_err(bad)?;
        }
        // Ingress changes on a live pod would drift persisted vs runtime
        // state — same rule as `config` (pod_op is held, so the running
        // check can't race a concurrent start).
        let old_ingress = {
            let st = self.st.lock().await;
            st.pods
                .get(&name)
                .map(|m| m.ingress.clone())
                .unwrap_or_default()
        };
        if !same_ingress(&old_ingress, &meta.ingress)
            && self.engine.running_pid(&name).await.is_some()
        {
            return Err(Status::failed_precondition(format!(
                "pod {name} is running — stop the pod before changing ingress"
            )));
        }
        {
            let mut st = self.st.lock().await;
            if !st.pods.contains_key(&name) {
                return Err(Status::not_found(format!("pod {name} not found")));
            }
            validate_host_ports(&st, &name, &meta.stack, &meta.ports)?;
            validate_ingress_conflicts(&st, &name, &ingress_to_proto(&meta.ingress))?;
            st.pods.insert(name.clone(), meta.clone());
        }
        // A hand edit of stopped_by_user must reach the supervisor's
        // in-memory mirror; the conf remains the source of truth.
        if meta.stopped_by_user {
            self.stop_intent.lock().await.insert(name.clone());
        } else {
            self.stop_intent.lock().await.remove(&name);
        }
        if self.engine.running_pid(&name).await.is_some() {
            self.engine
                .apply_limits(&name, &meta.limits)
                .await
                .map_err(int)?;
        }
        self.apply_storage_cap(&meta).await.map_err(int)?;
        let leader = self.engine.running_pid(&name).await;
        Ok(Response::new(to_pod(
            &meta,
            &self.pod_rootfs(&name),
            leader,
            &self.health_view(&name).await,
            self.mesh_prefix(),
        )))
    }

    /// `rustypods ingress init`: provision the managed gateway pod —
    /// local PKI, dataplane binary + leaf cert copied into a rootfs
    /// cloned from the chosen image. Idempotent: a stopped gateway gets
    /// its binary/certs refreshed, a running one is left alone, and a
    /// foreign pod under the reserved name can't exist (load() enforces
    /// the name↔flag invariant).
    async fn init_ingress(
        &self,
        req: Request<InitIngressRequest>,
    ) -> Result<Response<IngressDeployment>, Status> {
        let req = req.into_inner();
        let image = proto::validate_name(&req.image).map_err(bad)?.to_string();
        let img_dir = self.cfg.images_dir().join(&image);
        if !img_dir.is_dir() {
            return Err(Status::not_found(format!("image {image} not found")));
        }
        let _op = self.pod_op(proto::INGRESS_POD).await;
        // Host loopback :80/:443 must be free BEFORE we wire nft
        // redirects — nft never takes a userspace bind, so an existing
        // listener would be hijacked silently.
        Self::blocking(net::check_ingress_ports_free).await?;
        // PKI + trust install are filesystem/crypto work — off-executor.
        let data_dir = self.cfg.data_dir.clone();
        let paths = Self::blocking(move || pki::ensure(&data_dir)).await?;
        let ca_installed = if req.install_ca {
            let p = paths.clone();
            Self::blocking(move || pki::install_host_trust(&p).map(|_| ())).await?;
            true
        } else {
            false
        };
        // The host-built dataplane binary — real file, executable, sane
        // size (never a symlink, never a giant planted blob).
        let bin = self.cfg.bin_dir().join("rustypods-ingress");
        let bin_bytes = Self::blocking(move || {
            let md = std::fs::symlink_metadata(&bin)
                .with_context(|| format!("stat {}", bin.display()))?;
            if !md.file_type().is_file() {
                bail!("{} is not a regular file", bin.display());
            }
            if md.len() == 0 || md.len() > 128 * 1024 * 1024 {
                bail!("{} has an unexpected size ({})", bin.display(), md.len());
            }
            use std::os::unix::fs::PermissionsExt;
            if md.permissions().mode() & 0o111 == 0 {
                bail!("{} is not executable", bin.display());
            }
            std::fs::read(&bin).with_context(|| format!("read {}", bin.display()))
        })
        .await?;
        let tls_crt = Self::blocking({
            let p = paths.tls_crt.clone();
            move || std::fs::read(&p).with_context(|| format!("read {}", p.display()))
        })
        .await?;
        let tls_key = Self::blocking({
            let p = paths.tls_key.clone();
            move || std::fs::read(&p).with_context(|| format!("read {}", p.display()))
        })
        .await?;
        let rootfs = self.pod_rootfs(proto::INGRESS_POD);
        let existing = {
            let st = self.st.lock().await;
            st.pods.get(proto::INGRESS_POD).cloned()
        };
        // Managed identity — InitIngress owns every field that defines
        // WHAT the gateway is; created_unix/net_index/started are
        // preserved across re-inits.
        let managed = |prev: Option<&PodMeta>| PodMeta {
            format: 1,
            name: proto::INGRESS_POD.into(),
            image: image.clone(),
            created_unix: prev.map(|m| m.created_unix).unwrap_or_else(state::now_unix),
            limits: LimitsSpec {
                memory_high_bytes: 256 << 20,
                memory_max_bytes: 512 << 20,
                cpu_quota_percent: 100,
                tasks_max: state::DEFAULT_TASKS_MAX,
            },
            ephemeral: false,
            private_users: true,
            started: prev.map(|m| m.started).unwrap_or(false),
            stopped_by_user: prev.map(|m| m.stopped_by_user).unwrap_or(false),
            stop_timeout_secs: prev.map(|m| m.stop_timeout_secs).unwrap_or(0),
            storage_max_bytes: 0,
            ports: vec![],
            ingress: vec![],
            net_index: prev.map(|m| m.net_index).unwrap_or(0),
            stack: String::new(),
            binds: vec![],
            cmd: vec!["/usr/local/bin/rustypods-ingress".into()],
            snap_keep_last: 0,
            snap_max_age_secs: 0,
            ingress_gateway: true,
            autostart: true,
            restart: "always".into(),
            healthcheck: Default::default(),
            env: vec![],
            volumes: vec![],
            host_access: false,
            isolated: false,
            allow_setuid: false,
        };
        // Copy the dataplane binary + LEAF pair into the rootfs via
        // symlink-safe helpers. The CA key NEVER leaves the host.
        let provision = |rootfs: &Path| {
            let (bin, crt, key) = (bin_bytes.clone(), tls_crt.clone(), tls_key.clone());
            let rootfs = rootfs.to_path_buf();
            async move {
                Self::blocking(move || {
                    crate::rootfs::mkdir_in_rootfs(&rootfs, "usr/local/bin")?;
                    crate::rootfs::mkdir_in_rootfs(&rootfs, "etc/rustypods-ingress")?;
                    crate::rootfs::write_in_rootfs(
                        &rootfs,
                        "usr/local/bin/rustypods-ingress",
                        &bin,
                        Some(0o755),
                    )?;
                    crate::rootfs::write_in_rootfs(
                        &rootfs,
                        "etc/rustypods-ingress/tls.crt",
                        &crt,
                        Some(0o644),
                    )?;
                    crate::rootfs::write_in_rootfs(
                        &rootfs,
                        "etc/rustypods-ingress/tls.key",
                        &key,
                        Some(0o600),
                    )?;
                    Ok(())
                })
                .await?;
                Ok::<(), Status>(())
            }
        };
        let meta = match existing {
            Some(m) => {
                if !m.ingress_gateway {
                    return Err(Status::failed_precondition(format!(
                        "{} exists but is not the managed gateway — refusing to replace it",
                        proto::INGRESS_POD
                    )));
                }
                if m.image != image {
                    return Err(Status::failed_precondition(format!(
                        "ingress gateway is provisioned from image '{}' — destroy it first to switch images",
                        m.image
                    )));
                }
                if self.engine.running_pid(&m.name).await.is_some() {
                    // Running: managed files are in use — return state as
                    // it is; the CLI start-step becomes a no-op. Warn if
                    // the PKI rotated under it: the in-pod leaf is stale
                    // until the next gateway restart.
                    let rf = rootfs.clone();
                    let want = tls_crt.clone();
                    let drift = Self::blocking(move || -> Result<bool> {
                        match crate::rootfs::read_file_in_rootfs(
                            &rf,
                            "etc/rustypods-ingress/tls.crt",
                        )? {
                            Some(p) => Ok(p != want),
                            None => Ok(true),
                        }
                    })
                    .await
                    .unwrap_or(false);
                    if drift {
                        tracing::warn!(
                            "ingress PKI changed while the gateway is running — restart {} to load the current leaf certificate",
                            proto::INGRESS_POD
                        );
                    }
                    m
                } else {
                    // Conf without a rootfs = a partial destroy — the
                    // managed pod has no user data, so re-clone cleanly.
                    if !rootfs.exists() {
                        if let Err(e) = self.st_clone(&img_dir, &rootfs).await {
                            let _ = self.st_delete(&rootfs).await;
                            return Err(e);
                        }
                    }
                    provision(&rootfs).await?;
                    let meta = managed(Some(&m));
                    {
                        let mut st = self.st.lock().await;
                        st.pods.insert(proto::INGRESS_POD.into(), meta.clone());
                    }
                    self.save_pod(&meta).map_err(int)?;
                    meta
                }
            }
            None => {
                // A stray rootfs without conf is a partial init — it's the
                // managed name, so cleaning it is safe.
                if rootfs.exists() {
                    self.st_delete(&rootfs).await?;
                }
                if let Err(e) = self.st_clone(&img_dir, &rootfs).await {
                    let _ = self.st_delete(&rootfs).await;
                    return Err(e);
                }
                if let Err(e) = provision(&rootfs).await {
                    let _ = self.st_delete(&rootfs).await;
                    return Err(e);
                }
                let meta = managed(None);
                {
                    let mut st = self.st.lock().await;
                    st.pods.insert(proto::INGRESS_POD.into(), meta.clone());
                }
                self.save_pod(&meta).map_err(int)?;
                meta
            }
        };
        let leader = self.engine.running_pid(&meta.name).await;
        Ok(Response::new(IngressDeployment {
            pod: Some(to_pod(
                &meta,
                &rootfs,
                leader,
                &self.health_view(&meta.name).await,
                self.mesh_prefix(),
            )),
            ca_cert_path: paths.ca_crt.display().to_string(),
            ca_installed,
        }))
    }

    /// `rustypods ingress status`: gateway shape + dataplane liveness.
    async fn ingress_gateway_status(
        &self,
        _req: Request<IngressGatewayStatusRequest>,
    ) -> Result<Response<IngressGatewayStatusResponse>, Status> {
        let configured = {
            let st = self.st.lock().await;
            st.pods.values().any(|m| m.ingress_gateway)
        };
        let running = configured && self.engine.running_pid(proto::INGRESS_POD).await.is_some();
        let (control_ready, generation, route_count) = if running {
            match ingress::gateway_status(&self.cfg.data_dir).await {
                Ok(s) => (true, s.generation, s.route_count),
                Err(_) => (false, 0, 0),
            }
        } else {
            (false, 0, 0)
        };
        Ok(Response::new(IngressGatewayStatusResponse {
            configured,
            running,
            control_ready,
            generation,
            route_count,
            ca_cert_path: self
                .cfg
                .data_dir
                .join("pki")
                .join("ca.crt")
                .display()
                .to_string(),
        }))
    }

    async fn uninstall_ingress_ca(
        &self,
        _req: Request<Empty>,
    ) -> Result<Response<IngressCaResult>, Status> {
        let dest = Self::blocking(pki::uninstall_host_trust).await?;
        Ok(Response::new(IngressCaResult {
            ca_cert_path: dest.display().to_string(),
            detail: "removed from the host trust store".into(),
        }))
    }

    async fn rotate_ingress_ca(
        &self,
        _req: Request<Empty>,
    ) -> Result<Response<IngressCaResult>, Status> {
        let data = self.cfg.data_dir.clone();
        let paths = Self::blocking(move || pki::rotate(&data)).await?;
        self.install_gateway_leaf().await?;
        Ok(Response::new(IngressCaResult {
            ca_cert_path: paths.ca_crt.display().to_string(),
            detail: "replaced the CA; re-import it into browsers and the host trust store".into(),
        }))
    }

    async fn create_shm(&self, req: Request<ShmRequest>) -> Result<Response<ShmSegment>, Status> {
        let req = req.into_inner();
        let pod = proto::validate_name(&req.pod).map_err(bad)?.to_string();
        let name = proto::validate_name(&req.name).map_err(bad)?.to_string();
        {
            let st = self.st.lock().await;
            if !st.pods.contains_key(&pod) {
                return Err(Status::not_found(format!("pod {pod} not found")));
            }
        }
        if req.size_bytes == 0 || req.size_bytes > SHM_MAX_BYTES {
            return Err(Status::invalid_argument(format!(
                "shm size must be 1..={SHM_MAX_BYTES} bytes"
            )));
        }
        let dir = proto::shm_host_dir(&pod);
        // /dev/shm is world-writable; the pod dir must be a real directory,
        // not a planted symlink, before we create anything inside it.
        match std::fs::symlink_metadata(&dir) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => {
                return Err(Status::failed_precondition(format!(
                    "shm dir {} exists but is not a real directory",
                    dir.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&dir).map_err(int)?;
            }
            Err(e) => return Err(int(e)),
        }
        let path = dir.join(&name);
        // O_NOFOLLOW + create_new: the segment must not exist yet, and a
        // symlink raced into place between the dir check and the open is
        // refused by the kernel (ELOOP). fchmod/fchown act on the open fd —
        // no path re-resolution, no symlink to follow.
        use std::os::unix::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Status::already_exists(format!("shm segment {name} already exists"))
                } else {
                    int(e)
                }
            })?;
        f.set_len(req.size_bytes).map_err(int)?;
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o660))
            .map_err(int)?;
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: fchown on a valid open fd.
            if unsafe { libc::fchown(f.as_raw_fd(), self.cfg.allowed_uid, self.cfg.allowed_uid) }
                != 0
            {
                tracing::warn!(
                    "fchown {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                );
            }
        }
        Ok(Response::new(ShmSegment {
            name: name.clone(),
            host_path: path.display().to_string(),
            pod_path: format!("{}/{name}", proto::POD_SHM_DIR),
            size_bytes: req.size_bytes,
        }))
    }

    async fn list_shm(&self, req: Request<PodRef>) -> Result<Response<ShmList>, Status> {
        let pod = proto::validate_name(&req.into_inner().name)
            .map_err(bad)?
            .to_string();
        let dir = proto::shm_host_dir(&pod);
        let mut segs = Vec::new();
        // Only list a real directory — never enumerate through a symlink.
        let real_dir = std::fs::symlink_metadata(&dir)
            .map(|m| m.is_dir())
            .unwrap_or(false);
        if real_dir {
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    // symlink_metadata: report the entry itself, don't stat
                    // through planted symlinks.
                    if let Ok(md) = std::fs::symlink_metadata(e.path()) {
                        let name = e.file_name().to_string_lossy().into_owned();
                        segs.push(ShmSegment {
                            pod_path: format!("{}/{name}", proto::POD_SHM_DIR),
                            host_path: e.path().display().to_string(),
                            size_bytes: md.len(),
                            name,
                        });
                    }
                }
            }
        }
        Ok(Response::new(ShmList { segs }))
    }

    async fn remove_shm(&self, req: Request<ShmRef>) -> Result<Response<Empty>, Status> {
        let req = req.into_inner();
        let pod = proto::validate_name(&req.pod).map_err(bad)?.to_string();
        let name = proto::validate_name(&req.name).map_err(bad)?.to_string();
        let dir = proto::shm_host_dir(&pod);
        match std::fs::symlink_metadata(&dir) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => {
                return Err(Status::failed_precondition(format!(
                    "shm dir {} exists but is not a real directory",
                    dir.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Status::not_found(format!("shm segment {name} not found")));
            }
            Err(e) => return Err(int(e)),
        }
        let path = dir.join(&name);
        // remove_file unlinks the entry itself — a planted symlink is
        // unlinked, never followed to its target.
        std::fs::remove_file(&path).map_err(int)?;
        Ok(Response::new(Empty {}))
    }

    type ExecStream = ReceiverStream<Result<ExecChunk, Status>>;
    async fn exec(
        &self,
        req: Request<tonic::Streaming<ExecChunk>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        use rustypods_proto::rpc::exec_chunk::Kind;
        let mut stream = req.into_inner();
        let start = match stream.next().await {
            Some(Ok(c)) => match c.kind {
                Some(Kind::Start(s)) => s,
                _ => return Err(Status::invalid_argument("first chunk must be ExecStart")),
            },
            Some(Err(e)) => return Err(e),
            None => return Err(Status::invalid_argument("empty exec stream")),
        };
        let name = proto::validate_name(&start.pod).map_err(bad)?.to_string();
        let (private_users, allow_setuid) = {
            let st = self.st.lock().await;
            let Some(m) = st.pods.get(&name) else {
                return Err(Status::not_found(format!("pod {name} not found")));
            };
            (m.private_users, m.allow_setuid)
        };
        let Some(leader) = self.engine.running_pid(&name).await else {
            return Err(Status::failed_precondition(format!(
                "pod {name} is not running"
            )));
        };
        if leader == 0 {
            // Registered with machined but no leader yet — nsenter has
            // nothing to attach to.
            return Err(Status::failed_precondition(format!(
                "pod {name} is still booting — no leader pid yet"
            )));
        }
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        crate::exec::run(
            start,
            &self.pod_rootfs(&name),
            leader,
            private_users,
            allow_setuid,
            stream,
            tx,
        )
        .await
        .map_err(int)?;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type PodMetricsStream = ReceiverStream<Result<Metric, Status>>;
    async fn pod_metrics(
        &self,
        req: Request<PodRef>,
    ) -> Result<Response<Self::PodMetricsStream>, Status> {
        let name = proto::validate_name(&req.into_inner().name)
            .map_err(bad)?
            .to_string();
        {
            let st = self.st.lock().await;
            if !st.pods.contains_key(&name) {
                return Err(Status::not_found(format!("pod {name} not found")));
            }
        }
        let mut rx = agent::latest_rx(&self.metrics, &name).await;
        let (tx, out) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            // The watch channel's initial value is Metric::default() until
            // the agent's first push — don't stream a bogus all-zero
            // sample (ts_unix_ms == 0 marks it synthetic).
            let first = *rx.borrow();
            if first.ts_unix_ms > 0 && tx.send(Ok(first)).await.is_err() {
                return;
            }
            // A quiet pod never pushes, so tx.send never fails. tx.closed()
            // fires when the client drops logs/metrics follow.
            loop {
                tokio::select! {
                    _ = tx.closed() => break,
                    changed = rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let m = *rx.borrow_and_update();
                        if tx.send(Ok(m)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(out)))
    }

    type StreamLogsStream = ReceiverStream<Result<LogLine, Status>>;
    async fn stream_logs(
        &self,
        req: Request<PodRef>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        let name = proto::validate_name(&req.into_inner().name)
            .map_err(bad)?
            .to_string();
        // Booted images (no OCI entrypoint/cmd) run systemd → journal to the
        // host journal under the machine name. Non-boot OCI pods carry no
        // journal at all: probe `journalctl -M` anyway (a stopped boot pod
        // fails machined -M resolution too) and fall back to the nspawn
        // console log the daemon always keeps for started pods.
        let boot_pod = {
            let st = self.st.lock().await;
            let Some(m) = st.pods.get(&name) else {
                return Err(Status::not_found(format!("pod {name} not found")));
            };
            !is_payload_pod(&st, m)
        };
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let log_path = self.cfg.logs_dir().join(format!("{name}.log"));
        tokio::spawn(async move {
            let has_journal = boot_pod
                && tokio::process::Command::new("journalctl")
                    .args(["-M", &name, "-n", "1", "--no-pager"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .await
                    .map(|s| s.success())
                    .unwrap_or(false);
            let spawned = if has_journal {
                // `-o cat`: raw message text only — no timestamp/host/unit
                // prefix. AI/agent consumers of the gRPC stream (and humans
                // copying compiler errors) want the message, not journal
                // chrome.
                tokio::process::Command::new("journalctl")
                    .args(["-M", &name, "-f", "-n", "100", "-o", "cat", "--no-pager"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .kill_on_drop(true)
                    .spawn()
            } else {
                // -F (capital): keep retrying if the log doesn't exist yet.
                tokio::process::Command::new("tail")
                    .arg("-n")
                    .arg("100")
                    .arg("-F")
                    .arg(&log_path)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .kill_on_drop(true)
                    .spawn()
            };
            let mut child = match spawned {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx
                        .send(Err(Status::internal(format!("log source spawn: {e}"))))
                        .await;
                    return;
                }
            };
            let Some(stdout) = child.stdout.take() else {
                return;
            };
            let mut reader = tokio::io::BufReader::new(stdout);
            let mut line = Vec::with_capacity(4096);
            // Quiet pods produce no lines, so send() never fails and an
            // abandoned `logs -f` would keep tail/journalctl forever.
            // tx.closed() is the disconnect signal; then kill and reap.
            loop {
                tokio::select! {
                    _ = tx.closed() => break,
                    read = read_log_line(&mut reader, &mut line) => {
                        match read {
                            Ok(true) => {
                                if tx
                                    .send(Ok(LogLine {
                                        ts_unix_ms: now_unix_ms(),
                                        data: std::mem::take(&mut line),
                                    }))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Ok(false) => break,
                            Err(e) => {
                                let _ = tx.send(Err(int(e))).await;
                                break;
                            }
                        }
                    }
                }
            }
            let _ = child.kill().await;
            let _ = child.wait().await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn create_volume(&self, req: Request<VolumeRef>) -> Result<Response<VolumeInfo>, Status> {
        let name = proto::validate_name(&req.into_inner().name)
            .map_err(bad)?
            .to_string();
        {
            let st = self.st.lock().await;
            if st.volumes.contains_key(&name) {
                return Err(Status::already_exists(format!(
                    "volume {name} already exists"
                )));
            }
        }
        let v = self.ensure_volume(&name).await?;
        Ok(Response::new(self.volume_info(&v).await))
    }

    async fn list_volumes(&self, _req: Request<Empty>) -> Result<Response<VolumeInfoList>, Status> {
        // Reconcile the registry with the fs first: a volume dir created
        // while the daemon was down (or whose conf vanished) still
        // mounts — adopt it so `ls` is complete.
        let vdir = proto::volumes_dir(&self.cfg.data_dir);
        let orphans: Vec<String> = Self::blocking({
            let vdir = vdir.clone();
            move || {
                let mut out = Vec::new();
                let Ok(rd) = std::fs::read_dir(&vdir) else {
                    return Ok(out);
                };
                for e in rd.flatten() {
                    let Ok(md) = e.metadata() else { continue };
                    if md.is_dir() {
                        if let Some(n) = e.file_name().to_str() {
                            out.push(n.to_string());
                        }
                    }
                }
                Ok(out)
            }
        })
        .await?;
        for n in orphans {
            self.ensure_volume(&n).await?;
        }
        let metas: Vec<VolumeMeta> = {
            let st = self.st.lock().await;
            st.volumes.values().cloned().collect()
        };
        let mut volumes = Vec::with_capacity(metas.len());
        for v in &metas {
            volumes.push(self.volume_info(v).await);
        }
        Ok(Response::new(VolumeInfoList { volumes }))
    }

    async fn remove_volume(&self, req: Request<VolumeRef>) -> Result<Response<Empty>, Status> {
        let name = proto::validate_name(&req.into_inner().name)
            .map_err(bad)?
            .to_string();
        let _vol = self.pod_op(&format!("volume:{name}")).await;
        let attachers = self.volume_attachers(&name).await;
        if !attachers.is_empty() {
            return Err(Status::failed_precondition(format!(
                "volume {name} is still referenced by pod(s) {} — remove the mount first",
                attachers.join(", ")
            )));
        }
        let dir = proto::volumes_dir(&self.cfg.data_dir).join(&name);
        let on_disk = dir.exists();
        let registered = {
            let st = self.st.lock().await;
            st.volumes.contains_key(&name)
        };
        if !on_disk && !registered {
            return Err(Status::not_found(format!("volume {name} not found")));
        }
        if on_disk {
            self.st_delete(&dir).await?;
        }
        state::remove_volume(&self.cfg.data_dir, &name).map_err(int)?;
        self.st.lock().await.volumes.remove(&name);
        Ok(Response::new(Empty {}))
    }

    /// `volume send <name> --to <peer>` — daemon→daemon push over the
    /// mesh (cluster plane). The heavy lifting lives in svc/cluster.rs.
    async fn send_volume(
        &self,
        req: Request<SendVolumeRequest>,
    ) -> Result<Response<SendVolumeResult>, Status> {
        Svc::send_volume(self, req).await
    }

    /// Dataplane endpoint for `send_volume` on the RECEIVING side.
    /// Only reachable over the mesh-RPC listener (token + peer guard)
    /// in real deployments; on UDS it works too, for tests.
    async fn receive_volume(
        &self,
        req: Request<tonic::Streaming<VolumeChunk>>,
    ) -> Result<Response<ReceiveVolumeResult>, Status> {
        let res = self.receive_volume(req.into_inner()).await?;
        Ok(Response::new(res))
    }

    type ExportPodStream = ReceiverStream<Result<ExportChunk, Status>>;

    async fn export_pod(
        &self,
        req: Request<ExportRequest>,
    ) -> Result<Response<Self::ExportPodStream>, Status> {
        let req = req.into_inner();
        Ok(Response::new(
            self.export_archive(&req.name, &req.format, req.allow_inconsistent)
                .await?,
        ))
    }

    async fn import_pod(
        &self,
        req: Request<tonic::Streaming<ImportChunk>>,
    ) -> Result<Response<Pod>, Status> {
        let p = self.import_archive(req.into_inner()).await?;
        Ok(Response::new(p))
    }
}

/// Per-line cap for stream_logs: BufReader::lines() buffers a whole line
/// unbounded — a pod emitting one giant unterminated line would grow
/// daemon RAM without limit. Longer lines are emitted truncated with a
/// marker, and the remainder up to the newline is discarded.
const LOG_LINE_MAX: usize = 64 << 10;
const TRUNCATED_MARK: &[u8] = b" [truncated]";
/// Total bytes the REST/gRPC log tail will hold. A console log can contain
/// one multi-gigabyte line with no newline; reading it via `tail` `.output()`
/// would OOM the root daemon.
const LOG_TAIL_MAX: usize = 1 << 20;

/// Last lines of a pod log, plus whether a cap discarded bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LogTail {
    pub lines: Vec<String>,
    pub truncated: bool,
}

/// Read one line (the '\n' is consumed but not included) into `out`,
/// capped at LOG_LINE_MAX. Returns Ok(false) only on clean EOF before any
/// byte; a final unterminated line still returns Ok(true).
async fn read_log_line<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
    out: &mut Vec<u8>,
) -> std::io::Result<bool> {
    use tokio::io::AsyncBufReadExt;
    out.clear();
    // true once the cap was hit: discard everything up to the line's '\n'.
    let mut skipping = false;
    loop {
        let buf = r.fill_buf().await?;
        if buf.is_empty() {
            return Ok(!out.is_empty());
        }
        if skipping {
            match buf.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    let n = i + 1;
                    r.consume(n);
                    return Ok(true);
                }
                None => {
                    let n = buf.len();
                    r.consume(n);
                }
            }
            continue;
        }
        let budget = LOG_LINE_MAX - out.len();
        match buf.iter().position(|&b| b == b'\n') {
            Some(i) if i <= budget => {
                out.extend_from_slice(&buf[..i]);
                let n = i + 1;
                r.consume(n);
                return Ok(true);
            }
            _ => {
                let take = budget.min(buf.len());
                out.extend_from_slice(&buf[..take]);
                r.consume(take);
                if out.len() >= LOG_LINE_MAX {
                    out.extend_from_slice(TRUNCATED_MARK);
                    skipping = true;
                }
            }
        }
    }
}

/// Read a child stdout until EOF or `cap` bytes. Over the cap, kill the
/// child so a journal line with no newline cannot grow without bound.
async fn read_capped_stdout(
    child: &mut tokio::process::Child,
    cap: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    use tokio::io::AsyncReadExt;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("child has no stdout"))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = stdout.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        let room = cap.saturating_sub(buf.len());
        if n > room {
            buf.extend_from_slice(&tmp[..room]);
            truncated = true;
            let _ = child.start_kill();
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let _ = child.wait().await;
    Ok((buf, truncated))
}

/// Last `n` lines of a console log, reading at most [`LOG_TAIL_MAX`] bytes
/// from the end of the file. Never loads the whole file.
fn read_log_tail_file(path: &std::path::Path, n: usize) -> std::io::Result<LogTail> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let cap = LOG_TAIL_MAX as u64;
    let start = len.saturating_sub(cap);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.take(cap).read_to_end(&mut buf)?;
    let mut cut = start > 0;
    if cut {
        // Drop the partial first line so we don't invent a head fragment,
        // unless the window contains no newline at all (one giant line).
        if let Some(i) = buf.iter().position(|b| *b == b'\n') {
            buf.drain(..=i);
        }
    }
    if buf.len() >= LOG_TAIL_MAX {
        cut = true;
    }
    Ok(split_log_tail(&buf, n, cut))
}

fn split_log_tail(buf: &[u8], n: usize, mut truncated: bool) -> LogTail {
    if buf.is_empty() || n == 0 {
        return LogTail {
            lines: Vec::new(),
            truncated,
        };
    }
    let mut parts: Vec<&[u8]> = buf.split(|b| *b == b'\n').collect();
    if buf.last() == Some(&b'\n') {
        parts.pop();
    }
    let mut lines = Vec::with_capacity(parts.len());
    for raw in parts {
        let (slice, cut) = if raw.len() > LOG_LINE_MAX {
            truncated = true;
            (&raw[..LOG_LINE_MAX], true)
        } else {
            (raw, false)
        };
        let mut s = String::from_utf8_lossy(slice).into_owned();
        if cut {
            s.push_str(" [truncated]");
        }
        lines.push(s);
    }
    if lines.len() > n {
        truncated = true;
        lines = lines.split_off(lines.len() - n);
    }
    LogTail { lines, truncated }
}

/// Write `bytes` into a daemon-owned directory via an `O_NOFOLLOW|O_EXCL`
/// temp file and `rename`. `rename` replaces a symlink at the destination;
/// it does not follow it. The directory itself is mode 0700; `mode` is the
/// file's own mode, which is what a pod sees through a file bind mount
/// (a userns pod can't read a 0600 root-owned file).
fn write_daemon_file(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<std::path::PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    let dest = dir.join(name);
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_EXCL)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        // The open mode is filtered by the daemon's umask.
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.write_all(bytes)?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, &dest).with_context(|| format!("rename {}", dest.display()))?;
    Ok(dest)
}

/// Mask vendor tmpfiles snippets that would operate on host paths bound
/// into a pod running without a user namespace. A symlink to `/dev/null`
/// in `/etc/tmpfiles.d/` disables the same-named file under
/// `/usr/lib/tmpfiles.d/`.
fn mask_host_tmpfiles(rootfs: &Path, binds: &[proto::BindSpec]) -> Result<()> {
    if !binds.iter().any(|b| !b.ro) {
        return Ok(());
    }
    crate::rootfs::mkdir_in_rootfs(rootfs, "etc/tmpfiles.d")?;
    for name in ["tmp.conf", "x11.conf"] {
        crate::rootfs::symlink_in_rootfs(
            rootfs,
            format!("etc/tmpfiles.d/{name}"),
            Path::new("/dev/null"),
        )?;
    }
    Ok(())
}

/// Create `etc/resolv.conf` inside the rootfs when it is missing, without
/// following a symlink at `etc` or at the leaf. An existing regular file is
/// left alone (the bind mounts over it). A leaf symlink is unlinked and
/// replaced with an empty regular file.
fn ensure_resolv_target(rootfs: &Path) -> Result<()> {
    crate::rootfs::mkdir_in_rootfs(rootfs, "etc")?;
    match crate::rootfs::classify(rootfs, "etc/resolv.conf")? {
        crate::rootfs::Leaf::File => Ok(()),
        crate::rootfs::Leaf::Symlink => {
            crate::rootfs::remove_in_rootfs(rootfs, "etc/resolv.conf")?;
            crate::rootfs::write_in_rootfs(rootfs, "etc/resolv.conf", b"", Some(0o644))
        }
        crate::rootfs::Leaf::Absent => {
            crate::rootfs::write_in_rootfs(rootfs, "etc/resolv.conf", b"", Some(0o644))
        }
        _ => bail!("etc/resolv.conf is not a regular file"),
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// True when the operator explicitly allowed a non-loopback REST bind.
pub fn http_insecure_enabled() -> bool {
    std::env::var_os("RUSTYPODS_HTTP_INSECURE").is_some()
}

pub fn http_token_rotate() -> bool {
    std::env::var_os("RUSTYPODS_HTTP_TOKEN_ROTATE").is_some()
}

/// Snapshot GC predicate: `snaps` is newest-first; a snapshot is collected
/// when its index reaches keep_last (if > 0) OR it is older than max_age
/// (if > 0). Both criteria apply — the union is deleted.
fn snapshot_expired(idx: usize, created_unix: u64, keep_last: u32, max_age: u64, now: u64) -> bool {
    (keep_last > 0 && idx >= keep_last as usize)
        || (max_age > 0 && now.saturating_sub(created_unix) > max_age)
}

/// Does the rootfs carry a systemd init? Checked on the pod rootfs at
/// start: distrobox imports have it, OCI-pulled images don't (they run
/// non-boot via their recorded entrypoint/cmd instead).
fn has_systemd_init(rootfs: &Path) -> bool {
    // Same leaf policy as resolve_in_rootfs: symlinked intermediates are
    // refused (no host-fs stat), a leaf symlink counts as existing.
    [
        "usr/lib/systemd/systemd",
        "lib/systemd/systemd",
        "sbin/init",
    ]
    .iter()
    .any(|p| {
        crate::rootfs::classify(rootfs, p)
            .map(|l| l.exists())
            .unwrap_or(false)
    })
}

/// Resolve a payload argv[0] inside the rootfs: absolute paths checked
/// verbatim, bare names searched in the usual container PATH dirs (same
/// order as nspawn's built-in default). Returns the in-container path.
/// The existence probe goes through rootfs::safe_join_if_exists — a
/// planted '..' or a symlinked parent (e.g. `usr -> /host/usr`) must
/// never make this stat the HOST fs.
fn resolve_in_rootfs(rootfs: &Path, prog: &str) -> Option<String> {
    // Leaf policy: symlink_metadata — a leaf symlink counts as existing
    // (it resolves inside the container), and is never followed host-side.
    let exists = |rel: &str| -> bool {
        crate::rootfs::classify(rootfs, rel)
            .map(|l| l.exists())
            .unwrap_or(false)
    };
    if prog.contains('/') {
        return exists(prog).then(|| prog.to_string());
    }
    for d in [
        "usr/local/sbin",
        "usr/local/bin",
        "usr/sbin",
        "usr/bin",
        "sbin",
        "bin",
    ] {
        if exists(&format!("{d}/{prog}")) {
            return Some(format!("/{d}/{prog}"));
        }
    }
    None
}

/// Recursive byte size of a dir — plain metadata walk, works on btrfs
/// and fallback alike (du would double-count reflinked extents anyway).
fn dir_size(path: &std::path::Path) -> Result<u64> {
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(d) = stack.pop() {
        let rd = match std::fs::read_dir(&d) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for e in rd.flatten() {
            // DirEntry::metadata does NOT traverse symlinks (unlike
            // Path::metadata) — a planted symlink is counted as itself,
            // never followed outside the volume.
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                stack.push(e.path());
            } else {
                total += md.len();
            }
        }
    }
    Ok(total)
}

/// "Pre-upgrade v2!" → "pre-upgrade-v2" — snapshot labels become dir names.
fn slugify(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().flat_map(|c| c.to_lowercase()) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    out.trim_end_matches('-').chars().take(40).collect()
}

/// Apply/clear the pod's storage cap through the active driver. Best-effort
/// caller sites decide whether failure is fatal (config apply) or a warning
/// (pod start).
/// Strip distrobox/podman runtime artifacts so `systemd-nspawn --boot` gets a
/// clean Arch rootfs: host binds aren't in the export, but init leftovers are.
/// `container_id` = the distrobox name — host wrappers in ~/.local/bin check
/// CONTAINER_ID and exec the local binary directly when it matches.
fn sanitize_rootfs(root: &Path, container_id: &str) -> Result<()> {
    // All rootfs access goes through the symlink-safe helpers: an image
    // with `etc -> /host/etc` planted must fail here, never let these
    // deletes/writes land on the host.
    use crate::rootfs as rfs;
    for rel in [
        "etc/hostname",
        "etc/hosts",
        "etc/resolv.conf",
        "usr/bin/entrypoint",
        "usr/bin/distrobox-init",
        "usr/bin/distrobox-export",
        "usr/bin/distrobox-host-exec",
    ] {
        rfs::remove_in_rootfs(root, rel)?;
    }
    // Empty machine-id = uninitialized → container generates its own.
    rfs::write_in_rootfs(root, "etc/machine-id", b"", None)?;
    rfs::remove_in_rootfs(root, "run/host")?;
    // Read-only enumeration — never list host dirs through a symlink.
    rfs::remove_children_containing(root, "etc/profile.d", "distrobox")?;
    // distrobox-export wrappers in ~/.local/bin branch on CONTAINER_ID:
    // matching the source box name makes them exec the real /usr/bin binary.
    // Fallback for unset CONTAINER_ID: a shim at the absolute path the
    // wrappers call, stripping "-n <box> --" and exec'ing the payload.
    let mut envf = rfs::read_file_in_rootfs(root, "etc/environment")
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    if !envf.contains("CONTAINER_ID=") {
        envf.push_str(&format!("CONTAINER_ID={container_id}\n"));
        rfs::write_in_rootfs(root, "etc/environment", envf.as_bytes(), None)?;
    }
    rfs::write_in_rootfs(
        root,
        "usr/bin/distrobox-enter",
        "#!/bin/sh\n# rustypods shim: inside an nspawn pod, exec the payload directly.\nwhile [ $# -gt 0 ]; do [ \"$1\" = \"--\" ] && { shift; break; }; shift; done\nexec \"$@\"\n"
            .as_bytes(),
        Some(0o755),
    )?;

    // In-pod telemetry agent: enabled unit, binary comes via the ro-bind of
    // /var/lib/rustypods/bin → /run/rustypods/bin at pod start.
    rfs::mkdir_in_rootfs(root, "etc/systemd/system/multi-user.target.wants")?;
    rfs::write_in_rootfs(
        root,
        "etc/systemd/system/rustypods-agent.service",
        "[Unit]\nDescription=RustyPods in-pod telemetry agent\nAfter=local-fs.target\n\n[Service]\nExecStart=/run/rustypods/bin/rustypods-agent\nRestart=always\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n"
            .as_bytes(),
        None,
    )?;
    rfs::symlink_in_rootfs(
        root,
        "etc/systemd/system/multi-user.target.wants/rustypods-agent.service",
        Path::new("../rustypods-agent.service"),
    )?;
    Ok(())
}

/// Repair pod directories left by a crash: restore `.rollback-old` when
/// it is the only rootfs, drop disposable staging, and quarantine orphan
/// rootfs dirs (no conf) so the name can be reused. Nothing here deletes
/// the only copy of a pod's data. `.import-*` / `.export-*` are left for
/// the transfer sweep.
async fn reconcile_pod_dirs(cfg: &Config, storage: &Arc<dyn StorageDriver>, st: &Mutex<State>) {
    let pods_dir = cfg.pods_dir();
    // Quarantined confs still own their rootfs: fixing the conf by hand
    // must find the tree where it was, not under `.orphan`.
    let conf_names: BTreeSet<String> = {
        let guard = st.lock().await;
        guard
            .pods
            .keys()
            .cloned()
            .chain(guard.quarantined.iter().map(|q| q.name.clone()))
            .collect()
    };
    let entries: Vec<String> = match std::fs::read_dir(&pods_dir) {
        Ok(rd) => rd
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect(),
        Err(e) => {
            tracing::warn!("startup reconcile: read {}: {e}", pods_dir.display());
            return;
        }
    };
    let actions = state::plan_rootfs_reconcile(&entries, &conf_names);
    for action in actions {
        match action {
            state::RootfsAction::Rename { from, to } => {
                let src = pods_dir.join(&from);
                let dst = pods_dir.join(&to);
                match std::fs::rename(&src, &dst) {
                    Ok(()) => tracing::info!("startup reconcile: renamed {from} → {to}"),
                    Err(e) => {
                        tracing::error!("startup reconcile: rename {from} → {to} failed: {e}")
                    }
                }
            }
            state::RootfsAction::Delete { name } => {
                let path = pods_dir.join(&name);
                match storage.delete_rootfs(&path) {
                    Ok(()) => tracing::info!("startup reconcile: removed {name}"),
                    Err(e) => tracing::error!("startup reconcile: remove {name} failed: {e:#}"),
                }
            }
            state::RootfsAction::Report { message } => {
                tracing::error!("startup reconcile: {message}");
            }
        }
    }
}

#[cfg(test)]
impl Svc {
    pub(crate) fn stub(data_dir: std::path::PathBuf) -> Self {
        struct NopEngine;
        #[tonic::async_trait]
        impl RuntimeEngine for NopEngine {
            fn name(&self) -> &'static str {
                "nop"
            }
            async fn start(&self, _: &crate::runtime::StartSpec, _: &LimitsSpec) -> Result<u32> {
                Ok(1)
            }
            async fn stop(&self, _: &str, _: Duration) -> Result<()> {
                Ok(())
            }
            async fn running_pid(&self, _: &str) -> Option<u32> {
                None
            }
            async fn registered(&self, _: &str) -> Result<bool> {
                Ok(false)
            }
            async fn apply_limits(&self, _: &str, _: &LimitsSpec) -> Result<()> {
                Ok(())
            }
            async fn healthy(&self) -> bool {
                true
            }
        }
        struct NopStore;
        impl StorageDriver for NopStore {
            fn name(&self) -> &'static str {
                "nop"
            }
            fn supports_quota(&self) -> bool {
                false
            }
            fn create_rootfs(&self, _: &Path) -> Result<()> {
                Ok(())
            }
            fn clone_rootfs(&self, _: &Path, _: &Path) -> Result<()> {
                Ok(())
            }
            fn delete_rootfs(&self, _: &Path) -> Result<()> {
                Ok(())
            }
            fn apply_quota(&self, _: &Path, _: u64) -> Result<()> {
                Ok(())
            }
        }
        Svc {
            cfg: Config {
                data_dir,
                socket: std::path::PathBuf::from("/tmp/rustypods-test.sock"),
                allowed_uid: 1000,
                read_only_uids: Vec::new(),
                import_user: "test".into(),
                http_addr: String::new(),
                gc_interval_secs: 300,
                notify: Default::default(),
            },
            st: Arc::new(Mutex::new(State::default())),
            metrics: Default::default(),
            listeners: Default::default(),
            engine: Arc::new(NopEngine),
            storage: Arc::new(NopStore),
            ops: Default::default(),
            ingress_generation: Arc::new(AtomicU64::new(0)),
            ingress_mu: Arc::new(Mutex::new(())),
            ingress_last_err: Arc::new(Mutex::new(None)),
            ingress_last_push: Arc::new(Mutex::new(None)),
            health: Default::default(),
            stop_intent: Default::default(),
            mesh: Default::default(),
            mesh_rpc_stop: Arc::new(std::sync::Mutex::new(None)),
            mesh_lifecycle: Default::default(),
            inflight: Inflight::new(),
        }
    }
}

pub async fn serve(cfg: Config) -> Result<()> {
    net::load_pool().context("pod address pool")?;
    for d in [
        cfg.images_dir(),
        cfg.pods_dir(),
        cfg.logs_dir(),
        cfg.bin_dir(),
        cfg.shm_dir(),
        state::pods_conf_dir(&cfg.data_dir),
        state::images_conf_dir(&cfg.data_dir),
        cfg.resolv_dir(),
        proto::volumes_dir(&cfg.data_dir),
    ] {
        std::fs::create_dir_all(&d).with_context(|| format!("mkdir {}", d.display()))?;
    }
    state::secure_conf_dirs(&cfg.data_dir)?;
    std::fs::create_dir_all(cfg.data_dir.join("snapshots"))
        .with_context(|| format!("mkdir {}/snapshots", cfg.data_dir.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        // Rootfs trees keep image-owned setuid-root binaries (pulled or
        // imported images included); a traversable parent would let any
        // local host user execute them. nspawn mounts as root and
        // pivot_roots, so pods never walk these parents.
        for d in [
            cfg.resolv_dir(),
            cfg.images_dir(),
            cfg.pods_dir(),
            cfg.data_dir.join("snapshots"),
        ] {
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {}", d.display()))?;
        }
    }
    // SIGKILL'd pulls/imports leave .layer-*/.export-* blobs behind.
    oci::sweep_tmpfiles(&cfg.images_dir());
    transfer::sweep_stale_staging(&cfg.data_dir);
    // /dev/shm is world-writable (1777): the SHM subtree root must be a
    // real root-owned 0700 dir, or any local user could plant symlinks the
    // daemon (running as root) would follow during create_shm/start_pod —
    // a classic world-writable-dir privesc.
    {
        let shm_root = Path::new("/dev/shm/rustypods");
        match std::fs::symlink_metadata(shm_root) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => bail!(
                "{} exists but is not a real directory — refusing to start",
                shm_root.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(shm_root)
                    .with_context(|| format!("mkdir {}", shm_root.display()))?;
            }
            Err(e) => return Err(e).with_context(|| format!("stat {}", shm_root.display())),
        }
        // Lock it down: root-owned, 0700. Skip the calls when already right —
        // a non-root daemon can't chmod a root-owned dir, but an already-
        // secured one doesn't need it to.
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::symlink_metadata(shm_root)?;
        if md.mode() & 0o777 != 0o700 {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(shm_root, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {}", shm_root.display()))?;
        }
        if crate::euid() == 0 && md.uid() != 0 {
            std::os::unix::fs::chown(shm_root, Some(0), Some(0))
                .with_context(|| format!("chown {}", shm_root.display()))?;
        }
    }
    if let Some(p) = cfg.socket.parent() {
        std::fs::create_dir_all(p)?;
    }
    if cfg.socket.exists() {
        std::fs::remove_file(&cfg.socket)?;
    }
    let listener = UnixListener::bind(&cfg.socket)
        .with_context(|| format!("bind {}", cfg.socket.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&cfg.socket, std::fs::Permissions::from_mode(0o666))?;

    // Engine + storage drivers, auto-detected. The nspawn engine owns the
    // shared system-bus connection (zbus multiplexes all calls over it).
    let dbus = zbus::Connection::system()
        .await
        .context("connecting to system D-Bus")?;
    let engine: Arc<dyn RuntimeEngine> = Arc::new(runtime::SystemdNspawn { dbus: dbus.clone() });
    // `detect` probes the fs with `stat -f` — a subprocess; off the
    // executor even though nothing is serving yet.
    let dd = cfg.data_dir.clone();
    let storage = tokio::task::spawn_blocking(move || storage::detect(&dd))
        .await
        .context("storage detect task")?;
    engine.init().await?;

    let st = Arc::new(Mutex::new(state::load(&cfg.data_dir)?));
    reconcile_pod_dirs(&cfg, &storage, &st).await;
    {
        let live: std::collections::BTreeSet<String> =
            st.lock().await.pods.keys().cloned().collect();
        crate::runtime::logs::sweep_orphan_logs(&cfg.logs_dir(), &live);
    }
    crate::runtime::logs::spawn_rotator(cfg.logs_dir());
    let metrics: MetricsMap = Default::default();
    let listeners: ListenerMap = Default::default();
    let svc = Svc {
        cfg: cfg.clone(),
        st: st.clone(),
        metrics: metrics.clone(),
        listeners: listeners.clone(),
        engine: engine.clone(),
        storage,
        ops: Default::default(),
        inflight: Inflight::new(),
        ingress_generation: Arc::new(AtomicU64::new(0)),
        ingress_mu: Arc::new(Mutex::new(())),
        ingress_last_err: Arc::new(Mutex::new(None)),
        ingress_last_push: Arc::new(Mutex::new(None)),
        health: Default::default(),
        stop_intent: Default::default(),
        mesh: Default::default(),
        mesh_rpc_stop: Arc::new(std::sync::Mutex::new(None)),
        mesh_lifecycle: Default::default(),
    };

    // Restore unless-stopped intent from conf so the in-memory set matches
    // disk before the supervisor's first tick.
    {
        let names: Vec<String> = {
            let st = svc.st.lock().await;
            st.pods
                .values()
                .filter(|m| m.stopped_by_user)
                .map(|m| m.name.clone())
                .collect()
        };
        *svc.stop_intent.lock().await = names.into_iter().collect();
    }

    // Daemon restarted while pods kept running → rebind their agent channels.
    let running: Vec<(String, bool)> = {
        let guard = st.lock().await;
        guard
            .pods
            .values()
            .map(|m| (m.name.clone(), m.private_users))
            .collect()
    };
    for (name, userns) in running {
        let run_dir = proto::run_dir(&cfg.data_dir, &name);
        if let Some(leader) = engine.running_pid(&name).await {
            if let Err(e) =
                agent::spawn_listener(&run_dir, &name, metrics.clone(), listeners.clone()).await
            {
                tracing::warn!("agent-listener {name}: {e:#}");
            }
            // Same as start_pod: hand agent.sock to the mapped kuid.
            if userns && leader > 0 {
                agent::chown_sock_for_userns(&run_dir, leader);
            }
        }
    }

    // Transfer staging dirs are always disposable: a crash mid-export/
    // import would otherwise leak ro subvolumes forever. Sweep them once
    // at boot — nothing legitimate ever creates .export-*/.import-*.
    {
        let storage = svc.storage.clone();
        let dd = svc.cfg.data_dir.clone();
        tokio::task::spawn_blocking(move || {
            for e in std::fs::read_dir(&dd).into_iter().flatten().flatten() {
                let n = e.file_name();
                let n = n.to_string_lossy();
                if n.starts_with(".export-") || n.starts_with(".import-") {
                    tracing::info!("sweeping stale transfer staging {}", e.path().display());
                    for inner in std::fs::read_dir(e.path()).into_iter().flatten().flatten() {
                        let _ = storage.delete_rootfs(&inner.path());
                    }
                    let _ = std::fs::remove_dir_all(e.path());
                }
            }
        });
    }

    // Wave I mesh: conf/mesh.conf carries a stable WG identity, so a
    // daemon restart re-derives the same /48 and re-attaches the same
    // persistent rp-mesh0 — routes and pod addrs survive intact. Bring
    // it up BEFORE autostart so those pods get mesh addresses.
    match state::load_mesh(&cfg.data_dir) {
        Ok(Some(conf)) => match mesh::Mesh::start(&cfg.data_dir, conf).await {
            Ok(m) => {
                tracing::info!("mesh up: {} on [::]:{}", m.prefix, m.port);
                match svc.mesh.write() {
                    Ok(mut g) => *g = Some(m),
                    Err(poisoned) => {
                        tracing::error!("mesh lock poisoned; recovering to store the mesh");
                        *poisoned.into_inner() = Some(m);
                    }
                }
                svc.assign_mesh_addrs().await;
                // Kernel drop before the listener. If nft fails, leave
                // :5306 unbound rather than accept on lo.
                if let Err(e) = svc.sync_mesh_rpc_guard().await {
                    tracing::error!("mesh rpc guard failed; cluster listener stays down: {e}");
                } else {
                    svc.spawn_mesh_rpc().await;
                }
            }
            Err(e) => tracing::error!("mesh start failed (mesh disabled): {e:#}"),
        },
        Ok(None) => {}
        Err(e) => tracing::error!(
            "mesh.conf failed to load; mesh stays down (fix or remove the file — do not generate a new key): {e:#}"
        ),
    }

    // Autostart: pods flagged `autostart = true` in their conf get booted
    // by the daemon itself. Sequential, detached — a slow boot must never
    // stall serve(), and a failing pod is logged and skipped, not fatal.
    // Goes through the real start_pod RPC so the per-pod op mutex, conf
    // persistence and NAT wiring all behave exactly like `rustypods start`.
    {
        let svc = svc.clone();
        tokio::spawn(async move {
            let flagged: Vec<String> = {
                let st = svc.st.lock().await;
                st.pods
                    .values()
                    .filter(|m| m.autostart && !m.stopped_by_user)
                    .map(|m| m.name.clone())
                    .collect()
            };
            // The gateway goes first: backends' start-time route sync
            // needs its control socket up.
            let mut flagged = flagged;
            flagged.sort_by_key(|n| (n != proto::INGRESS_POD, n.clone()));
            for name in flagged {
                // Pods that survived a daemon restart are already up.
                if svc.engine.running_pid(&name).await.is_some() {
                    continue;
                }
                tracing::info!("autostart: booting pod {name}");
                if let Err(e) = svc
                    .start_pod(Request::new(StartPodRequest {
                        name: name.clone(),
                        limits: None,
                        ephemeral: false,
                        private_users: None,
                    }))
                    .await
                {
                    tracing::warn!("autostart {name}: {e}");
                }
            }
        });
    }

    // Periodic ingress reconciliation: while a gateway pod is configured
    // and running, push a fresh snapshot every 2s — heals daemon/gateway
    // restarts and any drift between starts/stops and the dataplane's
    // route table. Errors are throttled: identical messages log once,
    // recovery logs once.
    {
        let svc = svc.clone();
        spawn_restarting("ingress reconciler", move || {
            let svc = svc.clone();
            async move {
                let mut tick = tokio::time::interval(Duration::from_secs(2));
                loop {
                    tick.tick().await;
                    let gw_name = {
                        let st = svc.st.lock().await;
                        st.pods
                            .get(proto::INGRESS_POD)
                            .filter(|m| m.ingress_gateway)
                            .map(|m| m.name.clone())
                    };
                    let (configured, gw_running) = match gw_name {
                        Some(n) => (true, svc.engine.running_pid(&n).await.is_some()),
                        None => (false, false),
                    };
                    if !configured || !gw_running {
                        continue;
                    }
                    if let Err(e) = svc.maintain_ingress_pki().await {
                        tracing::warn!("ingress pki: {e}");
                    }
                    match svc.sync_ingress(None, false).await {
                        Ok(()) => {
                            let mut last = svc.ingress_last_err.lock().await;
                            if last.take().is_some() {
                                tracing::info!("ingress reconciliation recovered");
                            }
                        }
                        Err(e) => {
                            let msg = format!("{e}");
                            let mut last = svc.ingress_last_err.lock().await;
                            if last.as_deref() != Some(msg.as_str()) {
                                tracing::warn!("ingress reconciliation: {msg}");
                                *last = Some(msg);
                            }
                        }
                    }
                }
            }
        });
    }

    // firewalld --reload and an nft flush drop pod NAT and zone bindings.
    // Rebuild on a 30s tick and immediately on firewalld's Reloaded signal.
    {
        let svc = svc.clone();
        let mut reloaded = net::watch_firewalld_reloads(dbus);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = reloaded.recv() => {
                        tracing::info!("firewalld reloaded — reconciling pod firewall");
                    }
                }
                if let Err(e) = svc.sync_nat().await {
                    tracing::warn!("net reconcile: {e}");
                }
                let _ = tokio::task::spawn_blocking(net::rebind_firewalld_ifaces).await;
            }
        });
    }

    // Supervisor: per-second death-watch + liveness probes for pods with
    // a restart policy or a healthcheck (and the managed gateway).
    {
        let svc = svc.clone();
        spawn_critical("supervisor", async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                svc.supervise_once().await;
            }
        });
    }

    // REST/JSON facade (axum) for automation — bearer-token gated (token
    // in <socket-dir>/http-token, mode 0400). The default bind is
    // localhost-only; empty --http-addr disables it. If the token file
    // can't be written, the listener stays OFF — never serve unauth'd.
    if !cfg.http_addr.is_empty() {
        let loopback = cfg
            .http_addr
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false);
        if !loopback {
            tracing::warn!(
                "SECURITY: REST API bound to non-loopback {} over plain HTTP with a \
                 root-equivalent bearer token. This is not a supported remote path. \
                 Use SSH forwarding (`ssh -L 9180:127.0.0.1:9180 host`) or the gRPC \
                 client `--remote` mode. Unset RUSTYPODS_HTTP_INSECURE to refuse this bind.",
                cfg.http_addr
            );
        }
        match tokio::net::TcpListener::bind(&cfg.http_addr).await {
            Ok(l) => match crate::http::ensure_http_tokens(
                &cfg.socket,
                cfg.allowed_uid,
                http_token_rotate(),
            ) {
                Ok((auth, token_path, ro_path)) => match crate::http::router(svc.clone(), auth) {
                    Ok(router) => {
                        tracing::info!(
                            "http api listening on http://{} — bearer token in {} (read-only {})",
                            cfg.http_addr,
                            token_path.display(),
                            ro_path.display()
                        );
                        spawn_critical("http server", async move {
                            if let Err(e) = crate::http::listen(l, router).await {
                                tracing::error!("http api: {e}");
                            }
                        });
                    }
                    Err(e) => tracing::error!("http api disabled — {e:#}"),
                },
                Err(e) => tracing::warn!("http api disabled — token setup failed: {e:#}"),
            },
            Err(e) => tracing::warn!("http api bind {}: {e}", cfg.http_addr),
        }
    }

    // Snapshot GC: per-pod retention (snap_keep_last / snap_max_age) applied
    // every gc_interval_secs. First tick fires immediately (startup sweep).
    {
        let gc = svc.clone();
        let every = Duration::from_secs(cfg.gc_interval_secs.max(1));
        spawn_restarting("snapshot gc", move || {
            let gc = gc.clone();
            let every = every;
            async move {
                let mut tick = tokio::time::interval(every);
                loop {
                    tick.tick().await;
                    gc.gc_snapshots().await;
                }
            }
        });
    }

    let audit = access::AuditLog::open(&cfg.data_dir).context("mutation audit log")?;
    let readers: Arc<BTreeSet<u32>> = Arc::new(cfg.read_only_uids.iter().copied().collect());
    let allowed = cfg.allowed_uid;
    let readers_accept = Arc::clone(&readers);
    let (tx, rx) = tokio::sync::mpsc::channel::<tokio::net::UnixStream>(32);
    let (shut_tx, shut_rx) = tokio::sync::watch::channel(false);
    {
        let shut_tx = shut_tx.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("SIGTERM handler: {e}");
                    std::process::exit(1);
                }
            };
            let mut intr = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("SIGINT handler: {e}");
                    std::process::exit(1);
                }
            };
            tokio::select! {
                _ = term.recv() => tracing::info!("SIGTERM — draining"),
                _ = intr.recv() => tracing::info!("SIGINT — draining"),
            }
            let _ = shut_tx.send(true);
        });
    }
    let mut shut_accept = shut_rx.clone();
    let accept_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                changed = shut_accept.changed() => {
                    if changed.is_err() || *shut_accept.borrow() {
                        break;
                    }
                }
                acc = listener.accept() => match acc {
                    Ok((s, _)) => match s.peer_cred() {
                        Ok(c)
                            if c.uid() == 0
                                || c.uid() == allowed
                                || readers_accept.contains(&c.uid()) =>
                        {
                            if tx.try_send(s).is_err() {
                                tracing::warn!("accept queue full, connection dropped");
                            }
                        }
                        Ok(c) => tracing::warn!("uid {} refused on rustypods.sock", c.uid()),
                        Err(e) => tracing::warn!("peer_cred: {e}"),
                    },
                    Err(e) => {
                        tracing::warn!("accept: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
            }
        }
    });
    let inflight = Arc::clone(&svc.inflight);
    let incoming = ReceiverStream::new(rx).map(Ok::<_, std::io::Error>);
    tracing::info!("rustypodsd listening on {}", cfg.socket.display());
    cfg.notify.ready();
    let mut shut_serve = shut_rx.clone();
    let readers_gate = Arc::clone(&readers);
    let grpc = Server::builder()
        // The socket admits uid 0, the admin uid, and the read-only
        // uids. Streaming RPCs (journalctl/tail/exec) stay admin-only.
        // Cap in-flight requests per connection and across the whole
        // server so one chatty client can't exhaust the subprocess budget.
        .concurrency_limit_per_connection(32)
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(256))
        .layer(access::StampPathLayer)
        .add_service(PodControlServer::with_interceptor(
            svc,
            move |req: Request<()>| access::authorize(&audit, allowed, &readers_gate, req),
        ))
        .serve_with_incoming_shutdown(incoming, async move {
            let _ = shut_serve.wait_for(|v| *v).await;
        });
    tokio::pin!(grpc);
    let mut shut_main = shut_rx;
    tokio::select! {
        result = &mut grpc => {
            result?;
        }
        joined = accept_task => {
            if let Err(e) = joined {
                tracing::error!("grpc accept panicked: {e}");
                std::process::exit(1);
            }
            // Accept loop returned: shutdown closed it, or it stopped.
            // Dropping `grpc` cancels handlers; detached mutating tasks
            // keep running until the drain below.
        }
        _ = shut_main.changed() => {
            tracing::info!("stopping accept; draining in-flight operations");
        }
    }
    cfg.notify.stopping();
    match tokio::time::timeout(Duration::from_secs(30), inflight.drained()).await {
        Ok(()) => tracing::info!("in-flight operations finished"),
        Err(_) => tracing::error!("drain timed out after 30s; exiting"),
    }
    let _ = std::fs::remove_file(&cfg.socket);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tonic::Request;

    struct SlowDelete;

    impl StorageDriver for SlowDelete {
        fn name(&self) -> &'static str {
            "slow"
        }
        fn supports_quota(&self) -> bool {
            false
        }
        fn create_rootfs(&self, _: &Path) -> Result<()> {
            Ok(())
        }
        fn clone_rootfs(&self, _: &Path, _: &Path) -> Result<()> {
            Ok(())
        }
        fn apply_quota(&self, _: &Path, _: u64) -> Result<()> {
            Ok(())
        }
        fn delete_rootfs(&self, path: &Path) -> Result<()> {
            std::thread::sleep(Duration::from_millis(250));
            if path.exists() {
                std::fs::remove_dir_all(path)?;
            }
            Ok(())
        }
    }

    #[test]
    fn staging_guard_drop_does_not_run_cleanup_inline() {
        let dir = std::env::temp_dir().join(format!(
            "rustypods-stage-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let started = std::time::Instant::now();
        drop(StagingGuard {
            dir: dir.clone(),
            storage: Arc::new(SlowDelete),
            armed: true,
        });
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "StagingGuard::drop blocked the caller for {:?}",
            started.elapsed()
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while dir.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!dir.exists(), "sweeper did not remove {}", dir.display());
    }

    #[test]
    fn daemon_file_replaces_symlink_without_following() {
        let dir = std::env::temp_dir().join(format!("rustypods-wdf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let outside = dir.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("victim");
        std::fs::write(&victim, b"safe").unwrap();
        let owned = dir.join("owned");
        std::fs::create_dir_all(&owned).unwrap();
        std::os::unix::fs::symlink(&victim, owned.join("p.conf")).unwrap();
        write_daemon_file(&owned, "p.conf", b"nameserver fd00::1\n", 0o644).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"safe");
        assert_eq!(
            std::fs::read(owned.join("p.conf")).unwrap(),
            b"nameserver fd00::1\n"
        );
        let meta = std::fs::symlink_metadata(owned.join("p.conf")).unwrap();
        assert!(meta.file_type().is_file());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o644);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_tail_caps_a_giant_line_and_keeps_the_tail() {
        let t = split_log_tail(b"a\nb\nc\n", 2, false);
        assert_eq!(t.lines, vec!["b".to_string(), "c".to_string()]);
        assert!(t.truncated);
        let giant = vec![b'x'; LOG_LINE_MAX + 50];
        let t = split_log_tail(&giant, 10, false);
        assert_eq!(t.lines.len(), 1);
        assert!(t.lines[0].ends_with(" [truncated]"));
        assert!(t.truncated);
        assert!(t.lines[0].len() < giant.len());

        let dir = std::env::temp_dir().join(format!("rustypods-tail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("p.log");
        // Bigger than the response cap, no newline — must not read it all.
        let mut f = std::fs::File::create(&p).unwrap();
        std::io::Write::write_all(&mut f, &vec![b'z'; LOG_TAIL_MAX + 100]).unwrap();
        drop(f);
        let t = read_log_tail_file(&p, 5).unwrap();
        assert!(t.truncated);
        assert_eq!(t.lines.len(), 1);
        assert!(t.lines[0].contains("[truncated]"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::{
        op_slot_unreferenced, probe_addr, read_log_tail_file, restart_policy, snapshot_expired,
        split_log_tail, supervised, supervisor_idle, validate_ingress_conflicts,
        validate_ingress_conflicts_excluding, volume_refs, write_daemon_file, Svc, LOG_LINE_MAX,
        LOG_TAIL_MAX,
    };
    use crate::state::{IngressSpec, LimitsSpec, PodMeta, State};
    use rustypods_proto::rpc::IngressRule;
    use std::collections::{BTreeMap, BTreeSet};

    fn meta_with_ingress(name: &str, hosts: &[&str]) -> PodMeta {
        PodMeta {
            format: 1,
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
            ingress: hosts
                .iter()
                .map(|h| IngressSpec {
                    host: h.to_string(),
                    pod_port: 8080,
                })
                .collect(),
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

    fn meta_plain(name: &str) -> PodMeta {
        meta_with_ingress(name, &[])
    }

    #[tokio::test]
    async fn concurrent_patches_do_not_drop_updates() {
        let dir = std::env::temp_dir().join(format!(
            "rp-patch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let svc = Svc::stub(dir.clone());
        {
            let mut st = svc.st.lock().await;
            st.pods.insert("web".into(), meta_plain("web"));
        }
        let bump = |svc: Svc, field: u8| async move {
            let _op = svc.pod_op("web").await;
            let (lim, storage) = svc.pod_limit_snapshot("web").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            let mut limits = lim;
            if field == 0 {
                limits.memory_high_bytes = limits.memory_high_bytes.saturating_add(1);
            } else {
                limits.memory_max_bytes = limits.memory_max_bytes.saturating_add(1);
            }
            svc.apply_pod_config(rustypods_proto::rpc::UpdatePodConfigRequest {
                name: "web".into(),
                limits: Some(limits),
                storage_max_bytes: storage,
                ..Default::default()
            })
            .await
            .unwrap();
        };
        let (a, b) = tokio::join!(bump(svc.clone(), 0), bump(svc.clone(), 1));
        let _ = (a, b);
        let (lim, _) = svc.pod_limit_snapshot("web").await.unwrap();
        assert_eq!(lim.memory_high_bytes, 1);
        assert_eq!(lim.memory_max_bytes, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exchange_rename_swaps_directories() {
        let dir = std::env::temp_dir().join(format!("rp-xchg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a");
        let b = dir.join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        std::fs::write(a.join("old"), "old").unwrap();
        std::fs::write(b.join("new"), "new").unwrap();
        match super::exchange_rename(&a, &b) {
            Ok(()) => {
                assert_eq!(std::fs::read_to_string(a.join("new")).unwrap(), "new");
                assert_eq!(std::fs::read_to_string(b.join("old")).unwrap(), "old");
            }
            Err(e) => {
                // Some filesystems reject RENAME_EXCHANGE; the rollback
                // path falls back. The call itself must not panic.
                assert!(e.raw_os_error().is_some(), "{e}");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn volume_refs_include_quarantine() {
        let mut st = State {
            images: BTreeMap::new(),
            pods: BTreeMap::new(),
            volumes: BTreeMap::new(),
            quarantined: vec![crate::state::QuarantinedConf {
                name: "held".into(),
                reason: "bad".into(),
                net_index: 3,
                volumes: vec!["pg:/var/lib/pg".into()],
            }],
            reserved_net: BTreeSet::new(),
        };
        st.pods.insert(
            "live".into(),
            PodMeta {
                volumes: vec!["other:/x".into()],
                ..meta_plain("live")
            },
        );
        assert_eq!(volume_refs(&st, "pg"), vec!["held".to_string()]);
        assert!(volume_refs(&st, "missing").is_empty());
        assert!(!op_slot_unreferenced(2));
        assert!(op_slot_unreferenced(1));
    }

    #[test]
    fn supervisor_idle_unless_stopped() {
        // Never started: nothing to restart.
        assert!(supervisor_idle(false, false, false));
        // User stop, including the in-memory mirror before the conf write.
        assert!(supervisor_idle(true, true, false));
        assert!(supervisor_idle(true, false, true));
        // Crash or daemon restart with no user stop: death-watch may restart.
        assert!(!supervisor_idle(true, false, false));
    }

    #[tokio::test]
    async fn inflight_drain_wakes_on_last_guard() {
        let inflight = super::Inflight::new();
        let guards: Vec<_> = (0..16).map(|_| inflight.enter()).collect();
        let waiter = {
            let inflight = std::sync::Arc::clone(&inflight);
            tokio::spawn(async move { inflight.drained().await })
        };
        for g in guards {
            tokio::task::yield_now().await;
            drop(g);
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("drain must finish once the last guard drops")
            .unwrap();
    }

    #[test]
    fn restart_policy_rules() {
        let mut m = meta_plain("p");
        assert_eq!(restart_policy(&m), "no");
        m.restart = "no".into();
        assert_eq!(restart_policy(&m), "no");
        m.restart = "on-failure".into();
        assert_eq!(restart_policy(&m), "on-failure");
        m.restart = "always".into();
        assert_eq!(restart_policy(&m), "always");
        // Garbage in a hand-edited conf degrades to "no"...
        m.restart = "bogus".into();
        assert_eq!(restart_policy(&m), "no");
        // ...but the managed gateway is always "always".
        m.restart = "bogus".into();
        m.ingress_gateway = true;
        assert_eq!(restart_policy(&m), "always");
    }

    #[test]
    fn supervised_selection() {
        let mut m = meta_plain("p");
        assert!(!supervised(&m));
        m.restart = "on-failure".into();
        assert!(supervised(&m));
        m.restart = String::new();
        m.healthcheck.kind = "tcp".into();
        assert!(supervised(&m));
        m.healthcheck.kind = String::new();
        m.ingress_gateway = true;
        assert!(supervised(&m));
    }

    #[test]
    fn probe_addr_resolution() {
        let mut m = meta_plain("p");
        // No private net → ":port" has nothing to dial.
        assert!(probe_addr(&m, ":8080").is_none());
        // Explicit numeric host:port works regardless.
        assert_eq!(
            probe_addr(&m, "127.0.0.1:9090").unwrap().to_string(),
            "127.0.0.1:9090"
        );
        m.net_index = 7;
        assert_eq!(
            probe_addr(&m, ":8080").unwrap().to_string(),
            "10.220.7.2:8080"
        );
        assert!(probe_addr(&m, ":notaport").is_none());
    }

    fn rule(host: &str) -> IngressRule {
        IngressRule {
            host: host.into(),
            pod_port: 80,
        }
    }

    #[test]
    fn ingress_conflicts() {
        let mut st = State {
            images: BTreeMap::new(),
            pods: BTreeMap::new(),
            volumes: BTreeMap::new(),
            quarantined: Vec::new(),
            reserved_net: BTreeSet::new(),
        };
        st.pods.insert(
            "taken".into(),
            meta_with_ingress("taken", &["web.rustypods.localhost"]),
        );
        // A fresh host for a new pod is fine.
        assert!(validate_ingress_conflicts(&st, "new", &[rule("api.rustypods.localhost")]).is_ok());
        // Same host on another persisted pod — even stopped — conflicts.
        let e = validate_ingress_conflicts(&st, "new", &[rule("web.rustypods.localhost")]);
        assert!(e.is_err_and(|s| s.code() == tonic::Code::AlreadyExists));
        // Keeping your own rules on update is not a conflict.
        assert!(
            validate_ingress_conflicts(&st, "taken", &[rule("web.rustypods.localhost")]).is_ok()
        );
        // Duplicate hosts inside one request.
        let e = validate_ingress_conflicts(
            &st,
            "new",
            &[
                rule("api.rustypods.localhost"),
                rule("api.rustypods.localhost"),
            ],
        );
        assert!(e.is_err_and(|s| s.code() == tonic::Code::InvalidArgument));
        // Bad grammar is rejected before any state comparison.
        let e = validate_ingress_conflicts(&st, "new", &[rule("UPPER.rustypods.localhost")]);
        assert!(e.is_err_and(|s| s.code() == tonic::Code::InvalidArgument));
    }

    #[test]
    fn ingress_conflicts_excluding_desired_members() {
        let mut st = State {
            images: BTreeMap::new(),
            pods: BTreeMap::new(),
            volumes: BTreeMap::new(),
            quarantined: Vec::new(),
            reserved_net: BTreeSet::new(),
        };
        // Persisted: stack member web owns a.host, api owns b.host.
        st.pods.insert(
            "s-web".into(),
            meta_with_ingress("s-web", &["a.rustypods.localhost"]),
        );
        st.pods.insert(
            "s-api".into(),
            meta_with_ingress("s-api", &["b.rustypods.localhost"]),
        );
        st.pods.insert(
            "outside".into(),
            meta_with_ingress("outside", &["c.rustypods.localhost"]),
        );
        let desired: BTreeSet<String> = ["s-web".to_string(), "s-api".to_string()]
            .into_iter()
            .collect();
        // Desired swap (web↔api hosts) passes — sibling stale rules are
        // ignored while the atomic desired set is applied.
        assert!(validate_ingress_conflicts_excluding(
            &st,
            "s-web",
            &[rule("b.rustypods.localhost")],
            &desired
        )
        .is_ok());
        assert!(validate_ingress_conflicts_excluding(
            &st,
            "s-api",
            &[rule("a.rustypods.localhost")],
            &desired
        )
        .is_ok());
        // An outside pod's claim still conflicts.
        let e = validate_ingress_conflicts_excluding(
            &st,
            "s-web",
            &[rule("c.rustypods.localhost")],
            &desired,
        );
        assert!(e.is_err_and(|s| s.code() == tonic::Code::AlreadyExists));
    }

    #[test]
    fn gc_keep_last_counts_from_newest() {
        // idx 0 is the newest snapshot.
        assert!(!snapshot_expired(0, 0, 2, 0, 1_000_000));
        assert!(!snapshot_expired(1, 0, 2, 0, 1_000_000));
        assert!(snapshot_expired(2, 0, 2, 0, 1_000_000));
        assert!(snapshot_expired(5, 0, 2, 0, 1_000_000));
        // keep_last = 0 → count criterion disabled.
        assert!(!snapshot_expired(99, 0, 0, 0, 1_000_000));
    }

    #[test]
    fn gc_max_age_uses_creation_time() {
        let now = 1_000_000u64;
        assert!(!snapshot_expired(0, now - 100, 0, 86400, now));
        assert!(snapshot_expired(0, now - 90000, 0, 86400, now));
        // Exactly at the boundary is kept (strictly older than max_age).
        assert!(!snapshot_expired(0, now - 86400, 0, 86400, now));
        // max_age = 0 → age criterion disabled.
        assert!(!snapshot_expired(0, 1, 0, 0, now));
    }

    #[test]
    fn gc_criteria_are_a_union() {
        let now = 1_000_000u64;
        // New snapshot but index beyond keep_last → deleted.
        assert!(snapshot_expired(3, now, 3, 86400, now));
        // Old snapshot inside keep_last → deleted.
        assert!(snapshot_expired(0, now - 99999, 3, 86400, now));
        // New and inside keep_last → kept.
        assert!(!snapshot_expired(1, now - 100, 3, 86400, now));
        // Neither configured → nothing collected.
        assert!(!snapshot_expired(50, 1, 0, 0, now));
    }

    /// A stand-in engine that records start/stop. Lifecycle must refuse a
    /// start while the pod is already up, and a stop must reach the engine.
    #[tokio::test]
    async fn mock_engine_gates_start_and_records_stop() {
        use std::sync::atomic::{AtomicU32, Ordering as Atom};
        struct Rec {
            log: Arc<Mutex<Vec<&'static str>>>,
            pid: AtomicU32,
        }
        #[tonic::async_trait]
        impl RuntimeEngine for Rec {
            fn name(&self) -> &'static str {
                "rec"
            }
            async fn start(&self, _: &crate::runtime::StartSpec, _: &LimitsSpec) -> Result<u32> {
                self.log.lock().await.push("start");
                Ok(1)
            }
            async fn stop(&self, _: &str, _: Duration) -> Result<()> {
                self.log.lock().await.push("stop");
                self.pid.store(0, Atom::SeqCst);
                Ok(())
            }
            async fn running_pid(&self, _: &str) -> Option<u32> {
                let p = self.pid.load(Atom::SeqCst);
                (p != 0).then_some(p)
            }
            async fn registered(&self, _: &str) -> Result<bool> {
                Ok(self.pid.load(Atom::SeqCst) != 0)
            }
            async fn apply_limits(&self, _: &str, _: &LimitsSpec) -> Result<()> {
                Ok(())
            }
            async fn healthy(&self) -> bool {
                true
            }
        }
        let dir = std::env::temp_dir().join(format!("rp-mock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut svc = Svc::stub(dir.clone());
        let log = Arc::new(Mutex::new(Vec::new()));
        svc.engine = Arc::new(Rec {
            log: log.clone(),
            pid: AtomicU32::new(0),
        });
        let missing = svc
            .start_pod(Request::new(StartPodRequest {
                name: "missing".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::NotFound);
        assert!(log.lock().await.is_empty());

        {
            let mut st = svc.st.lock().await;
            st.pods.insert("web".into(), meta_plain("web"));
        }
        // Not running: a start would reach the engine. Pretend it is up.
        svc.engine = Arc::new(Rec {
            log: log.clone(),
            pid: AtomicU32::new(42),
        });
        let busy = svc
            .start_pod(Request::new(StartPodRequest {
                name: "web".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(busy.code(), tonic::Code::FailedPrecondition);
        assert!(
            log.lock().await.is_empty(),
            "start must not reach the engine"
        );

        svc.stop_pod(Request::new(PodRef { name: "web".into() }))
            .await
            .unwrap();
        assert_eq!(log.lock().await.as_slice(), ["stop"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn receive_volume_tar_lands_and_registers() {
        use rustypods_proto::rpc::volume_chunk::Kind as VolKind;
        let dir = std::env::temp_dir().join(format!("rp-vrecv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut svc = Svc::stub(dir.clone());
        // A real directory driver — NopStore never makes the dst tree.
        svc.storage = crate::storage::detect(&dir);
        assert_eq!(svc.storage.name(), "reflink-copy");

        // tar of `hello-vol/hello.txt` — the stream a peer would send.
        let mut tarbuf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tarbuf);
            let mut h = tar::Header::new_gnu();
            let data = b"cluster-data";
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "hello-vol/hello.txt", &data[..])
                .unwrap();
            b.finish().unwrap();
        }
        let chunks: Vec<Result<VolumeChunk, Status>> = vec![
            Ok(VolumeChunk {
                kind: Some(VolKind::Init(VolumeInit {
                    name: "hello-vol".into(),
                    format: "tar".into(),
                    force: false,
                })),
            }),
            Ok(VolumeChunk {
                kind: Some(VolKind::Data(tarbuf)),
            }),
        ];
        let res = svc
            .receive_volume(tokio_stream::iter(chunks))
            .await
            .expect("receive_volume failed");
        assert_eq!(res.name, "hello-vol");
        let landed = proto::volumes_dir(&dir).join("hello-vol/hello.txt");
        assert_eq!(std::fs::read(&landed).unwrap(), b"cluster-data");
        assert!(svc.st.lock().await.volumes.contains_key("hello-vol"));
        // A second send without force must refuse, not overwrite.
        let chunks2: Vec<Result<VolumeChunk, Status>> = vec![Ok(VolumeChunk {
            kind: Some(VolKind::Init(VolumeInit {
                name: "hello-vol".into(),
                format: "tar".into(),
                force: false,
            })),
        })];
        let err = svc
            .receive_volume(tokio_stream::iter(chunks2))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn apply_stack_rejects_placement_key() {
        let dir = std::env::temp_dir().join(format!("rp-stackpl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("images/img")).unwrap();
        let svc = Svc::stub(dir.clone());
        let toml = br#"name = "shop"
[pods.web]
image = "img"
placement = "s2"
"#
        .to_vec();
        let err = svc
            .apply_stack_work(Request::new(ApplyStackRequest { toml }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("placement"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
