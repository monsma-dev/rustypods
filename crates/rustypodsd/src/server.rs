//! tonic server on a Unix socket. Peer credentials gate access:
//! uid 0 or Config::allowed_uid may connect; everyone else is dropped.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::process::{Command as SyncCommand, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
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
use crate::state::{self, ImageMeta, IngressSpec, LimitsSpec, PodMeta, State};
use crate::storage::StorageDriver;
use crate::{exec, ingress, net, pki, runtime, stack, storage, Config};

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
    /// stack member ops must never interleave on the same pod name. Entries
    /// are never evicted — keyed by ≤32-char pod names, a few bytes each.
    ops: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
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
    ingress_last_push: Arc<Mutex<Option<(u64, Vec<ActiveIngressRoute>)>>>,
    /// Per-pod supervisor state for liveness probes and restarts.
    /// Entries exist only while a pod is under supervision (running
    /// with a restart policy or a configured probe).
    health: Arc<Mutex<HashMap<String, PodHealth>>>,
    /// Pods stopped on purpose via stop_pod — the supervisor must not
    /// restart these. PodMeta.started means "was ever started" (display
    /// state), not "should be running", so intent lives here. In-memory:
    /// a daemon restart clears it, matching Docker's "always" semantics
    /// (a dead should-be-running pod comes back).
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

fn to_pod(m: &PodMeta, rootfs: &Path, leader: Option<u32>, health: &str) -> Pod {
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
    })
    .unwrap_or_default()
}

/// rpc::HealthCheck → persisted HealthSpec, validating first so a
/// malformed probe can never reach the conf. "none" normalizes to "".
fn health_from_proto(h: &HealthCheck) -> Result<state::HealthSpec> {
    proto::validate_healthcheck(h)?;
    let kind = if h.kind == "none" { "" } else { h.kind.as_str() };
    Ok(state::HealthSpec {
        kind: kind.into(),
        target: h.target.trim().into(),
        argv: h.argv.clone(),
        interval_secs: h.interval_secs,
        timeout_secs: h.timeout_secs,
        retries: h.retries,
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

/// ":port" or a bare "port" → the pod's own veth address; "host:port"
/// (numeric) → verbatim. None when the pod has no private-net address
/// to probe.
fn probe_addr(m: &PodMeta, target: &str) -> Option<std::net::SocketAddr> {
    let t = target.trim();
    let bare = t.parse::<u16>().ok().map(|p| format!(":{p}"));
    let t = bare.as_deref().unwrap_or(t);
    match t.strip_prefix(':') {
        Some(p) if m.net_index > 0 => {
            Some((net::pod_ip(m.net_index), p.parse().ok()?).into())
        }
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
        v.iter()
            .map(|i| (i.host.as_str(), i.pod_port))
            .collect()
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
    async fn pod_op(&self, name: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let m = {
            let mut ops = self.ops.lock().await;
            ops.entry(name.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        m.lock_owned().await
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
        let (s, a, b) = (
            self.storage.clone(),
            src.to_path_buf(),
            dst.to_path_buf(),
        );
        Self::blocking(move || s.clone_rootfs(&a, &b)).await
    }
    async fn st_delete(&self, path: &Path) -> Result<(), Status> {
        let (s, p) = (self.storage.clone(), path.to_path_buf());
        Self::blocking(move || s.delete_rootfs(&p)).await
    }

    /// <data>/snapshots/<pod>/ — one subvolume per commit.
    fn snaps_dir(&self, pod: &str) -> std::path::PathBuf {
        self.cfg.data_dir.join("snapshots").join(pod)
    }

    /// Scan a pod's snapshot dir, newest first.
    fn snapshots(&self, pod: &str) -> Vec<Snapshot> {
        let dir = self.snaps_dir(pod);
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let id = e.file_name().to_string_lossy().into_owned();
                let (ts, label) = match id.split_once('-') {
                    Some((t, l)) => (t.parse().unwrap_or(0), l.to_string()),
                    None => (id.parse().unwrap_or(0), String::new()),
                };
                out.push(Snapshot {
                    id,
                    pod: pod.to_string(),
                    created_unix: ts,
                    path: e.path().display().to_string(),
                    label,
                });
            }
        }
        out.sort_by(|a, b| b.created_unix.cmp(&a.created_unix));
        out
    }

    /// Latest agent-pushed metric for a pod (REST /metrics). None when the
    /// agent never connected — a real sample always has ts_unix_ms > 0.
    pub(crate) async fn latest_metric(&self, pod: &str) -> Option<Metric> {
        self.metrics
            .lock()
            .await
            .get(pod)
            .map(|tx| tx.borrow().clone())
            .filter(|m| m.ts_unix_ms > 0)
    }

    /// One snapshot-GC sweep: per-pod retention from the conf (keep_last
    /// count cap and/or max_age) applied to snapshots/<pod>/, newest first.
    async fn gc_snapshots(&self) {
        let pods: Vec<PodMeta> = {
            let st = self.st.lock().await;
            st.pods
                .values()
                .filter(|m| m.snap_keep_last > 0 || m.snap_max_age_secs > 0)
                .cloned()
                .collect()
        };
        let now = state::now_unix();
        for m in pods {
            // Serialize against commit/rollback/delete_snapshot on the same
            // pod — they mutate snapshots/<pod>/ concurrently. A busy pod
            // just waits for the next sweep.
            let Some(_op) = self.try_pod_op(&m.name).await else {
                continue;
            };
            for (i, s) in self.snapshots(&m.name).iter().enumerate() {
                if snapshot_expired(i, s.created_unix, m.snap_keep_last, m.snap_max_age_secs, now) {
                    match self.st_delete(Path::new(&s.path)).await {
                        Ok(()) => tracing::info!("gc: deleted snapshot {} of pod {}", s.id, m.name),
                        Err(e) => {
                            tracing::warn!("gc: snapshot {} of pod {}: {e:#}", s.id, m.name)
                        }
                    }
                }
            }
        }
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

    /// Supervisor health string for Pod.health — "" when the pod isn't
    /// under supervision (stopped, or no probe and no restart policy).
    async fn health_view(&self, name: &str) -> String {
        self.health
            .lock()
            .await
            .get(name)
            .map(|h| h.status)
            .unwrap_or("")
            .to_string()
    }

    /// One supervisor tick: death-watch + liveness probes for every pod
    /// that opted in (restart policy or healthcheck) plus the managed
    /// gateway. Per-pod failures are logged, never fatal to the loop.
    async fn supervise_once(&self) {
        let pods: Vec<PodMeta> = {
            let st = self.st.lock().await;
            st.pods.values().filter(|m| supervised(m)).cloned().collect()
        };
        let now = std::time::Instant::now();
        for m in &pods {
            if let Err(e) = self.supervise_pod(m, now).await {
                tracing::warn!("supervise {}: {e:#}", m.name);
            }
        }
    }

    /// Supervise one pod: restart on leader death per its policy, run
    /// the configured probe when due, restart on sustained failure under
    /// "always". Decisions are taken under the health lock; the actions
    /// themselves run after it drops (start/stop re-enter health_view).
    async fn supervise_pod(&self, m: &PodMeta, now: std::time::Instant) -> Result<()> {
        enum Act {
            Idle,
            /// Leader died — restart via start_pod.
            Restart,
            /// Probe due — spec cloned out so the lock isn't held over .await.
            Probe(state::HealthSpec),
        }
        let policy = restart_policy(m);
        let running = self.engine.running_pid(&m.name).await.is_some();
        let act = {
            let mut map = self.health.lock().await;
            if !running
                && (!m.started || self.stop_intent.lock().await.contains(&m.name))
            {
                // Never booted, or stopped on purpose — nothing to watch
                // until a start (re)arms the death-watch.
                map.remove(&m.name);
                Act::Idle
            } else {
                let ent = map.entry(m.name.clone()).or_insert_with(|| PodHealth {
                    status: "starting",
                    fails: 0,
                    last_probe: now,
                    restart_count: 0,
                    backoff_until: None,
                    healthy_since: now,
                });
                if !running {
                    // No stop intent but the leader is gone → death-watch.
                    match policy {
                        "no" => {
                            ent.status = "dead";
                            Act::Idle
                        }
                        _ if ent.backoff_until.is_some_and(|t| now < t) => Act::Idle,
                        _ => Act::Restart,
                    }
                } else if m.healthcheck.kind.is_empty() {
                    // No probe: alive ⇒ healthy; decay backoff after a
                    // minute of uninterrupted health.
                    if ent.status != "healthy" {
                        ent.healthy_since = now;
                    } else if now.duration_since(ent.healthy_since) >= Duration::from_secs(60) {
                        ent.restart_count = 0;
                    }
                    ent.status = "healthy";
                    ent.fails = 0;
                    Act::Idle
                } else {
                    let secs = if m.healthcheck.interval_secs == 0 {
                        10
                    } else {
                        m.healthcheck.interval_secs.max(1)
                    } as u64;
                    if now.duration_since(ent.last_probe) >= Duration::from_secs(secs) {
                        ent.last_probe = now;
                        Act::Probe(m.healthcheck.clone())
                    } else {
                        Act::Idle
                    }
                }
            }
        };
        match act {
            Act::Idle => Ok(()),
            Act::Restart => self.supervised_restart(m, "leader died").await,
            Act::Probe(spec) => {
                let ok = self.probe(m, &spec).await;
                let mut do_restart = false;
                {
                    let mut map = self.health.lock().await;
                    if let Some(ent) = map.get_mut(&m.name) {
                        if ok {
                            if ent.status != "healthy" {
                                ent.healthy_since = std::time::Instant::now();
                            }
                            ent.status = "healthy";
                            ent.fails = 0;
                            if ent.healthy_since.elapsed() >= Duration::from_secs(60) {
                                ent.restart_count = 0;
                            }
                        } else {
                            ent.fails += 1;
                            let retries = if spec.retries == 0 { 3 } else { spec.retries };
                            if ent.fails >= retries {
                                ent.status = "unhealthy";
                                do_restart = policy == "always";
                            } else {
                                ent.status = "starting";
                            }
                        }
                    }
                }
                if do_restart {
                    self.supervised_restart(m, "probe unhealthy").await
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Restart a pod that died or went unhealthy. Goes through the real
    /// RPCs so op-locking, state flags and NAT behave exactly like a
    /// manual stop+start. Backoff is 2^n s per consecutive attempt
    /// (cap 60s) and decays after a minute of sustained health.
    async fn supervised_restart(&self, m: &PodMeta, why: &str) -> Result<()> {
        tracing::warn!("{}: {why} — restarting (policy {})", m.name, restart_policy(m));
        if self.engine.running_pid(&m.name).await.is_some() {
            if let Err(e) = self
                .stop_pod(Request::new(PodRef {
                    name: m.name.clone(),
                }))
                .await
            {
                tracing::warn!("{}: pre-restart stop failed: {e}", m.name);
            }
        }
        let attempt = self
            .start_pod(Request::new(StartPodRequest {
                name: m.name.clone(),
                limits: None,
                ephemeral: false,
                private_users: None,
            }))
            .await;
        {
            let mut map = self.health.lock().await;
            if let Some(ent) = map.get_mut(&m.name) {
                ent.restart_count = ent.restart_count.saturating_add(1);
                let secs = (1u64 << ent.restart_count.min(6)).min(60);
                ent.backoff_until =
                    Some(std::time::Instant::now() + Duration::from_secs(secs));
                ent.status = "starting";
                ent.fails = 0;
                ent.healthy_since = std::time::Instant::now();
                ent.last_probe = std::time::Instant::now();
            }
        }
        match attempt {
            Ok(_) => {
                tracing::info!("{}: restarted ({why})", m.name);
                Ok(())
            }
            Err(e) => {
                // Backoff is already recorded — a later tick retries.
                tracing::warn!("{}: restart failed ({why}): {e}", m.name);
                Ok(())
            }
        }
    }

    /// Run one liveness probe; true = healthy. Any error or timeout is
    /// a failure.
    async fn probe(&self, m: &PodMeta, spec: &state::HealthSpec) -> bool {
        let timeout = Duration::from_secs(if spec.timeout_secs == 0 {
            3
        } else {
            spec.timeout_secs
        } as u64);
        match spec.kind.as_str() {
            "exec" => self.probe_exec(m, spec, timeout).await,
            "tcp" => self.probe_tcp(m, &spec.target, timeout).await,
            "http" => self.probe_http(m, &spec.target, timeout).await,
            _ => true,
        }
    }

    /// exec probe: run argv inside the pod via the same nsenter+setpriv
    /// path as `rustypods exec` — exit 0 = healthy.
    async fn probe_exec(&self, m: &PodMeta, spec: &state::HealthSpec, timeout: Duration) -> bool {
        let Some(leader) = self.engine.running_pid(&m.name).await else {
            return false;
        };
        let start = ExecStart {
            pod: m.name.clone(),
            user: String::new(), // root
            argv: spec.argv.clone(),
            tty: false,
            rows: 0,
            cols: 0,
            env: vec![],
            workdir: String::new(),
        };
        let argv = match exec::exec_argv(leader, &self.pod_rootfs(&m.name), &start, m.private_users)
        {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("{}: exec probe argv: {e:#}", m.name);
                return false;
            }
        };
        // Same spawn discipline as exec.rs run_pipe: pre_exec preserves
        // stdin on STDIN_DUP_FD — without it the argv's `exec 0<&N`
        // wrapper fails and every probe exits non-zero.
        let mut scmd = std::process::Command::new(&argv[0]);
        scmd.args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            use std::os::unix::process::CommandExt;
            scmd.pre_exec(exec::preserve_stdin);
        }
        let mut cmd = tokio::process::Command::from(scmd);
        cmd.kill_on_drop(true);
        match tokio::time::timeout(timeout, cmd.status()).await {
            Ok(Ok(s)) => s.success(),
            _ => false,
        }
    }

    /// tcp probe: a completed connect = healthy. ":port" targets the
    /// pod's own veth address; "host:port" is dialed verbatim.
    async fn probe_tcp(&self, m: &PodMeta, target: &str, timeout: Duration) -> bool {
        let Some(addr) = probe_addr(m, target) else {
            return false;
        };
        matches!(
            tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await,
            Ok(Ok(_))
        )
    }

    /// http probe: plain HTTP/1.1 GET — 2xx/3xx = healthy. "/path"
    /// targets the pod's own veth address :80; a full
    /// "http://host[:port]/path" URL is dialed verbatim (numeric hosts
    /// only — the daemon never resolves DNS).
    async fn probe_http(&self, m: &PodMeta, target: &str, timeout: Duration) -> bool {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let t = target.trim();
        let (addr, req_path, host) = if t.starts_with('/') {
            if m.net_index == 0 {
                return false;
            }
            let ip = net::pod_ip(m.net_index);
            (
                std::net::SocketAddr::from((ip, 80)),
                t.to_string(),
                ip.to_string(),
            )
        } else {
            let Ok(uri) = t.parse::<http::Uri>() else {
                return false;
            };
            let Some(auth) = uri.authority() else {
                return false;
            };
            let host = auth.host().to_string();
            let Ok(ip) = host.parse::<std::net::IpAddr>() else {
                return false;
            };
            (
                std::net::SocketAddr::new(ip, auth.port_u16().unwrap_or(80)),
                uri.path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/")
                    .to_string(),
                host,
            )
        };
        let fut = async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
            let req = format!(
                "GET {req_path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rustypodsd-probe\r\nConnection: close\r\n\r\n"
            );
            s.write_all(req.as_bytes()).await.ok()?;
            let mut buf = [0u8; 256];
            let n = s.read(&mut buf).await.ok()?;
            let head = std::str::from_utf8(&buf[..n]).ok()?;
            let code: u16 = head.split_whitespace().nth(1)?.parse().ok()?;
            Some((200..400).contains(&code))
        };
        matches!(tokio::time::timeout(timeout, fut).await, Ok(Some(true)))
    }

    /// Current running set from the engine's point of view.
    async fn running_set(&self) -> BTreeSet<String> {
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
        running
    }

    /// Push the complete route snapshot to the ingress gateway, if it is
    /// configured and running. `exclude` is treated as non-running (a pod
    /// being drained before stop/destroy). `required` makes the absence of
    /// a usable control endpoint fail instead of degrading to a warning —
    /// a silent skip would leave stale routes pointing at reused IPs.
    async fn sync_ingress(&self, exclude: Option<&str>, required: bool) -> Result<(), Status> {
        // See ingress_mu: build inside the lock so a snapshot can never
        // carry pre-lock state past a newer push.
        let _push = self.ingress_mu.lock().await;
        let pods: Vec<PodMeta> = {
            let st = self.st.lock().await;
            st.pods.values().cloned().collect()
        };
        let gateway_configured = pods.iter().any(|m| m.ingress_gateway);
        let running = self.running_set().await;
        let gw_running = running.contains(proto::INGRESS_POD);
        let generation = self.ingress_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let snap =
            ingress::build_snapshot(pods.iter().collect(), &running, exclude, generation)
                .map_err(int)?;
        let want_routes = !snap.routes.is_empty();
        if !gateway_configured {
            if want_routes && required {
                return Err(Status::failed_precondition(
                    "pods have ingress rules but the gateway isn't initialized — run `rustypods ingress init` and start it",
                ));
            }
            return Ok(());
        }
        if !gw_running {
            let msg = "ingress gateway configured but not running — start it (`rustypods start rustypods-ingress`)";
            return Err(if required {
                Status::failed_precondition(msg)
            } else {
                Status::unavailable(msg)
            });
        }
        // Steady state: if the gateway verifiably still holds the exact
        // table we last pushed, skip the commit entirely — otherwise a
        // 2s reconciler tick burns a UDS round-trip + dataplane commit +
        // log line forever. A restarted gateway reports a different
        // generation and gets the full push.
        let last_gen = {
            let last = self.ingress_last_push.lock().await;
            match &*last {
                Some((g, pushed)) if *pushed == snap.routes => Some(*g),
                _ => None,
            }
        };
        if let Some(g) = last_gen {
            if matches!(
                ingress::gateway_status(&self.cfg.data_dir).await,
                Ok(s) if s.generation == g
            ) {
                return Ok(());
            }
        }
        ingress::push_snapshot(&self.cfg.data_dir, snap.clone())
            .await
            .map_err(|e| {
                if required {
                    Status::failed_precondition(format!("{e:#}"))
                } else {
                    Status::unavailable(format!("{e:#}"))
                }
            })?;
        *self.ingress_last_push.lock().await = Some((generation, snap.routes));
        Ok(())
    }

    /// Wait until the gateway's control UDS answers GetStatus — the
    /// dataplane needs a moment inside the pod to bind its socket.
    async fn wait_ingress_ready(&self) -> Result<(), Status> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            match ingress::gateway_status(&self.cfg.data_dir).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(Status::failed_precondition(format!(
                            "ingress control socket never came up: {e:#}"
                        )));
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
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
        }))
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
            return Err(Status::already_exists(format!("image {name} already exists")));
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
            return Err(Status::already_exists(format!("image {name} already exists")));
        }
        self.st_create(&dest).await?;
        let cfg = match oci::pull(&req.reference, &dest).await {
            Ok(c) => c,
            Err(e) => {
                let _ = self.st_delete(&dest).await;
                return Err(int(e));
            }
        };
        let meta = ImageMeta {
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
        state::remove_image(&self.cfg.data_dir, &name);
        Ok(Response::new(Empty {}))
    }

    async fn create_pod(&self, req: Request<CreatePodRequest>) -> Result<Response<Pod>, Status> {
        let req = req.into_inner();
        let name = proto::validate_name(&req.name).map_err(bad)?.to_string();
        if name == proto::INGRESS_POD {
            return Err(Status::failed_precondition(
                "{name} is reserved — use `rustypods ingress init`",
            ));
        }
        let _op = self.pod_op(&name).await;
        let image = proto::validate_name(&req.image).map_err(bad)?.to_string();
        let img_dir = self.cfg.images_dir().join(&image);
        if !img_dir.is_dir() {
            return Err(Status::not_found(format!("image {image} not found")));
        }
        let dest = self.pod_rootfs(&name);
        if dest.exists() {
            return Err(Status::already_exists(format!("pod {name} already exists")));
        }
        for p in &req.ports {
            proto::validate_port(p).map_err(bad)?;
        }
        {
            let st = self.st.lock().await;
            validate_host_ports(&st, &name, "", &req.ports)?;
            validate_ingress_conflicts(&st, &name, &req.ingress)?;
        }
        for b in &req.binds {
            proto::validate_bind(b).map_err(bad)?;
        }
        let mut binds = req.binds.clone();
        if req.desktop {
            for d in self.desktop_binds()? {
                if !binds.contains(&d) {
                    binds.push(d);
                }
            }
        }
        if !req.cmd.is_empty() {
            proto::validate_argv(&req.cmd).map_err(bad)?;
        }
        proto::validate_restart(&req.restart).map_err(bad)?;
        let hc = req
            .healthcheck
            .as_ref()
            .map(health_from_proto)
            .transpose()
            .map_err(bad)?
            .unwrap_or_default();
        if let Err(e) = self.st_clone(&img_dir, &dest).await {
            // A partial dest (fallback cp died mid-copy) would wedge the
            // name on "already exists" forever — clean it like pull/import.
            let _ = self.st_delete(&dest).await;
            return Err(e);
        }
        let meta = PodMeta {
            name: name.clone(),
            image,
            created_unix: state::now_unix(),
            limits: limits_from(req.limits),
            ephemeral: false,
            // userns on by default; desktop pods share the home dir and need
            // host-uid identity, so they opt out.
            private_users: !req.desktop,
            started: false,
            storage_max_bytes: req.storage_max_bytes,
            ports: req.ports.clone(),
            ingress: ingress_from_proto(&req.ingress),
            net_index: 0,
            stack: String::new(),
            binds,
            snap_keep_last: 0,
            snap_max_age_secs: 0,
            autostart: req.autostart,
            cmd: req.cmd.clone(),
            ingress_gateway: false,
            restart: req.restart.clone(),
            healthcheck: hc,
        };
        let mut st = self.st.lock().await;
        if let Err(e) = validate_ingress_conflicts(&st, &name, &ingress_to_proto(&meta.ingress)) {
            // A racing create claimed a host after the early check — drop
            // the freshly cloned rootfs rather than wedging the name.
            drop(st);
            let _ = self.st_delete(&dest).await;
            return Err(e);
        }
        st.pods.insert(name.clone(), meta.clone());
        drop(st);
        self.save_pod(&meta).map_err(int)?;
        Ok(Response::new(to_pod(&meta, &dest, None, "")))
    }

    /// `rustypods clone <src> <dest>`: instant btrfs snapshot of the pod
    /// rootfs + a copied conf with fresh identity. Cloning a running pod is
    /// allowed (subvolume snapshot is atomic) but the runtime state is
    /// reset — the clone starts stopped.
    async fn clone_pod(&self, req: Request<ClonePodRequest>) -> Result<Response<Pod>, Status> {
        let req = req.into_inner();
        let src = proto::validate_name(&req.source).map_err(bad)?.to_string();
        let dest = proto::validate_name(&req.dest).map_err(bad)?.to_string();
        // The reserved name may only come from `ingress init` — a cloned
        // conf here would have ingress_gateway=false and fail the next
        // state load outright.
        if dest == proto::INGRESS_POD {
            return Err(Status::failed_precondition(format!(
                "{dest} is reserved — use `rustypods ingress init`"
            )));
        }
        // Cloning the gateway would propagate its provisioned TLS key and
        // the managed identity into an ordinary pod — refuse.
        if src == proto::INGRESS_POD {
            return Err(Status::failed_precondition(format!(
                "{src} is the managed ingress gateway — it cannot be cloned"
            )));
        }
        // Source must exist before we touch the append-only ops map.
        {
            let st = self.st.lock().await;
            if !st.pods.contains_key(&src) {
                return Err(Status::not_found(format!("pod {src} not found")));
            }
        }
        // Lock both names, sorted — unordered acquisition would let
        // `clone a→b` racing `clone b→a` deadlock.
        let (first, second) = if src <= dest {
            (src.clone(), dest.clone())
        } else {
            (dest.clone(), src.clone())
        };
        let _g1 = self.pod_op(&first).await;
        let _g2 = if second != first {
            Some(self.pod_op(&second).await)
        } else {
            None
        };
        let meta = {
            let st = self.st.lock().await;
            let Some(m) = st.pods.get(&src) else {
                return Err(Status::not_found(format!("pod {src} not found")));
            };
            m.clone()
        };
        if self.engine.running_pid(&src).await.is_some() {
            tracing::warn!("cloning running pod {src} — snapshot is atomic but mid-write state is live");
        }
        let dst_root = self.pod_rootfs(&dest);
        if dst_root.exists() {
            return Err(Status::already_exists(format!("pod {dest} already exists")));
        }
        if let Err(e) = self.st_clone(&self.pod_rootfs(&src), &dst_root).await {
            // Same partial-dest cleanup as create/pull — a half-copied
            // rootfs must not wedge the dest name.
            let _ = self.st_delete(&dst_root).await;
            return Err(e);
        }
        let meta = PodMeta {
            name: dest.clone(),
            created_unix: state::now_unix(),
            started: false,
            // Fresh identity: net_index is reallocated on first start so two
            // clones can run side by side. Ports are kept — running BOTH
            // clones with identical host ports is a user-visible conflict.
            // Stack membership is dropped: a clone is standalone, not a
            // silent extra member of the source's shared netns. Ingress
            // hostnames are globally unique — a clone must NOT inherit
            // them, or it would collide with its own source.
            net_index: 0,
            stack: String::new(),
            ingress: vec![],
            // The gateway role is daemon-managed — a clone is never it.
            ingress_gateway: false,
            ..meta
        };
        let mut st = self.st.lock().await;
        st.pods.insert(dest.clone(), meta.clone());
        self.save_pod(&meta).map_err(int)?;
        Ok(Response::new(to_pod(&meta, &dst_root, None, "")))
    }

    /// `rustypods commit <pod> [label]`: atomic CoW snapshot of the live
    /// rootfs into snapshots/<pod>/<ts>[-label]. The live pod keeps running.
    async fn commit_pod(&self, req: Request<CommitPodRequest>) -> Result<Response<Snapshot>, Status> {
        let req = req.into_inner();
        let pod = proto::validate_name(&req.pod).map_err(bad)?.to_string();
        {
            let st = self.st.lock().await;
            if !st.pods.contains_key(&pod) {
                return Err(Status::not_found(format!("pod {pod} not found")));
            }
        }
        let _op = self.pod_op(&pod).await;
        if self.engine.running_pid(&pod).await.is_some() {
            tracing::warn!("commit on running pod {pod} — snapshot is atomic but mid-write state is live");
        }
        let slug = slugify(&req.label);
        let ts = state::now_unix();
        // Snapshot ids carry only second precision — two same-label
        // commits inside one second would collide on the dir name, and a
        // btrfs clone into an existing dir fails. Suffix -2, -3, … until
        // the name is free.
        let base = if slug.is_empty() {
            ts.to_string()
        } else {
            format!("{ts}-{slug}")
        };
        let mut id = base.clone();
        for n in 2..=99u32 {
            if !self.snaps_dir(&pod).join(&id).exists() {
                break;
            }
            id = format!("{base}-{n}");
        }
        let dst = self.snaps_dir(&pod).join(&id);
        if dst.exists() {
            return Err(Status::already_exists(format!(
                "snapshot id '{id}' already exists — wait a second and retry"
            )));
        }
        std::fs::create_dir_all(dst.parent().unwrap()).map_err(int)?;
        self.st_clone(&self.pod_rootfs(&pod), &dst).await?;
        Ok(Response::new(Snapshot {
            id,
            pod,
            created_unix: ts,
            path: dst.display().to_string(),
            label: slug,
        }))
    }

    /// `rustypods rollback <pod> [--to <id>]`: swap the live rootfs for a
    /// commit. The pod is stopped first — rollback discards current state.
    /// The snapshot itself survives (it becomes the new live rootfs' source).
    async fn rollback_pod(&self, req: Request<RollbackPodRequest>) -> Result<Response<Pod>, Status> {
        let req = req.into_inner();
        let pod = proto::validate_name(&req.pod).map_err(bad)?.to_string();
        let meta = {
            let st = self.st.lock().await;
            st.pods.get(&pod).cloned()
        };
        let Some(meta) = meta else {
            return Err(Status::not_found(format!("pod {pod} not found")));
        };
        let _op = self.pod_op(&pod).await;
        if !req.snapshot.is_empty() {
            proto::validate_snapshot_id(&req.snapshot).map_err(bad)?;
        }
        let snaps = self.snapshots(&pod);
        let snap = if req.snapshot.is_empty() {
            snaps.first().cloned()
        } else {
            snaps.iter().find(|s| s.id == req.snapshot).cloned()
        };
        let Some(snap) = snap else {
            return Err(Status::not_found(format!(
                "no snapshot{} for pod {pod}",
                if req.snapshot.is_empty() { "s".to_string() } else { format!(" '{}'", req.snapshot) }
            )));
        };
        self.engine.stop(&pod).await.map_err(int)?; // rollback discards live state
        agent::stop_listener(&self.listeners, &self.metrics, &pod).await;
        let rootfs = self.pod_rootfs(&pod);
        let snap_path = std::path::Path::new(&snap.path);
        // The snapshot may have been GC'd or deleted since we listed it —
        // never touch the live rootfs without a source to clone from.
        if !snap_path.exists() {
            return Err(Status::not_found(format!(
                "snapshot {} of pod {pod} no longer exists on disk",
                snap.id
            )));
        }
        // Clone-then-swap: build the new rootfs next to the live one (same
        // dir = same btrfs fs → clone is CoW), then atomically exchange the
        // two with rename(). A failure before the swap leaves the live pod
        // intact; the previous order (delete, then clone) bricked the pod
        // on any clone error.
        let parent = rootfs
            .parent()
            .unwrap_or_else(|| Path::new("/"))
            .to_path_buf();
        let staging = parent.join(format!("{pod}.rollback-new"));
        let backup = parent.join(format!("{pod}.rollback-old"));
        // Leftovers from a crashed earlier rollback — clear before staging.
        for p in [&staging, &backup] {
            if p.exists() || p.is_symlink() {
                self.st_delete(p).await?;
            }
        }
        self.st_clone(snap_path, &staging).await?;
        if let Err(e) = std::fs::rename(&rootfs, &backup) {
            let _ = self.st_delete(&staging).await;
            return Err(int(e));
        }
        if let Err(e) = std::fs::rename(&staging, &rootfs) {
            // Swap half-done: try to put the original back before reporting.
            let restore_err = std::fs::rename(&backup, &rootfs).err();
            let _ = self.st_delete(&staging).await;
            return Err(int(match restore_err {
                Some(r) => anyhow::anyhow!("{e:#}; restore also failed: {r:#}"),
                None => e.into(),
            }));
        }
        self.st_delete(&backup).await?;
        {
            let mut st = self.st.lock().await;
            if let Some(m) = st.pods.get_mut(&pod) {
                m.started = false;
                let m = m.clone();
                let _ = self.save_pod(&m);
            }
        }
        tracing::info!("rollback {pod} → snapshot {}", snap.id);
        Ok(Response::new(to_pod(&meta, &rootfs, None, &self.health_view(&pod).await)))
    }

    async fn list_snapshots(
        &self,
        req: Request<PodRef>,
    ) -> Result<Response<SnapshotList>, Status> {
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
            return Err(Status::not_found(format!("snapshot '{}' not found", req.id)));
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
        let toml_text = String::from_utf8(req.into_inner().toml)
            .map_err(|e| bad(anyhow::anyhow!("stack file is not UTF-8: {e}")))?;
        let def = {
            let st = self.st.lock().await;
            let img_dir = self.cfg.images_dir();
            stack::parse(&toml_text, |i| {
                st.images.contains_key(i) || img_dir.join(i).is_dir()
            })
            .map_err(bad)?
        };
        // Serialize the whole apply per stack name — two concurrent applies
        // of the same stack could otherwise compute different net indexes
        // and split the members across /30 pairs. The `stack:` prefix keeps
        // this key distinct from a pod literally named after the stack.
        let _stack_op = self.pod_op(&format!("stack:{}", def.name)).await;
        // Desired ingress per member as typed rules (stack::parse already
        // validated grammar + intra-stack dupes; re-parse to get IngressRule).
        let mut member_ingress: std::collections::BTreeMap<String, Vec<IngressRule>> =
            std::collections::BTreeMap::new();
        for (member, sp) in &def.pods {
            let mut rules = Vec::with_capacity(sp.ingress.len());
            for spec in &sp.ingress {
                rules.push(proto::parse_ingress_rule(spec).map_err(bad)?);
            }
            member_ingress.insert(stack::member_name(&def.name, member), rules);
        }
        // A stack/member combo that lands on the reserved gateway name
        // would squat the managed pod — reject the whole apply.
        if member_ingress
            .keys()
            .any(|n| n == proto::INGRESS_POD)
        {
            return Err(Status::failed_precondition(format!(
                "stack member name {} is reserved",
                proto::INGRESS_POD
            )));
        }
        // Hold every desired member's op lock for the WHOLE apply — a
        // direct config/start/destroy on a member mid-apply would
        // interleave with the atomic desired-set write. BTreeMap keys are
        // already sorted, matching the lock-ordering used by destroy_stack.
        let desired_names: Vec<String> = member_ingress.keys().cloned().collect();
        let desired_set: std::collections::BTreeSet<String> =
            desired_names.iter().cloned().collect();
        let mut _member_ops = Vec::with_capacity(desired_names.len());
        for n in &desired_names {
            _member_ops.push(self.pod_op(n).await);
        }
        // Host-port + ingress policy vs everything OUTSIDE this stack
        // before any state changes (stack::parse already deduped within
        // the stack).
        {
            let st = self.st.lock().await;
            for (member, sp) in &def.pods {
                let pname = stack::member_name(&def.name, member);
                validate_host_ports(&st, &pname, &def.name, &sp.ports)?;
            }
            // Ingress hostnames are global — but members of THIS apply are
            // being (re)written, so compare desired rules only against pods
            // outside the apply set, not against members' old persisted
            // rules.
            let mut claimed: std::collections::BTreeMap<&str, &str> =
                std::collections::BTreeMap::new();
            for (pname, rules) in &member_ingress {
                for r in rules {
                    if let Some(other) = claimed.insert(r.host.as_str(), pname.as_str()) {
                        return Err(Status::already_exists(format!(
                            "ingress host '{}' is claimed by both {other} and {pname}",
                            r.host
                        )));
                    }
                }
            }
            for m in st.pods.values() {
                if member_ingress.contains_key(&m.name) {
                    continue;
                }
                for i in &m.ingress {
                    if claimed.contains_key(i.host.as_str()) {
                        return Err(Status::already_exists(format!(
                            "ingress host '{}' is already claimed by pod {}",
                            i.host, m.name
                        )));
                    }
                }
            }
        }
        // Changing a RUNNING member's ingress would drift persisted vs
        // runtime state — refuse before any rootfs/state mutation.
        for (pname, rules) in &member_ingress {
            let changed = {
                let st = self.st.lock().await;
                st.pods
                    .get(pname)
                    .map(|m| !same_ingress(&m.ingress, &ingress_from_proto(rules)))
                    .unwrap_or(false)
            };
            if changed && self.engine.running_pid(pname).await.is_some() {
                return Err(Status::failed_precondition(format!(
                    "stop stack member {pname} before changing ingress"
                )));
            }
        }
        // One index per stack: reuse a live member's, else allocate fresh.
        let idx = {
            let st = self.st.lock().await;
            def.pods
                .keys()
                .filter_map(|m| st.pods.get(&stack::member_name(&def.name, m)))
                .map(|m| m.net_index)
                .find(|i| *i > 0)
                .unwrap_or_else(|| net::alloc_index(&st.pods))
        };
        if idx == 0 {
            return Err(Status::failed_precondition(
                "network pool exhausted (255 veths/stacks max)",
            ));
        }
        let mut out = Vec::new();
        for (member, sp) in &def.pods {
            let pname = stack::member_name(&def.name, member);
            let rootfs = self.pod_rootfs(&pname);
            // Check existence under the state lock — but never clone a
            // rootfs holding it: the reflink-fallback cp can copy gigabytes.
            let existing = {
                let st = self.st.lock().await;
                match st.pods.get(&pname) {
                    Some(m) if m.stack.is_empty() => {
                        return Err(Status::failed_precondition(format!(
                            "pod {pname} already exists as a standalone pod — \
                             destroy it before applying stack {}",
                            def.name
                        )));
                    }
                    Some(m) if m.stack != def.name => {
                        return Err(Status::failed_precondition(format!(
                            "pod {pname} belongs to stack '{}' — refusing to \
                             adopt it into '{}'",
                            m.stack, def.name
                        )));
                    }
                    other => other.cloned(),
                }
            };
            let meta = match existing {
                Some(mut m) => {
                    m.ports = sp.ports.clone();
                    m.ingress = ingress_from_proto(&member_ingress[&pname]);
                    m.limits = sp.limits;
                    m.storage_max_bytes = sp.storage_max_bytes;
                    m.stack = def.name.clone();
                    m.net_index = idx;
                    m.snap_keep_last = sp.snap_keep_last;
                    m.snap_max_age_secs = sp.snap_max_age_secs;
                    m.cmd = sp.cmd.clone();
                    {
                        let mut st = self.st.lock().await;
                        // Desired siblings are all being rewritten — ignore
                        // their stale rules; outsiders still count.
                        validate_ingress_conflicts_excluding(
                            &st,
                            &pname,
                            &member_ingress[&pname],
                            &desired_set,
                        )?;
                        st.pods.insert(pname.clone(), m.clone());
                    }
                    m
                }
                None => {
                    if let Err(e) = self
                        .st_clone(&self.cfg.images_dir().join(&sp.image), &rootfs)
                        .await
                    {
                        // Partial clone must not wedge the member name.
                        let _ = self.st_delete(&rootfs).await;
                        return Err(e);
                    }
                    let m = PodMeta {
                        name: pname.clone(),
                        image: sp.image.clone(),
                        created_unix: state::now_unix(),
                        limits: sp.limits,
                        ephemeral: false,
                        // Stacks join a pre-made netns via
                        // --network-namespace-path; setns() needs
                        // CAP_SYS_ADMIN in its owning userns
                        // (init_user_ns), which a pick-userns child
                        // never has — so stack members run without
                        // userns. Standalone `create` pods do get it.
                        private_users: false,
                        started: false,
                        storage_max_bytes: sp.storage_max_bytes,
                        ports: sp.ports.clone(),
                        ingress: ingress_from_proto(&member_ingress[&pname]),
                        net_index: idx,
                        stack: def.name.clone(),
                        binds: vec![],
                        cmd: sp.cmd.clone(),
                        snap_keep_last: sp.snap_keep_last,
                        snap_max_age_secs: sp.snap_max_age_secs,
                        // Stack lifecycle is driven by `stack start`, not
                        // the daemon boot path.
                        autostart: false,
                        ingress_gateway: false,
                        restart: String::new(),
                        healthcheck: Default::default(),
                    };
                    let mut st = self.st.lock().await;
                    if st.pods.contains_key(&pname) {
                        // Only possible if an op skipped the per-pod lock —
                        // drop the freshly cloned rootfs and bail cleanly.
                        drop(st);
                        let _ = self.st_delete(&rootfs).await;
                        return Err(Status::already_exists(format!(
                            "pod {pname} was created concurrently — re-apply the stack"
                        )));
                    }
                    if let Err(e) = validate_ingress_conflicts_excluding(
                        &st,
                        &pname,
                        &member_ingress[&pname],
                        &desired_set,
                    ) {
                        // A racing create claimed this host after the
                        // pre-apply check — same cleanup as above.
                        drop(st);
                        let _ = self.st_delete(&rootfs).await;
                        return Err(e);
                    }
                    st.pods.insert(pname.clone(), m.clone());
                    m
                }
            };
            self.save_pod(&meta).map_err(int)?;
            out.push(meta);
        }
        // Fail loudly at apply-time if netns/veth wiring doesn't work —
        // better here than on the first `stack start`.
        {
            let name = def.name.clone();
            Self::blocking(move || net::ensure_stack_net(&name, idx)).await?;
        }
        net::ensure_ip_forward().map_err(int)?;
        // Members' ports/net_index may have changed — rebuild the DNAT table.
        self.sync_nat().await?;
        let hmap: HashMap<String, String> = {
            let h = self.health.lock().await;
            h.iter().map(|(k, v)| (k.clone(), v.status.to_string())).collect()
        };
        let pods = out
            .iter()
            .map(|m| to_pod(m, &self.pod_rootfs(&m.name), None, hmap.get(&m.name).map(String::as_str).unwrap_or("")))
            .collect();
        Ok(Response::new(ApplyStackResponse {
            name: def.name,
            pods,
        }))
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
            self.engine.stop(pname).await.map_err(int)?;
            if self.engine.registered(pname).await.map_err(int)? {
                return Err(Status::failed_precondition(format!(
                    "pod {pname} is still registered with machined — refusing to destroy stack"
                )));
            }
            agent::stop_listener(&self.listeners, &self.metrics, pname).await;
            self.st_delete(&self.pod_rootfs(pname)).await?;
            state::remove_pod(&self.cfg.data_dir, pname);
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
        {
            let mut ops = self.ops.lock().await;
            ops.remove(&format!("stack:{name}"));
            for pname in &members {
                ops.remove(pname);
            }
        }
        Ok(Response::new(Empty {}))
    }

    async fn start_pod(&self, req: Request<StartPodRequest>) -> Result<Response<Pod>, Status> {
        let req = req.into_inner();
        let name = proto::validate_name(&req.name).map_err(bad)?.to_string();
        {
            let st = self.st.lock().await;
            if !st.pods.contains_key(&name) {
                return Err(Status::not_found(format!("pod {name} not found")));
            }
        }
        let _op = self.pod_op(&name).await;
        // Any start — manual, autostart or supervised — clears the
        // intentional-stop marker for the death-watch.
        self.stop_intent.lock().await.remove(&name);
        if self.engine.running_pid(&name).await.is_some() {
            return Err(Status::failed_precondition(format!(
                "pod {name} is already running"
            )));
        }
        let meta = {
            let mut st = self.st.lock().await;
            let next_idx = net::alloc_index(&st.pods);
            let Some(meta) = st.pods.get_mut(&name) else {
                return Err(Status::not_found(format!("pod {name} not found")));
            };
            // The gateway's isolation shape is managed: a private-users
            // downgrade would break the control-socket chown, and an
            // ephemeral gateway would silently drop provisioned files.
            if meta.ingress_gateway && (req.ephemeral || req.private_users.is_some()) {
                return Err(Status::failed_precondition(
                    "the ingress gateway is managed — ephemeral/private-users overrides are not allowed",
                ));
            }
            let lim = limits_from(req.limits);
            if !lim.is_empty() {
                meta.limits = lim;
            }
            // Sticky: only ever SET via `start -x`. A later plain start
            // (restart, GUI, REST — all send ephemeral:false) must not
            // silently clear a previously requested ephemeral pod.
            meta.ephemeral |= req.ephemeral;
            // Absent = keep the conf value (a bare `start` must not flip it).
            if let Some(pu) = req.private_users {
                meta.private_users = pu;
            }
            // Private networking is needed for published ports, ingress
            // rules (routed to the pod's private IP), stack membership, or
            // the ingress gateway itself (loopback 80/443 dnat target).
            let needs_network = !meta.ports.is_empty()
                || !meta.ingress.is_empty()
                || !meta.stack.is_empty()
                || meta.ingress_gateway;
            if needs_network && meta.net_index == 0 {
                meta.net_index = next_idx;
            }
            let m = meta.clone();
            self.save_pod(&m).map_err(int)?;
            m
        };
        let rootfs = self.pod_rootfs(&name);
        // Resolve binds up front: nspawn's failure for a missing source is
        // cryptic, so check existence (and re-validate hand-edited confs).
        let mut binds = Vec::with_capacity(meta.binds.len());
        for spec in &meta.binds {
            let b = proto::validate_bind(spec).map_err(bad)?;
            if !Path::new(&b.host).exists() {
                return Err(Status::failed_precondition(format!(
                    "bind source {} does not exist",
                    b.host
                )));
            }
            binds.push(b);
        }
        // Boot vs payload: OCI-pulled images record their entrypoint/cmd and
        // have no systemd → nspawn execs the payload directly (non-boot).
        // A conf-level cmd is a FULL override of the image entrypoint+cmd
        // and forces payload mode even on boot-capable images (env and
        // working_dir still come from the image when it's an OCI image).
        // Anything else must carry a real init or it can't be started.
        let (mut payload, env, chdir) = {
            let st = self.st.lock().await;
            if is_payload_pod(&st, &meta) {
                let im = st.images.get(&meta.image);
                let p = if !meta.cmd.is_empty() {
                    meta.cmd.clone()
                } else {
                    let mut p = im.map(|i| i.entrypoint.clone()).unwrap_or_default();
                    p.extend(im.map(|i| i.cmd.clone()).unwrap_or_default());
                    p
                };
                (
                    Some(p),
                    im.map(|i| i.env.clone()).unwrap_or_default(),
                    im.map(|i| i.working_dir.clone()).unwrap_or_default(),
                )
            } else {
                (None, Vec::new(), String::new())
            }
        };
        if let Some(p) = &mut payload {
            // OCI entrypoints are often bare names ("sh",
            // "docker-entrypoint.sh") — resolve inside the rootfs so the
            // error is clear and nspawn gets an absolute path.
            p[0] = resolve_in_rootfs(&rootfs, &p[0]).ok_or_else(|| {
                Status::failed_precondition(format!(
                    "entrypoint '{}' not found in image {}",
                    p[0], meta.image
                ))
            })?;
            if !chdir.is_empty() {
                // Docker semantics: a configured WorkingDir is created if
                // absent. Normalize first — '..' would escape the rootfs
                // entirely — then create without following image-planted
                // symlinks (rootfs helpers).
                if let Some(rel) = crate::rootfs::normalize_rel(&chdir).map_err(bad)? {
                    crate::rootfs::mkdir_in_rootfs(&rootfs, &rel).map_err(int)?;
                }
            }
        } else if !has_systemd_init(&rootfs) {
            return Err(Status::failed_precondition(format!(
                "image '{}' has no systemd init and no OCI entrypoint/cmd — it cannot be started",
                meta.image
            )));
        }
        let run_dir = proto::run_dir(&self.cfg.data_dir, &name);
        let shm_host = proto::shm_host_dir(&name);
        std::fs::create_dir_all(&run_dir).map_err(int)?;
        // The per-pod shm dir lives under a root-owned 0700 parent (see
        // serve()), but be paranoid anyway: it must be a REAL directory —
        // a planted symlink would make this chown and later segment files
        // follow it outside /dev/shm.
        match std::fs::symlink_metadata(&shm_host) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => {
                return Err(Status::failed_precondition(format!(
                    "shm dir {} exists but is not a real directory — refusing to start",
                    shm_host.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&shm_host).map_err(int)?;
            }
            Err(e) => return Err(int(e)),
        }
        let _ = std::os::unix::fs::chown(
            &shm_host,
            Some(self.cfg.allowed_uid),
            Some(self.cfg.allowed_uid),
        );
        let needs_network = !meta.ports.is_empty()
            || !meta.ingress.is_empty()
            || !meta.stack.is_empty()
            || meta.ingress_gateway;
        // Networking is wired BEFORE spawn: stack members join a pre-made
        // netns (nspawn opens the path at exec), standalone networked pods
        // get their static host0 config written into the rootfs. Everything
        // fallible happens BEFORE the agent listener is spawned — an early
        // return here must not leak a listener task + its stale socket.
        let netns = if meta.stack.is_empty() {
            if needs_network {
                if meta.net_index == 0 {
                    return Err(Status::failed_precondition(
                        "network pool exhausted (255 private-network pods max)",
                    ));
                }
                net::write_pod_network(&rootfs, meta.net_index).map_err(int)?;
            }
            None
        } else {
            if meta.net_index == 0 {
                return Err(Status::failed_precondition(
                    "port pool exhausted (255 port-mapped pods max)",
                ));
            }
            {
                let stack = meta.stack.clone();
                let idx = meta.net_index;
                Self::blocking(move || net::ensure_stack_net(&stack, idx)).await?;
            }
            Some(net::netns_path(&meta.stack))
        };
        // v4+v6 forwarding is a hard prerequisite: a networked pod that
        // can't route is a failed start, not a degraded one — and it must
        // fail BEFORE the listener spawns / engine starts.
        if needs_network {
            net::ensure_ip_forward().map_err(int)?;
        }
        // The gateway claims host :80/:443 via nft redirect — refuse to
        // start if something already listens on either loopback stack;
        // nft doesn't take a userspace bind, so it would silently hijack.
        if meta.ingress_gateway {
            Self::blocking(net::check_ingress_ports_free).await?;
        }
        // Last fallible step before spawn: the agent listener. From here on
        // the only failure path is engine.start below, which stops it.
        agent::spawn_listener(
            &run_dir,
            &name,
            self.metrics.clone(),
            self.listeners.clone(),
        )
        .await
        .map_err(int)?;
        let log = self.cfg.logs_dir().join(format!("{name}.log"));
        let spec = StartSpec {
            name: name.clone(),
            rootfs: rootfs.clone(),
            ephemeral: meta.ephemeral,
            private_users: meta.private_users,
            agent_bin: self.cfg.bin_dir(),
            run_dir,
            shm_dir: shm_host,
            ports: meta.ports.clone(),
            network_veth: meta.stack.is_empty() && needs_network,
            binds,
            netns,
            log: log.clone(),
            payload,
            env,
            chdir,
        };
        let leader = match self.engine.start(&spec, &meta.limits).await {
            Ok(pid) => Some(pid),
            Err(e) => {
                agent::stop_listener(&self.listeners, &self.metrics, &name).await;
                let _ = self.engine.stop(&name).await;
                return Err(int(e));
            }
        };
        // agent.sock is root:root 0660 — in a userns pod the in-pod agent's
        // "root" is a host subuid and couldn't connect; re-own the socket
        // to the kuid container-uid-0 maps to. The gateway also manages its
        // own control socket inside the run dir → chown the whole dir.
        if meta.private_users {
            if let Some(pid) = leader {
                agent::chown_sock_for_userns(&spec.run_dir, pid);
                if meta.ingress_gateway {
                    agent::chown_run_dir_for_userns(&spec.run_dir, pid);
                }
            }
        }
        // Btrfs qgroup cap: quota accounting doesn't survive a remount, so
        // re-enable + re-apply on every start.
        if meta.storage_max_bytes > 0 {
            if let Err(e) = self.apply_storage_cap(&meta).await {
                tracing::warn!("storage cap {name}: {e:#}");
            }
        }
        // Private networking must be usable BEFORE the pod reports
        // started: for standalone pods the daemon configures both veth
        // ends (dual-stack) now that the leader pid exists — bare OCI
        // payloads have no in-pod networkd to do it. Stack members were
        // wired at apply/first-member-start; everyone then gets the DNAT
        // table rebuilt from live state. A veth failure unwinds the
        // start rather than leaving a half-networked "running" pod.
        if needs_network && meta.stack.is_empty() {
            if let Err(e) =
                net::configure_veth(&name, meta.net_index, leader.unwrap_or(0)).await
            {
                agent::stop_listener(&self.listeners, &self.metrics, &name).await;
                let _ = self.engine.stop(&name).await;
                return Err(int(e));
            }
        }
        // Gateway control-plane readiness before NAT: the snapshot push
        // below needs a live UDS, and a gateway whose dataplane never
        // bound its socket must not stay half-started.
        if meta.ingress_gateway {
            if let Err(e) = self.wait_ingress_ready().await {
                agent::stop_listener(&self.listeners, &self.metrics, &name).await;
                let _ = self.engine.stop(&name).await;
                return Err(e);
            }
        }
        if needs_network {
            match self.sync_nat().await {
                Ok(()) => {}
                Err(e) if meta.ingress_gateway || !meta.ingress.is_empty() => {
                    // NAT is what makes ingress reachable — a failed
                    // rebuild means a "running" pod that's dark. Unwind.
                    agent::stop_listener(&self.listeners, &self.metrics, &name).await;
                    let _ = self.engine.stop(&name).await;
                    let _ = self.sync_nat().await;
                    return Err(e);
                }
                Err(e) => {
                    tracing::warn!("nft rebuild after {name} start failed: {e}");
                }
            }
        }
        // Route synchronization is part of "started": the gateway takes a
        // fresh complete snapshot (it routes nothing itself), an ingress
        // backend must be ACKed before we report it up. running_pid
        // already sees this pod, so the snapshot includes it.
        if meta.ingress_gateway || !meta.ingress.is_empty() {
            if let Err(e) = self.sync_ingress(None, true).await {
                agent::stop_listener(&self.listeners, &self.metrics, &name).await;
                let _ = self.engine.stop(&name).await;
                if needs_network {
                    let _ = self.sync_nat().await;
                }
                return Err(e);
            }
        }
        let mut st = self.st.lock().await;
        if let Some(m) = st.pods.get_mut(&name) {
            m.started = true;
            let m = m.clone();
            self.save_pod(&m).map_err(int)?;
        }
        let m = st.pods.get(&name).cloned().unwrap_or(meta);
        Ok(Response::new(to_pod(&m, &rootfs, leader, &self.health_view(&name).await)))
    }

    async fn stop_pod(&self, req: Request<PodRef>) -> Result<Response<Pod>, Status> {
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
        // Record intent before stopping: a racing supervisor tick must
        // not see "dead + no intent" mid-stop and restart the pod.
        self.stop_intent.lock().await.insert(name.clone());
        let meta = {
            let st = self.st.lock().await;
            st.pods.get(&name).cloned()
        };
        let ingress_gateway = meta.as_ref().is_some_and(|m| m.ingress_gateway);
        let has_ingress = meta.as_ref().is_some_and(|m| !m.ingress.is_empty());
        if ingress_gateway {
            // Draining the gateway while a backend still depends on it
            // would leave dead hostnames pointed at live IPs — refuse.
            let running = self.running_set().await;
            let dependent = {
                let st = self.st.lock().await;
                st.pods
                    .values()
                    .any(|m| m.name != name && !m.ingress.is_empty() && running.contains(&m.name))
            };
            if dependent {
                return Err(Status::failed_precondition(
                    "running pods still have ingress rules — stop them or clear their rules before stopping the gateway",
                ));
            }
            // Nobody needs routes anymore — clear the dataplane so nothing
            // lingers while the gateway is down. Best-effort: the stop
            // itself must still proceed.
            let gen = self.ingress_generation.fetch_add(1, Ordering::SeqCst) + 1;
            match ingress::push_snapshot(
                &self.cfg.data_dir,
                RouteSnapshot {
                    generation: gen,
                    routes: vec![],
                },
            )
            .await
            {
                Ok(_) => {
                    *self.ingress_last_push.lock().await = Some((gen, vec![]));
                }
                Err(e) => {
                    tracing::warn!("empty ingress snapshot before gateway stop: {e:#}");
                }
            }
        } else if has_ingress {
            // Drain this pod's routes BEFORE it stops so clients never hit
            // a dead backend. Best-effort — the stop must proceed.
            if let Err(e) = self.sync_ingress(Some(&name), false).await {
                tracing::warn!("ingress drain before {name} stop: {e}");
            }
        }
        self.engine.stop(&name).await.map_err(int)?;
        agent::stop_listener(&self.listeners, &self.metrics, &name).await;
        let st = self.st.lock().await;
        let Some(m) = st.pods.get(&name) else {
            return Err(Status::not_found(format!("pod {name} not found")));
        };
        let p = to_pod(m, &self.pod_rootfs(&name), None, &self.health_view(&name).await);
        drop(st);
        if let Err(e) = self.sync_nat().await {
            tracing::warn!("nft rebuild after {name} stop failed: {e}");
        }
        // Second drain pass: the pod is confirmed down now, so the
        // post-stop snapshot can't race its next start (pod_op held).
        if has_ingress {
            if let Err(e) = self.sync_ingress(None, false).await {
                tracing::warn!("ingress resync after {name} stop: {e}");
            }
        }
        Ok(Response::new(p))
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
            h.iter().map(|(k, v)| (k.clone(), v.status.to_string())).collect()
        };
        let mut out = Vec::new();
        for m in &pods {
            out.push(to_pod(
                m,
                &self.pod_rootfs(&m.name),
                self.engine.running_pid(&m.name).await,
                hmap.get(&m.name).map(String::as_str).unwrap_or(""),
            ));
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Response::new(PodList { pods: out }))
    }

    async fn destroy_pod(&self, req: Request<PodRef>) -> Result<Response<Empty>, Status> {
        let name = proto::validate_name(&req.into_inner().name)
            .map_err(bad)?
            .to_string();
        // Cheap existence check BEFORE pod_op: ops is an append-only map,
        // so RPCs on never-existing names must not grow it.
        {
            let st = self.st.lock().await;
            if !st.pods.contains_key(&name) {
                return Err(Status::not_found(format!("pod {name} not found")));
            }
        }
        let _op = self.pod_op(&name).await;
        let meta = {
            let st = self.st.lock().await;
            st.pods.get(&name).cloned()
        };
        let ingress_gateway = meta.as_ref().is_some_and(|m| m.ingress_gateway);
        let has_ingress = meta.as_ref().is_some_and(|m| !m.ingress.is_empty());
        if ingress_gateway {
            // Destroying the gateway while ANY other pod still carries
            // ingress rules would strand them — rules must be cleared or
            // the pods destroyed first, even if they're all stopped.
            let dependent = {
                let st = self.st.lock().await;
                st.pods
                    .values()
                    .any(|m| m.name != name && !m.ingress.is_empty())
            };
            if dependent {
                return Err(Status::failed_precondition(
                    "pods still have ingress rules — clear their rules or destroy them before destroying the gateway",
                ));
            }
        }
        self.engine.stop(&name).await.map_err(int)?;
        // Never delete the rootfs of a pod machined still knows about —
        // a failed/busy bus must not look like "pod is gone".
        if self.engine.registered(&name).await.map_err(int)? {
            return Err(Status::failed_precondition(format!(
                "pod {name} is still registered with machined — refusing to destroy"
            )));
        }
        agent::stop_listener(&self.listeners, &self.metrics, &name).await;
        if has_ingress && !ingress_gateway {
            // Route removal must be ACKed before the pod's identity (and
            // its reusable net_index) disappears — an unreachable gateway
            // means a stale route could point at a recycled IP later.
            self.sync_ingress(Some(&name), true).await?;
        }
        self.st_delete(&self.pod_rootfs(&name)).await?;
        state::remove_pod(&self.cfg.data_dir, &name);
        agent::cleanup_pod_dirs(
            &proto::run_dir(&self.cfg.data_dir, &name),
            &proto::shm_host_dir(&name),
        );
        let mut st = self.st.lock().await;
        let removed = st.pods.remove(&name);
        // GC: last member of a stack going away individually still tears
        // the shared netns down — `stack destroy` is just the bulk path.
        let orphan_netns = removed
            .map(|m| m.stack)
            .filter(|s| !s.is_empty())
            .filter(|s| !st.pods.values().any(|m| &m.stack == s));
        drop(st);
        // Its time machine dies with the pod — each snapshot is a subvol.
        let snaps = self.snaps_dir(&name);
        if let Ok(rd) = std::fs::read_dir(&snaps) {
            for e in rd.flatten() {
                let _ = self.st_delete(&e.path()).await;
            }
            let _ = std::fs::remove_dir(&snaps);
        }
        if let Some(stack) = orphan_netns {
            let _ = Self::blocking(move || {
                net::teardown_stack_net(&stack);
                Ok(())
            })
            .await;
        }
        if let Err(e) = self.sync_nat().await {
            tracing::warn!("nft rebuild after {name} destroy failed: {e}");
        }
        // The pod is gone for good — drop its op-lock entry so ops stays
        // bounded by live pod names. Guard must drop first: removing while
        // locked is harmless (the guard just holds a dead Arc), but
        // explicit order keeps it obvious.
        drop(_op);
        self.ops.lock().await.remove(&name);
        self.stop_intent.lock().await.remove(&name);
        self.health.lock().await.remove(&name);
        Ok(Response::new(Empty {}))
    }

    /// `rustypods config`: update the conf + live-apply to the scope.
    async fn update_pod_config(
        &self,
        req: Request<UpdatePodConfigRequest>,
    ) -> Result<Response<Pod>, Status> {
        let req = req.into_inner();
        let name = proto::validate_name(&req.name).map_err(bad)?.to_string();
        {
            let st = self.st.lock().await;
            if !st.pods.contains_key(&name) {
                return Err(Status::not_found(format!("pod {name} not found")));
            }
        }
        let _op = self.pod_op(&name).await;
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
                    || req.healthcheck.is_some())
            {
                return Err(Status::failed_precondition(
                    "the ingress gateway is managed — cmd/ports/binds/ingress/restart are not configurable; re-run `rustypods ingress init`",
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
            if let Some(h) = new_hc {
                m.healthcheck = h;
            }
            let m = m.clone();
            self.save_pod(&m).map_err(int)?;
            m
        };
        // Hot-apply while the pod runs — no restart needed.
        if self.engine.running_pid(&name).await.is_some() {
            self.engine.apply_limits(&name, &meta.limits).await.map_err(int)?;
        }
        self.apply_storage_cap(&meta).await.map_err(int)?;
        if ports_changed {
            if let Err(e) = self.sync_nat().await {
                tracing::warn!("nft rebuild after {name} config failed: {e}");
            }
        }
        let leader = self.engine.running_pid(&name).await;
        Ok(Response::new(to_pod(&meta, &self.pod_rootfs(&name), leader, &self.health_view(&name).await)))
    }

    /// `rustypods reload`: reread the conf from disk (hand edits) + apply.
    async fn reload_pod_config(
        &self,
        req: Request<PodRef>,
    ) -> Result<Response<Pod>, Status> {
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
                        || meta.private_users != cur.private_users)
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
        if self.engine.running_pid(&name).await.is_some() {
            self.engine.apply_limits(&name, &meta.limits).await.map_err(int)?;
        }
        self.apply_storage_cap(&meta).await.map_err(int)?;
        let leader = self.engine.running_pid(&name).await;
        Ok(Response::new(to_pod(&meta, &self.pod_rootfs(&name), leader, &self.health_view(&name).await)))
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
            name: proto::INGRESS_POD.into(),
            image: image.clone(),
            created_unix: prev.map(|m| m.created_unix).unwrap_or_else(state::now_unix),
            limits: LimitsSpec {
                memory_high_bytes: 256 << 20,
                memory_max_bytes: 512 << 20,
                cpu_quota_percent: 100,
            },
            ephemeral: false,
            private_users: true,
            started: prev.map(|m| m.started).unwrap_or(false),
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
                        match crate::rootfs::safe_join_if_exists(
                            &rf,
                            "etc/rustypods-ingress/tls.crt",
                        )? {
                            Some(p) => Ok(std::fs::read(&p)? != want),
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
            pod: Some(to_pod(&meta, &rootfs, leader, &self.health_view(&meta.name).await)),
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
        let running = configured
            && self
                .engine
                .running_pid(proto::INGRESS_POD)
                .await
                .is_some();
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

    async fn create_shm(
        &self,
        req: Request<ShmRequest>,
    ) -> Result<Response<ShmSegment>, Status> {
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
                return Err(Status::not_found(format!(
                    "shm segment {name} not found"
                )));
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
        let private_users = {
            let st = self.st.lock().await;
            let Some(m) = st.pods.get(&name) else {
                return Err(Status::not_found(format!("pod {name} not found")));
            };
            m.private_users
        };
        let Some(leader) = self.engine.running_pid(&name).await else {
            return Err(Status::failed_precondition(format!("pod {name} is not running")));
        };
        if leader == 0 {
            // Registered with machined but no leader yet — nsenter has
            // nothing to attach to.
            return Err(Status::failed_precondition(format!(
                "pod {name} is still booting — no leader pid yet"
            )));
        }
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        crate::exec::run(start, &self.pod_rootfs(&name), leader, private_users, stream, tx)
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
            let first = rx.borrow().clone();
            if first.ts_unix_ms > 0 && tx.send(Ok(first)).await.is_err() {
                return;
            }
            loop {
                if rx.changed().await.is_err() {
                    break;
                }
                let m = rx.borrow_and_update().clone();
                if tx.send(Ok(m)).await.is_err() {
                    break;
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
            loop {
                match read_log_line(&mut reader, &mut line).await {
                    Ok(true) => {
                        if tx
                            .send(Ok(LogLine {
                                ts_unix_ms: now_unix_ms(),
                                data: std::mem::take(&mut line),
                            }))
                            .await
                            .is_err()
                        {
                            break; // client gone — kill_on_drop reaps the child
                        }
                    }
                    Ok(false) => break,
                    Err(e) => {
                        let _ = tx.send(Err(int(e))).await;
                        break;
                    }
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// Per-line cap for stream_logs: BufReader::lines() buffers a whole line
/// unbounded — a pod emitting one giant unterminated line would grow
/// daemon RAM without limit. Longer lines are emitted truncated with a
/// marker, and the remainder up to the newline is discarded.
const LOG_LINE_MAX: usize = 64 << 10;
const TRUNCATED_MARK: &[u8] = b" [truncated]";

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

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Generate the REST bearer token (32 bytes from /dev/urandom, hex) and
/// write it to <socket-dir>/http-token, mode 0400, owned by allowed_uid
/// when running as root — the same uid that may already drive the unix
/// socket. Non-root daemon → owned by the daemon's euid.
fn write_http_token(cfg: &Config) -> Result<(Arc<str>, std::path::PathBuf)> {
    use std::io::Read;
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .context("reading /dev/urandom")?;
    let mut token = String::with_capacity(64);
    for b in buf {
        token.push_str(&format!("{b:02x}"));
    }
    let dir = cfg
        .socket
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("/run/rustypods"));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("http-token");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o400)
            .open(&path)
            .with_context(|| format!("create {}", path.display()))?;
        f.write_all(token.as_bytes())?;
    }
    // Pre-existing file keeps its old mode — force 0400 either way.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
    if crate::euid() == 0 {
        std::os::unix::fs::chown(&path, Some(cfg.allowed_uid), Some(cfg.allowed_uid))
            .with_context(|| format!("chown {}", path.display()))?;
    }
    Ok((Arc::from(token.as_str()), path))
}

/// Snapshot GC predicate: `snaps` is newest-first; a snapshot is collected
/// when its index reaches keep_last (if > 0) OR it is older than max_age
/// (if > 0). Both criteria apply — the union is deleted.
fn snapshot_expired(idx: usize, created_unix: u64, keep_last: u32, max_age: u64, now: u64) -> bool {
    (keep_last > 0 && idx >= keep_last as usize)
        || (max_age > 0 && now.saturating_sub(created_unix) > max_age)
}

/// Rootless podman lives in the user's store — root can't reach it, so the
/// export runs as that user. The tarball is staged to a temp file next to
/// `dest` (same fs — same pattern as oci::pull_layer) and then fed to the
/// in-tree hardened untar (`oci::unpack_tar`): normalized paths, no device
/// nodes, symlink-safe whiteout handling — strictly stronger than piping
/// into GNU `tar -x`.
fn import_distrobox(user: &str, container: &str, dest: &Path) -> Result<()> {
    let uid_out = SyncCommand::new("id")
        .args(["-u", user])
        .output()
        .context("id -u")?;
    if !uid_out.status.success() {
        bail!("id -u {user} failed: {}", String::from_utf8_lossy(&uid_out.stderr).trim());
    }
    let uid = String::from_utf8_lossy(&uid_out.stdout).trim().to_string();
    let mut exp = SyncCommand::new("runuser")
        .args(["-u", user, "--"])
        .arg("env")
        .arg(format!("XDG_RUNTIME_DIR=/run/user/{uid}"))
        .args(["podman", "export", container])
        .stdout(Stdio::piped())
        .spawn()
        .context("runuser podman export")?;
    // TmpGuard: unique .export-<container>-<pid>-<nanos> name, unlinked on
    // scope exit — concurrent imports can't collide and nothing leaks on
    // the error paths below (SIGKILL leftovers → serve()'s tmp sweep).
    let guard = oci::TmpGuard::new(dest.parent().unwrap_or(dest), "export-", container);
    let tmp = guard.path().to_path_buf();
    // Drain the export stream to the temp file — podman blocks on a full
    // pipe if we wait first, so copy before checking the exit status.
    let copy_res = exp
        .stdout
        .take()
        .context("export stdout")
        .and_then(|mut out| {
            let mut f = std::fs::File::create(&tmp)
                .with_context(|| format!("create {}", tmp.display()))?;
            std::io::copy(&mut out, &mut f)
                .map(|_| ())
                .context("reading podman export stream")
        });
    let s_exp = exp.wait()?;
    if let Err(e) = copy_res {
        return Err(e);
    }
    if !s_exp.success() {
        bail!("podman export '{container}' failed — does the box exist? (podman ps -a)");
    }
    std::fs::File::open(&tmp)
        .with_context(|| format!("open {}", tmp.display()))
        .and_then(|f| oci::unpack_tar(f, dest))
        .with_context(|| format!("extracting export into {}", dest.display()))
}

/// Does the rootfs carry a systemd init? Checked on the pod rootfs at
/// start: distrobox imports have it, OCI-pulled images don't (they run
/// non-boot via their recorded entrypoint/cmd instead).
fn has_systemd_init(rootfs: &Path) -> bool {
    // Same leaf policy as resolve_in_rootfs: symlinked intermediates are
    // refused (no host-fs stat), a leaf symlink counts as existing.
    ["usr/lib/systemd/systemd", "lib/systemd/systemd", "sbin/init"]
        .iter()
        .any(|p| {
            crate::rootfs::safe_join_if_exists(rootfs, p)
                .ok()
                .flatten()
                .map(|p| std::fs::symlink_metadata(&p).is_ok())
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
        crate::rootfs::safe_join_if_exists(rootfs, rel)
            .ok()
            .flatten()
            .map(|p| std::fs::symlink_metadata(&p).is_ok())
            .unwrap_or(false)
    };
    if prog.contains('/') {
        return exists(prog).then(|| prog.to_string());
    }
    for d in ["usr/local/sbin", "usr/local/bin", "usr/sbin", "usr/bin", "sbin", "bin"] {
        if exists(&format!("{d}/{prog}")) {
            return Some(format!("/{d}/{prog}"));
        }
    }
    None
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
impl Svc {
    /// Quota calls spawn `btrfs` subprocesses — off the async executor.
    async fn apply_storage_cap(&self, meta: &PodMeta) -> Result<()> {
        if !self.storage.supports_quota() && meta.storage_max_bytes > 0 {
            bail!(
                "storage_max needs btrfs — driver '{}' doesn't support quotas",
                self.storage.name()
            );
        }
        if !self.storage.supports_quota() {
            return Ok(());
        }
        let s = self.storage.clone();
        let path = self.cfg.pods_dir().join(&meta.name);
        let bytes = meta.storage_max_bytes;
        match tokio::task::spawn_blocking(move || s.apply_quota(&path, bytes)).await {
            Ok(r) => r,
            Err(e) => Err(anyhow::anyhow!("blocking task: {e}")),
        }
    }
}

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
    if let Some(profile_d) = rfs::safe_join_if_exists(root, "etc/profile.d")? {
        if let Ok(rd) = std::fs::read_dir(&profile_d) {
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().contains("distrobox") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }
    // distrobox-export wrappers in ~/.local/bin branch on CONTAINER_ID:
    // matching the source box name makes them exec the real /usr/bin binary.
    // Fallback for unset CONTAINER_ID: a shim at the absolute path the
    // wrappers call, stripping "-n <box> --" and exec'ing the payload.
    let mut envf = rfs::safe_join(root, "etc/environment")
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
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

pub async fn serve(cfg: Config) -> Result<()> {
    for d in [
        cfg.images_dir(),
        cfg.pods_dir(),
        cfg.logs_dir(),
        cfg.bin_dir(),
        cfg.shm_dir(),
        state::pods_conf_dir(&cfg.data_dir),
        state::images_conf_dir(&cfg.data_dir),
    ] {
        std::fs::create_dir_all(&d).with_context(|| format!("mkdir {}", d.display()))?;
    }
    // SIGKILL'd pulls/imports leave .layer-*/.export-* blobs behind.
    oci::sweep_tmpfiles(&cfg.images_dir());
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
            Err(e) => {
                return Err(e).with_context(|| format!("stat {}", shm_root.display()))
            }
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
    let engine: Arc<dyn RuntimeEngine> = Arc::new(runtime::SystemdNspawn {
        dbus: zbus::Connection::system()
            .await
            .context("connecting to system D-Bus")?,
    });
    // `detect` probes the fs with `stat -f` — a subprocess; off the
    // executor even though nothing is serving yet.
    let dd = cfg.data_dir.clone();
    let storage = tokio::task::spawn_blocking(move || storage::detect(&dd))
        .await
        .context("storage detect task")?;
    engine.init().await?;

    let st = Arc::new(Mutex::new(state::load(&cfg.data_dir)?));
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
        ingress_generation: Arc::new(AtomicU64::new(0)),
        ingress_mu: Arc::new(Mutex::new(())),
        ingress_last_err: Arc::new(Mutex::new(None)),
        ingress_last_push: Arc::new(Mutex::new(None)),
        health: Default::default(),
        stop_intent: Default::default(),
    };

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
                    .filter(|m| m.autostart)
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
        tokio::spawn(async move {
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
        });
    }

    // Supervisor: per-second death-watch + liveness probes for pods with
    // a restart policy or a healthcheck (and the managed gateway).
    {
        let svc = svc.clone();
        tokio::spawn(async move {
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
        match tokio::net::TcpListener::bind(&cfg.http_addr).await {
            Ok(l) => match write_http_token(&cfg) {
                Ok((token, token_path)) => {
                    tracing::info!(
                        "http api listening on http://{} — bearer token in {}",
                        cfg.http_addr,
                        token_path.display()
                    );
                    let router = crate::http::router(svc.clone(), token);
                    tokio::spawn(async move {
                        if let Err(e) = axum::serve(l, router).await {
                            tracing::warn!("http api: {e}");
                        }
                    });
                }
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
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            loop {
                tick.tick().await;
                gc.gc_snapshots().await;
            }
        });
    }

    let allowed = cfg.allowed_uid;
    let (tx, rx) = tokio::sync::mpsc::channel::<tokio::net::UnixStream>(32);
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((s, _)) => match s.peer_cred() {
                    Ok(c) if c.uid() == 0 || c.uid() == allowed => {
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
            }
        }
    });

    let incoming = ReceiverStream::new(rx).map(Ok::<_, std::io::Error>);
    tracing::info!("rustypodsd listening on {}", cfg.socket.display());
    Server::builder()
        // The socket admits uid 0 and the allowed uid — both can spawn
        // streaming RPCs (journalctl/tail/nsenter). Cap in-flight requests
        // per connection and across the whole server so one chatty client
        // can't exhaust the subprocess/desc budget.
        .concurrency_limit_per_connection(32)
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(256))
        .add_service(PodControlServer::new(svc))
        .serve_with_incoming_shutdown(incoming, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    let _ = std::fs::remove_file(&cfg.socket);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        probe_addr, restart_policy, snapshot_expired, supervised,
        validate_ingress_conflicts, validate_ingress_conflicts_excluding,
    };
    use crate::state::{IngressSpec, LimitsSpec, PodMeta, State};
    use rustypods_proto::rpc::IngressRule;
    use std::collections::{BTreeMap, BTreeSet};

    fn meta_with_ingress(name: &str, hosts: &[&str]) -> PodMeta {
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
        }
    }

    fn meta_plain(name: &str) -> PodMeta {
        meta_with_ingress(name, &[])
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
        };
        st.pods.insert(
            "taken".into(),
            meta_with_ingress("taken", &["web.rustypods.localhost"]),
        );
        // A fresh host for a new pod is fine.
        assert!(
            validate_ingress_conflicts(&st, "new", &[rule("api.rustypods.localhost")]).is_ok()
        );
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
        let desired: BTreeSet<String> =
            ["s-web".to_string(), "s-api".to_string()].into_iter().collect();
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
}
