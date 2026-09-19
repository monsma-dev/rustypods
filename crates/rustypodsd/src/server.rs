//! tonic server on a Unix socket. Peer credentials gate access:
//! uid 0 or Config::allowed_uid may connect; everyone else is dropped.

use std::path::Path;
use std::process::{Command as SyncCommand, Stdio};
use std::sync::Arc;
use std::time::Duration;

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
use crate::state::{self, ImageMeta, LimitsSpec, PodMeta, State};
use crate::{btrfs, dbus, net, nspawn, Config};

pub struct Svc {
    cfg: Config,
    st: Arc<Mutex<State>>,
    metrics: MetricsMap,
    listeners: ListenerMap,
    /// Shared system-bus connection (zbus multiplexes all calls over it).
    dbus: zbus::Connection,
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
    }
}

fn to_pod(m: &PodMeta, rootfs: &Path, leader: Option<u32>) -> Pod {
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
    }
}

fn limits_from(l: Option<Limits>) -> LimitsSpec {
    l.map(|l| LimitsSpec {
        memory_high_bytes: l.memory_high_bytes,
        memory_max_bytes: l.memory_max_bytes,
        cpu_quota_percent: l.cpu_quota_percent,
    })
    .unwrap_or_default()
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

    /// Rebuild the nftables DNAT table from current state (running pods only).
    async fn sync_nat(&self) {
        let pods: Vec<PodMeta> = {
            let st = self.st.lock().await;
            st.pods.values().cloned().collect()
        };
        let mut running = std::collections::BTreeSet::new();
        for m in &pods {
            if dbus::leader_pid(&self.dbus, &m.name).await.is_some() {
                running.insert(m.name.clone());
            }
        }
        net::rebuild_nat(pods.iter(), &running);
    }
}

#[tonic::async_trait]
impl PodControl for Svc {
    async fn ping(&self, _req: Request<PingRequest>) -> Result<Response<DaemonInfo>, Status> {
        Ok(Response::new(DaemonInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            socket_path: self.cfg.socket.display().to_string(),
            data_dir: self.cfg.data_dir.display().to_string(),
            machined: dbus::machined_up(&self.dbus).await,
            btrfs: btrfs::is_btrfs(&self.cfg.data_dir),
        }))
    }

    async fn import_image(
        &self,
        req: Request<ImportImageRequest>,
    ) -> Result<Response<Image>, Status> {
        let req = req.into_inner();
        let name = proto::validate_name(&req.name).map_err(bad)?.to_string();
        let dest = self.cfg.images_dir().join(&name);
        if dest.exists() {
            return Err(Status::already_exists(format!("image {name} already exists")));
        }
        let user = if req.import_user.is_empty() {
            self.cfg.import_user.clone()
        } else {
            req.import_user.clone()
        };
        btrfs::create_subvol(&dest).map_err(int)?;
        let d = dest.clone();
        let cont = req.distrobox.clone();
        let res = tokio::task::spawn_blocking(move || import_distrobox(&user, &cont, &d)).await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = btrfs::delete(&dest);
                return Err(int(e));
            }
            Err(je) => {
                let _ = btrfs::delete(&dest);
                return Err(int(anyhow::anyhow!("task: {je}")));
            }
        }
        sanitize_rootfs(&dest, &req.distrobox).map_err(int)?;
        let meta = ImageMeta {
            name: name.clone(),
            source: format!("distrobox:{}", req.distrobox),
            created_unix: state::now_unix(),
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
        let mut st = self.st.lock().await;
        if st.pods.values().any(|p| p.image == name) {
            return Err(Status::failed_precondition(format!(
                "image {name} is still in use by a pod"
            )));
        }
        btrfs::delete(&self.cfg.images_dir().join(&name)).map_err(int)?;
        st.images.remove(&name);
        state::remove_image(&self.cfg.data_dir, &name);
        Ok(Response::new(Empty {}))
    }

    async fn create_pod(&self, req: Request<CreatePodRequest>) -> Result<Response<Pod>, Status> {
        let req = req.into_inner();
        let name = proto::validate_name(&req.name).map_err(bad)?.to_string();
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
            validate_port(p).map_err(bad)?;
        }
        btrfs::snapshot(&img_dir, &dest).map_err(int)?;
        let meta = PodMeta {
            name: name.clone(),
            image,
            created_unix: state::now_unix(),
            limits: LimitsSpec::default(),
            ephemeral: false,
            private_users: false,
            started: false,
            storage_max_bytes: req.storage_max_bytes,
            ports: req.ports.clone(),
            net_index: 0,
        };
        let mut st = self.st.lock().await;
        st.pods.insert(name.clone(), meta.clone());
        self.save_pod(&meta).map_err(int)?;
        Ok(Response::new(to_pod(&meta, &dest, None)))
    }

    /// `rustypods clone <src> <dest>`: instant btrfs snapshot of the pod
    /// rootfs + a copied conf with fresh identity. Cloning a running pod is
    /// allowed (subvolume snapshot is atomic) but the runtime state is
    /// reset — the clone starts stopped.
    async fn clone_pod(&self, req: Request<ClonePodRequest>) -> Result<Response<Pod>, Status> {
        let req = req.into_inner();
        let src = proto::validate_name(&req.source).map_err(bad)?.to_string();
        let dest = proto::validate_name(&req.dest).map_err(bad)?.to_string();
        let meta = {
            let st = self.st.lock().await;
            let Some(m) = st.pods.get(&src) else {
                return Err(Status::not_found(format!("pod {src} not found")));
            };
            m.clone()
        };
        if dbus::leader_pid(&self.dbus, &src).await.is_some() {
            tracing::warn!("cloning running pod {src} — snapshot is atomic but mid-write state is live");
        }
        let dst_root = self.pod_rootfs(&dest);
        if dst_root.exists() {
            return Err(Status::already_exists(format!("pod {dest} already exists")));
        }
        btrfs::snapshot(&self.pod_rootfs(&src), &dst_root).map_err(int)?;
        let meta = PodMeta {
            name: dest.clone(),
            created_unix: state::now_unix(),
            started: false,
            // Fresh identity: net_index is reallocated on first start so two
            // clones can run side by side. Ports are kept — running BOTH
            // clones with identical host ports is a user-visible conflict.
            net_index: 0,
            ..meta
        };
        let mut st = self.st.lock().await;
        st.pods.insert(dest.clone(), meta.clone());
        self.save_pod(&meta).map_err(int)?;
        Ok(Response::new(to_pod(&meta, &dst_root, None)))
    }

    async fn start_pod(&self, req: Request<StartPodRequest>) -> Result<Response<Pod>, Status> {
        let req = req.into_inner();
        let name = proto::validate_name(&req.name).map_err(bad)?.to_string();
        let meta = {
            let mut st = self.st.lock().await;
            let next_idx = net::alloc_index(&st.pods);
            let Some(meta) = st.pods.get_mut(&name) else {
                return Err(Status::not_found(format!("pod {name} not found")));
            };
            let lim = limits_from(req.limits);
            if !lim.is_empty() {
                meta.limits = lim;
            }
            meta.ephemeral = req.ephemeral;
            meta.private_users = req.private_users;
            if !meta.ports.is_empty() && meta.net_index == 0 {
                meta.net_index = next_idx;
            }
            let m = meta.clone();
            self.save_pod(&m).map_err(int)?;
            m
        };
        if dbus::leader_pid(&self.dbus, &name).await.is_some() {
            return Err(Status::failed_precondition(format!("pod {name} is already running")));
        }
        let rootfs = self.pod_rootfs(&name);
        let run_dir = proto::run_dir(&self.cfg.data_dir, &name);
        let shm_host = proto::shm_host_dir(&name);
        std::fs::create_dir_all(&run_dir).map_err(int)?;
        std::fs::create_dir_all(&shm_host).map_err(int)?;
        let _ = std::os::unix::fs::chown(
            &shm_host,
            Some(self.cfg.allowed_uid),
            Some(self.cfg.allowed_uid),
        );
        agent::spawn_listener(
            &run_dir,
            &name,
            self.metrics.clone(),
            self.listeners.clone(),
        )
        .await
        .map_err(int)?;
        // Static host0 config must exist in the rootfs before boot.
        if !meta.ports.is_empty() {
            if meta.net_index == 0 {
                agent::stop_listener(&self.listeners, &name).await;
                return Err(Status::failed_precondition(
                    "port pool exhausted (255 port-mapped pods max)",
                ));
            }
            net::write_pod_network(&rootfs, meta.net_index).map_err(int)?;
        }
        let argv = nspawn::start_argv(
            &rootfs,
            &name,
            meta.ephemeral,
            meta.private_users,
            &self.cfg.bin_dir(),
            &run_dir,
            &shm_host,
            &meta.ports,
        );
        let log = self.cfg.logs_dir().join(format!("{name}.log"));
        if let Err(e) = nspawn::spawn(&argv, &log).await {
            agent::stop_listener(&self.listeners, &name).await;
            return Err(int(e));
        }
        if let Err(e) = dbus::wait_registered(&self.dbus, &name, Duration::from_secs(15)).await {
            agent::stop_listener(&self.listeners, &name).await;
            let _ = dbus::stop(&self.dbus, &name).await;
            return Err(int(e.context(format!("boot failed — see {}", log.display()))));
        }
        // Guardrails are the point: a pod that can't be capped gets stopped.
        if let Err(e) = dbus::apply_limits(&self.dbus, &name, &meta.limits).await {
            agent::stop_listener(&self.listeners, &name).await;
            let _ = dbus::stop(&self.dbus, &name).await;
            return Err(int(e.context("applying limits failed")));
        }
        // Btrfs qgroup cap: quota accounting doesn't survive a remount, so
        // re-enable + re-apply on every start.
        if meta.storage_max_bytes > 0 {
            if let Err(e) = apply_storage_cap(&self.cfg, &meta) {
                tracing::warn!("storage cap {name}: {e:#}");
            }
        }
        // Port forwarding: configure the host veth once nspawn creates it,
        // then rebuild the NAT table. Async — the pod boot continues.
        if !meta.ports.is_empty() {
            if let Err(e) = net::ensure_ip_forward() {
                tracing::warn!("ip_forward: {e:#}");
            }
            let pod = name.clone();
            let idx = meta.net_index;
            let st = self.st.clone();
            let conn = self.dbus.clone();
            tokio::spawn(async move {
                if let Err(e) = net::configure_host_veth(&pod, idx).await {
                    tracing::warn!("veth setup {pod}: {e:#}");
                    return;
                }
                let pods: Vec<PodMeta> = {
                    let g = st.lock().await;
                    g.pods.values().cloned().collect()
                };
                let mut running = std::collections::BTreeSet::new();
                for m in &pods {
                    if dbus::leader_pid(&conn, &m.name).await.is_some() {
                        running.insert(m.name.clone());
                    }
                }
                net::rebuild_nat(pods.iter(), &running);
            });
        }
        let leader = dbus::leader_pid(&self.dbus, &name).await;
        let mut st = self.st.lock().await;
        if let Some(m) = st.pods.get_mut(&name) {
            m.started = true;
            let m = m.clone();
            self.save_pod(&m).map_err(int)?;
        }
        let m = st.pods.get(&name).cloned().unwrap_or(meta);
        Ok(Response::new(to_pod(&m, &rootfs, leader)))
    }

    async fn stop_pod(&self, req: Request<PodRef>) -> Result<Response<Pod>, Status> {
        let name = proto::validate_name(&req.into_inner().name)
            .map_err(bad)?
            .to_string();
        dbus::stop(&self.dbus, &name).await.map_err(int)?;
        agent::stop_listener(&self.listeners, &name).await;
        let st = self.st.lock().await;
        let Some(m) = st.pods.get(&name) else {
            return Err(Status::not_found(format!("pod {name} not found")));
        };
        let p = to_pod(m, &self.pod_rootfs(&name), None);
        drop(st);
        self.sync_nat().await;
        Ok(Response::new(p))
    }

    async fn list_pods(&self, _req: Request<ListPodsRequest>) -> Result<Response<PodList>, Status> {
        let st = self.st.lock().await;
        let mut out = Vec::new();
        for m in st.pods.values() {
            out.push(to_pod(
                m,
                &self.pod_rootfs(&m.name),
                dbus::leader_pid(&self.dbus, &m.name).await,
            ));
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Response::new(PodList { pods: out }))
    }

    async fn destroy_pod(&self, req: Request<PodRef>) -> Result<Response<Empty>, Status> {
        let name = proto::validate_name(&req.into_inner().name)
            .map_err(bad)?
            .to_string();
        dbus::stop(&self.dbus, &name).await.map_err(int)?;
        agent::stop_listener(&self.listeners, &name).await;
        btrfs::delete(&self.pod_rootfs(&name)).map_err(int)?;
        state::remove_pod(&self.cfg.data_dir, &name);
        agent::cleanup_pod_dirs(
            &proto::run_dir(&self.cfg.data_dir, &name),
            &proto::shm_host_dir(&name),
        );
        let mut st = self.st.lock().await;
        st.pods.remove(&name);
        drop(st);
        self.sync_nat().await;
        Ok(Response::new(Empty {}))
    }

    /// `rustypods config`: update the conf + live-apply to the scope.
    async fn update_pod_config(
        &self,
        req: Request<UpdatePodConfigRequest>,
    ) -> Result<Response<Pod>, Status> {
        let req = req.into_inner();
        let name = proto::validate_name(&req.name).map_err(bad)?.to_string();
        let lim = limits_from(req.limits);
        let meta = {
            let mut st = self.st.lock().await;
            let Some(m) = st.pods.get_mut(&name) else {
                return Err(Status::not_found(format!("pod {name} not found")));
            };
            m.limits = lim;
            m.storage_max_bytes = req.storage_max_bytes;
            let m = m.clone();
            self.save_pod(&m).map_err(int)?;
            m
        };
        // Hot-apply while the pod runs — no restart needed.
        if dbus::leader_pid(&self.dbus, &name).await.is_some() {
            dbus::apply_limits(&self.dbus, &name, &meta.limits)
                .await
                .map_err(int)?;
        }
        apply_storage_cap(&self.cfg, &meta).map_err(int)?;
        let leader = dbus::leader_pid(&self.dbus, &name).await;
        Ok(Response::new(to_pod(&meta, &self.pod_rootfs(&name), leader)))
    }

    /// `rustypods reload`: reread the conf from disk (hand edits) + apply.
    async fn reload_pod_config(
        &self,
        req: Request<PodRef>,
    ) -> Result<Response<Pod>, Status> {
        let name = proto::validate_name(&req.into_inner().name)
            .map_err(bad)?
            .to_string();
        let meta = state::load_pod(&self.cfg.data_dir, &name).map_err(int)?;
        {
            let mut st = self.st.lock().await;
            if !st.pods.contains_key(&name) {
                return Err(Status::not_found(format!("pod {name} not found")));
            }
            st.pods.insert(name.clone(), meta.clone());
        }
        if dbus::leader_pid(&self.dbus, &name).await.is_some() {
            dbus::apply_limits(&self.dbus, &name, &meta.limits)
                .await
                .map_err(int)?;
        }
        apply_storage_cap(&self.cfg, &meta).map_err(int)?;
        let leader = dbus::leader_pid(&self.dbus, &name).await;
        Ok(Response::new(to_pod(&meta, &self.pod_rootfs(&name), leader)))
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
        let dir = proto::shm_host_dir(&pod);
        std::fs::create_dir_all(&dir).map_err(int)?;
        let path = dir.join(&name);
        let f = std::fs::File::create(&path).map_err(int)?;
        f.set_len(req.size_bytes).map_err(int)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).map_err(int)?;
        let _ = std::os::unix::fs::chown(
            &path,
            Some(self.cfg.allowed_uid),
            Some(self.cfg.allowed_uid),
        );
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
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                if let Ok(md) = e.metadata() {
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
        Ok(Response::new(ShmList { segs }))
    }

    async fn remove_shm(&self, req: Request<ShmRef>) -> Result<Response<Empty>, Status> {
        let req = req.into_inner();
        let pod = proto::validate_name(&req.pod).map_err(bad)?.to_string();
        let name = proto::validate_name(&req.name).map_err(bad)?.to_string();
        let path = proto::shm_host_dir(&pod).join(&name);
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
        {
            let st = self.st.lock().await;
            if !st.pods.contains_key(&name) {
                return Err(Status::not_found(format!("pod {name} not found")));
            }
        }
        let Some(leader) = dbus::leader_pid(&self.dbus, &name).await else {
            return Err(Status::failed_precondition(format!("pod {name} is not running")));
        };
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        crate::exec::run(start, &self.pod_rootfs(&name), leader, stream, tx)
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
            let first = rx.borrow().clone();
            if tx.send(Ok(first)).await.is_err() {
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
        _req: Request<PodRef>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        Err(Status::unimplemented(
            "log streaming lands in a later phase — see /var/lib/rustypods/logs",
        ))
    }
}

/// Rootless podman lives in the user's store — root can't reach it, so the
/// export runs as that user and tar (as root) writes the real uids.
fn import_distrobox(user: &str, container: &str, dest: &Path) -> Result<()> {
    let uid_out = SyncCommand::new("id")
        .args(["-u", user])
        .output()
        .context("id -u")?;
    let uid = String::from_utf8_lossy(&uid_out.stdout).trim().to_string();
    let mut exp = SyncCommand::new("runuser")
        .args(["-u", user, "--"])
        .arg("env")
        .arg(format!("XDG_RUNTIME_DIR=/run/user/{uid}"))
        .args(["podman", "export", container])
        .stdout(Stdio::piped())
        .spawn()
        .context("runuser podman export")?;
    let mut tar = SyncCommand::new("tar")
        .args(["-x", "-C"])
        .arg(dest)
        .stdin(exp.stdout.take().context("export stdout")?)
        .spawn()
        .context("tar")?;
    let s_exp = exp.wait()?;
    let s_tar = tar.wait()?;
    if !s_exp.success() {
        bail!("podman export '{container}' failed — does the box exist? (podman ps -a)");
    }
    if !s_tar.success() {
        bail!("tar extract into {} failed", dest.display());
    }
    Ok(())
}

/// Validate "hostPort:podPort[/proto]" — both ports must be 1..=65535.
fn validate_port(spec: &str) -> Result<()> {
    let (ports, proto) = match spec.split_once('/') {
        Some((p, pr)) => (p, Some(pr)),
        None => (spec, None),
    };
    let ok = matches!(proto, None | Some("tcp") | Some("udp"))
        && ports.split(':').count() == 2
        && ports
            .split(':')
            .all(|s| s.parse::<u16>().map(|n| n > 0).unwrap_or(false));
    if ok {
        Ok(())
    } else {
        bail!("invalid port mapping '{spec}' — expected hostPort:podPort[/tcp|/udp]")
    }
}

/// Apply/clear the pod's btrfs qgroup cap. Best-effort caller sites decide
/// whether failure is fatal (config apply) or a warning (pod start).
fn apply_storage_cap(cfg: &Config, meta: &PodMeta) -> Result<()> {
    if !btrfs::is_btrfs(&cfg.data_dir) {
        if meta.storage_max_bytes > 0 {
            bail!("storage_max needs btrfs — {} is not", cfg.data_dir.display());
        }
        return Ok(());
    }
    btrfs::quota_enable(&cfg.data_dir)?;
    btrfs::set_quota_limit(&cfg.pods_dir().join(&meta.name), meta.storage_max_bytes)
}

/// Strip distrobox/podman runtime artifacts so `systemd-nspawn --boot` gets a
/// clean Arch rootfs: host binds aren't in the export, but init leftovers are.
/// `container_id` = the distrobox name — host wrappers in ~/.local/bin check
/// CONTAINER_ID and exec the local binary directly when it matches.
fn sanitize_rootfs(root: &Path, container_id: &str) -> Result<()> {
    for rel in [
        "etc/hostname",
        "etc/hosts",
        "etc/resolv.conf",
        "usr/bin/entrypoint",
        "usr/bin/distrobox-init",
        "usr/bin/distrobox-export",
        "usr/bin/distrobox-host-exec",
    ] {
        let p = root.join(rel);
        if p.exists() || p.is_symlink() {
            let _ = std::fs::remove_file(&p);
        }
    }
    // Empty machine-id = uninitialized → container generates its own.
    std::fs::write(root.join("etc/machine-id"), b"")?;
    let _ = std::fs::remove_dir_all(root.join("run/host"));
    if let Ok(rd) = std::fs::read_dir(root.join("etc/profile.d")) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().contains("distrobox") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    // distrobox-export wrappers in ~/.local/bin branch on CONTAINER_ID:
    // matching the source box name makes them exec the real /usr/bin binary.
    // Fallback for unset CONTAINER_ID: a shim at the absolute path the
    // wrappers call, stripping "-n <box> --" and exec'ing the payload.
    let mut envf = std::fs::read_to_string(root.join("etc/environment")).unwrap_or_default();
    if !envf.contains("CONTAINER_ID=") {
        envf.push_str(&format!("CONTAINER_ID={container_id}\n"));
        std::fs::write(root.join("etc/environment"), envf)?;
    }
    let shim = root.join("usr/bin/distrobox-enter");
    std::fs::write(
        &shim,
        "#!/bin/sh\n# rustypods shim: inside an nspawn pod, exec the payload directly.\nwhile [ $# -gt 0 ]; do [ \"$1\" = \"--\" ] && { shift; break; }; shift; done\nexec \"$@\"\n",
    )?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))?;

    // In-pod telemetry agent: enabled unit, binary comes via the ro-bind of
    // /var/lib/rustypods/bin → /run/rustypods/bin at pod start.
    let unit_dir = root.join("etc/systemd/system");
    let wants_dir = unit_dir.join("multi-user.target.wants");
    std::fs::create_dir_all(&wants_dir)?;
    std::fs::write(
        unit_dir.join("rustypods-agent.service"),
        "[Unit]\nDescription=RustyPods in-pod telemetry agent\nAfter=local-fs.target\n\n[Service]\nExecStart=/run/rustypods/bin/rustypods-agent\nRestart=always\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n",
    )?;
    let link = wants_dir.join("rustypods-agent.service");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink("../rustypods-agent.service", &link)?;
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

    // System-bus connection — machined/systemd calls go through zbus,
    // no subprocesses anymore.
    let dbus_conn = zbus::Connection::system()
        .await
        .context("connecting to system D-Bus")?;

    // Wake machined (socket-activated; best effort).
    let _ = dbus::wake_machined(&dbus_conn).await;

    let st = Arc::new(Mutex::new(state::load(&cfg.data_dir)));
    let metrics: MetricsMap = Default::default();
    let listeners: ListenerMap = Default::default();
    let svc = Svc {
        cfg: cfg.clone(),
        st: st.clone(),
        metrics: metrics.clone(),
        listeners: listeners.clone(),
        dbus: dbus_conn.clone(),
    };

    // Daemon restarted while pods kept running → rebind their agent channels.
    let running: Vec<String> = {
        let guard = st.lock().await;
        guard.pods.keys().cloned().collect()
    };
    for name in running {
        let run_dir = proto::run_dir(&cfg.data_dir, &name);
        if dbus::leader_pid(&dbus_conn, &name).await.is_some() {
            if let Err(e) =
                agent::spawn_listener(&run_dir, &name, metrics.clone(), listeners.clone()).await
            {
                tracing::warn!("agent-listener {name}: {e:#}");
            }
        }
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
        .add_service(PodControlServer::new(svc))
        .serve_with_incoming_shutdown(incoming, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    let _ = std::fs::remove_file(&cfg.socket);
    Ok(())
}
