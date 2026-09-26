use super::super::*;
use crate::{mesh, net};

impl super::super::Svc {
    /// Give every running standalone pod its mesh /128 — used after
    /// `mesh init`/daemon restart when pods outlived the daemon (or
    /// were started before the mesh existed). Idempotent: both the
    /// route and the addr use `replace`.
    pub(crate) async fn assign_mesh_addrs(&self) {
        let Some(m) = self.mesh() else { return };
        let pods: Vec<PodMeta> = {
            let st = self.st.lock().await;
            st.pods
                .values()
                .filter(|p| p.net_index > 0 && p.stack.is_empty())
                .cloned()
                .collect()
        };
        for p in pods {
            if let Some(leader) = self.engine.running_pid(&p.name).await {
                if let Err(e) = net::configure_mesh_addr(p.net_index, leader, m.prefix).await {
                    tracing::warn!("mesh addr for {}: {e:#}", p.name);
                }
            }
        }
        self.sync_mesh_names().await;
    }
    /// The live mesh handle, if the Wave I mesh is up.
    pub(crate) fn mesh(&self) -> Option<Arc<mesh::Mesh>> {
        match self.mesh.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => {
                tracing::error!("mesh lock poisoned; continuing with the inner value");
                poisoned.into_inner().clone()
            }
        }
    }
    /// Shared mesh-deinit body: cancel pump, delete rp-mesh0, strip pod
    /// /128s, remove conf/mesh.conf. Idempotent.
    pub(crate) async fn mesh_down(&self) -> Result<MeshStatus, Status> {
        let _lc = self.mesh_lifecycle.lock().await;
        let m = self
            .mesh
            .write()
            .map_err(|e| int(anyhow::anyhow!("{e}")))?
            .take();
        self.stop_mesh_rpc().await;
        if let Some(m) = m {
            self.remove_mesh_addrs(m.prefix).await;
            m.shutdown().await;
            state::remove_mesh(&self.cfg.data_dir).map_err(int)?;
            tracing::info!("mesh down: rp-mesh0 removed, conf/mesh.conf deleted");
        }
        Ok(MeshStatus {
            enabled: false,
            ..Default::default()
        })
    }
    /// This host's mesh /48 when the Wave I mesh is up — to_pod derives
    /// each pod's mesh_ip from it (never persisted).
    pub(crate) fn mesh_prefix(&self) -> Option<std::net::Ipv6Addr> {
        self.mesh().map(|m| m.prefix)
    }
    /// Shared mesh-init body for the gRPC handler and REST facade.
    /// `token` adopts the introducer's cluster secret when joining an
    /// existing mesh; empty/absent keeps or generates our own.
    pub(crate) async fn mesh_up(
        &self,
        listen_port: u32,
        token: &str,
    ) -> Result<MeshStatus, Status> {
        let _lc = self.mesh_lifecycle.lock().await;
        if let Some(m) = self.mesh() {
            return Ok(m.status().await);
        }
        let mut conf = match state::load_mesh(&self.cfg.data_dir) {
            Ok(c) => c.unwrap_or_default(),
            Err(e) => {
                return Err(Status::failed_precondition(format!(
                    "refusing to mesh init: {e:#}"
                )));
            }
        };
        if conf.private_key.is_empty() {
            let (priv_, _pub) = mesh::keygen();
            conf.private_key = priv_;
        }
        if !token.is_empty() {
            if !conf.cluster_token.is_empty() && conf.cluster_token != token {
                return Err(Status::failed_precondition(
                    "cluster token already set — refusing to rotate implicitly \
                     (edit conf/mesh.conf by hand if you really mean it)",
                ));
            }
            conf.cluster_token = token.to_string();
        }
        if conf.cluster_token.is_empty() {
            let mut raw = [0u8; 32];
            use std::io::Read;
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut raw))
                .map_err(int)?;
            conf.cluster_token = raw.iter().map(|b| format!("{b:02x}")).collect();
        }
        if let Some(port) =
            mesh::checked_listen_port(listen_port).map_err(Status::invalid_argument)?
        {
            conf.listen_port = port;
        }
        state::save_mesh(&self.cfg.data_dir, &conf).map_err(int)?;
        let m = mesh::Mesh::start(&self.cfg.data_dir, conf)
            .await
            .map_err(int)?;
        let status = m.status().await;
        {
            let mut g = self.mesh.write().map_err(|e| int(anyhow::anyhow!("{e}")))?;
            if let Some(old) = g.replace(m) {
                // init raced init — the loser's socket is already
                // bound; shut it down async, the winner stays.
                tokio::spawn(async move { old.shutdown().await });
            }
        }
        // Pods already running get their /128 now — mesh init must not
        // require a pod restart to take effect.
        self.assign_mesh_addrs().await;
        // Cluster plane: peer daemons reach this host's PodControl on
        // [fd<host>::1]:5306 — token-gated, plus the nft ::1-src guard.
        self.spawn_mesh_rpc().await;
        Ok(status)
    }

    /// TCP port the mesh-RPC listener serves on.
    pub(crate) const MESH_RPC_PORT: u16 = 5306;

    /// Start the cluster-plane listener on [fd<host>::1]:5306 if the
    /// mesh is up and it isn't already. Every request must carry the
    /// `x-cluster-token` metadata matching conf/mesh.conf — the nft
    /// guard narrows sources to peer daemon addrs but a pod on a peer
    /// can forge an ::1 source, so the token is the real gate.
    pub(crate) async fn spawn_mesh_rpc(&self) {
        {
            // A dead task must not block a respawn forever — clear a
            // finished handle so deinit→init (or a crashed listener) can
            // recover the cluster plane.
            let mut guard = match self.mesh_rpc_stop.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            match guard.as_ref() {
                Some((_, h)) if !h.is_finished() => return,
                _ => *guard = None,
            }
        }
        let Some(m) = self.mesh() else { return };
        let token = match m.ensure_cluster_token().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("cluster token init failed — mesh-RPC listener off: {e:#}");
                return;
            }
        };
        let (tx, rx) = tokio::sync::watch::channel(false);
        let svc = self.clone();
        let handle = tokio::spawn(async move {
            // Bind inside the task with a short retry — a just-stopped
            // listener may still be draining in-flight streams.
            let mut listener = None;
            for _ in 0..12 {
                match tokio::net::TcpListener::bind((m.host_addr, Self::MESH_RPC_PORT)).await {
                    Ok(l) => {
                        listener = Some(l);
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                    Err(e) => {
                        tracing::error!(
                            "mesh-RPC bind [{}]:{} failed: {e}",
                            m.host_addr,
                            Self::MESH_RPC_PORT
                        );
                        return;
                    }
                }
            }
            let Some(listener) = listener else {
                tracing::error!(
                    "mesh-RPC bind [{}]:{} still in use after retries — listener off",
                    m.host_addr,
                    Self::MESH_RPC_PORT
                );
                return;
            };
            tracing::info!(
                "mesh-RPC listening on [{}]:{}",
                m.host_addr,
                Self::MESH_RPC_PORT
            );
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            let mut rx = rx;
            let res = Server::builder()
                .concurrency_limit_per_connection(32)
                .layer(tower::limit::GlobalConcurrencyLimitLayer::new(256))
                .add_service(PodControlServer::with_interceptor(
                    svc,
                    move |req: Request<()>| {
                        let ok = req
                            .metadata()
                            .get("x-cluster-token")
                            .and_then(|v| v.to_str().ok())
                            .map(|v| v == token)
                            .unwrap_or(false);
                        if ok {
                            Ok(req)
                        } else {
                            Err(Status::unauthenticated("missing/invalid x-cluster-token"))
                        }
                    },
                ))
                .serve_with_incoming_shutdown(incoming, async move {
                    let _ = rx.changed().await;
                })
                .await;
            if let Err(e) = res {
                tracing::error!("mesh-RPC server exited: {e:#}");
            }
        });
        {
            let mut guard = match self.mesh_rpc_stop.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            *guard = Some((tx, handle));
        }
    }

    /// Stop the mesh-RPC listener (mesh deinit / daemon shutdown) and
    /// wait briefly for the port to release so a following `init` can
    /// rebind immediately.
    pub(crate) async fn stop_mesh_rpc(&self) {
        let tup = match self.mesh_rpc_stop.lock() {
            Ok(mut g) => g.take(),
            Err(p) => p.into_inner().take(),
        };
        if let Some((tx, h)) = tup {
            let _ = tx.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
        }
    }
    /// `mesh deinit` counterpart: strip every pod's mesh /128. Best-
    /// effort per pod — a pod mid-stop just logs and moves on.
    pub(crate) async fn remove_mesh_addrs(&self, prefix: std::net::Ipv6Addr) {
        let pods: Vec<PodMeta> = {
            let st = self.st.lock().await;
            st.pods
                .values()
                .filter(|p| p.net_index > 0 && p.stack.is_empty())
                .cloned()
                .collect()
        };
        for p in pods {
            if let Some(leader) = self.engine.running_pid(&p.name).await {
                if let Err(e) = net::remove_mesh_addr(p.net_index, leader, prefix).await {
                    tracing::warn!("mesh addr removal for {}: {e:#}", p.name);
                }
            }
        }
    }
    /// Push the running standalone pods into the mesh registry (name →
    /// mesh addr). Called on every lifecycle edge; a no-op diff inside
    /// set_local_names keeps the announce quiet when nothing changed.
    pub(crate) async fn sync_mesh_names(&self) {
        let Some(m) = self.mesh() else { return };
        let pods: Vec<PodMeta> = {
            let st = self.st.lock().await;
            st.pods
                .values()
                .filter(|p| p.net_index > 0 && p.stack.is_empty())
                .cloned()
                .collect()
        };
        let mut names = std::collections::BTreeMap::new();
        for p in pods {
            if self.engine.running_pid(&p.name).await.is_some() {
                names.insert(p.name.clone(), mesh::mesh_ip(m.prefix, p.net_index));
            }
        }
        m.set_local_names(names).await;
    }
    /// Mesh-DNS (Wave K): write a resolv.conf pointing the pod at the
    /// host's mesh addr (fd<host>::1:53) with the real upstream as
    /// fallback, and return the ro bind over /etc/resolv.conf.
    ///
    /// The file lives in a daemon-owned directory that is never bind-mounted
    /// into a pod. The per-pod run dir is chowned to the pod and is therefore
    /// attacker-controlled between runs — `fs::write` there would follow a
    /// planted symlink. The rootfs target is created through the rootfs
    /// helpers so a symlink at `etc` or `etc/resolv.conf` cannot redirect
    /// the create onto the host.
    pub(crate) fn mesh_resolv_bind(
        &self,
        rootfs: &Path,
        name: &str,
        host_addr: std::net::Ipv6Addr,
    ) -> Result<proto::BindSpec, Status> {
        let mut content = format!("nameserver {host_addr}\n");
        if let Some(up) = net::upstream_resolver() {
            // Loopback stubs (127.0.0.53) are unreachable from the pod's
            // netns — only offer a fallback the pod can actually dial;
            // our responder already relays upstream itself.
            if !up.ip().is_loopback() {
                content += &format!("nameserver {}\n", up.ip());
            }
        }
        content += "search rp pods\n";
        let file = write_daemon_file(
            &self.cfg.resolv_dir(),
            &format!("{name}.conf"),
            content.as_bytes(),
            0o644,
        )
        .map_err(int)?;
        ensure_resolv_target(rootfs).map_err(int)?;
        Ok(proto::BindSpec {
            host: file.display().to_string(),
            pod: "/etc/resolv.conf".into(),
            ro: true,
        })
    }
}
