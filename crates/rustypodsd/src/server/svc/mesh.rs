use super::super::*;
use crate::{mesh, net};
use std::net::SocketAddr;

/// rustls already required a mesh-CA client certificate. This records
/// which node it is, and refuses a certificate whose IP SAN is not the
/// TCP source. Handlers can read [`crate::meshca::MeshNodeId`].
fn require_mesh_peer(mut req: Request<()>) -> Result<Request<()>, Status> {
    let der = req
        .peer_certs()
        .and_then(|certs| certs.first().cloned())
        .ok_or_else(|| Status::unauthenticated("mesh peer certificate required"))?;
    let id = crate::meshca::identity_from_der(der.as_ref()).map_err(|e| {
        tracing::debug!("mesh peer certificate rejected: {e:#}");
        Status::unauthenticated("mesh peer certificate rejected")
    })?;
    let src = req
        .remote_addr()
        .ok_or_else(|| Status::unauthenticated("mesh peer address missing"))?;
    let SocketAddr::V6(src) = src else {
        return Err(Status::unauthenticated("mesh peer is not IPv6"));
    };
    if *src.ip() != id.addr {
        return Err(Status::unauthenticated(
            "mesh peer certificate does not match the source address",
        ));
    }
    tracing::debug!(dns = %id.dns, addr = %id.addr, "mesh peer authenticated");
    req.extensions_mut().insert(id);
    Ok(req)
}

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
        // Close the accept socket first, then delete the drop table.
        // The other order would open :5306 for the whole teardown window.
        self.stop_mesh_rpc().await;
        match tokio::task::spawn_blocking(net::remove_mesh_rpc_guard).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!("mesh rpc guard teardown: {e:#}"),
            Err(e) => tracing::warn!("mesh rpc guard teardown task: {e}"),
        }
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
            // A previous init may have stored the mesh and then failed
            // the guard. Retry both so :5306 never listens unguarded.
            self.sync_mesh_rpc_guard().await?;
            self.spawn_mesh_rpc().await;
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
        // Install the kernel drop before the listener binds, so a local
        // connect to :5306 cannot land in the accept queue.
        self.sync_mesh_rpc_guard().await?;
        self.spawn_mesh_rpc().await;
        Ok(status)
    }

    /// Rebuild `inet rustypods-mesh-rpc` from the live peer set. An empty
    /// set still installs the drop, which is what closes :5306 on `lo`.
    pub(crate) async fn sync_mesh_rpc_guard(&self) -> Result<(), Status> {
        let Some(m) = self.mesh() else {
            return Ok(());
        };
        let addrs = m.peer_host_addrs().await;
        tokio::task::spawn_blocking(move || net::ensure_mesh_rpc_guard(&addrs))
            .await
            .map_err(|e| int(anyhow::anyhow!("mesh rpc guard task: {e}")))?
            .map_err(int)
    }

    /// Add a peer, then rebuild the :5306 guard. The nft error is
    /// returned after the session exists so the operator sees that the
    /// kernel filter did not catch up.
    pub(crate) async fn apply_mesh_peer(
        &self,
        endpoint: &str,
        pubkey: &str,
        name: &str,
    ) -> Result<MeshStatus, Status> {
        let Some(m) = self.mesh() else {
            return Err(Status::failed_precondition(
                "mesh not initialized — run `rustypods mesh init` first",
            ));
        };
        let alias = (!name.is_empty()).then_some(name);
        m.add_peer(endpoint, pubkey, alias).await.map_err(bad)?;
        self.sync_mesh_rpc_guard().await?;
        Ok(m.status().await)
    }

    /// Remove a peer, then rebuild the guard so that host's `fd…::1`
    /// loses its accept. A missing peer does not touch nft.
    pub(crate) async fn drop_mesh_peer(&self, pubkey: &str) -> Result<MeshStatus, Status> {
        let Some(m) = self.mesh() else {
            return Err(Status::failed_precondition(
                "mesh not initialized — run `rustypods mesh init` first",
            ));
        };
        if !m.remove_peer(pubkey).await.map_err(bad)? {
            return Err(Status::not_found("no such mesh peer"));
        }
        self.sync_mesh_rpc_guard().await?;
        Ok(m.status().await)
    }

    /// TCP port the mesh-RPC listener serves on.
    pub(crate) const MESH_RPC_PORT: u16 = 5306;

    /// Start the cluster-plane listener on [fd<host>::1]:5306 if the
    /// mesh is up and it isn't already. The TCP listener requires mTLS
    /// with the mesh CA; the UDS listener stays plaintext. A handshake
    /// that cannot present a mesh-CA client certificate never reaches
    /// HTTP/2. Gossip still uses the cluster token, which is why that
    /// token is minted here even though RPC no longer reads it.
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
        if let Err(e) = m.ensure_cluster_token().await {
            tracing::error!("cluster token init failed — mesh-RPC listener off: {e:#}");
            return;
        }
        let data_dir = self.cfg.data_dir.clone();
        let allowed_uid = self.cfg.allowed_uid;
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
            if let Err(e) = crate::meshca::share_node_key(&data_dir, allowed_uid) {
                tracing::warn!(
                    "mesh node key stays root-only; `rustypods --host` cannot present it: {e:#}"
                );
            }
            let material = match crate::meshca::load_material(&data_dir) {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!("mesh-RPC TLS material missing — listener off: {e:#}");
                    return;
                }
            };
            let _ = rustls::crypto::ring::default_provider().install_default();
            let tls = tonic::transport::ServerTlsConfig::new()
                .identity(tonic::transport::Identity::from_pem(
                    material.node_crt,
                    material.node_key,
                ))
                .client_ca_root(tonic::transport::Certificate::from_pem(material.ca_crt));
            let mut server = match Server::builder()
                .concurrency_limit_per_connection(32)
                .layer(tower::limit::GlobalConcurrencyLimitLayer::new(256))
                .tls_config(tls)
            {
                Ok(server) => server,
                Err(e) => {
                    tracing::error!("mesh-RPC TLS config refused — listener off: {e:#}");
                    return;
                }
            };
            tracing::info!(
                "mesh-RPC listening on [{}]:{} (mTLS)",
                m.host_addr,
                Self::MESH_RPC_PORT
            );
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            let mut rx = rx;
            let res = server
                .add_service(PodControlServer::with_interceptor(svc, require_mesh_peer))
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

#[cfg(test)]
mod tests {
    #[test]
    fn missing_peer_cert_is_rejected() {
        let err = super::require_mesh_peer(tonic::Request::new(())).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn server_tls_config_builds_from_mesh_material() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("rp-mtls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let host = "fd12:3456:789a::1".parse().unwrap();
        crate::meshca::ensure(&dir, "pubkey", host).unwrap();
        let material = crate::meshca::load_material(&dir).unwrap();
        let tls = tonic::transport::ServerTlsConfig::new()
            .identity(tonic::transport::Identity::from_pem(
                &material.node_crt,
                &material.node_key,
            ))
            .client_ca_root(tonic::transport::Certificate::from_pem(&material.ca_crt));
        tonic::transport::Server::builder()
            .tls_config(tls)
            .expect("mesh material must build a client-authenticated TLS acceptor");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
