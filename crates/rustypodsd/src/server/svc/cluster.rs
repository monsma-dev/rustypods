//! Cluster plane: daemon→daemon volume streaming over the mesh.
//!
//! `volume send <name> --to <peer>` lands here as `SendVolume`: the
//! local daemon resolves the peer, opens a token-authenticated gRPC
//! client to `fd<peer>::1:5306`, and pushes the volume as a tar or
//! btrfs-send stream. The peer's `ReceiveVolume` handler is the other
//! end. The CLI never touches the payload bytes.

use super::super::*;
use crate::transfer;
use rustypods_proto::rpc::pod_control_client::PodControlClient;
use rustypods_proto::rpc::volume_chunk::Kind as VolKind;
use std::net::Ipv6Addr;

/// The WG session is already up or the TCP connect would hang; bound it.
const CLUSTER_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Mesh-RPC port — keep in step with rustypods_client::MESH_RPC_PORT.
/// Duplicated on purpose: rustypodsd does not depend on the client
/// crate (it IS the server).
const MESH_RPC_PORT: u16 = 5306;

/// `x-cluster-token` injector for outbound peer calls.
#[derive(Clone)]
struct ClusterAuth(tonic::metadata::MetadataValue<tonic::metadata::Ascii>);

impl tonic::service::Interceptor for ClusterAuth {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        req.metadata_mut().insert("x-cluster-token", self.0.clone());
        Ok(req)
    }
}

type ClusterClient = PodControlClient<
    tonic::service::interceptor::InterceptedService<tonic::transport::Channel, ClusterAuth>,
>;

impl super::super::Svc {
    /// Open a token-authenticated PodControl channel to a peer daemon.
    async fn cluster_client(&self, peer_addr: Ipv6Addr) -> Result<ClusterClient, Status> {
        let Some(m) = self.mesh() else {
            return Err(Status::failed_precondition(
                "mesh is not up — `rustypods mesh init` first",
            ));
        };
        let token = m.cluster_token().await;
        if token.is_empty() {
            return Err(Status::failed_precondition(
                "this mesh has no cluster token — re-run `mesh init` or fix conf/mesh.conf",
            ));
        }
        let tok_val = token
            .parse()
            .map_err(|_| Status::internal("cluster token is not valid gRPC metadata"))?;
        let ep =
            tonic::transport::Endpoint::try_from(format!("http://[{peer_addr}]:{MESH_RPC_PORT}"))
                .map_err(int)?
                .connect_timeout(CLUSTER_DIAL_TIMEOUT);
        // No .timeout(): a volume stream is one long call and a per-call
        // bound would sever a big transfer mid-flight.
        let ch = ep.connect().await.map_err(|e| {
            Status::unavailable(format!(
                "dialing peer [{peer_addr}]:{MESH_RPC_PORT} over the mesh: {e}"
            ))
        })?;
        Ok(PodControlClient::with_interceptor(ch, ClusterAuth(tok_val)))
    }

    /// `volume send <name> --to <peer>` — the sending half. Resolves the
    /// peer, pings it for its storage driver to negotiate the payload
    /// format, then streams the volume (tar or btrfs send) to the
    /// peer's ReceiveVolume. The volume's op lock is held for the whole
    /// transfer so remove/rename can't race the read.
    pub(crate) async fn send_volume(
        &self,
        req: Request<SendVolumeRequest>,
    ) -> Result<Response<SendVolumeResult>, Status> {
        let req = req.into_inner();
        let vol = proto::validate_name(&req.volume).map_err(bad)?.to_string();
        {
            let st = self.st.lock().await;
            if !st.volumes.contains_key(&vol) {
                return Err(Status::not_found(format!("volume {vol} not found")));
            }
        }
        let src_dir = proto::volumes_dir(&self.cfg.data_dir).join(&vol);
        if !src_dir.is_dir() {
            return Err(Status::failed_precondition(format!(
                "volume {vol} has a conf but no data dir — corrupt state"
            )));
        }
        let Some(m) = self.mesh() else {
            return Err(Status::failed_precondition("mesh is not up"));
        };
        let (peer_disp, peer_addr) = m.resolve_peer(&req.peer).await.ok_or_else(|| {
            Status::invalid_argument(format!(
                "unknown mesh peer '{}' — see `rustypods mesh status`",
                req.peer
            ))
        })?;
        // Sending to ourselves would deadlock on the volume op lock:
        // the Send handler holds it while our own Receive handler
        // blocks acquiring it before reading the stream.
        if peer_addr == m.host_addr {
            return Err(Status::invalid_argument(
                "cannot send a volume to this host itself",
            ));
        }
        let target_name = if req.rename.is_empty() {
            vol.clone()
        } else {
            proto::validate_name(&req.rename).map_err(bad)?.to_string()
        };

        let _op = self.pod_op(&format!("volume:{vol}")).await;
        let mut peer = self.cluster_client(peer_addr).await?;

        // Format negotiation: ping the peer for its storage driver.
        // btrfs send streams only land on btrfs — anything else (and
        // everything on our AlmaLinux/XFS fleet) takes tar.
        let peer_driver = peer
            .ping(PingRequest {})
            .await
            .map_err(|e| {
                Status::unavailable(format!(
                    "peer {peer_disp} unreachable or token rejected: {e}"
                ))
            })?
            .into_inner()
            .storage_driver;
        let local_btrfs = self.storage.name() == "btrfs";
        let peer_btrfs = peer_driver == "btrfs";
        let format = match req.format.as_str() {
            "" => {
                if local_btrfs && peer_btrfs {
                    "btrfs"
                } else {
                    "tar"
                }
            }
            "tar" => "tar",
            "btrfs" => {
                if !(local_btrfs && peer_btrfs) {
                    return Err(Status::failed_precondition(format!(
                        "--format btrfs needs btrfs on both ends (local '{}', peer '{peer_driver}')",
                        self.storage.name()
                    )));
                }
                "btrfs"
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "unknown format '{other}' (expected tar or btrfs)"
                )))
            }
        };

        // Spawn the payload producer: btrfs snapshots a ro subvol into
        // staging for `btrfs send`; tar reads the live dir. Volumes are
        // data stores — a crash-consistent read is acceptable here
        // (unlike export, there is no cgroup freeze story).
        let staging_dir = self
            .cfg
            .data_dir
            .join(transfer::unique_staging_name("vsend"));
        // Armed from here on: snapshot failures, spawn failures and
        // handler cancellation must all lose the staging dir.
        let mut send_guard = StagingGuard {
            dir: staging_dir.clone(),
            storage: self.storage.clone(),
            armed: true,
        };
        let mut child = if format == "btrfs" {
            {
                let stage = staging_dir.clone();
                let src = src_dir.clone();
                Self::blocking(move || {
                    std::fs::create_dir_all(&stage)?;
                    storage::btrfs::snapshot_ro(&src, &stage.join("vol"))
                })
                .await?;
            }
            tokio::process::Command::new("btrfs")
                .arg("send")
                .arg(staging_dir.join("vol"))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(int)?
        } else {
            tokio::process::Command::new("tar")
                .args(transfer::tar_create_flags())
                // Entries land under the RECEIVER's name — the receiver
                // unpacks into volumes/ wholesale. Names are
                // [a-z0-9-_] so the sed regex needs no escaping.
                .arg("--transform")
                .arg(format!("s|^{vol}|{target_name}|"))
                .arg("-cf")
                .arg("-")
                .arg("-C")
                .arg(proto::volumes_dir(&self.cfg.data_dir))
                .arg(&vol)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(int)?
        };

        let Some(mut stdout) = child.stdout.take() else {
            return Err(Status::internal("export child has no stdout"));
        };
        // Drain stderr while stdout is still being read. Waiting until
        // the producer exits lets a full stderr pipe stall tar/btrfs
        // before it closes stdout.
        let stderr_task = child
            .stderr
            .take()
            .map(|stderr| tokio::spawn(transfer::drain_stderr(stderr)));
        let (tx, rx) = tokio::sync::mpsc::channel::<VolumeChunk>(8);

        // Producer: init frame, then raw payload bytes until EOF or
        // the receiver drops us. Reaps the child so its exit status
        // is part of the outcome, not just the stream's.
        let producer = tokio::spawn(async move {
            let mut bytes = 0u64;
            let init_ok = tx
                .send(VolumeChunk {
                    kind: Some(VolKind::Init(VolumeInit {
                        name: target_name,
                        format: format.to_string(),
                        force: req.force,
                    })),
                })
                .await
                .is_ok();
            let mut read_err: Option<String> = None;
            if init_ok {
                let mut buf = vec![0u8; transfer::CHUNK];
                loop {
                    match stdout.read(&mut buf).await {
                        Ok(0) => break,
                        Err(e) => {
                            read_err = Some(format!("reading volume payload: {e}"));
                            break;
                        }
                        Ok(n) => {
                            bytes += n as u64;
                            if tx
                                .send(VolumeChunk {
                                    kind: Some(VolKind::Data(buf[..n].to_vec())),
                                })
                                .await
                                .is_err()
                            {
                                break; // receiver hung up — child dies below
                            }
                        }
                    }
                }
            }
            let _ = child.kill().await.ok();
            let st = child.wait().await;
            (bytes, read_err, st)
        });

        let res = peer
            .receive_volume(tokio_stream::wrappers::ReceiverStream::new(rx))
            .await;
        let (bytes, read_err, child_status) = producer
            .await
            .map_err(|e| Status::internal(format!("producer task: {e}")))?;
        let err_tail = match stderr_task {
            Some(task) => task.await.unwrap_or_default(),
            None => String::new(),
        };
        clean_staging(&staging_dir, &self.storage).await;
        send_guard.armed = false;

        if let Some(e) = read_err {
            return Err(Status::internal(format!("{e}: {err_tail}")));
        }
        match child_status {
            Ok(st) if st.success() => {}
            Ok(st) => {
                return Err(Status::internal(format!(
                    "{format} producer exited {st}: {err_tail}"
                )))
            }
            Err(e) => {
                return Err(Status::internal(format!(
                    "waiting for {format} producer: {e}: {err_tail}"
                )))
            }
        }
        let res = res
            .map_err(|e| Status::internal(format!("peer {peer_disp} receive failed: {e}")))?
            .into_inner();
        Ok(Response::new(SendVolumeResult {
            volume: res.name,
            peer: peer_disp,
            bytes: res.bytes.max(bytes),
            format: format.to_string(),
        }))
    }

    /// The receiving half: client-streamed `VolumeChunk`s where the
    /// first frame carries `VolumeInit` (name + format + force). Writes
    /// the payload to a staging file, unpacks (tar → filtered unpack,
    /// btrfs → `btrfs receive`), moves the tree into volumes/, and
    /// registers the VolumeMeta so `volume ls` and pod mounts see it.
    pub(crate) async fn receive_volume<S>(
        &self,
        mut stream: S,
    ) -> Result<ReceiveVolumeResult, Status>
    where
        S: tokio_stream::Stream<Item = Result<VolumeChunk, Status>> + Unpin + Send + 'static,
    {
        // First frame: the init envelope.
        let init = loop {
            match stream.next().await {
                None => {
                    return Err(Status::invalid_argument(
                        "empty volume stream — expected an init frame",
                    ))
                }
                Some(Err(e)) => return Err(e),
                Some(Ok(c)) => match c.kind {
                    Some(VolKind::Init(i)) => break i,
                    Some(VolKind::Data(_)) => {
                        return Err(Status::invalid_argument(
                            "volume stream opened with data — init must come first",
                        ))
                    }
                    None => {}
                },
            }
        };
        let name = proto::validate_name(&init.name).map_err(bad)?.to_string();
        let format = match init.format.as_str() {
            "tar" | "btrfs" => init.format.clone(),
            other => {
                return Err(Status::invalid_argument(format!(
                    "unknown volume payload format '{other}'"
                )))
            }
        };
        if format == "btrfs" && self.storage.name() != "btrfs" {
            return Err(Status::failed_precondition(
                "peer sent a btrfs stream but this host's storage isn't btrfs",
            ));
        }
        let vols_dir = proto::volumes_dir(&self.cfg.data_dir);
        let dst = vols_dir.join(&name);
        // Fast-path check (no lock) — the authoritative one runs under
        // the op lock right before the commit, after staging.
        {
            let st = self.st.lock().await;
            if (st.volumes.contains_key(&name) || dst.exists()) && !init.force {
                return Err(Status::already_exists(format!(
                    "volume {name} already exists — resend with force to overwrite"
                )));
            }
        }

        // Stage the payload to disk first — a mid-stream abort must
        // never leave a half-written volume registered. Size-capped so
        // a peer can't fill the data dir.
        let staging = self
            .cfg
            .data_dir
            .join(transfer::unique_staging_name("vrecv"));
        std::fs::create_dir_all(&staging).map_err(int)?;
        let mut guard = StagingGuard {
            dir: staging.clone(),
            storage: self.storage.clone(),
            armed: true,
        };
        let payload_path = staging.join(".payload");
        let mut file = tokio::fs::File::create(&payload_path).await.map_err(int)?;
        let max_bytes = transfer::import_max_bytes().map_err(int)?;
        let mut bytes = 0u64;
        while let Some(c) = stream.next().await {
            let c = c?;
            if let Some(VolKind::Data(d)) = c.kind {
                bytes += d.len() as u64;
                if bytes > max_bytes {
                    return Err(Status::resource_exhausted(format!(
                        "volume payload exceeds the {} byte receive cap",
                        max_bytes
                    )));
                }
                file.write_all(&d).await.map_err(int)?;
            }
        }
        file.flush().await.map_err(int)?;
        drop(file);
        if bytes == 0 {
            return Err(Status::invalid_argument(
                "volume stream ended after init — no payload received",
            ));
        }

        // Extract into staging — nothing touches volumes/ yet.
        let staged_root = if format == "btrfs" {
            let f = std::fs::File::open(&payload_path).map_err(int)?;
            let mut child = tokio::process::Command::new("btrfs")
                .arg("receive")
                .arg("--chroot")
                .arg(&staging)
                .stdin(Stdio::from(f))
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(int)?;
            let mut errbuf: Vec<u8> = Vec::new();
            if let Some(mut s) = child.stderr.take() {
                let mut tmp = [0u8; 512];
                while let Ok(n) = s.read(&mut tmp).await {
                    if n == 0 {
                        break;
                    }
                    transfer::push_capped(&mut errbuf, &tmp[..n], transfer::STDERR_CAP);
                }
            }
            let st = child.wait().await.map_err(int)?;
            if !st.success() {
                return Err(Status::internal(format!(
                    "btrfs receive failed: {}",
                    String::from_utf8_lossy(&errbuf).trim()
                )));
            }
            // receive creates staging/<sentname> as a ro subvol — the
            // sender always names it "vol".
            let src = staging.join("vol");
            if !src.exists() {
                return Err(Status::internal(
                    "btrfs receive produced no 'vol' subvolume",
                ));
            }
            src
        } else {
            // tar: the sender rewrote entries to land under <name>/ —
            // verify every entry honours that before anything is
            // written, then create the tree through the driver (subvol
            // on btrfs, plain dir elsewhere) and unpack into it.
            self.st_create(&staging.join(&name)).await?;
            let path = payload_path.clone();
            let nm = name.clone();
            let sg = staging.clone();
            Self::blocking(move || {
                let f = std::fs::File::open(&path)?;
                transfer::tar_entries_under(&f, &nm)?;
                // Re-open: the pre-scan consumed the archive.
                let f = std::fs::File::open(&path)?;
                // Sender is a token-authenticated peer daemon — trust
                // the payload fully (device nodes and all).
                transfer::unpack_tar_payload(f, &sg, true)
            })
            .await?;
            staging.join(&name)
        };

        // Commit: under the volume op lock, re-verify the destination
        // is legal to write (a pod may have mounted it, or it may have
        // been created, while we were staging).
        let _op = self.pod_op(&format!("volume:{name}")).await;
        {
            let st = self.st.lock().await;
            let exists = st.volumes.contains_key(&name) || dst.exists();
            if exists && !init.force {
                return Err(Status::already_exists(format!(
                    "volume {name} appeared while receiving — resend with force to overwrite"
                )));
            }
            if exists && !volume_refs(&st, &name).is_empty() {
                return Err(Status::failed_precondition(format!(
                    "volume {name} is mounted by pods — detach before overwriting"
                )));
            }
        }
        if init.force && dst.exists() {
            let storage = self.storage.clone();
            let d = dst.clone();
            Self::blocking(move || storage.delete_rootfs(&d)).await?;
            state::remove_volume(&self.cfg.data_dir, &name).map_err(int)?;
            self.st.lock().await.volumes.remove(&name);
        }
        self.st_clone(&staged_root, &dst).await?;
        // Volumes are shared writable space across userns mappings.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o777)).map_err(int)?;
        }
        let v = VolumeMeta {
            format: 1,
            name: name.clone(),
            created_unix: state::now_unix(),
        };
        state::save_volume(&self.cfg.data_dir, &v).map_err(int)?;
        self.st.lock().await.volumes.insert(name.clone(), v);
        guard.armed = false;
        // Driver-aware cleanup — the staged tree may be a btrfs subvol.
        clean_staging(&staging, &self.storage).await;
        tracing::info!(
            "received volume {name} ({bytes} bytes, {format}) → {}",
            dst.display()
        );
        Ok(ReceiveVolumeResult {
            name,
            path: dst.display().to_string(),
            bytes,
        })
    }
}
