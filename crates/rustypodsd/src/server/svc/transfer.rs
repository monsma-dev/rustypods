use super::super::*;
use crate::transfer;

impl super::super::Svc {
    /// `rustypods export <pod>`: serialize the pod — rootfs, conf, image
    /// conf and every attached named volume — as one archive stream
    /// (transfer.rs container format). On btrfs the payload is a
    /// multi-subvolume `btrfs send` of read-only snapshots; elsewhere a
    /// tar stream. A running pod is cgroup-frozen for the snapshot
    /// window so rootfs + volumes capture one point in time. The pod op
    /// lock is held until the stream ends so destroy/rollback cannot
    /// race the send. Any exporter failure is an error frame — the
    /// stream never ends cleanly on a partial payload.
    pub(crate) async fn export_archive(
        &self,
        name: &str,
        format: &str,
        allow_inconsistent: bool,
    ) -> Result<ReceiverStream<Result<ExportChunk, Status>>, Status> {
        let pod = proto::validate_name(name).map_err(bad)?.to_string();
        let meta = {
            let st = self.st.lock().await;
            st.pods.get(&pod).cloned()
        }
        .ok_or_else(|| Status::not_found(format!("pod {pod} not found")))?;
        if meta.ingress_gateway {
            return Err(Status::failed_precondition(
                "the managed ingress gateway is per-host infrastructure — run init-ingress on the target host",
            ));
        }
        let op = self.pod_op(&pod).await;

        let mut vol_names = Vec::new();
        for spec in &meta.volumes {
            let v = proto::parse_volume_spec(spec).map_err(bad)?;
            if v.name == pod {
                return Err(Status::failed_precondition(format!(
                    "volume '{pod}' shares the pod name — archive entries would collide; rename it first"
                )));
            }
            vol_names.push(v.name);
        }
        let (image_conf, volume_confs) = {
            let st = self.st.lock().await;
            (
                st.images
                    .get(&meta.image)
                    .and_then(|m| toml::to_string(m).ok()),
                vol_names
                    .iter()
                    .filter_map(|n| {
                        st.volumes
                            .get(n)
                            .and_then(|m| toml::to_string(m).ok().map(|t| (n.clone(), t)))
                    })
                    .collect(),
            )
        };
        let host_btrfs = self.storage.name() == "btrfs";
        let use_btrfs = transfer::export_uses_btrfs(format, host_btrfs).map_err(bad)?;

        let staging_dir = self
            .cfg
            .data_dir
            .join(transfer::unique_staging_name("export"));
        let warnings = if use_btrfs {
            let scope = self.engine.scope_name(&pod).await;
            let freeze_path = scope.map(|u| {
                std::path::PathBuf::from("/sys/fs/cgroup/machine.slice")
                    .join(u)
                    .join("cgroup.freeze")
            });
            let rootfs = self.pod_rootfs(&pod);
            let vols_dir = proto::volumes_dir(&self.cfg.data_dir);
            let stage = staging_dir.clone();
            let vols = vol_names.clone();
            let pname = pod.clone();
            match Self::blocking(move || {
                let mut freeze = FreezeGuard { path: None };
                let freeze_failed = match &freeze_path {
                    Some(p) => {
                        if std::fs::write(p, "1").is_ok() {
                            freeze.path = Some(p.clone());
                            false
                        } else {
                            true
                        }
                    }
                    None => false,
                };
                if freeze_failed {
                    let msg = "cgroup freeze failed — snapshot would be crash-consistent only";
                    tracing::warn!("{msg} for pod {pname}");
                    if !allow_inconsistent {
                        bail!(
                            "{msg}; export aborted. Pass --allow-inconsistent to continue anyway"
                        );
                    }
                }
                std::fs::create_dir_all(&stage)?;
                storage::btrfs::snapshot_ro(&rootfs, &stage.join(&pname))?;
                for v in &vols {
                    storage::btrfs::snapshot_ro(&vols_dir.join(v), &stage.join(v))?;
                }
                let mut notes = Vec::new();
                if freeze_failed {
                    notes.push(
                        "cgroup freeze failed; archive is crash-consistent only (--allow-inconsistent)"
                            .to_string(),
                    );
                }
                Ok(notes)
            })
            .await
            {
                Ok(w) => w,
                Err(e) => {
                    clean_staging(&staging_dir, &self.storage).await;
                    return Err(e);
                }
            }
        } else {
            Vec::new()
        };

        let manifest = transfer::Manifest {
            format: if use_btrfs {
                "btrfs".into()
            } else {
                "tar".into()
            },
            pod_conf: toml::to_string(&meta).map_err(int)?,
            image_conf,
            volume_confs,
            exported_unix: state::now_unix(),
            warnings: warnings.clone(),
        };
        let head = transfer::header(&manifest).map_err(int)?;

        let mut child = if use_btrfs {
            let mut args: Vec<std::ffi::OsString> = vec![staging_dir.join(&pod).into_os_string()];
            args.extend(
                vol_names
                    .iter()
                    .map(|v| staging_dir.join(v).into_os_string()),
            );
            tokio::process::Command::new("btrfs")
                .arg("send")
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(int)?
        } else {
            let mut cmd = tokio::process::Command::new("tar");
            cmd.args(transfer::tar_create_flags())
                .arg("-cf")
                .arg("-")
                .arg("-C")
                .arg(self.cfg.pods_dir())
                .arg(&pod);
            for v in &vol_names {
                cmd.arg("-C")
                    .arg(proto::volumes_dir(&self.cfg.data_dir))
                    .arg(v);
            }
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(int)?
        };

        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let storage = self.storage.clone();
        tokio::spawn(async move {
            let _op = op;
            for w in warnings {
                if tx
                    .send(Ok(ExportChunk {
                        data: Vec::new(),
                        warning: w,
                    }))
                    .await
                    .is_err()
                {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    clean_staging(&staging_dir, &storage).await;
                    return;
                }
            }
            if tx
                .send(Ok(ExportChunk {
                    data: head,
                    warning: String::new(),
                }))
                .await
                .is_err()
            {
                let _ = child.kill().await;
                let _ = child.wait().await;
                clean_staging(&staging_dir, &storage).await;
                return;
            }
            let Some(mut stdout) = child.stdout.take() else {
                let _ = tx
                    .send(Err(Status::internal("export child has no stdout")))
                    .await;
                let _ = child.kill().await;
                let _ = child.wait().await;
                clean_staging(&staging_dir, &storage).await;
                return;
            };
            let stderr = child.stderr.take();
            let stderr_task = tokio::spawn(async move {
                let mut buf = Vec::new();
                if let Some(mut stderr) = stderr {
                    let mut tmp = [0u8; 512];
                    loop {
                        match stderr.read(&mut tmp).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                transfer::push_capped(&mut buf, &tmp[..n], transfer::STDERR_CAP)
                            }
                        }
                    }
                }
                String::from_utf8_lossy(&buf).trim().to_string()
            });
            let mut hasher = transfer::PayloadHasher::new();
            let mut buf = vec![0u8; transfer::CHUNK];
            let mut failed: Option<String> = None;
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) => break,
                    Err(e) => {
                        failed = Some(format!("reading export payload: {e}"));
                        let _ = child.kill().await;
                        break;
                    }
                    Ok(n) => {
                        hasher.update(&buf[..n]);
                        if tx
                            .send(Ok(ExportChunk {
                                data: buf[..n].to_vec(),
                                warning: String::new(),
                            }))
                            .await
                            .is_err()
                        {
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                            let _ = stderr_task.await;
                            clean_staging(&staging_dir, &storage).await;
                            return;
                        }
                    }
                }
            }
            let status = child.wait().await;
            let err_text = stderr_task.await.unwrap_or_default();
            match (failed, status) {
                (Some(msg), _) => {
                    let extra = if err_text.is_empty() {
                        String::new()
                    } else {
                        format!(": {err_text}")
                    };
                    let _ = tx
                        .send(Err(Status::internal(format!("{msg}{extra}"))))
                        .await;
                }
                (None, Ok(st)) if st.success() => {
                    let _ = tx
                        .send(Ok(ExportChunk {
                            data: hasher.trailer().to_vec(),
                            warning: String::new(),
                        }))
                        .await;
                }
                (None, Ok(st)) => {
                    let _ = tx
                        .send(Err(Status::internal(format!(
                            "export command exited {st}: {err_text}"
                        ))))
                        .await;
                }
                (None, Err(e)) => {
                    let _ = tx
                        .send(Err(Status::internal(format!(
                            "waiting for export command: {e}: {err_text}"
                        ))))
                        .await;
                }
            }
            clean_staging(&staging_dir, &storage).await;
        });
        Ok(ReceiverStream::new(rx))
    }

    /// `rustypods load`: reconstruct an exported pod. The manifest is
    /// peeled off first (format + name/volume collisions refuse before
    /// the payload is committed). Version 2 stages the payload, checks
    /// the trailer, then unpacks; a mismatch deletes staging and fails.
    /// Version 1 still loads, with a warning that it has no checksum.
    pub(crate) async fn import_archive<S>(&self, mut stream: S) -> Result<Pod, Status>
    where
        S: tokio_stream::Stream<Item = Result<ImportChunk, Status>> + Unpin + Send + 'static,
    {
        use rustypods_proto::rpc::import_chunk::Kind;
        let mut head: Vec<u8> = Vec::new();
        let mut rename: Option<String> = None;
        let mut trust = false;
        let (manifest, payload, version) = loop {
            let c = match stream.next().await {
                None => {
                    return Err(Status::invalid_argument(
                        "empty import stream — expected archive bytes",
                    ))
                }
                Some(Err(e)) => return Err(e),
                Some(Ok(c)) => c,
            };
            match c.kind {
                Some(Kind::Options(o)) => {
                    if !head.is_empty() {
                        return Err(Status::invalid_argument(
                            "options must precede archive data",
                        ));
                    }
                    if !o.rename.is_empty() {
                        rename = Some(o.rename);
                    }
                    trust = o.trust;
                }
                Some(Kind::Data(d)) => {
                    head.extend_from_slice(&d);
                    if head.len() > 12 + transfer::MAX_MANIFEST {
                        return Err(Status::invalid_argument("manifest exceeds cap"));
                    }
                    if let Some(parsed) = transfer::parse_header(&head).map_err(bad)? {
                        let off = parsed.payload_off;
                        let version = parsed.version;
                        break (parsed.manifest, head.split_off(off), version);
                    }
                }
                None => {}
            }
        };

        transfer::reject_incompatible_payload(&manifest.format, self.storage.name())
            .map_err(bad)?;

        let meta: PodMeta = toml::from_str(&manifest.pod_conf).map_err(bad)?;
        let orig_name = meta.name.clone();
        let (meta, report) =
            transfer::sanitize_import(meta, rename.as_deref(), trust).map_err(bad)?;
        state::check_pod_meta(&meta, &meta.name, true)
            .map_err(|e| bad(anyhow::anyhow!("imported pod conf invalid: {e:#}")))?;

        let _op = self.pod_op(&meta.name).await;
        {
            let st = self.st.lock().await;
            if st.pods.contains_key(&meta.name) {
                return Err(Status::already_exists(format!(
                    "pod {} already exists",
                    meta.name
                )));
            }
            for v in manifest.volume_confs.keys() {
                if st.volumes.contains_key(v)
                    || proto::volumes_dir(&self.cfg.data_dir).join(v).exists()
                {
                    return Err(Status::failed_precondition(format!(
                        "volume {v} already exists on this host — refusing to overwrite data"
                    )));
                }
            }
        }
        if self.pod_rootfs(&meta.name).exists() {
            return Err(Status::already_exists(format!(
                "rootfs for {} already exists",
                meta.name
            )));
        }

        let staging = self
            .cfg
            .data_dir
            .join(transfer::unique_staging_name("import"));
        std::fs::create_dir_all(&staging).map_err(int)?;
        let mut guard = StagingGuard {
            dir: staging.clone(),
            storage: self.storage.clone(),
            armed: true,
        };
        let payload_path = staging.join(".payload");
        let mut file = tokio::fs::File::create(&payload_path).await.map_err(int)?;
        let mut acc = transfer::PayloadWriter::new(version, transfer::import_max_bytes());
        let first = acc.push(&payload).map_err(bad)?;
        if !first.is_empty() {
            file.write_all(&first).await.map_err(int)?;
        }
        while let Some(c) = stream.next().await {
            let c = c?;
            if let Some(Kind::Data(d)) = c.kind {
                let out = acc.push(&d).map_err(bad)?;
                if !out.is_empty() {
                    file.write_all(&out).await.map_err(int)?;
                }
            }
        }
        acc.finish().map_err(bad)?;
        file.flush().await.map_err(int)?;
        drop(file);

        if version < 2 {
            tracing::warn!(
                "importing RPEX0001 archive for pod {} — no integrity trailer",
                meta.name
            );
        }

        if manifest.format == "btrfs" {
            let f = std::fs::File::open(&payload_path).map_err(int)?;
            let out = tokio::process::Command::new("btrfs")
                .arg("receive")
                .arg("--chroot")
                .arg(&staging)
                .stdin(Stdio::from(f))
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(int)?;
            if !out.status.success() {
                return Err(Status::internal(format!(
                    "btrfs receive failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
        } else if trust {
            let f = std::fs::File::open(&payload_path).map_err(int)?;
            let out = tokio::process::Command::new("tar")
                .args(transfer::tar_extract_flags())
                .arg("-xf")
                .arg("-")
                .arg("-C")
                .arg(&staging)
                .stdin(Stdio::from(f))
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(int)?;
            if !out.status.success() {
                return Err(Status::internal(format!(
                    "tar extract failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
        } else {
            let path = payload_path.clone();
            let stage = staging.clone();
            Self::blocking(move || {
                let f = std::fs::File::open(&path)?;
                transfer::unpack_tar_payload(f, &stage, false)
            })
            .await?;
        }
        let _ = std::fs::remove_file(&payload_path);

        {
            let vols_dir = proto::volumes_dir(&self.cfg.data_dir);
            let stage = staging.clone();
            let rootfs_dst = self.pod_rootfs(&meta.name);
            let orig = orig_name.clone();
            let vols: Vec<String> = manifest.volume_confs.keys().cloned().collect();
            let btrfs = manifest.format == "btrfs";
            let storage = self.storage.clone();
            Self::blocking(move || {
                let mut placed = Vec::new();
                let r = (|| -> Result<()> {
                    let rootfs_src = stage.join(&orig);
                    if !rootfs_src.exists() {
                        bail!("archive payload did not contain pod rootfs '{orig}'");
                    }
                    if btrfs {
                        storage.clone_rootfs(&rootfs_src, &rootfs_dst)?;
                    } else {
                        std::fs::rename(&rootfs_src, &rootfs_dst)?;
                    }
                    placed.push(rootfs_dst);
                    for v in &vols {
                        let src = stage.join(v);
                        if !src.exists() {
                            bail!("archive payload missing volume '{v}'");
                        }
                        let dst = vols_dir.join(v);
                        if btrfs {
                            storage.clone_rootfs(&src, &dst)?;
                        } else {
                            std::fs::rename(&src, &dst)?;
                        }
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o777))?;
                        placed.push(dst);
                    }
                    Ok(())
                })();
                if r.is_err() {
                    for p in &placed {
                        let _ = storage.delete_rootfs(p);
                    }
                }
                r
            })
            .await?;
        }
        clean_staging(&staging, &self.storage).await;
        guard.armed = false;

        for (vname, vtoml) in &manifest.volume_confs {
            if let Ok(v) = toml::from_str::<VolumeMeta>(vtoml) {
                state::save_volume(&self.cfg.data_dir, &v).map_err(int)?;
                self.st.lock().await.volumes.insert(vname.clone(), v);
            }
        }
        let have_image = {
            let st = self.st.lock().await;
            st.images.contains_key(&meta.image)
        };
        if !have_image {
            if let Some(itoml) = &manifest.image_conf {
                if let Ok(im) = toml::from_str::<ImageMeta>(itoml) {
                    state::save_image(&self.cfg.data_dir, &im).map_err(int)?;
                    self.st.lock().await.images.insert(im.name.clone(), im);
                }
            }
        }
        state::save_pod(&self.cfg.data_dir, &meta).map_err(int)?;
        self.st
            .lock()
            .await
            .pods
            .insert(meta.name.clone(), meta.clone());
        tracing::info!(
            "imported pod {} (from '{}' archive, {} volumes, trust={trust})",
            meta.name,
            orig_name,
            manifest.volume_confs.len()
        );
        let rootfs = self.pod_rootfs(&meta.name);
        let mut pod = to_pod(
            &meta,
            &rootfs,
            None,
            &self.health_view(&meta.name).await,
            self.mesh_prefix(),
        );
        let mut notes = report.notes;
        if version < 2 {
            notes.insert(
                0,
                "RPEX0001 archive has no integrity trailer; checksum was not verified".into(),
            );
        }
        for w in &manifest.warnings {
            notes.push(format!("export warning: {w}"));
        }
        pod.notes = notes;
        Ok(pod)
    }
}

/// Rootless podman lives in the user's store — root can't reach it, so the
/// export runs as that user. The tarball is staged to a temp file next to
/// `dest` (same fs — same pattern as oci::pull_layer) and then fed to the
/// in-tree hardened untar (`oci::unpack_tar`): normalized paths, no device
/// nodes, symlink-safe whiteout handling — strictly stronger than piping
/// into GNU `tar -x`.
pub(crate) fn import_distrobox(user: &str, container: &str, dest: &Path) -> Result<()> {
    let uid_out = SyncCommand::new("id")
        .args(["-u", user])
        .output()
        .context("id -u")?;
    if !uid_out.status.success() {
        bail!(
            "id -u {user} failed: {}",
            String::from_utf8_lossy(&uid_out.stderr).trim()
        );
    }
    let uid = String::from_utf8_lossy(&uid_out.stdout).trim().to_string();
    let inspect = SyncCommand::new("runuser")
        .args(["-u", user, "--"])
        .arg("env")
        .arg(format!("XDG_RUNTIME_DIR=/run/user/{uid}"))
        .args([
            "podman",
            "inspect",
            "--format",
            "{{json .HostConfig.IDMappings}}",
            container,
        ])
        .output()
        .context("runuser podman inspect")?;
    if !inspect.status.success() {
        bail!(
            "podman inspect '{container}' failed — does the box exist? (podman ps -a): {}",
            String::from_utf8_lossy(&inspect.stderr).trim()
        );
    }
    let idmap = oci::IdMap::from_podman_json(&String::from_utf8_lossy(&inspect.stdout))
        .with_context(|| format!("reading the id mapping of '{container}'"))?;
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
            let mut f =
                std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            std::io::copy(&mut out, &mut f)
                .map(|_| ())
                .context("reading podman export stream")
        });
    let s_exp = exp.wait()?;
    copy_res?;
    if !s_exp.success() {
        bail!("podman export '{container}' failed — does the box exist? (podman ps -a)");
    }
    std::fs::File::open(&tmp)
        .with_context(|| format!("open {}", tmp.display()))
        .and_then(|f| oci::unpack_tar_remapped(f, dest, &idmap))
        .with_context(|| format!("extracting export into {}", dest.display()))
}
