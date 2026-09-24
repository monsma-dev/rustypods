use super::super::*;

impl super::super::Svc {
    /// Quota calls spawn `btrfs` subprocesses — off the async executor.
    pub(crate) async fn apply_storage_cap(&self, meta: &PodMeta) -> Result<()> {
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
    /// Make a named volume exist on disk + in the registry. Idempotent;
    /// called wherever a pod's volume specs resolve (create/update/start)
    /// so even hand-edited confs auto-materialise their volumes. A dir
    /// that exists without a conf entry (conf deleted by hand) is
    /// adopted rather than rejected.
    pub(crate) async fn ensure_volume(&self, name: &str) -> Result<VolumeMeta, Status> {
        let name = proto::validate_name(name).map_err(bad)?.to_string();
        let _vol = self.pod_op(&format!("volume:{name}")).await;
        {
            let st = self.st.lock().await;
            if let Some(v) = st.volumes.get(&name) {
                return Ok(v.clone());
            }
        }
        let dir = proto::volumes_dir(&self.cfg.data_dir).join(&name);
        // Single statx — cheap enough for the executor; the create/delete
        // below stay on the blocking pool.
        let existed = match std::fs::symlink_metadata(&dir) {
            Ok(md) => {
                if !md.is_dir() {
                    return Err(Status::failed_precondition(format!(
                        "volume path {} exists but is not a directory",
                        dir.display()
                    )));
                }
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(int(e)),
        };
        if !existed {
            self.st_create(&dir).await?;
        }
        // Pod roots under --private-users map to an arbitrary host UID —
        // a plain root-owned 0755 dir would be read-only inside the pod.
        // Volumes are shared writable space: 0777 keeps every userns
        // mapping (and non-userns pods) able to write, like /tmp.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).map_err(int)?;
        }
        let v = VolumeMeta {
            format: 1,
            name,
            created_unix: state::now_unix(),
        };
        state::save_volume(&self.cfg.data_dir, &v).map_err(int)?;
        let mut st = self.st.lock().await;
        st.volumes.insert(v.name.clone(), v.clone());
        Ok(v)
    }
    /// Pod names whose conf references this volume (for `volume ls`/`rm`).
    pub(crate) async fn volume_attachers(&self, name: &str) -> Vec<String> {
        let st = self.st.lock().await;
        volume_refs(&st, name)
    }
    /// VolumeMeta → wire view: path, byte usage, attaching pods.
    pub(crate) async fn volume_info(&self, v: &VolumeMeta) -> VolumeInfo {
        let dir = proto::volumes_dir(&self.cfg.data_dir).join(&v.name);
        let size_bytes = Self::blocking({
            let d = dir.clone();
            move || dir_size(&d)
        })
        .await
        .unwrap_or(0);
        VolumeInfo {
            name: v.name.clone(),
            path: dir.display().to_string(),
            created_unix: v.created_unix,
            size_bytes,
            pods: self.volume_attachers(&v.name).await,
        }
    }
}
