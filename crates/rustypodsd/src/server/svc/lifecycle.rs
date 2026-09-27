use super::super::*;
use crate::{ingress, net};

impl super::super::Svc {
    pub(crate) async fn clone_pod_work(
        &self,
        req: Request<ClonePodRequest>,
    ) -> Result<Response<Pod>, Status> {
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
            tracing::warn!(
                "cloning running pod {src} — snapshot is atomic but mid-write state is live"
            );
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
            format: 1,
            name: dest.clone(),
            created_unix: state::now_unix(),
            started: false,
            stopped_by_user: false,
            stop_timeout_secs: 0,
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
        Ok(Response::new(to_pod(
            &meta,
            &dst_root,
            None,
            "",
            self.mesh_prefix(),
        )))
    }
    pub(crate) async fn destroy_pod_work(
        &self,
        req: Request<PodRef>,
    ) -> Result<Response<Empty>, Status> {
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
        self.stop_engine(&name).await?;
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
        // Snapshots before the conf: a failure here must leave the pod
        // registered so a retry can finish, and a later pod of the same
        // name cannot inherit this time machine. Console logs are left
        // for the log-retention path.
        let snaps = self.snaps_dir(&name);
        if snaps.is_dir() {
            let entries: Vec<_> = std::fs::read_dir(&snaps)
                .map_err(int)?
                .flatten()
                .map(|e| e.path())
                .collect();
            for path in entries {
                self.st_delete(&path).await?;
            }
            std::fs::remove_dir(&snaps).map_err(int)?;
        }
        self.st_delete(&self.pod_rootfs(&name)).await?;
        state::remove_pod(&self.cfg.data_dir, &name).map_err(int)?;
        crate::runtime::logs::remove_pod_logs(&self.cfg.logs_dir(), &name).map_err(int)?;
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
        self.release_op_slot(&name).await;
        self.stop_intent.lock().await.remove(&name);
        self.health.lock().await.remove(&name);
        self.sync_mesh_names().await;
        Ok(Response::new(Empty {}))
    }
    /// One snapshot-GC sweep: per-pod retention from the conf (keep_last
    /// count cap and/or max_age) applied to snapshots/<pod>/, newest first.
    pub(crate) async fn gc_snapshots(&self) {
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
                if snapshot_expired(
                    i,
                    s.created_unix,
                    m.snap_keep_last,
                    m.snap_max_age_secs,
                    now,
                ) {
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
    pub(crate) async fn halt_pod(
        &self,
        name: &str,
        user_intent: bool,
    ) -> Result<Response<Pod>, Status> {
        {
            let st = self.st.lock().await;
            if !st.pods.contains_key(name) {
                return Err(Status::not_found(format!("pod {name} not found")));
            }
        }
        let _op = self.pod_op(name).await;
        let meta = {
            let st = self.st.lock().await;
            st.pods.get(name).cloned()
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
            if let Err(e) = self.sync_ingress(Some(name), false).await {
                tracing::warn!("ingress drain before {name} stop: {e}");
            }
        }
        // Record intent immediately before the engine stop, after
        // precondition checks: a refused gateway stop must not stick,
        // and a racing supervisor tick must not see "dead + no intent".
        // Supervisor-driven halts do not persist user intent.
        if user_intent {
            self.stop_intent.lock().await.insert(name.to_string());
            self.persist_stop_intent(name, true).await?;
        }
        self.stop_engine(name).await?;
        agent::stop_listener(&self.listeners, &self.metrics, name).await;
        let st = self.st.lock().await;
        let Some(m) = st.pods.get(name) else {
            return Err(Status::not_found(format!("pod {name} not found")));
        };
        let p = to_pod(
            m,
            &self.pod_rootfs(name),
            None,
            &self.health_view(name).await,
            self.mesh_prefix(),
        );
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
        self.sync_mesh_names().await;
        Ok(Response::new(p))
    }
    /// Write `stopped_by_user` through to the conf. The in-memory
    /// `stop_intent` set is updated by the caller (it must be visible
    /// before this await, so a tick cannot miss it).
    pub(crate) async fn persist_stop_intent(
        &self,
        name: &str,
        stopped: bool,
    ) -> Result<(), Status> {
        let meta = {
            let mut st = self.st.lock().await;
            let Some(m) = st.pods.get_mut(name) else {
                return Ok(());
            };
            if m.stopped_by_user == stopped {
                return Ok(());
            }
            m.stopped_by_user = stopped;
            m.clone()
        };
        self.save_pod(&meta).map_err(int)
    }
    /// <data>/snapshots/<pod>/ — one subvolume per commit.
    pub(crate) fn snaps_dir(&self, pod: &str) -> std::path::PathBuf {
        self.cfg.data_dir.join("snapshots").join(pod)
    }
    /// Scan a pod's snapshot dir, newest first.
    pub(crate) fn snapshots(&self, pod: &str) -> Vec<Snapshot> {
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
        out.sort_by_key(|s| std::cmp::Reverse(s.created_unix));
        out
    }
    pub(crate) async fn start_pod_work(
        &self,
        req: Request<StartPodRequest>,
    ) -> Result<Response<Pod>, Status> {
        if self.cfg.role == crate::ha::Role::Witness {
            return Err(Status::failed_precondition(
                "a witness votes and does not start pods",
            ));
        }
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
        // intentional-stop marker before the engine runs, so a failed
        // start still counts as "user wants this up" and the supervisor
        // retries. Persisted so a daemon restart mid-start does the same.
        self.stop_intent.lock().await.remove(&name);
        self.persist_stop_intent(&name, false).await?;
        if self.engine.running_pid(&name).await.is_some() {
            return Err(Status::failed_precondition(format!(
                "pod {name} is already running"
            )));
        }
        let meta = {
            let mut st = self.st.lock().await;
            let next_idx = state::alloc_net_index(&st.pods, &st.reserved_net);
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
        let mut binds = Vec::with_capacity(meta.binds.len() + meta.volumes.len());
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
        // Named volumes: auto-create missing ones (hand-edited confs can
        // reference volumes that don't exist yet), then bind-mount like
        // any other host dir.
        for spec in &meta.volumes {
            let v = proto::parse_volume_spec(spec).map_err(bad)?;
            self.ensure_volume(&v.name).await.map_err(int)?;
            binds.push(proto::BindSpec {
                host: proto::volumes_dir(&self.cfg.data_dir)
                    .join(&v.name)
                    .display()
                    .to_string(),
                pod: v.target,
                ro: v.ro,
            });
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
        // Pod env merges over the image env: same KEY wins. Boot pods
        // get --setenv on PID 1 (image env is empty for them anyway).
        let mut env = env;
        for kv in &meta.env {
            let key = kv.split('=').next().unwrap_or(kv);
            env.retain(|e| e.split('=').next() != Some(key));
            env.push(kv.clone());
        }
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
        // Mesh-DNS: networked standalone pods get a resolv.conf bound
        // onto /etc/resolv.conf pointing at fd<host>::1. Failure is a
        // warning, not fatal — worst case the pod keeps upstream DNS
        // only and can't resolve pod names.
        if needs_network && meta.stack.is_empty() {
            if let Some(m) = self.mesh() {
                match self.mesh_resolv_bind(&rootfs, &name, m.host_addr) {
                    Ok(b) => binds.push(b),
                    Err(e) => tracing::warn!("mesh resolv.conf for {name}: {e:#}"),
                }
            }
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
        // No-userns pods run the image's systemd-tmpfiles as host root.
        // An rw bind of /tmp (desktop) makes `q /tmp` and `D /tmp/.X11-unix`
        // apply to the HOST. Mask the vendor snippets that own those paths.
        if !meta.private_users {
            mask_host_tmpfiles(&rootfs, &binds).map_err(int)?;
        }
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
                let _ = self.stop_engine(&name).await;
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
            if let Err(e) = net::configure_veth(&name, meta.net_index, leader.unwrap_or(0)).await {
                agent::stop_listener(&self.listeners, &self.metrics, &name).await;
                let _ = self.stop_engine(&name).await;
                return Err(int(e));
            }
            // Mesh identity is part of "started" too — a pod that can't
            // take its mesh addr while the mesh is up would report
            // running yet be unreachable cluster-wide. Same unwind.
            if let Some(m) = self.mesh() {
                if let Err(e) =
                    net::configure_mesh_addr(meta.net_index, leader.unwrap_or(0), m.prefix).await
                {
                    agent::stop_listener(&self.listeners, &self.metrics, &name).await;
                    let _ = self.stop_engine(&name).await;
                    return Err(int(e));
                }
            }
        }
        // Gateway control-plane readiness before NAT: the snapshot push
        // below needs a live UDS, and a gateway whose dataplane never
        // bound its socket must not stay half-started.
        if meta.ingress_gateway {
            if let Err(e) = self.wait_ingress_ready().await {
                agent::stop_listener(&self.listeners, &self.metrics, &name).await;
                let _ = self.stop_engine(&name).await;
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
                    let _ = self.stop_engine(&name).await;
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
                let _ = self.stop_engine(&name).await;
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
        let pod = to_pod(
            &m,
            &rootfs,
            leader,
            &self.health_view(&name).await,
            self.mesh_prefix(),
        );
        drop(st);
        self.sync_mesh_names().await;
        Ok(Response::new(pod))
    }
    pub(crate) async fn stop_pod_work(
        &self,
        req: Request<PodRef>,
    ) -> Result<Response<Pod>, Status> {
        let name = proto::validate_name(&req.into_inner().name)
            .map_err(bad)?
            .to_string();
        self.halt_pod(&name, true).await
    }
    pub(crate) async fn create_pod_work(
        &self,
        req: Request<CreatePodRequest>,
    ) -> Result<Response<Pod>, Status> {
        if self.cfg.role == crate::ha::Role::Witness {
            return Err(Status::failed_precondition(
                "a witness votes and does not create pods",
            ));
        }
        let req = req.into_inner();
        let name = proto::validate_name(&req.name).map_err(bad)?.to_string();
        if name == proto::INGRESS_POD {
            return Err(Status::failed_precondition(
                "{name} is reserved — use `rustypods ingress init`",
            ));
        }
        let _op = self.pod_op(&name).await;
        let image = proto::validate_name(&req.image).map_err(bad)?.to_string();
        let _img = self.pod_op(&format!("image:{image}")).await;
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
        if req.stop_timeout_secs > 600 {
            return Err(Status::invalid_argument(
                "stop_timeout_secs must be 0 (default 8s) or 1..=600",
            ));
        }
        let hc = req
            .healthcheck
            .as_ref()
            .map(health_from_proto)
            .transpose()
            .map_err(bad)?
            .unwrap_or_default();
        proto::validate_env(&req.env).map_err(bad)?;
        for spec in &req.volumes {
            proto::parse_volume_spec(spec).map_err(bad)?;
        }
        if let Err(e) = self.st_clone(&img_dir, &dest).await {
            // A partial dest (fallback cp died mid-copy) would wedge the
            // name on "already exists" forever — clean it like pull/import.
            let _ = self.st_delete(&dest).await;
            return Err(e);
        }
        let meta = PodMeta {
            format: 1,
            name: name.clone(),
            image,
            created_unix: state::now_unix(),
            limits: limits_from(req.limits)
                .with_create_defaults()
                .map_err(|e| Status::internal(format!("daemon environment: {e:#}")))?,
            ephemeral: false,
            // userns on by default; desktop pods share the home dir and need
            // host-uid identity, so they opt out.
            private_users: !req.desktop,
            started: false,
            stopped_by_user: false,
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
            env: req.env.clone(),
            volumes: req.volumes.clone(),
            host_access: false,
            isolated: false,
            allow_setuid: false,
            stop_timeout_secs: req.stop_timeout_secs,
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
        for spec in &meta.volumes {
            let v = proto::parse_volume_spec(spec).map_err(bad)?;
            self.ensure_volume(&v.name).await.map_err(int)?;
        }
        self.save_pod(&meta).map_err(int)?;
        Ok(Response::new(to_pod(
            &meta,
            &dest,
            None,
            "",
            self.mesh_prefix(),
        )))
    }
    pub(crate) async fn commit_pod_work(
        &self,
        req: Request<CommitPodRequest>,
    ) -> Result<Response<Snapshot>, Status> {
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
            tracing::warn!(
                "commit on running pod {pod} — snapshot is atomic but mid-write state is live"
            );
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
    pub(crate) async fn rollback_pod_work(
        &self,
        req: Request<RollbackPodRequest>,
    ) -> Result<Response<Pod>, Status> {
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
                if req.snapshot.is_empty() {
                    "s".to_string()
                } else {
                    format!(" '{}'", req.snapshot)
                }
            )));
        };
        self.stop_engine(&pod).await?; // rollback discards live state
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
        // Staging is a disposable clone. `.rollback-old` is the previous
        // rootfs — never delete it before the swap has succeeded, or a
        // crash in between leaves the pod with no tree.
        if staging.exists() || staging.symlink_metadata().is_ok() {
            self.st_delete(&staging).await?;
        }
        if !rootfs.exists() && backup.symlink_metadata().is_ok() {
            std::fs::rename(&backup, &rootfs).map_err(int)?;
            tracing::warn!("rollback {pod}: restored missing rootfs from .rollback-old");
        }
        self.st_clone(snap_path, &staging).await?;
        if rootfs.exists() {
            match exchange_rename(&rootfs, &staging) {
                Ok(()) => {
                    // staging now holds the previous tree.
                    if let Err(e) = self.st_delete(&staging).await {
                        tracing::warn!(
                            "rollback {pod}: previous rootfs left at {}: {e}",
                            staging.display()
                        );
                    }
                    if backup.symlink_metadata().is_ok() {
                        if let Err(e) = self.st_delete(&backup).await {
                            tracing::warn!("rollback {pod}: leftover .rollback-old: {e}");
                        }
                    }
                }
                Err(e) => {
                    if backup.symlink_metadata().is_ok() {
                        let _ = self.st_delete(&staging).await;
                        return Err(int(anyhow::anyhow!(
                            "atomic exchange failed ({e}) and {pod}.rollback-old already exists — refusing to delete it"
                        )));
                    }
                    if let Err(re) = std::fs::rename(&rootfs, &backup) {
                        let _ = self.st_delete(&staging).await;
                        return Err(int(anyhow::anyhow!(
                            "exchange failed ({e}); rename aside also failed: {re}"
                        )));
                    }
                    if let Err(re) = std::fs::rename(&staging, &rootfs) {
                        let restore = std::fs::rename(&backup, &rootfs).err();
                        let _ = self.st_delete(&staging).await;
                        return Err(int(match restore {
                            Some(r) => anyhow::anyhow!(
                                "exchange failed ({e}); install failed ({re}); restore failed ({r})"
                            ),
                            None => anyhow::anyhow!(
                                "exchange failed ({e}); install failed ({re}); original restored"
                            ),
                        }));
                    }
                    if let Err(de) = self.st_delete(&backup).await {
                        tracing::warn!("rollback {pod}: leftover .rollback-old: {de}");
                    }
                }
            }
        } else if let Err(e) = std::fs::rename(&staging, &rootfs) {
            return Err(int(e));
        }
        {
            let mut st = self.st.lock().await;
            if let Some(m) = st.pods.get_mut(&pod) {
                m.started = false;
                let m = m.clone();
                let _ = self.save_pod(&m);
            }
        }
        tracing::info!("rollback {pod} → snapshot {}", snap.id);
        Ok(Response::new(to_pod(
            &meta,
            &rootfs,
            None,
            &self.health_view(&pod).await,
            self.mesh_prefix(),
        )))
    }
    pub(crate) async fn update_pod_config_work(
        &self,
        req: Request<UpdatePodConfigRequest>,
    ) -> Result<Response<Pod>, Status> {
        let req = req.into_inner();
        let name = proto::validate_name(&req.name).map_err(bad)?.to_string();
        let _op = self.pod_op(&name).await;
        self.apply_pod_config(req).await.map(Response::new)
    }
}
