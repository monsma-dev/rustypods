use super::super::*;
use crate::{net, stack};

impl super::super::Svc {
    pub(crate) async fn apply_stack_work(
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
        // `placement` is resolved CLI-side: the CLI rewrites the toml per
        // target host and strips the key before ApplyStack. A toml that
        // still carries it was aimed at the wrong layer — refuse loudly
        // instead of materialising foreign members on this host.
        if let Some((member, p)) = def.pods.iter().find(|(_, p)| p.placement.is_some()) {
            return Err(bad(anyhow::anyhow!(
                "pods.{member}: placement '{}' must be resolved by the CLI — \
                 run `rustypods apply` (without --remote/--host) on a \
                 mesh-connected daemon",
                p.placement.as_deref().unwrap_or_default()
            )));
        }
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
        if member_ingress.keys().any(|n| n == proto::INGRESS_POD) {
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
                .unwrap_or_else(|| state::alloc_net_index(&st.pods, &st.reserved_net))
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
                        format: 1,
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
                        stopped_by_user: false,
                        stop_timeout_secs: 0,
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
                        env: sp.env.clone(),
                        volumes: sp.volumes.clone(),
                        host_access: sp.host_access,
                        isolated: sp.isolated,
                        allow_setuid: false,
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
            for spec in &meta.volumes {
                let v = proto::parse_volume_spec(spec).map_err(bad)?;
                self.ensure_volume(&v.name).await.map_err(int)?;
            }
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
            h.iter()
                .map(|(k, v)| (k.clone(), v.status.to_string()))
                .collect()
        };
        let pods = out
            .iter()
            .map(|m| {
                to_pod(
                    m,
                    &self.pod_rootfs(&m.name),
                    None,
                    hmap.get(&m.name).map(String::as_str).unwrap_or(""),
                    self.mesh_prefix(),
                )
            })
            .collect();
        Ok(Response::new(ApplyStackResponse {
            name: def.name,
            pods,
        }))
    }
}
