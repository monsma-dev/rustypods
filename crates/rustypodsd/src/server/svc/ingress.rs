use super::super::*;
use crate::{ingress, pki};

impl super::super::Svc {
    /// Copy the current leaf into the gateway rootfs. No restart: stopping
    /// the gateway is refused while backends have routes, and the gateway
    /// reloads the pair when tls.crt's mtime changes.
    pub(crate) async fn install_gateway_leaf(&self) -> Result<(), Status> {
        let configured = {
            let st = self.st.lock().await;
            st.pods
                .get(proto::INGRESS_POD)
                .is_some_and(|m| m.ingress_gateway)
        };
        if !configured {
            return Ok(());
        }
        let rootfs = self.pod_rootfs(proto::INGRESS_POD);
        if !rootfs.exists() {
            return Ok(());
        }
        let crt = std::fs::read(self.cfg.data_dir.join("pki").join("tls.crt")).map_err(int)?;
        let key = std::fs::read(self.cfg.data_dir.join("pki").join("tls.key")).map_err(int)?;
        Self::blocking(move || {
            crate::rootfs::mkdir_in_rootfs(&rootfs, "etc/rustypods-ingress")?;
            // Key first: the gateway's reload triggers on tls.crt's mtime,
            // so the matching key must already be in place.
            crate::rootfs::write_in_rootfs(
                &rootfs,
                "etc/rustypods-ingress/tls.key",
                &key,
                Some(0o600),
            )?;
            crate::rootfs::write_in_rootfs(
                &rootfs,
                "etc/rustypods-ingress/tls.crt",
                &crt,
                Some(0o644),
            )?;
            Ok(())
        })
        .await?;
        Ok(())
    }
    /// Renew a near-expiry leaf and, when the bytes change, put them in
    /// the gateway rootfs; the gateway hot-reloads on the cert's mtime.
    /// Runs from the 2s ingress tick but does real work at most hourly —
    /// renewal has a 30-day window, and the unconstrained-CA warning
    /// would otherwise flood the journal.
    pub(crate) async fn maintain_ingress_pki(&self) -> Result<(), Status> {
        static LAST_RUN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let now = state::now_unix();
        let last = LAST_RUN.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) < 3600 {
            return Ok(());
        }
        LAST_RUN.store(now, Ordering::Relaxed);
        let crt = self.cfg.data_dir.join("pki").join("ca.crt");
        if !crt.exists() {
            return Ok(());
        }
        let data = self.cfg.data_dir.clone();
        let before = self.cfg.data_dir.join("pki").join("tls.crt");
        let old = std::fs::read(&before).ok();
        let paths = Self::blocking(move || pki::ensure(&data)).await?;
        pki::warn_if_unconstrained(&paths);
        let new = std::fs::read(&paths.tls_crt).ok();
        if old.is_some() && old != new {
            self.install_gateway_leaf().await?;
            tracing::info!("ingress leaf renewed; gateway reloads it within 30s");
        }
        Ok(())
    }
    /// Push the complete route snapshot to the ingress gateway, if it is
    /// configured and running. `exclude` is treated as non-running (a pod
    /// being drained before stop/destroy). `required` makes the absence of
    /// a usable control endpoint fail instead of degrading to a warning —
    /// a silent skip would leave stale routes pointing at reused IPs.
    pub(crate) async fn sync_ingress(
        &self,
        exclude: Option<&str>,
        required: bool,
    ) -> Result<(), Status> {
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
        let snap = ingress::build_snapshot(pods.iter().collect(), &running, exclude, generation)
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
    pub(crate) async fn wait_ingress_ready(&self) -> Result<(), Status> {
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
