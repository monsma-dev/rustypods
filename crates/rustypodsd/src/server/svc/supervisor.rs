use super::super::*;
use crate::{exec, net};

impl super::super::Svc {
    /// Supervisor health string for Pod.health — "" when the pod isn't
    /// under supervision (stopped, or no probe and no restart policy).
    pub(crate) async fn health_view(&self, name: &str) -> String {
        self.health
            .lock()
            .await
            .get(name)
            .map(|h| h.status)
            .unwrap_or("")
            .to_string()
    }
    /// Run one liveness probe; true = healthy. Any error or timeout is
    /// a failure.
    pub(crate) async fn probe(&self, m: &PodMeta, spec: &state::HealthSpec) -> bool {
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
    /// exec probe: run argv inside the pod via the same nsenter path as
    /// `rustypods exec` — exit 0 = healthy. Identity is `healthcheck.user`
    /// from the conf; unset means pod root in userns pods but an
    /// unprivileged user (nobody/65534) in pods WITHOUT a user namespace,
    /// where root would be host root. A hung probe is group-killed and
    /// reaped on timeout so it can't accumulate every interval.
    pub(crate) async fn probe_exec(
        &self,
        m: &PodMeta,
        spec: &state::HealthSpec,
        timeout: Duration,
    ) -> bool {
        let Some(leader) = self.engine.running_pid(&m.name).await else {
            return false;
        };
        let rootfs = self.pod_rootfs(&m.name);
        let user = if !spec.user.is_empty() {
            spec.user.clone()
        } else if m.private_users {
            String::new()
        } else {
            exec::default_probe_user(&rootfs)
        };
        let start = ExecStart {
            pod: m.name.clone(),
            user,
            argv: spec.argv.clone(),
            tty: false,
            rows: 0,
            cols: 0,
            env: vec![],
            workdir: String::new(),
        };
        let plan = match exec::exec_plan(leader, &rootfs, &start, m.private_users) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("{}: exec probe: {e:#}", m.name);
                return false;
            }
        };
        if plan.host_root {
            tracing::debug!(
                "{}: exec probe runs as HOST root (healthcheck.user = root, no userns)",
                m.name
            );
        }
        match exec::run_status(&plan, timeout).await {
            Ok(Some(s)) => s.success(),
            Ok(None) => {
                tracing::warn!("{}: exec probe timed out — killed", m.name);
                false
            }
            Err(e) => {
                tracing::warn!("{}: exec probe spawn: {e:#}", m.name);
                false
            }
        }
    }
    /// http probe: plain HTTP/1.1 GET — 2xx/3xx = healthy. "/path"
    /// targets the pod's own veth address :80; a full
    /// "http://host[:port]/path" URL is dialed verbatim (numeric hosts
    /// only — the daemon never resolves DNS).
    pub(crate) async fn probe_http(&self, m: &PodMeta, target: &str, timeout: Duration) -> bool {
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
    /// tcp probe: a completed connect = healthy. ":port" targets the
    /// pod's own veth address; "host:port" is dialed verbatim.
    pub(crate) async fn probe_tcp(&self, m: &PodMeta, target: &str, timeout: Duration) -> bool {
        let Some(addr) = probe_addr(m, target) else {
            return false;
        };
        matches!(
            tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await,
            Ok(Ok(_))
        )
    }
    /// Current running set from the engine's point of view.
    pub(crate) async fn running_set(&self) -> BTreeSet<String> {
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
    /// One supervisor tick: death-watch + liveness probes for every pod
    /// that opted in (restart policy or healthcheck) plus the managed
    /// gateway. Per-pod failures are logged, never fatal to the loop.
    pub(crate) async fn supervise_once(&self) {
        let pods: Vec<PodMeta> = {
            let st = self.st.lock().await;
            st.pods
                .values()
                .filter(|m| supervised(m))
                .cloned()
                .collect()
        };
        let now = std::time::Instant::now();
        // One slow start (ingress wait, D-Bus) must not stall death-watch
        // for every other pod. The semaphore caps parallelism; this
        // function is awaited by the tick, so a pod has at most one
        // in-flight action.
        let sem = Arc::new(tokio::sync::Semaphore::new(SUPERVISE_PARALLEL));
        let mut joins = Vec::with_capacity(pods.len());
        for m in pods {
            let permit = match sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let svc = self.clone();
            joins.push(tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = svc.supervise_pod(&m, now).await {
                    tracing::warn!("supervise {}: {e:#}", m.name);
                }
            }));
        }
        for join in joins {
            if let Err(e) = join.await {
                tracing::error!("supervise task panicked: {e}");
            }
        }
    }
    /// Supervise one pod: restart on leader death per its policy, run
    /// the configured probe when due, restart on sustained failure under
    /// "always". Decisions are taken under the health lock; the actions
    /// themselves run after it drops (start/stop re-enter health_view).
    pub(crate) async fn supervise_pod(&self, m: &PodMeta, now: std::time::Instant) -> Result<()> {
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
            let user_stopped = self.stop_intent.lock().await.contains(&m.name);
            if !running && supervisor_idle(m.started, m.stopped_by_user, user_stopped) {
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
    pub(crate) async fn supervised_restart(&self, m: &PodMeta, why: &str) -> Result<()> {
        tracing::warn!(
            "{}: {why} — restarting (policy {})",
            m.name,
            restart_policy(m)
        );
        if self.engine.running_pid(&m.name).await.is_some() {
            // Not a user stop — leave stopped_by_user clear so a crash
            // between this halt and the following start still restarts.
            if let Err(e) = self.halt_pod(&m.name, false).await {
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
                ent.backoff_until = Some(std::time::Instant::now() + Duration::from_secs(secs));
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
}
