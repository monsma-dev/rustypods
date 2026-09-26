use super::*;

pub(crate) async fn run(mut cli: Cli) -> Result<()> {
    let cmd = cli.cmd.take().unwrap();
    match cmd {
        Cmd::StdioBridge { socket } => {
            stdio_bridge(&socket)?;
            return Ok(());
        }
        Cmd::Doctor => {
            if cli.remote.is_some() {
                anyhow::bail!(
                    "doctor inspects the local host; run 'rustypods doctor' on the remote host"
                );
            }
            doctor::run(cli.socket.clone()).await?;
        }
        Cmd::Shell {
            name,
            user,
            workdir,
            strict,
            cmd,
        } => {
            shell_exec(&cli, name, user, workdir, strict, cmd).await?;
        }
        Cmd::Volume { sub } => {
            let mut c = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone()).await?;
            match sub {
                VolumeCmd::Create { name } => {
                    let v = c.create_volume(VolumeRef { name }).await?.into_inner();
                    println!("volume {} → {}", v.name, v.path);
                }
                VolumeCmd::Ls => {
                    let l = c.list_volumes(Empty {}).await?.into_inner();
                    for v in &l.volumes {
                        println!(
                            "{:<24} {:>9}  pods=[{}]  {}",
                            v.name,
                            fmt_bytes(v.size_bytes),
                            v.pods.join(","),
                            v.path
                        );
                    }
                    if l.volumes.is_empty() {
                        println!("no volumes — `rustypods volume create <name>` or mount one with --volume");
                    }
                }
                VolumeCmd::Inspect { name } => {
                    let l = c.list_volumes(Empty {}).await?.into_inner();
                    let v = l
                        .volumes
                        .into_iter()
                        .find(|v| v.name == name)
                        .context(format!("volume {name} not found"))?;
                    println!("name:    {}", v.name);
                    println!("path:    {}", v.path);
                    println!("size:    {}", fmt_bytes(v.size_bytes));
                    println!("created: {}", v.created_unix);
                    println!(
                        "pods:    {}",
                        if v.pods.is_empty() {
                            "-".into()
                        } else {
                            v.pods.join(", ")
                        }
                    );
                }
                VolumeCmd::Rm { name } => {
                    if !confirm_destructive(cli.yes, &format!("Delete volume {name}?"))? {
                        println!("aborted");
                        return Ok(());
                    }
                    c.remove_volume(VolumeRef { name: name.clone() }).await?;
                    println!("volume {name} removed");
                }
                VolumeCmd::Send {
                    name,
                    to,
                    rename_as,
                    format,
                    force,
                } => {
                    if let Some(r) = &rename_as {
                        rustypods_proto::validate_name(r)
                            .with_context(|| format!("invalid --rename-as '{r}'"))?;
                    }
                    // The receiver DELETES the same-named volume before
                    // writing — same irreversibility as `volume rm`,
                    // same prompt.
                    if force
                        && !confirm_destructive(
                            cli.yes,
                            &format!(
                                "Overwrite volume {} on peer {to}? Its current data is deleted.",
                                rename_as.as_deref().unwrap_or(&name)
                            ),
                        )?
                    {
                        println!("aborted");
                        return Ok(());
                    }
                    // Long bound: the daemon streams peer→peer; a big
                    // volume legitimately outlasts the 30s default.
                    let r = connect_timeout(
                        cli.socket.clone(),
                        cli.remote.clone(),
                        cli.host.clone(),
                        LONG_RPC,
                    )
                    .await?
                    .send_volume(SendVolumeRequest {
                        volume: name.clone(),
                        peer: to,
                        rename: rename_as.unwrap_or_default(),
                        format: format.unwrap_or_default(),
                        force,
                    })
                    .await?
                    .into_inner();
                    println!(
                        "volume {} → {} [{}]  {} bytes ({})",
                        name, r.peer, r.volume, r.bytes, r.format
                    );
                }
            }
        }
        Cmd::Mesh { sub } => match sub {
            MeshCmd::Init { port, token } => {
                let st = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                    .await?
                    .mesh_init(MeshInitRequest {
                        listen_port: port,
                        token: token.unwrap_or_default(),
                    })
                    .await?
                    .into_inner();
                print_mesh_status(&st);
            }
            MeshCmd::Status => {
                let st = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                    .await?
                    .get_mesh_status(Empty {})
                    .await?
                    .into_inner();
                if !st.enabled {
                    println!("mesh disabled — `rustypods mesh init` to enable");
                } else {
                    print_mesh_status(&st);
                }
            }
            MeshCmd::AddPeer {
                endpoint,
                pubkey,
                name,
            } => {
                let st = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                    .await?
                    .mesh_add_peer(MeshPeer {
                        endpoint,
                        pubkey,
                        name: name.unwrap_or_default(),
                    })
                    .await?
                    .into_inner();
                print_mesh_status(&st);
            }
            MeshCmd::RmPeer { pubkey } => {
                let st = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                    .await?
                    .mesh_remove_peer(MeshPeer {
                        endpoint: String::new(),
                        pubkey,
                        name: String::new(),
                    })
                    .await?
                    .into_inner();
                print_mesh_status(&st);
            }
            MeshCmd::Deinit => {
                connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                    .await?
                    .mesh_deinit(Empty {})
                    .await?;
                println!("mesh down — rp-mesh0 removed, identity forgotten");
            }
        },
        Cmd::Ingress { sub } => match sub {
            IngressCmd::Init { image, install_ca } => {
                let d = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                    .await?
                    .init_ingress(InitIngressRequest { image, install_ca })
                    .await?
                    .into_inner();
                let Some(pod) = d.pod else {
                    anyhow::bail!("daemon returned no gateway pod");
                };
                // Init provisions but doesn't boot — start it like
                // `rustypods start` would (already-running is a no-op).
                let pod = if pod.state == PodState::Running as i32 {
                    pod
                } else {
                    connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                        .await?
                        .start_pod(StartPodRequest {
                            name: pod.name.clone(),
                            limits: None,
                            ephemeral: false,
                            private_users: None,
                        })
                        .await?
                        .into_inner()
                };
                println!("ca:    {}", d.ca_cert_path);
                println!(
                    "trust: {}",
                    if d.ca_installed {
                        "installed into host store"
                    } else {
                        "not installed (re-run with --install-ca or import the CA yourself)"
                    }
                );
                print_pod(&pod);
            }
            IngressCmd::Status => {
                let s = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                    .await?
                    .ingress_gateway_status(IngressGatewayStatusRequest {})
                    .await?
                    .into_inner();
                println!("configured:    {}", s.configured);
                println!("running:       {}", s.running);
                println!("control ready: {}", s.control_ready);
                println!("generation:    {}", s.generation);
                println!("routes:        {}", s.route_count);
                println!("ca:            {}", s.ca_cert_path);
            }
            IngressCmd::UninstallCa => {
                let r = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                    .await?
                    .uninstall_ingress_ca(Empty {})
                    .await?
                    .into_inner();
                println!("removed: {}", r.ca_cert_path);
                println!("{}", r.detail);
            }
            IngressCmd::RotateCa => {
                let r = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                    .await?
                    .rotate_ingress_ca(Empty {})
                    .await?
                    .into_inner();
                println!("ca: {}", r.ca_cert_path);
                println!("{}", r.detail);
            }
        },
        Cmd::Ping => {
            let i = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                .await?
                .ping(PingRequest {})
                .await?
                .into_inner();
            println!("rustypodsd v{}", i.version);
            println!("socket:   {}", i.socket_path);
            println!("data:     {}", i.data_dir);
            println!("machined: {}   btrfs: {}", i.machined, i.btrfs);
            println!(
                "storage:  {}   engine: {}",
                i.storage_driver, i.runtime_engine
            );
            for q in &i.quarantined {
                println!("quarantine: {q}");
            }
        }
        Cmd::Apply { file } => {
            let toml =
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            match split_stack_by_placement(&toml)? {
                // No placement keys — the classic single-daemon apply.
                None => {
                    let r = connect_timeout(
                        cli.socket.clone(),
                        cli.remote.clone(),
                        cli.host.clone(),
                        LONG_RPC,
                    )
                    .await?
                    .apply_stack(ApplyStackRequest { toml })
                    .await?
                    .into_inner();
                    println!(
                        "stack {} applied ({} pods, shared netns)",
                        r.name,
                        r.pods.len()
                    );
                    for p in &r.pods {
                        print_pod(p);
                    }
                    println!("start: rustypods stack start {}", r.name);
                    let published: Vec<String> =
                        r.pods.iter().flat_map(|p| p.ports.clone()).collect();
                    note_implicit_port_binds(&published);
                }
                // Mesh fan-out: one ApplyStack per target host, each with a
                // rewritten toml holding only that host's members.
                Some(groups) => {
                    if cli.host.is_some() || cli.remote.is_some() {
                        anyhow::bail!(
                            "placement names resolve through THIS host's mesh — \
                             run `rustypods apply` without --host/--remote"
                        );
                    }
                    apply_stack_fanout(&cli, groups).await?;
                }
            }
        }
        Cmd::Stack { sub } => {
            let start = matches!(sub, StackCmd::Start { .. });
            let mut c = if start {
                connect_timeout(
                    cli.socket.clone(),
                    cli.remote.clone(),
                    cli.host.clone(),
                    LONG_RPC,
                )
                .await?
            } else {
                connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone()).await?
            };
            match sub {
                StackCmd::Destroy { name } => {
                    if !confirm_destructive(
                        cli.yes,
                        &format!("Destroy stack {name} and its pods?"),
                    )? {
                        println!("aborted");
                        return Ok(());
                    }
                    c.destroy_stack(PodRef { name: name.clone() }).await?;
                    println!("stack {name} destroyed");
                }
                StackCmd::Start { name } | StackCmd::Stop { name } => {
                    let members: Vec<String> = c
                        .list_pods(ListPodsRequest {})
                        .await?
                        .into_inner()
                        .pods
                        .into_iter()
                        .filter(|p| p.stack == name)
                        .map(|p| p.name)
                        .collect();
                    if members.is_empty() {
                        anyhow::bail!("stack {name} not found");
                    }
                    for m in members {
                        let p = if start {
                            c.start_pod(StartPodRequest {
                                name: m,
                                limits: None,
                                ephemeral: false,
                                private_users: None,
                            })
                            .await?
                            .into_inner()
                        } else {
                            c.stop_pod(PodRef { name: m }).await?.into_inner()
                        };
                        print_pod(&p);
                    }
                }
            }
        }
        Cmd::Logs { name, follow } => {
            use std::io::Write;
            use tokio::time::{Duration, Instant};
            /// -f only: a dying stream (daemon restart, journalctl hiccup)
            /// is no reason to exit — reconnect while the pod lives.
            const MAX_RECONNECTS: u32 = 5;
            let print = |data: &[u8]| -> Result<()> {
                let mut out = std::io::stdout().lock();
                out.write_all(data)?;
                out.write_all(b"\n")?;
                out.flush()?;
                Ok(())
            };
            let mut c = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone()).await?;
            let mut retries = 0u32;
            loop {
                let mut s = match c.stream_logs(PodRef { name: name.clone() }).await {
                    Ok(r) => r.into_inner(),
                    Err(e) => {
                        // A pod that doesn't exist will never produce logs.
                        if !follow || e.code() == tonic::Code::NotFound || retries >= MAX_RECONNECTS
                        {
                            return Err(e.into());
                        }
                        retries += 1;
                        eprintln!("logs: {e} — reconnecting ({retries}/{MAX_RECONNECTS})…");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        if let Ok(nc) =
                            connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone()).await
                        {
                            c = nc;
                        }
                        continue;
                    }
                };
                if !follow {
                    // Bounded backlog drain: the daemon's sources
                    // (journalctl -f, tail -F) never EOF on their own, so
                    // instead of a per-message "quiet" heuristic cap the
                    // TOTAL wait — 3s after the first line arrives, or 3s
                    // overall for an empty backlog. A real stream end or
                    // error exits immediately.
                    let mut deadline = Instant::now() + Duration::from_secs(3);
                    let mut first = true;
                    loop {
                        match tokio::time::timeout_at(deadline, s.message()).await {
                            Ok(Ok(Some(l))) => {
                                print(&l.data)?;
                                if first {
                                    first = false;
                                    deadline = Instant::now() + Duration::from_secs(3);
                                }
                            }
                            Ok(Ok(None)) | Err(_) => break,
                            Ok(Err(e)) => return Err(e.into()),
                        }
                    }
                    break;
                }
                // EOF or error ends the loop → reconnect
                while let Ok(Some(l)) = s.message().await {
                    retries = 0; // healthy stream resets the budget
                    print(&l.data)?;
                }
                // Reconnect only while the pod is alive and running — a
                // dead pod's stream ending is a normal exit, not a retry.
                let running = c
                    .list_pods(ListPodsRequest {})
                    .await
                    .map(|l| {
                        l.into_inner()
                            .pods
                            .iter()
                            .any(|p| p.name == name && p.state == PodState::Running as i32)
                    })
                    .unwrap_or(true); // daemon unreachable → don't guess, retry
                if !running {
                    break;
                }
                retries += 1;
                if retries > MAX_RECONNECTS {
                    eprintln!("logs: stream keeps dying ({MAX_RECONNECTS} retries) — giving up");
                    break;
                }
                eprintln!("logs: stream ended — reconnecting ({retries}/{MAX_RECONNECTS})…");
                tokio::time::sleep(Duration::from_secs(1)).await;
                if let Ok(nc) =
                    connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone()).await
                {
                    c = nc;
                }
            }
        }
        Cmd::Metrics { name } => {
            let mut c = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone()).await?;
            let mut s = c.pod_metrics(PodRef { name }).await?.into_inner();
            while let Some(m) = s.message().await? {
                let high = if m.mem_high_bytes > 0 {
                    fmt_bytes(m.mem_high_bytes)
                } else {
                    "max".into()
                };
                println!(
                    "mem {:>8}/{:<8} cpu {:>6.1}%  pids {:<5} psi mem={:.1} io={:.1}",
                    fmt_bytes(m.mem_bytes),
                    high,
                    m.cpu_pct,
                    m.pids,
                    m.mem_psi_avg10,
                    m.io_psi_avg10
                );
            }
        }
        Cmd::Shm { sub } => {
            let mut c = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone()).await?;
            match sub {
                ShmCmd::Create { pod, name, size } => {
                    let seg = c
                        .create_shm(ShmRequest {
                            pod,
                            name,
                            size_bytes: parse_bytes(&size)?,
                        })
                        .await?
                        .into_inner();
                    println!("shm {} ({})", seg.name, fmt_bytes(seg.size_bytes));
                    println!("  host: {}", seg.host_path);
                    println!("  pod:  {}", seg.pod_path);
                }
                ShmCmd::Ls { pod } => {
                    let l = c.list_shm(PodRef { name: pod }).await?.into_inner();
                    for s in &l.segs {
                        println!(
                            "{:<20} {:>10}  {}",
                            s.name,
                            fmt_bytes(s.size_bytes),
                            s.host_path
                        );
                    }
                    if l.segs.is_empty() {
                        println!("no segments");
                    }
                }
                ShmCmd::Rm { pod, name } => {
                    c.remove_shm(ShmRef {
                        pod,
                        name: name.clone(),
                    })
                    .await?;
                    println!("segment {name} removed");
                }
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// Groups of stack members destined for one daemon: `None` = the
/// connected daemon itself, `Some(peer)` = a mesh placement.
type StackGroups = Vec<(Option<String>, Vec<u8>)>;

/// Split a stack.toml into per-host subsets. Returns `None` when no
/// member carries `placement` so the caller can keep the fast path.
/// Each returned toml contains only that host's `[pods.*]` tables with
/// the `placement` key stripped — daemons reject the key outright, so a
/// leaked placement in the wire format would fail loudly, not silently.
fn split_stack_by_placement(toml_bytes: &[u8]) -> Result<Option<StackGroups>> {
    let text = std::str::from_utf8(toml_bytes).context("stack file is not UTF-8")?;
    let doc: toml::Value = toml::from_str(text).context("parsing stack.toml")?;
    let pods = match doc.get("pods").and_then(|p| p.as_table()) {
        Some(t) => t,
        // No pods table — let the daemon's strict parser report it.
        None => return Ok(None),
    };
    let placement_of = |member: &str, spec: &toml::Value| -> Result<String> {
        match spec.get("placement") {
            None => Ok(String::new()),
            Some(v) => match v.as_str() {
                Some(s) => Ok(s.trim().to_string()),
                // `placement = 5` must not silently mean "local".
                None => {
                    anyhow::bail!("pods.{member}: placement must be a string (peer name), got {v}")
                }
            },
        }
    };
    // Fan out whenever the key EXISTS — even empty — so the rewrite
    // strips it and the daemon's strict parser never sees it.
    if pods.values().all(|v| v.get("placement").is_none()) {
        return Ok(None);
    }
    // A `placement` buried in a nested table (e.g. [pods.db.limits])
    // would survive the top-level strip and read as "local" — refuse.
    for (member, spec) in pods {
        if let Some(t) = spec.as_table() {
            for (k, v) in t.iter() {
                if v.is_table() && v.get("placement").is_some() {
                    anyhow::bail!("pods.{member}.{k}: placement only belongs on the member itself");
                }
            }
        }
    }
    // Member names grouped by placement string ("" = connected daemon).
    let mut by_placement: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for (member, spec) in pods {
        by_placement
            .entry(placement_of(member, spec)?)
            .or_default()
            .push(member.clone());
    }
    let mut groups = Vec::with_capacity(by_placement.len());
    for (pl, members) in by_placement {
        let mut sub = doc.clone();
        let t = sub
            .get_mut("pods")
            .and_then(|p| p.as_table_mut())
            .ok_or_else(|| anyhow::anyhow!("internal: pods table vanished mid-rewrite"))?;
        t.retain(|m, _| members.iter().any(|x| x == m));
        for (_, v) in t.iter_mut() {
            if let Some(spec) = v.as_table_mut() {
                spec.remove("placement");
            }
        }
        let bytes = toml::to_string(&sub)
            .context("serializing per-host stack subset")?
            .into_bytes();
        groups.push(((!pl.is_empty()).then_some(pl), bytes));
    }
    Ok(Some(groups))
}

/// Apply each placement group on its target daemon — local groups via
/// the normal transport, named placements over the cluster plane.
/// Every host's apply is atomic; a failure on one host is reported but
/// does not roll back the others (re-running `apply` is idempotent).
async fn apply_stack_fanout(cli: &Cli, groups: StackGroups) -> Result<()> {
    let total: usize = groups.len();
    let mut failures = Vec::new();
    for (placement, sub) in groups {
        let host_label = placement.clone().unwrap_or_else(|| "local".into());
        let res: Result<_, anyhow::Error> = async {
            let mut c = match &placement {
                Some(p) => rustypods_client::connect_mesh(&cli.socket, p, LONG_RPC)
                    .await
                    .with_context(|| format!("resolving placement '{p}'"))?,
                None => {
                    connect_timeout(cli.socket.clone(), cli.remote.clone(), None, LONG_RPC).await?
                }
            };
            Ok::<_, anyhow::Error>(
                c.apply_stack(ApplyStackRequest { toml: sub })
                    .await?
                    .into_inner(),
            )
        }
        .await;
        match res {
            Ok(r) => {
                println!(
                    "stack {} @ {host_label}: {} pod{} applied",
                    r.name,
                    r.pods.len(),
                    if r.pods.len() == 1 { "" } else { "s" }
                );
                for p in &r.pods {
                    print_pod(p);
                }
            }
            Err(e) => {
                eprintln!("stack apply @ {host_label}: {e:#}");
                failures.push(host_label);
            }
        }
    }
    if !failures.is_empty() {
        anyhow::bail!(
            "stack apply failed on {} — re-run `rustypods apply` to converge",
            failures.join(", ")
        );
    }
    if total > 1 {
        println!(
            "members on different hosts reach each other by mesh name \
             (<stack>-<member>.rustypods.local), not 127.0.0.1"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_placement_returns_none() {
        let t = b"name = \"shop\"\n[pods.web]\nimage = \"img\"\n";
        assert!(split_stack_by_placement(t).unwrap().is_none());
    }

    #[test]
    fn splits_by_placement_and_strips_key() {
        let t = br#"
name = "shop"
[pods.web]
image = "img"
placement = "s2"
[pods.db]
image = "img"
volumes = ["d:/var/lib/db"]
"#;
        let groups = split_stack_by_placement(t).unwrap().unwrap();
        assert_eq!(groups.len(), 2);
        for (pl, bytes) in &groups {
            let text = String::from_utf8(bytes.clone()).unwrap();
            assert!(!text.contains("placement"), "key must be stripped");
            let sub: toml::Value = toml::from_str(&text).unwrap();
            let pods = sub["pods"].as_table().unwrap();
            assert_eq!(pods.len(), 1);
            match pl {
                Some(p) => {
                    assert_eq!(p, "s2");
                    assert!(pods.contains_key("web"));
                }
                None => assert!(pods.contains_key("db")),
            }
            // Volume spec must survive the rewrite untouched.
            if pods.contains_key("db") {
                assert_eq!(pods["db"]["volumes"][0].as_str().unwrap(), "d:/var/lib/db");
            }
        }
    }

    #[test]
    fn empty_placement_counts_as_local() {
        let t = b"name = \"x\"\n[pods.a]\nimage=\"i\"\nplacement = \"\"\n[pods.b]\nimage=\"i\"\nplacement=\"s2\"\n";
        let groups = split_stack_by_placement(t).unwrap().unwrap();
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().any(|(p, _)| p.is_none()));
    }
}
