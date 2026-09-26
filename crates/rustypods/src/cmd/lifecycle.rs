use super::*;

pub(crate) async fn run(mut cli: Cli) -> Result<()> {
    let cmd = cli.cmd.take().unwrap();
    match cmd {
        Cmd::Create {
            name,
            image,
            storage_max,
            port,
            desktop,
            bind,
            autostart,
            ingress,
            cmd,
            restart,
            health_cmd,
            health_tcp,
            health_http,
            health_interval,
            health_timeout,
            health_retries,
            env,
            env_file,
            volume,
            stop_timeout,
        } => {
            let storage_max_bytes = storage_max
                .as_deref()
                .map(parse_bytes)
                .transpose()?
                .unwrap_or(0);
            if !port.is_empty() || !ingress.is_empty() {
                eprintln!("note: --port/--ingress imply a private netns (--network-veth); the pod no longer shares host networking");
            }
            note_implicit_port_binds(&port);
            let mut ingress_rules = Vec::with_capacity(ingress.len());
            for spec in &ingress {
                ingress_rules.push(rustypods_proto::parse_ingress_rule(spec)?);
            }
            let healthcheck = healthcheck_proto(
                health_cmd.as_ref(),
                health_tcp.as_ref(),
                health_http.as_ref(),
                health_interval.as_ref(),
                health_timeout.as_ref(),
                health_retries,
            )?;
            let env = collect_env(env_file.as_ref(), env)?;
            for spec in &volume {
                rustypods_proto::parse_volume_spec(spec)?;
            }
            let p = connect_timeout(
                cli.socket.clone(),
                cli.remote.clone(),
                cli.host.clone(),
                LONG_RPC,
            )
            .await?
            .create_pod(CreatePodRequest {
                name,
                image,
                storage_max_bytes,
                ports: port,
                ingress: ingress_rules,
                desktop,
                binds: bind,
                limits: None,
                autostart,
                cmd,
                restart: restart.unwrap_or_default(),
                healthcheck,
                env,
                volumes: volume,
                stop_timeout_secs: stop_timeout.unwrap_or(0),
            })
            .await?
            .into_inner();
            print_pod(&p);
        }
        Cmd::Start {
            name,
            memory_high,
            memory_max,
            cpu,
            ephemeral,
            private_users,
            no_private_users,
        } => {
            let pu = if private_users {
                Some(true)
            } else if no_private_users {
                Some(false)
            } else {
                None
            };
            let p = connect_timeout(
                cli.socket.clone(),
                cli.remote.clone(),
                cli.host.clone(),
                LONG_RPC,
            )
            .await?
            .start_pod(StartPodRequest {
                name: name.clone(),
                limits: limits_proto(memory_high.as_deref(), memory_max.as_deref(), cpu)?,
                ephemeral,
                private_users: pu,
            })
            .await?
            .into_inner();
            print_pod(&p);
            println!("shell: rustypods shell {name}");
        }
        Cmd::Stop { name } => {
            let p = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                .await?
                .stop_pod(PodRef { name })
                .await?
                .into_inner();
            print_pod(&p);
        }
        Cmd::Restart { name } => {
            let mut c = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone()).await?;
            c.stop_pod(PodRef { name: name.clone() }).await?;
            let p = c
                .start_pod(StartPodRequest {
                    name,
                    limits: None,
                    ephemeral: false,
                    private_users: None,
                })
                .await?
                .into_inner();
            print_pod(&p);
        }
        Cmd::Ps => {
            let l = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                .await?
                .list_pods(ListPodsRequest {})
                .await?
                .into_inner();
            for p in &l.pods {
                print_pod(p);
            }
            if l.pods.is_empty() {
                println!("no pods — `rustypods create <name> --image <image>`");
            }
        }
        Cmd::Destroy { name } => {
            use std::io::IsTerminal;
            let mut c = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone()).await?;
            let n = if std::io::stdin().is_terminal() && !cli.yes {
                c.list_snapshots(PodRef { name: name.clone() })
                    .await?
                    .into_inner()
                    .snapshots
                    .len()
            } else {
                0
            };
            if !confirm_destructive(
                cli.yes,
                &format!("Destroy pod {name} and its {n} snapshots?"),
            )? {
                println!("aborted");
                return Ok(());
            }
            c.destroy_pod(PodRef { name: name.clone() }).await?;
            println!("pod {name} destroyed");
        }
        Cmd::Clone { source, dest } => {
            let p = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                .await?
                .clone_pod(ClonePodRequest {
                    source: source.clone(),
                    dest,
                })
                .await?
                .into_inner();
            print_pod(&p);
            if !p.ports.is_empty() {
                eprintln!("note: ports copied — running both pods needs distinct host ports (edit conf/pods/{}.conf + reload)", p.name);
            }
        }
        Cmd::Commit { pod, label } => {
            let s = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                .await?
                .commit_pod(CommitPodRequest {
                    pod: pod.clone(),
                    label: label.unwrap_or_default(),
                })
                .await?
                .into_inner();
            println!("snapshot {} — instant CoW ({})", s.id, s.path);
        }
        Cmd::Rollback { pod, to } => {
            let p = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                .await?
                .rollback_pod(RollbackPodRequest {
                    pod: pod.clone(),
                    snapshot: to.clone().unwrap_or_default(),
                })
                .await?
                .into_inner();
            println!(
                "{} rolled back{}",
                p.name,
                to.map(|t| format!(" to {t}"))
                    .unwrap_or_else(|| " to latest".into())
            );
            print_pod(&p);
        }
        Cmd::Snapshots { pod } => {
            let l = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                .await?
                .list_snapshots(PodRef { name: pod })
                .await?
                .into_inner();
            for s in &l.snapshots {
                println!("{:<44} {}", s.id, s.label);
            }
            if l.snapshots.is_empty() {
                println!("no snapshots — `rustypods commit <pod> [label]`");
            }
        }
        Cmd::Rmsnap { pod, id } => {
            if !confirm_destructive(cli.yes, &format!("Delete snapshot {id} of pod {pod}?"))? {
                println!("aborted");
                return Ok(());
            }
            connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                .await?
                .delete_snapshot(SnapshotRef {
                    pod,
                    id: id.clone(),
                })
                .await?;
            println!("snapshot {id} deleted");
        }
        Cmd::Config {
            name,
            memory_high,
            memory_max,
            cpu,
            storage_max,
            bind,
            clear_binds,
            snap_keep,
            snap_max_age,
            autostart,
            ingress,
            clear_ingress,
            cmd,
            clear_cmd,
            restart,
            health_cmd,
            health_tcp,
            health_http,
            health_interval,
            health_timeout,
            health_retries,
            clear_health,
            env,
            env_file,
            clear_env,
            volume,
            clear_volumes,
            stop_timeout,
        } => {
            // Missing flags = keep current values → fetch them first.
            let mut c = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone()).await?;
            let cur = c
                .list_pods(ListPodsRequest {})
                .await?
                .into_inner()
                .pods
                .into_iter()
                .find(|p| p.name == name)
                .context(format!("pod {name} not found"))?;
            let cur_lim = cur.limits.unwrap_or_default();
            let lim = Limits {
                memory_high_bytes: memory_high
                    .as_deref()
                    .map(parse_bytes)
                    .transpose()?
                    .unwrap_or(cur_lim.memory_high_bytes),
                memory_max_bytes: memory_max
                    .as_deref()
                    .map(parse_bytes)
                    .transpose()?
                    .unwrap_or(cur_lim.memory_max_bytes),
                cpu_quota_percent: cpu.unwrap_or(cur_lim.cpu_quota_percent),
            };
            let storage_max_bytes = storage_max
                .as_deref()
                .map(parse_bytes)
                .transpose()?
                .unwrap_or(cur.storage_max_bytes);
            let binds = if clear_binds {
                Some(BindList { binds: vec![] })
            } else if !bind.is_empty() {
                Some(BindList { binds: bind })
            } else {
                None
            };
            let ingress = if clear_ingress {
                Some(IngressList { rules: vec![] })
            } else if !ingress.is_empty() {
                let mut rules = Vec::with_capacity(ingress.len());
                for spec in &ingress {
                    rules.push(rustypods_proto::parse_ingress_rule(spec)?);
                }
                Some(IngressList { rules })
            } else {
                None
            };
            let cmd = if clear_cmd {
                Some(CmdList { argv: vec![] })
            } else if !cmd.is_empty() {
                Some(CmdList { argv: cmd })
            } else {
                None
            };
            let healthcheck = if clear_health {
                // Present-but-empty kind disables the probe.
                Some(HealthCheck::default())
            } else {
                healthcheck_proto(
                    health_cmd.as_ref(),
                    health_tcp.as_ref(),
                    health_http.as_ref(),
                    health_interval.as_ref(),
                    health_timeout.as_ref(),
                    health_retries,
                )?
            };
            let env = if clear_env {
                Some(EnvList { entries: vec![] })
            } else if env_file.is_some() || !env.is_empty() {
                Some(EnvList {
                    entries: collect_env(env_file.as_ref(), env)?,
                })
            } else {
                None
            };
            let volumes = if clear_volumes {
                Some(VolumeList { specs: vec![] })
            } else if !volume.is_empty() {
                for spec in &volume {
                    rustypods_proto::parse_volume_spec(spec)?;
                }
                Some(VolumeList { specs: volume })
            } else {
                None
            };
            let p = c
                .update_pod_config(UpdatePodConfigRequest {
                    name,
                    limits: Some(lim),
                    storage_max_bytes,
                    ports: None,
                    binds,
                    ingress,
                    cmd,
                    snap_keep_last: snap_keep,
                    snap_max_age_secs: snap_max_age.as_deref().map(parse_duration).transpose()?,
                    autostart,
                    restart,
                    healthcheck,
                    env,
                    volumes,
                    stop_timeout_secs: stop_timeout,
                })
                .await?
                .into_inner();
            print_pod(&p);
        }
        Cmd::Reload { name } => {
            let p = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone())
                .await?
                .reload_pod_config(PodRef { name })
                .await?
                .into_inner();
            print_pod(&p);
        }
        _ => unreachable!(),
    }
    Ok(())
}
