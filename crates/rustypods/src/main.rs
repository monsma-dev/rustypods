mod doctor;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

use rustypods_client::{connect, connect_timeout};
use rustypods_proto::rpc::*;
use rustypods_proto::{fmt_bytes, parse_bytes, parse_duration, SOCKET_PATH};
use tokio_stream::StreamExt;

#[derive(Parser)]
#[command(
    name = "rustypods",
    disable_version_flag = true,
    arg_required_else_help = true,
    about = "nspawn pods on Btrfs — podman/distrobox-light"
)]
struct Cli {
    /// Print this CLI's version and, when the daemon answers, its version too.
    #[arg(short = 'V', long = "version", global = true, action = clap::ArgAction::SetTrue)]
    show_version: bool,
    /// Path to the daemon socket (remote path when --remote is used).
    #[arg(long, global = true, default_value = SOCKET_PATH)]
    socket: PathBuf,

    /// Manage a remote daemon over SSH: `rustypods --remote user@host ps`.
    /// Spawns `ssh <dest> socat - UNIX-CONNECT:<socket>` as the transport —
    /// no extra ports, full SSH auth/encryption. Requires socat (or nc-openbsd
    /// with -U) on the remote host.
    #[arg(long, global = true)]
    remote: Option<String>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Daemon status (version, machined, btrfs).
    Ping,
    /// Check that the local host can run rustypodsd — works before the
    /// daemon is installed (daemon probe is a warning, not a failure).
    Doctor,
    /// List images.
    Images,
    /// Import a rootless podman/distrobox container as an image.
    Import {
        /// Container to export (e.g. "arch").
        #[arg(long)]
        from_distrobox: String,
        /// Image name (default: <container>-base).
        #[arg(long)]
        name: Option<String>,
        /// Host user owning the rootless podman store (default: $USER).
        #[arg(long)]
        user: Option<String>,
    },
    /// Pull an OCI image from a registry (native — no podman/docker needed).
    /// Supports docker.io, ghcr.io and any OCI-compliant registry.
    Pull {
        /// Image reference, e.g. "busybox:latest" or "ghcr.io/org/tool:v1".
        reference: String,
        /// Image name (default: <repo-basename>-<tag>, e.g. "node-20-alpine").
        #[arg(long)]
        name: Option<String>,
    },
    /// Remove an image.
    Rmi { name: String },
    /// Create a pod: a Btrfs snapshot of an image.
    Create {
        name: String,
        #[arg(long)]
        image: String,
        /// Btrfs quota cap on the pod rootfs, e.g. 20G (0 = none).
        #[arg(long)]
        storage_max: Option<String>,
        /// Port mapping [hostIp:]hostPort:podPort[/tcp|/udp]; repeatable.
        /// No host IP binds 127.0.0.1 only. 0.0.0.0 publishes on every
        /// address. Implies private networking (--network-veth).
        #[arg(long)]
        port: Vec<String>,
        /// Desktop preset: your home + /tmp rw, /run/user/<uid> + /dev/dri ro.
        /// Implies no user-namespace (shared home needs host-uid identity).
        #[arg(long)]
        desktop: bool,
        /// Bind mount host[:pod][:ro]; repeatable. Applied at start.
        #[arg(long)]
        bind: Vec<String>,
        /// Boot this pod automatically whenever the daemon starts.
        #[arg(long)]
        autostart: bool,
        /// Ingress rule <host>.rustypods.localhost:<pod-port>; repeatable.
        /// Implies private networking (--network-veth).
        #[arg(long)]
        ingress: Vec<String>,
        /// Payload command override, e.g. --cmd sh -c '...' — replaces the
        /// image's entrypoint+cmd and forces non-boot mode. Everything after
        /// --cmd is command argv, so it must be the final rustypods option.
        #[arg(long, num_args = 1.., value_delimiter = None, allow_hyphen_values = true)]
        cmd: Vec<String>,
        /// Restart policy on exit/death: no|on-failure|always. "always"
        /// also restarts on sustained healthcheck failure.
        #[arg(long, value_parser = ["no", "on-failure", "always"])]
        restart: Option<String>,
        /// Exec liveness probe — run via `sh -c` inside the pod; exit 0 = healthy.
        #[arg(long, conflicts_with_all = ["health_tcp", "health_http"])]
        health_cmd: Option<String>,
        /// TCP liveness probe — ":port" (the pod's own address) or "host:port".
        #[arg(long, conflicts_with = "health_http")]
        health_tcp: Option<String>,
        /// HTTP liveness probe — "/path" (pod address :80) or a full
        /// "http://ip:port/path" URL.
        #[arg(long)]
        health_http: Option<String>,
        /// Probe interval, e.g. 10s (default 10s).
        #[arg(long)]
        health_interval: Option<String>,
        /// Per-probe timeout, e.g. 3s (default 3s).
        #[arg(long)]
        health_timeout: Option<String>,
        /// Consecutive probe failures before unhealthy (default 3).
        #[arg(long)]
        health_retries: Option<u32>,
        /// Env var KEY=value; repeatable. Wins over --env-file entries on
        /// duplicate keys. Visible via /proc/<pid>/environ — treat as
        /// config, not a secret vault.
        #[arg(long)]
        env: Vec<String>,
        /// Read KEY=value lines from a file (blank lines and # comments
        /// ignored; no shell expansion).
        #[arg(long)]
        env_file: Option<PathBuf>,
        /// Named volume mount <name>:/pod/path[:ro]; repeatable. Volumes
        /// are btrfs subvols that survive pod destroy; missing volumes
        /// are auto-created on first use.
        #[arg(long)]
        volume: Vec<String>,
    },
    /// Start a pod (nspawn --boot, machined registration).
    Start {
        name: String,
        /// Soft cap, e.g. 10G — kernel pushes towards swap instead of OOM.
        #[arg(long)]
        memory_high: Option<String>,
        /// Hard cap, e.g. 12G.
        #[arg(long)]
        memory_max: Option<String>,
        /// CPU limit in percent (400 = four cores).
        #[arg(long)]
        cpu: Option<u32>,
        /// Throwaway run: disk changes vanish on stop.
        #[arg(long)]
        ephemeral: bool,
        /// Stronger isolation; breaks shared-home uid mapping.
        /// Overrides the conf value (persisted).
        #[arg(long, conflicts_with = "no_private_users")]
        private_users: bool,
        /// Disable the user namespace for this and future starts.
        #[arg(long)]
        no_private_users: bool,
    },
    /// Stop a pod (SIGRTMIN+3 → terminate).
    Stop { name: String },
    /// Restart with the persisted limits.
    Restart { name: String },
    /// List pods.
    #[command(visible_alias = "ls", alias = "list")]
    Ps,
    /// Stop and remove a pod (Btrfs snapshot gone).
    Destroy { name: String },
    /// Instant CoW clone: snapshot a pod's rootfs + conf under a new name.
    Clone { source: String, dest: String },
    /// Snapshot a pod's rootfs instantly (the "commit" — Git for servers).
    Commit {
        pod: String,
        /// Optional tag, e.g. "pre-upgrade".
        label: Option<String>,
    },
    /// Restore a pod to a snapshot: swaps the rootfs (pod ends stopped).
    Rollback {
        pod: String,
        /// Snapshot id (see `rustypods snapshots`); default = latest.
        #[arg(long)]
        to: Option<String>,
    },
    /// List a pod's snapshots.
    Snapshots { pod: String },
    /// Delete one snapshot.
    Rmsnap { pod: String, id: String },
    /// Export a pod — rootfs + conf + image conf + attached volumes —
    /// as one archive stream. Pipe to another host:
    /// `rustypods export db | ssh host2 rustypods load -`
    Export {
        pod: String,
        /// Write to a file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Load an exported pod archive onto this host.
    Load {
        /// Archive path, or "-" for stdin.
        file: String,
        /// Register the pod under a different name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Apply a stack.toml: create/update grouped pods sharing one netns
    /// (K8s-pod model — members reach each other on 127.0.0.1).
    Apply { file: PathBuf },
    /// Stack-level lifecycle: start/stop/destroy all members at once.
    Stack {
        #[command(subcommand)]
        sub: StackCmd,
    },
    /// Adjust limits live (writes the conf + applies to the running scope).
    Config {
        name: String,
        /// Soft cap, e.g. 8G — "0" removes it.
        #[arg(long)]
        memory_high: Option<String>,
        /// Hard cap, e.g. 12G — "0" removes it.
        #[arg(long)]
        memory_max: Option<String>,
        /// CPU limit in percent (0 removes it).
        #[arg(long)]
        cpu: Option<u32>,
        /// Btrfs quota cap, e.g. 20G — "0" removes it (hot-applied).
        #[arg(long)]
        storage_max: Option<String>,
        /// Bind mount host[:pod][:ro]; repeatable. Replaces the whole list —
        /// applied at the next start.
        #[arg(long, conflicts_with = "clear_binds")]
        bind: Vec<String>,
        /// Remove all bind mounts (applied at the next start).
        #[arg(long)]
        clear_binds: bool,
        /// Snapshot GC: keep at most N commits (0 = keep all).
        #[arg(long)]
        snap_keep: Option<u32>,
        /// Snapshot GC: drop commits older than this, e.g. 7d (0 = keep forever).
        #[arg(long)]
        snap_max_age: Option<String>,
        /// Boot with the daemon: --autostart on|off.
        #[arg(long, value_parser = clap::builder::BoolishValueParser::new())]
        autostart: Option<bool>,
        /// Ingress rule <host>.rustypods.localhost:<pod-port>; repeatable.
        /// Replaces the whole list — the pod must be stopped.
        #[arg(long, conflicts_with = "clear_ingress")]
        ingress: Vec<String>,
        /// Remove all ingress rules (the pod must be stopped).
        #[arg(long)]
        clear_ingress: bool,
        /// Payload command override, e.g. --cmd sh -c '...' — replaces the
        /// whole override (applied at the next start). Everything after --cmd
        /// is command argv, so it must be the final rustypods option.
        #[arg(long, num_args = 1.., value_delimiter = None, conflicts_with = "clear_cmd", allow_hyphen_values = true)]
        cmd: Vec<String>,
        /// Remove the payload command override (applied at the next start).
        #[arg(long)]
        clear_cmd: bool,
        /// Restart policy on exit/death: no|on-failure|always (replaces
        /// current). "always" also restarts on sustained healthcheck failure.
        #[arg(long, value_parser = ["no", "on-failure", "always"])]
        restart: Option<String>,
        /// Exec liveness probe — run via `sh -c` inside the pod; exit 0 = healthy.
        #[arg(long, conflicts_with_all = ["health_tcp", "health_http", "clear_health"])]
        health_cmd: Option<String>,
        /// TCP liveness probe — ":port" (the pod's own address) or "host:port".
        #[arg(long, conflicts_with_all = ["health_http", "clear_health"])]
        health_tcp: Option<String>,
        /// HTTP liveness probe — "/path" (pod address :80) or a full
        /// "http://ip:port/path" URL.
        #[arg(long, conflicts_with = "clear_health")]
        health_http: Option<String>,
        /// Probe interval, e.g. 10s (default 10s).
        #[arg(long, conflicts_with = "clear_health")]
        health_interval: Option<String>,
        /// Per-probe timeout, e.g. 3s (default 3s).
        #[arg(long, conflicts_with = "clear_health")]
        health_timeout: Option<String>,
        /// Consecutive probe failures before unhealthy (default 3).
        #[arg(long, conflicts_with = "clear_health")]
        health_retries: Option<u32>,
        /// Remove the liveness probe.
        #[arg(long)]
        clear_health: bool,
        /// Env var KEY=value; repeatable. Replaces the whole env set —
        /// applied at the next start.
        #[arg(long, conflicts_with_all = ["env_file", "clear_env"])]
        env: Vec<String>,
        /// Replace the env set with KEY=value lines from a file.
        #[arg(long, conflicts_with = "clear_env")]
        env_file: Option<PathBuf>,
        /// Remove all pod env vars (applied at the next start).
        #[arg(long)]
        clear_env: bool,
        /// Named volume mount <name>:/pod/path[:ro]; repeatable. Replaces
        /// the whole mount set — applied at the next start.
        #[arg(long, conflicts_with = "clear_volumes")]
        volume: Vec<String>,
        /// Remove all volume mounts (next start). The volumes themselves
        /// are kept — `rustypods volume rm` deletes data.
        #[arg(long)]
        clear_volumes: bool,
    },
    /// Reread a hand-edited <pod>.conf and apply it.
    Reload { name: String },
    /// Pod logs: journal for booted pods, the console log otherwise.
    /// Prints the recent backlog; -f keeps following new output.
    Logs {
        name: String,
        /// Follow the stream instead of exiting once the backlog goes quiet.
        #[arg(short, long)]
        follow: bool,
    },
    /// Live telemetry from the pod (rustypods-agent → daemon).
    Metrics { name: String },
    /// Shared-memory segments: mmap'able files, host /dev/shm ↔ pod /run/rustypods/shm.
    Shm {
        #[command(subcommand)]
        sub: ShmCmd,
    },
    /// Shell into a running pod (native Exec RPC: nsenter + host pty).
    #[command(visible_alias = "exec")]
    Shell {
        name: String,
        /// Log in as this container user (default: $USER).
        #[arg(long)]
        user: Option<String>,
        /// In-container working directory (absolute path).
        #[arg(short, long)]
        workdir: Option<String>,
        /// Fail if any stage of a pipeline fails: exports SHELLOPTS=pipefail
        /// into the payload so `bash -lc 'cargo build | tail'` can't hide a
        /// build error behind tail's exit 0. Only effective for bash.
        #[arg(long)]
        strict: bool,
        /// Command instead of an interactive shell.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Copy files/dirs between host and pod. Exactly one side must be a
    /// `pod:/abs/path` — the other is a host path. Streams via tar/cat over
    /// the Exec RPC; needs `tar` in the image for directory transfers.
    Cp {
        /// Source: host path or `pod:/abs/path`.
        src: String,
        /// Destination: host path or `pod:/abs/path`.
        dst: String,
        /// Container user for the remote side (default: $USER).
        #[arg(long)]
        user: Option<String>,
    },
    /// Managed ingress gateway: TLS-terminating reverse proxy for
    /// `*.rustypods.localhost` backed by a local PKI.
    Ingress {
        #[command(subcommand)]
        sub: IngressCmd,
    },
    /// Named data volumes: btrfs subvols that outlive pods and mount via
    /// --volume <name>:/path.
    Volume {
        #[command(subcommand)]
        sub: VolumeCmd,
    },
    /// Multi-host mesh: userspace WireGuard (BoringTun) giving every pod
    /// a ULA address reachable from pods on peer hosts — L3, no NAT.
    Mesh {
        #[command(subcommand)]
        sub: MeshCmd,
    },
}

#[derive(Subcommand)]
enum MeshCmd {
    /// Generate (or reuse) this host's WG identity and bring the mesh
    /// up. Prints the pubkey + ULA /48 to hand to peer hosts.
    Init {
        /// UDP port WireGuard listens on (default 51820).
        #[arg(long, default_value_t = 51820)]
        port: u32,
    },
    /// Show mesh state: pubkey, listen addr, /48, per-peer handshakes.
    Status,
    /// Add a peer host: its UDP endpoint + WG pubkey (`mesh status` on
    /// that host prints both).
    AddPeer {
        /// "ip:port" or "[v6]:port" the peer daemon listens on.
        endpoint: String,
        /// Peer's base64 WG pubkey (its `mesh init` output).
        pubkey: String,
    },
    /// Remove a peer by its pubkey.
    RmPeer {
        /// Peer's base64 WG pubkey (`mesh status` lists them).
        pubkey: String,
    },
    /// Tear the mesh down: stop the pump, delete rp-mesh0, strip pod
    /// mesh addresses and forget the WG identity (conf/mesh.conf).
    Deinit,
}

#[derive(Subcommand)]
enum IngressCmd {
    /// Provision the gateway pod (local PKI + dataplane binary) and start
    /// it. The image must be ABI-compatible with the host-built
    /// `rustypods-ingress` binary that gets copied in — it RUNS inside
    /// this rootfs. Debian host → a Debian-family image, Fedora →
    /// Fedora-family; on this machine `arch-base` matches the dev pod
    /// toolchain.
    Init {
        /// Image to clone the gateway rootfs from (ABI-compatible with
        /// the host's binary build — see above).
        #[arg(long)]
        image: String,
        /// Also install the generated CA into the HOST system trust
        /// store (update-ca-certificates / update-ca-trust — mutates
        /// system trust; skip it to import the CA yourself).
        #[arg(long)]
        install_ca: bool,
    },
    /// Show gateway state: configured/running, dataplane liveness,
    /// applied snapshot generation and route count, CA path.
    Status,
}

#[derive(Subcommand)]
enum VolumeCmd {
    /// Create a volume (volumes are also auto-created on first mount).
    Create { name: String },
    /// List volumes with usage and attaching pods.
    #[command(visible_alias = "list")]
    Ls,
    /// Show one volume's details.
    Inspect { name: String },
    /// Delete a volume's data (refused while any pod still mounts it).
    #[command(visible_alias = "remove")]
    Rm { name: String },
}

#[derive(Subcommand)]
enum StackCmd {
    /// Start every pod in the stack (shares one netns, one IP).
    Start { name: String },
    /// Stop every pod in the stack.
    Stop { name: String },
    /// Stop+delete every member pod and tear down the shared netns.
    Destroy { name: String },
}

#[derive(Subcommand)]
enum ShmCmd {
    /// Create a segment (default 64M).
    Create {
        pod: String,
        name: String,
        #[arg(long, default_value = "64M")]
        size: String,
    },
    /// List a pod's segments.
    Ls { pod: String },
    /// Remove a segment.
    Rm { pod: String, name: String },
}

fn limits_proto(high: Option<&str>, max: Option<&str>, cpu: Option<u32>) -> Result<Option<Limits>> {
    let l = Limits {
        memory_high_bytes: high.map(parse_bytes).transpose()?.unwrap_or(0),
        memory_max_bytes: max.map(parse_bytes).transpose()?.unwrap_or(0),
        cpu_quota_percent: cpu.unwrap_or(0),
    };
    Ok((l.memory_high_bytes > 0 || l.memory_max_bytes > 0 || l.cpu_quota_percent > 0).then_some(l))
}

/// `rustypods shell` over the Exec RPC: the daemon nsenters on the machined
/// leader pid, a host pty gives job control, the remote exit code comes back
/// exactly. Raw mode + SIGWINCH forwarding on this side.
async fn shell_exec(
    sock: PathBuf,
    remote: Option<String>,
    name: String,
    user: Option<String>,
    workdir: Option<String>,
    strict: bool,
    cmd: Vec<String>,
) -> Result<()> {
    use rustypods_proto::rpc::exec_chunk::Kind;
    use std::io::{IsTerminal, Write};
    use tokio::io::AsyncReadExt;
    use tokio_stream::wrappers::ReceiverStream;

    let tty = std::io::stdin().is_terminal();
    let user = user
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "root".into());
    let (rows, cols) = if tty { term_size() } else { (0, 0) };
    let mut env = Vec::new();
    for k in ["TERM", "COLORTERM", "LANG"] {
        if let Ok(v) = std::env::var(k) {
            env.push(format!("{k}={v}"));
        }
    }
    if strict {
        // bash imports SHELLOPTS at startup — any bash in the payload
        // (including `bash -lc 'a | b'`) then runs with pipefail on.
        env.push("SHELLOPTS=pipefail".into());
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<ExecChunk>(32);
    tx.send(ExecChunk {
        kind: Some(Kind::Start(ExecStart {
            pod: name,
            user,
            argv: cmd,
            tty,
            rows,
            cols,
            env,
            workdir: workdir.unwrap_or_default(),
        })),
    })
    .await?;
    let mut c = connect(sock, remote).await?;
    let mut inbound = c.exec(ReceiverStream::new(rx)).await?.into_inner();

    // Raw mode so the remote pty gets every keystroke unprocessed.
    let raw = if tty { RawGuard::enter() } else { None };

    // SIGWINCH → daemon → TIOCSWINSZ on the pty (kernel signals the fg group)
    if tty {
        let tx_w = tx.clone();
        tokio::spawn(async move {
            if let Ok(mut sig) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            {
                while sig.recv().await.is_some() {
                    let (rows, cols) = term_size();
                    let _ = tx_w
                        .send(ExecChunk {
                            kind: Some(Kind::Winsize(WinSize { rows, cols })),
                        })
                        .await;
                }
            }
        });
    }
    // stdin → daemon. tx MOVES here: on stdin-EOF the last sender drops
    // (non-tty) → outbound stream ends → daemon closes child-stdin → the
    // remote process sees EOF and exits.
    let stdin_task = tokio::spawn(async move {
        let mut si = tokio::io::stdin();
        let mut buf = [0u8; 8192];
        loop {
            match si.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx
                        .send(ExecChunk {
                            kind: Some(Kind::Stdin(buf[..n].to_vec())),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    let mut code = 1;
    let mut out = std::io::stdout();
    while let Some(m) = inbound.message().await? {
        match m.kind {
            Some(Kind::Stdout(b)) => {
                out.write_all(&b)?;
                out.flush()?;
            }
            Some(Kind::Stderr(b)) => {
                std::io::stderr().write_all(&b)?;
            }
            Some(Kind::Exit(e)) => {
                code = e.code;
                break;
            }
            _ => {}
        }
    }
    stdin_task.abort();
    drop(raw); // restore termios before exit
    std::process::exit(code);
}

// ── cp ──────────────────────────────────────────────────────────────────────

/// `pod:/abs/path` → (pod, path). Host paths (anything without a bare
/// `name:` prefix) return None.
fn split_pod_path(s: &str) -> Result<Option<(String, String)>> {
    let Some((name, path)) = s.split_once(':') else {
        return Ok(None);
    };
    if name.is_empty() || name.contains('/') {
        return Ok(None); // host path containing ':'
    }
    if !path.starts_with('/') {
        anyhow::bail!("pod path must be absolute: '{s}'");
    }
    Ok(Some((name.to_string(), path.to_string())))
}

/// Open an Exec stream: sends Start, returns the stdin channel + response.
async fn exec_open(
    sock: &std::path::Path,
    remote: &Option<String>,
    start: ExecStart,
) -> Result<(
    tokio::sync::mpsc::Sender<ExecChunk>,
    tonic::Streaming<ExecChunk>,
)> {
    use rustypods_proto::rpc::exec_chunk::Kind;
    use tokio_stream::wrappers::ReceiverStream;
    let (tx, rx) = tokio::sync::mpsc::channel::<ExecChunk>(32);
    tx.send(ExecChunk {
        kind: Some(Kind::Start(start)),
    })
    .await?;
    let mut c = connect(sock.to_path_buf(), remote.clone()).await?;
    let inbound = c.exec(ReceiverStream::new(rx)).await?.into_inner();
    Ok((tx, inbound))
}

/// Drain an exec stream: collects stderr, returns (exit_code, stderr).
async fn exec_wait(inbound: &mut tonic::Streaming<ExecChunk>) -> Result<(i32, String)> {
    use rustypods_proto::rpc::exec_chunk::Kind;
    let mut code = 1;
    let mut err = String::new();
    while let Some(m) = inbound.message().await? {
        match m.kind {
            Some(Kind::Stderr(b)) => err.push_str(&String::from_utf8_lossy(&b)),
            Some(Kind::Exit(e)) => {
                code = e.code;
                break;
            }
            _ => {}
        }
    }
    Ok((code, err))
}

fn cp_start(pod: &str, user: &str, argv: Vec<String>) -> ExecStart {
    ExecStart {
        pod: pod.to_string(),
        user: user.to_string(),
        argv,
        tty: false,
        rows: 0,
        cols: 0,
        env: vec![],
        workdir: String::new(),
    }
}

/// Remote `[ -d path ]` probe — exit 0 = directory.
async fn pod_is_dir(
    sock: &std::path::Path,
    remote: &Option<String>,
    pod: &str,
    user: &str,
    path: &str,
) -> Result<bool> {
    let (tx, mut inbound) = exec_open(
        sock,
        remote,
        cp_start(
            pod,
            user,
            vec![
                "sh".into(),
                "-c".into(),
                "[ -d \"$1\" ]".into(),
                "sh".into(),
                path.into(),
            ],
        ),
    )
    .await?;
    drop(tx); // no stdin needed
    let (code, _) = exec_wait(&mut inbound).await?;
    Ok(code == 0)
}

/// Stream local bytes into the exec's stdin. Tar spawns host-side
/// `tar -C <cwd> -cf - <base>`; File streams the file directly.
enum Producer {
    File(std::path::PathBuf),
    Tar {
        cwd: std::path::PathBuf,
        base: std::ffi::OsString,
    },
}

impl Producer {
    async fn stream(self, tx: tokio::sync::mpsc::Sender<ExecChunk>) -> Result<()> {
        use rustypods_proto::rpc::exec_chunk::Kind;
        use tokio::io::AsyncReadExt;
        let (mut reader, mut child): (
            std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
            Option<tokio::process::Child>,
        ) = match self {
            Producer::File(p) => (Box::pin(tokio::fs::File::open(&p).await?), None),
            Producer::Tar { cwd, base } => {
                let mut child = tokio::process::Command::new("tar")
                    .args(["-C"])
                    .arg(&cwd)
                    .args(["-cf", "-"])
                    .arg(&base)
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .context("spawn host tar")?;
                let out = child.stdout.take().context("tar stdout")?;
                (Box::pin(out), Some(child))
            }
        };
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx
                        .send(ExecChunk {
                            kind: Some(Kind::Stdin(buf[..n].to_vec())),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        // tx drop → outbound stream ends → daemon closes remote stdin (EOF).
        drop(tx);
        if let Some(c) = child.as_mut() {
            let st = c.wait().await?;
            if !st.success() {
                anyhow::bail!("host tar failed: {st}");
            }
        }
        Ok(())
    }
}

async fn cp_to_pod(
    sock: PathBuf,
    remote: Option<String>,
    pod: &str,
    user: &str,
    src: &std::path::Path,
    dst: &str,
) -> Result<()> {
    let meta = std::fs::metadata(src)
        .with_context(|| format!("{}: no such file or directory", src.display()))?;
    let dst_is_dir = pod_is_dir(&sock, &remote, pod, user, dst).await?;
    let base = src
        .file_name()
        .context("source has no file name")?
        .to_os_string();
    // Relative paths like `file.txt` have an empty parent — tar needs ".".
    let parent = src
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    let (argv, producer) = if dst_is_dir {
        // File or dir → extract inside the remote dir.
        (
            vec![
                "tar".into(),
                "-C".into(),
                dst.into(),
                "-xf".into(),
                "-".into(),
            ],
            Producer::Tar { cwd: parent, base },
        )
    } else {
        if meta.is_dir() {
            anyhow::bail!(
                "{dst}: not an existing directory in the pod — create it first or end the path with /"
            );
        }
        // Single file → plain copy with rename semantics.
        (
            vec![
                "sh".into(),
                "-c".into(),
                "cat > \"$1\"".into(),
                "sh".into(),
                dst.into(),
            ],
            Producer::File(src.to_path_buf()),
        )
    };

    let (tx, mut inbound) = exec_open(&sock, &remote, cp_start(pod, user, argv)).await?;
    let prod = tokio::spawn(producer.stream(tx));
    let (code, err) = exec_wait(&mut inbound).await?;
    prod.await??;
    if code != 0 {
        anyhow::bail!("cp: remote exited {code}: {}", err.trim());
    }
    Ok(())
}

async fn cp_from_pod(
    sock: PathBuf,
    remote: Option<String>,
    pod: &str,
    user: &str,
    src: &str,
    dst: &std::path::Path,
) -> Result<()> {
    use rustypods_proto::rpc::exec_chunk::Kind;
    use std::io::Write;
    use tokio::io::AsyncWriteExt;

    let src_is_dir = pod_is_dir(&sock, &remote, pod, user, src).await?;
    let base = std::path::Path::new(src)
        .file_name()
        .context("source has no file name")?
        .to_string_lossy()
        .to_string();

    if src_is_dir {
        // tar stream → extract on the host into dst (created if missing).
        std::fs::create_dir_all(dst).with_context(|| format!("create {}", dst.display()))?;
        let parent = std::path::Path::new(src)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/".into());
        let (tx, mut inbound) = exec_open(
            &sock,
            &remote,
            cp_start(
                pod,
                user,
                vec![
                    "tar".into(),
                    "-C".into(),
                    parent,
                    "-cf".into(),
                    "-".into(),
                    base,
                ],
            ),
        )
        .await?;
        drop(tx);
        let mut tar = tokio::process::Command::new("tar")
            .args(["-C"])
            .arg(dst)
            .args(["-xf", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("spawn host tar")?;
        let mut tin = tar.stdin.take().context("tar stdin")?;
        let mut err = String::new();
        let mut code = 1;
        while let Some(m) = inbound.message().await? {
            match m.kind {
                Some(Kind::Stdout(b)) => tin.write_all(&b).await?,
                Some(Kind::Stderr(b)) => err.push_str(&String::from_utf8_lossy(&b)),
                Some(Kind::Exit(e)) => {
                    code = e.code;
                    break;
                }
                _ => {}
            }
        }
        drop(tin);
        let st = tar.wait().await?;
        if code != 0 {
            anyhow::bail!("cp: remote exited {code}: {}", err.trim());
        }
        if !st.success() {
            anyhow::bail!("cp: host tar failed: {st}");
        }
    } else {
        // Single file → cat; dst is a dir → keep basename, else rename.
        let target = if dst.is_dir() {
            dst.join(&base)
        } else {
            dst.to_path_buf()
        };
        let (tx, mut inbound) = exec_open(
            &sock,
            &remote,
            cp_start(pod, user, vec!["cat".into(), src.into()]),
        )
        .await?;
        drop(tx);
        let mut f = std::fs::File::create(&target)
            .with_context(|| format!("create {}", target.display()))?;
        let mut err = String::new();
        let mut code = 1;
        while let Some(m) = inbound.message().await? {
            match m.kind {
                Some(Kind::Stdout(b)) => f.write_all(&b)?,
                Some(Kind::Stderr(b)) => err.push_str(&String::from_utf8_lossy(&b)),
                Some(Kind::Exit(e)) => {
                    code = e.code;
                    break;
                }
                _ => {}
            }
        }
        if code != 0 {
            let _ = std::fs::remove_file(&target);
            anyhow::bail!("cp: remote exited {code}: {}", err.trim());
        }
        println!("{} → {}", src, target.display());
    }
    Ok(())
}

async fn cp_cmd(
    sock: PathBuf,
    remote: Option<String>,
    src: String,
    dst: String,
    user: Option<String>,
) -> Result<()> {
    let src_pod = split_pod_path(&src)?;
    let dst_pod = split_pod_path(&dst)?;
    let user = user
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "root".into());
    match (src_pod, dst_pod) {
        (Some((pod, sp)), None) => {
            cp_from_pod(sock, remote, &pod, &user, &sp, &PathBuf::from(&dst)).await
        }
        (None, Some((pod, dp))) => {
            cp_to_pod(sock, remote, &pod, &user, &PathBuf::from(&src), &dp).await
        }
        (Some(_), Some(_)) => {
            anyhow::bail!("pod-to-pod copy not supported — copy via the host")
        }
        (None, None) => anyhow::bail!("one side must be `pod:/abs/path`"),
    }
}

/// Username for commands that need a host user (import). $USER wins when it
/// is set and not root; otherwise /etc/passwd is consulted for the euid.
fn current_username() -> Result<String> {
    if let Ok(u) = std::env::var("USER") {
        if !u.is_empty() && u != "root" {
            return Ok(u);
        }
    }
    let euid = unsafe { libc::geteuid() };
    let text = std::fs::read_to_string("/etc/passwd").context("reading /etc/passwd")?;
    rustypods_proto::username_for_uid(&text, euid)
        .with_context(|| format!("no /etc/passwd entry for uid {euid} — pass --user"))
}

fn term_size() -> (u32, u32) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) == 0 {
            (ws.ws_row as u32, ws.ws_col as u32)
        } else {
            (24, 80)
        }
    }
}

/// Put stdin in raw mode; Drop restores termios.
struct RawGuard {
    orig: libc::termios,
}
impl RawGuard {
    fn enter() -> Option<Self> {
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) != 0 {
                return None;
            }
            let orig = t;
            libc::cfmakeraw(&mut t);
            libc::tcsetattr(0, libc::TCSANOW, &t);
            Some(Self { orig })
        }
    }
}
impl Drop for RawGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.orig);
        }
    }
}

fn pod_state(p: &Pod) -> &'static str {
    match PodState::try_from(p.state).unwrap_or(PodState::Unknown) {
        PodState::Running => "running",
        PodState::Created => "created",
        PodState::Stopped => "stopped",
        PodState::Failed => "failed",
        PodState::Unknown => "unknown",
    }
}

/// One line when a publish omits the host address. The daemon then
/// binds 127.0.0.1 — a deliberate change from "every interface".
fn note_implicit_port_binds(ports: &[String]) {
    let implicit = ports.iter().any(|s| {
        rustypods_proto::parse_port(s)
            .ok()
            .is_some_and(|p| p.implicit_loopback())
    });
    if implicit {
        eprintln!(
            "note: a port without a host address is published on 127.0.0.1 only — \
             use 0.0.0.0:HOST:POD to publish on every address"
        );
    }
}

fn print_pod(p: &Pod) {
    let lim = p.limits.as_ref().map(|l| {
        let mut s = String::new();
        if l.memory_high_bytes > 0 {
            s.push_str(&format!("high={} ", fmt_bytes(l.memory_high_bytes)));
        }
        if l.memory_max_bytes > 0 {
            s.push_str(&format!("max={} ", fmt_bytes(l.memory_max_bytes)));
        }
        if l.cpu_quota_percent > 0 {
            s.push_str(&format!("cpu={}%", l.cpu_quota_percent));
        }
        s.trim().to_string()
    });
    let mut extra = lim.unwrap_or_default();
    if p.storage_max_bytes > 0 {
        extra.push_str(&format!(" disk={}", fmt_bytes(p.storage_max_bytes)));
    }
    if !p.ports.is_empty() {
        extra.push_str(&format!(" ports=[{}]", p.ports.join(",")));
    }
    if !p.ingress.is_empty() {
        let rules: Vec<String> = p
            .ingress
            .iter()
            .map(|r| format!("{}:{}", r.host, r.pod_port))
            .collect();
        extra.push_str(&format!(" ingress=[{}]", rules.join(",")));
    }
    if !p.cmd.is_empty() {
        extra.push_str(&format!(" cmd={}", p.cmd.join(" ")));
    }
    if !p.stack.is_empty() {
        extra.push_str(&format!(" stack={}", p.stack));
    }
    if p.autostart {
        extra.push_str(" autostart");
    }
    if !p.health.is_empty() {
        extra.push_str(&format!(" health={}", p.health));
    }
    if !p.restart.is_empty() && p.restart != "no" {
        extra.push_str(&format!(" restart={}", p.restart));
    }
    if !p.mesh_ip.is_empty() {
        extra.push_str(&format!(" mesh={}", p.mesh_ip));
    }
    if !p.volumes.is_empty() {
        let vs: Vec<String> = p
            .volumes
            .iter()
            .map(|v| format!("{}:{}{}", v.name, v.target, if v.ro { ":ro" } else { "" }))
            .collect();
        extra.push_str(&format!(" vols=[{}]", vs.join(",")));
    }
    println!(
        "{:<20} {:<8} {:<8} pid={:<7} {}",
        p.name,
        p.image,
        pod_state(p),
        p.leader_pid,
        extra.trim()
    );
}

fn print_mesh_status(st: &MeshStatus) {
    println!("pubkey:  {}", st.pubkey);
    println!("listen:  {}", st.listen);
    println!("prefix:  {}", st.prefix);
    println!(
        "pump:    ticks={} udp={} tun={}",
        st.pump_ticks, st.udp_pkts, st.tun_pkts
    );
    if st.peers.is_empty() {
        println!("peers:   none — `rustypods mesh add-peer <ip:port> <pubkey>`");
    }
    for p in &st.peers {
        let hs = if p.handshake_secs_ago < 0 {
            "no handshake".to_string()
        } else {
            format!("handshake {}s ago", p.handshake_secs_ago)
        };
        println!(
            "peer {} {}  {}  tx={} rx={}",
            p.endpoint,
            p.prefix,
            hs,
            fmt_bytes(p.tx_bytes),
            fmt_bytes(p.rx_bytes)
        );
    }
    if !st.names.is_empty() {
        println!("names:");
        for (n, a) in &st.names {
            println!("  {n:<20} {a}");
        }
    }
}

/// Build the proto HealthCheck from the CLI's --health-* flags.
/// `--health-cmd` runs via `sh -c` (same model as Docker HEALTHCHECK CMD);
/// the daemon re-validates before persisting.
fn healthcheck_proto(
    exec: Option<&String>,
    tcp: Option<&String>,
    http: Option<&String>,
    interval: Option<&String>,
    timeout: Option<&String>,
    retries: Option<u32>,
) -> Result<Option<HealthCheck>> {
    let (kind, target, argv) = if let Some(c) = exec {
        (
            "exec".to_string(),
            String::new(),
            vec!["sh".into(), "-c".into(), c.clone()],
        )
    } else if let Some(t) = tcp {
        ("tcp".to_string(), t.clone(), vec![])
    } else if let Some(h) = http {
        ("http".to_string(), h.clone(), vec![])
    } else {
        if interval.is_some() || timeout.is_some() || retries.is_some() {
            anyhow::bail!(
                "--health-interval/--health-timeout/--health-retries need a probe (--health-cmd/--health-tcp/--health-http)"
            );
        }
        return Ok(None);
    };
    let hc = HealthCheck {
        kind,
        target,
        argv,
        interval_secs: interval
            .map(|s| parse_duration(s))
            .transpose()?
            .unwrap_or(0) as u32,
        timeout_secs: timeout.map(|s| parse_duration(s)).transpose()?.unwrap_or(0) as u32,
        retries: retries.unwrap_or(0),
    };
    rustypods_proto::validate_healthcheck(&hc)?;
    Ok(Some(hc))
}

/// Merge --env-file lines with --env entries into the pod env list:
/// file first, then explicit flags win per key (the same rule the
/// daemon applies merging pod env over image env). No shell expansion —
/// `A=$HOME` stores the literal.
fn collect_env(env_file: Option<&PathBuf>, env: Vec<String>) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    if let Some(p) = env_file {
        let text =
            std::fs::read_to_string(p).with_context(|| format!("read env file {}", p.display()))?;
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            anyhow::ensure!(
                line.contains('='),
                "{}:{}: expected KEY=value, got {:?}",
                p.display(),
                i + 1,
                line
            );
            out.push(line.to_string());
        }
    }
    for kv in env {
        let key = kv.split('=').next().unwrap_or(&kv);
        out.retain(|e| e.split('=').next() != Some(key));
        out.push(kv);
    }
    rustypods_proto::validate_env(&out)?;
    Ok(out)
}

async fn print_versions(cli: &Cli) -> Result<()> {
    println!("rustypods {}", env!("CARGO_PKG_VERSION"));
    match connect(cli.socket.clone(), cli.remote.clone()).await {
        Ok(mut c) => match c.ping(PingRequest {}).await {
            Ok(info) => println!("rustypodsd {}", info.into_inner().version),
            Err(e) => println!("rustypodsd unreachable ({e})"),
        },
        Err(_) => println!("rustypodsd unreachable"),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.show_version {
        print_versions(&cli).await?;
        return Ok(());
    }
    let Some(cmd) = cli.cmd else {
        Cli::command().print_long_help()?;
        std::process::exit(2);
    };
    match cmd {
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
            shell_exec(cli.socket, cli.remote, name, user, workdir, strict, cmd).await?;
        }
        Cmd::Cp { src, dst, user } => {
            cp_cmd(cli.socket, cli.remote, src, dst, user).await?;
        }
        Cmd::Volume { sub } => {
            let mut c = connect(cli.socket.clone(), cli.remote.clone()).await?;
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
                    c.remove_volume(VolumeRef { name: name.clone() }).await?;
                    println!("volume {name} removed");
                }
            }
        }
        Cmd::Mesh { sub } => match sub {
            MeshCmd::Init { port } => {
                let st = connect(cli.socket.clone(), cli.remote.clone())
                    .await?
                    .mesh_init(MeshInitRequest { listen_port: port })
                    .await?
                    .into_inner();
                print_mesh_status(&st);
            }
            MeshCmd::Status => {
                let st = connect(cli.socket.clone(), cli.remote.clone())
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
            MeshCmd::AddPeer { endpoint, pubkey } => {
                let st = connect(cli.socket.clone(), cli.remote.clone())
                    .await?
                    .mesh_add_peer(MeshPeer { endpoint, pubkey })
                    .await?
                    .into_inner();
                print_mesh_status(&st);
            }
            MeshCmd::RmPeer { pubkey } => {
                let st = connect(cli.socket.clone(), cli.remote.clone())
                    .await?
                    .mesh_remove_peer(MeshPeer {
                        endpoint: String::new(),
                        pubkey,
                    })
                    .await?
                    .into_inner();
                print_mesh_status(&st);
            }
            MeshCmd::Deinit => {
                connect(cli.socket.clone(), cli.remote.clone())
                    .await?
                    .mesh_deinit(Empty {})
                    .await?;
                println!("mesh down — rp-mesh0 removed, identity forgotten");
            }
        },
        Cmd::Ingress { sub } => match sub {
            IngressCmd::Init { image, install_ca } => {
                let d = connect(cli.socket.clone(), cli.remote.clone())
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
                    connect(cli.socket.clone(), cli.remote.clone())
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
                let s = connect(cli.socket.clone(), cli.remote.clone())
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
        },
        Cmd::Ping => {
            let i = connect(cli.socket.clone(), cli.remote.clone())
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
        }
        Cmd::Images => {
            let l = connect(cli.socket.clone(), cli.remote.clone())
                .await?
                .list_images(ListImagesRequest {})
                .await?
                .into_inner();
            for i in &l.images {
                let mut extra = String::new();
                if !i.entrypoint.is_empty() || !i.cmd.is_empty() {
                    extra = format!(
                        "  run: {}",
                        i.entrypoint
                            .iter()
                            .chain(i.cmd.iter())
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                }
                println!("{:<20} {:<28} {}{}", i.name, i.source, i.path, extra);
            }
            if l.images.is_empty() {
                println!("no images — `rustypods pull busybox:latest` or `rustypods import --from-distrobox arch`");
            }
        }
        Cmd::Pull { reference, name } => {
            println!("pulling {reference} (this can take a while)...");
            // Pulls routinely outlast the default 30s call bound.
            let img = rustypods_client::connect_timeout(
                cli.socket.clone(),
                cli.remote.clone(),
                std::time::Duration::from_secs(600),
            )
            .await?
            .pull_image(PullImageRequest {
                reference,
                name: name.unwrap_or_default(),
            })
            .await?
            .into_inner();
            println!("image {} → {}", img.name, img.path);
            if !img.entrypoint.is_empty() || !img.cmd.is_empty() {
                println!(
                    "  runs non-boot: {}",
                    img.entrypoint
                        .iter()
                        .chain(img.cmd.iter())
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }
        }
        Cmd::Import {
            from_distrobox,
            name,
            user,
        } => {
            let name = name.unwrap_or_else(|| format!("{from_distrobox}-base"));
            let user = match user {
                Some(u) => u,
                None => current_username()?,
            };
            println!("exporting: {from_distrobox} → {name} (this can take a while)...");
            let img = rustypods_client::connect_timeout(
                cli.socket.clone(),
                cli.remote.clone(),
                std::time::Duration::from_secs(600),
            )
            .await?
            .import_image(ImportImageRequest {
                name: name.clone(),
                distrobox: from_distrobox,
                import_user: user,
            })
            .await?
            .into_inner();
            println!("image {} → {}", img.name, img.path);
        }
        Cmd::Rmi { name } => {
            connect(cli.socket.clone(), cli.remote.clone())
                .await?
                .remove_image(ImageRef { name: name.clone() })
                .await?;
            println!("image {name} removed");
        }
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
            let p = connect(cli.socket.clone(), cli.remote.clone())
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
            let p = connect(cli.socket.clone(), cli.remote.clone())
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
            let p = connect(cli.socket.clone(), cli.remote.clone())
                .await?
                .stop_pod(PodRef { name })
                .await?
                .into_inner();
            print_pod(&p);
        }
        Cmd::Restart { name } => {
            let mut c = connect(cli.socket.clone(), cli.remote.clone()).await?;
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
            let l = connect(cli.socket.clone(), cli.remote.clone())
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
            connect(cli.socket.clone(), cli.remote.clone())
                .await?
                .destroy_pod(PodRef { name: name.clone() })
                .await?;
            println!("pod {name} destroyed");
        }
        Cmd::Clone { source, dest } => {
            let p = connect(cli.socket.clone(), cli.remote.clone())
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
            let s = connect(cli.socket.clone(), cli.remote.clone())
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
            let p = connect(cli.socket.clone(), cli.remote.clone())
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
            let l = connect(cli.socket.clone(), cli.remote.clone())
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
        Cmd::Export { pod, output } => {
            let mut c = connect(cli.socket.clone(), cli.remote.clone()).await?;
            let mut stream = c
                .export_pod(PodRef { name: pod.clone() })
                .await?
                .into_inner();
            // Raw archive bytes go to stdout/file — progress stays on
            // stderr so `export db | ssh host rustypods load -` works.
            use tokio::io::AsyncWriteExt;
            let mut out: Box<dyn tokio::io::AsyncWrite + Unpin> = match &output {
                Some(p) => Box::new(
                    tokio::fs::File::create(p)
                        .await
                        .with_context(|| format!("create {}", p.display()))?,
                ),
                None => Box::new(tokio::io::stdout()),
            };
            let mut total = 0u64;
            while let Some(chunk) = stream.next().await {
                let data = chunk?.data;
                total += data.len() as u64;
                out.write_all(&data).await?;
                eprint!("\rexporting {pod}: {}\x1b[K", fmt_bytes(total));
            }
            out.flush().await?;
            eprintln!("\rexported {pod}: {}", fmt_bytes(total));
        }
        Cmd::Load { file, name } => {
            // The unary reply only lands after the full upload — the
            // default 30s call timeout would cut big archives mid-send.
            let mut c = connect_timeout(
                cli.socket.clone(),
                cli.remote.clone(),
                std::time::Duration::from_secs(3600),
            )
            .await?;
            use rustypods_proto::rpc::import_chunk::Kind;
            // Open before the RPC so a missing file errors locally.
            let mut input: Box<dyn tokio::io::AsyncRead + Unpin + Send> = if file == "-" {
                Box::new(tokio::io::stdin())
            } else {
                Box::new(
                    tokio::fs::File::open(&file)
                        .await
                        .with_context(|| format!("open {file}"))?,
                )
            };
            let (tx, rx) = tokio::sync::mpsc::channel::<ImportChunk>(8);
            tokio::spawn(async move {
                if let Some(r) = &name {
                    let _ = tx
                        .send(ImportChunk {
                            kind: Some(Kind::Options(ImportOptions { rename: r.clone() })),
                        })
                        .await;
                }
                use tokio::io::AsyncReadExt;
                let mut buf = vec![0u8; 1 << 20];
                let mut total = 0u64;
                loop {
                    match input.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            total += n as u64;
                            eprint!("\ruploading: {}\x1b[K", fmt_bytes(total));
                            if tx
                                .send(ImportChunk {
                                    kind: Some(Kind::Data(buf[..n].to_vec())),
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!("\nread error after {}: {e}", fmt_bytes(total));
                            break;
                        }
                    }
                }
            });
            let pod = c
                .import_pod(tokio_stream::wrappers::ReceiverStream::new(rx))
                .await?
                .into_inner();
            eprintln!("\rimported {} ({})", pod.name, pod.rootfs);
        }
        Cmd::Rmsnap { pod, id } => {
            connect(cli.socket.clone(), cli.remote.clone())
                .await?
                .delete_snapshot(SnapshotRef {
                    pod,
                    id: id.clone(),
                })
                .await?;
            println!("snapshot {id} deleted");
        }
        Cmd::Apply { file } => {
            let toml =
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let r = connect(cli.socket.clone(), cli.remote.clone())
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
            let published: Vec<String> = r.pods.iter().flat_map(|p| p.ports.clone()).collect();
            note_implicit_port_binds(&published);
        }
        Cmd::Stack { sub } => {
            let start = matches!(sub, StackCmd::Start { .. });
            let mut c = connect(cli.socket.clone(), cli.remote.clone()).await?;
            match sub {
                StackCmd::Destroy { name } => {
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
        } => {
            // Missing flags = keep current values → fetch them first.
            let mut c = connect(cli.socket.clone(), cli.remote.clone()).await?;
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
                })
                .await?
                .into_inner();
            print_pod(&p);
        }
        Cmd::Reload { name } => {
            let p = connect(cli.socket.clone(), cli.remote.clone())
                .await?
                .reload_pod_config(PodRef { name })
                .await?
                .into_inner();
            print_pod(&p);
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
            let mut c = connect(cli.socket.clone(), cli.remote.clone()).await?;
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
                        if let Ok(nc) = connect(cli.socket.clone(), cli.remote.clone()).await {
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
                if let Ok(nc) = connect(cli.socket.clone(), cli.remote.clone()).await {
                    c = nc;
                }
            }
        }
        Cmd::Metrics { name } => {
            let mut c = connect(cli.socket.clone(), cli.remote.clone()).await?;
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
            let mut c = connect(cli.socket.clone(), cli.remote.clone()).await?;
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
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_env_merges_file_and_flags() {
        let dir = std::env::temp_dir();
        let f = dir.join(format!("rustypods-env-test-{}.env", std::process::id()));
        std::fs::write(&f, "# comment\n\nA=1\nB=two=parts\n  TRIM= spaced \n").unwrap();
        // --env overrides a same-key file entry; new keys append.
        let env = collect_env(Some(&f), vec!["A=flag".into(), "C=3".into()]).unwrap();
        assert_eq!(env, vec!["B=two=parts", "TRIM= spaced", "A=flag", "C=3"]);
        // Malformed file line → error naming file:line.
        std::fs::write(&f, "NOEQ\n").unwrap();
        let e = collect_env(Some(&f), vec![]).unwrap_err();
        assert!(e.to_string().contains(":1"));
        // Invalid KEY rejected by the validator.
        std::fs::write(&f, "1BAD=x\n").unwrap();
        assert!(collect_env(Some(&f), vec![]).is_err());
        let _ = std::fs::remove_file(&f);
    }

    // --cmd takes hyphen-leading argv (regression: `--cmd sh -c '...'` used
    // to be rejected, breaking payload scripts like busybox httpd setups).
    #[test]
    fn version_flag_does_not_need_a_subcommand() {
        let cli = Cli::try_parse_from(["rustypods", "--version"]).unwrap();
        assert!(cli.show_version);
        assert!(cli.cmd.is_none());
        let cli = Cli::try_parse_from(["rustypods", "-V", "--remote", "user@host"]).unwrap();
        assert!(cli.show_version);
        assert_eq!(cli.remote.as_deref(), Some("user@host"));
    }

    #[test]
    fn create_cmd_accepts_hyphen_argv() {
        let cli = Cli::try_parse_from([
            "rustypods",
            "create",
            "demo",
            "--image",
            "busybox-latest",
            "--autostart",
            "--cmd",
            "sh",
            "-c",
            "echo ok",
        ])
        .unwrap();
        let Some(Cmd::Create { autostart, cmd, .. }) = cli.cmd else {
            panic!("expected Cmd::Create");
        };
        assert!(autostart);
        assert_eq!(cmd, ["sh", "-c", "echo ok"]);
    }

    #[test]
    fn config_cmd_accepts_hyphen_argv() {
        let cli = Cli::try_parse_from([
            "rustypods",
            "config",
            "demo",
            "--autostart",
            "on",
            "--cmd",
            "sh",
            "-c",
            "echo ok",
        ])
        .unwrap();
        let Some(Cmd::Config { autostart, cmd, .. }) = cli.cmd else {
            panic!("expected Cmd::Config");
        };
        assert_eq!(autostart, Some(true));
        assert_eq!(cmd, ["sh", "-c", "echo ok"]);
    }
}
