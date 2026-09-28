mod cmd;
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
pub(crate) struct Cli {
    /// Print this CLI's version and, when the daemon answers, its version too.
    #[arg(short = 'V', long = "version", global = true, action = clap::ArgAction::SetTrue)]
    show_version: bool,

    /// Skip the confirmation prompt on destroy, rmi, rmsnap, and volume rm.
    #[arg(short = 'y', long = "yes", global = true, action = clap::ArgAction::SetTrue)]
    yes: bool,
    /// Path to the daemon socket (remote path when --remote is used).
    #[arg(long, global = true, default_value = SOCKET_PATH)]
    socket: PathBuf,

    /// Manage a remote daemon over SSH: `rustypods --remote user@host ps`.
    /// Spawns `ssh <dest> rustypods stdio-bridge` (falls back to socat) as
    /// the transport — no extra ports, full SSH auth/encryption.
    #[arg(long, global = true)]
    remote: Option<String>,

    /// Manage a configured mesh peer directly over the encrypted cluster plane.
    /// Accepts the peer name, pubkey, /48 prefix, or fd…::1 address.
    #[arg(long, global = true, conflicts_with = "remote")]
    host: Option<String>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
pub(crate) enum Cmd {
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
        /// Clear setuid/setgid bits while extracting. Default keeps them
        /// (sudo, ping). Pods without a user namespace should only run
        /// images you trust, or pass this flag.
        #[arg(long)]
        strip_setuid: bool,
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
        /// Seconds to wait for a clean poweroff before hard-kill (default 8).
        #[arg(long)]
        stop_timeout: Option<u64>,
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
        /// Force the payload format. `tar` works on non-btrfs hosts;
        /// default is btrfs send when the data dir is btrfs.
        #[arg(long, value_parser = ["tar", "btrfs"])]
        format: Option<String>,
        /// Export even if cgroup freeze fails. The archive is then only
        /// crash-consistent (a torn write is possible).
        #[arg(long)]
        allow_inconsistent: bool,
    },
    /// Load an exported pod archive onto this host.
    Load {
        /// Archive path, or "-" for stdin.
        file: String,
        /// Register the pod under a different name.
        #[arg(long)]
        name: Option<String>,
        /// Keep exported binds, ports, env, autostart, restart policy,
        /// healthchecks and private_users=false. Without this flag those
        /// host-root grants are stripped.
        #[arg(long)]
        trust: bool,
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
        /// Seconds to wait for a clean poweroff before hard-kill.
        #[arg(long)]
        stop_timeout: Option<u64>,
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
    /// Copy stdin/stdout onto the daemon Unix socket. Hidden: `--remote`
    /// runs this over ssh so the far side does not need socat.
    #[command(hide = true)]
    StdioBridge {
        #[arg(long)]
        socket: PathBuf,
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
        /// Shared cluster token from the introducing host. Empty on the
        /// first host generates a new token.
        #[arg(long)]
        token: Option<String>,
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
        /// Optional stable alias used by `rustypods --host <name> …`.
        #[arg(long)]
        name: Option<String>,
        /// This peer votes and must not receive a workload.
        #[arg(long)]
        witness: bool,
    },
    /// Remove a peer by its pubkey.
    RmPeer {
        /// Peer's base64 WG pubkey (`mesh status` lists them).
        pubkey: String,
    },
    /// Tear the mesh down: stop the pump, delete rp-mesh0, strip pod
    /// mesh addresses and forget the WG identity (conf/mesh.conf).
    Deinit,
    /// Joiner: persist the WireGuard key and `node.key`, and print the
    /// CSR plus the pubkey. Does not create a CA.
    CreateCsr,
    /// Root: sign a joiner. Names inside the CSR are discarded; the
    /// certificate is stamped from the WireGuard pubkey. Prints
    /// `ca.crt` then `node.crt`.
    SignCsr {
        /// Joiner's WireGuard public key (`create-csr` prints it).
        pubkey: String,
        /// CSR PEM, a path to that PEM, or `-` to read stdin.
        csr: String,
    },
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
    /// Remove the RustyPods CA from the host trust store. The inverse of
    /// `init --install-ca`. Does not delete the on-disk CA.
    UninstallCa,
    /// Replace the local CA and leaf. Browsers and trust stores that
    /// imported the old CA must import the new one. Use this to retire an
    /// older CA that had no name constraints.
    RotateCa,
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
    /// Copy a named volume daemon-to-daemon over the encrypted mesh.
    Send {
        name: String,
        /// Target peer name, pubkey, prefix, or fd…::1 address.
        #[arg(long)]
        to: String,
        /// Store under a different name on the receiver.
        #[arg(long)]
        rename_as: Option<String>,
        /// Transfer format; auto uses btrfs only when both hosts support it.
        #[arg(long, value_parser = ["tar", "btrfs"])]
        format: Option<String>,
        /// Replace an existing unmounted volume on the receiver.
        #[arg(long)]
        force: bool,
    },
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

/// Whether a destructive command should proceed.
/// Non-TTY (scripts) and `-y` proceed. A TTY proceeds only on `y`/`Y`.
pub(crate) fn proceed_destructive(tty: bool, yes: bool, answer: &str) -> bool {
    if yes || !tty {
        true
    } else {
        matches!(answer.trim(), "y" | "Y")
    }
}

pub(crate) fn confirm_destructive(yes: bool, prompt: &str) -> Result<bool> {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() || yes {
        return Ok(true);
    }
    eprint!("{prompt} [y/N] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(proceed_destructive(true, false, &line))
}

pub(crate) fn limits_proto(
    high: Option<&str>,
    max: Option<&str>,
    cpu: Option<u32>,
) -> Result<Option<Limits>> {
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
pub(crate) async fn shell_exec(
    cli: &Cli,
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
    let mut c = connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone()).await?;
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
pub(crate) fn split_pod_path(s: &str) -> Result<Option<(String, String)>> {
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
pub(crate) async fn exec_open(
    sock: &std::path::Path,
    remote: &Option<String>,
    host: &Option<String>,
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
    let mut c = connect(sock.to_path_buf(), remote.clone(), host.clone()).await?;
    let inbound = c.exec(ReceiverStream::new(rx)).await?.into_inner();
    Ok((tx, inbound))
}

/// Drain an exec stream: collects stderr, returns (exit_code, stderr).
pub(crate) async fn exec_wait(inbound: &mut tonic::Streaming<ExecChunk>) -> Result<(i32, String)> {
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

pub(crate) fn cp_start(pod: &str, user: &str, argv: Vec<String>) -> ExecStart {
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
pub(crate) async fn pod_is_dir(
    sock: &std::path::Path,
    remote: &Option<String>,
    host: &Option<String>,
    pod: &str,
    user: &str,
    path: &str,
) -> Result<bool> {
    let (tx, mut inbound) = exec_open(
        sock,
        remote,
        host,
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

pub(crate) async fn cp_to_pod(
    sock: PathBuf,
    remote: Option<String>,
    host: Option<String>,
    pod: &str,
    user: &str,
    src: &std::path::Path,
    dst: &str,
) -> Result<()> {
    let meta = std::fs::metadata(src)
        .with_context(|| format!("{}: no such file or directory", src.display()))?;
    let dst_is_dir = pod_is_dir(&sock, &remote, &host, pod, user, dst).await?;
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

    let (tx, mut inbound) = exec_open(&sock, &remote, &host, cp_start(pod, user, argv)).await?;
    let prod = tokio::spawn(producer.stream(tx));
    let (code, err) = exec_wait(&mut inbound).await?;
    prod.await??;
    if code != 0 {
        anyhow::bail!("cp: remote exited {code}: {}", err.trim());
    }
    Ok(())
}

pub(crate) async fn cp_from_pod(
    sock: PathBuf,
    remote: Option<String>,
    host: Option<String>,
    pod: &str,
    user: &str,
    src: &str,
    dst: &std::path::Path,
) -> Result<()> {
    use rustypods_proto::rpc::exec_chunk::Kind;
    use std::io::Write;
    use tokio::io::AsyncWriteExt;

    let src_is_dir = pod_is_dir(&sock, &remote, &host, pod, user, src).await?;
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
            &host,
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
            &host,
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

pub(crate) async fn cp_cmd(
    sock: PathBuf,
    remote: Option<String>,
    host: Option<String>,
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
            cp_from_pod(sock, remote, host, &pod, &user, &sp, &PathBuf::from(&dst)).await
        }
        (None, Some((pod, dp))) => {
            cp_to_pod(sock, remote, host, &pod, &user, &PathBuf::from(&src), &dp).await
        }
        (Some(_), Some(_)) => {
            anyhow::bail!("pod-to-pod copy not supported — copy via the host")
        }
        (None, None) => anyhow::bail!("one side must be `pod:/abs/path`"),
    }
}

/// Username for commands that need a host user (import). $USER wins when it
/// is set and not root; otherwise /etc/passwd is consulted for the euid.
pub(crate) fn current_username() -> Result<String> {
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

pub(crate) fn term_size() -> (u32, u32) {
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

pub(crate) fn pod_state(p: &Pod) -> &'static str {
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
pub(crate) fn note_implicit_port_binds(ports: &[String]) {
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

pub(crate) fn print_pod(p: &Pod) {
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
    if p.allow_setuid {
        extra.push_str(if p.private_users {
            " setuid"
        } else {
            " setuid(host-root)"
        });
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

pub(crate) fn print_mesh_status(st: &MeshStatus) {
    println!("pubkey:  {}", st.pubkey);
    println!("listen:  {}", st.listen);
    println!("prefix:  {}", st.prefix);
    if !st.grpc_addr.is_empty() {
        println!(
            "rpc:     [{}]:{}",
            st.grpc_addr,
            rustypods_client::MESH_RPC_PORT
        );
    }
    if !st.cluster_token.is_empty() {
        println!("token:   present (redacted — rotate via POST /v1/mesh/rotate-token)");
    }
    println!(
        "pump:    ticks={} udp={} tun={} tun_drops={}",
        st.pump_ticks, st.udp_pkts, st.tun_pkts, st.tun_drops
    );
    if let Some(r) = &st.raft {
        let role = match rustypods_proto::rpc::RaftRole::try_from(r.role)
            .unwrap_or(rustypods_proto::rpc::RaftRole::Host)
        {
            rustypods_proto::rpc::RaftRole::Host => "host",
            rustypods_proto::rpc::RaftRole::Witness => "witness",
        };
        println!(
            "raft:    term={} {} quorum={}/{} voted_for={} role={role}",
            r.current_term,
            if r.is_leader { "leader" } else { "follower" },
            if r.has_quorum { "yes" } else { "no" },
            r.quorum_size,
            if r.voted_for.is_empty() {
                "-"
            } else {
                &r.voted_for
            },
        );
    }
    if !st.conf_error.is_empty() {
        println!("error:   {}", st.conf_error);
    }
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
            "peer {}{}{} {}  rpc=[{}]:{}  {}  tx={} rx={}",
            if p.is_witness { "witness " } else { "" },
            if p.name.is_empty() {
                String::new()
            } else {
                format!("{} ", p.name)
            },
            p.endpoint,
            p.prefix,
            p.grpc_addr,
            rustypods_client::MESH_RPC_PORT,
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
pub(crate) fn healthcheck_proto(
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
pub(crate) fn collect_env(env_file: Option<&PathBuf>, env: Vec<String>) -> Result<Vec<String>> {
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

/// Bidirectional copy between stdio and the daemon socket. Blocking is
/// fine: this process does nothing else. Shutdown(Write) on stdin EOF
/// so the daemon sees the client go away.
pub(crate) fn stdio_bridge(socket: &std::path::Path) -> Result<()> {
    use std::io::Write;
    let mut writer = std::os::unix::net::UnixStream::connect(socket)
        .with_context(|| format!("connect {}", socket.display()))?;
    let mut reader = writer.try_clone()?;
    let stdout_thread = std::thread::spawn(move || {
        let _ = std::io::copy(&mut reader, &mut std::io::stdout());
    });
    let _ = std::io::copy(&mut std::io::stdin(), &mut writer);
    let _ = writer.shutdown(std::net::Shutdown::Write);
    let _ = writer.flush();
    let _ = stdout_thread.join();
    Ok(())
}

/// Pull, export/load, apply, create, and start can outlast the 30s default.
const LONG_RPC: std::time::Duration = std::time::Duration::from_secs(3600);

/// A `\r`-redrawn byte counter on stderr. Redraws at most every 100ms and
/// stays silent when stderr is not a terminal (logs, CI, `2>file`).
struct Progress {
    tty: bool,
    last: Option<std::time::Instant>,
}

impl Progress {
    fn new() -> Self {
        use std::io::IsTerminal;
        Self {
            tty: std::io::stderr().is_terminal(),
            last: None,
        }
    }

    fn tick(&mut self, line: impl FnOnce() -> String) {
        let due = self
            .last
            .is_none_or(|t| t.elapsed() >= std::time::Duration::from_millis(100));
        if self.tty && due {
            self.last = Some(std::time::Instant::now());
            eprint!("\r{}\x1b[K", line());
        }
    }

    /// Final line; clears a redrawn counter first.
    fn done(&self, line: &str) {
        if self.tty {
            eprintln!("\r{line}\x1b[K");
        } else {
            eprintln!("{line}");
        }
    }
}

pub(crate) async fn print_versions(cli: &Cli) -> Result<()> {
    println!("rustypods {}", env!("CARGO_PKG_VERSION"));
    match connect(cli.socket.clone(), cli.remote.clone(), cli.host.clone()).await {
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
    cmd::dispatch(cli).await
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
    fn destructive_prompt_only_on_a_tty_without_yes() {
        assert!(proceed_destructive(false, false, ""));
        assert!(proceed_destructive(false, false, "n"));
        assert!(proceed_destructive(true, true, "n"));
        assert!(proceed_destructive(true, false, "y"));
        assert!(proceed_destructive(true, false, "Y\n"));
        assert!(!proceed_destructive(true, false, ""));
        assert!(!proceed_destructive(true, false, "n"));
        assert!(!proceed_destructive(true, false, "yes"));
    }

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
    fn mesh_host_and_cluster_flags_parse() {
        let cli = Cli::try_parse_from(["rustypods", "--host", "s2", "ps"]).unwrap();
        assert_eq!(cli.host.as_deref(), Some("s2"));
        assert!(matches!(cli.cmd, Some(Cmd::Ps)));
        assert!(
            Cli::try_parse_from(["rustypods", "--host", "s2", "--remote", "user@host", "ps",])
                .is_err()
        );

        let cli =
            Cli::try_parse_from(["rustypods", "mesh", "sign-csr", "pubkey-value", "node.csr"])
                .unwrap();
        assert!(matches!(
            cli.cmd,
            Some(Cmd::Mesh {
                sub: MeshCmd::SignCsr { ref pubkey, ref csr },
            }) if pubkey == "pubkey-value" && csr == "node.csr"
        ));
        assert!(matches!(
            Cli::try_parse_from(["rustypods", "mesh", "create-csr"])
                .unwrap()
                .cmd,
            Some(Cmd::Mesh {
                sub: MeshCmd::CreateCsr,
            })
        ));

        let cli = Cli::try_parse_from(["rustypods", "mesh", "init", "--token", "cluster-secret"])
            .unwrap();
        assert!(matches!(
            cli.cmd,
            Some(Cmd::Mesh {
                sub: MeshCmd::Init {
                    token: Some(ref t),
                    ..
                }
            }) if t == "cluster-secret"
        ));

        let cli = Cli::try_parse_from([
            "rustypods",
            "volume",
            "send",
            "dbdata",
            "--to",
            "s2",
            "--rename-as",
            "dbcopy",
            "--format",
            "tar",
        ])
        .unwrap();
        assert!(matches!(
            cli.cmd,
            Some(Cmd::Volume {
                sub: VolumeCmd::Send {
                    ref name,
                    ref to,
                    rename_as: Some(ref rename),
                    format: Some(ref format),
                    ..
                }
            }) if name == "dbdata" && to == "s2" && rename == "dbcopy" && format == "tar"
        ));
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
