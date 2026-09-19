use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

use rustypods_proto::rpc::pod_control_client::PodControlClient;
use rustypods_proto::rpc::*;
use rustypods_proto::{fmt_bytes, parse_bytes, SOCKET_PATH};

#[derive(Parser)]
#[command(name = "rustypods", version, about = "nspawn pods on Btrfs — podman/distrobox-light")]
struct Cli {
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
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Daemon status (version, machined, btrfs).
    Ping,
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
        /// Port mapping hostPort:podPort[/tcp|/udp]; repeatable.
        /// Implies private networking (--network-veth), so no host-net parity.
        #[arg(long)]
        port: Vec<String>,
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
        #[arg(long)]
        private_users: bool,
    },
    /// Stop a pod (SIGRTMIN+3 → terminate).
    Stop { name: String },
    /// Restart with the persisted limits.
    Restart { name: String },
    /// List pods.
    Ps,
    /// Stop and remove a pod (Btrfs snapshot gone).
    Destroy { name: String },
    /// Instant CoW clone: snapshot a pod's rootfs + conf under a new name.
    Clone { source: String, dest: String },
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
    },
    /// Reread a hand-edited <pod>.conf and apply it.
    Reload { name: String },
    /// Live telemetry from the pod (rustypods-agent → daemon).
    Metrics { name: String },
    /// Shared-memory segments: mmap'able files, host /dev/shm ↔ pod /run/rustypods/shm.
    Shm {
        #[command(subcommand)]
        sub: ShmCmd,
    },
    /// Shell into a running pod (native Exec RPC: nsenter + host pty).
    Shell {
        name: String,
        /// Log in as this container user (default: $USER).
        #[arg(long)]
        user: Option<String>,
        /// Command instead of an interactive shell.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
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

/// Transport: local Unix socket, or an SSH subprocess whose stdio is
/// bridged to the remote daemon socket via socat (the podman approach).
#[allow(dead_code)] // the Child field is kept for kill_on_drop teardown
enum Conn {
    Unix(UnixStream),
    Ssh(tokio::process::ChildStdout, tokio::process::ChildStdin, tokio::process::Child),
}

impl tokio::io::AsyncRead for Conn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Conn::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Conn::Ssh(o, _, _) => std::pin::Pin::new(o).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Conn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            Conn::Unix(s) => std::pin::Pin::new(s).poll_write(cx, data),
            Conn::Ssh(_, i, _) => std::pin::Pin::new(i).poll_write(cx, data),
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Conn::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
            Conn::Ssh(_, i, _) => std::pin::Pin::new(i).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Conn::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Conn::Ssh(_, i, _) => std::pin::Pin::new(i).poll_shutdown(cx),
        }
    }
}

fn ssh_pipe(dest: &str, sock: &PathBuf) -> std::io::Result<Conn> {
    // socat bridges ssh stdio to the remote UDS. -T: no pty (pure channel),
    // BatchMode: fail fast instead of an interactive password prompt.
    let mut child = tokio::process::Command::new("ssh")
        .args([
            "-q",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            dest,
            "socat",
            "-",
            &format!("UNIX-CONNECT:{}", sock.display()),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit()) // ssh errors surface directly
        .kill_on_drop(true)
        .spawn()?;
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    Ok(Conn::Ssh(stdout, stdin, child))
}

async fn connect(path: PathBuf, remote: Option<String>) -> Result<PodControlClient<Channel>> {
    let err_hint = match &remote {
        Some(d) => format!("connecting to rustypodsd via {d} — ssh up? socat installed remotely?"),
        None => "connecting to rustypodsd — is it running? (sudo systemctl start rustypodsd)".into(),
    };
    let ch = Endpoint::try_from("http://[::]:0")?
        .connect_with_connector(service_fn(move |_: http::Uri| {
            let p = path.clone();
            let remote = remote.clone();
            async move {
                let conn = match &remote {
                    Some(dest) => ssh_pipe(dest, &p)?,
                    None => Conn::Unix(UnixStream::connect(&p).await?),
                };
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(conn))
            }
        }))
        .await
        .context(err_hint)?;
    Ok(PodControlClient::new(ch))
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
    cmd: Vec<String>,
) -> Result<()> {
    use rustypods_proto::rpc::exec_chunk::Kind;
    use std::io::{IsTerminal, Write};
    use tokio::io::AsyncReadExt;
    use tokio_stream::wrappers::ReceiverStream;

    let tty = std::io::stdin().is_terminal();
    let user = user.or_else(|| std::env::var("USER").ok()).unwrap_or_else(|| "root".into());
    let (rows, cols) = if tty { term_size() } else { (0, 0) };
    let mut env = Vec::new();
    for k in ["TERM", "COLORTERM", "LANG"] {
        if let Ok(v) = std::env::var(k) {
            env.push(format!("{k}={v}"));
        }
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
    if !p.stack.is_empty() {
        extra.push_str(&format!(" stack={}", p.stack));
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Shell { name, user, cmd } => {
            shell_exec(cli.socket, cli.remote, name, user, cmd).await?;
        }
        Cmd::Ping => {
            let i = connect(cli.socket.clone(), cli.remote.clone()).await?.ping(PingRequest {}).await?.into_inner();
            println!("rustypodsd v{}", i.version);
            println!("socket:   {}", i.socket_path);
            println!("data:     {}", i.data_dir);
            println!("machined: {}   btrfs: {}", i.machined, i.btrfs);
        }
        Cmd::Images => {
            let l = connect(cli.socket.clone(), cli.remote.clone()).await?.list_images(ListImagesRequest {}).await?.into_inner();
            for i in &l.images {
                println!("{:<20} {:<20} {}", i.name, i.source, i.path);
            }
            if l.images.is_empty() {
                println!("no images — `rustypods import --from-distrobox arch`");
            }
        }
        Cmd::Import { from_distrobox, name, user } => {
            let name = name.unwrap_or_else(|| format!("{from_distrobox}-base"));
            let user = user.unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "nick".into()));
            println!("exporting: {from_distrobox} → {name} (this can take a while)...");
            let img = connect(cli.socket.clone(), cli.remote.clone())
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
            connect(cli.socket.clone(), cli.remote.clone()).await?.remove_image(ImageRef { name: name.clone() }).await?;
            println!("image {name} removed");
        }
        Cmd::Create { name, image, storage_max, port } => {
            let storage_max_bytes = storage_max.as_deref().map(parse_bytes).transpose()?.unwrap_or(0);
            if !port.is_empty() {
                eprintln!("note: --port implies a private netns (--network-veth); the pod no longer shares host networking");
            }
            let p = connect(cli.socket.clone(), cli.remote.clone())
                .await?
                .create_pod(CreatePodRequest { name, image, storage_max_bytes, ports: port })
                .await?
                .into_inner();
            print_pod(&p);
        }
        Cmd::Start { name, memory_high, memory_max, cpu, ephemeral, private_users } => {
            let p = connect(cli.socket.clone(), cli.remote.clone())
                .await?
                .start_pod(StartPodRequest {
                    name: name.clone(),
                    limits: limits_proto(memory_high.as_deref(), memory_max.as_deref(), cpu)?,
                    ephemeral,
                    private_users,
                })
                .await?
                .into_inner();
            print_pod(&p);
            println!("shell: rustypods shell {name}");
        }
        Cmd::Stop { name } => {
            let p = connect(cli.socket.clone(), cli.remote.clone()).await?.stop_pod(PodRef { name }).await?.into_inner();
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
                    private_users: false,
                })
                .await?
                .into_inner();
            print_pod(&p);
        }
        Cmd::Ps => {
            let l = connect(cli.socket.clone(), cli.remote.clone()).await?.list_pods(ListPodsRequest {}).await?.into_inner();
            for p in &l.pods {
                print_pod(p);
            }
            if l.pods.is_empty() {
                println!("no pods — `rustypods create <name> --image <image>`");
            }
        }
        Cmd::Destroy { name } => {
            connect(cli.socket.clone(), cli.remote.clone()).await?.destroy_pod(PodRef { name: name.clone() }).await?;
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
        Cmd::Apply { file } => {
            let toml = std::fs::read(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let r = connect(cli.socket.clone(), cli.remote.clone())
                .await?
                .apply_stack(ApplyStackRequest { toml })
                .await?
                .into_inner();
            println!("stack {} applied ({} pods, shared netns)", r.name, r.pods.len());
            for p in &r.pods {
                print_pod(p);
            }
            println!("start: rustypods stack start {}", r.name);
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
                                private_users: false,
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
        Cmd::Config { name, memory_high, memory_max, cpu, storage_max } => {
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
            let cur_lim = cur.limits.clone().unwrap_or_default();
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
            let p = c
                .update_pod_config(UpdatePodConfigRequest {
                    name,
                    limits: Some(lim),
                    storage_max_bytes,
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
                        println!("{:<20} {:>10}  {}", s.name, fmt_bytes(s.size_bytes), s.host_path);
                    }
                    if l.segs.is_empty() {
                        println!("no segments");
                    }
                }
                ShmCmd::Rm { pod, name } => {
                    c.remove_shm(ShmRef { pod, name: name.clone() }).await?;
                    println!("segment {name} removed");
                }
            }
        }
    }
    Ok(())
}
