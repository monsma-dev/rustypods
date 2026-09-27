use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use rustypodsd::{euid, server, Config};

#[derive(Parser)]
#[command(
    name = "rustypodsd",
    about = "RustyPods daemon — nspawn pods on Btrfs, driven over UDS+gRPC"
)]
struct Args {
    /// Root for images/, pods/, logs/, bin/, shm/, conf/.
    #[arg(long, default_value = rustypods_proto::DATA_DIR)]
    data_dir: PathBuf,

    /// Unix socket for the control plane.
    #[arg(long, default_value = rustypods_proto::SOCKET_PATH)]
    socket: PathBuf,

    /// Besides root, this uid may drive the daemon.
    #[arg(long, default_value_t = 1000)]
    allowed_uid: u32,

    /// Host user owning the rootless podman store (for `import
    /// --from-distrobox`). Default: the login name behind --allowed-uid.
    #[arg(long)]
    import_user: Option<String>,

    /// REST/JSON API bind address — bearer-token gated, loopback only by
    /// default. Empty string disables the HTTP listener. A non-loopback
    /// bind needs RUSTYPODS_HTTP_INSECURE=1 in the environment.
    #[arg(long, default_value = "127.0.0.1:9180")]
    http_addr: String,

    /// Snapshot GC sweep interval in seconds.
    #[arg(long, default_value_t = 300)]
    gc_interval_secs: u64,

    /// Print the nftables transaction the daemon would apply (every
    /// networked pod treated as running) and exit — for piping into
    /// `nft --check -f -` on the host. Applies nothing.
    #[arg(long, hide = true)]
    print_nat: bool,

    #[command(subcommand)]
    cmd: Option<DaemonCmd>,
}

#[derive(clap::Subcommand)]
enum DaemonCmd {
    /// Remove RustyPods nft tables, marker firewall inserts, and
    /// firewalld runtime zone bindings. Does not restore sysctls.
    /// Root only. For uninstall scripts.
    TeardownNet,
}

fn main() -> Result<()> {
    // Before the runtime spawns its worker threads (see Notifier docs).
    let notify = rustypodsd::notify::Notifier::take_from_env();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?
        .block_on(run(notify))
}

async fn run(notify: rustypodsd::notify::Notifier) -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    // Fail before any listener, nft script, or pod create if a set
    // RUSTYPODS_* value does not parse. Missing variables keep defaults.
    rustypodsd::envcfg::load().context("daemon environment")?;
    rustypodsd::net::load_pool().context("pod address pool")?;
    // reqwest (oci-client) is built with rustls-no-provider — install the
    // ring backend process-wide before any OCI pull touches TLS.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("rustls ring provider already installed"))?;
    // The REST API is bearer-token gated but carries root-equivalent power
    // over plain HTTP — keep it on loopback unless the operator opts out.
    if !args.http_addr.is_empty() {
        let loopback = args
            .http_addr
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false);
        if !loopback && !rustypodsd::server::http_insecure_enabled() {
            anyhow::bail!(
                "refusing to bind the REST API to non-loopback '{}' — \
                 set RUSTYPODS_HTTP_INSECURE=1 to override. The supported \
                 remote path is SSH forwarding (ssh -L 9180:127.0.0.1:9180 host) \
                 or the gRPC client --remote mode",
                args.http_addr
            );
        }
        if !loopback {
            tracing::warn!(
                "SECURITY: RUSTYPODS_HTTP_INSECURE=1 — REST API will bind to {}. \
                 Plain HTTP, root-equivalent token. Prefer SSH -L or gRPC --remote.",
                args.http_addr
            );
        }
    }
    if matches!(args.cmd, Some(DaemonCmd::TeardownNet)) {
        if euid() != 0 {
            anyhow::bail!("teardown-net must run as root");
        }
        return rustypodsd::net::teardown_all();
    }
    if euid() != 0 {
        tracing::warn!("rustypodsd is not running as root — nspawn/btrfs/machined will fail");
    }
    // Default import user: whoever --allowed-uid maps to. A uid without a
    // passwd entry needs an explicit --import-user.
    let import_user = match args.import_user {
        Some(u) => u,
        None => {
            let passwd = std::fs::read_to_string("/etc/passwd").context("reading /etc/passwd")?;
            rustypods_proto::username_for_uid(&passwd, args.allowed_uid).with_context(|| {
                format!(
                    "--import-user is required because uid {} has no passwd entry",
                    args.allowed_uid
                )
            })?
        }
    };
    rustypods_proto::validate_unix_user(&import_user)?;
    if args.print_nat {
        let st = rustypodsd::state::load(&args.data_dir)?;
        // Treat every networked pod as running so the generated script
        // shows the FULL rule shape (incl. gateway redirects) for check.
        let running: std::collections::BTreeSet<String> = st
            .pods
            .values()
            .filter(|m| m.net_index > 0)
            .map(|m| m.name.clone())
            .collect();
        print!(
            "{}",
            rustypodsd::net::nat_script(st.pods.values(), &running)
        );
        return Ok(());
    }
    server::serve(Config {
        data_dir: args.data_dir,
        socket: args.socket,
        allowed_uid: args.allowed_uid,
        read_only_uids: rustypodsd::envcfg::load()
            .context("daemon environment")?
            .read_only_uids
            .clone(),
        role: rustypodsd::envcfg::load()
            .context("daemon environment")?
            .role,
        import_user,
        http_addr: args.http_addr,
        gc_interval_secs: args.gc_interval_secs,
        notify,
    })
    .await
}
