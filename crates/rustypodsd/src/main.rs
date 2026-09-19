use anyhow::Result;
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

    /// Host user owning the rootless podman store (for `import --from-distrobox`).
    #[arg(long, default_value = "nick")]
    import_user: String,

    /// REST/JSON API bind address — bearer-token gated, loopback only by
    /// default. Empty string disables the HTTP listener. A non-loopback
    /// bind needs RUSTYPODS_HTTP_INSECURE=1 in the environment.
    #[arg(long, default_value = "127.0.0.1:9180")]
    http_addr: String,

    /// Snapshot GC sweep interval in seconds.
    #[arg(long, default_value_t = 300)]
    gc_interval_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    // The REST API is bearer-token gated but carries root-equivalent power
    // over plain HTTP — keep it on loopback unless the operator opts out.
    if !args.http_addr.is_empty() {
        let loopback = args
            .http_addr
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false);
        if !loopback && std::env::var_os("RUSTYPODS_HTTP_INSECURE").is_none() {
            anyhow::bail!(
                "refusing to bind the REST API to non-loopback '{}' — \
                 set RUSTYPODS_HTTP_INSECURE=1 to override",
                args.http_addr
            );
        }
    }
    if euid() != 0 {
        tracing::warn!("rustypodsd is not running as root — nspawn/btrfs/machined will fail");
    }
    server::serve(Config {
        data_dir: args.data_dir,
        socket: args.socket,
        allowed_uid: args.allowed_uid,
        import_user: args.import_user,
        http_addr: args.http_addr,
        gc_interval_secs: args.gc_interval_secs,
    })
    .await
}
