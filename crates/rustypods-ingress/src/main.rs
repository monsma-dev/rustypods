//! rustypods-ingress — the public edge for `<host>.rustypods.localhost`.
//! Plain HTTP only redirects to HTTPS; TLS terminates here (local PKI
//! certs, pod traffic never leaves the box). Route control comes from
//! rustypodsd over a root-only UDS.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use rustypods_ingress::{control, net, proxy};
use rustypods_proto::POD_INGRESS_SOCK;

#[derive(Parser)]
#[command(name = "rustypods-ingress", about = "RustyPods ingress proxy")]
struct Cli {
    /// Plain-HTTP bind (health + 308 redirect to HTTPS).
    #[arg(long, default_value = "[::]:8080")]
    http_addr: SocketAddr,
    /// TLS bind — the actual proxy.
    #[arg(long, default_value = "[::]:8443")]
    https_addr: SocketAddr,
    /// Control unix socket (daemon pushes route snapshots).
    #[arg(long, default_value = POD_INGRESS_SOCK)]
    control_socket: PathBuf,
    /// PEM certificate chain for the HTTPS listener.
    #[arg(long, default_value = "/etc/rustypods-ingress/tls.crt")]
    tls_cert: PathBuf,
    /// PEM private key for the HTTPS listener.
    #[arg(long, default_value = "/etc/rustypods-ingress/tls.key")]
    tls_key: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();

    // rustls is built without a default crypto provider (axum-server's
    // tls-rustls-no-provider feature) — install ring explicitly so the
    // TLS stack doesn't silently pull a second provider crate.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("install ring crypto provider"))?;
    // Fail fast: no certs, no proxy. Both files must parse as PEM before
    // any listener binds.
    let tls = RustlsConfig::from_pem_file(&cli.tls_cert, &cli.tls_key)
        .await
        .with_context(|| {
            format!(
                "load TLS pair {} / {}",
                cli.tls_cert.display(),
                cli.tls_key.display()
            )
        })?;

    let routes = Arc::new(control::RouteState::new());
    let limits = proxy::ProxyLimits::from_env();
    let state = proxy::proxy_state_with(routes.clone(), limits.clone());
    let http_listener = net::dual_stack_listener(cli.http_addr)
        .with_context(|| format!("bind http {}", cli.http_addr))?;
    let http_limits = limits.clone();
    let http =
        async move { proxy::serve_capped(http_listener, proxy::http_app(), http_limits).await };
    let https_std = net::dual_stack_listener(cli.https_addr)
        .with_context(|| format!("bind https {}", cli.https_addr))?
        .into_std()
        .context("https listener to std")?;
    let tls_watch = tls.clone();
    let acceptor =
        axum_server::tls_rustls::RustlsAcceptor::new(tls).handshake_timeout(limits.tls_handshake);
    let mut https = axum_server::from_tcp(https_std)?.acceptor(acceptor);
    proxy::configure_public_http(https.http_builder(), &limits);
    let https = https.serve(proxy::https_app(state).into_make_service());
    let watch_cert = cli.tls_cert.clone();
    let watch_key = cli.tls_key.clone();
    tokio::spawn(async move {
        let mut seen = std::fs::metadata(&watch_cert)
            .and_then(|m| m.modified())
            .ok();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let now = std::fs::metadata(&watch_cert)
                .and_then(|m| m.modified())
                .ok();
            if now.is_some() && now != seen {
                match tls_watch
                    .reload_from_pem_file(&watch_cert, &watch_key)
                    .await
                {
                    Ok(()) => {
                        seen = now;
                        tracing::info!("reloaded ingress TLS certificate");
                    }
                    Err(e) => tracing::warn!("tls reload: {e}"),
                }
            }
        }
    });
    let ctrl = {
        let sock = cli.control_socket.clone();
        async move { control::serve(&sock, routes, std::future::pending()).await }
    };

    tracing::info!(
        "rustypods-ingress: http={} https={} control={}",
        cli.http_addr,
        cli.https_addr,
        cli.control_socket.display()
    );
    // First error wins — the remaining futures are dropped with it.
    tokio::try_join!(
        async move { http.await.map_err(|e| anyhow::anyhow!("http: {e}")) },
        async move { https.await.map_err(|e| anyhow::anyhow!("https: {e}")) },
        ctrl,
    )
    .map(|_| ())
}
