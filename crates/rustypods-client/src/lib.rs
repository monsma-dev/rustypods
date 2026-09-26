//! Shared client transport for the daemon's gRPC API.
#![forbid(unsafe_code)]
//!
//! Local mode connects straight to the Unix socket; remote mode spawns
//! `ssh -T <dest> socat - UNIX-CONNECT:<sock>` and pipes gRPC over its
//! stdio — the podman/docker remote pattern (SSH supplies auth+encryption).
//! Used by both the `rustypods` CLI and the Tauri GUI backend.

use anyhow::{Context, Result};
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use tokio::net::UnixStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tower::service_fn;

use rustypods_proto::rpc::pod_control_client::PodControlClient;
use rustypods_proto::rpc::{Empty, MeshPeerInfo, PingRequest};

/// Daemon-to-daemon PodControl port inside the encrypted mesh.
pub const MESH_RPC_PORT: u16 = 5306;

/// Pass-through so UDS, SSH, and mesh share one client type. Mesh calls
/// authenticate in the TLS handshake; UDS calls authenticate with
/// SO_PEERCRED on the daemon.
#[derive(Clone, Default)]
pub struct ClusterAuth;

impl tonic::service::Interceptor for ClusterAuth {
    fn call(
        &mut self,
        req: tonic::Request<()>,
    ) -> std::result::Result<tonic::Request<()>, tonic::Status> {
        Ok(req)
    }
}

pub type Client =
    PodControlClient<tonic::service::interceptor::InterceptedService<Channel, ClusterAuth>>;

/// `major.minor` of a Cargo version (`0.1.0` → `(0, 1)`). Patch is ignored.
pub fn major_minor(version: &str) -> Option<(u64, u64)> {
    let mut parts = version.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Same major.minor means the CLI and daemon speak the same RPC generation.
pub fn versions_compatible(cli: &str, daemon: &str) -> bool {
    match (major_minor(cli), major_minor(daemon)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn warn_version_mismatch(daemon_version: &str, remote: bool) {
    let ours = env!("CARGO_PKG_VERSION");
    if versions_compatible(ours, daemon_version) {
        return;
    }
    let where_ = if remote {
        "remote daemon"
    } else {
        "local daemon"
    };
    eprintln!(
        "warning: this CLI is {ours} but the {where_} is {daemon_version} (major.minor differ) — upgrade both before relying on this session"
    );
}

/// Transport: local Unix socket, or an SSH subprocess whose stdio is
/// bridged to the remote daemon socket via socat.
#[allow(dead_code)] // the Child field is kept for kill_on_drop teardown
enum Conn {
    Unix(UnixStream),
    Ssh(
        tokio::process::ChildStdout,
        tokio::process::ChildStdin,
        tokio::process::Child,
    ),
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

/// Remote shell snippet: prefer the hidden `stdio-bridge` subcommand so
/// the far side needs no socat, and fall back to socat for older installs.
pub fn remote_bridge_script(sock: &Path) -> String {
    let q = shell_quote(&sock.display().to_string());
    format!("rustypods stdio-bridge --socket {q} || socat - UNIX-CONNECT:{q}")
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn ssh_pipe(dest: &str, sock: &Path) -> std::io::Result<Conn> {
    // A dest starting with '-' would be read by ssh as an option.
    if dest.starts_with('-') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid ssh destination",
        ));
    }
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
            "sh",
            "-c",
            &remote_bridge_script(sock),
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

/// Connect to the daemon — local UDS, remote via SSH, or a named mesh peer.
pub async fn connect(
    path: PathBuf,
    remote: Option<String>,
    host: Option<String>,
) -> Result<Client> {
    connect_timeout(path, remote, host, std::time::Duration::from_secs(30)).await
}

/// `connect` with a caller-chosen per-request bound — image pulls can
/// legitimately outlast the default 30s on slow links.
pub async fn connect_timeout(
    path: PathBuf,
    remote: Option<String>,
    host: Option<String>,
    timeout: std::time::Duration,
) -> Result<Client> {
    if let Some(host) = host {
        anyhow::ensure!(
            remote.is_none(),
            "--host and --remote are mutually exclusive"
        );
        return connect_mesh(&path, &host, timeout).await;
    }
    connect_direct(path, remote, timeout).await
}

async fn connect_direct(
    path: PathBuf,
    remote: Option<String>,
    timeout: std::time::Duration,
) -> Result<Client> {
    let is_remote = remote.is_some();
    let err_hint = match &remote {
        Some(d) => format!(
            "connecting to rustypodsd via {d} — ssh up? remote needs `rustypods` (stdio-bridge) or socat"
        ),
        None => {
            "connecting to rustypodsd — is it running? (sudo systemctl start rustypodsd)".into()
        }
    };
    let ch = Endpoint::try_from("http://[::]:0")?
        // Bound each call so a wedged daemon can't hang the CLI/GUI
        // forever. tonic's timeout wraps the per-request response future —
        // for streaming RPCs it resolves when response HEADERS arrive, so
        // long-lived streams (logs -f, metrics, exec) are NOT cut off.
        .timeout(timeout)
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
    let mut client = PodControlClient::with_interceptor(ch, ClusterAuth);
    // Once per process, not once per RPC. A later connect in the same
    // invocation (start after stop, export then load) reuses the result.
    static CHECKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !CHECKED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        match client.ping(PingRequest {}).await {
            Ok(info) => warn_version_mismatch(&info.into_inner().version, is_remote),
            Err(_) => {
                // Don't cache a failed probe — the next command should try again.
                CHECKED.store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
    Ok(client)
}

fn peer_host_addr(peer: &MeshPeerInfo) -> Option<Ipv6Addr> {
    if let Ok(addr) = peer.grpc_addr.trim_matches(['[', ']']).parse() {
        return Some(addr);
    }
    let prefix: Ipv6Addr = peer.prefix.trim_end_matches("/48").parse().ok()?;
    Some(Ipv6Addr::from(((u128::from(prefix) >> 80) << 80) | 1))
}

fn peer_matches(peer: &MeshPeerInfo, selector: &str) -> bool {
    let selector = selector.trim().trim_matches(['[', ']']);
    peer.name == selector
        || peer.pubkey == selector
        || peer.grpc_addr.trim_matches(['[', ']']) == selector
        || peer.prefix == selector
        || peer.prefix.trim_end_matches("/48") == selector
        || peer_host_addr(peer).is_some_and(|a| a.to_string() == selector)
}

/// Resolve a peer through the local UDS and dial its mTLS PodControl
/// listener over the WireGuard mesh. The server name is that peer's
/// WireGuard DNS SAN. The local identity is `<data>/mesh-pki`.
pub async fn connect_mesh(
    path: &Path,
    selector: &str,
    timeout: std::time::Duration,
) -> Result<Client> {
    let mut local =
        connect_direct(path.to_path_buf(), None, std::time::Duration::from_secs(30)).await?;
    let status = local
        .get_mesh_status(Empty {})
        .await
        .context("reading local mesh registry")?
        .into_inner();
    anyhow::ensure!(status.enabled, "mesh is not enabled on this host");
    let matches: Vec<&MeshPeerInfo> = status
        .peers
        .iter()
        .filter(|peer| peer_matches(peer, selector))
        .collect();
    anyhow::ensure!(
        !matches.is_empty(),
        "unknown mesh peer '{selector}' — see `rustypods mesh status`"
    );
    anyhow::ensure!(
        matches.len() == 1,
        "mesh peer selector '{selector}' is ambiguous"
    );
    let peer = matches[0];
    let addr = peer_host_addr(peer)
        .with_context(|| format!("peer '{selector}' has no valid mesh gRPC address"))?;
    let pki = Path::new(rustypods_proto::DATA_DIR).join("mesh-pki");
    let ca = std::fs::read(pki.join("ca.crt")).context("mesh CA certificate")?;
    let cert = std::fs::read(pki.join("node.crt")).context("mesh node certificate")?;
    let key = std::fs::read(pki.join("node.key")).with_context(|| {
        format!(
            "mesh node key {} — the daemon shares it with the allowed uid",
            pki.join("node.key").display()
        )
    })?;
    let tls = ClientTlsConfig::new()
        .domain_name(rustypods_proto::node_dns(&peer.pubkey))
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(cert, key));
    let ch = Endpoint::try_from(format!("https://[{addr}]:{MESH_RPC_PORT}"))?
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(timeout)
        .tls_config(tls)
        .context("mesh TLS")?
        .connect()
        .await
        .with_context(|| {
            format!("connecting to mesh peer '{selector}' at [{addr}]:{MESH_RPC_PORT}")
        })?;
    let mut client = PodControlClient::with_interceptor(ch, ClusterAuth);
    if let Ok(info) = client.ping(PingRequest {}).await {
        warn_version_mismatch(&info.into_inner().version, true);
    }
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn major_minor_ignores_patch() {
        assert_eq!(major_minor("0.1.0"), Some((0, 1)));
        assert_eq!(major_minor("1.2.3-dev"), Some((1, 2)));
        assert!(major_minor("nope").is_none());
        assert!(versions_compatible("0.1.9", "0.1.0"));
        assert!(!versions_compatible("0.2.0", "0.1.0"));
        assert!(!versions_compatible("1.0.0", "0.1.0"));
        assert!(!versions_compatible("garbage", "0.1.0"));
    }

    #[test]
    fn remote_bridge_quotes_socket_and_falls_back_to_socat() {
        let s = remote_bridge_script(Path::new("/run/rustypods/daemon.sock"));
        assert!(s.contains("rustypods stdio-bridge --socket '/run/rustypods/daemon.sock'"));
        assert!(s.contains("|| socat - UNIX-CONNECT:"));
        let q = remote_bridge_script(Path::new("/tmp/it's.sock"));
        assert!(q.contains("'\\''"));
    }

    #[test]
    fn mesh_peer_selector_and_address_fallback() {
        let peer = MeshPeerInfo {
            endpoint: "192.0.2.1:51820".into(),
            pubkey: "pubkey".into(),
            prefix: "fd12:3456:789a::/48".into(),
            name: "s2".into(),
            ..Default::default()
        };
        assert!(peer_matches(&peer, "s2"));
        assert!(peer_matches(&peer, "pubkey"));
        assert!(peer_matches(&peer, "fd12:3456:789a::"));
        assert!(peer_matches(&peer, "fd12:3456:789a::1"));
        assert_eq!(
            peer_host_addr(&peer).unwrap(),
            "fd12:3456:789a::1".parse::<Ipv6Addr>().unwrap()
        );
    }
}
