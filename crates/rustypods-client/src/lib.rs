//! Shared client transport for the daemon's gRPC API.
#![forbid(unsafe_code)]
//!
//! Local mode connects straight to the Unix socket; remote mode spawns
//! `ssh -T <dest> socat - UNIX-CONNECT:<sock>` and pipes gRPC over its
//! stdio — the podman/docker remote pattern (SSH supplies auth+encryption).
//! Used by both the `rustypods` CLI and the Tauri GUI backend.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

use rustypods_proto::rpc::pod_control_client::PodControlClient;
use rustypods_proto::rpc::PingRequest;

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
    let where_ = if remote { "remote daemon" } else { "local daemon" };
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

/// Connect to the daemon — local UDS, or remote via `ssh … socat`.
pub async fn connect(path: PathBuf, remote: Option<String>) -> Result<PodControlClient<Channel>> {
    connect_timeout(path, remote, std::time::Duration::from_secs(30)).await
}

/// `connect` with a caller-chosen per-request bound — image pulls can
/// legitimately outlast the default 30s on slow links.
pub async fn connect_timeout(
    path: PathBuf,
    remote: Option<String>,
    timeout: std::time::Duration,
) -> Result<PodControlClient<Channel>> {
    let is_remote = remote.is_some();
    let err_hint = match &remote {
        Some(d) => format!("connecting to rustypodsd via {d} — ssh up? socat installed remotely?"),
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
    let mut client = PodControlClient::new(ch);
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
}
