//! Shared client transport for the daemon's gRPC API.
//!
//! Local mode connects straight to the Unix socket; remote mode spawns
//! `ssh -T <dest> socat - UNIX-CONNECT:<sock>` and pipes gRPC over its
//! stdio — the podman/docker remote pattern (SSH supplies auth+encryption).
//! Used by both the `rustypods` CLI and the Tauri GUI backend.

use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

use rustypods_proto::rpc::pod_control_client::PodControlClient;

/// Transport: local Unix socket, or an SSH subprocess whose stdio is
/// bridged to the remote daemon socket via socat.
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
    let err_hint = match &remote {
        Some(d) => format!("connecting to rustypodsd via {d} — ssh up? socat installed remotely?"),
        None => "connecting to rustypodsd — is it running? (sudo systemctl start rustypodsd)".into(),
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
    Ok(PodControlClient::new(ch))
}
