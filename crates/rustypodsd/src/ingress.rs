//! Ingress gateway reconciliation: complete route snapshots pushed over
//! the gateway's control UDS. Snapshot construction is pure (testable);
//! the push/status helpers speak tonic over the managed Unix socket.

use std::collections::BTreeSet;
use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{bail, Context, Result};
use rustypods_proto as proto;
use rustypods_proto::rpc::ingress_control_client::IngressControlClient;
use rustypods_proto::rpc::{
    ActiveIngressRoute, IngressStatus, IngressStatusRequest, RouteSnapshot, RouteSnapshotAck,
};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

use crate::net;
use crate::state::PodMeta;

/// Build one complete route snapshot: every RUNNING pod's persisted
/// ingress rules → its pod IPv4 endpoint. The gateway itself is never a
/// backend; `exclude` is treated as non-running (pre-stop/destroy drain).
/// An ingress rule on a pod without a net_index is corrupt state → error,
/// never silently dropped (a missing route would still ACK and leave the
/// pod unreachable instead of surfacing the bug).
pub fn build_snapshot(
    pods: Vec<&PodMeta>,
    running: &BTreeSet<String>,
    exclude: Option<&str>,
    generation: u64,
) -> Result<RouteSnapshot> {
    let mut routes = Vec::new();
    for m in pods {
        if m.ingress_gateway
            || m.ingress.is_empty()
            || !running.contains(&m.name)
            || exclude == Some(m.name.as_str())
        {
            continue;
        }
        if m.net_index == 0 {
            bail!("pod {} has ingress rules but no net_index", m.name);
        }
        let ip = net::pod_ip(m.net_index).to_string();
        for r in &m.ingress {
            routes.push(ActiveIngressRoute {
                host: r.host.clone(),
                backend_ip: ip.clone(),
                backend_port: r.pod_port as u32,
            });
        }
    }
    // Deterministic order — pod-map iteration is unordered, and the
    // daemon dedups pushes by comparing route sets for equality.
    routes.sort_by(|a, b| a.host.cmp(&b.host));
    Ok(RouteSnapshot { generation, routes })
}

/// Connect to the gateway control UDS: 1s connect, 2s per-request bound —
/// a hung dataplane must not stall the daemon's pod-lock caller forever.
/// Open the gateway control socket without following a symlink. The path
/// lives in the pod's run directory, which pod-root can rewrite. A symlink
/// there would make the root daemon connect to an arbitrary host socket.
/// The inode is opened `O_PATH|O_NOFOLLOW` and must be a socket owned by
/// the same uid as the run directory (root, or the userns mapped root).
pub fn open_control_socket(sock: &Path) -> Result<std::os::fd::OwnedFd> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
    let parent = sock
        .parent()
        .context("ingress control socket has no parent")?;
    let dir =
        std::fs::symlink_metadata(parent).with_context(|| format!("stat {}", parent.display()))?;
    if !dir.file_type().is_dir() {
        bail!("{} is not a directory", parent.display());
    }
    let expect_uid = dir.uid();
    let fd = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open(sock)
        .with_context(|| format!("open {}", sock.display()))?;
    let md = fd.metadata().context("fstat ingress control socket")?;
    if md.file_type().is_symlink() || !md.file_type().is_socket() {
        bail!("{} is not a unix socket", sock.display());
    }
    if md.uid() != expect_uid {
        bail!(
            "{} is owned by uid {}, expected {} (run dir owner)",
            sock.display(),
            md.uid(),
            expect_uid
        );
    }
    Ok(fd.into())
}

async fn control_client(data_dir: &Path) -> Result<IngressControlClient<Channel>> {
    let sock = proto::ingress_socket(data_dir);
    let fd = open_control_socket(&sock)?;
    let ch = Endpoint::try_from("http://[::]:0")?
        .connect_timeout(std::time::Duration::from_secs(1))
        .timeout(std::time::Duration::from_secs(2))
        .connect_with_connector(service_fn(move |_: http::Uri| {
            let fd = fd.try_clone().map_err(|e| {
                std::io::Error::new(e.kind(), format!("clone control socket fd: {e}"))
            });
            async move {
                let fd = fd?;
                // /proc/self/fd/N names the inode we already opened with
                // O_NOFOLLOW, so a later swap of the path cannot redirect us.
                let proc = format!("/proc/self/fd/{}", fd.as_raw_fd());
                let stream = UnixStream::connect(&proc)
                    .await
                    .map_err(|e| std::io::Error::new(e.kind(), format!("connect {proc}: {e}")))?;
                drop(fd);
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .context("connect ingress control socket")?;
    Ok(IngressControlClient::new(ch))
}

/// Push a complete snapshot; the ACK must echo generation + route count
/// exactly — a mismatched ACK means the gateway applied something else.
pub async fn push_snapshot(data_dir: &Path, snapshot: RouteSnapshot) -> Result<RouteSnapshotAck> {
    let mut c = control_client(data_dir).await?;
    let want_gen = snapshot.generation;
    let want_routes = snapshot.routes.len() as u32;
    let ack = c
        .replace_routes(snapshot)
        .await
        .context("replace ingress routes")?
        .into_inner();
    if ack.generation != want_gen || ack.route_count != want_routes {
        bail!(
            "ingress ack mismatch: wanted generation {want_gen}/{want_routes} routes, got {}/{}",
            ack.generation,
            ack.route_count
        );
    }
    Ok(ack)
}

/// Gateway dataplane status (generation + live route count).
pub async fn gateway_status(data_dir: &Path) -> Result<IngressStatus> {
    let mut c = control_client(data_dir).await?;
    Ok(c.get_status(IngressStatusRequest {})
        .await
        .context("ingress status")?
        .into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::PodMeta;

    fn meta(name: &str, net_index: u32, rules: &[(&str, u16)]) -> PodMeta {
        PodMeta {
            format: 1,
            name: name.into(),
            image: "img".into(),
            created_unix: 0,
            limits: Default::default(),
            ephemeral: false,
            private_users: true,
            started: false,
            stopped_by_user: false,
            stop_timeout_secs: 0,
            storage_max_bytes: 0,
            ports: vec![],
            ingress: rules
                .iter()
                .map(|(h, p)| crate::state::IngressSpec {
                    host: h.to_string(),
                    pod_port: *p,
                })
                .collect(),
            net_index,
            stack: String::new(),
            binds: vec![],
            cmd: vec![],
            snap_keep_last: 0,
            snap_max_age_secs: 0,
            ingress_gateway: false,
            autostart: false,
            restart: String::new(),
            healthcheck: Default::default(),
            env: vec![],
            volumes: vec![],
            host_access: false,
            isolated: false,
            allow_setuid: false,
        }
    }

    fn running(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn snapshot_running_only() {
        let up = meta("up", 3, &[("a.rustypods.localhost", 8080)]);
        let down = meta("down", 4, &[("b.rustypods.localhost", 80)]);
        let s = build_snapshot(vec![&up, &down], &running(&["up"]), None, 7).unwrap();
        assert_eq!(s.generation, 7);
        assert_eq!(s.routes.len(), 1);
        assert_eq!(s.routes[0].host, "a.rustypods.localhost");
        assert_eq!(s.routes[0].backend_ip, "10.220.3.2");
        assert_eq!(s.routes[0].backend_port, 8080);
    }

    #[test]
    fn snapshot_excludes_and_skips_gateway() {
        let mut gw = meta(proto::INGRESS_POD, 9, &[]);
        gw.ingress_gateway = true;
        let drain = meta("drain", 5, &[("d.rustypods.localhost", 80)]);
        let s = build_snapshot(
            vec![&gw, &drain],
            &running(&[proto::INGRESS_POD, "drain"]),
            Some("drain"),
            1,
        )
        .unwrap();
        assert!(s.routes.is_empty());
    }

    #[test]
    fn snapshot_stack_members_share_ip() {
        // Stack members persist the stack's net_index — same backend IP.
        let a = meta("s-web", 6, &[("web.rustypods.localhost", 8080)]);
        let b = meta("s-api", 6, &[("api.rustypods.localhost", 9000)]);
        let s = build_snapshot(vec![&a, &b], &running(&["s-web", "s-api"]), None, 2).unwrap();
        assert_eq!(s.routes.len(), 2);
        assert!(s.routes.iter().all(|r| r.backend_ip == "10.220.6.2"));
    }

    #[test]
    fn snapshot_rejects_ingress_without_index() {
        let bad = meta("bad", 0, &[("x.rustypods.localhost", 80)]);
        assert!(build_snapshot(vec![&bad], &running(&["bad"]), None, 1).is_err());
    }

    #[tokio::test]
    async fn control_socket_rejects_a_symlink() {
        let dir = std::env::temp_dir().join(format!(
            "rp-sock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("ingress.sock");
        let _listener = tokio::net::UnixListener::bind(&real).unwrap();
        assert!(open_control_socket(&real).is_ok());
        let link = dir.join("via-link.sock");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(open_control_socket(&link).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
