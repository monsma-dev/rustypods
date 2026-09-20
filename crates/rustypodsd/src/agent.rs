//! Per-pod agent channel: the daemon binds a UDS listener inside the pod's
//! rw-bound run dir; rustypods-agent dials it from inside and pushes Metric
//! samples. Latest sample per pod lives in a watch channel for PodMetrics.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UnixListener;
use tokio::sync::{oneshot, watch, Mutex};
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::StreamExt;
use tonic::{transport::Server, Request, Response, Status, Streaming};

use rustypods_proto::rpc::agent_server::{Agent, AgentServer};
use rustypods_proto::rpc::*;

/// Latest metric per pod name.
pub type MetricsMap = Arc<Mutex<HashMap<String, watch::Sender<Metric>>>>;

/// Shutdown handles for per-pod listeners (keyed by pod name).
pub type ListenerMap = Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>;

struct AgentSvc {
    pod: String,
    metrics: MetricsMap,
}

#[tonic::async_trait]
impl Agent for AgentSvc {
    async fn ping(&self, _req: Request<Empty>) -> Result<Response<AgentInfo>, Status> {
        Ok(Response::new(AgentInfo {
            version: env!("CARGO_PKG_VERSION").into(),
        }))
    }

    async fn stream_metrics(
        &self,
        req: Request<Streaming<Metric>>,
    ) -> Result<Response<Empty>, Status> {
        let mut stream = req.into_inner();
        let tx = {
            let mut m = self.metrics.lock().await;
            m.entry(self.pod.clone())
                .or_insert_with(|| watch::channel(Metric::default()).0)
                .clone()
        };
        while let Some(item) = stream.next().await {
            match item {
                Ok(m) => {
                    let _ = tx.send(m);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Response::new(Empty {}))
    }
}

/// Bind `<run_dir>/agent.sock` and serve the Agent service until shutdown.
pub async fn spawn_listener(
    run_dir: &Path,
    pod: &str,
    metrics: MetricsMap,
    listeners: ListenerMap,
) -> Result<()> {
    std::fs::create_dir_all(run_dir)
        .with_context(|| format!("mkdir {}", run_dir.display()))?;
    let sock = run_dir.join("agent.sock");
    if sock.exists() {
        let _ = std::fs::remove_file(&sock);
    }
    let listener = UnixListener::bind(&sock)
        .with_context(|| format!("bind {}", sock.display()))?;
    // 0660 root:root: the in-pod agent connects as container root; other
    // pod-side processes can't open the socket to spoof metrics. For a
    // userns pod (--private-users) container root is a host SUBUID — the
    // caller must chown_sock_for_userns() once the leader pid is known.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o660))?;

    let (tx, rx) = oneshot::channel::<()>();
    listeners.lock().await.insert(pod.to_string(), tx);
    let pod_name = pod.to_string();
    let sock_path = sock.clone();
    tokio::spawn(async move {
        let svc = AgentSvc {
            pod: pod_name.clone(),
            metrics,
        };
        // Reachable by untrusted in-pod code: cap concurrency. No
        // `timeout` — it's per-request in tonic and would kill the
        // long-lived StreamMetrics stream.
        let _ = Server::builder()
            .concurrency_limit_per_connection(8)
            .max_concurrent_streams(8)
            .add_service(AgentServer::new(svc))
            .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
                let _ = rx.await;
            })
            .await;
        let _ = std::fs::remove_file(&sock_path);
        tracing::info!("agent listener {pod_name} stopped");
    });
    Ok(())
}

/// For a userns pod, re-own `<run_dir>/agent.sock` to the kuid/kgid that
/// container uid/gid 0 map to (first line of the leader's {u,g}id_map) —
/// the socket is root:root 0660 and would otherwise be unreachable for
/// the in-pod agent. Pods on the identity map (private_users=false) map
/// 0→0: nothing to do.
pub fn chown_sock_for_userns(run_dir: &Path, leader: u32) {
    let mapped = |kind: &str| -> Option<u32> {
        let m = std::fs::read_to_string(format!("/proc/{leader}/{kind}_map")).ok()?;
        m.lines().next()?.split_whitespace().nth(1)?.parse().ok()
    };
    let (Some(uid), Some(gid)) = (mapped("uid"), mapped("gid")) else {
        return;
    };
    if uid == 0 {
        return; // identity map — container root IS host root
    }
    let sock = run_dir.join("agent.sock");
    if let Err(e) = std::os::unix::fs::chown(&sock, Some(uid), Some(gid)) {
        tracing::warn!("chown {} for userns pod: {e}", sock.display());
    }
}

/// Tear down a pod's agent listener (stop/destroy) and drop its metrics
/// watch channel — a stopped pod has no live metric source, and dropping
/// the sender cleanly ends any PodMetrics subscribers (changed() → Err).
pub async fn stop_listener(listeners: &ListenerMap, metrics: &MetricsMap, pod: &str) {
    if let Some(tx) = listeners.lock().await.remove(pod) {
        let _ = tx.send(());
    }
    metrics.lock().await.remove(pod);
}

/// Latest metric for a pod, creating the watch pair if absent.
pub async fn latest_rx(metrics: &MetricsMap, pod: &str) -> watch::Receiver<Metric> {
    let mut m = metrics.lock().await;
    m.entry(pod.to_string())
        .or_insert_with(|| watch::channel(Metric::default()).0)
        .subscribe()
}

/// Remove per-pod runtime dirs (run channel + shm host dir).
pub fn cleanup_pod_dirs(run_dir: &Path, shm_host: &Path) {
    let _ = std::fs::remove_dir_all(run_dir);
    let _ = std::fs::remove_dir_all(shm_host);
}

pub fn pod_sock(run_dir: &Path) -> PathBuf {
    run_dir.join("agent.sock")
}
