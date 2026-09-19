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
    // Pod-side processes must be able to connect: world-writable socket on a
    // daemon-owned dir (single-user box; peer is by definition this pod).
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666))?;

    let (tx, rx) = oneshot::channel::<()>();
    listeners.lock().await.insert(pod.to_string(), tx);
    let pod_name = pod.to_string();
    let sock_path = sock.clone();
    tokio::spawn(async move {
        let svc = AgentSvc {
            pod: pod_name.clone(),
            metrics,
        };
        let _ = Server::builder()
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

/// Tear down a pod's agent listener (stop/destroy).
pub async fn stop_listener(listeners: &ListenerMap, pod: &str) {
    if let Some(tx) = listeners.lock().await.remove(pod) {
        let _ = tx.send(());
    }
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
