//! RustyPods Desktop backend — thin IPC bridge: React `invoke()` → gRPC over
//! /run/rustypods/daemon.sock via the shared rustypods-client crate.
//!
//! Commands return the protobuf messages verbatim (serde → camelCase JSON);
//! the frontend decodes them with the ts-proto types generated from the same
//! .proto, so daemon and UI share one contract.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::Serialize;
use tauri::{Emitter, State};
use tonic::transport::Channel;

use rustypods_client::connect;
use rustypods_proto::rpc::pod_control_client::PodControlClient;
use rustypods_proto::rpc::*;
use rustypods_proto::SOCKET_PATH;

/// One tokio runtime for the app — Tauri commands spawn gRPC work on it.
struct Rt(tokio::runtime::Runtime);

/// Active PodMetrics subscriptions — pod name → stream task abort handle.
#[derive(Default)]
struct WatchMap(Mutex<HashMap<String, tokio::task::AbortHandle>>);

async fn call<T, F, Fut>(rt: &tokio::runtime::Runtime, f: F) -> Result<T, String>
where
    F: FnOnce(PodControlClient<Channel>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, String>> + Send,
    T: Send + 'static,
{
    rt.spawn(async move {
        let c = connect(PathBuf::from(SOCKET_PATH), None)
            .await
            .map_err(|e| format!("{e:#}"))?;
        f(c).await
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Guarantees `limits` is present so the UI never sees a null submessage.
fn with_limits(mut p: Pod) -> Pod {
    if p.limits.is_none() {
        p.limits = Some(Limits::default());
    }
    p
}

#[tauri::command]
async fn get_pods(rt: State<'_, Rt>) -> Result<Vec<Pod>, String> {
    call(&rt.0, |mut c| async move {
        let l = c
            .list_pods(ListPodsRequest {})
            .await
            .map_err(|e| e.to_string())?
            .into_inner();
        Ok(l.pods.into_iter().map(with_limits).collect())
    })
    .await
}

#[tauri::command]
async fn start_pod(rt: State<'_, Rt>, name: String) -> Result<Pod, String> {
    call(&rt.0, |mut c| async move {
        let p = c
            .start_pod(StartPodRequest {
                name,
                limits: None,
                ephemeral: false,
                private_users: None,
            })
            .await
            .map_err(|e| e.message().to_string())?
            .into_inner();
        Ok(with_limits(p))
    })
    .await
}

#[tauri::command]
async fn stop_pod(rt: State<'_, Rt>, name: String) -> Result<Pod, String> {
    call(&rt.0, |mut c| async move {
        let p = c
            .stop_pod(PodRef { name })
            .await
            .map_err(|e| e.message().to_string())?
            .into_inner();
        Ok(with_limits(p))
    })
    .await
}

#[tauri::command]
async fn destroy_pod(rt: State<'_, Rt>, name: String) -> Result<(), String> {
    call(&rt.0, |mut c| async move {
        c.destroy_pod(PodRef { name })
            .await
            .map(|_| ())
            .map_err(|e| e.message().to_string())
    })
    .await
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn update_pod_config(
    rt: State<'_, Rt>,
    name: String,
    memory_high_bytes: u64,
    memory_max_bytes: u64,
    cpu_quota_percent: u32,
    storage_max_bytes: u64,
    ports: Option<Vec<String>>,
) -> Result<Pod, String> {
    call(&rt.0, move |mut c| async move {
        let p = c
            .update_pod_config(UpdatePodConfigRequest {
                name,
                limits: Some(Limits {
                    memory_high_bytes,
                    memory_max_bytes,
                    cpu_quota_percent,
                }),
                storage_max_bytes,
                ports: ports.map(|ports| PortMappings { ports }),
                binds: None,
            })
            .await
            .map_err(|e| e.message().to_string())?
            .into_inner();
        Ok(with_limits(p))
    })
    .await
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn create_pod(
    rt: State<'_, Rt>,
    name: String,
    image: String,
    memory_high_bytes: u64,
    memory_max_bytes: u64,
    cpu_quota_percent: u32,
    storage_max_bytes: u64,
    ports: Vec<String>,
    binds: Vec<String>,
    desktop: bool,
) -> Result<Pod, String> {
    call(&rt.0, move |mut c| async move {
        // Same convention as update_pod_config: limits are flattened to
        // scalars on the IPC boundary; all-zero means "no guardrails" →
        // leave the submessage absent.
        let limits = (memory_high_bytes > 0 || memory_max_bytes > 0 || cpu_quota_percent > 0)
            .then_some(Limits {
                memory_high_bytes,
                memory_max_bytes,
                cpu_quota_percent,
            });
        let p = c
            .create_pod(CreatePodRequest {
                name,
                image,
                storage_max_bytes,
                ports,
                desktop,
                binds,
                limits,
            })
            .await
            .map_err(|e| e.message().to_string())?
            .into_inner();
        Ok(with_limits(p))
    })
    .await
}

#[tauri::command]
async fn get_images(rt: State<'_, Rt>) -> Result<Vec<Image>, String> {
    call(&rt.0, |mut c| async move {
        let l = c
            .list_images(ListImagesRequest {})
            .await
            .map_err(|e| e.to_string())?
            .into_inner();
        Ok(l.images)
    })
    .await
}

/// `pod-metrics` event payload: the agent's Metric sample, flattened, plus
/// the pod name it belongs to so one listener can fan out to every row.
#[derive(Serialize, Clone)]
struct MetricEvent {
    pod: String,
    #[serde(flatten)]
    metric: Metric,
}

/// Subscribe to a pod's live metric stream; each sample is emitted to the
/// frontend as a `pod-metrics` event. Re-subscribing replaces the old task.
#[tauri::command]
async fn watch_metrics<R: tauri::Runtime>(
    rt: State<'_, Rt>,
    watches: State<'_, WatchMap>,
    app: tauri::AppHandle<R>,
    name: String,
) -> Result<(), String> {
    let pod = name.clone();
    let task = rt.0.spawn(async move {
        let Ok(mut c) = connect(PathBuf::from(SOCKET_PATH), None).await else {
            return;
        };
        let Ok(mut s) = c
            .pod_metrics(PodRef {
                name: pod.clone(),
            })
            .await
            .map(|r| r.into_inner())
        else {
            return;
        };
        while let Ok(Some(m)) = s.message().await {
            let ev = MetricEvent {
                pod: pod.clone(),
                metric: m,
            };
            if app.emit("pod-metrics", ev).is_err() {
                break;
            }
        }
    });
    let mut w = watches.0.lock().unwrap();
    if let Some(old) = w.insert(name, task.abort_handle()) {
        old.abort();
    }
    Ok(())
}

#[tauri::command]
async fn unwatch_metrics(watches: State<'_, WatchMap>, name: String) -> Result<(), String> {
    if let Some(h) = watches.0.lock().unwrap().remove(&name) {
        h.abort();
    }
    Ok(())
}

#[tauri::command]
async fn get_daemon_info(rt: State<'_, Rt>) -> Result<DaemonInfo, String> {
    call(&rt.0, |mut c| async move {
        c.ping(PingRequest {})
            .await
            .map(|r| r.into_inner())
            .map_err(|e| e.to_string())
    })
    .await
}

/// Shared builder wiring — used by the desktop entry point and the IPC tests.
pub fn app_builder<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    builder
        .manage(Rt(rt))
        .manage(WatchMap::default())
        .invoke_handler(tauri::generate_handler![
            get_pods,
            create_pod,
            start_pod,
            stop_pod,
            destroy_pod,
            update_pod_config,
            watch_metrics,
            unwatch_metrics,
            get_images,
            get_daemon_info,
        ])
}

pub fn run() {
    app_builder(tauri::Builder::default())
        .run(tauri::generate_context!())
        .expect("error running RustyPods Desktop");
}
