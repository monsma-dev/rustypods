//! RustyPods Desktop backend — thin IPC bridge: React `invoke()` → gRPC over
//! /run/rustypods/daemon.sock via the shared rustypods-client crate.

use std::future::Future;
use std::path::PathBuf;

use serde::Serialize;
use tauri::State;
use tonic::transport::Channel;

use rustypods_client::connect;
use rustypods_proto::rpc::pod_control_client::PodControlClient;
use rustypods_proto::rpc::*;
use rustypods_proto::{fmt_bytes, SOCKET_PATH};

/// One tokio runtime for the app — Tauri commands spawn gRPC work on it.
struct Rt(tokio::runtime::Runtime);

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

fn state_name(p: &Pod) -> &'static str {
    match PodState::try_from(p.state) {
        Ok(PodState::Running) => "running",
        Ok(PodState::Stopped) => "stopped",
        Ok(PodState::Failed) => "failed",
        _ => "created",
    }
}

#[derive(Serialize)]
struct PodInfo {
    name: String,
    image: String,
    state: &'static str,
    leader_pid: u32,
    created_unix: u64,
    memory_high: String,
    memory_max: String,
    memory_high_bytes: u64,
    memory_max_bytes: u64,
    cpu_quota_percent: u32,
    storage_max: String,
    storage_max_bytes: u64,
    ports: Vec<String>,
    stack: String,
    ephemeral: bool,
}

fn to_info(p: Pod) -> PodInfo {
    let state = state_name(&p);
    let lim = p.limits.unwrap_or_default();
    PodInfo {
        name: p.name,
        image: p.image,
        state,
        leader_pid: p.leader_pid,
        created_unix: p.created_unix,
        memory_high: fmt_bytes(lim.memory_high_bytes),
        memory_max: fmt_bytes(lim.memory_max_bytes),
        memory_high_bytes: lim.memory_high_bytes,
        memory_max_bytes: lim.memory_max_bytes,
        cpu_quota_percent: lim.cpu_quota_percent,
        storage_max: fmt_bytes(p.storage_max_bytes),
        storage_max_bytes: p.storage_max_bytes,
        ports: p.ports,
        stack: p.stack,
        ephemeral: p.ephemeral,
    }
}

#[tauri::command]
async fn get_pods(rt: State<'_, Rt>) -> Result<Vec<PodInfo>, String> {
    call(&rt.0, |mut c| async move {
        let l = c
            .list_pods(ListPodsRequest {})
            .await
            .map_err(|e| e.to_string())?
            .into_inner();
        Ok(l.pods.into_iter().map(to_info).collect())
    })
    .await
}

#[tauri::command]
async fn start_pod(rt: State<'_, Rt>, name: String) -> Result<PodInfo, String> {
    call(&rt.0, |mut c| async move {
        let p = c
            .start_pod(StartPodRequest {
                name,
                limits: None,
                ephemeral: false,
                private_users: false,
            })
            .await
            .map_err(|e| e.message().to_string())?
            .into_inner();
        Ok(to_info(p))
    })
    .await
}

#[tauri::command]
async fn stop_pod(rt: State<'_, Rt>, name: String) -> Result<PodInfo, String> {
    call(&rt.0, |mut c| async move {
        let p = c
            .stop_pod(PodRef { name })
            .await
            .map_err(|e| e.message().to_string())?
            .into_inner();
        Ok(to_info(p))
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
) -> Result<PodInfo, String> {
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
            })
            .await
            .map_err(|e| e.message().to_string())?
            .into_inner();
        Ok(to_info(p))
    })
    .await
}

#[derive(Serialize)]
struct ImageInfo {
    name: String,
    path: String,
    source: String,
    created_unix: u64,
}

#[tauri::command]
async fn get_images(rt: State<'_, Rt>) -> Result<Vec<ImageInfo>, String> {
    call(&rt.0, |mut c| async move {
        let l = c
            .list_images(ListImagesRequest {})
            .await
            .map_err(|e| e.to_string())?
            .into_inner();
        Ok(l.images
            .into_iter()
            .map(|i| ImageInfo {
                name: i.name,
                path: i.path,
                source: i.source,
                created_unix: i.created_unix,
            })
            .collect())
    })
    .await
}

#[derive(Serialize)]
struct DaemonStatus {
    version: String,
    socket_path: String,
    data_dir: String,
    machined: bool,
    storage_driver: String,
    runtime_engine: String,
}

#[tauri::command]
async fn get_daemon_info(rt: State<'_, Rt>) -> Result<DaemonStatus, String> {
    call(&rt.0, |mut c| async move {
        let i = c
            .ping(PingRequest {})
            .await
            .map_err(|e| e.to_string())?
            .into_inner();
        Ok(DaemonStatus {
            version: i.version,
            socket_path: i.socket_path,
            data_dir: i.data_dir,
            machined: i.machined,
            storage_driver: i.storage_driver,
            runtime_engine: i.runtime_engine,
        })
    })
    .await
}

/// Shared builder wiring — used by the desktop entry point and the IPC tests.
pub fn app_builder<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    builder.manage(Rt(rt)).invoke_handler(tauri::generate_handler![
        get_pods,
        start_pod,
        stop_pod,
        update_pod_config,
        get_images,
        get_daemon_info,
    ])
}

pub fn run() {
    app_builder(tauri::Builder::default())
        .run(tauri::generate_context!())
        .expect("error running RustyPods Desktop");
}
