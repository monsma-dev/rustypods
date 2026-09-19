//! RustyPods Desktop backend — thin IPC bridge: React `invoke()` → gRPC over
//! /run/rustypods/daemon.sock via the shared rustypods-client crate.
//!
//! Commands return the protobuf messages verbatim (serde → camelCase JSON);
//! the frontend decodes them with the ts-proto types generated from the same
//! .proto, so daemon and UI share one contract.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{Emitter, State};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;

use rustypods_client::connect;
use rustypods_proto::rpc::exec_chunk::Kind;
use rustypods_proto::rpc::pod_control_client::PodControlClient;
use rustypods_proto::rpc::*;
use rustypods_proto::SOCKET_PATH;

/// One tokio runtime for the app — Tauri commands spawn gRPC work on it.
struct Rt(tokio::runtime::Runtime);

/// Active PodMetrics subscriptions — pod name → stream task abort handle.
#[derive(Default)]
struct WatchMap(Mutex<HashMap<String, tokio::task::AbortHandle>>);

/// Active StreamLogs subscriptions — same shape as WatchMap, kept as a
/// separate managed state so a metrics watch and a log tail for the same
/// pod don't fight over one slot.
#[derive(Default)]
struct LogWatchMap(Mutex<HashMap<String, tokio::task::AbortHandle>>);

/// One live exec session: `stdin` feeds the bidi stream, `abort` kills the
/// task that owns the outbound stream (and with it the gRPC call).
struct PtySession {
    stdin: mpsc::Sender<ExecChunk>,
    abort: tokio::task::AbortHandle,
}

/// Active exec/PTY sessions keyed by pod name.
type PtyMap = Arc<Mutex<HashMap<String, PtySession>>>;

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
    snap_keep_last: Option<u32>,
    snap_max_age_secs: Option<u64>,
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
                // proto `optional`: absent param (None) = keep current; a
                // real 0 = clear the retention rule.
                snap_keep_last,
                snap_max_age_secs,
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

/// `apply_stack`: raw stack.toml bytes to the daemon — members come back as
/// pods named <stack>-<member> on one shared netns.
#[tauri::command]
async fn apply_stack(rt: State<'_, Rt>, toml: String) -> Result<ApplyStackResponse, String> {
    call(&rt.0, move |mut c| async move {
        c.apply_stack(ApplyStackRequest {
            toml: toml.into_bytes(),
        })
        .await
        .map(|r| r.into_inner())
        .map_err(|e| e.message().to_string())
    })
    .await
}

#[tauri::command]
async fn destroy_stack(rt: State<'_, Rt>, name: String) -> Result<(), String> {
    call(&rt.0, move |mut c| async move {
        c.destroy_stack(PodRef { name })
            .await
            .map(|_| ())
            .map_err(|e| e.message().to_string())
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

/* ---------- log tail (StreamLogs → log-<pod> events) ---------- */

/// Subscribe to a pod's log stream (journal for booted pods, console log
/// otherwise); each LogLine is emitted to the frontend as a `log-<pod>`
/// event with a lossy-UTF8 String payload. Re-subscribing replaces the old
/// task.
#[tauri::command]
async fn watch_logs<R: tauri::Runtime>(
    rt: State<'_, Rt>,
    watches: State<'_, LogWatchMap>,
    app: tauri::AppHandle<R>,
    name: String,
) -> Result<(), String> {
    let pod = name.clone();
    let ev = format!("log-{pod}");
    let task = rt.0.spawn(async move {
        let Ok(mut c) = connect(PathBuf::from(SOCKET_PATH), None).await else {
            return;
        };
        let Ok(mut s) = c
            .stream_logs(PodRef { name: pod })
            .await
            .map(|r| r.into_inner())
        else {
            return;
        };
        while let Ok(Some(l)) = s.message().await {
            if app.emit(&ev, String::from_utf8_lossy(&l.data)).is_err() {
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
async fn unwatch_logs(watches: State<'_, LogWatchMap>, name: String) -> Result<(), String> {
    if let Some(h) = watches.0.lock().unwrap().remove(&name) {
        h.abort();
    }
    Ok(())
}

/* ---------- embedded exec terminal (bidi Exec RPC → pty-* events) ---------- */

/// Open a login-shell exec session for `pod` on a real PTY. Stdout/stderr
/// chunks arrive as `pty-out-<pod>` events (Vec<u8> → JSON int array); the
/// remote exit code lands on `pty-exit-<pod>`. Re-opening replaces any
/// existing session for the pod.
#[tauri::command]
async fn open_pty<R: tauri::Runtime>(
    rt: State<'_, Rt>,
    map: State<'_, PtyMap>,
    app: tauri::AppHandle<R>,
    pod: String,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    if let Some(old) = map.lock().unwrap().remove(&pod) {
        old.abort.abort();
    }
    let (tx, rx) = mpsc::channel::<ExecChunk>(32);
    // Protocol: the first chunk is always ExecStart — empty argv asks the
    // daemon for a login shell, empty user = pod root.
    tx.send(ExecChunk {
        kind: Some(Kind::Start(ExecStart {
            pod: pod.clone(),
            user: String::new(),
            argv: vec![],
            tty: true,
            rows,
            cols,
            env: vec!["TERM=xterm-256color".into(), "COLORTERM=truecolor".into()],
        })),
    })
    .await
    .map_err(|e| e.to_string())?;

    // Connect + exec inside the spawned task: the response stream must be
    // polled on the same tokio runtime that owns the connection (cross-
    // runtime polling of an IO resource panics). Setup errors come back on a
    // oneshot so open_pty still reports "pod not running" to the frontend.
    let (setup_tx, setup_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
    let out_ev = format!("pty-out-{pod}");
    let exit_ev = format!("pty-exit-{pod}");
    let map2 = map.inner().clone();
    let pod2 = pod.clone();
    let task = rt.0.spawn(async move {
        let setup = async {
            let mut c = connect(PathBuf::from(SOCKET_PATH), None)
                .await
                .map_err(|e| format!("{e:#}"))?;
            c.exec(ReceiverStream::new(rx))
                .await
                .map_err(|e| e.message().to_string())
                .map(|r| r.into_inner())
        };
        let mut stream = match setup.await {
            Ok(s) => {
                let _ = setup_tx.send(Ok(()));
                s
            }
            Err(e) => {
                let _ = setup_tx.send(Err(e));
                return;
            }
        };
        loop {
            match stream.message().await {
                Ok(Some(ExecChunk {
                    kind: Some(Kind::Stdout(b) | Kind::Stderr(b)),
                })) => {
                    let _ = app.emit(&out_ev, b);
                }
                Ok(Some(ExecChunk {
                    kind: Some(Kind::Exit(e)),
                })) => {
                    let _ = app.emit(&exit_ev, e.code);
                    break;
                }
                // Stream ended or errored without an exit chunk — tell the
                // frontend so the pane doesn't look alive-but-dead.
                Ok(None) | Err(_) => {
                    let _ = app.emit(&exit_ev, -1);
                    break;
                }
                _ => {}
            }
        }
        map2.lock().unwrap().remove(&pod2);
    });
    match setup_rx.await {
        Ok(Ok(())) => {
            map.lock()
                .unwrap()
                .insert(pod, PtySession { stdin: tx, abort: task.abort_handle() });
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err("pty task died during setup".into()),
    }
}

/// Keystrokes from xterm.js → the pod's PTY stdin. A dead session swallows
/// writes silently — the UI tears itself down on `pty-exit-*` anyway.
#[tauri::command]
async fn write_pty(map: State<'_, PtyMap>, pod: String, data: Vec<u8>) -> Result<(), String> {
    let tx = map.lock().unwrap().get(&pod).map(|s| s.stdin.clone());
    if let Some(tx) = tx {
        let _ = tx
            .send(ExecChunk {
                kind: Some(Kind::Stdin(data)),
            })
            .await;
    }
    Ok(())
}

/// xterm.js resize → TIOCSWINSZ on the pod-side PTY.
#[tauri::command]
async fn resize_pty(map: State<'_, PtyMap>, pod: String, cols: u32, rows: u32) -> Result<(), String> {
    let tx = map.lock().unwrap().get(&pod).map(|s| s.stdin.clone());
    if let Some(tx) = tx {
        let _ = tx
            .send(ExecChunk {
                kind: Some(Kind::Winsize(WinSize { rows, cols })),
            })
            .await;
    }
    Ok(())
}

/// Kill the session task (drops the gRPC stream) and remove it. Dropping the
/// last stdin sender also closes the daemon-side child stdin.
#[tauri::command]
async fn close_pty(map: State<'_, PtyMap>, pod: String) -> Result<(), String> {
    if let Some(s) = map.lock().unwrap().remove(&pod) {
        s.abort.abort();
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
        .manage(LogWatchMap::default())
        .manage(PtyMap::default())
        .invoke_handler(tauri::generate_handler![
            get_pods,
            create_pod,
            start_pod,
            stop_pod,
            destroy_pod,
            update_pod_config,
            apply_stack,
            destroy_stack,
            watch_metrics,
            unwatch_metrics,
            watch_logs,
            unwatch_logs,
            open_pty,
            write_pty,
            resize_pty,
            close_pty,
            get_images,
            get_daemon_info,
        ])
}

pub fn run() {
    app_builder(tauri::Builder::default())
        .run(tauri::generate_context!())
        .expect("error running RustyPods Desktop");
}
