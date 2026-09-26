//! REST/JSON facade over the gRPC control plane — the same PodControl
//! methods the CLI uses, exposed for automation and agents. Proto types
//! serialize camelCase, so responses match the protobuf field names.
//!
//! **Bearer-token auth.** Every `/v1/*` request needs
//! `Authorization: Bearer <token>`. The read-write token lives in
//! `<socket-dir>/http-token` and a second read-only token in
//! `http-token-ro` (both mode 0400, owned by the allowed uid). They are
//! created once and reused across restarts (the unit sets
//! `RuntimeDirectoryPreserve=yes`; /run is tmpfs, so a reboot still mints
//! new ones); `RUSTYPODS_HTTP_TOKEN_ROTATE=1` rotates on demand. The read-only token may only call GET. Requests carrying
//! `Origin` or `Sec-Fetch-Site` are rejected — browsers have no business
//! here. `/healthz` stays open and reports whether daemon state can be
//! locked. The bind is loopback-only unless `RUSTYPODS_HTTP_INSECURE=1`;
//! that flag is not a supported remote path (use SSH `-L` or gRPC
//! `--remote`). JSON bodies are capped at 1 MiB. `POST /v1/import` streams
//! up to `RUSTYPODS_IMPORT_MAX_BYTES` (default 64 GiB).

use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Extension, Path, Query, Request as AxumRequest, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;
use tonic::{Request, Status};

use rustypods_proto::rpc::pod_control_server::PodControl;
use rustypods_proto::rpc::*;

use crate::server::Svc;

type ApiErr = (StatusCode, Json<serde_json::Value>);

fn api_err(s: Status) -> ApiErr {
    let code = match s.code() {
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::AlreadyExists => StatusCode::CONFLICT,
        tonic::Code::FailedPrecondition => StatusCode::PRECONDITION_FAILED,
        tonic::Code::ResourceExhausted => StatusCode::PAYLOAD_TOO_LARGE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, Json(serde_json::json!({ "error": s.message() })))
}

/// Buffered JSON/text bodies (create, patch, exec, stack.toml).
pub const JSON_BODY_MAX: usize = 1 << 20;
/// Non-streaming handlers. Exec is capped by its own timeout (≤900s).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const EXEC_REQUEST_TIMEOUT: Duration = Duration::from_secs(910);
/// Slowloris: drop a connection that hasn't finished its headers.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Matches the gRPC server's global in-flight cap.
pub const MAX_CONNECTIONS: usize = 256;
/// Read-write plus optional read-only bearer tokens.
#[derive(Clone)]
pub struct HttpAuth {
    pub rw: Arc<str>,
    pub ro: Arc<str>,
}

/// `RUSTYPODS_IMPORT_MAX_BYTES`, default 64 GiB. Same parse as the
/// transfer path: unset keeps the default, anything else must be a
/// positive integer byte count.
pub fn import_max_bytes() -> anyhow::Result<u64> {
    crate::transfer::import_max_bytes()
}

/// `POST /v1/pods` body — local request struct (proto types are
/// Serialize-only; Deserialize here would fight the prost codegen).
#[derive(Deserialize)]
struct CreatePodIn {
    name: String,
    image: String,
    memory_high_bytes: Option<u64>,
    memory_max_bytes: Option<u64>,
    cpu_quota_percent: Option<u32>,
    #[serde(default)]
    storage_max_bytes: u64,
    #[serde(default)]
    ports: Vec<String>,
    #[serde(default)]
    desktop: bool,
    #[serde(default)]
    binds: Vec<String>,
    #[serde(default)]
    autostart: bool,
    /// Payload override argv; replaces the image entrypoint+cmd.
    #[serde(default)]
    cmd: Option<Vec<String>>,
    /// "<host>.rustypods.localhost:<port>" ingress rules.
    #[serde(default)]
    ingress: Vec<String>,
    /// Restart policy: "no" (default) | "on-failure" | "always".
    #[serde(default)]
    restart: Option<String>,
    /// Liveness probe spec (see rpc::HealthCheck).
    #[serde(default)]
    healthcheck: Option<HealthCheck>,
    /// Pod-level env "KEY=value", merged over the image env at start.
    #[serde(default)]
    env: Vec<String>,
    /// Named-volume mounts "name:/pod/path[:ro]"; auto-created on first
    /// use, outlive the pod.
    #[serde(default)]
    volumes: Vec<String>,
}

/// `PATCH /v1/pods/:name` body — absent fields keep their current values.
#[derive(Deserialize)]
struct UpdatePodIn {
    memory_high_bytes: Option<u64>,
    memory_max_bytes: Option<u64>,
    cpu_quota_percent: Option<u32>,
    storage_max_bytes: Option<u64>,
    /// Absent = keep current mappings; present (even []) replaces them.
    ports: Option<Vec<String>>,
    /// Absent = keep current binds; present (even []) replaces them.
    binds: Option<Vec<String>>,
    snap_keep_last: Option<u32>,
    snap_max_age_secs: Option<u64>,
    /// Absent = keep; true/false sets the boot-time autostart flag.
    autostart: Option<bool>,
    /// Absent = keep; present (even []) replaces the payload override.
    cmd: Option<Vec<String>>,
    /// Absent = keep current rules; present (even []) replaces them.
    /// The pod must be stopped to change ingress.
    ingress: Option<Vec<String>>,
    /// Absent = keep; present replaces the restart policy.
    restart: Option<String>,
    /// Absent = keep; present replaces the probe (empty kind = off).
    healthcheck: Option<HealthCheck>,
    /// Absent = keep; present (even []) replaces pod env. Next start.
    env: Option<Vec<String>>,
    /// Absent = keep; present (even []) replaces volume mounts.
    /// Next start.
    volumes: Option<Vec<String>>,
}

fn parse_ingress(specs: &[String]) -> Result<Vec<IngressRule>, ApiErr> {
    specs
        .iter()
        .map(|s| rustypods_proto::parse_ingress_rule(s))
        .collect::<anyhow::Result<_>>()
        .map_err(|e| api_err(Status::invalid_argument(format!("{e:#}"))))
}

/// Unauthenticated and minimal: only whether the daemon can take its state
/// lock quickly. A stuck lock (or a wedged runtime) is not "ok".
async fn healthz(State(s): State<Svc>) -> Response {
    if s.http_ready().await {
        (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "ok": false })),
        )
            .into_response()
    }
}

async fn daemon_info(State(s): State<Svc>) -> Result<Json<DaemonInfo>, ApiErr> {
    s.ping(Request::new(PingRequest {}))
        .await
        .map(|r| Json(r.into_inner()))
        .map_err(api_err)
}

async fn list_pods(State(s): State<Svc>) -> Result<Json<PodList>, ApiErr> {
    s.list_pods(Request::new(ListPodsRequest {}))
        .await
        .map(|r| Json(r.into_inner()))
        .map_err(api_err)
}

async fn list_images(State(s): State<Svc>) -> Result<Json<ImageList>, ApiErr> {
    s.list_images(Request::new(ListImagesRequest {}))
        .await
        .map(|r| Json(r.into_inner()))
        .map_err(api_err)
}

async fn create_pod(
    State(s): State<Svc>,
    Json(b): Json<CreatePodIn>,
) -> Result<(StatusCode, Json<Pod>), ApiErr> {
    let limits = Limits {
        memory_high_bytes: b.memory_high_bytes.unwrap_or(0),
        memory_max_bytes: b.memory_max_bytes.unwrap_or(0),
        cpu_quota_percent: b.cpu_quota_percent.unwrap_or(0),
    };
    let has_limits =
        limits.memory_high_bytes > 0 || limits.memory_max_bytes > 0 || limits.cpu_quota_percent > 0;
    let p = s
        .create_pod(Request::new(CreatePodRequest {
            name: b.name,
            image: b.image,
            storage_max_bytes: b.storage_max_bytes,
            ports: b.ports,
            desktop: b.desktop,
            binds: b.binds,
            limits: has_limits.then_some(limits),
            autostart: b.autostart,
            cmd: b.cmd.unwrap_or_default(),
            ingress: parse_ingress(&b.ingress)?,
            restart: b.restart.unwrap_or_default(),
            healthcheck: b.healthcheck,
            env: b.env,
            volumes: b.volumes,
            stop_timeout_secs: 0,
        }))
        .await
        .map_err(api_err)?
        .into_inner();
    Ok((StatusCode::CREATED, Json(p)))
}

async fn start_pod(State(s): State<Svc>, Path(name): Path<String>) -> Result<Json<Pod>, ApiErr> {
    s.start_pod(Request::new(StartPodRequest {
        name,
        limits: None,
        ephemeral: false,
        private_users: None,
    }))
    .await
    .map(|r| Json(r.into_inner()))
    .map_err(api_err)
}

async fn stop_pod(State(s): State<Svc>, Path(name): Path<String>) -> Result<Json<Pod>, ApiErr> {
    s.stop_pod(Request::new(PodRef { name }))
        .await
        .map(|r| Json(r.into_inner()))
        .map_err(api_err)
}

async fn destroy_pod(State(s): State<Svc>, Path(name): Path<String>) -> Result<StatusCode, ApiErr> {
    s.destroy_pod(Request::new(PodRef { name }))
        .await
        .map_err(api_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn update_pod(
    State(s): State<Svc>,
    Path(name): Path<String>,
    Json(b): Json<UpdatePodIn>,
) -> Result<Json<Pod>, ApiErr> {
    // Merge under the per-pod op lock. Reading via list_pods and then
    // calling update_pod_config let two PATCHes each snapshot the same
    // pod and the later write drop the earlier field change.
    let _op = s.pod_op(&name).await;
    let (cur_lim, storage_max) = s
        .pod_limit_snapshot(&name)
        .await
        .ok_or_else(|| api_err(Status::not_found(format!("pod {name} not found"))))?;
    let p = s
        .apply_pod_config(UpdatePodConfigRequest {
            name,
            limits: Some(Limits {
                memory_high_bytes: b.memory_high_bytes.unwrap_or(cur_lim.memory_high_bytes),
                memory_max_bytes: b.memory_max_bytes.unwrap_or(cur_lim.memory_max_bytes),
                cpu_quota_percent: b.cpu_quota_percent.unwrap_or(cur_lim.cpu_quota_percent),
            }),
            storage_max_bytes: b.storage_max_bytes.unwrap_or(storage_max),
            ports: b.ports.map(|ports| PortMappings { ports }),
            binds: b.binds.map(|binds| BindList { binds }),
            snap_keep_last: b.snap_keep_last,
            snap_max_age_secs: b.snap_max_age_secs,
            autostart: b.autostart,
            cmd: b.cmd.map(|argv| CmdList { argv }),
            ingress: b
                .ingress
                .as_deref()
                .map(parse_ingress)
                .transpose()?
                .map(|rules| IngressList { rules }),
            restart: b.restart,
            healthcheck: b.healthcheck,
            env: b.env.map(|entries| EnvList { entries }),
            volumes: b.volumes.map(|specs| VolumeList { specs }),
            stop_timeout_secs: None,
        })
        .await
        .map_err(api_err)?;
    Ok(Json(p))
}

/// Latest agent-pushed metric; 404 while the pod has none (agent-less pods).
async fn pod_metrics(
    State(s): State<Svc>,
    Path(name): Path<String>,
) -> Result<Json<Metric>, ApiErr> {
    s.latest_metric(&name)
        .await
        .map(Json)
        .ok_or_else(|| api_err(Status::not_found(format!("no metrics for pod {name}"))))
}

/// `GET /v1/pods/:name` — single-pod detail for agents (same view as
/// the gRPC Pod message).
async fn get_pod(State(s): State<Svc>, Path(name): Path<String>) -> Result<Json<Pod>, ApiErr> {
    let p = s
        .list_pods(Request::new(ListPodsRequest {}))
        .await
        .map_err(api_err)?
        .into_inner()
        .pods
        .into_iter()
        .find(|p| p.name == name)
        .ok_or_else(|| api_err(Status::not_found(format!("pod {name} not found"))))?;
    Ok(Json(p))
}

/// `GET /v1/pods/:name/logs?lines=N` — last N lines as a JSON array:
/// journal for boot pods, the console log otherwise (same source
/// selection as the gRPC log stream). Default 200, capped at 5000.
#[derive(Deserialize)]
struct LogsQuery {
    lines: Option<u32>,
}

async fn pod_logs(
    State(s): State<Svc>,
    Path(name): Path<String>,
    Query(q): Query<LogsQuery>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    let lines = q.lines.unwrap_or(200).min(5000);
    let out = s.pod_log_tail(&name, lines).await.map_err(api_err)?;
    Ok(Json(serde_json::json!({
        "name": name,
        "lines": out.lines,
        "truncated": out.truncated,
    })))
}

/// `GET /v1/pods/:name/stats` — live cgroup-v2 snapshot read straight
/// from /sys/fs/cgroup/machine.slice/<scope>/ (no agent needed).
#[derive(Serialize)]
struct StatsOut {
    unit: String,
    cpu_usage_us: u64,
    mem_bytes: u64,
    mem_peak_bytes: Option<u64>,
    pids: u64,
}

fn read_u64(path: &std::path::Path) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn read_cgroup_stats(unit: &str) -> Option<StatsOut> {
    let dir = std::path::Path::new("/sys/fs/cgroup/machine.slice").join(unit);
    let mem_bytes = read_u64(&dir.join("memory.current"))?;
    let cpu_usage_us = std::fs::read_to_string(dir.join("cpu.stat"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("usage_usec "))
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0);
    Some(StatsOut {
        unit: unit.to_string(),
        cpu_usage_us,
        mem_bytes,
        mem_peak_bytes: read_u64(&dir.join("memory.peak")),
        pids: read_u64(&dir.join("pids.current")).unwrap_or(0),
    })
}

async fn pod_stats(
    State(s): State<Svc>,
    Path(name): Path<String>,
) -> Result<Json<StatsOut>, ApiErr> {
    if !s.pod_exists(&name).await {
        return Err(api_err(Status::not_found(format!("pod {name} not found"))));
    }
    let Some(unit) = s.pod_scope(&name).await else {
        return Err(api_err(Status::failed_precondition(format!(
            "pod {name} is not running"
        ))));
    };
    let stats = tokio::task::spawn_blocking(move || read_cgroup_stats(&unit))
        .await
        .map_err(|e| api_err(Status::internal(format!("{e}"))))?
        .ok_or_else(|| api_err(Status::internal("cgroup scope not readable")))?;
    Ok(Json(stats))
}

/// `POST /v1/pods/:name/exec` — run a non-tty command in the pod and
/// return captured output. The agent-facing alternative to the gRPC
/// bidi stream: one request, one response.
#[derive(Deserialize)]
struct ExecIn {
    /// Argv, e.g. ["sh","-c","ls -la /data"]. Required — there is no
    /// interactive login shell over REST.
    cmd: Vec<String>,
    /// Container user; empty/absent = root.
    #[serde(default)]
    user: Option<String>,
    /// Absolute in-container cwd; absent = $HOME/inherited.
    #[serde(default)]
    workdir: Option<String>,
    /// Extra "K=V" env for the payload.
    #[serde(default)]
    env: Option<Vec<String>>,
    /// Wall-clock cap in seconds (default 60, max 900). On timeout the
    /// payload is killed and partial output returns with timed_out.
    #[serde(default)]
    timeout_secs: Option<u64>,
}

#[derive(Serialize)]
struct ExecOut {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    timed_out: bool,
    truncated: bool,
}

async fn pod_exec(
    State(s): State<Svc>,
    Path(name): Path<String>,
    Json(b): Json<ExecIn>,
) -> Result<Json<ExecOut>, ApiErr> {
    if b.cmd.is_empty() {
        return Err(api_err(Status::invalid_argument(
            "cmd must be a non-empty argv (e.g. [\"sh\",\"-c\",\"...\"])",
        )));
    }
    let timeout_secs = b.timeout_secs.unwrap_or(60).clamp(1, 900);
    let start = ExecStart {
        pod: name,
        user: b.user.unwrap_or_default(),
        argv: b.cmd,
        tty: false,
        rows: 0,
        cols: 0,
        env: b.env.unwrap_or_default(),
        workdir: b.workdir.unwrap_or_default(),
    };
    let out = s
        .exec_collect(start, 4 << 20, std::time::Duration::from_secs(timeout_secs))
        .await
        .map_err(api_err)?;
    Ok(Json(ExecOut {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        exit_code: out.exit_code,
        timed_out: out.timed_out,
        truncated: out.truncated,
    }))
}

/// `GET /v1/pods/:name/export?format=tar&allow_inconsistent=true`
async fn export_pod_http(
    State(s): State<Svc>,
    Path(name): Path<String>,
    Query(q): Query<ExportQuery>,
) -> Result<Response, ApiErr> {
    let stream = s
        .export_archive(
            &name,
            q.format.as_deref().unwrap_or(""),
            q.allow_inconsistent.unwrap_or(false),
        )
        .await
        .map_err(api_err)?;
    let warn_name = name.clone();
    let bytes = stream.map(move |c| {
        c.map(|c| {
            if !c.warning.is_empty() {
                tracing::warn!("export {warn_name}: {}", c.warning);
            }
            Bytes::from(c.data)
        })
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{name}.rpod\""),
        )
        .body(Body::from_stream(bytes))
        .map_err(|e| api_err(Status::internal(format!("{e}"))))
}

/// `POST /v1/import?name=<rename>&trust=true` — upload an archive.
/// Without `trust=true` host-root grants in the pod conf are stripped.
#[derive(Deserialize)]
struct ExportQuery {
    format: Option<String>,
    allow_inconsistent: Option<bool>,
}

#[derive(Deserialize)]
struct ImportQuery {
    name: Option<String>,
    trust: Option<bool>,
}

async fn import_pod_http(
    State(s): State<Svc>,
    Extension(max): Extension<u64>,
    Query(q): Query<ImportQuery>,
    req: AxumRequest,
) -> Result<Json<Pod>, ApiErr> {
    use rustypods_proto::rpc::import_chunk::Kind;
    if let Some(len) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        if len > max {
            return Err(api_err(Status::resource_exhausted(format!(
                "import body {len} bytes exceeds limit {max}"
            ))));
        }
    }
    let rename = q.name.filter(|n| !n.is_empty());
    let trust = q.trust.unwrap_or(false);
    let options = if rename.is_some() || trust {
        Some(ImportChunk {
            kind: Some(Kind::Options(ImportOptions {
                rename: rename.unwrap_or_default(),
                trust,
            })),
        })
    } else {
        None
    };
    let mut seen = 0u64;
    let data = req.into_body().into_data_stream().map(move |b| {
        b.map_err(|e| Status::internal(format!("body read: {e}")))
            .and_then(|b| {
                seen = seen.saturating_add(b.len() as u64);
                if seen > max {
                    Err(Status::resource_exhausted(format!(
                        "import body exceeds limit {max} bytes"
                    )))
                } else {
                    Ok(ImportChunk {
                        kind: Some(Kind::Data(b.to_vec())),
                    })
                }
            })
    });
    let stream = tokio_stream::iter(options.map(Ok::<_, Status>)).chain(data);
    let pod = s.import_archive(stream).await.map_err(api_err)?;
    Ok(Json(pod))
}

/// Raw stack.toml as the body (application/toml or plain text).
async fn apply_stack(
    State(s): State<Svc>,
    body: Bytes,
) -> Result<Json<ApplyStackResponse>, ApiErr> {
    s.apply_stack(Request::new(ApplyStackRequest {
        toml: body.to_vec(),
    }))
    .await
    .map(|r| Json(r.into_inner()))
    .map_err(api_err)
}

async fn destroy_stack(
    State(s): State<Svc>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiErr> {
    s.destroy_stack(Request::new(PodRef { name }))
        .await
        .map_err(api_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/volumes` body.
#[derive(Deserialize)]
struct CreateVolumeIn {
    name: String,
}

async fn create_volume(
    State(s): State<Svc>,
    Json(b): Json<CreateVolumeIn>,
) -> Result<(StatusCode, Json<VolumeInfo>), ApiErr> {
    s.create_volume(Request::new(VolumeRef { name: b.name }))
        .await
        .map(|r| (StatusCode::CREATED, Json(r.into_inner())))
        .map_err(api_err)
}

async fn list_volumes(State(s): State<Svc>) -> Result<Json<VolumeInfoList>, ApiErr> {
    s.list_volumes(Request::new(Empty {}))
        .await
        .map(|r| Json(r.into_inner()))
        .map_err(api_err)
}

async fn remove_volume(
    State(s): State<Svc>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiErr> {
    s.remove_volume(Request::new(VolumeRef { name }))
        .await
        .map_err(api_err)?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Multi-host mesh (Wave I/J) ---

/// `POST /v1/mesh/init?listen_port=N&token=…` — empty body, both optional.
#[derive(Deserialize, Default)]
struct MeshInitIn {
    #[serde(default)]
    listen_port: u32,
    #[serde(default)]
    token: String,
}

async fn mesh_status_http(State(s): State<Svc>) -> Result<Json<MeshStatus>, ApiErr> {
    let mut st = s
        .get_mesh_status(Request::new(Empty {}))
        .await
        .map(|r| r.into_inner())
        .map_err(api_err)?;
    // The cluster token unlocks the full PodControl API on every peer —
    // it must never ride the (possibly read-only) REST channel.
    st.cluster_token.clear();
    Ok(Json(st))
}

async fn mesh_init_http(
    State(s): State<Svc>,
    Query(q): Query<MeshInitIn>,
) -> Result<Json<MeshStatus>, ApiErr> {
    s.mesh_init(Request::new(MeshInitRequest {
        listen_port: q.listen_port,
        token: q.token,
    }))
    .await
    .map(|r| Json(r.into_inner()))
    .map_err(api_err)
}

async fn mesh_deinit_http(State(s): State<Svc>) -> Result<Json<MeshStatus>, ApiErr> {
    s.mesh_deinit(Request::new(Empty {}))
        .await
        .map(|r| Json(r.into_inner()))
        .map_err(api_err)
}

/// `POST /v1/mesh/peers` body — proto types don't derive Deserialize.
#[derive(Deserialize)]
struct MeshPeerIn {
    endpoint: String,
    pubkey: String,
    #[serde(default)]
    name: String,
}

async fn mesh_add_peer_http(
    State(s): State<Svc>,
    Json(b): Json<MeshPeerIn>,
) -> Result<Json<MeshStatus>, ApiErr> {
    s.mesh_add_peer(Request::new(MeshPeer {
        endpoint: b.endpoint,
        pubkey: b.pubkey,
        name: b.name,
    }))
    .await
    .map(|r| Json(r.into_inner()))
    .map_err(api_err)
}

/// `DELETE /v1/mesh/peers/*pubkey` — wildcard because raw base64 may
/// contain `/`.
async fn mesh_rm_peer_http(
    State(s): State<Svc>,
    Path(pubkey): Path<String>,
) -> Result<Json<MeshStatus>, ApiErr> {
    s.mesh_remove_peer(Request::new(MeshPeer {
        endpoint: String::new(),
        pubkey,
        name: String::new(),
    }))
    .await
    .map(|r| Json(r.into_inner()))
    .map_err(api_err)
}

/// Constant-time equality. Length is part of the compare so a short
/// guess doesn't return early; both sides are hashed to a fixed width
/// first so the loop count doesn't depend on the attacker-controlled
/// input length.
pub(crate) fn token_eq(presented: &str, expected: &str) -> bool {
    use sha2::{Digest, Sha256};
    let a = Sha256::digest(presented.as_bytes());
    let b = Sha256::digest(expected.as_bytes());
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Bearer auth + browser-header rejection for /v1/*.
///
/// 1. `Origin` or `Sec-Fetch-Site` → 403.
/// 2. Read-write token → any method. Read-only token → GET only.
/// 3. Anything else → 401.
///
/// Both tokens are always compared so a match on the first doesn't
/// skip the second.
async fn require_token(
    State(auth): State<HttpAuth>,
    req: AxumRequest,
    next: Next,
) -> Result<Response, StatusCode> {
    let h = req.headers();
    if h.contains_key(header::ORIGIN) || h.contains_key("sec-fetch-site") {
        return Err(StatusCode::FORBIDDEN);
    }
    let presented = bearer(h).unwrap_or("");
    let rw = token_eq(presented, &auth.rw);
    let ro = token_eq(presented, &auth.ro);
    if rw {
        return Ok(next.run(req).await);
    }
    if ro && req.method() == axum::http::Method::GET {
        return Ok(next.run(req).await);
    }
    if ro {
        return Err(StatusCode::FORBIDDEN);
    }
    Err(StatusCode::UNAUTHORIZED)
}

/// Streaming transfers aren't bound by the 60s handler timeout — an
/// archive or a log tail can legitimately run longer. Exec keeps its
/// own ≤900s cap; the HTTP deadline sits just above that.
fn request_budget(path: &str) -> Option<Duration> {
    if path.ends_with("/export") || path.ends_with("/logs") || path == "/v1/import" {
        None
    } else if path.ends_with("/exec") {
        Some(EXEC_REQUEST_TIMEOUT)
    } else {
        Some(REQUEST_TIMEOUT)
    }
}

async fn limit_request_time(req: AxumRequest, next: Next) -> Response {
    let budget = request_budget(req.uri().path());
    match budget {
        None => next.run(req).await,
        Some(d) => match tokio::time::timeout(d, next.run(req)).await {
            Ok(r) => r,
            Err(_) => (
                StatusCode::REQUEST_TIMEOUT,
                Json(serde_json::json!({ "error": "request timed out" })),
            )
                .into_response(),
        },
    }
}

pub fn router(svc: Svc, auth: HttpAuth) -> anyhow::Result<Router> {
    Ok(router_with(svc, auth, import_max_bytes()?))
}

pub fn router_with(svc: Svc, auth: HttpAuth, import_max: u64) -> Router {
    let v1 = Router::new()
        .route("/v1/daemon", get(daemon_info))
        .route("/v1/pods", get(list_pods).post(create_pod))
        .route("/v1/images", get(list_images))
        .route("/v1/pods/{name}/start", post(start_pod))
        .route("/v1/pods/{name}/stop", post(stop_pod))
        .route("/v1/pods/{name}/metrics", get(pod_metrics))
        .route("/v1/pods/{name}/stats", get(pod_stats))
        .route("/v1/pods/{name}/logs", get(pod_logs))
        .route("/v1/pods/{name}/exec", post(pod_exec))
        .route("/v1/pods/{name}/export", get(export_pod_http))
        .route("/v1/import", post(import_pod_http))
        .route(
            "/v1/pods/{name}",
            get(get_pod).patch(update_pod).delete(destroy_pod),
        )
        .route("/v1/stacks", post(apply_stack))
        .route("/v1/stacks/{name}", delete(destroy_stack))
        .route("/v1/volumes", get(list_volumes).post(create_volume))
        .route("/v1/volumes/{name}", delete(remove_volume))
        .route("/v1/mesh", get(mesh_status_http).delete(mesh_deinit_http))
        .route("/v1/mesh/init", post(mesh_init_http))
        .route("/v1/mesh/peers", post(mesh_add_peer_http))
        .route("/v1/mesh/peers/{*pubkey}", delete(mesh_rm_peer_http))
        .route_layer(axum::middleware::from_fn_with_state(auth, require_token));
    Router::new()
        .route("/healthz", get(healthz))
        .merge(v1)
        .layer(DefaultBodyLimit::max(JSON_BODY_MAX))
        .layer(axum::middleware::from_fn(limit_request_time))
        .layer(Extension(import_max))
        .with_state(svc)
}

/// Accept loop with a connection cap and an HTTP/1 header-read timeout.
/// `axum::serve` doesn't expose either. Hyper's header timeout needs a
/// timer or it panics.
pub async fn listen(listener: tokio::net::TcpListener, app: Router) -> std::io::Result<()> {
    listen_with(listener, app, HEADER_READ_TIMEOUT, MAX_CONNECTIONS).await
}

pub async fn listen_with(
    listener: tokio::net::TcpListener,
    app: Router,
    header_timeout: Duration,
    max_connections: usize,
) -> std::io::Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use hyper_util::server::conn::auto::Builder;
    use tower::ServiceExt;

    let sem = Arc::new(tokio::sync::Semaphore::new(max_connections));
    loop {
        let (sock, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("http accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    "http connection cap ({max_connections}) reached; dropping connection"
                );
                continue;
            }
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let io = TokioIo::new(sock);
            let svc =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    async move {
                        let req = req.map(Body::new);
                        app.oneshot(req).await
                    }
                });
            let mut builder = Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(header_timeout);
            builder.http2().max_concurrent_streams(32);
            if let Err(e) = builder.serve_connection(io, svc).await {
                tracing::debug!("http connection: {e}");
            }
        });
    }
}

/// 32 bytes from /dev/urandom, hex. Empty or unreadable files are replaced.
fn mint_token() -> anyhow::Result<String> {
    use std::io::Read;
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .context("reading /dev/urandom")?;
    let mut token = String::with_capacity(64);
    for b in buf {
        token.push_str(&format!("{b:02x}"));
    }
    Ok(token)
}

fn read_token_file(path: &FsPath) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim().to_string();
    if s.is_empty() || s.len() > 256 {
        None
    } else {
        Some(s)
    }
}

fn store_token(path: &FsPath, token: &str, allowed_uid: u32) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o400)
            .open(path)
            .with_context(|| format!("create {}", path.display()))?;
        f.write_all(token.as_bytes())?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    if crate::euid() == 0 {
        std::os::unix::fs::chown(path, Some(allowed_uid), Some(allowed_uid))
            .with_context(|| format!("chown {}", path.display()))?;
    }
    Ok(())
}

/// Load or create the read-write and read-only token files. Existing
/// files are kept so a daemon restart doesn't invalidate automation.
/// `rotate` (RUSTYPODS_HTTP_TOKEN_ROTATE=1) replaces both.
pub fn ensure_http_tokens(
    socket: &FsPath,
    allowed_uid: u32,
    rotate: bool,
) -> anyhow::Result<(HttpAuth, PathBuf, PathBuf)> {
    let dir = socket
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/run/rustypods"));
    std::fs::create_dir_all(&dir)?;
    let rw_path = dir.join("http-token");
    let ro_path = dir.join("http-token-ro");
    let load = |path: &FsPath| -> anyhow::Result<String> {
        if !rotate {
            if let Some(existing) = read_token_file(path) {
                // Owner can't open a 0400 file for write — only re-assert mode.
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
                return Ok(existing);
            }
        }
        // A previous 0400 file is not writable even by its owner.
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        let token = mint_token()?;
        store_token(path, &token, allowed_uid)?;
        Ok(token)
    };
    let rw = load(&rw_path)?;
    let ro = load(&ro_path)?;
    Ok((
        HttpAuth {
            rw: Arc::from(rw),
            ro: Arc::from(ro),
        },
        rw_path,
        ro_path,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn auth() -> HttpAuth {
        HttpAuth {
            rw: Arc::from("rw-token"),
            ro: Arc::from("ro-token"),
        }
    }

    fn app() -> Router {
        let dir = std::env::temp_dir().join(format!("rp-http-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        router_with(crate::server::Svc::stub(dir), auth(), 64)
    }

    async fn call(app: Router, req: Request<Body>) -> Response {
        app.oneshot(req).await.unwrap()
    }

    #[test]
    fn token_eq_rejects_mismatch_and_prefix() {
        assert!(token_eq("rw-token", "rw-token"));
        assert!(!token_eq("rw-token", "ro-token"));
        assert!(!token_eq("rw-token-extra", "rw-token"));
        assert!(!token_eq("", "rw-token"));
    }

    #[test]
    fn tokens_persist_until_rotate() {
        let dir = std::env::temp_dir().join(format!(
            "rp-tok-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("rustypods.sock");
        let (a, rw, ro) = ensure_http_tokens(&sock, 1000, false).unwrap();
        let (b, _, _) = ensure_http_tokens(&sock, 1000, false).unwrap();
        assert_eq!(&*a.rw, &*b.rw);
        assert_eq!(&*a.ro, &*b.ro);
        assert_ne!(&*a.rw, &*a.ro);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&rw).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert_eq!(
            std::fs::metadata(&ro).unwrap().permissions().mode() & 0o777,
            0o400
        );
        let (c, _, _) = ensure_http_tokens(&sock, 1000, true).unwrap();
        assert_ne!(&*a.rw, &*c.rw);
        assert_ne!(&*a.ro, &*c.ro);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn auth_gates_and_healthz() {
        let res = call(
            app(),
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK);

        let res = call(
            app(),
            Request::builder()
                .uri("/v1/pods")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let res = call(
            app(),
            Request::builder()
                .uri("/v1/pods")
                .header("authorization", "Bearer wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let res = call(
            app(),
            Request::builder()
                .uri("/v1/pods")
                .header("authorization", "Bearer rw-token")
                .header("origin", "http://evil")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let res = call(
            app(),
            Request::builder()
                .uri("/v1/pods")
                .header("authorization", "Bearer ro-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK);

        let res = call(
            app(),
            Request::builder()
                .method("POST")
                .uri("/v1/pods")
                .header("authorization", "Bearer ro-token")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"a","image":"img"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn json_body_over_1mib_is_413() {
        let big = "x".repeat(JSON_BODY_MAX + 8);
        let body = format!(r#"{{"name":"a","image":"{big}"}}"#);
        let res = call(
            app(),
            Request::builder()
                .method("POST")
                .uri("/v1/pods")
                .header("authorization", "Bearer rw-token")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn import_content_length_over_cap_is_413() {
        let res = call(
            app(),
            Request::builder()
                .method("POST")
                .uri("/v1/import")
                .header("authorization", "Bearer rw-token")
                .header("content-length", "1000")
                .body(Body::from("nope"))
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn header_read_timeout_drops_a_slow_client() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = app();
        tokio::spawn(async move {
            let _ = listen_with(listener, app, Duration::from_millis(200), 8).await;
        });
        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::AsyncWriteExt;
        sock.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut buf = [0u8; 64];
        use tokio::io::AsyncReadExt;
        let n = tokio::time::timeout(Duration::from_millis(500), sock.read(&mut buf))
            .await
            .expect("read")
            .unwrap_or(0);
        // Connection closed before a response (header never finished).
        assert_eq!(n, 0, "slow header should be dropped, got {:?}", &buf[..n]);
    }

    #[test]
    fn streaming_paths_skip_the_short_deadline() {
        assert!(request_budget("/v1/import").is_none());
        assert!(request_budget("/v1/pods/dev/export").is_none());
        assert!(request_budget("/v1/pods/dev/logs").is_none());
        assert_eq!(
            request_budget("/v1/pods/dev/exec"),
            Some(EXEC_REQUEST_TIMEOUT)
        );
        assert_eq!(request_budget("/v1/pods"), Some(REQUEST_TIMEOUT));
    }
}
