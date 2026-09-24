//! REST/JSON facade over the gRPC control plane — the same PodControl
//! methods the CLI uses, exposed for automation and agents. Proto types
//! serialize camelCase, so responses match the protobuf field names.
//!
//! **Bearer-token auth.** Every `/v1/*` request needs
//! `Authorization: Bearer <token>`; the token is generated at daemon start
//! and written to /run/rustypods/http-token (mode 0400, owned by the
//! allowed uid). Requests carrying `Origin` or `Sec-Fetch-Site` headers are
//! rejected outright — browsers have no business here (CSRF/drive-by).
//! `/healthz` stays open. The bind address is loopback-only unless the
//! operator sets RUSTYPODS_HTTP_INSECURE=1.

use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, Request as AxumRequest, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
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
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, Json(serde_json::json!({ "error": s.message() })))
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

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
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
    // The RPC takes concrete limits — merge over the current pod so absent
    // JSON fields keep their values (same rule as `rustypods config`).
    let cur = s
        .list_pods(Request::new(ListPodsRequest {}))
        .await
        .map_err(api_err)?
        .into_inner()
        .pods
        .into_iter()
        .find(|p| p.name == name)
        .ok_or_else(|| api_err(Status::not_found(format!("pod {name} not found"))))?;
    let cur_lim = cur.limits.unwrap_or_default();
    let p = s
        .update_pod_config(Request::new(UpdatePodConfigRequest {
            name,
            limits: Some(Limits {
                memory_high_bytes: b.memory_high_bytes.unwrap_or(cur_lim.memory_high_bytes),
                memory_max_bytes: b.memory_max_bytes.unwrap_or(cur_lim.memory_max_bytes),
                cpu_quota_percent: b.cpu_quota_percent.unwrap_or(cur_lim.cpu_quota_percent),
            }),
            storage_max_bytes: b.storage_max_bytes.unwrap_or(cur.storage_max_bytes),
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
        }))
        .await
        .map_err(api_err)?
        .into_inner();
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
    Query(q): Query<ImportQuery>,
    req: AxumRequest,
) -> Result<Json<Pod>, ApiErr> {
    use rustypods_proto::rpc::import_chunk::Kind;
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
    let data = req.into_body().into_data_stream().map(|b| {
        b.map(|b| ImportChunk {
            kind: Some(Kind::Data(b.to_vec())),
        })
        .map_err(|e| Status::internal(format!("body read: {e}")))
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

/// `POST /v1/mesh/init?listen_port=N` — empty body, port optional.
#[derive(Deserialize, Default)]
struct MeshInitIn {
    #[serde(default)]
    listen_port: u32,
}

async fn mesh_status_http(State(s): State<Svc>) -> Result<Json<MeshStatus>, ApiErr> {
    s.get_mesh_status(Request::new(Empty {}))
        .await
        .map(|r| Json(r.into_inner()))
        .map_err(api_err)
}

async fn mesh_init_http(
    State(s): State<Svc>,
    Query(q): Query<MeshInitIn>,
) -> Result<Json<MeshStatus>, ApiErr> {
    s.mesh_init(Request::new(MeshInitRequest {
        listen_port: q.listen_port,
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
}

async fn mesh_add_peer_http(
    State(s): State<Svc>,
    Json(b): Json<MeshPeerIn>,
) -> Result<Json<MeshStatus>, ApiErr> {
    s.mesh_add_peer(Request::new(MeshPeer {
        endpoint: b.endpoint,
        pubkey: b.pubkey,
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
    }))
    .await
    .map(|r| Json(r.into_inner()))
    .map_err(api_err)
}

/// Bearer auth + browser-header rejection for /v1/*. Two gates:
/// 1. Any `Origin` or `Sec-Fetch-Site` header → 403. Browsers attach those
///    to cross-origin requests; a local web page must never drive the API.
/// 2. Missing/wrong `Authorization: Bearer <token>` → 401.
async fn require_token(
    State(expected): State<Arc<str>>,
    req: AxumRequest,
    next: Next,
) -> Result<Response, StatusCode> {
    let h = req.headers();
    if h.contains_key(axum::http::header::ORIGIN) || h.contains_key("sec-fetch-site") {
        return Err(StatusCode::FORBIDDEN);
    }
    let want = format!("Bearer {expected}");
    let ok = h
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == want)
        .unwrap_or(false);
    if !ok {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(req).await)
}

pub fn router(svc: Svc, token: Arc<str>) -> Router {
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
        .route_layer(axum::middleware::from_fn_with_state(token, require_token));
    Router::new()
        .route("/healthz", get(healthz))
        .merge(v1)
        .with_state(svc)
}
