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
    body::Bytes,
    extract::{Path, Request as AxumRequest, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
    routing::{delete, get, patch, post},
    Json, Router,
};
use serde::Deserialize;
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
    let has_limits = limits.memory_high_bytes > 0
        || limits.memory_max_bytes > 0
        || limits.cpu_quota_percent > 0;
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
    let cur_lim = cur.limits.clone().unwrap_or_default();
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
        .route("/v1/pods/{name}", patch(update_pod).delete(destroy_pod))
        .route("/v1/stacks", post(apply_stack))
        .route("/v1/stacks/{name}", delete(destroy_stack))
        .route_layer(axum::middleware::from_fn_with_state(
            token,
            require_token,
        ));
    Router::new()
        .route("/healthz", get(healthz))
        .merge(v1)
        .with_state(svc)
}
