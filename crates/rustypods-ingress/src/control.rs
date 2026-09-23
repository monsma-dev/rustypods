//! Control plane: the daemon pushes COMPLETE route snapshots over a
//! root-only unix socket. Snapshots validate as a unit — a bad one is
//! rejected wholesale and the live map + generation stay untouched, so
//! the proxy never serves a half-applied table.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use rustypods_proto::rpc::ingress_control_server::{IngressControl, IngressControlServer};
use rustypods_proto::rpc::{
    IngressRule, IngressStatus, IngressStatusRequest, RouteSnapshot, RouteSnapshotAck,
};
use rustypods_proto::validate_ingress_rule;

/// Sanity ceiling on one snapshot — 4096 hosts per daemon is far beyond
/// the 255-entry private-network pool.
const MAX_ROUTES: usize = 4096;

/// One resolved route: the pod's veth/stack endpoint + ingress port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Backend {
    pub ip: Ipv4Addr,
    pub port: u16,
}

/// host → backend. Swapped wholesale per generation.
pub type Routes = HashMap<String, Backend>;

/// One coherent snapshot: generation and route set are updated together,
/// so a reader can never observe them out of step.
#[derive(Debug)]
struct LiveRoutes {
    generation: u64,
    routes: Routes,
}

/// The shared route table: an immutable `LiveRoutes` behind an ArcSwap.
/// Readers never lock; writers replace the whole snapshot in one store.
pub struct RouteState {
    live: ArcSwap<LiveRoutes>,
}

impl RouteState {
    pub fn new() -> Self {
        Self {
            live: ArcSwap::from_pointee(LiveRoutes {
                generation: 0,
                routes: Routes::new(),
            }),
        }
    }

    /// Hot-path lookup: loads the current immutable snapshot.
    pub fn lookup(&self, host: &str) -> Option<Backend> {
        self.live.load().routes.get(host).cloned()
    }

    /// (generation, route_count) from ONE snapshot load — a status read
    /// can never mix a new generation with an old count.
    pub fn snapshot_meta(&self) -> (u64, usize) {
        let live = self.live.load();
        (live.generation, live.routes.len())
    }

    /// Swap in a fully-validated table (control plane + tests).
    pub fn commit(&self, generation: u64, routes: Routes) {
        self.live.store(Arc::new(LiveRoutes { generation, routes }));
    }
}

/// A backend_ip string must name a daemon-owned pod endpoint:
/// 10.220.<idx>.2 — idx 1..=255 (the .1 host side and every other last
/// octet are refused, so the proxy can't be aimed at arbitrary IPs).
fn backend_ip(spec: &str) -> Result<Ipv4Addr> {
    let ip: Ipv4Addr = spec
        .parse()
        .with_context(|| format!("backend ip '{spec}' is not an IPv4 address"))?;
    let [a, b, idx, host] = ip.octets();
    if !(a == 10 && b == 220 && idx != 0 && host == 2) {
        bail!("backend ip '{spec}' is not a pod endpoint (want 10.220.<idx>.2)");
    }
    Ok(ip)
}

/// Validate an entire snapshot into a fresh map. Pure — no state touched.
fn validate_snapshot(snap: &RouteSnapshot) -> Result<Routes> {
    if snap.routes.len() > MAX_ROUTES {
        bail!("{} routes exceeds limit {MAX_ROUTES}", snap.routes.len());
    }
    let mut next = Routes::with_capacity(snap.routes.len());
    for r in &snap.routes {
        // Host grammar + port range is exactly the IngressRule contract:
        // backend_port is the pod-side port the daemon picked.
        validate_ingress_rule(&IngressRule {
            host: r.host.clone(),
            pod_port: r.backend_port,
        })?;
        let ip = backend_ip(&r.backend_ip)?;
        if next
            .insert(r.host.clone(), Backend { ip, port: r.backend_port as u16 })
            .is_some()
        {
            bail!("duplicate host '{}'", r.host);
        }
    }
    Ok(next)
}

struct ControlSvc {
    state: Arc<RouteState>,
}

#[tonic::async_trait]
impl IngressControl for ControlSvc {
    async fn replace_routes(
        &self,
        req: Request<RouteSnapshot>,
    ) -> Result<Response<RouteSnapshotAck>, Status> {
        let snap = req.into_inner();
        let routes = validate_snapshot(&snap).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let count = routes.len() as u32;
        self.state.commit(snap.generation, routes);
        tracing::info!(generation = snap.generation, routes = count, "route snapshot applied");
        Ok(Response::new(RouteSnapshotAck {
            generation: snap.generation,
            route_count: count,
        }))
    }

    async fn get_status(
        &self,
        _req: Request<IngressStatusRequest>,
    ) -> Result<Response<IngressStatus>, Status> {
        let (generation, route_count) = self.state.snapshot_meta();
        Ok(Response::new(IngressStatus {
            generation,
            route_count: route_count as u32,
        }))
    }
}

/// Prepare the socket path: the parent dir is the caller's job (the
/// daemon owns /run/rustypods/run). A stale SOCKET is replaced; anything
/// else squatting on the path fails closed — never delete a foreign file.
fn prepare_socket_path(sock: &Path) -> Result<()> {
    let parent = sock
        .parent()
        .with_context(|| format!("control socket {} has no parent", sock.display()))?;
    if !parent.is_dir() {
        bail!("control socket parent {} does not exist", parent.display());
    }
    match std::fs::symlink_metadata(sock) {
        Ok(md) if md.file_type().is_socket() => {
            std::fs::remove_file(sock)
                .with_context(|| format!("remove stale socket {}", sock.display()))?;
        }
        Ok(_) => bail!(
            "{} exists and is not a unix socket — refusing to remove",
            sock.display()
        ),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("stat {}", sock.display())),
    }
    Ok(())
}

/// Serve IngressControl on `sock` (0600, root-only) until `shutdown`.
pub async fn serve(
    sock: &Path,
    state: Arc<RouteState>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    prepare_socket_path(sock)?;
    let listener = UnixListener::bind(sock)
        .with_context(|| format!("bind {}", sock.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", sock.display()))?;
    tracing::info!("ingress control listening on {}", sock.display());
    Server::builder()
        .add_service(IngressControlServer::new(ControlSvc { state }))
        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), shutdown)
        .await
        .with_context(|| format!("control server {}", sock.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustypods_proto::rpc::ingress_control_client::IngressControlClient;
    use rustypods_proto::rpc::ActiveIngressRoute;
    use tonic::transport::Endpoint;
    use tower::service_fn;

    fn svc() -> (ControlSvc, Arc<RouteState>) {
        let state = Arc::new(RouteState::new());
        (
            ControlSvc {
                state: state.clone(),
            },
            state,
        )
    }

    fn route(host: &str, ip: &str, port: u32) -> ActiveIngressRoute {
        ActiveIngressRoute {
            host: host.into(),
            backend_ip: ip.into(),
            backend_port: port,
        }
    }

    fn snap(gen: u64, routes: Vec<ActiveIngressRoute>) -> Request<RouteSnapshot> {
        Request::new(RouteSnapshot {
            generation: gen,
            routes,
        })
    }

    fn ok_route(host: &str) -> ActiveIngressRoute {
        route(host, "10.220.7.2", 8080)
    }

    #[tokio::test]
    async fn valid_replace_swaps_atomically() {
        let (s, st) = svc();
        let ack = s
            .replace_routes(snap(7, vec![ok_route("a.rustypods.localhost")]))
            .await
            .unwrap()
            .into_inner();
        assert_eq!((ack.generation, ack.route_count), (7, 1));
        assert_eq!(st.snapshot_meta().0, 7);
        assert_eq!(
            st.lookup("a.rustypods.localhost"),
            Some(Backend {
                ip: "10.220.7.2".parse().unwrap(),
                port: 8080
            })
        );
        // Generation need not be monotonic — a daemon restart may reset.
        let ack = s
            .replace_routes(snap(2, vec![]))
            .await
            .unwrap()
            .into_inner();
        assert_eq!((ack.generation, ack.route_count), (2, 0));
        assert_eq!(st.snapshot_meta().0, 2);
        assert!(st.lookup("a.rustypods.localhost").is_none());
    }

    #[tokio::test]
    async fn invalid_snapshot_leaves_state_untouched() {
        let (s, st) = svc();
        s.replace_routes(snap(5, vec![ok_route("a.rustypods.localhost")]))
            .await
            .unwrap();
        let assert_untouched = |st: &Arc<RouteState>| {
            assert_eq!(st.snapshot_meta(), (5, 1));
            assert!(st.lookup("a.rustypods.localhost").is_some());
        };
        // Bad host grammar.
        let e = s
            .replace_routes(snap(9, vec![ok_route("UPPER.rustypods.localhost")]))
            .await;
        assert!(e.is_err_and(|s| s.code() == tonic::Code::InvalidArgument));
        assert_untouched(&st);
        // Bad backend port.
        let e = s
            .replace_routes(snap(9, vec![route("b.rustypods.localhost", "10.220.7.2", 0)]))
            .await;
        assert!(e.is_err_and(|s| s.code() == tonic::Code::InvalidArgument));
        assert_untouched(&st);
        // Backend IPs outside the pod endpoint shape.
        for ip in ["192.168.1.2", "10.220.0.2", "10.220.7.1", "10.220.7.3", "::1", "nope"] {
            let e = s
                .replace_routes(snap(9, vec![route("b.rustypods.localhost", ip, 80)]))
                .await;
            assert!(e.is_err_and(|s| s.code() == tonic::Code::InvalidArgument), "{ip}");
            assert_untouched(&st);
        }
        // Duplicate host within the snapshot.
        let e = s
            .replace_routes(snap(
                9,
                vec![ok_route("a.rustypods.localhost"), ok_route("a.rustypods.localhost")],
            ))
            .await;
        assert!(e.is_err_and(|s| s.code() == tonic::Code::InvalidArgument));
        assert_untouched(&st);
        // Over the ceiling — build via repeat to keep the test cheap.
        let e = s
            .replace_routes(snap(9, vec![ok_route("x.rustypods.localhost"); MAX_ROUTES + 1]))
            .await;
        assert!(e.is_err_and(|s| s.code() == tonic::Code::InvalidArgument));
        assert_untouched(&st);
    }

    #[tokio::test]
    async fn status_reads_current_snapshot() {
        let (s, _st) = svc();
        let st0 = s
            .get_status(Request::new(IngressStatusRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!((st0.generation, st0.route_count), (0, 0));
        s.replace_routes(snap(3, vec![ok_route("a.rustypods.localhost"), ok_route("b.rustypods.localhost")]))
            .await
            .unwrap();
        let st1 = s
            .get_status(Request::new(IngressStatusRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!((st1.generation, st1.route_count), (3, 2));
    }

    /// Full path over a real UDS: bind → tonic client → replace + status.
    #[tokio::test]
    async fn uds_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rp-ingress-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("ingress.sock");
        let state = Arc::new(RouteState::new());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let srv = {
            let sock = sock.clone();
            let state = state.clone();
            tokio::spawn(async move {
                serve(&sock, state, async {
                    let _ = rx.await;
                })
                .await
            })
        };
        // Wait for the socket file to appear.
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(sock.exists());
        // Socket must be root-only.
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);

        let dial = sock.clone();
        let ch = Endpoint::try_from("http://[::]:0")
            .unwrap()
            .connect_with_connector(service_fn(move |_: http::Uri| {
                let p = dial.clone();
                async move { tokio::net::UnixStream::connect(p).await.map(hyper_util::rt::TokioIo::new) }
            }))
            .await
            .unwrap();
        let mut client = IngressControlClient::new(ch);
        let ack = client
            .replace_routes(snap(11, vec![ok_route("a.rustypods.localhost")]).into_inner())
            .await
            .unwrap()
            .into_inner();
        assert_eq!((ack.generation, ack.route_count), (11, 1));
        let st = client
            .get_status(IngressStatusRequest {})
            .await
            .unwrap()
            .into_inner();
        assert_eq!((st.generation, st.route_count), (11, 1));

        // Non-socket squatters are refused, never removed.
        drop(client);
        let _ = tx.send(());
        srv.await.unwrap().unwrap();
        std::fs::remove_file(&sock).unwrap();
        std::fs::write(&sock, b"not a socket").unwrap();
        let (tx2, rx2) = tokio::sync::oneshot::channel::<()>();
        let e = serve(&sock, state, async {
            let _ = rx2.await;
        })
        .await;
        assert!(e.is_err());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = tx2;
    }
}
