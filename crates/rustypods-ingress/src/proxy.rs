//! Public side: plain HTTP only redirects to HTTPS (local TLS is the
//! only served scheme for pod traffic), and HTTPS terminates here and
//! streams to the pod endpoint behind each canonical host. The route
//! table comes from `control::RouteState` — backend IPs are always
//! state-derived, never taken from request input.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;

use crate::control::RouteState;
use rustypods_proto::rpc::IngressRule;
use rustypods_proto::validate_ingress_rule;

const HEALTH_PATH: &str = "/__rustypods/health";

/// Hop-by-hop headers never forwarded either direction (RFC 9110 §7.6.1
/// plus the proxy-auth pair). Connection/Upgrade join the list only for
/// non-upgrade traffic — WebSocket upgrades need them intact.
const HOP_HEADERS: [HeaderName; 8] = [
    header::CONNECTION,
    HeaderName::from_static("proxy-connection"),
    HeaderName::from_static("keep-alive"),
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
];

/// Everything the proxy needs: the shared route table + one pooled
/// upstream client (connect timeout 5s, idle pool 60s/32-per-host).
pub struct ProxyState {
    routes: Arc<RouteState>,
    client: Client<HttpConnector, Body>,
}

pub fn proxy_state(routes: Arc<RouteState>) -> Arc<ProxyState> {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(Duration::from_secs(5)));
    connector.enforce_http(true);
    let client = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(32)
        .build(connector);
    Arc::new(ProxyState { routes, client })
}

/// Plain-HTTP app: health only; everything else 308s to HTTPS.
pub fn http_app() -> Router {
    Router::new()
        .route(HEALTH_PATH, get(health))
        .fallback(http_redirect)
}

/// HTTPS app: health + the hostname proxy.
pub fn https_app(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route(HEALTH_PATH, get(health))
        .fallback(https_proxy)
        .with_state(state)
}

async fn health() -> &'static str {
    "ok\n"
}

/// `Host` → canonical route key: UTF-8, valid authority (strips any
/// :port), lowercase, and matching the ingress grammar — a name the
/// daemon could never have pushed is malformed, not "unknown".
///
/// HTTP/2 carries the authority in `:authority`, not a Host header —
/// hyper exposes it via `uri().authority()`, so check the header first
/// (h1 semantics) then the URI (h2 / absolute-form), same precedence as
/// axum's `Host` extractor.
fn canonical_host(req: &Request) -> Result<String, Response> {
    let raw = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_owned()));
    let Some(s) = raw else {
        return Err(bad_request("missing Host"));
    };
    let authority: http::uri::Authority =
        s.parse().map_err(|_| bad_request("malformed Host"))?;
    let host = authority.host().to_ascii_lowercase();
    validate_ingress_rule(&IngressRule {
        host: host.clone(),
        pod_port: 80,
    })
    .map_err(|_| bad_request("host is not an ingress name"))?;
    Ok(host)
}

fn bad_request(msg: &'static str) -> Response {
    (StatusCode::BAD_REQUEST, msg).into_response()
}

/// `Connection` lists further hop-by-hop headers by name — strip those
/// too, then the fixed list. `ws` keeps the upgrade handshake itself:
/// Connection is normalized to `upgrade` (other tokens still die) and
/// the `Upgrade` header survives.
fn strip_hop_headers(h: &mut HeaderMap, ws: bool) {
    if let Some(v) = h.get(header::CONNECTION).and_then(|v| v.to_str().ok()) {
        let named: Vec<HeaderName> = v
            .split(',')
            .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
            .collect();
        for n in named {
            // The handshake names "upgrade" (and sometimes "connection")
            // as Connection tokens — those are the parts we keep.
            if ws && (n == header::CONNECTION || n == header::UPGRADE) {
                continue;
            }
            h.remove(&n);
        }
    }
    for n in &HOP_HEADERS {
        h.remove(n);
    }
    if ws {
        h.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    } else {
        h.remove(header::UPGRADE);
    }
}

/// Client-supplied forwarding headers are spoofable — drop `Forwarded`,
/// `X-Real-IP` and every `X-Forwarded-*`, then write our own.
fn sanitize_forward_headers(h: &mut HeaderMap, host: &str, proto: &str) {
    let spoofed: Vec<HeaderName> = h
        .keys()
        .filter(|k| k.as_str().starts_with("x-forwarded-"))
        .cloned()
        .collect();
    for k in spoofed {
        h.remove(&k);
    }
    h.remove(HeaderName::from_static("forwarded"));
    h.remove(HeaderName::from_static("x-real-ip"));
    if let Ok(v) = HeaderValue::from_str(host) {
        h.insert(HeaderName::from_static("x-forwarded-host"), v);
    }
    h.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static(match proto {
            "http" => "http",
            _ => "https",
        }),
    );
}

/// `Connection: upgrade` + `Upgrade: websocket` (either token order).
fn is_websocket_upgrade(h: &HeaderMap) -> bool {
    let conn = h
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    let up = h
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    conn && up
}

async fn http_redirect(req: Request) -> Response {
    let host = match canonical_host(&req) {
        Ok(h) => h,
        Err(e) => return e,
    };
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    (
        StatusCode::PERMANENT_REDIRECT,
        [(header::LOCATION, format!("https://{host}{pq}"))],
    )
        .into_response()
}

async fn https_proxy(State(st): State<Arc<ProxyState>>, req: Request) -> Response {
    proxy_request(&st, req).await
}

async fn proxy_request(st: &ProxyState, mut req: Request) -> Response {
    if req.method() == Method::CONNECT {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let host = match canonical_host(&req) {
        Ok(h) => h,
        Err(e) => return e,
    };
    let Some(backend) = st.routes.lookup(&host) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let ws = is_websocket_upgrade(req.headers());
    // Consumes the pending upgrade hyper's server put on the INCOMING
    // request — resolves once our 101 response goes out downstream.
    let down_upgrade = ws.then(|| hyper::upgrade::on(&mut req));

    // Point the request at the state-derived backend; keep the canonical
    // Host so in-pod virtual-host apps see the original name.
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "/".into());
    let target: Uri = match format!("http://{}:{}{}", backend.ip, backend.port, pq).parse() {
        Ok(u) => u,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    *req.uri_mut() = target;
    // Upstream is always HTTP/1.1 — the pooled client is h1-only and an
    // h2 (TLS/ALPN) downstream version would be rejected outright.
    *req.version_mut() = Version::HTTP_11;
    if let Ok(v) = HeaderValue::from_str(&host) {
        req.headers_mut().insert(header::HOST, v);
    }
    strip_hop_headers(req.headers_mut(), ws);
    sanitize_forward_headers(req.headers_mut(), &host, "https");

    let mut resp = match st.client.request(req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("upstream {host}: {e}");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    if ws && resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        // Upstream agreed — sanitize the 101 the same way (Connection may
        // nominate junk headers; keep only the upgrade pair) before
        // splicing the two raw streams. The downstream OnUpgrade resolves
        // when hyper writes this 101 back.
        strip_hop_headers(resp.headers_mut(), true);
        let up_upgrade = hyper::upgrade::on(&mut resp);
        let host = host.clone();
        tokio::spawn(async move {
            match (down_upgrade.expect("ws checked").await, up_upgrade.await) {
                (Ok(down), Ok(up)) => {
                    let mut down = TokioIo::new(down);
                    let mut up = TokioIo::new(up);
                    match tokio::io::copy_bidirectional(&mut down, &mut up).await {
                        Ok((a, b)) => {
                            tracing::debug!("websocket {host}: closed ({a} up, {b} down)")
                        }
                        Err(e) => tracing::debug!("websocket {host}: {e}"),
                    }
                }
                (d, u) => {
                    tracing::debug!("websocket {host}: upgrade failed ({d:?}, {u:?})")
                }
            }
        });
    } else {
        strip_hop_headers(resp.headers_mut(), false);
    }

    let (parts, body) = resp.into_parts();
    Response::from_parts(parts, Body::new(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{Backend, RouteState, Routes};
    use http_body_util::BodyExt;
    use std::net::Ipv4Addr;
    use tower::ServiceExt;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        h
    }

    fn req_with_host(host: Option<&str>) -> Request {
        let mut b = Request::builder().uri("/");
        if let Some(h) = host {
            b = b.header("host", h);
        }
        b.body(Body::empty()).unwrap()
    }

    #[test]
    fn host_normalization() {
        // Missing → malformed/missing error (400 path).
        assert!(canonical_host(&req_with_host(None)).is_err());
        // Not an ingress name → malformed.
        assert!(canonical_host(&req_with_host(Some("www.example.com"))).is_err());
        // Garbage that isn't an authority.
        assert!(canonical_host(&req_with_host(Some("no spaces allowed"))).is_err());
        // Port stripped, case folded.
        assert_eq!(
            canonical_host(&req_with_host(Some("Web.Rustypods.Localhost:8443"))).unwrap(),
            "web.rustypods.localhost"
        );
        // Nested names are malformed — one label only (wildcard SAN).
        assert!(canonical_host(&req_with_host(Some("api.dev.rustypods.localhost"))).is_err());
    }

    #[test]
    fn host_via_uri_authority() {
        // h2/absolute-form: no Host header, authority on the URI.
        let req = Request::builder()
            .uri("https://Demo.Rustypods.Localhost:8443/x")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            canonical_host(&req).unwrap(),
            "demo.rustypods.localhost"
        );
    }

    #[tokio::test]
    async fn http_redirects_to_https() {
        let app = http_app();
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/some/path?x=1&y=2")
                    .header("host", "Web.Rustypods.Localhost:8080")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            r.headers().get("location").unwrap(),
            "https://web.rustypods.localhost/some/path?x=1&y=2"
        );
        // Malformed host → 400, no redirect.
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header("host", "evil.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        // Health is served directly on :8080 without a route lookup.
        let r = app
            .oneshot(
                Request::builder()
                    .uri(HEALTH_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let body = r.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ok\n");
    }

    /// A local echo backend standing in for a pod endpoint; routes are
    /// committed directly (control-plane validation is tested in
    /// control.rs — the proxy only does lookups).
    async fn echo_backend() -> (Arc<ProxyState>, tokio::task::JoinHandle<()>) {
        let backend = Router::new().fallback(|req: Request| async move {
            let host = req
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let xfh = req
                .headers()
                .get("x-forwarded-host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let xfp = req
                .headers()
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let xff = req.headers().contains_key("x-forwarded-for");
            let xri = req.headers().contains_key("x-real-ip");
            let conn = req.headers().contains_key("connection");
            let body = req.into_body().collect().await.unwrap().to_bytes();
            format!(
                "host={host} xfh={xfh} xfp={xfp} xff={xff} xri={xri} conn={conn} body={}",
                String::from_utf8_lossy(&body)
            )
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            axum::serve(listener, backend).await.unwrap();
        });
        let routes = Arc::new(RouteState::new());
        let mut m = Routes::new();
        m.insert(
            "web.rustypods.localhost".to_string(),
            Backend {
                ip: Ipv4Addr::LOCALHOST,
                port,
            },
        );
        routes.commit(1, m);
        (proxy_state(routes), task)
    }

    #[tokio::test]
    async fn https_proxies_and_sanitizes() {
        let (state, _backend) = echo_backend().await;
        let app = https_app(state);
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/echo?a=b")
                    .header("host", "Web.Rustypods.Localhost:8443")
                    .header("x-forwarded-for", "1.2.3.4")
                    .header("x-real-ip", "1.2.3.4")
                    .header("forwarded", "for=evil")
                    .header("connection", "keep-alive, x-secret")
                    .header("x-secret", "poison")
                    .body(Body::from("hello-body"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let body = r.into_body().collect().await.unwrap().to_bytes();
        let s = String::from_utf8_lossy(&body);
        // Canonical host survives; our forwarding pair is set; the
        // client's spoofed XFF/Forwarded/Connection-named headers are gone.
        assert!(s.contains("host=web.rustypods.localhost"), "{s}");
        assert!(s.contains("xfh=web.rustypods.localhost"), "{s}");
        assert!(s.contains("xfp=https"), "{s}");
        assert!(s.contains("xff=false"), "{s}");
        assert!(s.contains("xri=false"), "{s}");
        assert!(s.contains("conn=false"), "{s}");
        assert!(s.contains("body=hello-body"), "{s}");
    }

    #[tokio::test]
    async fn https_unknown_and_bad_requests() {
        let (state, _b) = echo_backend().await;
        let app = https_app(state);
        // Valid grammar, no route → 404.
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "ghost.rustypods.localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        // CONNECT refused outright.
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::CONNECT)
                    .uri("web.rustypods.localhost:443")
                    .header("host", "web.rustypods.localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
        // Route exists but nothing is listening → 502, no internals.
        let routes = Arc::new(RouteState::new());
        let mut m = Routes::new();
        m.insert(
            "dead.rustypods.localhost".to_string(),
            Backend {
                ip: Ipv4Addr::LOCALHOST,
                port: 1,
            },
        );
        routes.commit(2, m);
        let app = https_app(proxy_state(routes));
        let r = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "dead.rustypods.localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn websocket_detection_and_header_preservation() {
        let ws = headers(&[
            ("connection", "keep-alive, Upgrade"),
            ("upgrade", "websocket"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("x-forwarded-for", "9.9.9.9"),
        ]);
        assert!(is_websocket_upgrade(&ws));
        assert!(!is_websocket_upgrade(&headers(&[("upgrade", "websocket")])));
        assert!(!is_websocket_upgrade(&headers(&[("connection", "upgrade")])));
        let mut h = ws.clone();
        strip_hop_headers(&mut h, true);
        // Upgrade traffic keeps its handshake headers, loses spoofables.
        assert!(h.contains_key("connection"));
        assert!(h.contains_key("upgrade"));
        assert!(h.contains_key("sec-websocket-key"));
        // Non-upgrade traffic loses Upgrade too.
        let mut h2 = headers(&[("upgrade", "websocket"), ("connection", "upgrade")]);
        strip_hop_headers(&mut h2, false);
        assert!(!h2.contains_key("upgrade"));
        assert!(!h2.contains_key("connection"));
    }

    #[test]
    fn ws_response_sanitized_but_upgrade_survives() {
        // An upstream 101 whose Connection nominates junk headers: poison
        // dies, the upgrade pair stays normalized.
        let mut h = headers(&[
            ("connection", "upgrade, x-poison"),
            ("upgrade", "websocket"),
            ("x-poison", "bad"),
            ("keep-alive", "timeout=5"),
            ("proxy-authenticate", "Basic"),
            ("transfer-encoding", "chunked"),
        ]);
        strip_hop_headers(&mut h, true);
        assert_eq!(h.get("connection").unwrap(), "upgrade");
        assert_eq!(h.get("upgrade").unwrap(), "websocket");
        assert!(!h.contains_key("x-poison"));
        assert!(!h.contains_key("keep-alive"));
        assert!(!h.contains_key("proxy-authenticate"));
        assert!(!h.contains_key("transfer-encoding"));
    }

    /// Real WebSocket through the whole path: client → ingress app
    /// (served plain — this tests proxy logic, not TLS) → upstream
    /// handshake → OnUpgrade both ends → copy_bidirectional. Text and
    /// binary frames must come back byte-exact.
    #[tokio::test]
    async fn websocket_e2e_transparent() {
        use futures_util::{SinkExt, StreamExt};
        use std::time::Duration;
        use tokio_tungstenite::tungstenite::Message;

        const T: Duration = Duration::from_secs(2);

        // Backend echo over raw TCP — same dep on the server side.
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bport = backend.local_addr().unwrap().port();
        let mut btask = tokio::spawn(async move {
            let (stream, _) = backend.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(m)) = ws.next().await {
                if m.is_close() {
                    let _ = ws.send(m).await;
                    break;
                }
                ws.send(m).await.unwrap();
            }
        });

        let routes = Arc::new(RouteState::new());
        let mut m = Routes::new();
        m.insert(
            "ws.rustypods.localhost".to_string(),
            Backend {
                ip: Ipv4Addr::LOCALHOST,
                port: bport,
            },
        );
        routes.commit(1, m);

        let front = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fport = front.local_addr().unwrap().port();
        let ftask = tokio::spawn(async move {
            axum::serve(front, https_app(proxy_state(routes)))
                .await
                .unwrap();
        });

        // Custom Host on a real handshake — the proxy must route on it.
        let req = http::Request::builder()
            .method("GET")
            .uri(format!("ws://127.0.0.1:{fport}/ws/path?x=1"))
            .header("Host", "ws.rustypods.localhost")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .body(())
            .unwrap();
        let (mut ws, resp) = tokio::time::timeout(T, tokio_tungstenite::connect_async(req))
            .await
            .expect("handshake timed out")
            .expect("handshake failed");
        assert_eq!(resp.status(), http::StatusCode::SWITCHING_PROTOCOLS);

        tokio::time::timeout(T, ws.send(Message::Text("hello-ws".into())))
            .await
            .unwrap()
            .unwrap();
        let echo = tokio::time::timeout(T, ws.next()).await.unwrap().unwrap().unwrap();
        assert_eq!(echo, Message::Text("hello-ws".into()));

        let blob = vec![0u8, 1, 2, 250, 255];
        tokio::time::timeout(T, ws.send(Message::Binary(blob.clone().into())))
            .await
            .unwrap()
            .unwrap();
        let echo = tokio::time::timeout(T, ws.next()).await.unwrap().unwrap().unwrap();
        assert_eq!(echo, Message::Binary(blob.into()));

        let _ = tokio::time::timeout(T, ws.close(None)).await;
        let _ = tokio::time::timeout(T, &mut btask).await;
        ftask.abort();
        btask.abort();
    }
}
