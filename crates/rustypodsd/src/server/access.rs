//! Local control-plane roles and the append-only mutation audit.
//!
//! uid 0 and `Config::allowed_uid` are administrators. Uids listed in
//! `RUSTYPODS_READ_ONLY_UIDS` may connect and call the read RPCs; a
//! mutating call is rejected and written to the audit log. The log is
//! one JSON object per line, opened `O_APPEND` mode 0600 under the
//! data directory.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use tonic::{Request, Status};
use tower::{Layer, Service};

/// gRPC path stamped onto the request before the interceptor runs.
/// Tonic's interceptor does not keep the HTTP URI.
#[derive(Clone, Debug)]
pub(crate) struct RpcPath(pub Arc<str>);

#[derive(Clone, Copy)]
pub(crate) struct StampPathLayer;

pub(crate) struct StampPath<S> {
    inner: S,
}

impl<S> Clone for StampPath<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S> Layer<S> for StampPathLayer {
    type Service = StampPath<S>;

    fn layer(&self, inner: S) -> Self::Service {
        StampPath { inner }
    }
}

impl<S, B> Service<http::Request<B>> for StampPath<S>
where
    S: Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        let path: Arc<str> = Arc::from(req.uri().path());
        req.extensions_mut().insert(RpcPath(path));
        self.inner.call(req)
    }
}

const READ_METHODS: &[&str] = &[
    "Ping",
    "ListImages",
    "ListPods",
    "ListSnapshots",
    "PodMetrics",
    "StreamLogs",
    "ListShm",
    "ListVolumes",
    "GetMeshStatus",
    "IngressGatewayStatus",
];

pub(crate) fn is_read_rpc(path: &str) -> bool {
    let Some(method) = path.strip_prefix("/rustypods.v1.PodControl/") else {
        return false;
    };
    READ_METHODS.contains(&method)
}

pub(crate) enum Decision {
    Allow { audit: bool },
    Deny,
}

pub(crate) fn decide(uid: u32, allowed_uid: u32, readers: &BTreeSet<u32>, path: &str) -> Decision {
    let read = is_read_rpc(path);
    if uid == 0 || uid == allowed_uid {
        return Decision::Allow { audit: !read };
    }
    if readers.contains(&uid) && read {
        return Decision::Allow { audit: false };
    }
    Decision::Deny
}

/// Append-only mutation log. A short write under the mutex; the file
/// is opened `O_APPEND` so concurrent processes do not tear a line.
#[derive(Clone)]
pub(crate) struct AuditLog {
    file: Arc<Mutex<std::fs::File>>,
}

impl AuditLog {
    pub(crate) fn open(data_dir: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let path = data_dir.join("audit.log");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;
        let mut perms = file.metadata()?.permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    pub(crate) fn record(&self, uid: u32, rpc: &str, result: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let rpc = clip(rpc, 160);
        let line = format!(
            "{{\"ts_ms\":{ts},\"uid\":{uid},\"rpc\":{},\"result\":{}}}\n",
            json_str(&rpc),
            json_str(result)
        );
        let mut file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        let _ = file.write_all(line.as_bytes());
        let _ = file.flush();
    }
}

fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                let n = c as u32;
                out.push_str(&format!("\\u{n:04x}"));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub(crate) fn authorize(
    audit: &AuditLog,
    allowed_uid: u32,
    readers: &BTreeSet<u32>,
    req: Request<()>,
) -> Result<Request<()>, Status> {
    let path = req
        .extensions()
        .get::<RpcPath>()
        .map(|p| p.0.as_ref())
        .unwrap_or("");
    let uid = req
        .extensions()
        .get::<tonic::transport::server::UdsConnectInfo>()
        .and_then(|info| info.peer_cred.as_ref())
        .map(|cred| cred.uid());
    let Some(uid) = uid else {
        return Err(Status::unauthenticated("peer credentials unavailable"));
    };
    // Own the path before `decide` borrows it and `record` needs it
    // after the request is returned.
    let path = path.to_string();
    match decide(uid, allowed_uid, readers, &path) {
        Decision::Allow { audit: true } => {
            audit.record(uid, &path, "allowed");
            Ok(req)
        }
        Decision::Allow { audit: false } => Ok(req),
        Decision::Deny => {
            audit.record(uid, &path, "denied");
            Err(Status::permission_denied(
                "read-only credential cannot call this method",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_may_list_and_cannot_destroy() {
        let readers = BTreeSet::from([1001]);
        match decide(1001, 1000, &readers, "/rustypods.v1.PodControl/ListPods") {
            Decision::Allow { audit } => assert!(!audit),
            Decision::Deny => panic!("list must be allowed"),
        }
        assert!(matches!(
            decide(1001, 1000, &readers, "/rustypods.v1.PodControl/DestroyPod"),
            Decision::Deny
        ));
        assert!(matches!(
            decide(1001, 1000, &readers, "/rustypods.v1.PodControl/Exec"),
            Decision::Deny
        ));
        match decide(1000, 1000, &readers, "/rustypods.v1.PodControl/DestroyPod") {
            Decision::Allow { audit } => assert!(audit),
            Decision::Deny => panic!("admin must be allowed"),
        }
        match decide(0, 1000, &readers, "/rustypods.v1.PodControl/Ping") {
            Decision::Allow { audit } => assert!(!audit),
            Decision::Deny => panic!("root read must be allowed"),
        }
        assert!(matches!(
            decide(1002, 1000, &readers, "/rustypods.v1.PodControl/ListPods"),
            Decision::Deny
        ));
    }

    #[test]
    fn audit_line_is_append_only_and_mode_0600() {
        let dir = std::env::temp_dir().join(format!(
            "rp-audit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log = AuditLog::open(&dir).unwrap();
        log.record(1000, "/rustypods.v1.PodControl/DestroyPod", "allowed");
        log.record(1001, "/rustypods.v1.PodControl/StartPod", "denied");
        let text = std::fs::read_to_string(dir.join("audit.log")).unwrap();
        let mut lines = text.lines();
        let first = lines.next().unwrap();
        assert!(first.contains("\"uid\":1000"), "{first}");
        assert!(first.contains("DestroyPod"), "{first}");
        assert!(first.contains("\"result\":\"allowed\""), "{first}");
        let second = lines.next().unwrap();
        assert!(second.contains("\"uid\":1001"), "{second}");
        assert!(second.contains("\"result\":\"denied\""), "{second}");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("audit.log"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
