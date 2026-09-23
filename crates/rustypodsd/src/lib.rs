pub mod agent;
pub mod dbus;
pub mod exec;
pub mod http;
pub mod ingress;
pub mod mesh;
pub mod net;
pub mod oci;
pub mod pki;
pub mod rootfs;
pub mod runtime;
pub mod server;
pub mod stack;
pub mod state;
pub mod storage;
pub mod transfer;

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    /// Root for images/, pods/, logs/, bin/, shm/, state.json.
    pub data_dir: PathBuf,
    /// Unix socket the daemon listens on.
    pub socket: PathBuf,
    /// Besides uid 0, this uid may talk to the daemon (single-user box).
    pub allowed_uid: u32,
    /// Host user that owns the rootless podman store (for distrobox import).
    pub import_user: String,
    /// REST/JSON API bind address; "" disables the HTTP listener.
    /// Bearer-token gated; loopback-only unless RUSTYPODS_HTTP_INSECURE=1.
    pub http_addr: String,
    /// Snapshot GC sweep interval.
    pub gc_interval_secs: u64,
}

impl Config {
    pub fn images_dir(&self) -> PathBuf {
        rustypods_proto::images_dir(&self.data_dir)
    }
    pub fn pods_dir(&self) -> PathBuf {
        rustypods_proto::pods_dir(&self.data_dir)
    }
    pub fn logs_dir(&self) -> PathBuf {
        rustypods_proto::logs_dir(&self.data_dir)
    }
    pub fn bin_dir(&self) -> PathBuf {
        rustypods_proto::bin_dir(&self.data_dir)
    }
    pub fn shm_dir(&self) -> PathBuf {
        rustypods_proto::shm_dir(&self.data_dir)
    }
    pub fn conf_dir(&self) -> PathBuf {
        rustypods_proto::conf_dir(&self.data_dir)
    }
}

pub fn euid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(u32::MAX)
}
