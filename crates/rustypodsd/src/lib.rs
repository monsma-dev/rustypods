pub mod btrfs;
pub mod nspawn;
pub mod server;
pub mod state;

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
    pub fn state_file(&self) -> PathBuf {
        rustypods_proto::state_file(&self.data_dir)
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
