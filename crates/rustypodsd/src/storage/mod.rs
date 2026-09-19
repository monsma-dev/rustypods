//! Storage abstraction: the daemon picks a driver at startup based on the
//! filesystem under <data>/pods. Btrfs gets instant CoW + qgroup quotas;
//! everything else degrades to reflink copies and no quota support.

pub mod btrfs;
pub mod fallback;

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;

pub use btrfs::BtrfsDriver;
pub use fallback::FallbackDriver;

/// What the daemon needs from a rootfs store. Implementations must be
/// idempotent: paths may be retried after partial failures.
pub trait StorageDriver: Send + Sync {
    /// Driver name for `ping`/logs, e.g. "btrfs".
    fn name(&self) -> &'static str;
    /// Whether `apply_quota` is real (btrfs qgroups) or always errors.
    fn supports_quota(&self) -> bool;
    /// Create an empty rootfs at `path` (subvolume or plain dir).
    fn create_rootfs(&self, path: &Path) -> Result<()>;
    /// Clone `src` to `dst` — instant CoW on btrfs, reflink copy elsewhere.
    fn clone_rootfs(&self, src: &Path, dst: &Path) -> Result<()>;
    /// Remove a rootfs tree (subvolume or dir).
    fn delete_rootfs(&self, path: &Path) -> Result<()>;
    /// Hard cap on the tree at `path`; `bytes == 0` clears it.
    fn apply_quota(&self, path: &Path, bytes: u64) -> Result<()>;
}

/// Pick the best driver for the filesystem hosting `data_dir`/pods.
pub fn detect(data_dir: &Path) -> Arc<dyn StorageDriver> {
    let pods = data_dir.join("pods");
    let probe = if pods.exists() { pods } else { data_dir.to_path_buf() };
    if btrfs::is_btrfs(&probe) {
        tracing::info!("storage driver: btrfs (CoW snapshots + qgroup quotas)");
        Arc::new(BtrfsDriver::new(data_dir))
    } else {
        tracing::info!("storage driver: reflink-copy fallback (no btrfs on {})", probe.display());
        Arc::new(FallbackDriver)
    }
}
