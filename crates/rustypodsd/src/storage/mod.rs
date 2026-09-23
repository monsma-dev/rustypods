//! Storage abstraction: the daemon picks a driver at startup based on the
//! filesystem under <data>/pods. Btrfs gets instant CoW + qgroup quotas;
//! everything else degrades to reflink copies and no quota support.

pub mod btrfs;
pub mod fallback;

use anyhow::{Context, Result};
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

/// Refuse to delete `path` while anything is mounted at or beneath it:
/// `rm -rf` crosses mount points, so a live mount under a rootfs would
/// turn "delete the container dir" into deleting mounted host data.
/// Compares on path components (starts_with on Path), never strings —
/// `/a/b` must not match `/a/bc`.
pub(crate) fn refuse_if_mounted(path: &Path) -> Result<()> {
    let target = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let mounts =
        std::fs::read_to_string("/proc/self/mounts").with_context(|| "read /proc/self/mounts")?;
    for line in mounts.lines() {
        // Field 2 is the mountpoint; octal escapes (\040 etc.) keep it
        // whitespace-free. A path under `target` is the danger.
        let Some(mp) = line.split_whitespace().nth(1) else {
            continue;
        };
        let mp = mp.replace("\\040", " ").replace("\\011", "\t");
        let mp = Path::new(&mp);
        if mp == target || mp.starts_with(&target) {
            anyhow::bail!(
                "refusing to delete {} — mountpoint {} is at/beneath it",
                target.display(),
                mp.display()
            );
        }
    }
    Ok(())
}

/// Pick the best driver for the filesystem hosting `data_dir`/pods.
pub fn detect(data_dir: &Path) -> Arc<dyn StorageDriver> {
    let pods = data_dir.join("pods");
    let probe = if pods.exists() {
        pods
    } else {
        data_dir.to_path_buf()
    };
    if btrfs::is_btrfs(&probe) {
        tracing::info!("storage driver: btrfs (CoW snapshots + qgroup quotas)");
        Arc::new(BtrfsDriver::new(data_dir))
    } else {
        tracing::info!(
            "storage driver: reflink-copy fallback (no btrfs on {})",
            probe.display()
        );
        Arc::new(FallbackDriver)
    }
}

#[cfg(test)]
mod tests {
    use super::refuse_if_mounted;

    #[test]
    fn refuse_if_mounted_behaviour() {
        // A plain tmp dir with nothing mounted under it passes.
        let dir = std::env::temp_dir().join(format!("rp-mnt-check-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(refuse_if_mounted(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);

        // /proc is itself a mountpoint → refused.
        assert!(refuse_if_mounted(std::path::Path::new("/proc")).is_err());
        // /dev has mounts beneath it (/dev/shm, /dev/pts, …) → refused.
        assert!(refuse_if_mounted(std::path::Path::new("/dev")).is_err());
        // Sibling-prefix must NOT match: a path whose name shares a
        // string prefix with a mountpoint is not "under" it.
        assert!(refuse_if_mounted(std::path::Path::new("/dev-shm-lookalike-missing")).is_ok());
    }
}
