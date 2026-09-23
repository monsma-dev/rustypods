//! Btrfs driver: subvolumes, instant CoW snapshots, qgroup quotas.
//! The free functions stay crate-visible so tests and the fallback driver
//! can share them.

use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::StorageDriver;

pub fn is_btrfs(path: &Path) -> bool {
    Command::new("stat")
        .args(["-f", "-c", "%T"])
        .arg(path)
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "btrfs")
        .unwrap_or(false)
}

pub(crate) fn run(cmd: &str, args: &[&OsStr]) -> Result<()> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running {cmd}"))?;
    if out.status.success() {
        Ok(())
    } else {
        bail!(
            "{cmd} {:?}: exit {:?} — {}",
            args,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

/// Enable quota accounting on the filesystem holding `root`. Idempotent and
/// cheap once on; the first call does a one-time tree scan. Quota state does
/// NOT survive a remount — call this again on every pod start.
fn quota_enable(root: &Path) -> Result<()> {
    run(
        "btrfs",
        &[OsStr::new("quota"), OsStr::new("enable"), root.as_os_str()],
    )
}

/// Exclusive cap on the subvolume at `path` (qgroup limit). `bytes == 0`
/// clears the limit. Requires quota_enable() to have run this mount cycle.
fn set_quota_limit(path: &Path, bytes: u64) -> Result<()> {
    let sz = bytes.to_string();
    let lim: &OsStr = if bytes == 0 {
        OsStr::new("none")
    } else {
        sz.as_ref()
    };
    run(
        "btrfs",
        &[
            OsStr::new("qgroup"),
            OsStr::new("limit"),
            lim,
            path.as_os_str(),
        ],
    )
}

/// Read-only snapshot — the source form `btrfs send` requires. Used by
/// pod export: a frozen ro snap is the bit-perfect, point-in-time view
/// that ships to another host.
pub fn snapshot_ro(src: &Path, dst: &Path) -> Result<()> {
    if dst.exists() {
        bail!("{} already exists", dst.display());
    }
    run(
        "btrfs",
        &[
            OsStr::new("subvolume"),
            OsStr::new("snapshot"),
            OsStr::new("-r"),
            src.as_os_str(),
            dst.as_os_str(),
        ],
    )
}

/// Btrfs storage: `btrfs subvolume` for everything.
pub struct BtrfsDriver {
    /// Filesystem root quota accounting is enabled on (the data dir).
    root: PathBuf,
}

impl BtrfsDriver {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.to_path_buf(),
        }
    }
}

impl StorageDriver for BtrfsDriver {
    fn name(&self) -> &'static str {
        "btrfs"
    }
    fn supports_quota(&self) -> bool {
        true
    }

    fn create_rootfs(&self, path: &Path) -> Result<()> {
        if path.exists() {
            bail!("{} already exists", path.display());
        }
        run(
            "btrfs",
            &[
                OsStr::new("subvolume"),
                OsStr::new("create"),
                path.as_os_str(),
            ],
        )
    }

    fn clone_rootfs(&self, src: &Path, dst: &Path) -> Result<()> {
        if dst.exists() {
            bail!("{} already exists", dst.display());
        }
        run(
            "btrfs",
            &[
                OsStr::new("subvolume"),
                OsStr::new("snapshot"),
                src.as_os_str(),
                dst.as_os_str(),
            ],
        )
    }

    fn delete_rootfs(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        super::refuse_if_mounted(path)?;
        // rm -rf is legitimate only for plain dirs — `subvolume delete`
        // tells those apart by name in stderr ("not a subvolume"). Any
        // other failure (EBUSY on a live/mounted tree, EPERM, send in
        // progress) must propagate: falling back to rm -rf there would
        // recurse through whatever is still mounted.
        let out = Command::new("btrfs")
            .args([
                OsStr::new("subvolume"),
                OsStr::new("delete"),
                path.as_os_str(),
            ])
            .output()
            .context("running btrfs")?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        let not_subvol =
            stderr.contains("not a subvolume") || stderr.contains("Not a Btrfs subvolume");
        if not_subvol {
            return run("rm", &[OsStr::new("-rf"), path.as_os_str()]);
        }
        bail!(
            "btrfs subvolume delete {}: {}",
            path.display(),
            stderr.trim()
        )
    }

    fn apply_quota(&self, path: &Path, bytes: u64) -> Result<()> {
        quota_enable(&self.root)?;
        set_quota_limit(path, bytes)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn create_clone_delete() {
        let base =
            std::env::temp_dir().join(format!("rustypods-storage-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let d = super::super::detect(&base); // tmpfs → fallback, still fine to use
        let img = base.join("img");
        let pod = base.join("pod");
        d.create_rootfs(&img).unwrap();
        std::fs::write(img.join("marker"), "x").unwrap();
        d.clone_rootfs(&img, &pod).unwrap();
        assert_eq!(std::fs::read_to_string(pod.join("marker")).unwrap(), "x");
        d.delete_rootfs(&pod).unwrap();
        assert!(!pod.exists());
        d.delete_rootfs(&img).unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }
}
