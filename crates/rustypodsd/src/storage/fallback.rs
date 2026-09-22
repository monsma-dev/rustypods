//! Fallback driver for non-btrfs roots (ext4, xfs, tmpfs): plain dirs +
//! `cp -a --reflink=auto` (still CoW on reflink-capable filesystems).
//! Quotas are unsupported — apply_quota errors clearly.

use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::path::Path;

use super::btrfs::run;
use super::StorageDriver;

pub struct FallbackDriver;

impl StorageDriver for FallbackDriver {
    fn name(&self) -> &'static str {
        "reflink-copy"
    }
    fn supports_quota(&self) -> bool {
        false
    }

    fn create_rootfs(&self, path: &Path) -> Result<()> {
        if path.exists() {
            bail!("{} already exists", path.display());
        }
        std::fs::create_dir_all(path).with_context(|| format!("mkdir {}", path.display()))
    }

    fn clone_rootfs(&self, src: &Path, dst: &Path) -> Result<()> {
        if dst.exists() {
            bail!("{} already exists", dst.display());
        }
        std::fs::create_dir_all(dst)?;
        run(
            "cp",
            &[
                OsStr::new("-a"),
                OsStr::new("--reflink=auto"),
                src.join(".").as_os_str(),
                dst.as_os_str(),
            ],
        )
    }

    fn delete_rootfs(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        // rm -rf crosses mount points — never run it under a live mount.
        super::refuse_if_mounted(path)?;
        run("rm", &[OsStr::new("-rf"), path.as_os_str()])
    }

    fn apply_quota(&self, _path: &Path, bytes: u64) -> Result<()> {
        if bytes == 0 {
            return Ok(()); // clearing a cap that was never set is a no-op
        }
        bail!("storage quotas require btrfs — this filesystem uses reflink-copy")
    }
}
