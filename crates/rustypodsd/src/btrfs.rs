//! Storage layer: Btrfs subvolumes when available, reflink-copy fallback
//! otherwise so the daemon stays testable on non-btrfs roots.

use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

pub fn is_btrfs(path: &Path) -> bool {
    Command::new("stat")
        .args(["-f", "-c", "%T"])
        .arg(path)
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "btrfs")
        .unwrap_or(false)
}

fn run(cmd: &str, args: &[&OsStr]) -> Result<()> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("{cmd} starten"))?;
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

/// Create `path` as a Btrfs subvolume (or plain dir off-btrfs).
pub fn create_subvol(path: &Path) -> Result<()> {
    if path.exists() {
        bail!("{} bestaat al", path.display());
    }
    let btrfs = path.parent().map(is_btrfs).unwrap_or(false);
    if btrfs {
        run(
            "btrfs",
            &[OsStr::new("subvolume"), OsStr::new("create"), path.as_os_str()],
        )
    } else {
        std::fs::create_dir_all(path).with_context(|| format!("mkdir {}", path.display()))
    }
}

/// Instant CoW clone on btrfs; reflink copy elsewhere.
pub fn snapshot(src: &Path, dst: &Path) -> Result<()> {
    if dst.exists() {
        bail!("{} bestaat al", dst.display());
    }
    let btrfs = dst.parent().map(is_btrfs).unwrap_or(false);
    if btrfs {
        run(
            "btrfs",
            &[
                OsStr::new("subvolume"),
                OsStr::new("snapshot"),
                src.as_os_str(),
                dst.as_os_str(),
            ],
        )
    } else {
        std::fs::create_dir_all(dst)?;
        let src_contents = src.join(".");
        run(
            "cp",
            &[
                OsStr::new("-a"),
                OsStr::new("--reflink=auto"),
                src_contents.as_os_str(),
                dst.as_os_str(),
            ],
        )
    }
}

/// Remove an image/pod tree (subvolume or dir).
pub fn delete(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if is_btrfs(path) {
        // Succeeds for subvolumes; plain dirs fall through to rm -rf.
        if run(
            "btrfs",
            &[OsStr::new("subvolume"), OsStr::new("delete"), path.as_os_str()],
        )
        .is_ok()
        {
            return Ok(());
        }
    }
    run("rm", &[OsStr::new("-rf"), path.as_os_str()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_snapshot_delete_off_btrfs() {
        let base = std::env::temp_dir().join(format!("rustypods-btrfs-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let img = base.join("img");
        let pod = base.join("pod");
        create_subvol(&img).unwrap();
        std::fs::write(img.join("marker"), "x").unwrap();
        snapshot(&img, &pod).unwrap();
        assert_eq!(std::fs::read_to_string(pod.join("marker")).unwrap(), "x");
        delete(&pod).unwrap();
        assert!(!pod.exists());
        delete(&img).unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }
}
