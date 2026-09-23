//! Symlink-safe filesystem operations inside an untrusted pod rootfs.
//!
//! Image content is attacker-controlled: a pulled or imported rootfs can
//! plant symlinks like `etc -> /host/etc` — a naive
//! `fs::write(rootfs.join("etc/hostname"))` would then clobber a host file.
//! Every write/remove the daemon performs inside a rootfs goes through the
//! helpers here, which resolve paths with a per-component `symlink_metadata`
//! (lstat) walk: every existing intermediate component must be a real
//! directory — a symlink or a non-directory is refused, so resolution never
//! escapes the rootfs.
//!
//! Residual TOCTOU: check-then-use is racy against a writer mutating the
//! rootfs between our check and the syscall (openat2/RESOLVE_BENEATH would
//! close that, at the cost of raw syscall plumbing). The threat model is
//! static image content — links are planted at pull/import time, when
//! nothing inside the rootfs runs — so the lstat walk is sufficient.

use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

/// Normalize an in-rootfs relative path into plain components: `.` and
/// leading `/` are dropped (`etc/x` and `/etc/x` mean the same file), `..`
/// and anything else structural is rejected outright.
fn components(rel: &Path) -> Result<Vec<&OsStr>> {
    let mut out = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::CurDir | Component::RootDir => {}
            _ => bail!(
                "in-rootfs path '{}' escapes the rootfs ('..' is not allowed)",
                rel.display()
            ),
        }
    }
    Ok(out)
}

/// Normalized in-rootfs path for callers that need the `PathBuf` itself
/// (e.g. the OCI WorkingDir). `Ok(None)` = the path resolves to the rootfs
/// root itself ("/", ".", "") — there is nothing to join/create.
pub fn normalize_rel(rel: &str) -> Result<Option<PathBuf>> {
    let comps = components(Path::new(rel))?;
    let mut out = PathBuf::new();
    for c in comps {
        out.push(c);
    }
    Ok((!out.as_os_str().is_empty()).then_some(out))
}

/// How a missing intermediate component is treated by [`join_parents`].
enum Missing {
    /// Bail — callers writing to the path want to know the tree is hostile.
    Error,
    /// Ok(None) — for removals: a missing parent means no leaf either.
    Absent,
}

/// Walk the parent components of `rel` under `rootfs`: each must exist as a
/// REAL directory (lstat — a symlink-to-dir fails `is_dir`). Returns the
/// leaf path with the leaf itself unchecked; `Ok(None)` only under
/// `Missing::Absent` when a parent does not exist.
fn join_parents(rootfs: &Path, rel: &Path, missing: Missing) -> Result<Option<PathBuf>> {
    let comps = components(rel)?;
    let Some((&leaf, parents)) = comps.split_last() else {
        bail!("empty in-rootfs path");
    };
    let mut cur = rootfs.to_path_buf();
    for c in parents {
        cur.push(*c);
        match std::fs::symlink_metadata(&cur) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => bail!(
                "in-rootfs path '{}': {} is not a real directory",
                rel.display(),
                cur.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match missing {
                Missing::Absent => return Ok(None),
                Missing::Error => bail!(
                    "in-rootfs path '{}': {} does not exist",
                    rel.display(),
                    cur.display()
                ),
            },
            Err(e) => return Err(e).with_context(|| format!("stat {}", cur.display())),
        }
    }
    cur.push(leaf);
    Ok(Some(cur))
}

/// Resolve `rel` under `rootfs` without following symlinks: every
/// intermediate component must exist as a real directory. The returned leaf
/// path is unchecked — it may be absent, a file, or a symlink; each helper
/// below picks the leaf policy appropriate to its operation.
pub fn safe_join(rootfs: &Path, rel: impl AsRef<Path>) -> Result<PathBuf> {
    // Ok(None) is impossible under Missing::Error.
    Ok(join_parents(rootfs, rel.as_ref(), Missing::Error)?
        .expect("Missing::Error never yields None"))
}

/// Parent resolution for read-only access (read_dir, read_to_string):
/// `Ok(None)` = the path can't exist (missing parent). An error still means
/// a hostile tree (symlinked/non-dir parent).
pub fn safe_join_if_exists(rootfs: &Path, rel: impl AsRef<Path>) -> Result<Option<PathBuf>> {
    join_parents(rootfs, rel.as_ref(), Missing::Absent)
}

/// `mkdir -p` under `rootfs`, refusing to traverse symlinks: each existing
/// component must be a real directory; missing ones are created.
pub fn mkdir_in_rootfs(rootfs: &Path, rel: impl AsRef<Path>) -> Result<PathBuf> {
    let rel = rel.as_ref();
    let mut cur = rootfs.to_path_buf();
    for c in components(rel)? {
        cur.push(c);
        match std::fs::symlink_metadata(&cur) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => bail!(
                "in-rootfs path '{}': {} exists but is not a real directory",
                rel.display(),
                cur.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&cur).with_context(|| format!("mkdir {}", cur.display()))?;
            }
            Err(e) => return Err(e).with_context(|| format!("stat {}", cur.display())),
        }
    }
    Ok(cur)
}

/// Write `bytes` at `rel`, creating or truncating the leaf. Parents must be
/// real directories; the leaf is opened O_NOFOLLOW so a symlink planted at
/// the leaf itself is refused (ELOOP) rather than followed. `mode` (when
/// given) is applied via fchmod on the open fd — no path re-resolution.
pub fn write_in_rootfs(
    rootfs: &Path,
    rel: impl AsRef<Path>,
    bytes: &[u8],
    mode: Option<u32>,
) -> Result<()> {
    let p = safe_join(rootfs, rel)?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)
        .with_context(|| format!("write {}", p.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("write {}", p.display()))?;
    if let Some(m) = mode {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(m))
            .with_context(|| format!("chmod {:o} {}", m, p.display()))?;
    }
    Ok(())
}

/// Remove the leaf at `rel` — a file or symlink is unlinked (the link
/// itself, never its target), a real directory is removed recursively.
/// Missing leaf or missing parent → Ok. A symlinked/non-dir parent is an
/// error: resolving through it would delete outside the rootfs.
pub fn remove_in_rootfs(rootfs: &Path, rel: impl AsRef<Path>) -> Result<()> {
    let Some(p) = join_parents(rootfs, rel.as_ref(), Missing::Absent)? else {
        return Ok(());
    };
    match std::fs::symlink_metadata(&p) {
        Ok(md) if md.is_dir() => {
            std::fs::remove_dir_all(&p).with_context(|| format!("rm -rf {}", p.display()))
        }
        Ok(_) => std::fs::remove_file(&p).with_context(|| format!("rm {}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("stat {}", p.display())),
    }
}

/// Create a symlink at `rel` pointing to `target` (stored verbatim — it is
/// an in-container path, never resolved on the host). An existing leaf
/// file/symlink is replaced; a leaf directory is refused.
pub fn symlink_in_rootfs(rootfs: &Path, rel: impl AsRef<Path>, target: &Path) -> Result<()> {
    let p = safe_join(rootfs, rel)?;
    match std::fs::symlink_metadata(&p) {
        Ok(md) if md.is_dir() => {
            bail!(
                "{} is a directory — refusing to replace it with a symlink",
                p.display()
            )
        }
        Ok(_) => std::fs::remove_file(&p).with_context(|| format!("rm {}", p.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("stat {}", p.display())),
    }
    std::os::unix::fs::symlink(target, &p).with_context(|| format!("symlink {}", p.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tree(PathBuf);
    impl Tree {
        fn new(tag: &str) -> Self {
            let base = std::env::temp_dir().join(format!("rp-rootfs-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(base.join("rootfs")).unwrap();
            std::fs::create_dir_all(base.join("outside")).unwrap();
            Tree(base)
        }
        fn rootfs(&self) -> PathBuf {
            self.0.join("rootfs")
        }
        fn outside(&self) -> PathBuf {
            self.0.join("outside")
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn normalization() {
        assert_eq!(
            normalize_rel("/etc/x").unwrap().unwrap(),
            PathBuf::from("etc/x")
        );
        assert_eq!(
            normalize_rel("etc/./x").unwrap().unwrap(),
            PathBuf::from("etc/x")
        );
        assert_eq!(normalize_rel("/").unwrap(), None);
        assert_eq!(normalize_rel("").unwrap(), None);
        assert!(normalize_rel("../x").is_err());
        assert!(normalize_rel("a/../../x").is_err());
    }

    #[test]
    fn happy_path() {
        let t = Tree::new("ok");
        let r = t.rootfs();
        mkdir_in_rootfs(&r, "etc/systemd/network").unwrap();
        write_in_rootfs(&r, "etc/hostname", b"pod", None).unwrap();
        assert_eq!(std::fs::read(r.join("etc/hostname")).unwrap(), b"pod");
        write_in_rootfs(&r, "etc/motd", b"x", Some(0o755)).unwrap();
        symlink_in_rootfs(&r, "etc/link", Path::new("/usr/lib/x")).unwrap();
        assert!(r.join("etc/link").is_symlink());
        // Replacing a leaf symlink works; removing a leaf symlink unlinks
        // the link itself and leaves the target alone.
        write_in_rootfs(&r, "etc/real", b"r", None).unwrap();
        symlink_in_rootfs(&r, "etc/alias", Path::new("real")).unwrap();
        remove_in_rootfs(&r, "etc/alias").unwrap();
        assert!(r.join("etc/real").exists());
        remove_in_rootfs(&r, "etc/missing/deep").unwrap(); // absent parent → Ok
        remove_in_rootfs(&r, "etc/hostname").unwrap();
        assert!(!r.join("etc/hostname").exists());
    }

    /// The core guarantee: a rootfs whose `etc` is a symlink to a host dir
    /// must turn every write/mkdir/remove/symlink into an error — and the
    /// outside dir must stay untouched.
    #[test]
    fn symlinked_dir_never_followed() {
        let t = Tree::new("esc");
        let r = t.rootfs();
        std::os::unix::fs::symlink(t.outside(), r.join("etc")).unwrap();
        std::fs::write(t.outside().join("victim"), b"v").unwrap();

        assert!(write_in_rootfs(&r, "etc/pwned", b"x", None).is_err());
        assert!(mkdir_in_rootfs(&r, "etc/systemd").is_err());
        assert!(remove_in_rootfs(&r, "etc/victim").is_err());
        assert!(symlink_in_rootfs(&r, "etc/l", Path::new("/x")).is_err());
        assert!(safe_join(&r, "etc/x").is_err());
        assert!(safe_join_if_exists(&r, "etc/x").is_err());

        assert!(!t.outside().join("pwned").exists());
        assert!(!t.outside().join("systemd").exists());
        assert_eq!(std::fs::read(t.outside().join("victim")).unwrap(), b"v");
        assert!(!t.outside().join("l").exists());
    }

    /// A symlink at the LEAF is refused on write (O_NOFOLLOW) even when the
    /// parents are honest dirs.
    #[test]
    fn leaf_symlink_not_written() {
        let t = Tree::new("leaf");
        let r = t.rootfs();
        std::fs::create_dir_all(r.join("etc")).unwrap();
        std::os::unix::fs::symlink(t.outside().join("target"), r.join("etc/f")).unwrap();
        assert!(write_in_rootfs(&r, "etc/f", b"x", None).is_err());
        assert!(!t.outside().join("target").exists());
    }
}
