//! Symlink-safe filesystem operations inside an untrusted pod rootfs.
//!
//! Image content is attacker-controlled: a pulled or imported rootfs can
//! plant symlinks like `etc -> /host/etc`. Every write, remove, mkdir and
//! read the daemon performs inside a rootfs goes through a directory fd
//! opened with `openat2` and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`
//! (Linux 5.6+). The kernel rejects a component that is a symlink or that
//! resolves outside the rootfs directory in the same syscall that uses it,
//! so a rename between an `lstat` and a later `open` cannot redirect the
//! operation onto the host.

use anyhow::{bail, Context, Result};
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::{Read as _, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

/// What `fstatat(AT_SYMLINK_NOFOLLOW)` saw for the leaf. `Absent` is a
/// missing parent or a missing leaf. A symlink leaf is reported as
/// [`Leaf::Symlink`] and is never followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leaf {
    Absent,
    File,
    Dir,
    Symlink,
    Other,
}

impl Leaf {
    pub fn exists(self) -> bool {
        !matches!(self, Leaf::Absent)
    }
}

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

fn cstr(name: &OsStr) -> Result<CString> {
    CString::new(name.as_bytes()).context("in-rootfs path contains an interior NUL")
}

fn joined(comps: &[&OsStr]) -> PathBuf {
    let mut out = PathBuf::new();
    for c in comps {
        out.push(c);
    }
    out
}

/// `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`. `path` is a
/// single component or a relative path under `dirfd`.
fn openat2(dirfd: impl AsFd, path: &CString, flags: i32, mode: u32) -> std::io::Result<OwnedFd> {
    // Kernel `struct open_how`. libc marks its copy non_exhaustive, so the
    // syscall argument is this layout-compatible local struct. The size
    // argument lets the kernel accept this 24-byte prefix.
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let mut how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: mode as u64,
        resolve: libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: `path` is a NUL-terminated CString live for the call, `how`
    // is a valid open_how of the size we pass, and a non-negative return
    // is an owned fd.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd.as_fd().as_raw_fd(),
            path.as_ptr(),
            &mut how as *mut OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: syscall returned a new fd. It is not shared.
        Ok(unsafe { OwnedFd::from_raw_fd(rc as std::os::fd::RawFd) })
    }
}

fn open_root(rootfs: &Path) -> Result<OwnedFd> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(rootfs)
        .with_context(|| format!("open rootfs {}", rootfs.display()))?;
    Ok(f.into())
}

fn open_child(dir: &OwnedFd, name: &OsStr, flags: i32, mode: u32) -> std::io::Result<OwnedFd> {
    let path = cstr(name).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    openat2(dir, &path, flags, mode)
}

fn explain(err: std::io::Error, rel: &Path, what: &Path) -> anyhow::Error {
    match err.raw_os_error() {
        Some(libc::ELOOP | libc::EXDEV | libc::ENOTDIR) => anyhow::anyhow!(
            "in-rootfs path '{}': {} is not a real directory beneath the rootfs",
            rel.display(),
            what.display()
        ),
        Some(libc::ENOSYS) => {
            anyhow::anyhow!("openat2 is unavailable — rootfs access requires Linux 5.6+")
        }
        _ if err.kind() == std::io::ErrorKind::NotFound => anyhow::anyhow!(
            "in-rootfs path '{}': {} does not exist",
            rel.display(),
            what.display()
        ),
        _ => anyhow::Error::from(err).context(format!("open {}", what.display())),
    }
}

/// Walk `parents` from `root`, pinning each real directory with openat2.
/// `Ok(None)` when a component is missing.
fn open_chain(root: &OwnedFd, rel: &Path, parents: &[&OsStr]) -> Result<Option<OwnedFd>> {
    let mut dir = root.try_clone().context("dup rootfs directory fd")?;
    let mut so_far = PathBuf::new();
    for name in parents {
        so_far.push(name);
        match open_child(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(next) => dir = next,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(explain(e, rel, &so_far)),
        }
    }
    Ok(Some(dir))
}

fn fstat_leaf(dir: &OwnedFd, name: &OsStr) -> Result<Option<libc::stat>> {
    let path = cstr(name)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `path` is a NUL-terminated name, `st` is a valid stat buffer,
    // and AT_SYMLINK_NOFOLLOW keeps a leaf symlink from being followed.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            path.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        return Ok(Some(st));
    }
    let err = std::io::Error::last_os_error();
    if err.kind() == std::io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(err).with_context(|| format!("stat {}", name.to_string_lossy()))
    }
}

fn is_mode(mode: libc::mode_t, kind: libc::mode_t) -> bool {
    mode & libc::S_IFMT == kind
}

fn leaf_of(st: &libc::stat) -> Leaf {
    let mode = st.st_mode;
    if is_mode(mode, libc::S_IFLNK) {
        Leaf::Symlink
    } else if is_mode(mode, libc::S_IFDIR) {
        Leaf::Dir
    } else if is_mode(mode, libc::S_IFREG) {
        Leaf::File
    } else {
        Leaf::Other
    }
}

/// Classify `rel` under `rootfs` without following a symlink. A symlinked
/// or non-directory parent is an error. A missing parent or leaf is
/// [`Leaf::Absent`].
pub fn classify(rootfs: &Path, rel: impl AsRef<Path>) -> Result<Leaf> {
    let rel = rel.as_ref();
    let comps = components(rel)?;
    let Some((leaf, parents)) = comps.split_last() else {
        bail!("empty in-rootfs path");
    };
    let root = open_root(rootfs)?;
    let Some(parent) = open_chain(&root, rel, parents)? else {
        return Ok(Leaf::Absent);
    };
    Ok(match fstat_leaf(&parent, leaf)? {
        Some(st) => leaf_of(&st),
        None => Leaf::Absent,
    })
}

/// Read a regular file. `Ok(None)` when it is missing or not a regular
/// file (a leaf symlink is not followed). A symlinked parent is an error.
pub fn read_file_in_rootfs(rootfs: &Path, rel: impl AsRef<Path>) -> Result<Option<Vec<u8>>> {
    let rel = rel.as_ref();
    let comps = components(rel)?;
    let Some((leaf, parents)) = comps.split_last() else {
        bail!("empty in-rootfs path");
    };
    let root = open_root(rootfs)?;
    let Some(parent) = open_chain(&root, rel, parents)? else {
        return Ok(None);
    };
    match fstat_leaf(&parent, leaf)? {
        Some(st) if is_mode(st.st_mode, libc::S_IFREG) => {}
        _ => return Ok(None),
    }
    let fd = open_child(&parent, leaf, libc::O_RDONLY, 0)
        .map_err(|e| explain(e, rel, &joined(&comps)))?;
    let mut f = File::from(fd);
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .with_context(|| format!("read {}", rel.display()))?;
    Ok(Some(buf))
}

/// `readlinkat` of the leaf. `Ok(None)` when the leaf is missing or not a
/// symlink. The link text is returned verbatim and is not resolved.
pub fn read_link_in_rootfs(rootfs: &Path, rel: impl AsRef<Path>) -> Result<Option<PathBuf>> {
    let rel = rel.as_ref();
    let comps = components(rel)?;
    let Some((leaf, parents)) = comps.split_last() else {
        bail!("empty in-rootfs path");
    };
    let root = open_root(rootfs)?;
    let Some(parent) = open_chain(&root, rel, parents)? else {
        return Ok(None);
    };
    let path = cstr(leaf)?;
    let mut buf = [0u8; 4096];
    // SAFETY: `path` is NUL-terminated and `buf` is a writable buffer of
    // the length we pass. readlinkat does not write a trailing NUL.
    let n = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            path.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINVAL) || err.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(err).with_context(|| format!("readlink {}", rel.display()));
    }
    let n = n as usize;
    if n >= buf.len() {
        bail!(
            "symlink {} is longer than {} bytes",
            rel.display(),
            buf.len()
        );
    }
    Ok(Some(PathBuf::from(OsStr::from_bytes(&buf[..n]))))
}

/// `(st_dev, st_ino)` of the leaf without following a symlink. `Ok(None)`
/// when the leaf is absent.
pub fn inode_in_rootfs(rootfs: &Path, rel: impl AsRef<Path>) -> Result<Option<(u64, u64)>> {
    let rel = rel.as_ref();
    let comps = components(rel)?;
    let Some((leaf, parents)) = comps.split_last() else {
        bail!("empty in-rootfs path");
    };
    let root = open_root(rootfs)?;
    let Some(parent) = open_chain(&root, rel, parents)? else {
        return Ok(None);
    };
    Ok(fstat_leaf(&parent, leaf)?.map(|st| (st.st_dev, st.st_ino)))
}

/// Resolve `rel` under `rootfs`. Every intermediate component must be a
/// real directory beneath the rootfs. The returned path is the joined
/// location; callers that read or write must use the fd helpers so the
/// use cannot be redirected after this check returns.
pub fn safe_join(rootfs: &Path, rel: impl AsRef<Path>) -> Result<PathBuf> {
    let rel = rel.as_ref();
    let comps = components(rel)?;
    let Some((_, parents)) = comps.split_last() else {
        bail!("empty in-rootfs path");
    };
    let root = open_root(rootfs)?;
    if open_chain(&root, rel, parents)?.is_none() {
        bail!(
            "in-rootfs path '{}': a parent does not exist",
            rel.display()
        );
    }
    Ok(rootfs.join(joined(&comps)))
}

/// Parent resolution for existence probes. `Ok(None)` = a parent is
/// missing. An error still means a hostile tree.
pub fn safe_join_if_exists(rootfs: &Path, rel: impl AsRef<Path>) -> Result<Option<PathBuf>> {
    let rel = rel.as_ref();
    let comps = components(rel)?;
    let Some((_, parents)) = comps.split_last() else {
        bail!("empty in-rootfs path");
    };
    let root = open_root(rootfs)?;
    if open_chain(&root, rel, parents)?.is_none() {
        return Ok(None);
    }
    Ok(Some(rootfs.join(joined(&comps))))
}

/// `mkdir -p` under `rootfs`. Each existing component is opened with
/// openat2; missing ones are created with `mkdirat` on that directory fd
/// and re-opened the same way, so a symlink swapped in after the create
/// is not descended into.
pub fn mkdir_in_rootfs(rootfs: &Path, rel: impl AsRef<Path>) -> Result<PathBuf> {
    let rel = rel.as_ref();
    let comps = components(rel)?;
    if comps.is_empty() {
        bail!("empty in-rootfs path");
    }
    let mut dir = open_root(rootfs)?;
    let mut so_far = PathBuf::new();
    for name in &comps {
        so_far.push(name);
        match open_child(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(next) => dir = next,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                mkdir_at(&dir, name).map_err(|err| explain(err, rel, &so_far))?;
                dir = open_child(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                    .map_err(|err| explain(err, rel, &so_far))?;
            }
            Err(e) => return Err(explain(e, rel, &so_far)),
        }
    }
    Ok(rootfs.join(joined(&comps)))
}

fn mkdir_at(dir: &OwnedFd, name: &OsStr) -> std::io::Result<()> {
    let path = cstr(name).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `path` is a single NUL-terminated component under `dir`.
    let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), path.as_ptr(), 0o755) };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    // Lost a race with another creator. The following openat2 decides
    // whether the winner is a real directory.
    if err.raw_os_error() == Some(libc::EEXIST) {
        Ok(())
    } else {
        Err(err)
    }
}

/// Write `bytes` at `rel`, creating or truncating the leaf. Parents must
/// already be real directories. The leaf is opened with openat2, so a
/// symlink at the leaf is `ELOOP` rather than a write to its target.
pub fn write_in_rootfs(
    rootfs: &Path,
    rel: impl AsRef<Path>,
    bytes: &[u8],
    mode: Option<u32>,
) -> Result<()> {
    let rel = rel.as_ref();
    let comps = components(rel)?;
    let Some((leaf, parents)) = comps.split_last() else {
        bail!("empty in-rootfs path");
    };
    let root = open_root(rootfs)?;
    let parent = open_chain(&root, rel, parents)?.with_context(|| {
        format!(
            "in-rootfs path '{}': a parent does not exist",
            rel.display()
        )
    })?;
    let fd = open_child(
        &parent,
        leaf,
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
        0o666,
    )
    .map_err(|e| explain(e, rel, &joined(&comps)))?;
    let mut f = File::from(fd);
    f.write_all(bytes)
        .with_context(|| format!("write {}", rel.display()))?;
    if let Some(m) = mode {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(m))
            .with_context(|| format!("chmod {:o} {}", m, rel.display()))?;
    }
    Ok(())
}

fn unlink_at(dir: &OwnedFd, name: &OsStr, flags: i32) -> std::io::Result<()> {
    let path = cstr(name).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `path` is a single NUL-terminated component under `dir`.
    let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), path.as_ptr(), flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn list_dir(dir: &OwnedFd) -> Result<Vec<OsString>> {
    // The fd is the directory inode. Listing via /proc keeps the walk on
    // that inode instead of re-resolving the original path.
    let proc = format!("/proc/self/fd/{}", dir.as_raw_fd());
    let mut names = Vec::new();
    for ent in std::fs::read_dir(&proc).with_context(|| format!("read dirfd {}", proc))? {
        names.push(ent?.file_name());
    }
    Ok(names)
}

fn rm_tree(parent: &OwnedFd, name: &OsStr) -> Result<()> {
    match unlink_at(parent, name, 0) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EISDIR) => {}
        Err(e) => {
            return Err(e).with_context(|| format!("rm {}", name.to_string_lossy()));
        }
    }
    let child = open_child(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0).map_err(|e| {
        explain(
            e,
            Path::new(name),
            Path::new(&name.to_string_lossy().into_owned()),
        )
    })?;
    for n in list_dir(&child)? {
        rm_tree(&child, &n)?;
    }
    unlink_at(parent, name, libc::AT_REMOVEDIR)
        .with_context(|| format!("rmdir {}", name.to_string_lossy()))
}

/// Remove the leaf at `rel`. A file or symlink is unlinked (the link
/// itself, never its target). A real directory is removed by walking
/// directory fds. Missing leaf or missing parent → Ok. A symlinked parent
/// is an error.
pub fn remove_in_rootfs(rootfs: &Path, rel: impl AsRef<Path>) -> Result<()> {
    let rel = rel.as_ref();
    let comps = components(rel)?;
    let Some((leaf, parents)) = comps.split_last() else {
        bail!("empty in-rootfs path");
    };
    let root = open_root(rootfs)?;
    let Some(parent) = open_chain(&root, rel, parents)? else {
        return Ok(());
    };
    rm_tree(&parent, leaf)
}

/// Unlink children of the directory `rel` whose names contain `needle`.
/// A missing directory is Ok. A symlink at `rel` is an error — the names
/// are listed from the directory fd, not by following a path.
pub fn remove_children_containing(
    rootfs: &Path,
    rel: impl AsRef<Path>,
    needle: &str,
) -> Result<()> {
    let rel = rel.as_ref();
    let comps = components(rel)?;
    if comps.is_empty() {
        bail!("empty in-rootfs path");
    }
    let root = open_root(rootfs)?;
    let Some(dir) = open_chain(&root, rel, &comps)? else {
        return Ok(());
    };
    for name in list_dir(&dir)? {
        if name.to_string_lossy().contains(needle) {
            let _ = unlink_at(&dir, &name, 0);
        }
    }
    Ok(())
}

/// Create a symlink at `rel` pointing to `target` (stored verbatim — it is
/// an in-container path, never resolved on the host). An existing leaf
/// file/symlink is replaced; a leaf directory is refused.
pub fn symlink_in_rootfs(rootfs: &Path, rel: impl AsRef<Path>, target: &Path) -> Result<()> {
    let rel = rel.as_ref();
    let comps = components(rel)?;
    let Some((leaf, parents)) = comps.split_last() else {
        bail!("empty in-rootfs path");
    };
    let root = open_root(rootfs)?;
    let parent = open_chain(&root, rel, parents)?.with_context(|| {
        format!(
            "in-rootfs path '{}': a parent does not exist",
            rel.display()
        )
    })?;
    match fstat_leaf(&parent, leaf)? {
        Some(st) if is_mode(st.st_mode, libc::S_IFDIR) => {
            bail!(
                "{} is a directory — refusing to replace it with a symlink",
                rel.display()
            )
        }
        Some(_) => {
            unlink_at(&parent, leaf, 0).with_context(|| format!("rm {}", rel.display()))?;
        }
        None => {}
    }
    let from = cstr(leaf)?;
    let to = CString::new(target.as_os_str().as_bytes())
        .context("symlink target contains an interior NUL")?;
    // SAFETY: both pointers are NUL-terminated and `parent` is the
    // directory that will hold the new link. The target is not resolved.
    let rc = unsafe { libc::symlinkat(to.as_ptr(), parent.as_raw_fd(), from.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).with_context(|| format!("symlink {}", rel.display()))
    }
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
        write_in_rootfs(&r, "etc/real", b"r", None).unwrap();
        symlink_in_rootfs(&r, "etc/alias", Path::new("real")).unwrap();
        remove_in_rootfs(&r, "etc/alias").unwrap();
        assert!(r.join("etc/real").exists());
        remove_in_rootfs(&r, "etc/missing/deep").unwrap();
        remove_in_rootfs(&r, "etc/hostname").unwrap();
        assert!(!r.join("etc/hostname").exists());
        assert_eq!(read_file_in_rootfs(&r, "etc/motd").unwrap().unwrap(), b"x");
    }

    /// A rootfs whose `etc` is a symlink to a host dir must turn every
    /// write/mkdir/remove/symlink into an error — and the outside dir
    /// must stay untouched.
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
        assert!(classify(&r, "etc/x").is_err());
        assert!(read_file_in_rootfs(&r, "etc/victim").is_err());

        assert!(!t.outside().join("pwned").exists());
        assert!(!t.outside().join("systemd").exists());
        assert_eq!(std::fs::read(t.outside().join("victim")).unwrap(), b"v");
        assert!(!t.outside().join("l").exists());
    }

    /// A symlink at the leaf is refused on write even when the parents
    /// are honest directories.
    #[test]
    fn leaf_symlink_not_written() {
        let t = Tree::new("leaf");
        let r = t.rootfs();
        std::fs::create_dir_all(r.join("etc")).unwrap();
        std::os::unix::fs::symlink(t.outside().join("target"), r.join("etc/f")).unwrap();
        assert!(write_in_rootfs(&r, "etc/f", b"x", None).is_err());
        assert!(!t.outside().join("target").exists());
        assert_eq!(classify(&r, "etc/f").unwrap(), Leaf::Symlink);
        assert!(read_file_in_rootfs(&r, "etc/f").unwrap().is_none());
    }

    /// Removing a directory unlinks an interior symlink-to-dir. It does
    /// not descend into the outside tree that symlink names.
    #[test]
    fn remove_tree_does_not_follow_symlink_dir() {
        let t = Tree::new("rmtree");
        let r = t.rootfs();
        std::fs::create_dir_all(r.join("nested")).unwrap();
        std::fs::write(t.outside().join("victim"), b"v").unwrap();
        std::os::unix::fs::symlink(t.outside(), r.join("nested/out")).unwrap();
        remove_in_rootfs(&r, "nested").unwrap();
        assert!(!r.join("nested").exists());
        assert_eq!(std::fs::read(t.outside().join("victim")).unwrap(), b"v");
    }
}
