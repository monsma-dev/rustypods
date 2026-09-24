//! Exec: enter a running pod via nsenter on the machined leader pid.
//! tty=true allocates a real host pty (setsid+TIOCSCTTY in the child) so job
//! control and Ctrl-C behave; tty=false uses plain pipes. The exec'd process
//! is moved into the pod's machined scope so MemoryHigh/CPUQuota still apply.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use rustypods_proto::rpc::{exec_chunk::Kind, ExecChunk, ExecExit, ExecStart};
use tokio::io::unix::AsyncFd;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::StreamExt;

type Tx = mpsc::Sender<Result<ExecChunk, tonic::Status>>;

/// Workaround for a util-linux ≤2.42 nsenter bug: `open_cgroup_procs()` (for
/// --join-cgroup) declares `int cgroup_fd = 0` instead of -1, so
/// open_target_fd() close()s fd 0 and the /proc/<pid>/cgroup open() lands on
/// it — every exec'd payload then sees a bogus stdin (/proc/pid/cgroup →
/// instant EOF) while stdout/stderr survive. Fixed upstream to `= -1`, but
/// the hosts we run on are buggy. pre_exec() dup2(0 → STDIN_DUP_FD) preserves
/// real stdin across nsenter's clobber, and the payload wrapper re-dups it
/// back: `exec 0<&9 9<&-; …`. The fd must be single-digit: POSIX sh (dash,
/// Debian's /bin/sh) rejects fd numbers >9 in redirections.
const STDIN_DUP_FD: i32 = 9;

/// A payload that forks a detached child can keep the pty/pipes open after
/// the main process exits — the drain tasks then never see EOF and the
/// exit chunk would never ship. Bound the drain: grace 2s, send exit anyway.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// pre_exec hook: stash the real stdin on a high fd that survives nsenter's
/// fd-0 clobber (dup2 clears CLOEXEC, so it propagates through the
/// nsenter→setpriv→env→sh exec chain).
fn preserve_stdin() -> std::io::Result<()> {
    // SAFETY: dup2 only touches fds; called in pre_exec where fd 0 is the
    // child's real stdin and fd 9 is free in a fresh exec'd process.
    if unsafe { libc::dup2(0, STDIN_DUP_FD) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn chunk_stdout(b: Vec<u8>) -> Result<ExecChunk, tonic::Status> {
    Ok(ExecChunk {
        kind: Some(Kind::Stdout(b)),
    })
}
fn chunk_stderr(b: Vec<u8>) -> Result<ExecChunk, tonic::Status> {
    Ok(ExecChunk {
        kind: Some(Kind::Stderr(b)),
    })
}
fn chunk_exit(code: i32) -> Result<ExecChunk, tonic::Status> {
    Ok(ExecChunk {
        kind: Some(Kind::Exit(ExecExit { code })),
    })
}

/// Resolve an in-image helper binary to its absolute container path. exec
/// argv can't rely on PATH: the daemon's PATH doesn't include /bin, and a
/// minimal OCI image (busybox) may have *only* /bin.
fn image_bin(rootfs: &Path, name: &str) -> Option<String> {
    [
        "bin",
        "sbin",
        "usr/bin",
        "usr/sbin",
        "usr/local/bin",
        "usr/local/sbin",
    ]
    .iter()
    .find(|d| {
        // safe_join_if_exists refuses symlinked intermediates; the leaf
        // check is symlink_metadata (not exists()) so an absolute leaf
        // symlink can't be resolved against the HOST fs.
        matches!(
            crate::rootfs::safe_join_if_exists(rootfs, format!("{d}/{name}")),
            Ok(Some(p)) if p.symlink_metadata().is_ok()
        )
    })
    .map(|d| format!("/{d}/{name}"))
}

/// Is `path` (absolute in-container) a busybox applet — symlink to busybox
/// or a hardlink to the same inode? BusyBox's setpriv lacks --bounding-set
/// and --reuid entirely, so it counts as "no usable setpriv".
fn is_busybox_applet(rootfs: &Path, path: &str) -> bool {
    let Some(f) = crate::rootfs::safe_join_if_exists(rootfs, path.trim_start_matches('/'))
        .ok()
        .flatten()
    else {
        return false;
    };
    if std::fs::read_link(&f)
        .map(|t| t.file_name() == Some(std::ffi::OsStr::new("busybox")))
        .unwrap_or(false)
    {
        return true;
    }
    use std::os::unix::fs::MetadataExt;
    let Some(bb) = crate::rootfs::safe_join_if_exists(rootfs, "bin/busybox")
        .ok()
        .flatten()
    else {
        return false;
    };
    // symlink_metadata for the leaf: symlinks were handled above, and
    // following one could stat a host file.
    match (f.symlink_metadata(), std::fs::metadata(&bb)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// Is locale `loc` (e.g. "nl_NL.UTF-8") usable inside `rootfs`?
/// Per-locale dirs (`usr/lib/locale/<loc>` or the `.UTF-8`→`.utf8`
/// normalized form) prove it on any distro. The glibc
/// `usr/lib/locale/locale-archive` is authoritative elsewhere, but Debian
/// generates it lazily via `locale-gen` — there an uncommented
/// `/etc/locale.gen` line is the evidence.
fn locale_available(rootfs: &Path, loc: &str) -> bool {
    let exists = |rel: &str| -> bool {
        matches!(
            crate::rootfs::safe_join_if_exists(rootfs, rel),
            Ok(Some(p)) if p.exists()
        )
    };
    if exists(&format!("usr/lib/locale/{loc}")) {
        return true;
    }
    let norm = loc.replace(".UTF-8", ".utf8");
    if norm != loc && exists(&format!("usr/lib/locale/{norm}")) {
        return true;
    }
    if !exists("usr/lib/locale/locale-archive") {
        return false;
    }
    if !exists("etc/debian_version") {
        return true;
    }
    let gen = crate::rootfs::safe_join_if_exists(rootfs, "etc/locale.gen")
        .ok()
        .flatten()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();
    gen.lines().any(|l| {
        let l = l.trim_start();
        !l.starts_with('#')
            && l.split_whitespace()
                .next()
                .map(|name| name == loc || name == norm)
                .unwrap_or(false)
    })
}

/// name → (uid, gid, home, shell), parsed from the image's own /etc/passwd.
pub fn passwd_entry(rootfs: &Path, user: &str) -> Option<(u32, u32, String, String)> {
    let p = crate::rootfs::safe_join_if_exists(rootfs, "etc/passwd")
        .ok()
        .flatten()?;
    // The leaf must be a real file — an image-planted `passwd` symlink
    // (e.g. etc -> /host/etc covered by safe_join, but a leaf
    // `passwd -> /etc/passwd`) would make the daemon read a host file.
    if !p.symlink_metadata().ok()?.is_file() {
        return None;
    }
    let text = std::fs::read_to_string(p).ok()?;
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 7 && f[0] == user {
            return Some((
                f[2].parse().ok()?,
                f[3].parse().ok()?,
                f[5].to_string(),
                f[6].to_string(),
            ));
        }
    }
    None
}

/// nspawn's default capability set (man systemd-nspawn --capability=) —
/// exec'd processes get exactly these in the bounding set, no more. Notably
/// absent: sys_module, net_admin, sys_rawio. No --no-new-privs: that would
/// break su/sudo inside the pod.
pub const NSPAWN_DEFAULT_CAPS: &[&str] = &[
    "audit_control",
    "audit_write",
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "ipc_owner",
    "kill",
    "lease",
    "linux_immutable",
    "mknod",
    "net_bind_service",
    "net_broadcast",
    "net_raw",
    "setfcap",
    "setgid",
    "setpcap",
    "setuid",
    "sys_admin",
    "sys_boot",
    "sys_chroot",
    "sys_nice",
    "sys_ptrace",
    "sys_resource",
    "sys_tty_config",
];

/// nsenter argv — pure, testable. `private_users` mirrors the pod's conf:
/// when the pod runs under --private-users=pick, exec must also enter its
/// user namespace or it lands in the wrong uid view.
pub fn exec_argv(
    leader: u32,
    rootfs: &Path,
    start: &ExecStart,
    private_users: bool,
) -> Result<Vec<OsString>> {
    let (uid, gid, home, shell) = if start.user.is_empty() || start.user == "root" {
        (0u32, 0u32, "/root".to_string(), "/bin/sh".to_string())
    } else {
        passwd_entry(rootfs, &start.user)
            .with_context(|| format!("user '{}' not in image passwd", start.user))?
    };
    let mut a: Vec<OsString> = vec![
        "nsenter".into(),
        "--target".into(),
        leader.to_string().into(),
        "--mount".into(),
        "--uts".into(),
        "--ipc".into(),
        "--net".into(),
        "--pid".into(),
    ];
    if private_users {
        a.push("--user".into());
    }
    a.extend([
        // Enter the pod's cgroup view and join the leader's cgroup atomically —
        // children inherit it at fork, so the in-pod agent counts exec'd work
        // and scope limits apply, with no host-side cgroup.procs race.
        "--cgroup".into(),
        "--join-cgroup".into(),
    ]);
    // setpriv lives in the image (util-linux): the cap/uid drop must happen
    // after setns, so it has to run in-container. A busybox setpriv lacks
    // --bounding-set/--reuid — counts as absent.
    let setpriv = image_bin(rootfs, "setpriv").filter(|p| !is_busybox_applet(rootfs, p));
    let env = image_bin(rootfs, "env").context("image has no 'env' binary — exec unsupported")?;
    if setpriv.is_none() {
        if !private_users {
            // Without userns confinement an exec'd process would carry the
            // host's full bounding set (SYS_ADMIN…) — a container escape.
            anyhow::bail!(
                "image has no util-linux setpriv — exec needs --private-users \
                 (bounding-set drop impossible without it)"
            );
        }
        if uid != 0 {
            // nsenter itself switches ids post-setns (supplementary groups
            // are lost; minimal images rarely have any).
            a.push(format!("--setuid={uid}").into());
            a.push(format!("--setgid={gid}").into());
        }
        // The bounding-set drop can't be expressed via nsenter — the exec'd
        // process keeps its inherited set, confined to the pod's userns.
        tracing::warn!(
            "pod {}: image lacks setpriv — exec runs without cap bounding-set drop",
            start.pod
        );
    }
    a.push("--".into());
    if let Some(sp) = setpriv {
        // One setpriv for everyone: drop the bounding set to nspawn's default
        // cap list (nsenter'd processes would otherwise carry host-root's full
        // set), then drop to the target uid/gid when not root.
        a.push(sp.into());
        a.push(format!("--bounding-set=-all,+{}", NSPAWN_DEFAULT_CAPS.join(",+")).into());
        if uid != 0 {
            a.extend([
                format!("--reuid={uid}").into(),
                format!("--regid={gid}").into(),
                "--init-groups".into(),
            ]);
        }
        a.push("--".into());
    }
    a.push(env.into());
    a.push(format!("HOME={home}").into());
    a.push(
        format!(
            "USER={}",
            if start.user.is_empty() {
                "root"
            } else {
                &start.user
            }
        )
        .into(),
    );
    a.push(
        format!(
            "LOGNAME={}",
            if start.user.is_empty() {
                "root"
            } else {
                &start.user
            }
        )
        .into(),
    );
    // A container-default PATH unless the client overrides it — the
    // daemon's own PATH lacks /bin, which is all a minimal OCI image has.
    if !start.env.iter().any(|kv| kv.starts_with("PATH=")) {
        a.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    }
    for kv in &start.env {
        // Must be KEY=VALUE with a POSIX-ish key — anything else (a bare
        // word, or "-i"/"-S x") is an `env` option/command injection.
        let Some((key, value)) = kv.split_once('=') else {
            anyhow::bail!("invalid env entry '{kv}'");
        };
        let key_ok = !key.is_empty()
            && key
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '_')
                .unwrap_or(false)
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !key_ok {
            anyhow::bail!("invalid env entry '{kv}'");
        }
        // A forwarded host LANG/LC_ALL that the rootfs never generated
        // kills locale-aware tools (sphinx-build: locale.Error). C.UTF-8
        // always exists in glibc ≥2.35 — degrade to it.
        if matches!(key, "LANG" | "LC_ALL")
            && !matches!(value, "" | "C" | "POSIX" | "C.UTF-8" | "C.utf8")
            && !locale_available(rootfs, value)
        {
            tracing::debug!(
                "pod {}: {key}={value} not generated in rootfs — downgrading to C.UTF-8",
                start.pod
            );
            a.push(format!("{key}=C.UTF-8").into());
            continue;
        }
        a.push(kv.clone().into());
    }
    // workdir rides in the environment, not the sh -c string — no quoting
    // edge cases on spaces/single quotes in the path.
    if !start.workdir.is_empty() {
        if !start.workdir.starts_with('/') {
            anyhow::bail!("workdir must be an absolute in-container path");
        }
        a.push(format!("RUSTYPODS_WORKDIR={}", start.workdir).into());
    }
    // Restore the real stdin (see STDIN_DUP_FD), then run the payload.
    // `sh -c '…' name args…` puts name in $0 and the rest in $@.
    if start.argv.is_empty() {
        // cd $HOME first (machinectl behavior), then exec login shell.
        a.push("/bin/sh".into());
        a.push("-c".into());
        a.push(
            format!("exec 0<&{STDIN_DUP_FD} {STDIN_DUP_FD}<&-; cd \"${{RUSTYPODS_WORKDIR:-$HOME}}\" && exec \"$0\" \"$@\"")
                .into(),
        );
        a.push(shell.into());
        a.push("-l".into());
    } else {
        a.push("/bin/sh".into());
        a.push("-c".into());
        a.push(
            format!(
                "exec 0<&{STDIN_DUP_FD} {STDIN_DUP_FD}<&-; \
                 if [ -n \"$RUSTYPODS_WORKDIR\" ]; then cd \"$RUSTYPODS_WORKDIR\" || exit 1; fi; \
                 exec \"$0\" \"$@\""
            )
            .into(),
        );
        a.extend(start.argv.iter().map(OsString::from));
    }
    Ok(a)
}

/// Client-supplied winsize dimensions are u32 on the wire; the kernel's
/// are u16. Saturate instead of wrapping.
fn clamp_dim(v: u32) -> u16 {
    u16::try_from(v).unwrap_or(u16::MAX)
}

fn set_winsize(fd: std::os::fd::RawFd, rows: u32, cols: u32) {
    if rows == 0 || cols == 0 {
        return;
    }
    let ws = libc::winsize {
        ws_row: clamp_dim(rows),
        ws_col: clamp_dim(cols),
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads a struct winsize from the pointer we pass;
    // `ws` lives for the call. A bad fd only yields an error we ignore.
    unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
    }
}

/// openpty(3) via libc: master+slave as OwnedFd, optional initial winsize.
/// ptsname_r (not ptsname's static buffer) so concurrent tty execs on the
/// multi-threaded runtime can't open each other's slave; the master is
/// owned from the first line so no error path leaks it.
fn openpty(rows: u32, cols: u32) -> Result<(OwnedFd, OwnedFd)> {
    use std::os::fd::FromRawFd;
    // SAFETY: posix_openpt returns a fresh fd (or -1, checked before we
    // take ownership); nothing else refers to it.
    let m = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if m < 0 {
        return Err(std::io::Error::last_os_error()).context("posix_openpt");
    }
    let master = unsafe { OwnedFd::from_raw_fd(m) };
    // SAFETY: grantpt/unlockpt only operate on the valid master fd.
    if unsafe { libc::grantpt(master.as_raw_fd()) } != 0
        || unsafe { libc::unlockpt(master.as_raw_fd()) } != 0
    {
        return Err(std::io::Error::last_os_error()).context("grantpt/unlockpt");
    }
    set_winsize(master.as_raw_fd(), rows, cols);
    let mut name = [0 as libc::c_char; 64];
    // SAFETY: ptsname_r writes at most `name.len()` bytes into `name` and
    // NUL-terminates on success (returns 0; a positive errno otherwise).
    let rc = unsafe { libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()) };
    if rc != 0 {
        let e = if rc > 0 {
            std::io::Error::from_raw_os_error(rc)
        } else {
            std::io::Error::last_os_error()
        };
        return Err(e).context("ptsname_r");
    }
    // SAFETY: `name` is a NUL-terminated path from ptsname_r.
    let s = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if s < 0 {
        return Err(std::io::Error::last_os_error()).context("open pts slave");
    }
    // SAFETY: `s` is a fresh fd we own exclusively.
    Ok((master, unsafe { OwnedFd::from_raw_fd(s) }))
}

/// pre_exec hook shared by every spawn: stdin preservation (see
/// STDIN_DUP_FD) and an own session/process group. Only async-signal-safe
/// syscalls — no allocation, no locks, no formatting.
fn pre_exec_session(tty: bool) -> std::io::Result<()> {
    preserve_stdin()?;
    // SAFETY: setsid/ioctl are raw syscalls in the freshly forked child.
    unsafe {
        // Own session + process group: kill(-pid) on timeout/disconnect
        // reaches nsenter's forked pod-side child and its descendants.
        if libc::setsid() < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if tty {
            libc::ioctl(0, libc::TIOCSCTTY, 0);
        }
    }
    Ok(())
}

/// nsenter Command from an argv, with the session pre_exec hook. Stdio is
/// the caller's.
fn spawn_cmd(argv: &[OsString], tty: bool) -> std::process::Command {
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    // SAFETY: the closure only calls pre_exec_session (async-signal-safe
    // syscalls, no allocation).
    unsafe {
        cmd.pre_exec(move || pre_exec_session(tty));
    }
    cmd
}

fn set_nonblocking(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    // SAFETY: fcntl F_GETFL/F_SETFL on an fd we own; no memory is touched.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl < 0 || libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// SIGKILL a whole process group (`pgid` = the session leader's pid — the
/// pre_exec setsid makes every spawned nsenter one). Reaches nsenter's
/// forked in-pod child and its descendants; only processes that setsid()
/// themselves escape (documented residual).
pub fn kill_pgrp(pgid: u32) {
    let Ok(p) = i32::try_from(pgid) else {
        return;
    };
    if p <= 0 {
        return;
    }
    // SAFETY: kill(2) with a negative pid targets the group; no memory
    // involved. ESRCH (already gone) is harmless.
    unsafe {
        libc::kill(-p, libc::SIGKILL);
    }
}

/// Kill the session's process group and reap the host-side nsenter.
/// Returns the exit code to report (1 when the status is unavailable).
async fn kill_group_and_wait(child: &mut tokio::process::Child) -> i32 {
    if let Some(pid) = child.id() {
        kill_pgrp(pid);
    }
    let _ = child.kill().await;
    child
        .wait()
        .await
        .map(|s| s.code().unwrap_or(1))
        .unwrap_or(1)
}

/// Run an argv to completion with `Stdio::null()` everywhere, bounded by
/// `timeout` — the exec-healthcheck engine. On timeout the whole process
/// group is killed and nsenter reaped (no zombie, no lingering pod-side
/// probe accumulating every interval). Ok(None) = timed out.
pub async fn run_status(
    argv: &[OsString],
    timeout: Duration,
) -> Result<Option<std::process::ExitStatus>> {
    let mut scmd = spawn_cmd(argv, false);
    scmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut cmd = tokio::process::Command::from(scmd);
    cmd.kill_on_drop(true);
    let mut child = cmd.spawn().context("nsenter spawn")?;
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(st) => Ok(Some(st?)),
        Err(_) => {
            kill_group_and_wait(&mut child).await;
            Ok(None)
        }
    }
}

/// Wire up an exec session. `inbound` is the client stream positioned *after*
/// the ExecStart frame. All output (stdout/stderr + a terminal Exit chunk)
/// flows through `tx`.
pub async fn run<S>(
    start: ExecStart,
    rootfs: &Path,
    leader: u32,
    private_users: bool,
    inbound: S,
    tx: Tx,
) -> Result<()>
where
    S: Stream<Item = Result<ExecChunk, tonic::Status>> + Unpin + Send + 'static,
{
    let argv = exec_argv(leader, rootfs, &start, private_users)?;
    if start.tty {
        run_tty(&argv, &start, inbound, tx).await
    } else {
        run_pipe(&argv, inbound, tx).await
    }
}

/// Write all of `b` to the nonblocking pty master, awaiting writable
/// readiness between partial writes — never parks a runtime worker.
async fn pty_write_all(master: &AsyncFd<std::fs::File>, mut b: &[u8]) -> std::io::Result<()> {
    while !b.is_empty() {
        let mut guard = master.writable().await?;
        match guard.try_io(|inner| inner.get_ref().write(b)) {
            Ok(Ok(0)) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(Ok(n)) => b = &b[n..],
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => {}
        }
    }
    Ok(())
}

async fn run_tty<S>(argv: &[OsString], start: &ExecStart, mut inbound: S, tx: Tx) -> Result<()>
where
    S: Stream<Item = Result<ExecChunk, tonic::Status>> + Unpin + Send + 'static,
{
    let (master, slave) = openpty(start.rows, start.cols)?;
    let slave_in = slave.try_clone().context("slave clone")?;
    let slave_err = slave.try_clone().context("slave clone")?;

    let mut scmd = spawn_cmd(argv, true);
    scmd.stdin(Stdio::from(slave))
        .stdout(Stdio::from(slave_in))
        .stderr(Stdio::from(slave_err));
    let mut cmd = tokio::process::Command::from(scmd);
    cmd.kill_on_drop(true);
    let mut child = cmd.spawn().context("nsenter spawn")?;
    // The Command still owns the parent's slave copies — drop them now so
    // the master sees EIO once the pod side lets go of the pty.
    drop(cmd);

    set_nonblocking(master.as_raw_fd()).context("pty O_NONBLOCK")?;
    let master = Arc::new(AsyncFd::new(std::fs::File::from(master)).context("pty master AsyncFd")?);

    // Reader: pty master → stdout chunks. A tokio task on a nonblocking fd,
    // so the waiter can abort it when the session ends even if a detached
    // in-pod grandchild keeps the slave open (no EIO ever arrives then).
    // `guard.try_io` on the readiness guard we already hold — never await a
    // second readable() inside it (AGENTS.md mesh note).
    let rd = master.clone();
    let tx_r = tx.clone();
    let mut reader = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            let Ok(mut guard) = rd.readable().await else {
                break;
            };
            match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    if tx_r.send(chunk_stdout(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {}
                // EIO = slave side gone (child exited) — normal teardown.
                Ok(Err(_)) => break,
                Err(_would_block) => {}
            }
        }
    });

    // Inbound: stdin bytes → master; winsize → TIOCSWINSZ (kernel raises
    // SIGWINCH on the fg process group). Stream end = client gone: for a
    // tty that's a disconnect (Ctrl-D is data, not EOF) → kill the session,
    // else the remote shell lingers on the open pty.
    let (gone_tx, gone_rx) = tokio::sync::oneshot::channel::<()>();
    let wr = master.clone();
    let writer = tokio::spawn(async move {
        while let Some(Ok(c)) = inbound.next().await {
            match c.kind {
                Some(Kind::Stdin(b)) => {
                    if pty_write_all(&wr, &b).await.is_err() {
                        break;
                    }
                }
                Some(Kind::Winsize(w)) => set_winsize(wr.as_raw_fd(), w.rows, w.cols),
                _ => {}
            }
        }
        let _ = gone_tx.send(());
    });

    // Waiter: child exit OR client disconnect (inbound end / response
    // channel closed) → reader drained → exit chunk LAST (ordering).
    tokio::spawn(async move {
        let code = tokio::select! {
            st = child.wait() => st.map(|s| s.code().unwrap_or(1)).unwrap_or(1),
            _ = gone_rx => kill_group_and_wait(&mut child).await,
            _ = tx.closed() => kill_group_and_wait(&mut child).await,
        };
        // A detached grandchild holding the pty slave means no EIO ever —
        // grace the drain briefly, then stop the reader regardless.
        if tokio::time::timeout(DRAIN_GRACE, &mut reader)
            .await
            .is_err()
        {
            reader.abort();
        }
        let _ = tx.send(chunk_exit(code)).await;
        // Nothing may write to the pty after the session ended; this also
        // releases the last master reference held by a stalled writer.
        writer.abort();
    });
    Ok(())
}

async fn run_pipe<S>(argv: &[OsString], mut inbound: S, tx: Tx) -> Result<()>
where
    S: Stream<Item = Result<ExecChunk, tonic::Status>> + Unpin + Send + 'static,
{
    let mut scmd = spawn_cmd(argv, false);
    scmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut cmd = tokio::process::Command::from(scmd);
    cmd.kill_on_drop(true);
    let mut child = cmd.spawn().context("nsenter spawn")?;
    let mut stdin = child.stdin.take().context("stdin")?;
    let mut stdout = child.stdout.take().context("stdout")?;
    let mut stderr = child.stderr.take().context("stderr")?;

    let tx_out = tx.clone();
    let mut out_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx_out.send(chunk_stdout(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    let tx_err = tx.clone();
    let mut err_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx_err.send(chunk_stderr(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    tokio::spawn(async move {
        while let Some(Ok(c)) = inbound.next().await {
            if let Some(Kind::Stdin(b)) = c.kind {
                use tokio::io::AsyncWriteExt;
                if stdin.write_all(&b).await.is_err() {
                    break;
                }
            }
        }
    });

    // Waiter: child exit OR response-channel-closed (client gone / REST
    // timeout) → kill the whole process group. Note the trigger is
    // tx.closed(), NOT inbound-stream end — a piped payload legitimately
    // outlives its stdin (think `exec -- cat` doing work after EOF), so
    // stdin EOF alone must never kill.
    tokio::spawn(async move {
        let code = tokio::select! {
            st = child.wait() => st.map(|s| s.code().unwrap_or(1)).unwrap_or(1),
            _ = tx.closed() => kill_group_and_wait(&mut child).await,
        };
        // A detached grandchild holding the pipes open stalls both drain
        // tasks forever — bound the wait, then abort them so their `tx`
        // clones drop and the response stream can actually end.
        let drained = async {
            let _ = (&mut out_task).await;
            let _ = (&mut err_task).await;
        };
        if tokio::time::timeout(DRAIN_GRACE, drained).await.is_err() {
            out_task.abort();
            err_task.abort();
        }
        let _ = tx.send(chunk_exit(code)).await;
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn start(user: &str, argv: &[&str]) -> ExecStart {
        ExecStart {
            pod: "dev".into(),
            user: user.into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            tty: false,
            rows: 0,
            cols: 0,
            env: vec!["TERM=xterm".into()],
            workdir: String::new(),
        }
    }

    /// A minimal fake image: bin/env (+ bin/setpriv when asked), a passwd.
    fn fake_rootfs(tag: &str, with_setpriv: bool) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rp-exec-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("bin/env"), b"").unwrap();
        if with_setpriv {
            std::fs::write(dir.join("bin/setpriv"), b"").unwrap();
        }
        std::fs::write(
            dir.join("etc/passwd"),
            "root:x:0:0::/root:/bin/sh\nnick:x:1000:1000::/home/nick:/bin/bash\n",
        )
        .unwrap();
        dir
    }

    #[test]
    fn argv_root_cmd() {
        let dir = fake_rootfs("root", true);
        let a = exec_argv(42, &dir, &start("root", &["echo", "hi"]), false).unwrap();
        let s: Vec<&str> = a.iter().map(|o| o.to_str().unwrap()).collect();
        assert!(s.starts_with(&[
            "nsenter",
            "--target",
            "42",
            "--mount",
            "--uts",
            "--ipc",
            "--net",
            "--pid",
            "--cgroup",
            "--join-cgroup",
            "--"
        ]));
        // helpers resolve to absolute in-container paths
        assert!(s.contains(&"/bin/setpriv"), "everyone gets the cap drop");
        assert!(s.contains(&"/bin/env"));
        assert!(
            !s.iter().any(|x| x.starts_with("--reuid")),
            "root gets no reuid"
        );
        assert!(s.contains(&"HOME=/root"));
        assert!(s.ends_with(&["echo", "hi"]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn argv_cap_drop() {
        let dir = fake_rootfs("cap", true);
        let a = exec_argv(42, &dir, &start("root", &["true"]), false).unwrap();
        let s: Vec<String> = a.iter().map(|o| o.to_string_lossy().into_owned()).collect();
        let bset = s.iter().find(|x| x.starts_with("--bounding-set=")).unwrap();
        assert!(bset.contains("+sys_admin"));
        assert!(!bset.contains("sys_module"));
        assert!(!bset.contains("net_admin"));
        let pu = exec_argv(42, &dir, &start("root", &["true"]), true).unwrap();
        let ps: Vec<String> = pu
            .iter()
            .map(|o| o.to_string_lossy().into_owned())
            .collect();
        assert!(ps.iter().any(|x| x == "--user"));
        assert!(!s.iter().any(|x| x == "--user"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No setpriv in the image (minimal OCI): nsenter carries the uid/gid
    /// switch itself; the cap drop is skipped (logged) — confined to the
    /// pod userns under --private-users, refused without it.
    #[test]
    fn argv_no_setpriv_fallback() {
        let dir = fake_rootfs("nosetpriv", false);
        let a = exec_argv(42, &dir, &start("nick", &["id"]), true).unwrap();
        let s: Vec<String> = a.iter().map(|o| o.to_string_lossy().into_owned()).collect();
        assert!(!s.iter().any(|x| x.contains("setpriv")));
        assert!(s.iter().any(|x| x == "--setuid=1000"));
        assert!(s.iter().any(|x| x == "--setgid=1000"));
        assert!(s.iter().any(|x| *x == "/bin/env"));
        // root on a setpriv-less image: no id switch at all.
        let a = exec_argv(42, &dir, &start("root", &["id"]), true).unwrap();
        let s: Vec<String> = a.iter().map(|o| o.to_string_lossy().into_owned()).collect();
        assert!(!s
            .iter()
            .any(|x| x.starts_with("--setuid") || x.contains("setpriv")));
        // …but without userns confinement it's refused outright.
        assert!(exec_argv(42, &dir, &start("root", &["id"]), false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A busybox setpriv can't do --bounding-set — counts as absent.
    #[test]
    fn busybox_setpriv_is_no_setpriv() {
        let dir = fake_rootfs("bb", false);
        std::fs::write(dir.join("bin/busybox"), b"fake-bb").unwrap();
        std::fs::hard_link(dir.join("bin/busybox"), dir.join("bin/setpriv")).unwrap();
        assert!(exec_argv(42, &dir, &start("root", &["id"]), true).is_ok());
        assert!(exec_argv(42, &dir, &start("root", &["id"]), false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_option_injection_rejected() {
        let dir = fake_rootfs("inj", true);
        let mut s = start("root", &["true"]);
        s.env = vec!["TERM=xterm".into(), "-i".into()];
        assert!(exec_argv(42, &dir, &s, false).is_err());
        s.env = vec!["-S x".into()];
        assert!(exec_argv(42, &dir, &s, false).is_err());
        s.env = vec!["FOO".into()];
        assert!(exec_argv(42, &dir, &s, false).is_err());
        s.env = vec!["A_1=b=c".into()];
        assert!(exec_argv(42, &dir, &s, false).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn argv_user_login_shell() {
        let dir = fake_rootfs("login", true);
        let a = exec_argv(7, &dir, &start("nick", &[]), false).unwrap();
        let s: Vec<&str> = a.iter().map(|o| o.to_str().unwrap()).collect();
        assert!(s.contains(&"--reuid=1000"));
        assert!(s.contains(&"HOME=/home/nick"));
        assert!(s.contains(&"/bin/bash"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A forwarded LANG that the rootfs never generated downgrades to
    /// C.UTF-8; a generated one survives; C-locales are untouched.
    #[test]
    fn lang_downgrades_when_locale_missing() {
        let dir = fake_rootfs("lang", true);
        let mut s = start("root", &["true"]);
        s.env = vec!["LANG=nl_NL.UTF-8".into()];
        let a = exec_argv(42, &dir, &s, false).unwrap();
        let v: Vec<String> = a.iter().map(|o| o.to_string_lossy().into_owned()).collect();
        assert!(v.iter().any(|x| x == "LANG=C.UTF-8"));
        assert!(!v.iter().any(|x| x == "LANG=nl_NL.UTF-8"));

        // Per-locale dir present → kept.
        std::fs::create_dir_all(dir.join("usr/lib/locale/nl_NL.utf8")).unwrap();
        let a = exec_argv(42, &dir, &s, false).unwrap();
        let v: Vec<String> = a.iter().map(|o| o.to_string_lossy().into_owned()).collect();
        assert!(v.iter().any(|x| x == "LANG=nl_NL.UTF-8"));

        // Debian-style: archive + uncommented locale.gen line → kept.
        std::fs::remove_dir_all(dir.join("usr/lib/locale")).unwrap();
        std::fs::create_dir_all(dir.join("usr/lib/locale")).unwrap();
        std::fs::write(dir.join("usr/lib/locale/locale-archive"), b"").unwrap();
        std::fs::write(dir.join("etc/debian_version"), b"forky/sid\n").unwrap();
        let a = exec_argv(42, &dir, &s, false).unwrap();
        let v: Vec<String> = a.iter().map(|o| o.to_string_lossy().into_owned()).collect();
        assert!(
            v.iter().any(|x| x == "LANG=C.UTF-8"),
            "debian: archive alone is not proof"
        );
        std::fs::write(
            dir.join("etc/locale.gen"),
            "# en_US.UTF-8 UTF-8\nnl_NL.UTF-8 UTF-8\n",
        )
        .unwrap();
        let a = exec_argv(42, &dir, &s, false).unwrap();
        let v: Vec<String> = a.iter().map(|o| o.to_string_lossy().into_owned()).collect();
        assert!(
            v.iter().any(|x| x == "LANG=nl_NL.UTF-8"),
            "locale.gen line counts"
        );

        // C and POSIX always exist — pass through untouched.
        s.env = vec!["LANG=C".into(), "LC_ALL=POSIX".into()];
        let a = exec_argv(42, &dir, &s, false).unwrap();
        let v: Vec<String> = a.iter().map(|o| o.to_string_lossy().into_owned()).collect();
        assert!(v.iter().any(|x| x == "LANG=C"));
        assert!(v.iter().any(|x| x == "LC_ALL=POSIX"));

        // Non-debian rootfs: archive presence alone suffices.
        std::fs::remove_file(dir.join("etc/debian_version")).unwrap();
        s.env = vec!["LC_ALL=xx_YY.UTF-8".into()];
        let a = exec_argv(42, &dir, &s, false).unwrap();
        let v: Vec<String> = a.iter().map(|o| o.to_string_lossy().into_owned()).collect();
        assert!(v.iter().any(|x| x == "LC_ALL=xx_YY.UTF-8"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn winsize_dims_saturate() {
        assert_eq!(clamp_dim(0), 0);
        assert_eq!(clamp_dim(24), 24);
        assert_eq!(clamp_dim(65535), 65535);
        assert_eq!(clamp_dim(65536), u16::MAX);
        assert_eq!(clamp_dim(u32::MAX), u16::MAX);
    }

    /// Two ptys opened back to back get distinct slaves (ptsname_r, no
    /// shared static buffer) and the winsize lands on the slave.
    #[test]
    fn openpty_distinct_slaves() {
        let (m1, s1) = openpty(24, 80).unwrap();
        let (m2, s2) = openpty(0, 0).unwrap();
        let ino = |fd: &OwnedFd| {
            use std::os::unix::fs::MetadataExt;
            std::fs::File::from(fd.try_clone().unwrap())
                .metadata()
                .unwrap()
                .ino()
        };
        assert_ne!(ino(&s1), ino(&s2));
        let mut ws = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCGWINSZ fills the winsize we point at.
        let rc = unsafe { libc::ioctl(s1.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
        assert_eq!(rc, 0);
        assert_eq!((ws.ws_row, ws.ws_col), (24, 80));
        set_nonblocking(m1.as_raw_fd()).unwrap();
        drop((m1, m2, s1, s2));
    }

    /// kill_pgrp reaches a grandchild the parent no longer knows about:
    /// `sh -c 'sleep & echo $!; wait'` in its own group via setsid.
    #[test]
    fn kill_pgrp_kills_grandchild() {
        use std::io::BufRead;
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("sleep 30 & echo $!; wait")
            .stdout(Stdio::piped());
        // SAFETY: setsid is a raw syscall in the freshly forked child.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let grandchild: i32 = line.trim().parse().unwrap();
        kill_pgrp(child.id());
        child.wait().unwrap();
        // The orphaned sleep is reaped by init — poll until it's gone.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: kill with signal 0 only probes existence.
            let alive = unsafe { libc::kill(grandchild, 0) } == 0;
            if !alive {
                break;
            }
            // Zombie until init reaps it — /proc State tells the difference.
            let st =
                std::fs::read_to_string(format!("/proc/{grandchild}/status")).unwrap_or_default();
            if st
                .lines()
                .any(|l| l.starts_with("State:") && l.contains('Z'))
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "grandchild {grandchild} survived kill_pgrp"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
