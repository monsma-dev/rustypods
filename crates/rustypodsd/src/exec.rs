//! Exec: enter a running pod via nsenter on the machined leader pid.
//! tty=true allocates a real host pty (setsid+TIOCSCTTY in the child) so job
//! control and Ctrl-C behave; tty=false uses plain pipes. Each exec lives in
//! its own leaf cgroup under the pod scope so MemoryHigh/CPUQuota still apply
//! and a cancel can `cgroup.kill` descendants that called `setsid`.
//!
//! Privilege model: no binary from the pod image ever runs with more
//! privilege than the final target identity. The daemon prepares everything
//! host-side in `pre_exec` (bounding set, NO_NEW_PRIVS, gid + supplementary
//! groups, environment) and nsenter itself performs the uid switch after
//! setns — the first image binary executed is already the target user.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Name prefix for payload env keys that must not sit in the host
/// nsenter's environ; the in-pod wrapper restores the real name.
const ESCAPED_ENV_PREFIX: &str = "RUSTYPODS_ENV_";

/// Keys the host's dynamic loader or glibc act on at nsenter startup
/// (nsenter runs as root on the host fs before it setns()es).
fn loader_sensitive(key: &str) -> bool {
    const PREFIXES: &[&str] = &["LD_", "MALLOC_", "GLIBC_"];
    const EXACT: &[&str] = &[
        "GCONV_PATH",
        "LOCPATH",
        "NLSPATH",
        "HOSTALIASES",
        "RES_OPTIONS",
        "LOCALDOMAIN",
        "TZDIR",
    ];
    PREFIXES.iter().any(|p| key.starts_with(p)) || EXACT.contains(&key)
}

/// pre_exec step: stash the real stdin on a high fd that survives nsenter's
/// fd-0 clobber (dup2 clears CLOEXEC, so it propagates through the
/// nsenter→[setpriv→]sh exec chain).
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
        // classify refuses symlinked intermediates and does not follow a
        // leaf symlink out onto the host.
        crate::rootfs::classify(rootfs, format!("{d}/{name}"))
            .map(|l| l.exists())
            .unwrap_or(false)
    })
    .map(|d| format!("/{d}/{name}"))
}

/// Is `path` (absolute in-container) a busybox applet — symlink to busybox
/// or a hardlink to the same inode? BusyBox's setpriv lacks --bounding-set
/// and --reuid entirely, so it counts as "no usable setpriv".
fn is_busybox_applet(rootfs: &Path, path: &str) -> bool {
    let rel = path.trim_start_matches('/');
    if crate::rootfs::read_link_in_rootfs(rootfs, rel)
        .ok()
        .flatten()
        .as_ref()
        .and_then(|t| t.file_name())
        == Some(std::ffi::OsStr::new("busybox"))
    {
        return true;
    }
    // Hardlink to the busybox inode. Neither stat follows a symlink, so
    // a leaf that points at a host file cannot match.
    let Some(a) = crate::rootfs::inode_in_rootfs(rootfs, rel).ok().flatten() else {
        return false;
    };
    let Some(b) = crate::rootfs::inode_in_rootfs(rootfs, "bin/busybox")
        .ok()
        .flatten()
    else {
        return false;
    };
    a == b
}

/// Is locale `loc` (e.g. "nl_NL.UTF-8") usable inside `rootfs`?
/// Per-locale dirs (`usr/lib/locale/<loc>` or the `.UTF-8`→`.utf8`
/// normalized form) prove it on any distro. The glibc
/// `usr/lib/locale/locale-archive` is authoritative elsewhere, but Debian
/// generates it lazily via `locale-gen` — there an uncommented
/// `/etc/locale.gen` line is the evidence.
fn locale_available(rootfs: &Path, loc: &str) -> bool {
    let exists = |rel: &str| -> bool {
        crate::rootfs::classify(rootfs, rel)
            .map(|l| l.exists())
            .unwrap_or(false)
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
    let gen = crate::rootfs::read_file_in_rootfs(rootfs, "etc/locale.gen")
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
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

/// Read a colon-separated database (`etc/passwd`, `etc/group`) from the
/// image. The leaf must be a regular file. A symlinked parent or a leaf
/// symlink (`passwd -> /etc/passwd`) does not become a host-file read.
fn image_db(rootfs: &Path, rel: &str) -> Option<String> {
    let bytes = crate::rootfs::read_file_in_rootfs(rootfs, rel)
        .ok()
        .flatten()?;
    String::from_utf8(bytes).ok()
}

/// name → (uid, gid, home, shell), parsed from the image's own /etc/passwd.
pub fn passwd_entry(rootfs: &Path, user: &str) -> Option<(u32, u32, String, String)> {
    let text = image_db(rootfs, "etc/passwd")?;
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

/// The supplementary group list initgroups(3) would build for `user` from
/// the image's /etc/group: the primary gid first, then every group listing
/// the user as a member. A missing /etc/group yields just the primary gid.
pub fn supplementary_groups(rootfs: &Path, user: &str, primary_gid: u32) -> Vec<u32> {
    let mut groups = vec![primary_gid];
    if let Some(text) = image_db(rootfs, "etc/group") {
        for line in text.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 4 {
                continue;
            }
            let Ok(gid) = f[2].parse::<u32>() else {
                continue;
            };
            if f[3].split(',').any(|m| m.trim() == user) && !groups.contains(&gid) {
                groups.push(gid);
            }
        }
    }
    groups
}

/// The identity an exec session ends up with inside the pod.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    /// "" from a client means root — implicitly; "root"/"0" is explicit.
    explicit: bool,
    name: String,
    uid: u32,
    gid: u32,
    home: String,
    shell: String,
}

/// Resolve the requested user: image passwd by name, or a bare numeric uid
/// (uid == gid, home `/`, `/bin/sh`) so probes can run as `65534` on images
/// without a `nobody` entry.
fn resolve_target(rootfs: &Path, user: &str) -> Result<Target> {
    if user.is_empty() || user == "root" || user == "0" {
        return Ok(Target {
            explicit: !user.is_empty(),
            name: "root".into(),
            uid: 0,
            gid: 0,
            home: "/root".into(),
            shell: "/bin/sh".into(),
        });
    }
    if let Some((uid, gid, home, shell)) = passwd_entry(rootfs, user) {
        return Ok(Target {
            explicit: true,
            name: user.into(),
            uid,
            gid,
            home,
            shell,
        });
    }
    if let Ok(uid) = user.parse::<u32>() {
        return Ok(Target {
            explicit: true,
            name: user.into(),
            uid,
            gid: uid,
            home: "/".into(),
            shell: "/bin/sh".into(),
        });
    }
    anyhow::bail!("user '{user}' not in image passwd")
}

/// Default identity for exec healthchecks in pods WITHOUT a user namespace:
/// there "root" would be host root, so probes run as `nobody` when the image
/// has one, else as bare uid 65534.
pub fn default_probe_user(rootfs: &Path) -> String {
    if passwd_entry(rootfs, "nobody").is_some() {
        "nobody".into()
    } else {
        "65534".into()
    }
}

/// Linux capability numbers (uapi/linux/capability.h) — stable ABI, and the
/// libc crate doesn't export them. Used for the daemon-side bounding-set
/// drop; names match setpriv/nspawn spelling.
const CAP_NUMBERS: &[(&str, u32)] = &[
    ("chown", 0),
    ("dac_override", 1),
    ("dac_read_search", 2),
    ("fowner", 3),
    ("fsetid", 4),
    ("kill", 5),
    ("setgid", 6),
    ("setuid", 7),
    ("setpcap", 8),
    ("linux_immutable", 9),
    ("net_bind_service", 10),
    ("net_broadcast", 11),
    ("net_admin", 12),
    ("net_raw", 13),
    ("ipc_lock", 14),
    ("ipc_owner", 15),
    ("sys_module", 16),
    ("sys_rawio", 17),
    ("sys_chroot", 18),
    ("sys_ptrace", 19),
    ("sys_pacct", 20),
    ("sys_admin", 21),
    ("sys_boot", 22),
    ("sys_nice", 23),
    ("sys_resource", 24),
    ("sys_time", 25),
    ("sys_tty_config", 26),
    ("mknod", 27),
    ("lease", 28),
    ("audit_write", 29),
    ("audit_control", 30),
    ("setfcap", 31),
    ("mac_override", 32),
    ("mac_admin", 33),
    ("syslog", 34),
    ("wake_alarm", 35),
    ("block_suspend", 36),
    ("audit_read", 37),
    ("perfmon", 38),
    ("bpf", 39),
    ("checkpoint_restore", 40),
];

/// Highest capability number we try to drop. Kernels with a lower
/// cap_last_cap answer EINVAL for the excess — ignored on purpose, so a
/// newer kernel's additions are still dropped.
const CAP_DROP_MAX: u32 = 63;

/// Bitmask of capability numbers to keep in the bounding set (nspawn's
/// default set); everything else is dropped daemon-side before nsenter
/// execs. nsenter itself only needs sys_admin, sys_ptrace, setuid, setgid
/// and dac_override — all inside the kept set.
fn bounding_keep_mask() -> u64 {
    CAP_NUMBERS
        .iter()
        .filter(|(name, _)| NSPAWN_DEFAULT_CAPS.contains(name))
        .fold(0u64, |m, (_, n)| m | (1u64 << n))
}

/// nspawn's default capability set (man systemd-nspawn --capability=) —
/// exec'd processes get exactly these in the bounding set, no more. Notably
/// absent: sys_module, net_admin, sys_rawio.
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

/// Everything needed to spawn one exec session: the nsenter argv, the
/// environment nsenter passes through to the payload, and the daemon-side
/// `pre_exec` identity work. Pure and testable — `command()` turns it into
/// a `std::process::Command`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPlan {
    /// argv[0] is the bare `nsenter`; `command()` resolves it on the HOST
    /// PATH (never the container PATH in `env`).
    pub argv: Vec<OsString>,
    /// Payload environment. Set daemon-side via env_clear()+envs() instead
    /// of running the image's `env` binary; nsenter execvp()s with environ.
    pub env: Vec<(String, String)>,
    /// Daemon-side setgid + setgroups before nsenter (non-userns pods,
    /// non-root target). nsenter's own `--setgid` would setgroups(0) first
    /// and lose the supplementary list; a bare `--setuid` doesn't touch
    /// gids at all (verified in util-linux 2.41 nsenter.c main()).
    pub gid: Option<u32>,
    pub groups: Vec<u32>,
    /// PR_SET_NO_NEW_PRIVS: inherited through nsenter's exec, so setuid-root
    /// binaries in the pod can't regain caps. Applied in pods without a
    /// user namespace, where "root" is host root; userns pods keep su/sudo
    /// working — a setuid binary there only reaches pod root, which the
    /// same caller can request with `--user root` anyway.
    pub no_new_privs: bool,
    /// The payload runs as host root (non-userns pod, explicit `root`) —
    /// the caller logs the warning.
    pub host_root: bool,
    /// Machined leader pid. The exec leaf is created beside its cgroup.
    leader: u32,
}

/// Build the exec plan. `private_users` mirrors the pod's conf: when the
/// pod runs under --private-users=pick, exec must also enter its user
/// namespace or it lands in the wrong uid view.
///
/// Identity switching per case (see module docs):
/// - non-root target, no userns: pre_exec setgid+setgroups (host ids ==
///   pod ids), then `nsenter --setuid=<uid>` drops caps after setns.
/// - non-root target, userns: `nsenter --user --setuid --setgid` after
///   entering the pod userns (ids are pod-relative; supplementary groups
///   are lost — nsenter setgroups(0)s whenever it sets a gid).
/// - root target, userns: nsenter's default uid/gid 0 inside the userns;
///   the image's setpriv (running as pod root, post-userns — same trust
///   domain as the target) restores nspawn's bounding set when present.
/// - root target, no userns: host root minus nspawn's bounding set, with
///   NO_NEW_PRIVS. Requires an explicit `root`; trusted code only.
pub fn exec_plan(
    leader: u32,
    rootfs: &Path,
    start: &ExecStart,
    private_users: bool,
) -> Result<ExecPlan> {
    let t = resolve_target(rootfs, &start.user)?;
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
        // Enter the pod's cgroup namespace. Do not pass --join-cgroup: that
        // migrates the payload into the leader's own cgroup (the pod), so a
        // later cgroup.kill would take the pod down and a setsid() payload
        // would leave the process group we can signal. Membership is the
        // ephemeral leaf created in `ExecCgroup`, attached in pre_exec.
        "--cgroup".into(),
    ]);
    let mut gid = None;
    let mut groups = Vec::new();
    let mut setpriv = None;
    let host_root = t.uid == 0 && !private_users;
    if t.uid != 0 {
        a.push(format!("--setuid={}", t.uid).into());
        if private_users {
            a.push(format!("--setgid={}", t.gid).into());
        } else {
            gid = Some(t.gid);
            groups = supplementary_groups(rootfs, &t.name, t.gid);
        }
    } else if private_users {
        // A busybox setpriv lacks --bounding-set — counts as absent; the
        // process then keeps the full (userns-confined) bounding set.
        setpriv = image_bin(rootfs, "setpriv").filter(|p| !is_busybox_applet(rootfs, p));
        if setpriv.is_none() {
            tracing::debug!(
                "pod {}: image lacks setpriv — root exec keeps the userns bounding set",
                start.pod
            );
        }
    } else if !t.explicit {
        anyhow::bail!(
            "pod '{}' runs without a user namespace — root there is HOST root. \
             Pass an explicit user (`--user root` to accept; trusted code only)",
            start.pod
        );
    }
    a.push("--".into());
    if let Some(sp) = setpriv {
        a.push(sp.into());
        a.push(format!("--bounding-set=-all,+{}", NSPAWN_DEFAULT_CAPS.join(",+")).into());
        a.push("--".into());
    }
    let mut escaped: Vec<String> = Vec::new();
    let mut env: Vec<(String, String)> = vec![
        ("HOME".into(), t.home.clone()),
        ("USER".into(), t.name.clone()),
        ("LOGNAME".into(), t.name.clone()),
    ];
    // A container-default PATH unless the client overrides it — the
    // daemon's own PATH lacks /bin, which is all a minimal OCI image has.
    if !start.env.iter().any(|kv| kv.starts_with("PATH=")) {
        env.push((
            "PATH".into(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        ));
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
            env.push((key.into(), "C.UTF-8".into()));
            continue;
        }
        if loader_sensitive(key) {
            // The environ first reaches the HOST nsenter (root, before
            // setns): ld.so would honor LD_PRELOAD/GLIBC_TUNABLES/… from
            // a host path. Carry it under an inert name and export it
            // from the in-pod shell instead.
            env.push((format!("{ESCAPED_ENV_PREFIX}{key}"), value.into()));
            escaped.push(key.to_string());
            continue;
        }
        env.push((key.into(), value.into()));
    }
    // Keys are validated [A-Za-z_][A-Za-z0-9_]* above — safe to splice.
    let reexport: String = escaped
        .iter()
        .map(|k| {
            format!("export {k}=\"${ESCAPED_ENV_PREFIX}{k}\"; unset {ESCAPED_ENV_PREFIX}{k}; ")
        })
        .collect();
    // workdir rides in the environment, not the sh -c string — no quoting
    // edge cases on spaces/single quotes in the path.
    if !start.workdir.is_empty() {
        if !start.workdir.starts_with('/') {
            anyhow::bail!("workdir must be an absolute in-container path");
        }
        env.push(("RUSTYPODS_WORKDIR".into(), start.workdir.clone()));
    }
    // Restore the real stdin (see STDIN_DUP_FD), then run the payload.
    // `sh -c '…' name args…` puts name in $0 and the rest in $@.
    if start.argv.is_empty() {
        // cd $HOME first (machinectl behavior), then exec login shell.
        a.push("/bin/sh".into());
        a.push("-c".into());
        a.push(
            format!("exec 0<&{STDIN_DUP_FD} {STDIN_DUP_FD}<&-; {reexport}cd \"${{RUSTYPODS_WORKDIR:-$HOME}}\" && exec \"$0\" \"$@\"")
                .into(),
        );
        a.push(t.shell.clone().into());
        a.push("-l".into());
    } else {
        a.push("/bin/sh".into());
        a.push("-c".into());
        a.push(
            format!(
                "exec 0<&{STDIN_DUP_FD} {STDIN_DUP_FD}<&-; {reexport}\
                 if [ -n \"$RUSTYPODS_WORKDIR\" ]; then cd \"$RUSTYPODS_WORKDIR\" || exit 1; fi; \
                 exec \"$0\" \"$@\""
            )
            .into(),
        );
        a.extend(start.argv.iter().map(OsString::from));
    }
    Ok(ExecPlan {
        argv: a,
        env,
        gid,
        groups,
        no_new_privs: !private_users,
        host_root,
        leader,
    })
}

/// Locate nsenter on the daemon's own PATH (fallback: the usual system
/// dirs). The payload PATH in `ExecPlan::env` is a CONTAINER path and must
/// never drive a host binary lookup — with env_clear() std would otherwise
/// search the child's PATH.
pub fn host_nsenter() -> PathBuf {
    let dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    dirs.iter()
        .map(|d| d.join("nsenter"))
        .chain(
            ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
                .iter()
                .map(|d| Path::new(d).join("nsenter")),
        )
        .find(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("/usr/bin/nsenter"))
}

/// Move this process into `cgroup.procs` (`fd` opened by the parent).
/// Async-signal-safe: `getpid` + `write` only, pid rendered on the stack.
fn write_self_to_cgroup(fd: RawFd) -> std::io::Result<()> {
    let pid = unsafe { libc::getpid() };
    if pid <= 0 {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut n = pid as u32;
    let mut buf = [0u8; 16];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let bytes = &buf[i..];
    let mut off = 0;
    while off < bytes.len() {
        let rc = unsafe { libc::write(fd, bytes[off..].as_ptr().cast(), bytes.len() - off) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if rc == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        off += rc as usize;
    }
    Ok(())
}

/// The pre_exec identity/privilege work, as a plain function so it stays
/// obviously async-signal-safe: only raw syscalls, no allocation, no locks,
/// no formatting. `groups` must outlive the closure that calls this.
///
/// Order matters: the bounding-set drop needs CAP_SETPCAP (kept), the
/// setgroups/setgid need CAP_SETGID (kept, still effective until exec).
/// NO_NEW_PRIVS last — it's a task flag, unaffected by setns/exec/setuid.
fn pre_exec_identity(
    tty: bool,
    gid: Option<u32>,
    groups: &[libc::gid_t],
    no_new_privs: bool,
) -> std::io::Result<()> {
    preserve_stdin()?;
    // SAFETY: setsid/ioctl/setgroups/setgid/prctl are raw syscalls on the
    // freshly forked child; `groups` is a live slice for the duration of
    // the call. All are async-signal-safe (signal-safety(7)).
    unsafe {
        // Own session + process group: kill(-pid) on timeout/disconnect
        // reaches nsenter's forked pod-side child and its descendants.
        if libc::setsid() < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if tty {
            libc::ioctl(0, libc::TIOCSCTTY, 0);
        }
        if let Some(g) = gid {
            if libc::setgroups(groups.len(), groups.as_ptr()) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(g) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        let keep = bounding_keep_mask();
        for cap in 0..=CAP_DROP_MAX {
            if keep & (1u64 << cap) != 0 {
                continue;
            }
            if libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) < 0 {
                let e = std::io::Error::last_os_error();
                // EINVAL = beyond this kernel's cap_last_cap.
                if e.raw_os_error() != Some(libc::EINVAL) {
                    return Err(e);
                }
            }
        }
        if no_new_privs && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

impl ExecPlan {
    /// A ready-to-spawn Command: host nsenter, cleared environment replaced
    /// by `env`, and the identity pre_exec hook. Stdio is the caller's.
    pub fn command(&self, tty: bool) -> std::process::Command {
        self.command_in(tty, None)
    }

    /// Like `command`, and when `cgroup_procs` is set the child moves itself
    /// into that cgroup before `setgid` (still root, still async-signal-safe).
    fn command_in(&self, tty: bool, cgroup_procs: Option<RawFd>) -> std::process::Command {
        let mut cmd = std::process::Command::new(host_nsenter());
        cmd.args(&self.argv[1..])
            .env_clear()
            .envs(self.env.iter().cloned());
        let gid = self.gid;
        let groups: Vec<libc::gid_t> = self.groups.clone();
        let nnp = self.no_new_privs;
        // SAFETY: the closure only calls write_self_to_cgroup and
        // pre_exec_identity: async-signal-safe syscalls over data owned by
        // the closure (no allocation, no locks).
        unsafe {
            cmd.pre_exec(move || {
                if let Some(fd) = cgroup_procs {
                    write_self_to_cgroup(fd)?;
                }
                pre_exec_identity(tty, gid, &groups, nnp)
            });
        }
        cmd
    }
}

static EXEC_CGROUP_SEQ: AtomicU64 = AtomicU64::new(1);

/// One leaf cgroup per exec. Cancel writes `cgroup.kill`, which SIGKILLs
/// every member regardless of session — a payload that `setsid()`s stays
/// in this leaf because we do not pass `--join-cgroup`.
struct ExecCgroup {
    dir: PathBuf,
    procs: OwnedFd,
    /// Set on a normal exit so Drop does not kill a payload that
    /// intentionally outlived its parent. Cancel leaves it set.
    kill_on_drop: bool,
}

/// Parent directory of the leader's cgroup, so the leaf sits beside
/// `init.scope` and stays under the pod's MemoryHigh/CPUQuota.
fn pod_cgroup_parent(leader: u32) -> Option<PathBuf> {
    let text = std::fs::read_to_string(format!("/proc/{leader}/cgroup")).ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?;
    if !rel.starts_with('/') || rel.split('/').any(|s| s == "..") {
        return None;
    }
    let dir = PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    let parent = dir.parent()?.to_path_buf();
    if parent.starts_with("/sys/fs/cgroup") && parent.is_dir() {
        Some(parent)
    } else {
        None
    }
}

impl ExecCgroup {
    fn create(leader: u32) -> Result<Self> {
        let id = EXEC_CGROUP_SEQ.fetch_add(1, Ordering::Relaxed);
        let name = format!("rustypods-exec-{}-{id}", std::process::id());
        let parent = pod_cgroup_parent(leader).unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup"));
        let dir = parent.join(&name);
        if std::fs::create_dir(&dir).is_ok() {
            return Self::open(dir);
        }
        let fallback = PathBuf::from("/sys/fs/cgroup").join(&name);
        if fallback != dir {
            tracing::warn!(
                leader,
                parent = %parent.display(),
                "exec leaf under the pod cgroup failed; using the cgroup root"
            );
            std::fs::create_dir(&fallback)
                .with_context(|| format!("create {}", fallback.display()))?;
            return Self::open(fallback);
        }
        std::fs::create_dir(&dir).with_context(|| format!("create {}", dir.display()))?;
        Self::open(dir)
    }

    fn open(dir: PathBuf) -> Result<Self> {
        let file = match std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("cgroup.procs"))
        {
            Ok(f) => f,
            Err(e) => {
                let _ = std::fs::remove_dir(&dir);
                return Err(e).with_context(|| format!("open {}/cgroup.procs", dir.display()));
            }
        };
        Ok(Self {
            dir,
            procs: file.into(),
            kill_on_drop: true,
        })
    }

    fn raw_fd(&self) -> RawFd {
        self.procs.as_raw_fd()
    }

    fn kill_members(&self) {
        let _ = std::fs::write(self.dir.join("cgroup.kill"), b"1");
    }

    fn disarm(&mut self) {
        self.kill_on_drop = false;
    }
}

impl Drop for ExecCgroup {
    fn drop(&mut self) {
        let kill = self.kill_on_drop;
        if kill {
            self.kill_members();
        }
        let dir = std::mem::take(&mut self.dir);
        if dir.as_os_str().is_empty() || std::fs::remove_dir(&dir).is_ok() {
            return;
        }
        // A normal exit may leave an intentional daemon in the leaf. Only
        // the cancel path expects the directory to drain.
        if !kill {
            return;
        }
        std::thread::spawn(move || {
            for _ in 0..50 {
                std::thread::sleep(Duration::from_millis(20));
                if std::fs::remove_dir(&dir).is_ok() {
                    return;
                }
            }
            tracing::warn!(path = %dir.display(), "exec cgroup leftover after kill");
        });
    }
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
/// forked in-pod child and its descendants. A payload that setsid()s itself
/// leaves this group; `ExecCgroup::kill_members` is what still reaches it.
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

/// Kill the exec cgroup and the session's process group, then reap nsenter.
/// Returns the exit code to report (1 when the status is unavailable).
async fn kill_group_and_wait(child: &mut tokio::process::Child, cgroup: &ExecCgroup) -> i32 {
    cgroup.kill_members();
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

/// Run a plan to completion with `Stdio::null()` everywhere, bounded by
/// `timeout` — the exec-healthcheck engine. On timeout the whole process
/// group is killed and nsenter reaped (no zombie, no lingering pod-side
/// probe accumulating every interval). Ok(None) = timed out.
pub async fn run_status(
    plan: &ExecPlan,
    timeout: Duration,
) -> Result<Option<std::process::ExitStatus>> {
    let mut cgroup = ExecCgroup::create(plan.leader)?;
    let mut scmd = plan.command_in(false, Some(cgroup.raw_fd()));
    scmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut cmd = tokio::process::Command::from(scmd);
    cmd.kill_on_drop(true);
    let mut child = cmd.spawn().context("nsenter spawn")?;
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(st) => {
            cgroup.disarm();
            Ok(Some(st?))
        }
        Err(_) => {
            kill_group_and_wait(&mut child, &cgroup).await;
            Ok(None)
        }
    }
}

/// Wire up an exec session. `inbound` is the client stream positioned *after*
/// the ExecStart frame. All output (stdout/stderr + a terminal Exit chunk)
/// flows through `tx`. `allow_setuid` is the pod conf opt-in that lifts
/// NO_NEW_PRIVS (see `PodMeta::allow_setuid`).
pub async fn run<S>(
    start: ExecStart,
    rootfs: &Path,
    leader: u32,
    private_users: bool,
    allow_setuid: bool,
    inbound: S,
    tx: Tx,
) -> Result<()>
where
    S: Stream<Item = Result<ExecChunk, tonic::Status>> + Unpin + Send + 'static,
{
    let mut plan = exec_plan(leader, rootfs, &start, private_users)?;
    plan.no_new_privs &= !allow_setuid;
    if plan.host_root {
        tracing::warn!(
            "pod {}: exec as root in a pod without a user namespace — payload runs as HOST \
             root (nspawn bounding set, no seccomp); trusted code only",
            start.pod
        );
    }
    if start.tty {
        run_tty(&plan, &start, inbound, tx).await
    } else {
        run_pipe(&plan, inbound, tx).await
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

async fn run_tty<S>(plan: &ExecPlan, start: &ExecStart, mut inbound: S, tx: Tx) -> Result<()>
where
    S: Stream<Item = Result<ExecChunk, tonic::Status>> + Unpin + Send + 'static,
{
    let (master, slave) = openpty(start.rows, start.cols)?;
    let slave_in = slave.try_clone().context("slave clone")?;
    let slave_err = slave.try_clone().context("slave clone")?;

    let mut cgroup = ExecCgroup::create(plan.leader)?;
    let mut scmd = plan.command_in(true, Some(cgroup.raw_fd()));
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
        let mut normal_exit = false;
        let code = tokio::select! {
            st = child.wait() => {
                normal_exit = true;
                st.map(|s| s.code().unwrap_or(1)).unwrap_or(1)
            }
            _ = gone_rx => kill_group_and_wait(&mut child, &cgroup).await,
            _ = tx.closed() => kill_group_and_wait(&mut child, &cgroup).await,
        };
        if normal_exit {
            cgroup.disarm();
        }
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

async fn run_pipe<S>(plan: &ExecPlan, mut inbound: S, tx: Tx) -> Result<()>
where
    S: Stream<Item = Result<ExecChunk, tonic::Status>> + Unpin + Send + 'static,
{
    let mut cgroup = ExecCgroup::create(plan.leader)?;
    let mut scmd = plan.command_in(false, Some(cgroup.raw_fd()));
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
        let mut normal_exit = false;
        let code = tokio::select! {
            st = child.wait() => {
                normal_exit = true;
                st.map(|s| s.code().unwrap_or(1)).unwrap_or(1)
            }
            _ = tx.closed() => kill_group_and_wait(&mut child, &cgroup).await,
        };
        if normal_exit {
            cgroup.disarm();
        }
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

    /// A minimal fake image: bin/env (+ bin/setpriv when asked), a passwd
    /// and a group file with one supplementary group for nick.
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
        std::fs::write(
            dir.join("etc/group"),
            "root:x:0:\nwheel:x:998:nick\nvideo:x:985:alice,nick\nnick:x:1000:\naudio:x:995:alice\n",
        )
        .unwrap();
        dir
    }

    fn strs(p: &ExecPlan) -> Vec<String> {
        p.argv
            .iter()
            .map(|o| o.to_string_lossy().into_owned())
            .collect()
    }

    fn env_of<'a>(p: &'a ExecPlan, key: &str) -> Option<&'a str> {
        p.env
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    const NS_PREFIX: &[&str] = &[
        "nsenter", "--target", "42", "--mount", "--uts", "--ipc", "--net", "--pid",
    ];

    /// Explicit root in a non-userns pod: host root, no image binary before
    /// the payload, nspawn bounding set + NO_NEW_PRIVS from the daemon side.
    #[test]
    fn plan_explicit_root_no_userns() {
        let dir = fake_rootfs("root", true);
        let p = exec_plan(42, &dir, &start("root", &["echo", "hi"]), false).unwrap();
        let s = strs(&p);
        assert_eq!(&s[..NS_PREFIX.len()], NS_PREFIX);
        assert_eq!(&s[8..10], &["--cgroup", "--"]);
        assert!(
            !s.iter()
                .any(|x| x.contains("setpriv") || x.contains("/env")),
            "no image helper may run as host root: {s:?}"
        );
        assert!(!s.iter().any(|x| x.starts_with("--setuid")));
        assert_eq!(s[10], "/bin/sh");
        assert!(s.ends_with(&["echo".into(), "hi".into()]));
        assert!(p.host_root);
        assert!(p.no_new_privs);
        assert_eq!(p.gid, None);
        assert_eq!(env_of(&p, "HOME"), Some("/root"));
        assert_eq!(env_of(&p, "USER"), Some("root"));
        assert_eq!(env_of(&p, "TERM"), Some("xterm"));
        // "0" counts as explicit too.
        assert!(exec_plan(42, &dir, &start("0", &["true"]), false).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Implicit root ("" from REST/probes) in a non-userns pod is refused —
    /// it would silently be host root.
    #[test]
    fn plan_implicit_root_no_userns_refused() {
        let dir = fake_rootfs("implicit", true);
        let e = exec_plan(42, &dir, &start("", &["true"]), false).unwrap_err();
        assert!(e.to_string().contains("HOST root"), "{e}");
        // …while a userns pod still treats "" as (pod) root.
        let p = exec_plan(42, &dir, &start("", &["true"]), true).unwrap();
        assert!(!p.host_root);
        assert!(strs(&p).iter().any(|x| x == "--user"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Non-root target without userns: nsenter's bare --setuid drops caps
    /// after setns; gid + supplementary groups come from pre_exec (nsenter
    /// --setgid would setgroups(0) them away).
    #[test]
    fn plan_user_no_userns() {
        let dir = fake_rootfs("user", true);
        let p = exec_plan(42, &dir, &start("nick", &["id"]), false).unwrap();
        let s = strs(&p);
        assert!(s.iter().any(|x| x == "--setuid=1000"));
        assert!(!s.iter().any(|x| x.starts_with("--setgid")));
        assert!(!s.iter().any(|x| x == "--user"));
        assert!(!s
            .iter()
            .any(|x| x.contains("setpriv") || x.contains("/env")));
        assert_eq!(p.gid, Some(1000));
        assert_eq!(p.groups, vec![1000, 998, 985]);
        assert!(p.no_new_privs);
        assert!(!p.host_root);
        assert_eq!(env_of(&p, "HOME"), Some("/home/nick"));
        assert_eq!(env_of(&p, "USER"), Some("nick"));
        assert_eq!(env_of(&p, "LOGNAME"), Some("nick"));
        assert!(env_of(&p, "PATH").unwrap().contains("/usr/bin"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Non-root target with userns: nsenter sets both ids inside the pod
    /// userns (pod-relative), no daemon-side gid work, no NO_NEW_PRIVS.
    #[test]
    fn plan_user_userns() {
        let dir = fake_rootfs("useru", true);
        let p = exec_plan(42, &dir, &start("nick", &["id"]), true).unwrap();
        let s = strs(&p);
        assert!(s.iter().any(|x| x == "--user"));
        assert!(s.iter().any(|x| x == "--setuid=1000"));
        assert!(s.iter().any(|x| x == "--setgid=1000"));
        assert!(!s.iter().any(|x| x.contains("setpriv")));
        assert_eq!(p.gid, None);
        assert!(p.groups.is_empty());
        assert!(!p.no_new_privs);
        assert!(!p.host_root);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Root target with userns: image setpriv (post-userns, as pod root)
    /// restores nspawn's bounding set when present; absent = still fine.
    #[test]
    fn plan_root_userns_bounding_set() {
        let dir = fake_rootfs("rootu", true);
        let p = exec_plan(42, &dir, &start("root", &["true"]), true).unwrap();
        let s = strs(&p);
        assert!(s.iter().any(|x| x == "--user"));
        let i = s.iter().position(|x| x == "/bin/setpriv").unwrap();
        assert!(
            i > s.iter().position(|x| x == "--").unwrap(),
            "after nsenter's --"
        );
        let bset = s.iter().find(|x| x.starts_with("--bounding-set=")).unwrap();
        assert!(bset.contains("+sys_admin"));
        assert!(!bset.contains("sys_module"));
        assert!(!bset.contains("net_admin"));
        assert!(!s.iter().any(|x| x.starts_with("--setuid")));
        assert!(!p.host_root);

        let dir2 = fake_rootfs("rootu2", false);
        let p = exec_plan(42, &dir2, &start("root", &["true"]), true).unwrap();
        assert!(!strs(&p).iter().any(|x| x.contains("setpriv")));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    /// A busybox setpriv can't do --bounding-set — counts as absent.
    #[test]
    fn busybox_setpriv_is_no_setpriv() {
        let dir = fake_rootfs("bb", false);
        std::fs::write(dir.join("bin/busybox"), b"fake-bb").unwrap();
        std::fs::hard_link(dir.join("bin/busybox"), dir.join("bin/setpriv")).unwrap();
        let p = exec_plan(42, &dir, &start("root", &["id"]), true).unwrap();
        assert!(!strs(&p).iter().any(|x| x.contains("setpriv")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Images without setpriv/env no longer block exec — nothing from the
    /// image runs before the payload anymore.
    #[test]
    fn plan_needs_no_image_helpers() {
        let dir = fake_rootfs("bare", false);
        std::fs::remove_file(dir.join("bin/env")).unwrap();
        assert!(exec_plan(42, &dir, &start("nick", &["id"]), false).is_ok());
        assert!(exec_plan(42, &dir, &start("root", &["id"]), false).is_ok());
        assert!(exec_plan(42, &dir, &start("nick", &["id"]), true).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Numeric users not in passwd resolve to uid==gid, `/`, /bin/sh;
    /// unknown names are refused.
    #[test]
    fn numeric_user_fallback() {
        let dir = fake_rootfs("num", false);
        let p = exec_plan(42, &dir, &start("65534", &["true"]), false).unwrap();
        assert!(strs(&p).iter().any(|x| x == "--setuid=65534"));
        assert_eq!(p.gid, Some(65534));
        assert_eq!(p.groups, vec![65534]);
        assert_eq!(env_of(&p, "HOME"), Some("/"));
        assert!(exec_plan(42, &dir, &start("ghost", &["true"]), false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn probe_user_default() {
        let dir = fake_rootfs("probe", false);
        assert_eq!(default_probe_user(&dir), "65534");
        std::fs::write(
            dir.join("etc/passwd"),
            "root:x:0:0::/root:/bin/sh\nnobody:x:65534:65534::/:/usr/sbin/nologin\n",
        )
        .unwrap();
        assert_eq!(default_probe_user(&dir), "nobody");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn supplementary_groups_parse() {
        let dir = fake_rootfs("groups", false);
        assert_eq!(
            supplementary_groups(&dir, "nick", 1000),
            vec![1000, 998, 985]
        );
        assert_eq!(supplementary_groups(&dir, "alice", 7), vec![7, 985, 995]);
        assert_eq!(supplementary_groups(&dir, "nobody", 65534), vec![65534]);
        std::fs::remove_file(dir.join("etc/group")).unwrap();
        assert_eq!(supplementary_groups(&dir, "nick", 1000), vec![1000]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The daemon-side bounding set keeps exactly nspawn's default caps,
    /// which includes everything nsenter itself needs.
    #[test]
    fn bounding_mask_matches_nspawn_set() {
        for name in NSPAWN_DEFAULT_CAPS {
            assert!(
                CAP_NUMBERS.iter().any(|(n, _)| n == name),
                "unknown cap name {name}"
            );
        }
        let keep = bounding_keep_mask();
        assert_eq!(keep.count_ones() as usize, NSPAWN_DEFAULT_CAPS.len());
        for needed in [
            "sys_admin",
            "sys_ptrace",
            "setuid",
            "setgid",
            "dac_override",
            "setpcap",
        ] {
            let n = CAP_NUMBERS.iter().find(|(x, _)| *x == needed).unwrap().1;
            assert!(keep & (1 << n) != 0, "{needed} must stay for nsenter");
        }
        for dropped in [
            "sys_module",
            "net_admin",
            "sys_rawio",
            "sys_time",
            "bpf",
            "perfmon",
        ] {
            let n = CAP_NUMBERS.iter().find(|(x, _)| *x == dropped).unwrap().1;
            assert!(keep & (1 << n) == 0, "{dropped} must be dropped");
        }
        assert!(CAP_DROP_MAX >= CAP_NUMBERS.last().unwrap().1);
    }

    #[test]
    fn env_option_injection_rejected() {
        let dir = fake_rootfs("inj", true);
        let mut s = start("root", &["true"]);
        s.env = vec!["TERM=xterm".into(), "-i".into()];
        assert!(exec_plan(42, &dir, &s, true).is_err());
        s.env = vec!["-S x".into()];
        assert!(exec_plan(42, &dir, &s, true).is_err());
        s.env = vec!["FOO".into()];
        assert!(exec_plan(42, &dir, &s, true).is_err());
        s.env = vec!["A_1=b=c".into()];
        let p = exec_plan(42, &dir, &s, true).unwrap();
        assert_eq!(env_of(&p, "A_1"), Some("b=c"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A client PATH override lands in the payload env; the host nsenter
    /// lookup never consults it.
    #[test]
    fn client_path_override_and_host_nsenter() {
        let dir = fake_rootfs("path", true);
        let mut s = start("nick", &["true"]);
        s.env = vec!["PATH=/evil".into()];
        let p = exec_plan(42, &dir, &s, false).unwrap();
        assert_eq!(env_of(&p, "PATH"), Some("/evil"));
        assert_eq!(p.argv[0], OsString::from("nsenter"));
        let cmd = p.command(false);
        let prog = cmd.get_program().to_string_lossy().into_owned();
        assert!(
            prog.starts_with('/') && prog.ends_with("/nsenter"),
            "{prog}"
        );
        assert!(!prog.starts_with("/evil"));
        // env_clear + envs: only the plan's variables reach the child.
        let envs: Vec<_> = cmd.get_envs().collect();
        assert!(envs.iter().all(|(_, v)| v.is_some()));
        assert!(envs.iter().any(|(k, _)| *k == "HOME"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Loader-sensitive keys never reach the host nsenter's environ under
    /// their real name; the in-pod wrapper re-exports them.
    #[test]
    fn loader_env_is_escaped_past_host_nsenter() {
        let dir = fake_rootfs("ldenv", true);
        for argv in [&["true"][..], &[][..]] {
            let mut s = start("nick", argv);
            s.env = vec![
                "LD_PRELOAD=/tmp/x.so".into(),
                "GLIBC_TUNABLES=glibc.malloc.check=3".into(),
                "GCONV_PATH=/tmp".into(),
                "FOO=bar".into(),
            ];
            let p = exec_plan(42, &dir, &s, false).unwrap();
            for k in ["LD_PRELOAD", "GLIBC_TUNABLES", "GCONV_PATH"] {
                assert_eq!(env_of(&p, k), None, "{k} on host environ");
                assert!(env_of(&p, &format!("RUSTYPODS_ENV_{k}")).is_some());
                assert!(strs(&p).iter().any(|x| x.contains(&format!(
                    "export {k}=\"$RUSTYPODS_ENV_{k}\"; unset RUSTYPODS_ENV_{k};"
                ))));
            }
            assert_eq!(env_of(&p, "LD_PRELOAD"), None);
            assert_eq!(env_of(&p, "RUSTYPODS_ENV_LD_PRELOAD"), Some("/tmp/x.so"));
            assert_eq!(env_of(&p, "FOO"), Some("bar"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn argv_user_login_shell() {
        let dir = fake_rootfs("login", true);
        let p = exec_plan(7, &dir, &start("nick", &[]), false).unwrap();
        let s = strs(&p);
        assert!(s.contains(&"--setuid=1000".to_string()));
        assert!(s.contains(&"/bin/bash".to_string()));
        assert_eq!(s.last().unwrap(), "-l");
        assert!(s
            .iter()
            .any(|x| x.contains("cd \"${RUSTYPODS_WORKDIR:-$HOME}\"")));
        assert!(s.iter().any(|x| x.starts_with("exec 0<&9 9<&-")));
        assert_eq!(env_of(&p, "HOME"), Some("/home/nick"));
        let mut w = start("nick", &["pwd"]);
        w.workdir = "/tmp".into();
        let p = exec_plan(7, &dir, &w, false).unwrap();
        assert_eq!(env_of(&p, "RUSTYPODS_WORKDIR"), Some("/tmp"));
        w.workdir = "rel".into();
        assert!(exec_plan(7, &dir, &w, false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A forwarded LANG that the rootfs never generated downgrades to
    /// C.UTF-8; a generated one survives; C-locales are untouched.
    #[test]
    fn lang_downgrades_when_locale_missing() {
        let dir = fake_rootfs("lang", true);
        let mut s = start("root", &["true"]);
        s.env = vec!["LANG=nl_NL.UTF-8".into()];
        let p = exec_plan(42, &dir, &s, true).unwrap();
        assert_eq!(env_of(&p, "LANG"), Some("C.UTF-8"));

        // Per-locale dir present → kept.
        std::fs::create_dir_all(dir.join("usr/lib/locale/nl_NL.utf8")).unwrap();
        let p = exec_plan(42, &dir, &s, true).unwrap();
        assert_eq!(env_of(&p, "LANG"), Some("nl_NL.UTF-8"));

        // Debian-style: archive + uncommented locale.gen line → kept.
        std::fs::remove_dir_all(dir.join("usr/lib/locale")).unwrap();
        std::fs::create_dir_all(dir.join("usr/lib/locale")).unwrap();
        std::fs::write(dir.join("usr/lib/locale/locale-archive"), b"").unwrap();
        std::fs::write(dir.join("etc/debian_version"), b"forky/sid\n").unwrap();
        let p = exec_plan(42, &dir, &s, true).unwrap();
        assert_eq!(
            env_of(&p, "LANG"),
            Some("C.UTF-8"),
            "debian: archive alone is not proof"
        );
        std::fs::write(
            dir.join("etc/locale.gen"),
            "# en_US.UTF-8 UTF-8\nnl_NL.UTF-8 UTF-8\n",
        )
        .unwrap();
        let p = exec_plan(42, &dir, &s, true).unwrap();
        assert_eq!(
            env_of(&p, "LANG"),
            Some("nl_NL.UTF-8"),
            "locale.gen line counts"
        );

        // C and POSIX always exist — pass through untouched.
        s.env = vec!["LANG=C".into(), "LC_ALL=POSIX".into()];
        let p = exec_plan(42, &dir, &s, true).unwrap();
        assert_eq!(env_of(&p, "LANG"), Some("C"));
        assert_eq!(env_of(&p, "LC_ALL"), Some("POSIX"));

        // Non-debian rootfs: archive presence alone suffices.
        std::fs::remove_file(dir.join("etc/debian_version")).unwrap();
        s.env = vec!["LC_ALL=xx_YY.UTF-8".into()];
        let p = exec_plan(42, &dir, &s, true).unwrap();
        assert_eq!(env_of(&p, "LC_ALL"), Some("xx_YY.UTF-8"));
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

    /// A grandchild that calls setsid() leaves the process group, so
    /// kill_pgrp cannot see it. It stays in the exec leaf, and cgroup.kill
    /// still reaches it.
    #[test]
    fn cgroup_kill_reaches_setsid_child() {
        let cg = match ExecCgroup::create(u32::MAX) {
            Ok(cg) => cg,
            Err(e) => {
                eprintln!("cgroup kill test skipped: {e}");
                return;
            }
        };
        let fd = cg.raw_fd();
        let dir = cg.dir.clone();
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("setsid sleep 60 & echo $!; wait")
            .stdout(Stdio::piped());
        // SAFETY: write(2) and setsid(2) in the freshly forked child.
        unsafe {
            cmd.pre_exec(move || {
                write_self_to_cgroup(fd)?;
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().expect("spawn");
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        // Let `setsid` leave the shell's process group before we signal it.
        std::thread::sleep(Duration::from_millis(50));
        kill_pgrp(child.id());
        child.wait().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let left = std::fs::read_to_string(dir.join("cgroup.procs")).unwrap_or_default();
        assert!(
            left.split_whitespace().any(|p| !p.is_empty()),
            "setsid child was not in the exec cgroup after kill_pgrp (echo {line:?}, procs {left:?})"
        );
        cg.kill_members();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let procs = std::fs::read_to_string(dir.join("cgroup.procs")).unwrap_or_default();
            if procs.split_whitespace().next().is_none() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "cgroup.kill left members: {procs}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
