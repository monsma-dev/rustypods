//! `rustypods doctor` — local host capability probe. Everything here runs
//! against the local machine only; the daemon itself may not be installed
//! yet, so its check is a WARN, never a FAIL.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Level {
    Pass,
    Warn,
    Fail,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Level::Pass => "PASS",
            Level::Warn => "WARN",
            Level::Fail => "FAIL",
        }
    }
}

struct Check {
    level: Level,
    name: &'static str,
    detail: String,
}

/// First executable `name` on the given PATH-style search list (exec bit on
/// a regular file). Split out from env so tests can pass a private PATH.
fn find_executable_in(name: &str, path_var: &std::ffi::OsStr) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    for dir in std::env::split_paths(path_var) {
        let p = dir.join(name);
        if let Ok(m) = p.metadata() {
            if m.is_file() && m.permissions().mode() & 0o111 != 0 {
                return Some(p);
            }
        }
    }
    None
}

/// The search list the *daemon* effectively uses: the caller's PATH plus
/// the sbin dirs systemd always puts on a system unit's PATH — a desktop
/// user's shell PATH typically lacks /usr/sbin where nft/runuser live.
fn daemon_path() -> std::ffi::OsString {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    for d in ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let p = PathBuf::from(d);
        if !dirs.contains(&p) {
            dirs.push(p);
        }
    }
    std::env::join_paths(dirs).unwrap_or_default()
}

fn find_executable(name: &str) -> Option<PathBuf> {
    find_executable_in(name, &daemon_path())
}

/// Which of `required` strings are absent from a `--help` text.
fn missing_flags(help: &str, required: &[&str]) -> Vec<String> {
    required
        .iter()
        .filter(|f| !help.contains(**f))
        .map(|s| s.to_string())
        .collect()
}

/// "0\n" → false, "1234\n" → true, garbage → false.
fn parse_positive_u64(s: &str) -> bool {
    s.trim().parse::<u64>().map(|v| v > 0).unwrap_or(false)
}

/// Storage check verdict: btrfs only counts when btrfs-progs is installed —
/// the driver shells out to `btrfs` for every subvolume op.
fn storage_check(target: &Path, fs: Option<&str>, btrfs_progs: Option<&Path>) -> (Level, String) {
    match fs {
        Some("btrfs") => match btrfs_progs {
            Some(p) => (
                Level::Pass,
                format!(
                    "{} on btrfs (CoW snapshots + quotas); btrfs-progs at {}",
                    target.display(),
                    p.display()
                ),
            ),
            None => (
                Level::Fail,
                format!(
                    "{} is btrfs but btrfs-progs is missing",
                    target.display()
                ),
            ),
        },
        Some(fs) => (
            Level::Warn,
            format!(
                "{} on {fs} — copy/reflink fallback will be used",
                target.display()
            ),
        ),
        None => (
            Level::Warn,
            format!("cannot determine fs type of {}", target.display()),
        ),
    }
}

/// Filesystem type hosting `target`, via `findmnt -n -o FSTYPE -T`.
fn mount_fs_type(target: &Path) -> Option<String> {
    let out = Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(target)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let fs = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!fs.is_empty()).then_some(fs)
}

/// Run `prog args`, returning stdout on success. The error carries trimmed
/// stderr so the check line stays actionable.
fn cmd_stdout(prog: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(prog)
        .args(args)
        .output()
        .with_context(|| format!("running {prog}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.trim();
        bail!(
            "{prog} {} exited {status}{}",
            args.join(" "),
            if err.is_empty() {
                String::new()
            } else {
                format!(" — {err}")
            },
            status = out.status,
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub async fn run(socket: PathBuf) -> Result<()> {
    let mut checks: Vec<Check> = Vec::new();
    macro_rules! chk {
        ($lv:expr, $name:expr, $($d:tt)*) => {
            checks.push(Check { level: $lv, name: $name, detail: format!($($d)*) })
        };
    }

    // ── required (FAIL) checks ─────────────────────────────────────────
    chk!(
        if std::env::consts::OS == "linux" {
            Level::Pass
        } else {
            Level::Fail
        },
        "os",
        "{}/{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    let systemd = Path::new("/run/systemd/system").is_dir()
        && Path::new("/run/dbus/system_bus_socket").exists();
    chk!(
        if systemd { Level::Pass } else { Level::Fail },
        "systemd",
        "PID 1 environment (/run/systemd/system + system bus socket)"
    );

    chk!(
        if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            Level::Pass
        } else {
            Level::Fail
        },
        "cgroup",
        "cgroup v2 unified hierarchy"
    );

    let userns = Path::new("/proc/self/ns/user").exists()
        && std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
            .map(|s| parse_positive_u64(&s))
            .unwrap_or(false);
    chk!(
        if userns { Level::Pass } else { Level::Fail },
        "userns",
        "user namespaces enabled (max_user_namespaces > 0)"
    );

    const REQUIRED_TOOLS: &[&str] = &[
        "systemd-nspawn",
        "machinectl",
        "nsenter",
        "ip",
        "nft",
        "journalctl",
        "runuser",
        "id",
        "cp",
        "rm",
        "tail",
    ];
    for t in REQUIRED_TOOLS {
        match find_executable(t) {
            Some(p) => chk!(Level::Pass, "tool", "{t} → {}", p.display()),
            None => chk!(Level::Fail, "tool", "{t} not found on daemon PATH"),
        }
    }

    const NSPAWN_FLAGS: &[&str] = &[
        "--private-users",
        "--network-namespace-path",
        "--network-veth",
        "--bind-ro",
        "--setenv",
        "--chdir",
    ];
    match cmd_stdout("systemd-nspawn", &["--help"]) {
        Ok(help) => {
            let missing = missing_flags(&help, NSPAWN_FLAGS);
            if missing.is_empty() {
                chk!(Level::Pass, "nspawn", "all required options present");
            } else {
                chk!(
                    Level::Fail,
                    "nspawn",
                    "missing options: {}",
                    missing.join(", ")
                );
            }
        }
        Err(e) => chk!(Level::Fail, "nspawn", "{e:#}"),
    }
    // The daemon literally passes --private-users-chown; systemd ≥252 lists
    // only --private-users-ownership in --help and keeps the old spelling as
    // a hidden alias. Help text can't prove the alias still parses — probe
    // the exact flag the runtime uses.
    match cmd_stdout("systemd-nspawn", &["--private-users-chown", "--help"]) {
        Ok(_) => chk!(
            Level::Pass,
            "nspawn",
            "compat alias --private-users-chown accepted"
        ),
        Err(e) => chk!(
            Level::Fail,
            "nspawn",
            "--private-users-chown rejected at runtime: {e:#}"
        ),
    }

    match cmd_stdout("nsenter", &["--help"]) {
        Ok(help) => {
            let missing = missing_flags(&help, &["--join-cgroup", "--cgroup"]);
            if missing.is_empty() {
                chk!(Level::Pass, "nsenter", "--join-cgroup/--cgroup present");
            } else {
                chk!(
                    Level::Fail,
                    "nsenter",
                    "missing options: {}",
                    missing.join(", ")
                );
            }
        }
        Err(e) => chk!(Level::Fail, "nsenter", "{e:#}"),
    }

    match cmd_stdout("machinectl", &["list", "--no-legend", "--no-pager"]) {
        Ok(_) => chk!(Level::Pass, "machined", "machinectl list works"),
        Err(e) => chk!(Level::Fail, "machined", "{e:#}"),
    }

    use std::os::unix::fs::PermissionsExt;
    let shm_ok = std::fs::metadata("/dev/shm")
        .map(|m| m.is_dir() && m.permissions().mode() & 0o1777 == 0o1777)
        .unwrap_or(false);
    chk!(
        if shm_ok { Level::Pass } else { Level::Fail },
        "/dev/shm",
        "exists, mode 01777 (world-writable + sticky)"
    );

    for s in [
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/sys/net/ipv4/conf/all/route_localnet",
    ] {
        chk!(
            if Path::new(s).exists() {
                Level::Pass
            } else {
                Level::Fail
            },
            "sysctl",
            "{s} present"
        );
    }

    // ── WARN / info checks ─────────────────────────────────────────────
    let target = if Path::new("/var/lib/rustypods").exists() {
        Path::new("/var/lib/rustypods")
    } else {
        Path::new("/var/lib")
    };
    if find_executable("findmnt").is_none() {
        chk!(
            Level::Warn,
            "storage",
            "findmnt not found — cannot detect fs type"
        );
    } else {
        let fs = mount_fs_type(target);
        let (level, detail) = storage_check(target, fs.as_deref(), find_executable("btrfs").as_deref());
        chk!(level, "storage", "{detail}");
    }

    match find_executable("socat") {
        Some(p) => chk!(Level::Pass, "socat", "{}", p.display()),
        None => chk!(Level::Warn, "socat", "required only for --remote"),
    }
    match find_executable("podman") {
        Some(p) => chk!(Level::Pass, "podman", "{}", p.display()),
        None => chk!(
            Level::Warn,
            "podman",
            "optional; only distrobox import/bootstrap fallback"
        ),
    }

    match rustypods_client::connect_timeout(socket.clone(), None, Duration::from_secs(2)).await {
        Ok(mut c) => match c.ping(rustypods_proto::rpc::PingRequest {}).await {
            Ok(i) => {
                let i = i.into_inner();
                chk!(
                    Level::Pass,
                    "daemon",
                    "v{} storage={} engine={}",
                    i.version,
                    i.storage_driver,
                    i.runtime_engine
                );
            }
            Err(e) => chk!(Level::Warn, "daemon", "connected but ping failed: {e}"),
        },
        Err(e) => chk!(
            Level::Warn,
            "daemon",
            "not reachable at {} ({e:#}) — install/start rustypodsd",
            socket.display()
        ),
    }

    let ver =
        cmd_stdout("systemd", &["--version"]).or_else(|_| cmd_stdout("systemctl", &["--version"]));
    match ver {
        Ok(v) => chk!(
            Level::Pass,
            "systemd",
            "{}",
            v.lines().next().unwrap_or("unknown").trim()
        ),
        Err(e) => chk!(Level::Warn, "systemd", "version probe failed: {e:#}"),
    }

    let selinux = std::fs::read_to_string("/sys/fs/selinux/enforce")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    if selinux {
        chk!(
            Level::Warn,
            "selinux",
            "enforcing; Fedora/RHEL policy has not been validated on this host"
        );
    } else {
        chk!(Level::Pass, "selinux", "disabled or absent");
    }

    // ── report ─────────────────────────────────────────────────────────
    let mut fails = 0usize;
    let mut warns = 0usize;
    for c in &checks {
        println!("{} {:<10} {}", c.level.tag(), c.name, c.detail);
        match c.level {
            Level::Fail => fails += 1,
            Level::Warn => warns += 1,
            Level::Pass => {}
        }
    }
    println!(
        "\n{} passed, {} warning(s), {} failed",
        checks.len() - fails - warns,
        warns,
        fails
    );
    if fails > 0 {
        bail!("doctor found {fails} required check(s) failing");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_u64_edges() {
        assert!(parse_positive_u64("15063\n"));
        assert!(parse_positive_u64("1"));
        assert!(!parse_positive_u64("0"));
        assert!(!parse_positive_u64(""));
        assert!(!parse_positive_u64("abc"));
        assert!(!parse_positive_u64("-5"));
    }

    #[test]
    fn missing_flags_subset() {
        let help = "options: --private-users --bind-ro --chdir";
        assert!(missing_flags(help, &["--private-users", "--bind-ro"]).is_empty());
        assert_eq!(
            missing_flags(help, &["--chdir", "--network-veth"]),
            vec!["--network-veth".to_string()]
        );
        // Prefix trap: --private-users must not satisfy --private-users-chown.
        assert_eq!(
            missing_flags("--private-users", &["--private-users-chown"]),
            vec!["--private-users-chown".to_string()]
        );
    }

    #[test]
    fn storage_level_selection() {
        let t = Path::new("/var/lib/rustypods");
        let progs = Path::new("/usr/sbin/btrfs");
        assert_eq!(storage_check(t, Some("btrfs"), Some(progs)).0, Level::Pass);
        assert_eq!(storage_check(t, Some("btrfs"), None).0, Level::Fail);
        assert_eq!(storage_check(t, Some("ext4"), Some(progs)).0, Level::Warn);
        assert_eq!(storage_check(t, None, None).0, Level::Warn);
    }

    #[test]
    fn find_executable_respects_exec_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rp-doctor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("yes-tool");
        let bad = dir.join("no-tool");
        std::fs::write(&good, b"#!/bin/sh\n").unwrap();
        std::fs::write(&bad, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o644)).unwrap();
        let path = std::ffi::OsString::from(&dir);
        assert_eq!(find_executable_in("yes-tool", &path), Some(good));
        assert_eq!(find_executable_in("no-tool", &path), None);
        assert_eq!(find_executable_in("missing-tool", &path), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
