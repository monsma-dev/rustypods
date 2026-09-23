//! Shared API surface for RustyPods: generated gRPC code plus the few
//! constants and validators both the daemon and the CLI need.

use std::path::PathBuf;

pub mod rpc {
    tonic::include_proto!("rustypods.v1");
}

pub const SOCKET_PATH: &str = "/run/rustypods/daemon.sock";
pub const DATA_DIR: &str = "/var/lib/rustypods";

pub fn images_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("images")
}
pub fn pods_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("pods")
}
pub fn logs_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("logs")
}
pub fn bin_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("bin")
}
pub fn shm_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("shm")
}
/// Per-pod channel dir, bound rw into the pod at /run/rustypods/run.
pub fn run_dir(data_dir: &std::path::Path, pod: &str) -> PathBuf {
    data_dir.join("run").join(pod)
}
/// Host side of the SHM dataplane — tmpfs, bound rw to /run/rustypods/shm.
pub fn shm_host_dir(pod: &str) -> PathBuf {
    PathBuf::from("/dev/shm/rustypods").join(pod)
}
/// Per-entity TOML confs: conf/pods/<name>.conf, conf/images/<name>.conf.
/// Hand-editable; `rustypods reload <pod>` rereads them.
pub fn conf_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("conf")
}

/// In-pod paths (container side of the binds).
pub const POD_RUN_DIR: &str = "/run/rustypods/run";
pub const POD_AGENT_SOCK: &str = "/run/rustypods/run/agent.sock";
pub const POD_SHM_DIR: &str = "/run/rustypods/shm";

/// Pod/image names double as nspawn machine names and directory names.
/// Keep them to a strict hostname-ish slug.
pub fn validate_name(name: &str) -> anyhow::Result<&str> {
    let ok = !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        && name
            .chars()
            .next()
            .map(|c| c.is_ascii_lowercase())
            .unwrap_or(false);
    if ok {
        Ok(name)
    } else {
        anyhow::bail!(
            "invalid name '{name}' — use [a-z][a-z0-9-_]{{0,31}} (must start with a letter)"
        )
    }
}

/// Snapshot ids are "<unix_ts>[-slug]" — digits, then optionally "-" + [a-z0-9-]{1,40}.
pub fn validate_snapshot_id(id: &str) -> anyhow::Result<&str> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && !id.contains('/')
        && id
            .chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase() || c == '-')
        && id
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false);
    if ok {
        Ok(id)
    } else {
        anyhow::bail!("invalid snapshot id '{id}' — expected <unix_ts>[-slug]")
    }
}

/// A distrobox/podman container reference — the podman name charset
/// ([A-Za-z0-9][A-Za-z0-9_.-]*), so a leading '-' (option injection) is out.
pub fn validate_container_ref(s: &str) -> anyhow::Result<&str> {
    let ok = !s.is_empty()
        && s.len() <= 64
        && s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        && s
            .chars()
            .next()
            .map(|c| c.is_ascii_alphanumeric())
            .unwrap_or(false);
    if ok {
        Ok(s)
    } else {
        anyhow::bail!("invalid container ref '{s}' — use [A-Za-z0-9][A-Za-z0-9_.-]{{0,63}}")
    }
}

/// Look up the login name for `uid` in passwd(5)-format text. Shared by the
/// daemon (`--import-user` default) and the CLI (`import`/`shell` fallback).
pub fn username_for_uid(text: &str, uid: u32) -> Option<String> {
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        f.next()?; // password field
        let u: u32 = f.next()?.parse().ok()?;
        (u == uid && !name.is_empty()).then(|| name.to_string())
    })
}

/// A Unix login name: ^[a-z_][a-z0-9_-]{0,31}$.
pub fn validate_unix_user(u: &str) -> anyhow::Result<&str> {
    let ok = !u.is_empty()
        && u.len() <= 32
        && u
            .chars()
            .next()
            .map(|c| c.is_ascii_lowercase() || c == '_')
            .unwrap_or(false)
        && u
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if ok {
        Ok(u)
    } else {
        anyhow::bail!("invalid unix user '{u}' — use [a-z_][a-z0-9_-]{{0,31}}")
    }
}

/// Validate "hostPort:podPort[/proto]" — both ports must be 1..=65535.
pub fn validate_port(spec: &str) -> anyhow::Result<()> {
    let (ports, proto) = match spec.split_once('/') {
        Some((p, pr)) => (p, Some(pr)),
        None => (spec, None),
    };
    let ok = matches!(proto, None | Some("tcp") | Some("udp"))
        && ports.split(':').count() == 2
        && ports
            .split(':')
            .all(|s| s.parse::<u16>().map(|n| n > 0).unwrap_or(false));
    if ok {
        Ok(())
    } else {
        anyhow::bail!("invalid port mapping '{spec}' — expected hostPort:podPort[/tcp|/udp]")
    }
}

/// A parsed bind-mount spec (`host[:pod][:ro]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindSpec {
    pub host: String,
    pub pod: String,
    pub ro: bool,
}

fn clean_abs_path(p: &str) -> bool {
    p.starts_with('/')
        && (p == "/" || !p.ends_with('/'))
        && p.split('/')
            .skip(1)
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

fn under(path: &str, prefix: &str) -> bool {
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

/// Validate "host[:pod][:ro]": both paths absolute, no empty/dot components,
/// no trailing slash. The host path is canonicalized — `/var/run` resolves
/// to `/run`, `/bin` to `/usr/bin`, etc. — and the deny-lists are checked
/// against BOTH the literal and the resolved path, so symlink aliases can't
/// slip past. The host path must exist at validation time.
/// Host may not be exactly a system root ("/", "/proc", "/sys", "/dev",
/// "/boot", "/usr", "/etc", "/var", "/var/lib", "/run", "/root", "/var/run",
/// "/var/spool", "/var/cron"). Read-write binds under /run, /root,
/// /var/lib/rustypods, /etc, /usr, /boot, /proc, /sys, /dev are refused —
/// those are :ro-only (a pod's init system considers e.g. /run/user/<uid>
/// "theirs" and rm -rf's it; see AGENTS.md).
pub fn validate_bind(spec: &str) -> anyhow::Result<BindSpec> {
    let mut parts: Vec<&str> = spec.split(':').collect();
    let ro = parts.last() == Some(&"ro");
    if ro {
        parts.pop();
    }
    let bad = |spec: &str| anyhow::anyhow!("invalid bind '{spec}' — expected host[:pod][:ro], absolute paths");
    let (host, pod) = match parts.as_slice() {
        [h] => (*h, *h),
        [h, p] => (*h, *p),
        _ => return Err(bad(spec)),
    };
    if !clean_abs_path(host) || !clean_abs_path(pod) {
        return Err(bad(spec));
    }
    // Resolve symlink aliases (/var/run → /run, /bin → /usr/bin) so the
    // deny-lists can't be bypassed by spelling a denied path differently.
    // Nonexistent host paths are rejected here — pods can't bind paths that
    // don't exist yet.
    let resolved = std::fs::canonicalize(host).map_err(|_| {
        anyhow::anyhow!("invalid bind '{spec}' — host path {host} does not exist")
    })?;
    let host_resolved = resolved.to_string_lossy().into_owned();
    const EXACT_DENY: &[&str] = &[
        "/", "/proc", "/sys", "/dev", "/boot", "/usr", "/etc", "/var", "/var/lib", "/run",
        "/root", "/var/run", "/var/spool", "/var/cron",
    ];
    if EXACT_DENY.contains(&host) || EXACT_DENY.contains(&host_resolved.as_str()) {
        return Err(anyhow::anyhow!("invalid bind '{spec}' — host path {host} may not be bound wholesale"));
    }
    const RW_DENY: &[&str] = &[
        "/run", "/var/lib/rustypods", "/etc", "/usr", "/boot", "/proc", "/sys", "/dev",
        "/root", "/var/run",
    ];
    if !ro
        && (RW_DENY.iter().any(|p| under(host, p))
            || RW_DENY.iter().any(|p| under(&host_resolved, p)))
    {
        return Err(anyhow::anyhow!(
            "invalid bind '{spec}' — {host} is read-only territory, add ':ro'"
        ));
    }
    Ok(BindSpec {
        host: host_resolved,
        pod: pod.to_string(),
        ro,
    })
}

/// Largest value parse_bytes/parse_duration will produce: u64 results
/// cross a JSON/ts-proto boundary where numbers are f64 — anything past
/// 2^53 loses integer precision (and u64::MAX breaks i64 consumers).
const MAX_PARSED: u64 = 1 << 53;

/// f64 → u64 with sanity: NaN/±inf and negatives parse as f64 but are not
/// sizes, and the saturating `as` cast would silently turn them into 0 or
/// u64::MAX.
fn f64_to_u64(v: f64, mult: u64, what: &str, s: &str) -> anyhow::Result<u64> {
    if !(v.is_finite() && v >= 0.0) {
        anyhow::bail!("invalid {what} '{s}'");
    }
    let r = v * mult as f64;
    if !(r.is_finite() && r <= MAX_PARSED as f64) {
        anyhow::bail!("{what} '{s}' out of range (max {} )", MAX_PARSED);
    }
    Ok(r as u64)
}

/// Validate a payload argv (pod cmd override): non-empty vec, argv[0]
/// non-empty, no NUL bytes anywhere (they'd truncate at exec).
pub fn validate_argv(argv: &[String]) -> anyhow::Result<()> {
    if argv.is_empty() || argv[0].is_empty() {
        anyhow::bail!("invalid cmd — argv[0] must be non-empty");
    }
    if argv.iter().any(|a| a.contains('\0')) {
        anyhow::bail!("invalid cmd — argv entries may not contain NUL bytes");
    }
    Ok(())
}

/// Parse "10G", "512M", "1024" (bytes) into a byte count.
pub fn parse_bytes(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.as_bytes().last() {
        Some(b'G') | Some(b'g') => (&s[..s.len() - 1], 1u64 << 30),
        Some(b'M') | Some(b'm') => (&s[..s.len() - 1], 1u64 << 20),
        Some(b'K') | Some(b'k') => (&s[..s.len() - 1], 1u64 << 10),
        Some(b'B') | Some(b'b') => (&s[..s.len() - 1], 1u64),
        _ => (s, 1u64),
    };
    let v: f64 = num.parse().map_err(|_| anyhow::anyhow!("invalid size '{s}'"))?;
    f64_to_u64(v, mult, "size", s)
}

pub fn fmt_bytes(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.1}G", b as f64 / (1u64 << 30) as f64)
    } else if b >= 1 << 20 {
        format!("{:.1}M", b as f64 / (1u64 << 20) as f64)
    } else {
        format!("{b}B")
    }
}

/// Parse "7d", "24h", "30m", "60s", or a bare second count into seconds.
pub fn parse_duration(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.as_bytes().last() {
        Some(b'd') | Some(b'D') => (&s[..s.len() - 1], 86400u64),
        Some(b'h') | Some(b'H') => (&s[..s.len() - 1], 3600),
        Some(b'm') | Some(b'M') => (&s[..s.len() - 1], 60),
        Some(b's') | Some(b'S') => (&s[..s.len() - 1], 1),
        _ => (s, 1u64),
    };
    let v: f64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration '{s}'"))?;
    f64_to_u64(v, mult, "duration", s)
}

/// Seconds back to the coarsest whole unit: 604800 → "7d", 3600 → "1h".
pub fn fmt_duration(secs: u64) -> String {
    if secs == 0 {
        "0s".into()
    } else if secs % 86400 == 0 {
        format!("{}d", secs / 86400)
    } else if secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validation() {
        assert!(validate_name("arch-dev").is_ok());
        assert!(validate_name("a").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("1bad").is_err());
        assert!(validate_name("Bad").is_err());
        assert!(validate_name("bad name").is_err());
        assert!(validate_name(&"x".repeat(33)).is_err());
    }

    #[test]
    fn snapshot_id_validation() {
        assert!(validate_snapshot_id("1789836285").is_ok());
        assert!(validate_snapshot_id("1789836285-before-experiment").is_ok());
        assert!(validate_snapshot_id("").is_err());
        assert!(validate_snapshot_id("../x").is_err());
        assert!(validate_snapshot_id("a/b").is_err());
        assert!(validate_snapshot_id("1789836285/../../pods").is_err());
        assert!(validate_snapshot_id("-x").is_err());
        assert!(validate_snapshot_id("Bad").is_err());
    }

    #[test]
    fn container_ref_and_unix_user() {
        assert!(validate_container_ref("arch").is_ok());
        assert!(validate_container_ref("-o/tmp/x").is_err());
        assert!(validate_container_ref("a b").is_err());
        assert!(validate_unix_user("nick").is_ok());
        assert!(validate_unix_user("root").is_ok());
        assert!(validate_unix_user("-u").is_err());
    }

    #[test]
    fn username_for_uid_parses_passwd() {
        let text = "root:x:0:0:root:/root:/bin/bash\n\
                    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                    nick:x:1000:1000:Nick:/home/nick:/bin/bash\n";
        assert_eq!(username_for_uid(text, 1000).as_deref(), Some("nick"));
        assert_eq!(username_for_uid(text, 0).as_deref(), Some("root"));
        assert_eq!(username_for_uid(text, 1234), None);
        // Malformed lines are skipped, not fatal.
        assert_eq!(username_for_uid("badline\nnick:x:1000:g:::", 1000).as_deref(), Some("nick"));
        assert_eq!(username_for_uid("", 1000), None);
    }

    #[test]
    fn bind_validation() {
        let b = validate_bind("/home/nick").unwrap();
        assert_eq!(b, BindSpec { host: "/home/nick".into(), pod: "/home/nick".into(), ro: false });
        assert!(validate_bind("/tmp").is_ok());
        assert!(validate_bind("/run/user/1000:ro").unwrap().ro);
        assert!(validate_bind("/dev/dri:ro").unwrap().ro);
        assert!(validate_bind("/run/user/1000").is_err());
        assert!(validate_bind("/etc").is_err());
        assert!(validate_bind("home/nick").is_err());
        assert!(validate_bind("/a/../b").is_err());
        assert!(validate_bind("/var/tmp:/mnt/data").is_ok());
        assert!(validate_bind("/var/tmp:/mnt/data:ro").unwrap().ro);
        assert!(validate_bind("/x:rel").is_err());
        // Host path must exist — no binding not-yet-created paths.
        assert!(validate_bind("/definitely-not-here-rp").is_err());
        // Symlink aliases resolve before the deny-lists run:
        // /var/run → /run, /bin → /usr/bin on any usr-merged system.
        assert!(validate_bind("/var/run").is_err());
        assert!(validate_bind("/var/run/user/1000").is_err());
        assert!(validate_bind("/var/run/user/1000:ro").unwrap().ro);
        assert!(validate_bind("/bin/bash").is_err());
        assert!(validate_bind("/bin/bash:ro").unwrap().ro);
        assert!(validate_bind("/root").is_err());
    }

    #[test]
    fn argv_validation() {
        assert!(validate_argv(&["sleep".into(), "infinity".into()]).is_ok());
        assert!(validate_argv(&[]).is_err());
        assert!(validate_argv(&["".into()]).is_err());
        assert!(validate_argv(&["sh".into(), "a\0b".into()]).is_err());
    }

    #[test]
    fn port_validation() {
        assert!(validate_port("2222:22").is_ok());
        assert!(validate_port("53:53/udp").is_ok());
        assert!(validate_port("0:80").is_err());
        assert!(validate_port("8080").is_err());
        assert!(validate_port("1:2/sctp").is_err());
    }

    #[test]
    fn byte_parsing() {
        assert_eq!(parse_bytes("10G").unwrap(), 10 << 30);
        assert_eq!(parse_bytes("512m").unwrap(), 512 << 20);
        assert_eq!(parse_bytes("1024").unwrap(), 1024);
        assert!(parse_bytes("abc").is_err());
        // f64 parse accepts these — they must be rejected, not saturated.
        assert!(parse_bytes("NaN").is_err());
        assert!(parse_bytes("nan").is_err());
        assert!(parse_bytes("inf").is_err());
        assert!(parse_bytes("-5").is_err());
        assert!(parse_bytes("-5G").is_err());
        assert!(parse_bytes("1e30").is_err()); // > 2^53
        assert!(parse_bytes("9007199T").is_err()); // 'T' isn't a suffix → parse error
        assert_eq!(parse_bytes("9007199254740992").unwrap(), 1 << 53); // == 2^53 ok
        assert!(parse_bytes("10000000000000000").is_err()); // 1e16 > 2^53
        assert!(parse_bytes("").is_err());
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration("7d").unwrap(), 7 * 86400);
        assert_eq!(parse_duration("24h").unwrap(), 24 * 3600);
        assert_eq!(parse_duration("30m").unwrap(), 30 * 60);
        assert_eq!(parse_duration("60s").unwrap(), 60);
        assert_eq!(parse_duration("120").unwrap(), 120);
        assert_eq!(parse_duration("0").unwrap(), 0);
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("-5d").is_err());
        assert!(parse_duration("").is_err());
        // Same f64 traps as parse_bytes: NaN/inf parse fine, and a giant
        // multiplier can push a sane-looking number past 2^53.
        assert!(parse_duration("NaN").is_err());
        assert!(parse_duration("inf").is_err());
        assert!(parse_duration("-inf").is_err());
        assert!(parse_duration("99999999999999d").is_err());
    }

    #[test]
    fn duration_formatting() {
        assert_eq!(fmt_duration(7 * 86400), "7d");
        assert_eq!(fmt_duration(24 * 3600), "1d"); // coarsest whole unit wins
        assert_eq!(fmt_duration(36 * 3600), "36h");
        assert_eq!(fmt_duration(30 * 60), "30m");
        assert_eq!(fmt_duration(45), "45s");
        assert_eq!(fmt_duration(0), "0s");
    }
}
