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
/// no trailing slash. Host may not be exactly a system root ("/", "/proc",
/// "/sys", "/dev", "/boot", "/usr", "/etc", "/var", "/var/lib", "/run").
/// Read-write binds under /run, /var/lib/rustypods, /etc, /usr, /boot,
/// /proc, /sys, /dev are refused — those are :ro-only (a pod's init system
/// considers e.g. /run/user/<uid> "theirs" and rm -rf's it; see AGENTS.md).
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
    const EXACT_DENY: &[&str] = &[
        "/", "/proc", "/sys", "/dev", "/boot", "/usr", "/etc", "/var", "/var/lib", "/run",
    ];
    if EXACT_DENY.contains(&host) {
        return Err(anyhow::anyhow!("invalid bind '{spec}' — host path {host} may not be bound wholesale"));
    }
    const RW_DENY: &[&str] = &[
        "/run", "/var/lib/rustypods", "/etc", "/usr", "/boot", "/proc", "/sys", "/dev",
    ];
    if !ro && RW_DENY.iter().any(|p| under(host, p)) {
        return Err(anyhow::anyhow!(
            "invalid bind '{spec}' — {host} is read-only territory, add ':ro'"
        ));
    }
    Ok(BindSpec {
        host: host.to_string(),
        pod: pod.to_string(),
        ro,
    })
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
    Ok((v * mult as f64) as u64)
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
        assert!(validate_bind("/data:/mnt/data").is_ok());
        assert!(validate_bind("/data:/mnt/data:ro").unwrap().ro);
        assert!(validate_bind("/x:rel").is_err());
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
    }
}
