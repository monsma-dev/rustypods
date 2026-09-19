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
    fn byte_parsing() {
        assert_eq!(parse_bytes("10G").unwrap(), 10 << 30);
        assert_eq!(parse_bytes("512m").unwrap(), 512 << 20);
        assert_eq!(parse_bytes("1024").unwrap(), 1024);
        assert!(parse_bytes("abc").is_err());
    }
}
