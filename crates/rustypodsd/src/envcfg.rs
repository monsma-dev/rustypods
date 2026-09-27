//! Process environment for `rustypodsd`, parsed into one struct.
//!
//! A missing variable keeps its documented default. A variable that is
//! set but empty, not Unicode, or not the documented type fails the
//! parse — the daemon must not start on a limit the operator thought
//! they set. Byte caps are plain integers (`1099511627776`), not `100MB`.
//! `RUSTYPODS_DEFAULT_MEMORY_MAX` is the exception: it uses the same
//! `10G`/`512M` form as pod conf.

use anyhow::{bail, Context, Result};
use std::sync::OnceLock;

use crate::runtime::logs::DEFAULT_LOG_MAX_BYTES;
use crate::transfer::DEFAULT_IMPORT_MAX_BYTES;

const DEFAULT_POD_NET4: &str = "10.220.0.0/16";
const DEFAULT_POD_NET6: &str = "fd22:220::/32";

/// Snapshot of the daemon's `RUSTYPODS_*` settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonEnv {
    /// `RUSTYPODS_IMPORT_MAX_BYTES`. Plain byte count, default 64 GiB.
    pub import_max_bytes: u64,
    /// `RUSTYPODS_LOG_MAX_BYTES`. Plain byte count, default 10 MiB.
    pub log_max_bytes: u64,
    /// `RUSTYPODS_POD_NET4`, default `10.220.0.0/16`.
    pub pod_net4: String,
    /// `RUSTYPODS_POD_NET6`, default `fd22:220::/32`.
    pub pod_net6: String,
    /// `RUSTYPODS_DEFAULT_MEMORY_MAX` when set (`64M`, `1G`, or bytes).
    pub default_memory_max: Option<u64>,
    /// `RUSTYPODS_DEFAULT_CPU` when set (`50` or `50%`).
    pub default_cpu_percent: Option<u32>,
    /// `RUSTYPODS_HTTP_INSECURE` is present.
    pub http_insecure: bool,
    /// `RUSTYPODS_HTTP_TOKEN_ROTATE` is present.
    pub http_token_rotate: bool,
    /// `RUSTYPODS_READ_ONLY_UIDS`, comma-separated. Missing means nobody.
    pub read_only_uids: Vec<u32>,
    /// `RUSTYPODS_ROLE`. Missing means `host`. `witness` votes and does
    /// not schedule or publish DNS.
    pub role: crate::ha::Role,
}

static LOADED: OnceLock<DaemonEnv> = OnceLock::new();

impl DaemonEnv {
    /// Read the current process environment. Does not cache.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            import_max_bytes: var_u64("RUSTYPODS_IMPORT_MAX_BYTES", DEFAULT_IMPORT_MAX_BYTES)?,
            log_max_bytes: var_u64("RUSTYPODS_LOG_MAX_BYTES", DEFAULT_LOG_MAX_BYTES)?,
            pod_net4: var_string("RUSTYPODS_POD_NET4", DEFAULT_POD_NET4)?,
            pod_net6: var_string("RUSTYPODS_POD_NET6", DEFAULT_POD_NET6)?,
            default_memory_max: var_memory("RUSTYPODS_DEFAULT_MEMORY_MAX")?,
            default_cpu_percent: var_cpu("RUSTYPODS_DEFAULT_CPU")?,
            http_insecure: std::env::var_os("RUSTYPODS_HTTP_INSECURE").is_some(),
            http_token_rotate: std::env::var_os("RUSTYPODS_HTTP_TOKEN_ROTATE").is_some(),
            read_only_uids: var_uids("RUSTYPODS_READ_ONLY_UIDS")?,
            role: var_role("RUSTYPODS_ROLE")?,
        })
    }
}

/// Parse once for the process. A later successful call returns the same
/// snapshot. A failed parse is not cached, so a bad value cannot stick
/// after the variable is corrected in-process (tests).
pub fn load() -> Result<&'static DaemonEnv> {
    if let Some(env) = LOADED.get() {
        return Ok(env);
    }
    let env = DaemonEnv::from_env()?;
    let _ = LOADED.set(env);
    Ok(LOADED.get().expect("daemon env just stored"))
}

fn var_present(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("{name} is set but is not valid Unicode")
        }
        Ok(s) => {
            let t = s.trim();
            if t.is_empty() {
                bail!("{name} is set but empty");
            }
            Ok(Some(t.to_string()))
        }
    }
}

/// Comma-separated uids. Missing keeps an empty list. Empty, `0`, or a
/// non-numeric entry fails the parse — uid 0 is already an administrator.
fn var_uids(name: &str) -> Result<Vec<u32>> {
    let Some(s) = var_present(name)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            bail!("{name} contains an empty uid");
        }
        let uid: u32 = part
            .parse()
            .with_context(|| format!("{name} has a non-numeric uid {part:?}"))?;
        if uid == 0 {
            bail!("{name} must not list uid 0 — root is already an administrator");
        }
        if out.contains(&uid) {
            bail!("{name} lists uid {uid} more than once");
        }
        out.push(uid);
    }
    Ok(out)
}

fn var_role(name: &str) -> Result<crate::ha::Role> {
    match var_present(name)? {
        None => Ok(crate::ha::Role::Host),
        Some(s) if s == "host" => Ok(crate::ha::Role::Host),
        Some(s) if s == "witness" => Ok(crate::ha::Role::Witness),
        Some(s) => bail!("{name} must be host or witness, got {s}"),
    }
}

fn var_string(name: &str, default: &str) -> Result<String> {
    Ok(var_present(name)?.unwrap_or_else(|| default.to_string()))
}

/// Positive integer. Unit suffixes (`100MB`, `1G`) are rejected: a byte
/// cap that does not parse must not fall back to the default.
fn var_u64(name: &str, default: u64) -> Result<u64> {
    let Some(s) = var_present(name)? else {
        return Ok(default);
    };
    let n: u64 = s
        .parse()
        .with_context(|| format!("{name} must be a positive integer number of bytes, got {s:?}"))?;
    if n == 0 {
        bail!("{name} must be greater than 0");
    }
    Ok(n)
}

fn var_memory(name: &str) -> Result<Option<u64>> {
    let Some(s) = var_present(name)? else {
        return Ok(None);
    };
    let n = rustypods_proto::parse_bytes(&s)
        .with_context(|| format!("{name} is not a size ({s:?})"))?;
    if n == 0 {
        bail!("{name} must be greater than 0");
    }
    Ok(Some(n))
}

fn var_cpu(name: &str) -> Result<Option<u32>> {
    let Some(s) = var_present(name)? else {
        return Ok(None);
    };
    let t = s.trim_end_matches('%');
    let n: u32 = t
        .parse()
        .with_context(|| format!("{name} must be a percent (50 or 50%), got {s:?}"))?;
    Ok(Some(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Restore {
        name: &'static str,
        prev: Option<String>,
    }

    impl Restore {
        fn set(name: &'static str, value: &str) -> Self {
            let prev = std::env::var(name).ok();
            std::env::set_var(name, value);
            Self { name, prev }
        }

        fn clear(name: &'static str) -> Self {
            let prev = std::env::var(name).ok();
            std::env::remove_var(name);
            Self { name, prev }
        }
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.name, v),
                None => std::env::remove_var(self.name),
            }
        }
    }

    #[test]
    fn unset_keeps_defaults() {
        let _a = Restore::clear("RUSTYPODS_IMPORT_MAX_BYTES");
        let _b = Restore::clear("RUSTYPODS_LOG_MAX_BYTES");
        let _c = Restore::clear("RUSTYPODS_DEFAULT_MEMORY_MAX");
        let _d = Restore::clear("RUSTYPODS_DEFAULT_CPU");
        let _e = Restore::clear("RUSTYPODS_READ_ONLY_UIDS");
        let _f = Restore::clear("RUSTYPODS_ROLE");
        let env = DaemonEnv::from_env().unwrap();
        assert_eq!(env.import_max_bytes, DEFAULT_IMPORT_MAX_BYTES);
        assert_eq!(env.log_max_bytes, DEFAULT_LOG_MAX_BYTES);
        assert_eq!(env.default_memory_max, None);
        assert_eq!(env.default_cpu_percent, None);
        assert!(env.read_only_uids.is_empty());
        assert_eq!(env.role, crate::ha::Role::Host);
    }

    #[test]
    fn read_only_uids_parse_and_reject_garbage() {
        let _restore = Restore::set("RUSTYPODS_READ_ONLY_UIDS", "1001, 1002");
        assert_eq!(
            DaemonEnv::from_env().unwrap().read_only_uids,
            vec![1001, 1002]
        );
        drop(_restore);
        let _restore = Restore::set("RUSTYPODS_READ_ONLY_UIDS", "1001,,1002");
        assert!(DaemonEnv::from_env()
            .unwrap_err()
            .to_string()
            .contains("empty"));
        drop(_restore);
        let _restore = Restore::set("RUSTYPODS_READ_ONLY_UIDS", "0");
        assert!(DaemonEnv::from_env()
            .unwrap_err()
            .to_string()
            .contains("uid 0"));
        drop(_restore);
        let _restore = Restore::set("RUSTYPODS_READ_ONLY_UIDS", "");
        assert!(DaemonEnv::from_env()
            .unwrap_err()
            .to_string()
            .contains("empty"));
    }

    #[test]
    fn unit_suffix_on_a_byte_cap_is_rejected() {
        let _restore = Restore::set("RUSTYPODS_IMPORT_MAX_BYTES", "100MB");
        let err = DaemonEnv::from_env().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("RUSTYPODS_IMPORT_MAX_BYTES"), "{msg}");
        assert!(msg.contains("100MB"), "{msg}");
    }

    #[test]
    fn empty_and_zero_byte_caps_are_rejected() {
        let _restore = Restore::set("RUSTYPODS_LOG_MAX_BYTES", "  ");
        let err = DaemonEnv::from_env().unwrap_err();
        assert!(err.to_string().contains("empty"), "{err:#}");
        drop(_restore);
        let _restore = Restore::set("RUSTYPODS_LOG_MAX_BYTES", "0");
        let err = DaemonEnv::from_env().unwrap_err();
        assert!(err.to_string().contains("greater than 0"), "{err:#}");
    }

    #[test]
    fn memory_default_parses_suffix_and_rejects_garbage() {
        let _restore = Restore::set("RUSTYPODS_DEFAULT_MEMORY_MAX", "64M");
        let env = DaemonEnv::from_env().unwrap();
        assert_eq!(env.default_memory_max, Some(64 << 20));
        drop(_restore);
        let _restore = Restore::set("RUSTYPODS_DEFAULT_MEMORY_MAX", "100MB");
        let err = DaemonEnv::from_env().unwrap_err();
        assert!(
            err.to_string().contains("RUSTYPODS_DEFAULT_MEMORY_MAX"),
            "{err:#}"
        );
    }

    #[test]
    fn cpu_default_accepts_percent_and_rejects_words() {
        let _restore = Restore::set("RUSTYPODS_DEFAULT_CPU", "50%");
        assert_eq!(DaemonEnv::from_env().unwrap().default_cpu_percent, Some(50));
        drop(_restore);
        let _restore = Restore::set("RUSTYPODS_DEFAULT_CPU", "half");
        let err = DaemonEnv::from_env().unwrap_err();
        assert!(err.to_string().contains("RUSTYPODS_DEFAULT_CPU"), "{err:#}");
    }
}
