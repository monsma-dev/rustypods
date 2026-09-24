//! Console logs for nspawn (`logs/<pod>.log`).
//!
//! nspawn inherits the log fd opened `O_APPEND`, and it keeps that fd if the
//! daemon restarts (the child reparents to PID 1). Renaming the file would
//! leave nspawn writing the old inode, so rotation is copytruncate: copy the
//! bytes aside, then `ftruncate` the live inode. The next `O_APPEND` write
//! lands at offset 0. Bytes written during the copy can be lost; the cap is
//! a bound, not an audit trail.
//!
//! Files are mode 0600. One rotated sibling (`<pod>.log.1`) is kept.

use anyhow::{Context, Result};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Default live-file cap. Override with `RUSTYPODS_LOG_MAX_BYTES` (bytes).
pub const DEFAULT_LOG_MAX_BYTES: u64 = 10 << 20;

pub fn log_max_bytes() -> u64 {
    std::env::var("RUSTYPODS_LOG_MAX_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_LOG_MAX_BYTES)
}

fn rotated_path(log: &Path) -> PathBuf {
    let name = log
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    log.with_file_name(format!("{name}.1"))
}

/// Open (or create) the console log for append, mode 0600. An existing
/// looser mode is tightened on the open fd so a leftover 0644 file stops
/// being world-readable the next time a pod starts.
pub fn open_console_log(log: &Path) -> Result<std::fs::File> {
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    }
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(log)
        .with_context(|| format!("log {}", log.display()))?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", log.display()))?;
    Ok(f)
}

/// If `log` is larger than `max_bytes`, copy it to `<name>.1` and truncate
/// the live inode in place. Returns whether a rotation happened.
pub fn rotate_console_log(log: &Path, max_bytes: u64) -> Result<bool> {
    let meta = match std::fs::symlink_metadata(log) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("stat {}", log.display())),
    };
    if !meta.file_type().is_file() {
        anyhow::bail!("{} is not a regular file", log.display());
    }
    if meta.permissions().mode() & 0o777 != 0o600 {
        let _ = std::fs::set_permissions(log, std::fs::Permissions::from_mode(0o600));
    }
    if meta.len() <= max_bytes {
        return Ok(false);
    }
    let dest = rotated_path(log);
    {
        let mut src =
            std::fs::File::open(log).with_context(|| format!("read {}", log.display()))?;
        let mut dst = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&dest)
            .with_context(|| format!("rotate {}", dest.display()))?;
        std::io::copy(&mut src, &mut dst)
            .with_context(|| format!("copy {} → {}", log.display(), dest.display()))?;
        dst.sync_all().ok();
    }
    let live = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(log)
        .with_context(|| format!("truncate {}", log.display()))?;
    live.set_len(0)
        .with_context(|| format!("truncate {}", log.display()))?;
    Ok(true)
}

/// Delete `<name>.log` and its rotated sibling. Missing files are fine.
pub fn remove_pod_logs(logs_dir: &Path, name: &str) -> Result<()> {
    let live = logs_dir.join(format!("{name}.log"));
    for p in [live.clone(), rotated_path(&live)] {
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("rm {}", p.display())),
        }
    }
    Ok(())
}

/// Drop console logs whose pod name is not in `live`. Only `*.log` and
/// `*.log.1` are considered; anything else is left alone.
pub fn sweep_orphan_logs(logs_dir: &Path, live: &std::collections::BTreeSet<String>) {
    let Ok(rd) = std::fs::read_dir(logs_dir) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let pod = name
            .strip_suffix(".log.1")
            .or_else(|| name.strip_suffix(".log"));
        let Some(pod) = pod else { continue };
        if live.contains(pod) {
            continue;
        }
        if let Err(err) = std::fs::remove_file(e.path()) {
            tracing::warn!("orphan log {}: {err}", e.path().display());
        } else {
            tracing::info!("removed orphan console log {}", e.path().display());
        }
    }
}

/// Background copytruncate pass. One task for the daemon lifetime; a quiet
/// failure is logged, never fatal.
pub fn spawn_rotator(logs_dir: PathBuf) {
    let max = log_max_bytes();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let dir = logs_dir.clone();
            let res = tokio::task::spawn_blocking(move || rotate_dir(&dir, max)).await;
            if let Ok(Err(e)) = res {
                tracing::warn!("console log rotation: {e:#}");
            }
        }
    });
}

fn rotate_dir(logs_dir: &Path, max: u64) -> Result<()> {
    let rd = match std::fs::read_dir(logs_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".log") && !name.ends_with(".log.1") {
            rotate_console_log(&e.path(), max)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "rustypods-logs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn open_is_mode_0600_and_append() {
        let dir = scratch();
        let log = dir.join("dev.log");
        {
            let mut f = open_console_log(&log).unwrap();
            f.write_all(b"one\n").unwrap();
        }
        {
            let mut f = open_console_log(&log).unwrap();
            f.write_all(b"two\n").unwrap();
        }
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "one\ntwo\n");
        let mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_truncates_live_inode_and_keeps_one_old() {
        let dir = scratch();
        let log = dir.join("dev.log");
        std::fs::write(&log, b"abcdefghij").unwrap();
        assert!(rotate_console_log(&log, 4).unwrap());
        assert_eq!(std::fs::read(&log).unwrap(), b"");
        assert_eq!(std::fs::read(dir.join("dev.log.1")).unwrap(), b"abcdefghij");
        // Second rotation overwrites the single sibling.
        {
            let mut f = open_console_log(&log).unwrap();
            f.write_all(b"xyzxyzxyz").unwrap();
        }
        assert!(rotate_console_log(&log, 4).unwrap());
        assert_eq!(std::fs::read(dir.join("dev.log.1")).unwrap(), b"xyzxyzxyz");
        assert!(!rotate_console_log(&log, 4).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_and_sweep_orphans() {
        let dir = scratch();
        std::fs::write(dir.join("keep.log"), b"a").unwrap();
        std::fs::write(dir.join("keep.log.1"), b"b").unwrap();
        std::fs::write(dir.join("gone.log"), b"c").unwrap();
        std::fs::write(dir.join("gone.log.1"), b"d").unwrap();
        std::fs::write(dir.join("notes.txt"), b"leave").unwrap();
        remove_pod_logs(&dir, "keep").unwrap();
        assert!(!dir.join("keep.log").exists());
        assert!(!dir.join("keep.log.1").exists());
        let mut live = std::collections::BTreeSet::new();
        live.insert("keep".into());
        // keep is already gone; gone is the orphan.
        sweep_orphan_logs(&dir, &live);
        assert!(!dir.join("gone.log").exists());
        assert!(dir.join("notes.txt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
