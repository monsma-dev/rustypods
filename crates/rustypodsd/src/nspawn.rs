//! Execution layer: spawn `systemd-nspawn` as a daemon child; machined
//! registers the machine itself (CreateMachine moves the payload into
//! `machine-<name>.scope`), then we bolt resource limits onto that scope.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::path::Path;
use tokio::process::Command;

/// Pure argv builder — unit-testable.
pub fn start_argv(
    rootfs: &Path,
    name: &str,
    ephemeral: bool,
    private_users: bool,
    agent_bin: &Path,
    run_dir: &Path,
    shm_dir: &Path,
) -> Vec<OsString> {
    let mut a: Vec<OsString> = vec![
        "systemd-nspawn".into(),
        "--boot".into(),
        format!("--machine={name}").into(),
        "--directory".into(),
        rootfs.as_os_str().into(),
        // distrobox-parity binds: home + tmp. /run/user/1000 is READ-ONLY:
        // container-logind runs user-runtime-dir@1000 whose session cleanup
        // rm -rf's it — a rw bind wiped the host's user bus once already.
        "--bind=/home/nick".into(),
        "--bind=/tmp".into(),
        "--bind-ro=/run/user/1000".into(),
    ];
    if Path::new("/dev/dri").is_dir() {
        a.push("--bind-ro=/dev/dri".into());
    }
    if agent_bin.is_dir() {
        a.push(format!("--bind-ro={}:/run/rustypods/bin", agent_bin.display()).into());
    }
    if run_dir.is_dir() {
        a.push(format!("--bind={}:/run/rustypods/run", run_dir.display()).into());
    }
    if shm_dir.is_dir() {
        a.push(format!("--bind={}:/run/rustypods/shm", shm_dir.display()).into());
    }
    if ephemeral {
        a.push("-x".into()); // nspawn btrfs-snapshots the dir and discards on exit
    }
    if private_users {
        // Breaks shared-home writes (mapped uids); opt-in isolation.
        a.push("--private-users=pick".into());
        a.push("--private-users-chown".into());
    }
    a
}

/// Spawn nspawn with console output appended to `log`. A detached reaper task
/// waits on the child so it never zombies; nspawn keeps running if the daemon
/// restarts (it reparents to PID 1 and machined still owns the registration).
pub async fn spawn(argv: &[OsString], log: &Path) -> Result<u32> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .with_context(|| format!("log {}", log.display()))?;
    let err = f.try_clone()?;
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(f))
        .stderr(std::process::Stdio::from(err))
        .spawn()
        .with_context(|| format!("spawn {}", argv[0].to_string_lossy()))?;
    let pid = child.id().unwrap_or(0);
    tokio::spawn(async move {
        match child.wait().await {
            Ok(st) => tracing::info!("nspawn exited: {st}"),
            Err(e) => tracing::warn!("nspawn wait: {e}"),
        }
    });
    Ok(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn argv(ephemeral: bool, pu: bool) -> Vec<String> {
        start_argv(
            &PathBuf::from("/pods/dev"),
            "dev",
            ephemeral,
            pu,
            &PathBuf::from("/bin"),      // exists → agent-bin bind
            &PathBuf::from("/bin"),      // exists → run bind
            &PathBuf::from("/definitely-missing"), // skipped
        )
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect()
    }

    #[test]
    fn argv_basics() {
        let a = argv(false, false);
        assert!(a.contains(&"--boot".to_string()));
        assert!(a.contains(&"--machine=dev".to_string()));
        assert!(a.contains(&"--bind=/home/nick".to_string()));
        assert!(!a.contains(&"-x".to_string()));
    }

    #[test]
    fn argv_flags() {
        let a = argv(true, true);
        assert!(a.contains(&"-x".to_string()));
        assert!(a.contains(&"--private-users=pick".to_string()));
    }
}
