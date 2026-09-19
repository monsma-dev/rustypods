//! Execution layer: spawn `systemd-nspawn` as a daemon child; machined
//! registers the machine itself (CreateMachine moves the payload into
//! `machine-<name>.scope`), then we bolt resource limits onto that scope.

use anyhow::{bail, Context, Result};
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::{sleep, timeout};

use crate::state::LimitsSpec;

/// Pure argv builder — unit-testable.
pub fn start_argv(rootfs: &Path, name: &str, ephemeral: bool, private_users: bool, agent_bin: &Path) -> Vec<OsString> {
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
        a.push(format!("--bind-ro={}:/run/rustypods", agent_bin.display()).into());
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

pub async fn leader_pid(name: &str) -> Option<u32> {
    let out = Command::new("machinectl")
        .args(["show", name, "-p", "Leader", "--value"])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|p| *p > 0)
}

/// Wait for machined registration (nspawn does this itself during --boot).
pub async fn wait_registered(name: &str, dur: Duration) -> Result<u32> {
    timeout(dur, async {
        loop {
            if let Some(pid) = leader_pid(name).await {
                return pid;
            }
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .with_context(|| format!("machined registratie timeout voor {name}"))
}

/// Resource guardrails on the machined-managed scope — *this* is the cgroup
/// that holds the payload, not any wrapper we might have spawned around it.
pub async fn apply_limits(name: &str, lim: &LimitsSpec) -> Result<()> {
    let unit = format!("machine-{name}.scope");
    let mut args: Vec<String> = vec!["set-property".into(), unit];
    if lim.memory_high_bytes > 0 {
        args.push(format!("MemoryHigh={}", lim.memory_high_bytes));
    }
    if lim.memory_max_bytes > 0 {
        args.push(format!("MemoryMax={}", lim.memory_max_bytes));
    }
    if lim.cpu_quota_percent > 0 {
        args.push(format!("CPUQuota={}%", lim.cpu_quota_percent));
    }
    if args.len() <= 2 {
        return Ok(());
    }
    let out = Command::new("systemctl").args(&args).output().await?;
    if out.status.success() {
        Ok(())
    } else {
        bail!(
            "systemctl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

/// Clean shutdown → terminate → give up loudly.
pub async fn stop(name: &str) -> Result<()> {
    if leader_pid(name).await.is_none() {
        return Ok(());
    }
    let _ = Command::new("machinectl")
        .args(["poweroff", name])
        .output()
        .await;
    for _ in 0..75 {
        if leader_pid(name).await.is_none() {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }
    tracing::warn!("{name}: poweroff timeout — terminate");
    let _ = Command::new("machinectl")
        .args(["terminate", name])
        .output()
        .await;
    for _ in 0..25 {
        if leader_pid(name).await.is_none() {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }
    bail!("pod {name} weigert te stoppen")
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
            &PathBuf::from("/bin"), // exists → agent bind
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
