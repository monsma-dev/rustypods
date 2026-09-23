//! systemd-nspawn engine: spawn `systemd-nspawn` as a daemon child; machined
//! registers the machine itself (CreateMachine moves the payload into
//! `machine-<name>.scope`), then we bolt resource limits onto that scope.
//! All machined/systemd calls go over the shared zbus connection — no
//! subprocesses.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;

use super::{RuntimeEngine, StartSpec};
use crate::dbus;
use crate::state::LimitsSpec;

/// Pure argv builder — unit-testable.
pub fn start_argv(spec: &StartSpec) -> Vec<OsString> {
    let mut a: Vec<OsString> = vec!["systemd-nspawn".into()];
    // OCI payload images carry no systemd — nspawn execs the entrypoint
    // directly (non-boot). Distrobox-imported images boot their init.
    // Non-boot pods still register with machined.
    if spec.payload.is_none() {
        a.push("--boot".into());
    }
    a.push(format!("--machine={}", spec.name).into());
    a.push("--directory".into());
    a.push(spec.rootfs.as_os_str().into());
    // User binds come from the pod conf (validated by validate_bind at write
    // time). rw under /run is refused there: container-logind runs
    // user-runtime-dir@<uid> whose session cleanup rm -rf's it — a rw bind
    // wiped the host's user bus once already.
    for b in &spec.binds {
        let flag = if b.ro { "--bind-ro" } else { "--bind" };
        a.push(format!("{flag}={}:{}", b.host, b.pod).into());
    }
    if spec.agent_bin.is_dir() {
        a.push(format!("--bind-ro={}:/run/rustypods/bin", spec.agent_bin.display()).into());
    }
    if spec.run_dir.is_dir() {
        a.push(format!("--bind={}:/run/rustypods/run", spec.run_dir.display()).into());
    }
    if spec.shm_dir.is_dir() {
        a.push(format!("--bind={}:/run/rustypods/shm", spec.shm_dir.display()).into());
    }
    if spec.ephemeral {
        a.push("-x".into()); // nspawn btrfs-snapshots the dir and discards on exit
    }
    if spec.private_users {
        // Default for new pods: pod root is not host root. --private-users-
        // chown makes the FIRST start shift the rootfs ownership to the
        // picked range (metadata-level CoW on btrfs, one-time cost). It
        // breaks shared-home writes as host uids — desktop pods opt out.
        a.push("--private-users=pick".into());
        a.push("--private-users-chown".into());
    }
    if let Some(ns) = &spec.netns {
        // Stack member: join the shared netns — all stack pods share lo and
        // the stack IP (K8s pod model). The daemon wires the netns itself.
        a.push(format!("--network-namespace-path={}", ns.display()).into());
    } else if spec.network_veth {
        // Private networking (port mappings and/or ingress rules):
        // --network-veth gives the pod its own netns on ve-<name> (no
        // host-net parity anymore). The daemon configures both veth ends
        // and owns the DNAT (crate::net) — nspawn's --port relies on
        // systemd-networkd managing the host side, which most desktop
        // distros (NetworkManager, Netplan) don't run.
        a.push("--network-veth".into());
    }
    // OCI env + working dir (only populated for payload images).
    for kv in &spec.env {
        a.push(format!("--setenv={kv}").into());
    }
    if spec.payload.is_some() && !spec.chdir.is_empty() {
        a.push(format!("--chdir={}", spec.chdir).into());
    }
    if let Some(payload) = &spec.payload {
        a.push("--".into());
        a.extend(payload.iter().map(OsString::from));
    }
    a
}

/// Spawn nspawn with console output appended to `log`. A detached reaper task
/// waits on the child so it never zombies; nspawn keeps running if the daemon
/// restarts (it reparents to PID 1 and machined still owns the registration).
async fn spawn(argv: &[OsString], log: &Path) -> Result<u32> {
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

/// The nspawn+machined engine. Holds the shared system-bus connection;
/// zbus multiplexes all machined/systemd calls over it.
pub struct SystemdNspawn {
    pub dbus: zbus::Connection,
}

#[tonic::async_trait]
impl RuntimeEngine for SystemdNspawn {
    fn name(&self) -> &'static str {
        "systemd-nspawn"
    }

    async fn init(&self) -> Result<()> {
        // Wake machined (socket-activated; best effort).
        let _ = dbus::wake_machined(&self.dbus).await;
        Ok(())
    }

    async fn start(&self, spec: &StartSpec, limits: &LimitsSpec) -> Result<u32> {
        let argv = start_argv(spec);
        spawn(&argv, &spec.log).await?;
        dbus::wait_registered(&self.dbus, &spec.name, Duration::from_secs(15))
            .await
            .context(format!("boot failed — see {}", spec.log.display()))?;
        // Guardrails are the point: a pod that can't be capped is a failure.
        dbus::apply_limits(&self.dbus, &spec.name, limits)
            .await
            .context("applying limits failed")?;
        dbus::leader_pid(&self.dbus, &spec.name)
            .await?
            .context("registered but no leader pid")
    }

    async fn stop(&self, pod: &str) -> Result<()> {
        dbus::stop(&self.dbus, pod).await
    }

    async fn running_pid(&self, pod: &str) -> Option<u32> {
        // Some(0) = registered but still booting (leader property is 0).
        // Bus errors collapse to None here — callers needing the truth use
        // registered() (destroy) or get a clear error (stop).
        dbus::running_pid(&self.dbus, pod).await.ok().flatten()
    }

    async fn registered(&self, pod: &str) -> Result<bool> {
        dbus::registered(&self.dbus, pod).await
    }

    async fn apply_limits(&self, pod: &str, limits: &LimitsSpec) -> Result<()> {
        dbus::apply_limits(&self.dbus, pod, limits).await
    }

    async fn scope_name(&self, pod: &str) -> Option<String> {
        dbus::unit_name(&self.dbus, pod).await.ok().flatten()
    }

    async fn healthy(&self) -> bool {
        dbus::machined_up(&self.dbus).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec(ephemeral: bool, pu: bool) -> StartSpec {
        StartSpec {
            name: "dev".into(),
            rootfs: PathBuf::from("/pods/dev"),
            ephemeral,
            private_users: pu,
            agent_bin: PathBuf::from("/bin"), // exists → agent bind
            run_dir: PathBuf::from("/bin"),   // exists → run bind
            shm_dir: PathBuf::from("/definitely-missing"), // skipped
            ports: vec![],
            network_veth: false,
            binds: vec![],
            netns: None,
            log: PathBuf::from("/tmp/x.log"),
            payload: None,
            env: vec![],
            chdir: String::new(),
        }
    }

    fn argv(s: &StartSpec) -> Vec<String> {
        start_argv(s)
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn argv_basics() {
        let a = argv(&spec(false, false));
        assert!(a.contains(&"--boot".to_string()));
        assert!(a.contains(&"--machine=dev".to_string()));
        assert!(
            !a.iter().any(|s| s.contains(":/home/")),
            "no user binds in spec (daemon binds to /run/rustypods remain)"
        );
        assert!(!a.contains(&"-x".to_string()));
    }

    #[test]
    fn argv_binds() {
        let mut s = spec(false, false);
        s.binds = vec![
            rustypods_proto::validate_bind("/home/nick").unwrap(),
            rustypods_proto::validate_bind("/run/user/1000:ro").unwrap(),
        ];
        let a = argv(&s);
        assert!(a.contains(&"--bind=/home/nick:/home/nick".to_string()));
        assert!(a.contains(&"--bind-ro=/run/user/1000:/run/user/1000".to_string()));
    }

    #[test]
    fn argv_flags() {
        let a = argv(&spec(true, true));
        assert!(a.contains(&"-x".to_string()));
        assert!(a.contains(&"--private-users=pick".to_string()));
        assert!(!a.contains(&"--network-veth".to_string()));
    }

    #[test]
    fn argv_veth_only_via_flag() {
        // The flag, not the ports data, drives --network-veth: ingress-only
        // pods (empty ports) must get a veth, and the engine trusts the
        // server's needs_network decision either way.
        let mut s = spec(false, false);
        s.network_veth = true;
        assert!(argv(&s).contains(&"--network-veth".to_string()));
        let mut s = spec(false, false);
        s.ports = vec!["8080:80".into(), "53:53/udp".into()];
        assert!(!argv(&s).contains(&"--network-veth".to_string()));
    }

    #[test]
    fn argv_stack_joins_shared_netns() {
        let mut s = spec(false, false);
        s.name = "demo-web".into();
        s.ports = vec!["8080:80".into()];
        s.network_veth = true; // must not win over an explicit netns
        s.netns = Some(PathBuf::from("/var/run/netns/rustypods-demo"));
        let a = argv(&s);
        assert!(a.contains(&"--network-namespace-path=/var/run/netns/rustypods-demo".to_string()));
        assert!(!a.contains(&"--network-veth".to_string()));
    }

    #[test]
    fn argv_payload_is_non_boot() {
        let mut s = spec(false, true); // userns still applies in non-boot mode
        s.payload = Some(vec!["/bin/sh".into(), "-l".into()]);
        s.env = vec!["PATH=/usr/bin".into(), "HOME=/root".into()];
        s.chdir = "/app".into();
        let a = argv(&s);
        assert!(!a.contains(&"--boot".to_string()), "payload ⇒ no --boot");
        assert!(a.contains(&"--private-users=pick".to_string()));
        assert!(a.contains(&"--setenv=PATH=/usr/bin".to_string()));
        assert!(a.contains(&"--chdir=/app".to_string()));
        // Payload comes last, after a "--" separator.
        let tail: Vec<&str> = a[a.len() - 3..].iter().map(|s| s.as_str()).collect();
        assert_eq!(tail, ["--", "/bin/sh", "-l"]);
    }

    #[test]
    fn argv_boot_has_no_payload_bits() {
        let a = argv(&spec(false, false));
        assert!(a.contains(&"--boot".to_string()));
        assert!(!a.iter().any(|s| s == "--"));
        assert!(!a
            .iter()
            .any(|s| s.starts_with("--setenv") || s.starts_with("--chdir")));
    }
}
