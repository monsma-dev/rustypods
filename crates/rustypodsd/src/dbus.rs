//! Native D-Bus calls to machined + systemd — replaces the
//! `machinectl`/`systemctl` subprocesses. One shared system-bus `Connection`
//! in Svc; zbus multiplexes all calls over it.
//!
//! Verified on systemd 257 (busctl introspect + live experiments):
//! - `machinectl poweroff` ≙ `KillMachine(name, "leader", SIGRTMIN+3)`
//!   — the container's systemd interprets 37 as clean shutdown.
//! - `machinectl terminate` ≙ `TerminateMachine(name)` (hard kill).
//! - `systemctl set-property <scope> K=V` ≙
//!   `SetUnitProperties(unit, runtime=true, [("K", v)])` — CPUQuota is called
//!   `CPUQuotaPerSecUSec` on the bus (100% = 1_000_000 µs).

use anyhow::{bail, Context, Result};
use std::time::Duration;
use tokio::time::{sleep, timeout};
use zbus::zvariant::{OwnedObjectPath, Value};
use zbus::{proxy, Connection};

use crate::state::LimitsSpec;

/// glibc SIGRTMIN (kernel 32 + 2 NPTL reserves). +3 = poweroff in the pod.
const SIGRTMIN: i32 = 34;

#[proxy(
    interface = "org.freedesktop.machine1.Manager",
    default_service = "org.freedesktop.machine1",
    default_path = "/org/freedesktop/machine1"
)]
trait MachineManager {
    fn get_machine(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    fn list_machines(&self) -> zbus::Result<Vec<(String, String, String, OwnedObjectPath)>>;
    fn terminate_machine(&self, name: &str) -> zbus::Result<()>;
    fn kill_machine(&self, name: &str, who: &str, signo: i32) -> zbus::Result<()>;
}

#[proxy(
    interface = "org.freedesktop.machine1.Machine",
    default_service = "org.freedesktop.machine1"
)]
trait Machine {
    #[zbus(property)]
    fn leader(&self) -> zbus::Result<u32>;
    /// Authoritative scope name ("machine-dev.scope") — no guessing.
    #[zbus(property)]
    fn unit(&self) -> zbus::Result<String>;
}

#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait SystemdManager {
    fn set_unit_properties(
        &self,
        unit: &str,
        runtime: bool,
        props: Vec<(&str, Value<'_>)>,
    ) -> zbus::Result<()>;
    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
}

async fn machine<'a>(conn: &'a Connection, name: &str) -> Result<Option<MachineProxy<'a>>> {
    let mgr = MachineManagerProxy::new(conn).await?;
    let path = match mgr.get_machine(name).await {
        Ok(p) => p,
        Err(_) => return Ok(None), // NoSuchMachine → not registered
    };
    Ok(Some(
        MachineProxy::builder(conn).path(path)?.build().await?,
    ))
}

/// machined is socket-activated; ping the systemd manager to wake it.
pub async fn wake_machined(conn: &Connection) -> Result<()> {
    SystemdManagerProxy::new(conn)
        .await?
        .start_unit("systemd-machined.service", "replace")
        .await?;
    Ok(())
}

/// Is machined reachable on the bus? (for the `ping` output)
pub async fn machined_up(conn: &Connection) -> bool {
    match MachineManagerProxy::new(conn).await {
        Ok(p) => p.list_machines().await.is_ok(),
        Err(_) => false,
    }
}

/// Leader pid via machined; None when the pod isn't running.
pub async fn leader_pid(conn: &Connection, name: &str) -> Option<u32> {
    let m = machine(conn, name).await.ok()??;
    m.leader().await.ok().filter(|p| *p > 0)
}

/// Poll machined until the pod is registered (nspawn does that itself).
pub async fn wait_registered(conn: &Connection, name: &str, dur: Duration) -> Result<u32> {
    timeout(dur, async {
        loop {
            if let Some(pid) = leader_pid(conn, name).await {
                return pid;
            }
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .with_context(|| format!("machined registration timeout for {name}"))
}

/// Guardrails on the machined scope — SetUnitProperties(runtime=true),
/// equivalent to `systemctl set-property --runtime`.
pub async fn apply_limits(conn: &Connection, name: &str, lim: &LimitsSpec) -> Result<()> {
    let Some(m) = machine(conn, name).await? else {
        bail!("machine {name} not registered with machined")
    };
    let unit = m.unit().await?;
    let mut props: Vec<(&str, Value)> = Vec::new();
    if lim.memory_high_bytes > 0 {
        props.push(("MemoryHigh", Value::from(lim.memory_high_bytes)));
    }
    if lim.memory_max_bytes > 0 {
        props.push(("MemoryMax", Value::from(lim.memory_max_bytes)));
    }
    if lim.cpu_quota_percent > 0 {
        // CPUQuota on the bus: µs per second; 100% = 1_000_000.
        props.push((
            "CPUQuotaPerSecUSec",
            Value::from(u64::from(lim.cpu_quota_percent) * 10_000),
        ));
    }
    if props.is_empty() {
        return Ok(());
    }
    SystemdManagerProxy::new(conn)
        .await?
        .set_unit_properties(&unit, true, props)
        .await
        .with_context(|| format!("SetUnitProperties {unit}"))
}

/// Clean shutdown (SIGRTMIN+3 → leader) → terminate → give up loudly.
/// The poweroff grace is ~8s — long enough for systemd to unmount cleanly,
/// short enough that `stop` doesn't stall a GUI click for 15s.
pub async fn stop(conn: &Connection, name: &str) -> Result<()> {
    if leader_pid(conn, name).await.is_none() {
        return Ok(());
    }
    let mgr = MachineManagerProxy::new(conn).await?;
    let _ = mgr.kill_machine(name, "leader", SIGRTMIN + 3).await;
    for _ in 0..40 {
        if leader_pid(conn, name).await.is_none() {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }
    tracing::warn!("{name}: poweroff timeout — terminating");
    let _ = mgr.terminate_machine(name).await;
    for _ in 0..20 {
        if leader_pid(conn, name).await.is_none() {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }
    bail!("pod {name} refuses to stop")
}
