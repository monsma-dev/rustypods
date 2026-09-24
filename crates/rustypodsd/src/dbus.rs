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

/// machined's GetMachine answer for an unknown machine.
const NO_SUCH_MACHINE: &str = "org.freedesktop.machine1.NoSuchMachine";

fn is_no_such_machine(e: &zbus::Error) -> bool {
    match e {
        zbus::Error::MethodError(name, ..) => name.as_str() == NO_SUCH_MACHINE,
        // A nested fdo error can wrap the reply on some paths — look inside.
        zbus::Error::FDO(e) => e.to_string().contains(NO_SUCH_MACHINE),
        _ => false,
    }
}

async fn machine<'a>(conn: &'a Connection, name: &str) -> Result<Option<MachineProxy<'a>>> {
    let mgr = MachineManagerProxy::new(conn).await?;
    let path = match mgr.get_machine(name).await {
        Ok(p) => p,
        // Only NoSuchMachine means "not registered". Every other failure
        // (bus down, machined hung, access denied) must propagate — before
        // this, any error looked like "pod not running" and destroy_pod
        // would happily delete a live pod's rootfs.
        Err(e) if is_no_such_machine(&e) => return Ok(None),
        Err(e) => return Err(e).context("machined GetMachine"),
    };
    Ok(Some(MachineProxy::builder(conn).path(path)?.build().await?))
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

/// Leader pid via machined; Ok(None) when the pod isn't registered OR is
/// registered-but-still-booting (leader property reads 0). Use
/// `registered()` or `running_pid()` to tell those apart.
pub async fn leader_pid(conn: &Connection, name: &str) -> Result<Option<u32>> {
    let Some(m) = machine(conn, name).await? else {
        return Ok(None);
    };
    Ok(m.leader().await.ok().filter(|p| *p > 0))
}

/// Is the pod registered with machined at all? A booting pod (leader 0)
/// counts — it exists and must still be stoppable/undeletable.
pub async fn registered(conn: &Connection, name: &str) -> Result<bool> {
    machine(conn, name).await.map(|m| m.is_some())
}

/// Some(leader) while the pod is registered — leader 0 means booting.
/// Callers that need a real pid (nsenter) must handle 0; callers that only
/// distinguish running/not get the right answer either way.
pub async fn running_pid(conn: &Connection, name: &str) -> Result<Option<u32>> {
    let Some(m) = machine(conn, name).await? else {
        return Ok(None);
    };
    Ok(Some(m.leader().await.unwrap_or(0)))
}

/// The machined scope name ("machine-<name>.scope") — authoritative;
/// never format it yourself. None when the pod isn't registered.
pub async fn unit_name(conn: &Connection, name: &str) -> Result<Option<String>> {
    let Some(m) = machine(conn, name).await? else {
        return Ok(None);
    };
    Ok(Some(m.unit().await?))
}

/// Poll machined until the pod has a live leader (nspawn registers first,
/// the leader appears once init is up).
pub async fn wait_registered(conn: &Connection, name: &str, dur: Duration) -> Result<u32> {
    timeout(dur, async {
        loop {
            if let Some(pid) = leader_pid(conn, name).await? {
                return anyhow::Ok(pid);
            }
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .with_context(|| format!("machined registration timeout for {name}"))?
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
/// `grace` is how long to wait for the poweroff signal before
/// TerminateMachine. The hard-kill wait after that stays ~4s.
///
/// "Stopped" means *unregistered* — a booting pod (leader 0) has no signal
/// target but must still be terminated by name, not mistaken for stopped.
pub async fn stop(conn: &Connection, name: &str, grace: Duration) -> Result<()> {
    if !registered(conn, name).await? {
        return Ok(());
    }
    let mgr = MachineManagerProxy::new(conn).await?;
    // kill_machine("leader") fails on a leader-less booting pod — fine,
    // TerminateMachine below works by name either way.
    let _ = mgr.kill_machine(name, "leader", SIGRTMIN + 3).await;
    let polls = (grace.as_millis() / 200).min(u128::from(u32::MAX)) as u32;
    for _ in 0..polls {
        if !registered(conn, name).await.unwrap_or(true) {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }
    tracing::warn!("{name}: poweroff timeout — terminating");
    let _ = mgr.terminate_machine(name).await;
    for _ in 0..20 {
        if !registered(conn, name).await.unwrap_or(true) {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }
    bail!("pod {name} refuses to stop")
}
