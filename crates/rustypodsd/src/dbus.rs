//! Native D-Bus calls naar machined + systemd — vervangt de
//! `machinectl`/`systemctl` subprocessen. Één gedeelde system-bus
//! `Connection` in Svc; zbus multiplext alle calls eroverheen.
//!
//! Geverifieerd op systemd 257 (busctl introspect + live trace):
//! - `machinectl poweroff` ≙ `KillMachine(name, "leader", SIGRTMIN+3)`
//!   — container-systemd interpreteert 37 als clean shutdown.
//! - `machinectl terminate` ≙ `TerminateMachine(name)` (hard kill).
//! - `systemctl set-property <scope> K=V` ≙
//!   `SetUnitProperties(unit, runtime=true, [("K", v)])` — CPUQuota heet
//!   op de bus `CPUQuotaPerSecUSec` (100% = 1_000_000 µs).

use anyhow::{bail, Context, Result};
use std::time::Duration;
use tokio::time::{sleep, timeout};
use zbus::zvariant::{OwnedObjectPath, Value};
use zbus::{proxy, Connection};

use crate::state::LimitsSpec;

/// glibc SIGRTMIN (kernel 32 + 2 NPTL-reserves). +3 = poweroff in de pod.
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
    /// Authoritative scope-naam ("machine-dev.scope") — geen gokwerk.
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
        Err(_) => return Ok(None), // NoSuchMachine → niet geregistreerd
    };
    Ok(Some(
        MachineProxy::builder(conn).path(path)?.build().await?,
    ))
}

/// machined is socket-activated; ping de systemd-manager om hem te waken.
pub async fn wake_machined(conn: &Connection) -> Result<()> {
    SystemdManagerProxy::new(conn)
        .await?
        .start_unit("systemd-machined.service", "replace")
        .await?;
    Ok(())
}

/// Is machined bereikbaar op de bus? (voor de `ping`-output)
pub async fn machined_up(conn: &Connection) -> bool {
    match MachineManagerProxy::new(conn).await {
        Ok(p) => p.list_machines().await.is_ok(),
        Err(_) => false,
    }
}

/// Leader-pid via machined; None als de pod niet draait.
pub async fn leader_pid(conn: &Connection, name: &str) -> Option<u32> {
    let m = machine(conn, name).await.ok()??;
    m.leader().await.ok().filter(|p| *p > 0)
}

/// Poll machined tot de pod geregistreerd is (nspawn doet dat zelf).
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
    .with_context(|| format!("machined registratie timeout voor {name}"))
}

/// Guardrails op de machined scope — SetUnitProperties(runtime=true),
/// equivalent aan `systemctl set-property --runtime`.
pub async fn apply_limits(conn: &Connection, name: &str, lim: &LimitsSpec) -> Result<()> {
    let Some(m) = machine(conn, name).await? else {
        bail!("machine {name} niet bij machined geregistreerd")
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
        // CPUQuota op de bus: µs per seconde; 100% = 1_000_000.
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

/// Clean shutdown (SIGRTMIN+3 → leader) → terminate → geef luidkeels op.
pub async fn stop(conn: &Connection, name: &str) -> Result<()> {
    if leader_pid(conn, name).await.is_none() {
        return Ok(());
    }
    let mgr = MachineManagerProxy::new(conn).await?;
    let _ = mgr.kill_machine(name, "leader", SIGRTMIN + 3).await;
    for _ in 0..75 {
        if leader_pid(conn, name).await.is_none() {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }
    tracing::warn!("{name}: poweroff timeout — terminate");
    let _ = mgr.terminate_machine(name).await;
    for _ in 0..25 {
        if leader_pid(conn, name).await.is_none() {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }
    bail!("pod {name} weigert te stoppen")
}
