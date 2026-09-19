//! rustypods-agent — phase-2 in-pod telemetry agent.
//! M1 stub: prints own cgroup/proc pressure stats once, then exits.
//! Later: UDS server streaming PodMetrics back to rustypodsd via the
//! /run/rustypods bind-mount.

use anyhow::Result;

fn main() -> Result<()> {
    println!("rustypods-agent v{} (stub)", env!("CARGO_PKG_VERSION"));
    if let Ok(psi) = std::fs::read_to_string("/proc/pressure/memory") {
        println!("memory.pressure: {}", psi.lines().next().unwrap_or("?"));
    }
    if let Ok(psi) = std::fs::read_to_string("/proc/pressure/cpu") {
        println!("cpu.pressure:    {}", psi.lines().next().unwrap_or("?"));
    }
    if let Ok(cur) = std::fs::read_to_string("/sys/fs/cgroup/memory.current") {
        println!("memory.current:  {} bytes", cur.trim());
    }
    Ok(())
}
