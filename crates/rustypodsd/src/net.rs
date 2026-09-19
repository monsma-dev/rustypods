//! Port forwarding without nspawn's --port machinery (which requires
//! systemd-networkd on the host — NetworkManager/Netplan hosts have none).
//!
//! Instead the daemon owns the addressing and NAT itself:
//! - each port-mapped pod gets a stable index → a /30 pair in 10.220.<idx>.0/30
//!   (host side .1 on ve-<name>, pod side .2 on host0)
//! - a static networkd file is written into the pod rootfs before boot
//! - after boot the daemon configures the host veth and rebuilds a dedicated
//!   `ip rustypods` nftables table from live state (self-healing, idempotent)

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::state::PodMeta;

const POOL_BASE: [u8; 3] = [10, 220, 0];

/// Host iface for a pod's veth pair (nspawn truncates to IFNAMSIZ-1 chars).
pub fn veth_name(pod: &str) -> String {
    format!("ve-{}", &pod[..pod.len().min(12)])
}

pub fn host_ip(idx: u32) -> Ipv4Addr {
    Ipv4Addr::new(POOL_BASE[0], POOL_BASE[1], idx as u8, 1)
}
pub fn pod_ip(idx: u32) -> Ipv4Addr {
    Ipv4Addr::new(POOL_BASE[0], POOL_BASE[1], idx as u8, 2)
}
/// Lowest free index in 1..=255 across all pods.
pub fn alloc_index(pods: &BTreeMap<String, PodMeta>) -> u32 {
    let used: std::collections::BTreeSet<u32> =
        pods.values().map(|p| p.net_index).filter(|i| *i > 0).collect();
    (1..=255).find(|i| !used.contains(i)).unwrap_or(0)
}

/// Static host0 config inside the pod rootfs. Written to
/// etc/systemd/network/80-container-host0.network — an /etc file of the same
/// name cleanly overrides the stock /usr/lib one. Also enables networkd.
pub fn write_pod_network(rootfs: &Path, idx: u32) -> Result<()> {
    let dir = rootfs.join("etc/systemd/network");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("80-container-host0.network"),
        format!(
            "[Match]\nName=host0\n\n[Network]\nAddress={}/30\nGateway={}\n",
            pod_ip(idx),
            host_ip(idx)
        ),
    )?;
    // Enable systemd-networkd (service + its socket) in the pod.
    for wants in [
        "etc/systemd/system/multi-user.target.wants",
        "etc/systemd/system/sockets.target.wants",
    ] {
        let d = rootfs.join(wants);
        std::fs::create_dir_all(&d)?;
    }
    let units = [
        (
            "multi-user.target.wants/systemd-networkd.service",
            "/usr/lib/systemd/system/systemd-networkd.service",
        ),
        (
            "sockets.target.wants/systemd-networkd.socket",
            "/usr/lib/systemd/system/systemd-networkd.socket",
        ),
    ];
    for (link, target) in units {
        let p = rootfs.join("etc/systemd/system").join(link);
        let _ = std::fs::remove_file(&p);
        let _ = std::os::unix::fs::symlink(target, &p);
    }
    Ok(())
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running {cmd}"))?;
    if out.status.success() {
        Ok(())
    } else {
        bail!("{cmd} {args:?}: {}", String::from_utf8_lossy(&out.stderr).trim())
    }
}

// --- stacks: one shared netns per stack (the K8s pod model) -----------------

/// Named netns for a stack: `ip netns add rustypods-<stack>`.
pub fn netns_name(stack: &str) -> String {
    format!("rustypods-{stack}")
}

/// The path nspawn's --network-namespace-path expects (ip netns bind-mounts
/// the ns file there).
pub fn netns_path(stack: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/var/run/netns/{}", netns_name(stack)))
}

/// Peer interface inside the stack netns (host side stays ve-<stack>).
fn stack_peer(stack: &str) -> String {
    format!("vp-{}", &stack[..stack.len().min(12)])
}

/// Create (idempotently) the shared stack netns + its veth uplink:
/// ve-<stack> in the root ns gets .1/30, vp-<stack> inside the netns gets
/// .2/30 + a default route. Pods then join via --network-namespace-path and
/// share lo — every member sees the same 127.0.0.1.
pub fn ensure_stack_net(stack: &str, idx: u32) -> Result<()> {
    let ns = netns_name(stack);
    if !netns_path(stack).exists() {
        run("ip", &["netns", "add", &ns])?;
    }
    let host_v = veth_name(stack);
    let peer = stack_peer(stack);
    if !Path::new(&format!("/sys/class/net/{host_v}")).exists() {
        run("ip", &["link", "add", &host_v, "type", "veth", "peer", "name", &peer])?;
        run("ip", &["link", "set", &peer, "netns", &ns])?;
    }
    run("ip", &["link", "set", &host_v, "up"])?;
    run(
        "ip",
        &["addr", "replace", &format!("{}/30", host_ip(idx)), "dev", &host_v],
    )?;
    // Same localhost-DNAT martian guard as standalone pods.
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{host_v}/route_localnet"),
        "1",
    );
    run("ip", &["netns", "exec", &ns, "ip", "link", "set", "lo", "up"])?;
    run("ip", &["netns", "exec", &ns, "ip", "link", "set", &peer, "up"])?;
    run(
        "ip",
        &[
            "netns", "exec", &ns, "ip", "addr", "replace",
            &format!("{}/30", pod_ip(idx)), "dev", &peer,
        ],
    )?;
    run(
        "ip",
        &["netns", "exec", &ns, "ip", "route", "replace", "default", "via", &host_ip(idx).to_string()],
    )?;
    Ok(())
}

/// Tear the stack netns down: deleting the host veth also kills the peer
/// inside the ns; `ip netns del` removes the named namespace itself.
pub fn teardown_stack_net(stack: &str) {
    let _ = run("ip", &["link", "del", &veth_name(stack)]);
    let _ = run("ip", &["netns", "del", &netns_name(stack)]);
}

/// Wait for nspawn to create the veth, then give the host end its address.
pub async fn configure_host_veth(pod: &str, idx: u32) -> Result<()> {
    let veth = veth_name(pod);
    let sys = format!("/sys/class/net/{veth}");
    for _ in 0..150 {
        if Path::new(&sys).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !Path::new(&sys).exists() {
        bail!("veth {veth} never appeared");
    }
    run("ip", &["link", "set", &veth, "up"])?;
    run(
        "ip",
        &["addr", "replace", &format!("{}/30", host_ip(idx)), "dev", &veth],
    )?;
    // Replies to localhost-DNAT'd flows arrive with a 127/8 source — dropped
    // as martian unless the receiving iface allows it.
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{veth}/route_localnet"),
        "1",
    );
    Ok(())
}

/// Kernel knobs required for DNAT into the veth — ip_forward for routed
/// traffic, route_localnet so localhost→pod flows survive (Docker does the
/// same on container hosts). Idempotent.
pub fn ensure_ip_forward() -> Result<()> {
    let fwd = "/proc/sys/net/ipv4/ip_forward";
    if std::fs::read_to_string(fwd).ok().as_deref() != Some("1\n") {
        std::fs::write(fwd, "1").context("enable net.ipv4.ip_forward")?;
    }
    Ok(())
}

fn port_rule_ports(spec: &str) -> Option<(u16, u16, &'static str)> {
    let (ports, proto) = match spec.split_once('/') {
        Some((p, pr)) => (p, pr),
        None => (spec, "tcp"),
    };
    let proto = match proto {
        "tcp" => "tcp",
        "udp" => "udp",
        _ => return None,
    };
    let mut it = ports.split(':');
    let host: u16 = it.next()?.parse().ok()?;
    let pod: u16 = it.next().unwrap_or("").parse().unwrap_or(host);
    Some((host, pod, proto))
}

/// Rebuild the `ip rustypods` table from scratch for `pods` — every running
/// pod with a net_index contributes DNAT rules; masquerade covers outbound.
/// Idempotent and self-healing: any drift is corrected on the next call.
pub fn rebuild_nat<'a>(
    pods: impl Iterator<Item = &'a PodMeta>,
    running: &std::collections::BTreeSet<String>,
) {
    let mut dnat = String::new();
    for m in pods.filter(|m| m.net_index > 0 && running.contains(&m.name)) {
        for spec in &m.ports {
            let Some((hp, pp, proto)) = port_rule_ports(spec) else {
                continue;
            };
            let dst = format!("{}:{}", pod_ip(m.net_index), pp);
            // `fib daddr type local` scopes DNAT to traffic addressed to
            // THIS host — without it, outbound connections to another
            // machine on a mapped port would be redirected into the pod.
            dnat.push_str(&format!(
                "    fib daddr type local {proto} dport {hp} dnat ip to {dst}\n"
            ));
        }
    }
    let rules = format!(
        "table ip rustypods {{\n\
         \x20 chain prerouting {{\n\
         \x20   type nat hook prerouting priority dstnat; policy accept;\n\
         {dnat}\
         \x20 }}\n\
         \x20 chain output {{\n\
         \x20   type nat hook output priority -100; policy accept;\n\
         {dnat}\
         \x20 }}\n\
         \x20 chain postrouting {{\n\
         \x20   type nat hook postrouting priority srcnat; policy accept;\n\
         \x20   # host-originated traffic to pods must be SNAT'd to the veth ip\n\
         \x20   # (a pod would answer 127.0.0.1 on its OWN loopback otherwise)\n\
         \x20   fib saddr type local ip daddr 10.220.0.0/16 masquerade\n\
         \x20   # pod egress onto the real network\n\
         \x20   ip saddr 10.220.0.0/16 oifname != \"ve-*\" masquerade\n\
         \x20 }}\n\
         }}\n"
    );
    // Flush+replace atomically: declare the table (idempotent), delete its
    // old ruleset, recreate from live state.
    let script =
        format!("add table ip rustypods\ndelete table ip rustypods\n{rules}");
    let res = (|| -> Result<()> {
        use std::io::Write;
        let mut c = Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("spawn nft")?;
        c.stdin.take().unwrap().write_all(script.as_bytes())?;
        let st = c.wait()?;
        if !st.success() {
            bail!("nft -f exited {st}");
        }
        Ok(())
    })();
    if let Err(e) = res {
        tracing::warn!("nft rebuild failed: {e:#}");
    }
}
