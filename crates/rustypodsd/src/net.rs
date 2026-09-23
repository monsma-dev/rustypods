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
use std::net::{Ipv4Addr, Ipv6Addr};
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
/// Same per-pod pairing in IPv6 ULA space: fd22:0220:<idx>::1 (host) and
/// ::2 (pod) on a /64. `idx as u16` keeps the pool aligned with the v4
/// 1..=255 indexes.
pub fn host_ip6(idx: u32) -> Ipv6Addr {
    Ipv6Addr::new(0xfd22, 0x0220, idx as u16, 0, 0, 0, 0, 1)
}
pub fn pod_ip6(idx: u32) -> Ipv6Addr {
    Ipv6Addr::new(0xfd22, 0x0220, idx as u16, 0, 0, 0, 0, 2)
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
/// All writes go through crate::rootfs: an image-planted `etc -> /host`
/// symlink must fail, never redirect writes onto the host.
pub fn write_pod_network(rootfs: &Path, idx: u32) -> Result<()> {
    use crate::rootfs as rfs;
    rfs::mkdir_in_rootfs(rootfs, "etc/systemd/network")?;
    rfs::write_in_rootfs(
        rootfs,
        "etc/systemd/network/80-container-host0.network",
        format!(
            "[Match]\nName=host0\n\n[Network]\nAddress={}/30\nAddress={}/64\nGateway={}\nGateway={}\n",
            pod_ip(idx),
            pod_ip6(idx),
            host_ip(idx),
            host_ip6(idx)
        )
        .as_bytes(),
        None,
    )?;
    // Enable systemd-networkd (service + its socket) in the pod.
    for wants in [
        "etc/systemd/system/multi-user.target.wants",
        "etc/systemd/system/sockets.target.wants",
    ] {
        rfs::mkdir_in_rootfs(rootfs, wants)?;
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
        // The target is an in-container path — stored verbatim, never
        // resolved on the host.
        rfs::symlink_in_rootfs(
            rootfs,
            format!("etc/systemd/system/{link}"),
            Path::new(target),
        )?;
    }
    Ok(())
}

/// Blocking subprocess — the sync callers of this are themselves invoked
/// via `tokio::task::spawn_blocking` (or run on a dedicated thread), so it
/// never sits on the async executor.
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

/// `run` on the blocking pool — for the one async caller
/// (configure_veth) that can't itself be wrapped in spawn_blocking
/// because it interleaves `ip` calls with async sleeps.
async fn run_async(cmd: &'static str, args: &[&str]) -> Result<()> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run(cmd, &refs)
    })
    .await
    .context("blocking task")?
}

/// `nsenter --target <pid> --net -- <args>` — run the host's `ip` inside
/// one process's network namespace only. Used to wire host0 on pods whose
/// payload has no networkd (bare OCI images).
async fn nsenter_net(leader: u32, args: &[&str]) -> Result<()> {
    let mut argv: Vec<String> = vec![
        "--target".into(),
        leader.to_string(),
        "--net".into(),
        "--".into(),
    ];
    argv.extend(args.iter().map(|s| s.to_string()));
    tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        run("nsenter", &refs)
    })
    .await
    .context("blocking task")?
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
    // `nodad`: skip Duplicate Address Detection — the ULA space is
    // daemon-owned, and a tentative address would be unusable for ~1s.
    run(
        "ip",
        &[
            "addr",
            "replace",
            &format!("{}/64", host_ip6(idx)),
            "dev",
            &host_v,
            "nodad",
        ],
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
        &[
            "netns", "exec", &ns, "ip", "addr", "replace",
            &format!("{}/64", pod_ip6(idx)), "dev", &peer, "nodad",
        ],
    )?;
    run(
        "ip",
        &["netns", "exec", &ns, "ip", "route", "replace", "default", "via", &host_ip(idx).to_string()],
    )?;
    run(
        "ip",
        &[
            "netns", "exec", &ns, "ip", "-6", "route", "replace", "default", "via",
            &host_ip6(idx).to_string(),
        ],
    )?;
    Ok(())
}

/// Tear the stack netns down: deleting the host veth also kills the peer
/// inside the ns; `ip netns del` removes the named namespace itself.
pub fn teardown_stack_net(stack: &str) {
    let _ = run("ip", &["link", "del", &veth_name(stack)]);
    let _ = run("ip", &["netns", "del", &netns_name(stack)]);
}

/// Wait for nspawn to create the veth, configure the host end, then finish
/// the pod end inside the pod's netns via nsenter (entering ONLY the net
/// namespace — never the mount ns). The pod side matters for bare OCI
/// payload pods: they have no systemd-networkd to configure host0, so
/// without this they get a dead link. On booted pods it converges to the
/// same state networkd would reach — every step is idempotent.
/// `leader` is the pod init pid; 0 means "registered but no pid yet" and
/// is refused — start must not report success before the link is usable.
pub async fn configure_veth(pod: &str, idx: u32, leader: u32) -> Result<()> {
    if leader == 0 {
        bail!("pod has no usable leader pid yet — cannot enter its netns");
    }
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
    run_async("ip", &["link", "set", &veth, "up"]).await?;
    run_async(
        "ip",
        &["addr", "replace", &format!("{}/30", host_ip(idx)), "dev", &veth],
    )
    .await?;
    // `nodad` as on the stack path — the daemon owns this ULA space.
    run_async(
        "ip",
        &[
            "addr",
            "replace",
            &format!("{}/64", host_ip6(idx)),
            "dev",
            &veth,
            "nodad",
        ],
    )
    .await?;
    // Replies to localhost-DNAT'd flows arrive with a 127/8 source — dropped
    // as martian unless the receiving iface allows it.
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{veth}/route_localnet"),
        "1",
    );
    // Pod side: host root's nsenter into the leader's netns only, then the
    // host's `ip` binary (an in-pod iproute isn't guaranteed to exist).
    nsenter_net(leader, &["ip", "link", "set", "lo", "up"]).await?;
    nsenter_net(leader, &["ip", "link", "set", "host0", "up"]).await?;
    nsenter_net(
        leader,
        &[
            "ip",
            "addr",
            "replace",
            &format!("{}/30", pod_ip(idx)),
            "dev",
            "host0",
        ],
    )
    .await?;
    nsenter_net(
        leader,
        &[
            "ip",
            "addr",
            "replace",
            &format!("{}/64", pod_ip6(idx)),
            "dev",
            "host0",
            "nodad",
        ],
    )
    .await?;
    nsenter_net(
        leader,
        &["ip", "route", "replace", "default", "via", &host_ip(idx).to_string()],
    )
    .await?;
    nsenter_net(
        leader,
        &[
            "ip",
            "-6",
            "route",
            "replace",
            "default",
            "via",
            &host_ip6(idx).to_string(),
        ],
    )
    .await?;
    Ok(())
}

/// Kernel knobs required for DNAT into the veth — ip_forward (v4 and v6)
/// for routed traffic, route_localnet so localhost→pod flows survive
/// (Docker does the same on container hosts). Idempotent; a kernel
/// without IPv6 fails hard rather than leaving half-configured stacks.
pub fn ensure_ip_forward() -> Result<()> {
    let fwd = "/proc/sys/net/ipv4/ip_forward";
    if std::fs::read_to_string(fwd).ok().as_deref() != Some("1\n") {
        std::fs::write(fwd, "1").context("enable net.ipv4.ip_forward")?;
    }
    let fwd6 = "/proc/sys/net/ipv6/conf/all/forwarding";
    if std::fs::read_to_string(fwd6).ok().as_deref() != Some("1\n") {
        std::fs::write(fwd6, "1").context("enable net.ipv6.conf.all.forwarding")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_helpers() {
        assert_eq!(host_ip(1).to_string(), "10.220.1.1");
        assert_eq!(pod_ip(1).to_string(), "10.220.1.2");
        assert_eq!(host_ip(255).to_string(), "10.220.255.1");
        assert_eq!(host_ip6(1).to_string(), "fd22:220:1::1");
        assert_eq!(pod_ip6(1).to_string(), "fd22:220:1::2");
        assert_eq!(pod_ip6(255).to_string(), "fd22:220:ff::2");
    }

    /// The in-rootfs networkd file must configure host0 dual-stack so
    /// booted pods get both families; payload pods get the same values
    /// via configure_veth's nsenter calls.
    #[test]
    fn networkd_file_is_dual_stack() {
        let dir = std::env::temp_dir().join(format!("rp-net-{}", std::process::id()));
        let rootfs = dir.join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();
        write_pod_network(&rootfs, 7).unwrap();
        let text = std::fs::read_to_string(
            rootfs.join("etc/systemd/network/80-container-host0.network"),
        )
        .unwrap();
        assert!(text.contains("Address=10.220.7.2/30"));
        assert!(text.contains("Address=fd22:220:7::2/64"));
        assert!(text.contains("Gateway=10.220.7.1"));
        assert!(text.contains("Gateway=fd22:220:7::1"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
