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
    let used: std::collections::BTreeSet<u32> = pods
        .values()
        .map(|p| p.net_index)
        .filter(|i| *i > 0)
        .collect();
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
pub(crate) fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running {cmd}"))?;
    if out.status.success() {
        Ok(())
    } else {
        bail!(
            "{cmd} {args:?}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

/// Blocking subprocess returning stdout — same contract as `run`.
fn run_out(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running {cmd}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        bail!(
            "{cmd} {args:?}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
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
pub(crate) async fn nsenter_net(leader: u32, args: &[&str]) -> Result<()> {
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

/// `nsenter_net` variant that returns stdout (e.g. sysfs reads).
async fn nsenter_net_out(leader: u32, args: &[&str]) -> Result<String> {
    let mut argv: Vec<String> = vec![
        "--target".into(),
        leader.to_string(),
        "--net".into(),
        "--".into(),
    ];
    argv.extend(args.iter().map(|s| s.to_string()));
    tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        run_out("nsenter", &refs)
    })
    .await
    .context("blocking task")?
}

/// The host interface whose ifindex is `idx` — the peer index is unique
/// in the host's ifindex space, so this can never match the wrong veth.
fn host_iface_by_ifindex(idx: u32) -> Option<String> {
    for e in std::fs::read_dir("/sys/class/net").ok()?.flatten() {
        let Ok(s) = std::fs::read_to_string(e.path().join("ifindex")) else {
            continue;
        };
        if s.trim().parse::<u32>().ok() == Some(idx) {
            return Some(e.file_name().to_string_lossy().into_owned());
        }
    }
    None
}

/// Wait for nspawn to create the pod's veth pair and return the HOST
/// interface's real name. Resolved by peer ifindex — never by name:
/// nspawn's host ifname for a long machine name is not a plain
/// truncation (systemd's naming scheme rewrites it with a hash suffix,
/// e.g. 've-rustypod0iFF'), so guessing `ve-<name>` breaks on pod names
/// longer than ~12 chars.
///
/// `host0@ifN` inside the pod netns carries the host end's ifindex —
/// unique in the host's ifindex space. Read via `ip` (netlink → the
/// pod's CURRENT netns), not /sys: `nsenter --net` does not enter the
/// mount ns, so /sys/class/net keeps showing the HOST's interfaces.
pub(crate) async fn wait_host_veth(leader: u32) -> Result<String> {
    for _ in 0..150 {
        let out = nsenter_net_out(leader, &["ip", "-o", "link", "show"]).await;
        // Any interface with an '@if' peer suffix is the veth end — don't
        // assume the container side is literally called host0 either.
        let peer = out.ok().and_then(|s| {
            s.lines().find_map(|l| {
                l.split("@if")
                    .nth(1)?
                    .split(':')
                    .next()?
                    .parse::<u32>()
                    .ok()
            })
        });
        if let Some(idx) = peer {
            if let Some(name) = host_iface_by_ifindex(idx) {
                return Ok(name);
            }
        }
        // No veth end yet (still moving into the netns).
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("veth peer of pod leader {leader} never appeared (host0@ifN unresolved)");
}

/// firewalld locks `inet firewalld` with the kernel `owner` flag —
/// inserts from any other netlink socket get EPERM, so the
/// foreign-chain path can't coexist with it. The sanctioned interface
/// is `firewall-cmd`: binding each pod veth to the built-in `trusted`
/// zone (ACCEPT target) is exactly what the zone model is for — covers
/// FORWARD and INPUT, runtime-only, inert once the interface dies, and
/// never mutates the user's firewalld config. Silent when firewalld
/// isn't running.
async fn firewalld_bind(veth: &str) {
    if run_async("firewall-cmd", &["--state"]).await.is_err() {
        return;
    }
    if let Err(e) = run_async("firewall-cmd", &["--zone=trusted", "--add-interface", veth]).await {
        tracing::warn!("firewalld trusted-bind {veth}: {e:#}");
    }
}

/// Blocking variant for the sync stack-net path.
pub(crate) fn firewalld_bind_sync(veth: &str) {
    if run("firewall-cmd", &["--state"]).is_err() {
        return;
    }
    if let Err(e) = run("firewall-cmd", &["--zone=trusted", "--add-interface", veth]) {
        tracing::warn!("firewalld trusted-bind {veth}: {e:#}");
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
        run(
            "ip",
            &[
                "link", "add", &host_v, "type", "veth", "peer", "name", &peer,
            ],
        )?;
        run("ip", &["link", "set", &peer, "netns", &ns])?;
    }
    firewalld_bind_sync(&host_v);
    run("ip", &["link", "set", &host_v, "up"])?;
    run(
        "ip",
        &[
            "addr",
            "replace",
            &format!("{}/30", host_ip(idx)),
            "dev",
            &host_v,
        ],
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
    run(
        "ip",
        &["netns", "exec", &ns, "ip", "link", "set", "lo", "up"],
    )?;
    run(
        "ip",
        &["netns", "exec", &ns, "ip", "link", "set", &peer, "up"],
    )?;
    run(
        "ip",
        &[
            "netns",
            "exec",
            &ns,
            "ip",
            "addr",
            "replace",
            &format!("{}/30", pod_ip(idx)),
            "dev",
            &peer,
        ],
    )?;
    run(
        "ip",
        &[
            "netns",
            "exec",
            &ns,
            "ip",
            "addr",
            "replace",
            &format!("{}/64", pod_ip6(idx)),
            "dev",
            &peer,
            "nodad",
        ],
    )?;
    run(
        "ip",
        &[
            "netns",
            "exec",
            &ns,
            "ip",
            "route",
            "replace",
            "default",
            "via",
            &host_ip(idx).to_string(),
        ],
    )?;
    run(
        "ip",
        &[
            "netns",
            "exec",
            &ns,
            "ip",
            "-6",
            "route",
            "replace",
            "default",
            "via",
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
pub async fn configure_veth(_pod: &str, idx: u32, leader: u32) -> Result<()> {
    if leader == 0 {
        bail!("pod has no usable leader pid yet — cannot enter its netns");
    }
    let veth = wait_host_veth(leader).await?;
    firewalld_bind(&veth).await;
    run_async("ip", &["link", "set", &veth, "up"]).await?;
    run_async(
        "ip",
        &[
            "addr",
            "replace",
            &format!("{}/30", host_ip(idx)),
            "dev",
            &veth,
        ],
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
        &[
            "ip",
            "route",
            "replace",
            "default",
            "via",
            &host_ip(idx).to_string(),
        ],
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

/// Wave I: give a pod its mesh identity — fd<host>:<idx>::2/128 on
/// host0 plus a host-side route steering decrypted inbound traffic
/// into this pod's veth. Pods need no extra route: the v6 default
/// already points at the host. Idempotent (`replace`) so re-entry is
/// safe (mesh_init on already-running pods, daemon restart).
pub async fn configure_mesh_addr(idx: u32, leader: u32, prefix: std::net::Ipv6Addr) -> Result<()> {
    if leader == 0 {
        bail!("pod has no usable leader pid yet — cannot enter its netns");
    }
    let addr = crate::mesh::mesh_ip(prefix, idx);
    let veth = wait_host_veth(leader).await?;
    run_async(
        "ip",
        &[
            "-6",
            "route",
            "replace",
            &format!("{addr}/128"),
            "dev",
            &veth,
        ],
    )
    .await?;
    nsenter_net(
        leader,
        &[
            "ip",
            "-6",
            "addr",
            "replace",
            &format!("{addr}/128"),
            "dev",
            "host0",
            "nodad",
        ],
    )
    .await?;
    Ok(())
}

/// `mesh deinit` counterpart — strip a pod's mesh /128 (in-pod addr +
/// host-side route). Best-effort: the pod may be mid-stop, so failures
/// are the caller's to log, not fatal.
pub async fn remove_mesh_addr(idx: u32, leader: u32, prefix: std::net::Ipv6Addr) -> Result<()> {
    let addr = crate::mesh::mesh_ip(prefix, idx);
    if let Ok(veth) = wait_host_veth(leader).await {
        let _ = run_async(
            "ip",
            &["-6", "route", "del", &format!("{addr}/128"), "dev", &veth],
        )
        .await;
    }
    if leader != 0 {
        let _ = nsenter_net(
            leader,
            &[
                "ip",
                "-6",
                "addr",
                "del",
                &format!("{addr}/128"),
                "dev",
                "host0",
            ],
        )
        .await;
    }
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

/// Mesh forwarding accepts (Wave I): pod↔tun traffic carries ULA
/// fd00::/8 addresses, which sit OUTSIDE the fd22:220::/32 pod pool the
/// base accepts cover. ULA is non-routable on the public internet, so
/// accepting it in FORWARD is safe and required on every host firewall
/// shape (ufw iptables-compat, plain inet filter, and — via
/// firewalld_bind on rp-mesh0 — firewalld zones).
pub(crate) fn ensure_mesh_forward() {
    const MARK: &str = "rustypods-mesh-fwd";
    for (fam, rules) in [
        (
            "ip6",
            ["ip6 saddr fd00::/8 accept", "ip6 daddr fd00::/8 accept"].as_slice(),
        ),
        (
            "inet",
            ["ip6 saddr fd00::/8 accept", "ip6 daddr fd00::/8 accept"].as_slice(),
        ),
    ] {
        let out = Command::new("nft")
            .args(["list", "chain", fam, "filter", "FORWARD"])
            .output();
        let Ok(out) = out else { continue };
        if !out.status.success() {
            continue;
        }
        let txt = String::from_utf8_lossy(&out.stdout);
        if txt.contains(MARK) {
            continue;
        }
        for r in rules {
            let mut argv: Vec<&str> = vec!["insert", "rule", fam, "filter", "FORWARD"];
            argv.extend(r.split_whitespace());
            argv.extend(["comment", MARK]);
            match Command::new("nft").args(&argv).status() {
                Ok(s) if s.success() => {}
                Ok(s) => tracing::warn!("nft insert into {fam} filter FORWARD: exit {s}"),
                Err(e) => tracing::warn!("nft insert into {fam} filter FORWARD: {e}"),
            }
        }
        tracing::info!("installed mesh ULA accepts in {fam} filter FORWARD");
    }
}

/// Mesh INPUT accepts (Wave K): pod→host DNS and decapsulated gossip
/// hit the INPUT chain, not FORWARD — and an inbound WireGuard
/// handshake on a passive host is a NEW conntrack entry, dropped by
/// ufw/firewalld default-drop INPUT before boringtun ever sees it.
/// Scoped tight: ULA srcs only on our own interfaces (ve-* pod veths,
/// rp-mesh* TUNs), plus the WG UDP port on any interface.
pub(crate) fn ensure_mesh_input(wg_port: u16) {
    const MARK: &str = "rustypods-mesh-in";
    let wg = wg_port.to_string();
    // Rule tails as argv slices — iifname wildcards need real quotes,
    // so no whitespace-split string rules here.
    // Presence is probed per rule, not per chain: a changed WG
    // listen_port must still install its accept on a marked chain,
    // and stale accepts for an OLD port get deleted below.
    let ula_rule: Vec<&str> = vec![
        "iifname",
        "{",
        "\"ve-*\"",
        ",",
        "\"rp-mesh*\"",
        "}",
        "ip6",
        "saddr",
        "fd00::/8",
        "accept",
    ];
    for (fam, rules) in [
        (
            "ip6",
            vec![
                ("\"ve-*\"", ula_rule.clone()),
                ("dport", vec!["udp", "dport", wg.as_str(), "accept"]),
            ],
        ),
        (
            "inet",
            vec![
                ("\"ve-*\"", ula_rule.clone()),
                ("dport", vec!["udp", "dport", wg.as_str(), "accept"]),
            ],
        ),
        (
            "ip",
            vec![("dport", vec!["udp", "dport", wg.as_str(), "accept"])],
        ),
    ] {
        let out = Command::new("nft")
            .args(["-a", "list", "chain", fam, "filter", "INPUT"])
            .output();
        let Ok(out) = out else { continue };
        if !out.status.success() {
            continue;
        }
        let txt = String::from_utf8_lossy(&out.stdout);
        // Retire our own stale WG-port accepts from a previous
        // listen_port — the marker identifies them as ours.
        for line in txt.lines() {
            let stale_port = line.contains(MARK)
                && line.contains("udp dport")
                && !line.contains(&format!("udp dport {wg}"));
            if !stale_port {
                continue;
            }
            if let Some(h) = line
                .rsplit("handle ")
                .next()
                .and_then(|s| s.trim().parse::<u64>().ok())
            {
                let _ = Command::new("nft")
                    .args([
                        "delete",
                        "rule",
                        fam,
                        "filter",
                        "INPUT",
                        "handle",
                        &h.to_string(),
                    ])
                    .status();
            }
        }
        let mut installed = false;
        for (probe, r) in &rules {
            let present = match *probe {
                "dport" => txt.contains(&format!("udp dport {wg}")),
                _ => txt.contains(probe),
            };
            if present {
                continue;
            }
            let mut argv: Vec<&str> = vec!["insert", "rule", fam, "filter", "INPUT"];
            argv.extend(r.iter());
            argv.extend(["comment", MARK]);
            match Command::new("nft").args(&argv).status() {
                Ok(s) if s.success() => installed = true,
                Ok(s) => tracing::warn!("nft insert into {fam} filter INPUT: exit {s}"),
                Err(e) => tracing::warn!("nft insert into {fam} filter INPUT: {e}"),
            }
        }
        if installed {
            tracing::info!("installed mesh accepts in {fam} filter INPUT");
        }
    }
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
/// The whole nft transaction for both managed tables, generated from
/// state. Pure so tests (and `nft --check`) can inspect it.
///
/// Tables:
/// - `ip rustypods`: user port DNAT (prerouting + fib-local output),
///   host→pod and pod-egress masquerade — unchanged semantics. When the
///   ingress gateway runs it ALSO gets loopback-only OUTPUT rules for
///   80/443 → gateway :8080/:8443. Ingress rules live in OUTPUT only —
///   never prerouting, so nothing off-LAN can reach them.
/// - `ip6 rustypods6`: always managed (created+flushed even without a
///   gateway so stale rules die). ::1 OUTPUT dnat for the gateway plus
///   ULA postrouting masquerade covering loopback→pod and pod egress.
pub fn nat_script<'a>(
    pods: impl Iterator<Item = &'a PodMeta>,
    running: &std::collections::BTreeSet<String>,
) -> String {
    let mut dnat = String::new();
    let mut gw: Option<u32> = None;
    for m in pods.filter(|m| m.net_index > 0 && running.contains(&m.name)) {
        if m.ingress_gateway {
            // Exactly one gateway is enforced at load; last one wins if
            // a hand-built state slips through — harmless, same shape.
            gw = Some(m.net_index);
            continue;
        }
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
    // Loopback-only ingress redirects — OUTPUT hook, 127/8 destinations,
    // so a packet that arrived on any interface can never match (no
    // prerouting chain carries these at all).
    //
    // IPv6 is deliberately NOT redirected: ::1→pod dnat produces replies
    // whose un-nat'd ::1 tuple arrives on a veth — the kernel hard-drops
    // loopback tuples on non-loopback devices (tcp_v6_rcv; no
    // route_localnet equivalent exists for v6). Leaving ::1 alone gives
    // an instant RST and happy-eyeballs clients fall back to 127.0.0.1.
    let mut gw_v4 = String::new();
    if let Some(idx) = gw {
        let v4 = pod_ip(idx);
        gw_v4.push_str(&format!(
            "    ip daddr 127.0.0.0/8 tcp dport 80 dnat ip to {v4}:8080\n\
             \x20   ip daddr 127.0.0.0/8 tcp dport 443 dnat ip to {v4}:8443\n"
        ));
    }
    let rules = format!(
        "table ip rustypods {{\n\
         \x20 chain prerouting {{\n\
         \x20   type nat hook prerouting priority dstnat; policy accept;\n\
         {dnat}\
         \x20 }}\n\
         \x20 chain output {{\n\
         \x20   type nat hook output priority -100; policy accept;\n\
         {gw_v4}\
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
         }}\n\
         table ip6 rustypods6 {{\n\
         \x20 chain postrouting {{\n\
         \x20   type nat hook postrouting priority srcnat; policy accept;\n\
         \x20   # ULA pod egress onto the real network\n\
         \x20   ip6 saddr fd22:220::/32 oifname != \"ve-*\" masquerade\n\
         \x20 }}\n\
         }}\n"
    );
    // Flush+replace atomically: declare each table (idempotent), delete
    // the old ruleset, recreate from live state.
    format!(
        "add table ip rustypods\ndelete table ip rustypods\n\
         add table ip6 rustypods6\ndelete table ip6 rustypods6\n\
         {rules}"
    )
}

/// Apply the generated transaction — strict: nft failures propagate
/// (callers decide whether a NAT failure unwinds a start or only warns
/// on stop paths).
pub fn rebuild_nat<'a>(
    pods: impl Iterator<Item = &'a PodMeta>,
    running: &std::collections::BTreeSet<String>,
) -> Result<()> {
    let script = nat_script(pods, running);
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
    ensure_forward_accepts();
    Ok(())
}

/// Foreign firewalls (ufw, libvirt's iptables compat, firewalld) install
/// FORWARD base chains with a drop/reject policy — every pod↔pod and
/// pod↔wan packet dies there, and a RustyPods-owned accept chain cannot
/// override a foreign drop (each base chain at a hook gets its own
/// verdict). The only fix is accepts INSIDE the foreign chain, ahead of
/// its drop path — the same thing Docker does with DOCKER-USER.
///
/// Idempotent via a comment marker; absent tables/chains are skipped;
/// failures only warn (a strict host firewall shouldn't sink a start —
/// doctor reports the gap instead).
pub fn ensure_forward_accepts() {
    const MARK: &str = "rustypods-forward";
    const V4: [&str; 2] = [
        "ip saddr 10.220.0.0/16 accept",
        "ip daddr 10.220.0.0/16 accept",
    ];
    const V6: [&str; 2] = [
        "ip6 saddr fd22:220::/32 accept",
        "ip6 daddr fd22:220::/32 accept",
    ];
    const BOTH: [&str; 4] = [
        "ip saddr 10.220.0.0/16 accept",
        "ip daddr 10.220.0.0/16 accept",
        "ip6 saddr fd22:220::/32 accept",
        "ip6 daddr fd22:220::/32 accept",
    ];
    // (family, table, chain, rules to insert) — cover ufw's iptables-compat
    // tables and a plain inet filter table. firewalld is deliberately
    // absent: its `inet firewalld` table carries the kernel `owner`
    // flag (EPERM on any foreign insert — see firewalld_bind for the
    // sanctioned path). Insert whenever the chain exists and lacks our
    // marker, not only on drop policies — accepts scoped to pod subnets
    // are harmless where nothing was blocking.
    for (fam, table, chain, rules) in [
        ("ip", "filter", "FORWARD", V4.as_slice()),
        ("ip6", "filter", "FORWARD", V6.as_slice()),
        ("inet", "filter", "FORWARD", BOTH.as_slice()),
    ] {
        let out = Command::new("nft")
            .args(["list", "chain", fam, table, chain])
            .output();
        let Ok(out) = out else { continue };
        if !out.status.success() {
            continue;
        }
        let txt = String::from_utf8_lossy(&out.stdout);
        if txt.contains(MARK) {
            continue;
        }
        for r in rules {
            let mut argv: Vec<&str> = vec!["insert", "rule", fam, table, chain];
            argv.extend(r.split_whitespace());
            argv.extend(["comment", MARK]);
            match Command::new("nft").args(&argv).status() {
                Ok(s) if s.success() => {}
                Ok(s) => tracing::warn!("nft insert into {fam} {table} {chain}: exit {s}"),
                Err(e) => tracing::warn!("nft insert into {fam} {table} {chain}: {e}"),
            }
        }
        tracing::info!("installed pod-traffic accepts in {fam} {table} {chain}");
    }
}

/// TCP 80+443 on BOTH loopback stacks must be free before the gateway
/// claims them via nft redirect — nft doesn't take a userspace bind, so
/// an existing listener would be silently hijacked otherwise. Bind tests
/// only; closed immediately.
pub fn check_ingress_ports_free() -> Result<()> {
    for (ip, port) in [
        (std::net::IpAddr::from([127, 0, 0, 1]), 80u16),
        (std::net::IpAddr::from([127, 0, 0, 1]), 443),
        (std::net::IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]), 80),
        (std::net::IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]), 443),
    ] {
        let addr = std::net::SocketAddr::new(ip, port);
        match std::net::TcpListener::bind(addr) {
            Ok(l) => drop(l),
            Err(e) => {
                bail!("ingress needs {addr} free on the host — {e}");
            }
        }
    }
    Ok(())
}

/// First usable upstream resolver for DNS forwarding. Prefers
/// systemd-resolved's real upstream file over the 127.0.0.53 stub —
/// either is reachable for the host daemon, but only the real one is
/// usable as a pod's fallback nameserver.
pub(crate) fn upstream_resolver() -> Option<std::net::SocketAddr> {
    for path in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let Some(ns) = line.trim().strip_prefix("nameserver") else {
                continue;
            };
            if let Ok(ip) = ns.trim().parse::<std::net::IpAddr>() {
                return Some(std::net::SocketAddr::new(ip, 53));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gw_meta() -> PodMeta {
        use crate::state::LimitsSpec;
        PodMeta {
            name: "rustypods-ingress".into(),
            image: "img".into(),
            created_unix: 0,
            limits: LimitsSpec::default(),
            ephemeral: false,
            private_users: true,
            started: false,
            storage_max_bytes: 0,
            ports: vec![],
            ingress: vec![],
            net_index: 7,
            stack: String::new(),
            binds: vec![],
            cmd: vec![],
            snap_keep_last: 0,
            snap_max_age_secs: 0,
            autostart: false,
            ingress_gateway: true,
            restart: String::new(),
            healthcheck: Default::default(),
            env: vec![],
            volumes: vec![],
        }
    }

    fn running(names: &[&str]) -> std::collections::BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn gateway_rules_are_local_only() {
        let gw = gw_meta();
        let s = nat_script([&gw].into_iter(), &running(&["rustypods-ingress"]));
        assert!(s.contains("ip daddr 127.0.0.0/8 tcp dport 80 dnat ip to 10.220.7.2:8080"));
        assert!(s.contains("ip daddr 127.0.0.0/8 tcp dport 443 dnat ip to 10.220.7.2:8443"));
        // No ::1 redirect: the kernel drops loopback tuples arriving on
        // non-loopback devices, so v6 dnat could never complete a
        // handshake — ::1 must RST and let clients fall back to 127.0.0.1.
        assert!(!s.contains("ip6 daddr ::1"));
        // The gateway rules sit ONLY in the output chain: the prerouting
        // block must not contain dport 80/443 redirects at all.
        let prerouting = &s[s.find("chain prerouting").unwrap()..s.find("chain output").unwrap()];
        assert!(!prerouting.contains("8080") && !prerouting.contains("8443"));
        // Both managed tables always emitted.
        assert!(s.contains("add table ip6 rustypods6"));
        assert!(s.contains("delete table ip6 rustypods6"));
    }

    #[test]
    fn gateway_rules_absent_when_stopped() {
        let gw = gw_meta();
        let s = nat_script([&gw].into_iter(), &running(&[]));
        assert!(!s.contains("8080") && !s.contains("8443"));
        assert!(!s.contains("tcp dport 80"));
        // v6 table still managed (stale rules get flushed).
        assert!(s.contains("table ip6 rustypods6"));
    }

    #[test]
    fn gateway_rules_absent_without_gateway() {
        let s = nat_script(std::iter::empty(), &running(&[]));
        assert!(!s.contains("8080"));
        assert!(s.contains("add table ip rustypods"));
    }

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
        let text =
            std::fs::read_to_string(rootfs.join("etc/systemd/network/80-container-host0.network"))
                .unwrap();
        assert!(text.contains("Address=10.220.7.2/30"));
        assert!(text.contains("Address=fd22:220:7::2/64"));
        assert!(text.contains("Gateway=10.220.7.1"));
        assert!(text.contains("Gateway=fd22:220:7::1"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
