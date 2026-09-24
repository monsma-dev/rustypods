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

/// IPv4 /16 and IPv6 /32 the daemon carves per-pod /30s and /64s out of.
/// Defaults match the historical constants. Override with
/// `RUSTYPODS_POD_NET4=10.220.0.0/16` and `RUSTYPODS_POD_NET6=fd22:220::/32`.
#[derive(Clone, Debug)]
pub struct PodPool {
    pub v4: Ipv4Addr,
    pub v6_hi: u16,
    pub v6_mid: u16,
}

impl PodPool {
    pub fn v4_cidr(&self) -> String {
        format!("{}/16", self.v4)
    }
    pub fn v6_cidr(&self) -> String {
        format!("{:x}:{:x}::/32", self.v6_hi, self.v6_mid)
    }
}

pub fn parse_pod_pool(v4: &str, v6: &str) -> Result<PodPool> {
    let (addr, prefix) = v4
        .split_once('/')
        .context("RUSTYPODS_POD_NET4 must be a.b.0.0/16")?;
    if prefix != "16" {
        bail!("RUSTYPODS_POD_NET4 must be a /16, got {v4}");
    }
    let ip: Ipv4Addr = addr.parse().context("RUSTYPODS_POD_NET4 address")?;
    let o = ip.octets();
    if o[2] != 0 || o[3] != 0 {
        bail!("RUSTYPODS_POD_NET4 must be x.y.0.0/16 (the third octet is the pod index)");
    }
    let (addr6, prefix6) = v6
        .split_once('/')
        .context("RUSTYPODS_POD_NET6 must be x:y::/32")?;
    if prefix6 != "32" {
        bail!("RUSTYPODS_POD_NET6 must be a /32, got {v6}");
    }
    let ip6: Ipv6Addr = addr6.parse().context("RUSTYPODS_POD_NET6 address")?;
    let s = ip6.segments();
    if s[2..].iter().any(|x| *x != 0) {
        bail!("RUSTYPODS_POD_NET6 must be x:y::/32 (the third hextet is the pod index)");
    }
    Ok(PodPool {
        v4: ip,
        v6_hi: s[0],
        v6_mid: s[1],
    })
}

/// Fail the daemon on a bad pool instead of carving addresses out of
/// the wrong range. Tests use [`pool`], which falls back to the defaults.
pub fn load_pool() -> Result<&'static PodPool> {
    if let Some(p) = POD_POOL.get() {
        return Ok(p);
    }
    let p = pool_from_env()?;
    let _ = POD_POOL.set(p);
    Ok(POD_POOL.get().expect("pool just set"))
}

fn pool_from_env() -> Result<PodPool> {
    let v4 = std::env::var("RUSTYPODS_POD_NET4").unwrap_or_else(|_| "10.220.0.0/16".into());
    let v6 = std::env::var("RUSTYPODS_POD_NET6").unwrap_or_else(|_| "fd22:220::/32".into());
    parse_pod_pool(&v4, &v6)
}

static POD_POOL: std::sync::OnceLock<PodPool> = std::sync::OnceLock::new();

pub fn pool() -> &'static PodPool {
    POD_POOL.get_or_init(|| {
        pool_from_env().unwrap_or_else(|e| {
            tracing::warn!("{e:#} — using 10.220.0.0/16 and fd22:220::/32");
            parse_pod_pool("10.220.0.0/16", "fd22:220::/32").expect("default pool")
        })
    })
}

/// Host iface for a pod's veth pair (nspawn truncates to IFNAMSIZ-1 chars).
pub fn veth_name(pod: &str) -> String {
    format!("ve-{}", &pod[..pod.len().min(12)])
}

/// Stack uplink name. Two stacks that share a 12-character prefix must
/// not share a veth: nspawn-style truncation did that, and the second
/// stack then had no uplink. 15 chars (IFNAMSIZ-1): `ve-` + 4-char stem
/// + `-` + 7 hex of a stable hash of the full stack name.
pub fn stack_veth_name(stack: &str) -> String {
    let mut h: u32 = 2166136261;
    for b in stack.as_bytes() {
        h ^= u32::from(*b);
        h = h.wrapping_mul(16777619);
    }
    let hex = format!("{h:08x}");
    let stem: String = stack
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(4)
        .collect();
    let stem = if stem.is_empty() { "x" } else { stem.as_str() };
    format!("ve-{stem}-{}", &hex[..7])
}

fn stack_veth_is_ours(host_v: &str, ns: &str) -> bool {
    let Ok(idx) = std::fs::read_to_string(format!("/sys/class/net/{host_v}/ifindex")) else {
        return false;
    };
    let Ok(out) = run_out("ip", &["netns", "exec", ns, "ip", "-o", "link"]) else {
        return false;
    };
    out.contains(&format!("@if{}", idx.trim()))
}

pub fn host_ip(idx: u32) -> Ipv4Addr {
    let o = pool().v4.octets();
    Ipv4Addr::new(o[0], o[1], idx as u8, 1)
}
pub fn pod_ip(idx: u32) -> Ipv4Addr {
    let o = pool().v4.octets();
    Ipv4Addr::new(o[0], o[1], idx as u8, 2)
}
/// Same per-pod pairing in the configured IPv6 /32: x:y:<idx>::1 (host)
/// and ::2 (pod) on a /64. `idx as u16` keeps the pool aligned with the
/// v4 1..=255 indexes.
pub fn host_ip6(idx: u32) -> Ipv6Addr {
    let p = pool();
    Ipv6Addr::new(p.v6_hi, p.v6_mid, idx as u16, 0, 0, 0, 0, 1)
}
pub fn pod_ip6(idx: u32) -> Ipv6Addr {
    let p = pool();
    Ipv6Addr::new(p.v6_hi, p.v6_mid, idx as u16, 0, 0, 0, 0, 2)
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

/// Re-bind every pod veth and the mesh TUN to firewalld's trusted zone.
/// Runtime-only bindings die on `firewall-cmd --reload`; this puts them
/// back. Idempotent. No-op when firewalld is not running.
pub fn rebind_firewalld_ifaces() {
    let Ok(rd) = std::fs::read_dir("/sys/class/net") else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with(POD_VETH_PREFIX) || name.starts_with("rp-mesh") {
            firewalld_bind_sync(&name);
        }
    }
}

/// firewalld emits `Reloaded` on `org.fedoraproject.FirewallD1` after
/// `--reload` drops runtime interface bindings. The receiver fires once
/// per signal. If firewalld is absent the channel simply stays quiet
/// and the periodic reconcile is the backstop.
pub fn watch_firewalld_reloads(conn: zbus::Connection) -> tokio::sync::mpsc::Receiver<()> {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let proxy = match FirewallD1Proxy::new(&conn).await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("firewalld not available: {e}");
                return;
            }
        };
        use tokio_stream::StreamExt;
        let mut stream = match proxy.receive_reloaded().await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("firewalld Reloaded subscribe: {e}");
                return;
            }
        };
        while stream.next().await.is_some() {
            if tx.send(()).await.is_err() {
                break;
            }
        }
    });
    rx
}

#[zbus::proxy(
    interface = "org.fedoraproject.FirewallD1",
    default_service = "org.fedoraproject.FirewallD1",
    default_path = "/org/fedoraproject/FirewallD1"
)]
trait FirewallD1 {
    #[zbus(signal)]
    fn reloaded(&self) -> zbus::Result<()>;
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
    let host_v = stack_veth_name(stack);
    let peer = stack_peer(stack);
    if Path::new(&format!("/sys/class/net/{host_v}")).exists() {
        if !stack_veth_is_ours(&host_v, &ns) {
            bail!(
                "{host_v} already exists and is not the uplink for stack {stack} — refusing to reuse it"
            );
        }
    } else {
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
    let _ = run("ip", &["link", "del", &stack_veth_name(stack)]);
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
        tracing::warn!(
            "set net.ipv4.ip_forward=1 (not restored on teardown — disable it yourself if nothing else needs it)"
        );
    }
    // forwarding=1 makes the kernel ignore RAs on interfaces with
    // accept_ra=1, which drops the IPv6 default route on SLAAC hosts.
    // accept_ra=2 means "accept even when forwarding". Do this BEFORE
    // enabling forwarding. NetworkManager-managed hosts learn RAs in
    // userspace and are unaffected.
    preserve_accept_ra();
    let fwd6 = "/proc/sys/net/ipv6/conf/all/forwarding";
    if std::fs::read_to_string(fwd6).ok().as_deref() != Some("1\n") {
        std::fs::write(fwd6, "1").context("enable net.ipv6.conf.all.forwarding")?;
        tracing::warn!("set net.ipv6.conf.all.forwarding=1 (not restored on teardown)");
    }
    Ok(())
}

/// Interfaces that are not pod veths, stack peers, or the mesh TUN.
pub fn non_pod_ifaces() -> Vec<String> {
    let mut names = Vec::new();
    let Ok(rd) = std::fs::read_dir("/sys/class/net") else {
        return names;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name == "lo"
            || name.starts_with(POD_VETH_PREFIX)
            || name.starts_with("vp-")
            || name.starts_with("rp-mesh")
        {
            continue;
        }
        names.push(name);
    }
    names.sort();
    names
}

fn preserve_accept_ra() {
    for name in non_pod_ifaces() {
        let path = format!("/proc/sys/net/ipv6/conf/{name}/accept_ra");
        let Ok(cur) = std::fs::read_to_string(&path) else {
            continue;
        };
        if cur.trim() == "1" {
            match std::fs::write(&path, "2") {
                Ok(()) => tracing::warn!(
                    "set net.ipv6.conf.{name}.accept_ra=2 before enabling IPv6 forwarding \
                     (was 1; kernel would ignore router advertisements)"
                ),
                Err(e) => tracing::warn!("accept_ra {name}: {e}"),
            }
        }
    }
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

/// Host-veth name prefix. Standalone nspawn veths and stack uplinks both
/// use it, so one wildcard covers pod egress and pod↔pod forwarding.
pub const POD_VETH_PREFIX: &str = "ve-";

/// Comment marker on the foreign FORWARD accepts. Bumped when the rule
/// shape changes so a reconcile replaces the old blanket subnet accepts.
pub const FORWARD_MARK: &str = "rustypods-forward-v2";
const FORWARD_MARK_OLD: &str = "rustypods-forward";

/// FORWARD accepts inserted at the top of foreign filter chains.
///
/// `ct status dnat` is published traffic only. `iifname "ve-*"` is pod
/// egress and pod↔pod (both ends are our veths). Established covers
/// replies. There is deliberately no `ip daddr <pool> accept` — that
/// let any neighbour routing the pod prefix reach unpublished ports.
pub fn forward_accept_lines() -> &'static [&'static str] {
    &[
        "ct state established,related accept",
        "ct status dnat accept",
        "iifname \"ve-*\" accept",
    ]
}

fn listing_has_comment(listing: &str, mark: &str) -> bool {
    // nft prints `comment "mark"`. The old mark is a prefix of the new
    // one, so a bare substring test would treat v2 as the old generation.
    listing.contains(&format!("\"{mark}\"")) || listing.split_whitespace().any(|w| w == mark)
}

/// True when `nft list chain` output already has the current accepts
/// and not a previous generation's marker.
pub fn forward_chain_current(listing: &str) -> bool {
    if listing_has_comment(listing, FORWARD_MARK_OLD) {
        return false;
    }
    if !listing_has_comment(listing, FORWARD_MARK) {
        return false;
    }
    // A leftover blanket pool accept is the bug this generation removes.
    if listing.contains("ip daddr 10.220.0.0/16") || listing.contains("ip6 daddr fd22:220::/32") {
        return false;
    }
    forward_accept_lines().iter().all(|l| listing.contains(l))
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
    let mut dnat_pre = String::new();
    let mut dnat_out = String::new();
    let mut dnat6_pre = String::new();
    let mut dnat6_out = String::new();
    let mut gw: Option<u32> = None;
    let mut host_access_v4: Vec<String> = Vec::new();
    let mut host_access_v6: Vec<String> = Vec::new();
    let mut isolate = String::new();
    let v4cidr_pool = pool().v4_cidr();
    let v6cidr_pool = pool().v6_cidr();
    for m in pods.filter(|m| m.net_index > 0 && running.contains(&m.name)) {
        if m.host_access {
            host_access_v4.push(pod_ip(m.net_index).to_string());
            host_access_v6.push(pod_ip6(m.net_index).to_string());
        }
        if m.isolated {
            let v4 = pod_ip(m.net_index);
            let v6 = pod_ip6(m.net_index);
            isolate.push_str(&format!(
                "    ip saddr {v4} ip daddr {v4cidr_pool} drop\n\
                 \x20   ip daddr {v4} ip saddr {v4cidr_pool} drop\n\
                 \x20   ip6 saddr {v6} ip6 daddr {v6cidr_pool} drop\n\
                 \x20   ip6 daddr {v6} ip6 saddr {v6cidr_pool} drop\n"
            ));
        }
        if m.ingress_gateway {
            // Exactly one gateway is enforced at load; last one wins if
            // a hand-built state slips through — harmless, same shape.
            gw = Some(m.net_index);
            continue;
        }
        for spec in &m.ports {
            let Ok(map) = rustypods_proto::parse_port(spec) else {
                continue;
            };
            let v4dst = format!("{}:{}", pod_ip(m.net_index), map.pod_port);
            let v6dst = format!("[{}]:{}", pod_ip6(m.net_index), map.pod_port);
            match map.bind_addr() {
                std::net::IpAddr::V4(ip) if ip.is_unspecified() => {
                    // Explicit 0.0.0.0 — every local IPv4 address. `fib`
                    // keeps DNAT off traffic that is only forwarded.
                    let line = format!(
                        "    fib daddr type local {} dport {} dnat ip to {v4dst}\n",
                        map.proto, map.host_port
                    );
                    dnat_pre.push_str(&line);
                    dnat_out.push_str(&line);
                }
                std::net::IpAddr::V4(ip) => {
                    let line = format!(
                        "    ip daddr {ip} {} dport {} dnat ip to {v4dst}\n",
                        map.proto, map.host_port
                    );
                    // 127.0.0.0/8 is only reachable from the host itself.
                    // A prerouting rule would not see those packets, and
                    // must not exist so a neighbour cannot aim at them.
                    if !ip.is_loopback() {
                        dnat_pre.push_str(&line);
                    }
                    dnat_out.push_str(&line);
                }
                std::net::IpAddr::V6(ip) if ip.is_unspecified() => {
                    let line = format!(
                        "    fib daddr type local {} dport {} dnat ip6 to {v6dst}\n",
                        map.proto, map.host_port
                    );
                    dnat6_pre.push_str(&line);
                    dnat6_out.push_str(&line);
                }
                std::net::IpAddr::V6(ip) => {
                    let line = format!(
                        "    ip6 daddr {ip} {} dport {} dnat ip6 to {v6dst}\n",
                        map.proto, map.host_port
                    );
                    dnat6_pre.push_str(&line);
                    dnat6_out.push_str(&line);
                }
            }
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
    // host_access pods may open real connections to host services, including
    // 127.0.0.1. Everyone else is dropped before conntrack so a forged
    // 127/8 destination never becomes a flow.
    let raw_drop = if host_access_v4.is_empty() {
        "    iifname \"ve-*\" ip daddr 127.0.0.0/8 drop\n".to_string()
    } else {
        format!(
            "    iifname \"ve-*\" ip saddr != {{ {} }} ip daddr 127.0.0.0/8 drop\n",
            host_access_v4.join(", ")
        )
    };
    let mut host_ok = host_access_v4
        .iter()
        .map(|ip| format!("    ip saddr {ip} accept\n"))
        .collect::<String>();
    for ip in &host_access_v6 {
        host_ok.push_str(&format!("    ip6 saddr {ip} accept\n"));
    }
    let v4cidr = pool().v4_cidr();
    let v6cidr = pool().v6_cidr();
    let rules = format!(
        "table ip rustypods {{\n\
         \x20 chain prerouting {{\n\
         \x20   type nat hook prerouting priority dstnat; policy accept;\n\
         {dnat_pre}\
         \x20 }}\n\
         \x20 chain output {{\n\
         \x20   type nat hook output priority -100; policy accept;\n\
         {gw_v4}\
         {dnat_out}\
         \x20 }}\n\
         \x20 chain postrouting {{\n\
         \x20   type nat hook postrouting priority srcnat; policy accept;\n\
         \x20   # host-originated traffic to pods must be SNAT'd to the veth ip\n\
         \x20   # (a pod would answer 127.0.0.1 on its OWN loopback otherwise)\n\
         \x20   fib saddr type local ip daddr {v4cidr} masquerade\n\
         \x20   # pod egress onto the real network\n\
         \x20   ip saddr {v4cidr} oifname != \"ve-*\" masquerade\n\
         \x20 }}\n\
         }}\n\
         table ip6 rustypods6 {{\n\
         \x20 chain prerouting {{\n\
         \x20   type nat hook prerouting priority dstnat; policy accept;\n\
         {dnat6_pre}\
         \x20 }}\n\
         \x20 chain output {{\n\
         \x20   type nat hook output priority -100; policy accept;\n\
         {dnat6_out}\
         \x20 }}\n\
         \x20 chain postrouting {{\n\
         \x20   type nat hook postrouting priority srcnat; policy accept;\n\
         \x20   # ULA pod egress onto the real network\n\
         \x20   ip6 saddr {v6cidr} oifname != \"ve-*\" masquerade\n\
         \x20 }}\n\
         }}\n\
         table inet rustypods {{\n\
         \x20 chain rawpre {{\n\
         \x20   type filter hook prerouting priority raw; policy accept;\n\
         \x20   # Pod-injected dst 127/8 (route_localnet + CVE-2020-8558).\n\
         \x20   # Replies to host→pod localhost DNAT arrive with dst = the\n\
         \x20   # veth .1 and are de-NATed after this hook, so they miss it.\n\
         {raw_drop}\
         \x20 }}\n\
         \x20 chain frompod {{\n\
         \x20   type filter hook input priority -10; policy accept;\n\
         \x20   iifname \"ve-*\" ct state established,related accept\n\
         \x20   # Mesh DNS :53 and gossip :5305 on the host ULA.\n\
         \x20   iifname \"ve-*\" ip6 daddr fd00::/8 udp dport 53 accept\n\
         \x20   iifname \"ve-*\" ip6 daddr fd00::/8 udp dport 5305 accept\n\
         {host_ok}\
         \x20   iifname \"ve-*\" fib daddr type local drop\n\
         \x20 }}\n\
         \x20 chain isolate {{\n\
         \x20   type filter hook forward priority -10; policy accept;\n\
         \x20   # isolated pods: no pod↔pod. Outside egress and DNAT stay.\n\
         {isolate}\
         \x20 }}\n\
         }}\n"
    );
    // Flush+replace atomically: declare each table (idempotent), delete
    // the old ruleset, recreate from live state.
    format!(
        "add table ip rustypods\ndelete table ip rustypods\n\
         add table ip6 rustypods6\ndelete table ip6 rustypods6\n\
         add table inet rustypods\ndelete table inet rustypods\n\
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
    nft_apply(&script)?;
    ensure_forward_accepts();
    Ok(())
}

/// Feed `script` to `nft -f -` and always reap the child. A failed write
/// must not leave nft running with a live stdin pipe.
fn nft_apply(script: &str) -> Result<()> {
    use std::io::Write;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawn nft")?;
    let write_err = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(script.as_bytes()).err(),
        None => Some(std::io::Error::other("nft stdin was not piped")),
    };
    let out = child.wait_with_output().context("wait for nft")?;
    let err = String::from_utf8_lossy(&out.stderr);
    if let Some(e) = write_err {
        bail!("writing nft script: {e}; stderr: {}", err.trim());
    }
    if !out.status.success() {
        bail!("nft -f exited {}: {}", out.status, err.trim());
    }
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
    // (family, table, chain) — ufw's iptables-compat tables and a plain
    // inet filter. firewalld's `inet firewalld` table is absent: it
    // carries the kernel `owner` flag (EPERM — see firewalld_bind).
    // Insert whenever the chain exists and is not already current, not
    // only on drop policies: firewalld's filter_FORWARD is policy accept
    // yet still rejects via its zone dispatch.
    for (fam, table, chain) in [
        ("ip", "filter", "FORWARD"),
        ("ip6", "filter", "FORWARD"),
        ("inet", "filter", "FORWARD"),
    ] {
        let out = Command::new("nft")
            .args(["-a", "list", "chain", fam, table, chain])
            .output();
        let Ok(out) = out else { continue };
        if !out.status.success() {
            continue;
        }
        let txt = String::from_utf8_lossy(&out.stdout);
        if forward_chain_current(&txt) {
            continue;
        }
        delete_marked_rules(fam, table, chain, &txt, &[FORWARD_MARK, FORWARD_MARK_OLD]);
        for r in forward_accept_lines() {
            let mut argv: Vec<&str> = vec!["insert", "rule", fam, table, chain];
            argv.extend(r.split_whitespace());
            argv.extend(["comment", FORWARD_MARK]);
            match Command::new("nft").args(&argv).status() {
                Ok(s) if s.success() => {}
                Ok(s) => tracing::warn!("nft insert into {fam} {table} {chain}: exit {s}"),
                Err(e) => tracing::warn!("nft insert into {fam} {table} {chain}: {e}"),
            }
        }
        tracing::info!("installed pod-traffic accepts in {fam} {table} {chain}");
    }
}

/// Delete rules whose comment is one of `marks`. `listing` must come from
/// `nft -a list chain` so each rule line carries `handle N`.
fn delete_marked_rules(fam: &str, table: &str, chain: &str, listing: &str, marks: &[&str]) {
    for line in listing.lines() {
        if !marks.iter().any(|m| listing_has_comment(line, m)) {
            continue;
        }
        let Some(h) = line
            .rsplit("handle ")
            .next()
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u64>().ok())
        else {
            continue;
        };
        let handle = h.to_string();
        let _ = Command::new("nft")
            .args(["delete", "rule", fam, table, chain, "handle", &handle])
            .status();
    }
}

/// Remove everything RustyPods inserted into the host firewall: the
/// `rustypods` nft tables, marker-commented FORWARD/INPUT rules (including
/// mesh), and firewalld runtime trusted-zone bindings. Sysctls are left
/// as-is; the log line says which ones may have been changed.
pub fn teardown_all() -> Result<()> {
    for (fam, name) in [
        ("ip", "rustypods"),
        ("ip6", "rustypods6"),
        ("inet", "rustypods"),
    ] {
        let _ = run("nft", &["delete", "table", fam, name]);
    }
    let marks = [
        FORWARD_MARK,
        FORWARD_MARK_OLD,
        "rustypods-mesh-fwd",
        "rustypods-mesh-in",
    ];
    for (fam, table, chain) in [
        ("ip", "filter", "FORWARD"),
        ("ip6", "filter", "FORWARD"),
        ("inet", "filter", "FORWARD"),
        ("ip", "filter", "INPUT"),
        ("ip6", "filter", "INPUT"),
        ("inet", "filter", "INPUT"),
    ] {
        let out = Command::new("nft")
            .args(["-a", "list", "chain", fam, table, chain])
            .output();
        let Ok(out) = out else { continue };
        if !out.status.success() {
            continue;
        }
        let txt = String::from_utf8_lossy(&out.stdout);
        delete_marked_rules(fam, table, chain, &txt, &marks);
    }
    if run("firewall-cmd", &["--state"]).is_ok() {
        if let Ok(list) = run_out("firewall-cmd", &["--zone=trusted", "--list-interfaces"]) {
            for iface in list.split_whitespace() {
                if iface.starts_with(POD_VETH_PREFIX) || iface.starts_with("rp-mesh") {
                    let _ = run(
                        "firewall-cmd",
                        &["--zone=trusted", "--remove-interface", iface],
                    );
                }
            }
        }
    }
    tracing::warn!(
        "teardown-net removed nft tables ip rustypods, ip6 rustypods6, inet rustypods, \
         marker rules ({FORWARD_MARK}, rustypods-mesh-fwd, rustypods-mesh-in), and firewalld \
         trusted-zone bindings for ve-* and rp-mesh*. Sysctls were NOT restored: \
         net.ipv4.ip_forward and net.ipv6.conf.all.forwarding may still be 1, and non-pod \
         interfaces may have accept_ra=2. Revert those by hand if nothing else needs them."
    );
    Ok(())
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
            format: 1,
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
            host_access: false,
            isolated: false,
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

    fn pod_meta(name: &str, idx: u32, ports: &[&str]) -> PodMeta {
        let mut m = gw_meta();
        m.name = name.into();
        m.ingress_gateway = false;
        m.net_index = idx;
        m.ports = ports.iter().map(|s| s.to_string()).collect();
        m
    }

    #[test]
    fn published_ports_bind_loopback_unless_explicit() {
        let any = pod_meta("web", 1, &["0.0.0.0:8080:80"]);
        let db = pod_meta("db", 2, &["5432:5432"]);
        let s = nat_script([&any, &db].into_iter(), &running(&["web", "db"]));
        let pre = &s[s.find("chain prerouting").unwrap()..s.find("chain output").unwrap()];
        assert!(pre.contains("fib daddr type local tcp dport 8080 dnat ip to 10.220.1.2:80"));
        assert!(
            !pre.contains("5432"),
            "implicit loopback publish must not appear in prerouting"
        );
        let out = &s[s.find("chain output").unwrap()..s.find("chain postrouting").unwrap()];
        assert!(out.contains("ip daddr 127.0.0.1 tcp dport 5432 dnat ip to 10.220.2.2:5432"));
        assert!(!s.contains("fib daddr type local tcp dport 5432"));
        assert!(!s.contains("ip daddr 10.220.0.0/16 accept"));
    }

    #[test]
    fn forward_accepts_are_not_a_blanket_pool() {
        let lines = forward_accept_lines().join("\n");
        assert!(lines.contains("ct status dnat accept"));
        assert!(lines.contains("iifname \"ve-*\" accept"));
        assert!(lines.contains("ct state established,related accept"));
        assert!(!lines.contains("10.220.0.0/16"));
        let stale = "ip daddr 10.220.0.0/16 accept comment \"rustypods-forward\"";
        assert!(!forward_chain_current(stale));
        let current = forward_accept_lines()
            .iter()
            .map(|l| format!("{l} comment \"{FORWARD_MARK}\""))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(forward_chain_current(&current));
    }

    #[test]
    fn pods_cannot_reach_host_loopback_unless_opt_in() {
        let db = pod_meta("db", 2, &["5432:5432"]);
        let s = nat_script([&db].into_iter(), &running(&["db"]));
        assert!(s.contains("iifname \"ve-*\" ip daddr 127.0.0.0/8 drop"));
        assert!(s.contains("iifname \"ve-*\" fib daddr type local drop"));
        assert!(s.contains("udp dport 53 accept"));
        let raw = s.find("chain rawpre").unwrap();
        let frompod = s.find("chain frompod").unwrap();
        assert!(raw < frompod);
        let mut opted = db.clone();
        opted.host_access = true;
        let s = nat_script([&opted].into_iter(), &running(&["db"]));
        assert!(s.contains("ip saddr != { 10.220.2.2 } ip daddr 127.0.0.0/8 drop"));
        assert!(s.contains("ip saddr 10.220.2.2 accept"));
        assert!(s.contains("ip6 saddr fd22:220:2::2 accept"));
    }

    #[test]
    fn isolated_pod_drops_pod_to_pod_only() {
        let mut db = pod_meta("db", 2, &["5432:5432"]);
        db.isolated = true;
        let s = nat_script([&db].into_iter(), &running(&["db"]));
        assert!(s.contains("ip saddr 10.220.2.2 ip daddr 10.220.0.0/16 drop"));
        assert!(s.contains("ip daddr 10.220.2.2 ip saddr 10.220.0.0/16 drop"));
        let plain = pod_meta("web", 1, &["0.0.0.0:8080:80"]);
        let s = nat_script([&plain].into_iter(), &running(&["web"]));
        assert!(!s.contains("ip saddr 10.220.1.2 ip daddr"));
    }

    #[test]
    fn pool_rejects_bad_prefixes() {
        assert!(parse_pod_pool("10.220.0.0/16", "fd22:220::/32").is_ok());
        assert!(parse_pod_pool("10.220.1.0/16", "fd22:220::/32").is_err());
        assert!(parse_pod_pool("10.220.0.0/24", "fd22:220::/32").is_err());
        assert!(parse_pod_pool("10.220.0.0/16", "fd22:220:1::/32").is_err());
        assert!(parse_pod_pool("10.220.0.0/16", "fd22:220::/48").is_err());
    }

    #[test]
    fn stack_veth_names_do_not_collide() {
        let a = stack_veth_name("verylongstackname");
        let b = stack_veth_name("verylongstackother");
        assert_ne!(a, b);
        assert!(a.len() <= 15 && b.len() <= 15, "{a} {b}");
        assert!(a.starts_with("ve-") && b.starts_with("ve-"));
        assert_eq!(stack_veth_name("demo"), stack_veth_name("demo"));
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
