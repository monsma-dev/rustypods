//! Multi-host pod mesh (Wave I): userspace WireGuard via BoringTun.
//!
//! Each daemon derives a stable ULA /48 from its own WG pubkey —
//! `fd<40 bits of sha256(pubkey)>` — so every pod mesh address is
//! cryptographically bound to the host identity with zero
//! coordination, and a peer's prefix is verified BY its pubkey rather
//! than trusted from config.
//!
//! A pod's mesh address is `fd<host-prefix>:<net_idx>::2` — a second
//! /128 on host0 next to the intra-host fd22:220:<idx>::2. Pods need
//! no extra routes: the existing default-via-host covers mesh space,
//! and longest-prefix src selection picks the mesh addr when dialing
//! mesh addrs.
//!
//! Datapath: raw IP packets in/out of rp-mesh0 (persistent TUN,
//! IFF_NO_PI), encrypted/decrypted by one boringtun `Tunn` per peer
//! over a single UDP socket. `fd<peer>::/48 dev rp-mesh0` routes
//! cross-host traffic into the tunnel; `fd<local>:<idx>::2/128 dev
//! ve-<pod>` delivers inbound packets to the right pod.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use sha2::{Digest, Sha256};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{watch, Mutex};

use crate::net;
use crate::state::{MeshConf, MeshPeerConf};

pub const TUN_NAME: &str = "rp-mesh0";
pub const DEFAULT_PORT: u16 = 51820;
/// The host's own mesh address: `fd<host>::1/128` on rp-mesh0. Hosts
/// speak host-to-host control protocols (gossip, DNS) at this addr;
/// pods live at `:<idx>::2`.
pub const HOST_SUFFIX: u128 = 1;
/// Registry gossip between daemons — JSON over the tunnel.
const GOSSIP_PORT: u16 = 5305;
/// Pod-facing DNS on the host mesh addr.
const DNS_PORT: u16 = 53;
/// Announce cadence; remote registries expire after 3 intervals.
const ANNOUNCE_EVERY: Duration = Duration::from_secs(30);
const NAME_TTL: Duration = Duration::from_secs(95);
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
const WG_B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// base64(x25519 private) → base64(x25519 public).
pub fn pubkey_of(private_b64: &str) -> Result<String> {
    let bytes = WG_B64
        .decode(private_b64.trim())
        .context("mesh private key is not valid base64")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("mesh private key must decode to 32 bytes"))?;
    let secret = StaticSecret::from(bytes);
    Ok(WG_B64.encode(PublicKey::from(&secret).as_bytes()))
}

/// Generate a fresh WG identity (priv, pub), both base64.
pub fn keygen() -> (String, String) {
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = PublicKey::from(&secret);
    (
        WG_B64.encode(secret.to_bytes()),
        WG_B64.encode(public.as_bytes()),
    )
}

/// Validate a base64 x25519 pubkey → its 32 raw bytes.
fn parse_pubkey(b64: &str) -> Result<[u8; 32]> {
    let bytes = WG_B64.decode(b64.trim()).context("invalid pubkey base64")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("pubkey must decode to 32 bytes"))
}

/// Normalize an endpoint to a canonical v6 form: v4 addresses become
/// v4-mapped-v6. The mesh UDP socket binds [::] (dual-stack); on Linux
/// sendto() to a bare AF_INET sockaddr on an AF_INET6 socket fails
/// with EAFNOSUPPORT — mapped-v6 is the only v4 form the kernel
/// accepts there, and it also makes endpoint-map keys consistent with
/// the mapped-v6 src a dual-stack socket reports on receive.
fn canon_ep(ep: SocketAddr) -> SocketAddr {
    match ep {
        SocketAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        v6 => v6,
    }
}

/// The host's ULA /48: `fd` + the first 5 bytes of sha256(pubkey).
/// Deterministic per identity — peers derive each other's prefix from
/// the announced pubkey alone; a peer can't claim foreign space.
pub fn prefix_of(pubkey_b64: &str) -> Result<Ipv6Addr> {
    let pk = parse_pubkey(pubkey_b64)?;
    let h = Sha256::digest(pk);
    let mut s = h[0..5].to_vec();
    s[0] &= 0x3f;
    s[0] |= 0x40; // L-bit set: locally assigned ULA (RFC 4193)
    Ok(Ipv6Addr::new(
        0xfd00 | s[0] as u16,
        (s[1] as u16) << 8 | s[2] as u16,
        (s[3] as u16) << 8 | s[4] as u16,
        0,
        0,
        0,
        0,
        0,
    ))
}

/// A pod's mesh address inside a host prefix: fd<p>:<idx>::2 —
/// mirrors the fd22:220:<idx>::2 intra-host convention.
pub fn mesh_ip(prefix: Ipv6Addr, idx: u32) -> Ipv6Addr {
    let mut seg = prefix.segments();
    seg[3] = idx as u16;
    seg[7] = 2;
    Ipv6Addr::from(seg)
}

/// `fd<host>::1` — the daemon's own address on the mesh (gossip + DNS).
pub fn host_addr(prefix: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from((u128::from(prefix) & !0xffff_ffff) | HOST_SUFFIX)
}

/// Whether `addr` sits under `prefix` (/48 = first 6 bytes).
pub fn in_prefix(prefix: Ipv6Addr, addr: Ipv6Addr) -> bool {
    addr.segments()[..3] == prefix.segments()[..3]
}

/// pod name → mesh address.
type NameMap = std::collections::BTreeMap<String, Ipv6Addr>;

/// Per-peer WG session + its announced endpoint.
struct Peer {
    tunn: Tunn,
    endpoint: SocketAddr,
    pubkey_b64: String,
    prefix: Ipv6Addr,
}

/// The live mesh: one TUN, one UDP socket, N boringtun sessions.
pub struct Mesh {
    /// This host's fd…::/48 — the prefix remote pods dial into.
    pub prefix: Ipv6Addr,
    /// This host's WG pubkey (base64).
    pub pubkey: String,
    /// UDP port the WG socket listens on.
    pub port: u16,
    data_dir: PathBuf,
    conf: Mutex<MeshConf>,
    peers: Mutex<HashMap<[u8; 32], Peer>>,
    /// src endpoint → peer key; updated on roaming so NAT'd peers keep
    /// working after their source address changes mid-session.
    endpoints: Mutex<HashMap<SocketAddr, [u8; 32]>>,
    tun: AsyncFd<std::fs::File>,
    udp: UdpSocket,
    /// Device name (normally rp-mesh0) — route helpers need it.
    tun_name: String,
    /// Pump liveness probe: bumps once per select iteration. A parked
    /// process with unread UDP Recv-Q and a frozen counter = dead pump.
    pub pump_ticks: std::sync::atomic::AtomicU64,
    /// UDP datagrams the pump has consumed so far.
    pub udp_pkts: std::sync::atomic::AtomicU64,
    /// TUN packets the pump has consumed so far.
    pub tun_pkts: std::sync::atomic::AtomicU64,
    /// Where the pump is parked (diag): 0=in select, 1=tun read,
    /// 2=route_out, 3=udp recv, 4=handle_udp, 5=timers.
    pub pump_where: std::sync::atomic::AtomicU8,
    /// Graceful pump stop — `mesh deinit` sends true; the pump's
    /// select arm observes it and returns, ending the supervisor.
    shutdown_tx: watch::Sender<bool>,
    /// Supervisor task — awaited by shutdown() so `deinit` doesn't
    /// report "down" while the pump still holds the socket/TUN.
    supervisor: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// --- Mesh-DNS (Wave K) ---
    /// This daemon's addr on the mesh: `fd<host>::1` on the TUN.
    pub host_addr: Ipv6Addr,
    /// Pod-facing DNS responder bound to [fd<host>::1]:53 — UDP for
    /// the fast path, TCP for truncation/robustness (RFC 1035 §4.2).
    dns: UdpSocket,
    dns_tcp: TcpListener,
    /// Registry gossip bound to [fd<host>::1]:5305 — packets only
    /// arrive here after WireGuard decapsulation, and senders are
    /// validated to be exactly a peer's fd<peer>::1.
    gossip: UdpSocket,
    /// name → mesh addr for THIS host's running pods (fed by Svc).
    local_names: Mutex<std::collections::BTreeMap<String, Ipv6Addr>>,
    /// peer /48 → (last refresh, its registry). Entries expire after
    /// NAME_TTL without an announce — a dead peer's names decay.
    remote_names: Mutex<HashMap<Ipv6Addr, (std::time::Instant, NameMap)>>,
    /// Set by set_local_names/add_peer/remove_peer — wakes the
    /// announcer for an immediate push instead of waiting out the
    /// interval.
    announce: tokio::sync::Notify,
    /// Host's upstream resolver for non-mesh DNS queries (pods point
    /// all of resolv.conf at us, so we relay what we don't own).
    upstream: Option<SocketAddr>,
    /// Gossip/DNS task handles — awaited by shutdown().
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

#[repr(C)]
struct IfReq {
    name: [u8; 16],
    flags: i16,
    _pad: [u8; 22],
}

/// Attach to the persistent `rp-mesh0` TUN (created by `ip tuntap`
/// first so routes survive daemon restarts). IFF_NO_PI = reads/writes
/// are bare IP packets, no 4-byte header.
fn open_tun(name: &str) -> Result<std::fs::File> {
    // Persistent device: `ip tuntap add` fails with EEXIST when already
    // there — that's the steady-state path after a daemon restart.
    let _ = net::run("ip", &["tuntap", "add", "dev", name, "mode", "tun"]);
    net::run("ip", &["link", "set", "dev", name, "mtu", "1420", "up"])?;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/net/tun")
        .context("open /dev/net/tun — tun module available?")?;
    let mut req = IfReq {
        name: [0; 16],
        flags: IFF_TUN | IFF_NO_PI,
        _pad: [0; 22],
    };
    let nb = name.as_bytes();
    req.name[..nb.len().min(15)].copy_from_slice(&nb[..nb.len().min(15)]);
    if unsafe { libc::ioctl(f.as_raw_fd(), TUNSETIFF, &req) } < 0 {
        return Err(std::io::Error::last_os_error()).context("TUNSETIFF rp-mesh0");
    }
    Ok(f)
}

impl Mesh {
    /// Bring the mesh up on the standard `rp-mesh0` device.
    pub async fn start(data_dir: &Path, conf: MeshConf) -> Result<Arc<Mesh>> {
        Self::start_named(data_dir, conf, TUN_NAME).await
    }

    /// Bring the mesh up: TUN, UDP socket, peer sessions from conf,
    /// routes, and the packet-pump task. Async only for the spawn —
    /// all setup syscalls are wrapped in spawn_blocking. `tun_name`
    /// exists for the meshpeer test harness (a second mesh endpoint on
    /// one host needs a distinct device).
    pub async fn start_named(data_dir: &Path, conf: MeshConf, tun_name: &str) -> Result<Arc<Mesh>> {
        let privkey = conf.private_key.clone();
        let pubkey = pubkey_of(&privkey)?;
        let prefix = prefix_of(&pubkey)?;
        let port = if conf.listen_port == 0 {
            DEFAULT_PORT
        } else {
            conf.listen_port
        };
        let priv_bytes: [u8; 32] = WG_B64
            .decode(privkey.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("mesh private key must decode to 32 bytes"))?;
        let secret = StaticSecret::from(priv_bytes);

        let tn = tun_name.to_string();
        let tun = tokio::task::spawn_blocking(move || open_tun(&tn)).await??;
        net::ensure_ip_forward()?;
        net::firewalld_bind_sync(tun_name);
        net::ensure_mesh_forward();
        // INPUT side: pod→host DNS + decap'd gossip + inbound WG
        // handshakes (a passive peer's first packet is NEW conntrack
        // — default-drop INPUT kills it before boringtun sees it).
        net::ensure_mesh_input(port);

        // The host itself lives at fd<host>::1 — host-to-host control
        // protocols (gossip, pod-facing DNS) bind to it. `nodad`: the
        // addr is a /128 on a point-to-point TUN, DAD is meaningless.
        let host = host_addr(prefix);
        {
            let tn = tun_name.to_string();
            let ha = host.to_string();
            tokio::task::spawn_blocking(move || {
                net::run(
                    "ip",
                    &[
                        "-6",
                        "addr",
                        "replace",
                        &format!("{ha}/128"),
                        "dev",
                        &tn,
                        "nodad",
                        "noprefixroute",
                    ],
                )
            })
            .await?
            .context("host mesh addr on TUN")?;
        }

        let udp = UdpSocket::bind(("::", port))
            .await
            .with_context(|| format!("bind mesh udp :{port}"))?;
        // Two control sockets on the host addr: pod-facing DNS (53) and
        // daemon-to-daemon registry gossip (5305). Both only reachable
        // after WireGuard decapsulation or from local pods.
        let dns = UdpSocket::bind((host, DNS_PORT))
            .await
            .with_context(|| format!("bind mesh dns [{host}]:{DNS_PORT}"))?;
        let dns_tcp = TcpListener::bind((host, DNS_PORT))
            .await
            .with_context(|| format!("bind mesh dns/tcp [{host}]:{DNS_PORT}"))?;
        let gossip = UdpSocket::bind((host, GOSSIP_PORT))
            .await
            .with_context(|| format!("bind mesh gossip [{host}]:{GOSSIP_PORT}"))?;
        let upstream = net::upstream_resolver();

        let mut peers = HashMap::new();
        let mut endpoints = HashMap::new();
        for (i, pc) in conf.peers.iter().enumerate() {
            let (p, ep) = build_peer(&secret, pc, i as u32)?;
            let route = p.prefix;
            let tn = tun_name.to_string();
            tokio::task::spawn_blocking(move || {
                let _ = net::run(
                    "ip",
                    &["-6", "route", "replace", &format!("{route}/48"), "dev", &tn],
                );
            })
            .await?;
            endpoints.insert(ep, parse_pubkey(&pc.pubkey)?);
            peers.insert(parse_pubkey(&pc.pubkey)?, p);
        }

        let (shutdown_tx, _) = watch::channel(false);
        let mesh = Arc::new(Mesh {
            prefix,
            pubkey,
            port,
            data_dir: data_dir.to_path_buf(),
            conf: Mutex::new(conf),
            peers: Mutex::new(peers),
            endpoints: Mutex::new(endpoints),
            tun: AsyncFd::new(tun)?,
            udp,
            tun_name: tun_name.to_string(),
            pump_ticks: Default::default(),
            udp_pkts: Default::default(),
            tun_pkts: Default::default(),
            pump_where: Default::default(),
            shutdown_tx,
            supervisor: Mutex::new(None),
            host_addr: host,
            dns,
            dns_tcp,
            gossip,
            local_names: Mutex::new(Default::default()),
            remote_names: Mutex::new(Default::default()),
            announce: tokio::sync::Notify::new(),
            upstream,
            tasks: Mutex::new(Vec::new()),
        });
        // Supervised pump: a panic inside the spawned task would
        // otherwise die silently (dropped JoinHandle) leaving Recv-Q
        // to grow while `mesh status` still looks alive.
        let sup = mesh.clone();
        *mesh.supervisor.lock().await = Some(tokio::spawn(async move {
            loop {
                if *sup.shutdown_tx.borrow() {
                    break;
                }
                let h = tokio::spawn(sup.clone().pump());
                match h.await {
                    Ok(()) => break, // graceful shutdown
                    Err(e) => {
                        tracing::error!("mesh pump panicked: {e}; restarting");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }));
        // Mesh-DNS tasks: registry gossip + pod-facing DNS responder.
        // All subscribe to shutdown_tx and land in `tasks` so
        // shutdown() can wait for a real teardown.
        let mut tasks = mesh.tasks.lock().await;
        tasks.push(tokio::spawn(mesh.clone().gossip_rx()));
        tasks.push(tokio::spawn(mesh.clone().announcer()));
        tasks.push(tokio::spawn(mesh.clone().dns_server()));
        tasks.push(tokio::spawn(mesh.clone().dns_tcp_server()));
        drop(tasks);
        Ok(mesh)
    }

    /// Add/replace a peer live: session, endpoint map, route, conf.
    pub async fn add_peer(&self, endpoint: &str, pubkey_b64: &str) -> Result<()> {
        let pk = parse_pubkey(pubkey_b64)?;
        let _ep: SocketAddr = canon_ep(
            endpoint
                .parse()
                .with_context(|| format!("invalid endpoint '{endpoint}' — want ip:port"))?,
        );
        let priv_b64 = { self.conf.lock().await.private_key.clone() };
        let priv_bytes: [u8; 32] = WG_B64.decode(priv_b64.trim())?.try_into().unwrap();
        let secret = StaticSecret::from(priv_bytes);
        let pc = MeshPeerConf {
            endpoint: endpoint.to_string(),
            pubkey: pubkey_b64.to_string(),
        };
        let idx = { self.peers.lock().await.len() as u32 };
        let (peer, ep) = build_peer(&secret, &pc, idx)?;
        let prefix = peer.prefix;
        {
            let mut peers = self.peers.lock().await;
            // Replacing an existing peer: drop its endpoint mapping and
            // its route (a re-announced peer gets a fresh session).
            if let Some(old) = peers.insert(pk, peer) {
                self.endpoints.lock().await.remove(&old.endpoint);
            }
            self.endpoints.lock().await.insert(ep, pk);
        }
        let tn = self.tun_name.clone();
        tokio::task::spawn_blocking(move || {
            let _ = net::run(
                "ip",
                &[
                    "-6",
                    "route",
                    "replace",
                    &format!("{prefix}/48"),
                    "dev",
                    &tn,
                ],
            );
        })
        .await?;
        {
            let mut c = self.conf.lock().await;
            c.peers.retain(|p| p.pubkey != pubkey_b64);
            c.peers.push(pc);
            crate::state::save_mesh(&self.data_dir, &c)?;
        }
        // Kick the handshake proactively so `mesh status` shows liveness
        // before the first payload byte.
        self.kick(pk).await;
        // Push our registry immediately — a fresh peer shouldn't wait
        // a full interval to learn our pod names.
        self.announce.notify_one();
        Ok(())
    }

    /// Remove a peer: session, endpoint map, route, conf.
    pub async fn remove_peer(&self, pubkey_b64: &str) -> Result<bool> {
        let pk = parse_pubkey(pubkey_b64)?;
        let removed = {
            let mut peers = self.peers.lock().await;
            peers.remove(&pk)
        };
        let Some(old) = removed else {
            return Ok(false);
        };
        self.endpoints.lock().await.remove(&old.endpoint);
        let prefix = old.prefix;
        let tn = self.tun_name.clone();
        tokio::task::spawn_blocking(move || {
            let _ = net::run(
                "ip",
                &["-6", "route", "del", &format!("{prefix}/48"), "dev", &tn],
            );
        })
        .await?;
        {
            let mut c = self.conf.lock().await;
            c.peers.retain(|p| p.pubkey != pubkey_b64);
            crate::state::save_mesh(&self.data_dir, &c)?;
        }
        // A removed peer's names must not linger for the full TTL.
        self.remote_names.lock().await.remove(&prefix);
        Ok(true)
    }

    /// Send a handshake initiation to `pk` so the session is live
    /// before traffic flows.
    async fn kick(&self, pk: [u8; 32]) {
        let mut buf = [0u8; 148];
        let mut peers = self.peers.lock().await;
        if let Some(p) = peers.get_mut(&pk) {
            if let TunnResult::WriteToNetwork(d) =
                p.tunn.format_handshake_initiation(&mut buf, false)
            {
                let _ = self.udp.send_to(d, p.endpoint).await;
            }
        }
    }

    /// Snapshot for `mesh status` / REST.
    pub async fn status(&self) -> rustypods_proto::rpc::MeshStatus {
        let peers = self.peers.lock().await;
        let infos = peers
            .values()
            .map(|p| {
                let (since, tx, rx, _loss, _rtt) = p.tunn.stats();
                // Unmap for display — [::ffff:10.0.0.1]:51820 reads as
                // 10.0.0.1:51820, matching what the operator typed.
                let ip = match p.endpoint.ip() {
                    IpAddr::V6(v6) => v6
                        .to_ipv4_mapped()
                        .map(IpAddr::V4)
                        .unwrap_or(IpAddr::V6(v6)),
                    v4 => v4,
                };
                rustypods_proto::rpc::MeshPeerInfo {
                    endpoint: SocketAddr::new(ip, p.endpoint.port()).to_string(),
                    pubkey: p.pubkey_b64.clone(),
                    prefix: format!("{}/48", p.prefix),
                    handshake_secs_ago: since.map(|d| d.as_secs() as i64).unwrap_or(-1),
                    tx_bytes: tx as u64,
                    rx_bytes: rx as u64,
                }
            })
            .collect();
        rustypods_proto::rpc::MeshStatus {
            enabled: true,
            pubkey: self.pubkey.clone(),
            listen: format!("[::]:{}", self.port),
            prefix: format!("{}/48", self.prefix),
            peers: infos,
            pump_ticks: self.pump_ticks.load(std::sync::atomic::Ordering::Relaxed),
            udp_pkts: self.udp_pkts.load(std::sync::atomic::Ordering::Relaxed),
            tun_pkts: self.tun_pkts.load(std::sync::atomic::Ordering::Relaxed),
            names: self.names().await.into_iter().collect(),
        }
    }

    /// Graceful teardown (`mesh deinit`): signal the pump, wait for the
    /// supervisor to finish, then delete the persistent TUN. Routes
    /// through rp-mesh0 die with the device; the caller strips pod
    /// /128s and removes conf/mesh.conf.
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(h) = self.supervisor.lock().await.take() {
            if tokio::time::timeout(Duration::from_secs(3), h)
                .await
                .is_err()
            {
                tracing::warn!("mesh pump did not stop in 3s — abandoning");
            }
        }
        for h in self.tasks.lock().await.drain(..) {
            let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
        }
        // `ip link del` beats `tuntap del`: it removes the netdev even
        // while a stale fd keeps it depersisted-only.
        let tn = self.tun_name.clone();
        let tn2 = tn.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || net::run("ip", &["link", "del", &tn]))
            .await
            .map_err(anyhow::Error::from)
            .and_then(|r| r)
        {
            tracing::warn!("mesh teardown: delete {tn2}: {e:#}");
        }
    }

    /// The packet pump: TUN ↔ BoringTun ↔ UDP, plus a 1s timer pass for
    /// rekey/keepalive. Runs until the daemon dies.
    async fn pump(self: Arc<Self>) {
        let mut tun_buf = vec![0u8; 2048];
        let mut udp_buf = vec![0u8; 2048];
        let mut out = vec![0u8; 2048];
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut shutdown = self.shutdown_tx.subscribe();
        use std::sync::atomic::Ordering::Relaxed;
        loop {
            self.pump_ticks.fetch_add(1, Relaxed);
            self.pump_where.store(0, Relaxed);
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tick.tick() => {
                    self.pump_where.store(5, Relaxed);
                    self.update_timers(&mut out).await;
                }
                r = self.tun.readable() => {
                    // try_io on THIS guard only — a nested readable()
                    // inside the arm deadlocks (a second guard waits
                    // for `r` to drop, which can't happen until the
                    // arm returns: pump frozen, UDP Recv-Q grows).
                    self.pump_where.store(1, Relaxed);
                    let Ok(mut guard) = r else { continue };
                    if let Ok(Ok(n)) = guard.try_io(|fd| {
                        let n = unsafe {
                            libc::read(fd.as_raw_fd(), tun_buf.as_mut_ptr() as *mut _, tun_buf.len())
                        };
                        if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
                    }) {
                        self.tun_pkts.fetch_add(1, Relaxed);
                        self.pump_where.store(2, Relaxed);
                        self.route_out(&tun_buf[..n], &mut out).await;
                    }
                }
                r = self.udp.recv_from(&mut udp_buf) => {
                    self.pump_where.store(3, Relaxed);
                    if let Ok((n, src)) = r {
                        self.udp_pkts.fetch_add(1, Relaxed);
                        self.pump_where.store(4, Relaxed);
                        self.handle_udp(&udp_buf[..n], src, &mut out).await;
                    }
                }
            }
        }
    }

    async fn tun_write(&self, pkt: &[u8]) {
        let _ = unsafe {
            libc::write(
                self.tun.get_ref().as_raw_fd(),
                pkt.as_ptr() as *const _,
                pkt.len(),
            )
        };
    }

    /// TUN → wire: find the peer owning the dst /48 and encapsulate.
    async fn route_out(&self, pkt: &[u8], out: &mut [u8]) {
        let Some(IpAddr::V6(dst)) = Tunn::dst_address(pkt) else {
            return; // v4 has no place on the mesh — pods speak ULA v6
        };
        if in_prefix(self.prefix, dst) {
            return; // local space never re-enters the tunnel
        }
        let mut peers = self.peers.lock().await;
        for p in peers.values_mut() {
            if !in_prefix(p.prefix, dst) {
                continue;
            }
            match p.tunn.encapsulate(pkt, out) {
                TunnResult::WriteToNetwork(dgram) => {
                    if let Err(e) = self.udp.send_to(dgram, p.endpoint).await {
                        tracing::debug!("mesh udp send {}: {e}", p.endpoint);
                    }
                }
                TunnResult::Err(e) => {
                    tracing::debug!("mesh encapsulate: {e:?}");
                }
                _ => {}
            }
            return;
        }
        tracing::trace!("mesh: no peer route for {dst}");
    }

    /// Wire → TUN: attribute the datagram to a peer session (endpoint
    /// map first, key-scan fallback for roaming sources), decapsulate,
    /// and write resulting plaintext packets into the TUN. Chained
    /// decapsulate calls (empty datagram) drain handshake replies.
    async fn handle_udp(&self, dgram: &[u8], src: SocketAddr, out: &mut [u8]) {
        let src = canon_ep(src); // v4 peers arrive as mapped-v6 srcs
        let key = {
            let eps = self.endpoints.lock().await;
            eps.get(&src).copied()
        };
        let mut peers = self.peers.lock().await;
        // Resolve which peer this datagram belongs to: known endpoint
        // first; unknown sources try each session — only the right key
        // will verify. On success we (re)bind the endpoint (roaming).
        let pk = match key {
            Some(k) if peers.contains_key(&k) => Some(k),
            _ => {
                let mut found = None;
                for (k, p) in peers.iter_mut() {
                    match p.tunn.decapsulate(Some(src.ip()), dgram, out) {
                        TunnResult::Err(_) => continue,
                        r => {
                            self.dispatch_result(r, src).await;
                            found = Some(*k);
                            break;
                        }
                    }
                }
                if let Some(k) = found {
                    let mut eps = self.endpoints.lock().await;
                    if let Some(p) = peers.get_mut(&k) {
                        if p.endpoint != src {
                            tracing::info!("mesh peer {} roamed → {src}", p.pubkey_b64);
                            // Drop the stale mapping — a future datagram
                            // from the old endpoint must not re-attribute.
                            eps.remove(&p.endpoint);
                            p.endpoint = src;
                        }
                    }
                    eps.insert(src, k);
                }
                found
            }
        };
        let Some(pk) = pk else { return };
        // We already consumed the datagram in the fallback branch; for
        // the known-endpoint path decapsulate it now.
        if key.is_some() {
            let Some(p) = peers.get_mut(&pk) else { return };
            let r = p.tunn.decapsulate(Some(src.ip()), dgram, out);
            self.dispatch_result(r, src).await;
        }
        // Drain queued protocol messages until Done (boringtun contract).
        if let Some(p) = peers.get_mut(&pk) {
            loop {
                match p.tunn.decapsulate(None, &[], out) {
                    TunnResult::Done => break,
                    r => self.dispatch_result(r, src).await,
                }
            }
        }
    }

    /// Handle one TunnResult: protocol messages go back to the wire,
    /// plaintext goes into the TUN — but only when its dst sits inside
    /// OUR /48 (a peer may not inject routes for foreign space).
    async fn dispatch_result<'a>(&'a self, r: TunnResult<'a>, src: SocketAddr) {
        match r {
            TunnResult::WriteToNetwork(d) => {
                let _ = self.udp.send_to(d, src).await;
            }
            TunnResult::WriteToTunnelV6(pkt, _src_addr) => {
                if let Some(IpAddr::V6(dst)) = Tunn::dst_address(pkt) {
                    if in_prefix(self.prefix, dst) {
                        self.tun_write(pkt).await;
                    } else {
                        tracing::warn!("mesh: dropping injected packet for foreign dst {dst}");
                    }
                }
            }
            TunnResult::WriteToTunnelV4(_, _) => {} // v6-only mesh
            TunnResult::Err(e) => tracing::debug!("mesh decapsulate: {e:?}"),
            TunnResult::Done => {}
        }
    }

    /// Per-second timer pass — drives rekey, keepalive and handshake
    /// retransmits for every peer.
    async fn update_timers(&self, out: &mut [u8]) {
        let mut peers = self.peers.lock().await;
        for p in peers.values_mut() {
            if let TunnResult::WriteToNetwork(d) = p.tunn.update_timers(out) {
                let _ = self.udp.send_to(d, p.endpoint).await;
            }
        }
    }

    // --- Mesh-DNS (Wave K) ---

    /// Feed the local pod registry (Svc pushes on every pod lifecycle
    /// change). Triggers an immediate announce so peers learn fast.
    pub async fn set_local_names(&self, names: std::collections::BTreeMap<String, Ipv6Addr>) {
        let mut l = self.local_names.lock().await;
        if *l != names {
            *l = names;
            drop(l);
            self.announce.notify_one();
        }
    }

    /// Resolve a pod name across local + remote registries. Local
    /// always wins; among peers claiming the same name the lowest
    /// peer /48 wins — HashMap iteration order is nondeterministic,
    /// so a conflict must resolve the same way on every query.
    async fn resolve(&self, name: &str) -> Option<Ipv6Addr> {
        if let Some(a) = self.local_names.lock().await.get(name) {
            return Some(*a);
        }
        let r = self.remote_names.lock().await;
        r.iter()
            .filter(|(_, (t, _))| t.elapsed() < NAME_TTL)
            .filter_map(|(p, (_, reg))| reg.get(name).map(|a| (*p, *a)))
            .min_by_key(|(p, _)| *p)
            .map(|(_, a)| a)
    }

    /// Merged name→addr snapshot for `mesh status` / REST.
    async fn names(&self) -> std::collections::BTreeMap<String, String> {
        let mut out = std::collections::BTreeMap::new();
        for (n, a) in self.local_names.lock().await.iter() {
            out.insert(n.clone(), a.to_string());
        }
        // Sort peers by prefix so the displayed winner matches the
        // deterministic resolution in resolve().
        let remote = self.remote_names.lock().await;
        let mut remotes: Vec<_> = remote.iter().map(|(p, v)| (*p, v)).collect();
        remotes.sort_by_key(|(p, _)| *p);
        for (_, (t, reg)) in remotes {
            if t.elapsed() < NAME_TTL {
                for (n, a) in reg {
                    out.entry(n.clone()).or_insert_with(|| a.to_string());
                }
            }
        }
        out
    }

    /// Push the local registry to every peer: JSON over the tunnel to
    /// fd<peer>::1:5305. Full-state (not delta) — replace semantics
    /// heal missed updates and pod removals.
    async fn send_announces(&self) {
        let names = self.local_names.lock().await.clone();
        let body = serde_json::json!({ "names": names }).to_string();
        let peers = self.peers.lock().await;
        for p in peers.values() {
            let dst = SocketAddr::new(IpAddr::V6(host_addr(p.prefix)), GOSSIP_PORT);
            if let Err(e) = self.gossip.send_to(body.as_bytes(), dst).await {
                tracing::debug!("mesh gossip → {dst}: {e}");
            }
        }
    }

    /// Receive peers' registries. Trust boundary: the datagram arrived
    /// decapsulated from the tunnel AND src must be exactly that peer's
    /// fd<peer>::1 — a pod can't forge it (pods use :<idx>::2, and a
    /// spoofed src still has to be inside a *configured* peer /48).
    async fn gossip_rx(self: Arc<Self>) {
        let mut buf = vec![0u8; 8192];
        let mut shutdown = self.shutdown_tx.subscribe();
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                r = self.gossip.recv_from(&mut buf) => {
                    let Ok((n, src)) = r else { continue };
                    let IpAddr::V6(src6) = src.ip() else { continue };
                    let from_peer = {
                        let peers = self.peers.lock().await;
                        peers.values().any(|p| host_addr(p.prefix) == src6)
                    };
                    if !from_peer {
                        tracing::debug!("mesh gossip: dropped non-peer src {src}");
                        continue;
                    }
                    let peer_prefix = {
                        let segs = src6.segments();
                        Ipv6Addr::new(segs[0], segs[1], segs[2], 0, 0, 0, 0, 0)
                    };
                    #[derive(serde::Deserialize)]
                    struct Ann {
                        names: std::collections::BTreeMap<String, Ipv6Addr>,
                    }
                    match serde_json::from_slice::<Ann>(&buf[..n]) {
                        Ok(a) => {
                            let names = sanitize_registry(peer_prefix, a.names);
                            self.remote_names
                                .lock()
                                .await
                                .insert(peer_prefix, (std::time::Instant::now(), names));
                        }
                        Err(e) => tracing::debug!("mesh gossip parse: {e}"),
                    }
                }
            }
        }
    }

    /// Periodic announce + TTL sweep; Notify gives on-change pushes.
    async fn announcer(self: Arc<Self>) {
        let mut tick = tokio::time::interval(ANNOUNCE_EVERY);
        let mut shutdown = self.shutdown_tx.subscribe();
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = self.announce.notified() => self.send_announces().await,
                _ = tick.tick() => {
                    self.remote_names
                        .lock()
                        .await
                        .retain(|_, (t, _)| t.elapsed() < NAME_TTL);
                    self.send_announces().await;
                }
            }
        }
    }

    /// Pod-facing DNS on [fd<host>::1]:53. Mesh names answer locally
    /// (AAAA → addr, A → NODATA); everything else relays upstream so a
    /// pod's resolv.conf can point only at us without losing real DNS.
    async fn dns_server(self: Arc<Self>) {
        let mut buf = vec![0u8; 4096];
        let mut shutdown = self.shutdown_tx.subscribe();
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                r = self.dns.recv_from(&mut buf) => {
                    let Ok((n, src)) = r else { continue };
                    if let Some(rep) = self.answer_query(&buf[..n]).await {
                        let _ = self.dns.send_to(&rep, src).await;
                    }
                }
            }
        }
    }

    /// DNS-over-TCP on the same addr — RFC requires it for truncated
    /// answers and some resolvers probe TCP first. 2-byte length
    /// prefix framing per RFC 1035 §4.2.2.
    async fn dns_tcp_server(self: Arc<Self>) {
        let mut shutdown = self.shutdown_tx.subscribe();
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                r = self.dns_tcp.accept() => {
                    let Ok((mut s, _)) = r else { continue };
                    let m = self.clone();
                    tokio::spawn(async move {
                        let mut len = [0u8; 2];
                        while s.read_exact(&mut len).await.is_ok() {
                            let n = u16::from_be_bytes(len) as usize;
                            let mut q = vec![0u8; n];
                            if s.read_exact(&mut q).await.is_err() {
                                return;
                            }
                            if let Some(rep) = m.answer_query(&q).await {
                                let l = (rep.len() as u16).to_be_bytes();
                                if s.write_all(&l).await.is_err()
                                    || s.write_all(&rep).await.is_err()
                                {
                                    return;
                                }
                            }
                        }
                    });
                }
            }
        }
    }

    /// Shared query path for UDP and TCP: own the mesh names, relay
    /// the rest upstream.
    async fn answer_query(&self, pkt: &[u8]) -> Option<Vec<u8>> {
        let (qname, qtype) = dns_query_name(pkt)?;
        match self.resolve(&qname).await {
            Some(addr) if qtype == 28 => dns_answer_aaaa(pkt, addr),
            Some(_) => dns_nodata(pkt),
            None => self.dns_forward(pkt).await,
        }
    }

    /// Relay one query verbatim to the host resolver; None on timeout.
    /// The upstream is re-read per query — the address captured at mesh
    /// start goes stale when the host roams networks (DHCP/VPN).
    async fn dns_forward(&self, pkt: &[u8]) -> Option<Vec<u8>> {
        let up = canon_ep(net::upstream_resolver().or(self.upstream)?);
        let s = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await.ok()?;
        s.send_to(pkt, up).await.ok()?;
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(3), s.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
            _ => None,
        }
    }
}

/// Extract (single-label name, qtype) from a DNS query. Recognizes a
/// bare `db`, `db.rp`, `db.pods` or `db.local` — the zone suffixes a
/// pod's `search` line or a typed FQDN produces. Every index is
/// bounds-checked: a truncated question (missing qclass, cut-off
/// label) returns None instead of panicking the DNS task.
fn dns_query_name(pkt: &[u8]) -> Option<(String, u16)> {
    if pkt.len() < 12 || pkt[2] & 0x80 != 0 {
        return None; // not a query
    }
    // One question only — qd=0 has nothing to answer, qd>1 is not
    // something the mesh resolver owns.
    let qd = u16::from_be_bytes([*pkt.get(4)?, *pkt.get(5)?]);
    if qd != 1 {
        return None;
    }
    let mut qname = String::new();
    let mut i = 12;
    let mut labels = 0usize;
    loop {
        let len = *pkt.get(i)? as usize;
        if len == 0 {
            break;
        }
        // Compression pointer or an over-long label — refuse rather
        // than walk off the buffer (a 0xC0 length used to be added
        // unchecked and the following slice panicked).
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        i = i.checked_add(1)?;
        let label = std::str::from_utf8(pkt.get(i..i.checked_add(len)?)?).ok()?;
        if !qname.is_empty() {
            qname.push('.');
        }
        qname.push_str(&label.to_lowercase());
        i = i.checked_add(len)?;
        labels += 1;
        if labels > 128 {
            return None;
        }
    }
    // qtype AND qclass — an 18-byte `db` query has the type but not
    // the class; answering it used to panic in dns_response_base.
    let qtype = u16::from_be_bytes([*pkt.get(i.checked_add(1)?)?, *pkt.get(i.checked_add(2)?)?]);
    let _qclass = u16::from_be_bytes([*pkt.get(i.checked_add(3)?)?, *pkt.get(i.checked_add(4)?)?]);
    for zone in [".rp", ".pods", ".local", ".rustypods"] {
        if let Some(stripped) = qname.strip_suffix(zone) {
            qname = stripped.to_string();
            break;
        }
    }
    if qname.contains('.') || qname.is_empty() {
        return Some((String::new(), qtype)); // multi-label: never ours
    }
    Some((qname, qtype))
}

/// Walk one uncompressed DNS name starting at `i`. Returns the index
/// just past the root label. Compression pointers and labels >63 are
/// rejected — the builders only echo a question they fully own.
fn dns_skip_name(pkt: &[u8], mut i: usize) -> Option<usize> {
    let mut labels = 0usize;
    loop {
        let len = *pkt.get(i)? as usize;
        if len == 0 {
            return i.checked_add(1);
        }
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        i = i.checked_add(1)?.checked_add(len)?;
        if pkt.get(i).is_none() {
            return None;
        }
        labels += 1;
        if labels > 128 {
            return None;
        }
    }
}

/// Flip the query header into a response (QR|AA|RA, rcode NOERROR),
/// keep the single question, and drop any prior answers. None when
/// the packet is truncated, compressed, or not exactly one question —
/// callers must not slice past `pkt.len()`.
fn dns_response_base(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.get(..12).is_none() {
        return None;
    }
    let qd = u16::from_be_bytes([*pkt.get(4)?, *pkt.get(5)?]) as usize;
    if qd != 1 {
        return None;
    }
    let mut i = 12;
    for _ in 0..qd {
        i = dns_skip_name(pkt, i)?;
        // qtype + qclass
        if pkt.get(i..i.checked_add(4)?)?.len() != 4 {
            return None;
        }
        i += 4;
    }
    let mut out = pkt.get(..i)?.to_vec();
    out[2] |= 0x84; // QR + AA
    out[3] = 0x80; // RA
    out[6..8].copy_from_slice(&[0, 0]); // ancount
    out[8..10].copy_from_slice(&[0, 0]); // nscount
    out[10..12].copy_from_slice(&[0, 0]); // arcount
    Some(out)
}

/// NOERROR with zero answers — correct for `A podname` on a v6 mesh.
fn dns_nodata(pkt: &[u8]) -> Option<Vec<u8>> {
    dns_response_base(pkt)
}

/// AAAA answer for a resolved mesh name: name compressed to 0xC00C.
fn dns_answer_aaaa(pkt: &[u8], addr: Ipv6Addr) -> Option<Vec<u8>> {
    let mut out = dns_response_base(pkt)?;
    out[6..8].copy_from_slice(&[0, 1]); // ancount = 1
    out.extend_from_slice(&[0xc0, 0x0c]); // name → question
    out.extend_from_slice(&28u16.to_be_bytes()); // AAAA
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out.extend_from_slice(&5u32.to_be_bytes()); // TTL 5s
    out.extend_from_slice(&16u16.to_be_bytes()); // rdlength
    out.extend_from_slice(&addr.octets());
    Some(out)
}

/// Registry values must stay inside the announcer's own /48 — never
/// trust a peer to name OUR space or a third host's. Names must be
/// valid single DNS labels, and the whole registry is capped so a
/// hostile or buggy peer can't grow our memory unboundedly.
fn sanitize_registry(
    peer_prefix: Ipv6Addr,
    names: std::collections::BTreeMap<String, Ipv6Addr>,
) -> std::collections::BTreeMap<String, Ipv6Addr> {
    names
        .into_iter()
        .filter(|(n, a)| valid_dns_label(n) && in_prefix(peer_prefix, *a))
        .take(1024)
        .collect()
}

/// Single DNS label: ≤63 chars, alphanumeric plus '-'/'_'.
fn valid_dns_label(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 63
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Build one boringtun session for a peer conf.
fn build_peer(secret: &StaticSecret, pc: &MeshPeerConf, index: u32) -> Result<(Peer, SocketAddr)> {
    let pk = parse_pubkey(&pc.pubkey)?;
    let ep: SocketAddr = canon_ep(
        pc.endpoint
            .parse()
            .with_context(|| format!("invalid peer endpoint '{}'", pc.endpoint))?,
    );
    let tunn = Tunn::new(
        secret.clone(),
        PublicKey::from(pk),
        None,     // no preshared key — pubkey-derived ULA already binds identity
        Some(25), // keepalive: NAT'd peers stay mapped
        index,
        None, // per-peer rate limiter
    )
    .map_err(|e| anyhow::anyhow!("boringtun peer init: {e}"))?;
    Ok((
        Peer {
            tunn,
            endpoint: ep,
            pubkey_b64: pc.pubkey.clone(),
            prefix: prefix_of(&pc.pubkey)?,
        },
        ep,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_stable_and_ula() {
        let (_priv, pub_) = keygen();
        let p = prefix_of(&pub_).unwrap();
        // fd + locally-assigned bit, /48 → top 3 hextets only.
        assert_eq!(p.segments()[0] & 0xff00, 0xfd00);
        assert!(p.segments()[0] & 0x0040 != 0 || p.segments()[0] == 0xfd00);
        // Stability: same key → same prefix.
        assert_eq!(p, prefix_of(&pub_).unwrap());
    }

    #[test]
    fn mesh_ip_shape() {
        let p = Ipv6Addr::new(0xfdab, 0x1234, 0x5678, 0, 0, 0, 0, 0);
        let ip = mesh_ip(p, 4);
        assert_eq!(ip, Ipv6Addr::new(0xfdab, 0x1234, 0x5678, 4, 0, 0, 0, 2));
        assert!(in_prefix(p, ip));
        let other = Ipv6Addr::new(0xfdff, 0x1234, 0x5678, 4, 0, 0, 0, 2);
        assert!(!in_prefix(p, other));
    }

    /// The dataplane's core assumption: a tokio UdpSocket bound to [::]
    /// accepts mapped-v6 destinations and delivers them as IPv4, and
    /// reports v4 peers back as mapped-v6 srcs. If this fails on some
    /// platform, canon_ep/send semantics need revisiting.
    #[tokio::test]
    async fn mapped_v4_over_v6_socket() {
        use tokio::net::UdpSocket as U;
        let rx = U::bind((Ipv6Addr::UNSPECIFIED, 0)).await.unwrap();
        let port = rx.local_addr().unwrap().port();
        let tx = U::bind((Ipv6Addr::UNSPECIFIED, 0)).await.unwrap();
        let dst = canon_ep("127.0.0.1:0".parse::<SocketAddr>().unwrap());
        let dst = SocketAddr::new(dst.ip(), port);
        tx.send_to(b"hi", dst).await.unwrap();
        let mut buf = [0u8; 8];
        let (n, src) = tokio::time::timeout(Duration::from_secs(2), rx.recv_from(&mut buf))
            .await
            .expect("recv timeout — v6 socket can't do mapped-v4")
            .unwrap();
        assert_eq!(&buf[..n], b"hi");
        // src must canonicalize back to the same key we'd store.
        assert_eq!(canon_ep(src).ip(), canon_ep(dst).ip());
    }

    #[test]
    fn pubkey_of_roundtrip() {
        let (priv_, pub_) = keygen();
        assert_eq!(pubkey_of(&priv_).unwrap(), pub_);
        assert!(pubkey_of("not-b64!!!").is_err());
    }

    /// Minimal DNS query packet: id, flags, qdcount=1, one qname.
    fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut p = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes()); // IN
        p
    }

    #[test]
    fn dns_query_name_parses_zones() {
        assert_eq!(
            dns_query_name(&dns_query("db", 28)),
            Some(("db".into(), 28))
        );
        assert_eq!(
            dns_query_name(&dns_query("db.rp", 1)),
            Some(("db".into(), 1))
        );
        assert_eq!(
            dns_query_name(&dns_query("db.pods", 28)),
            Some(("db".into(), 28))
        );
        assert_eq!(
            dns_query_name(&dns_query("DB.LOCAL", 28)),
            Some(("db".into(), 28))
        );
        // Multi-label names are never ours — empty name sentinel.
        assert_eq!(
            dns_query_name(&dns_query("a.b.example.com", 28)),
            Some((String::new(), 28))
        );
        // Responses (QR bit) and truncated packets are rejected.
        let mut resp = dns_query("db", 28);
        resp[2] |= 0x80;
        assert_eq!(dns_query_name(&resp), None);
        assert_eq!(dns_query_name(&dns_query("db", 28)[..10]), None);
    }

    #[test]
    fn dns_aaaa_answer_roundtrips() {
        let q = dns_query("db", 28);
        let addr = Ipv6Addr::new(0xfd41, 0x85b6, 0xa9dd, 4, 0, 0, 0, 2);
        let ans = dns_answer_aaaa(&q, addr).unwrap();
        // Header: QR set, ancount=1.
        assert_eq!(ans[2] & 0x80, 0x80);
        assert_eq!(&ans[6..8], &[0, 1]);
        // Question preserved verbatim, answer tail carries the addr.
        assert!(ans.windows(2).any(|w| w == [0xc0, 0x0c]));
        assert_eq!(&ans[ans.len() - 16..], &addr.octets());
        // [name:2][type:2][class:2][ttl:4][rdlen:2][rdata:16] — the
        // AAAA type field sits 26 bytes from the tail.
        assert_eq!(&ans[ans.len() - 26..ans.len() - 24], &28u16.to_be_bytes());
    }

    #[test]
    fn dns_nodata_has_zero_answers() {
        let ans = dns_nodata(&dns_query("db", 1)).unwrap();
        assert_eq!(ans[2] & 0x80, 0x80); // still a valid response
        assert_eq!(&ans[6..8], &[0, 0]); // ancount = 0 → NODATA
        assert_eq!(ans[3] & 0x0f, 0); // rcode NOERROR, not NXDOMAIN
    }

    /// The 18-byte `db` query that killed the DNS task: header + label
    /// + root + qtype, qclass truncated. Builders must return None.
    #[test]
    fn dns_truncated_question_does_not_panic() {
        let mut q = dns_query("db", 28);
        assert!(q.len() > 18);
        q.truncate(18);
        assert_eq!(dns_query_name(&q), None);
        assert_eq!(dns_response_base(&q), None);
        assert_eq!(dns_nodata(&q), None);
        assert_eq!(dns_answer_aaaa(&q, Ipv6Addr::LOCALHOST), None);

        assert_eq!(dns_query_name(&[0u8; 11]), None); // truncated header
        assert_eq!(dns_response_base(&[0u8; 11]), None);

        let mut qd0 = dns_query("db", 28);
        qd0[4] = 0;
        qd0[5] = 0;
        assert_eq!(dns_query_name(&qd0), None);
        assert_eq!(dns_response_base(&qd0), None);

        let mut qd2 = dns_query("db", 28);
        qd2[5] = 2;
        assert_eq!(dns_query_name(&qd2), None);
        assert_eq!(dns_response_base(&qd2), None);

        // Compression pointer where a label length should be.
        let mut comp = dns_query("db", 28);
        comp[12] = 0xc0;
        comp[13] = 0x0c;
        assert_eq!(dns_query_name(&comp), None);
        assert_eq!(dns_response_base(&comp), None);

        // Label length 64 (illegal) and a length that would walk past
        // the buffer if added unchecked.
        let mut big = vec![0u8; 20];
        big[5] = 1; // qdcount
        big[12] = 64;
        assert_eq!(dns_query_name(&big), None);
        assert_eq!(dns_answer_aaaa(&big, Ipv6Addr::LOCALHOST), None);
        big[12] = 200;
        assert_eq!(dns_response_base(&big), None);
    }

    /// Every parser/builder must survive arbitrary input. xorshift so
    /// the sequence is deterministic and dependency-free.
    #[test]
    fn dns_random_bytes_never_panic() {
        let mut state = 0xA5A5_1234u32;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };
        for _ in 0..4_000 {
            let len = (next() % 80) as usize;
            let buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = dns_query_name(&buf);
            let _ = dns_response_base(&buf);
            let _ = dns_nodata(&buf);
            let _ = dns_answer_aaaa(&buf, Ipv6Addr::LOCALHOST);
            let _ = dns_skip_name(&buf, (next() as usize) % (len.max(1)));
        }
    }

    #[test]
    fn registry_json_roundtrip_and_sanitize() {
        let ours = Ipv6Addr::new(0xfd41, 0x85b6, 0xa9dd, 0, 0, 0, 0, 0);
        let theirs = Ipv6Addr::new(0xfd51, 0x0b83, 0x5157, 0, 0, 0, 0, 0);
        let mut names = std::collections::BTreeMap::new();
        names.insert("db".to_string(), mesh_ip(theirs, 1));
        names.insert("web".to_string(), mesh_ip(theirs, 7));
        let body = serde_json::json!({ "names": names }).to_string();
        #[derive(serde::Deserialize)]
        struct Ann {
            names: std::collections::BTreeMap<String, Ipv6Addr>,
        }
        let parsed: Ann = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.names.len(), 2);

        // Sanitize: addrs inside the announcer's /48 survive, foreign
        // addrs (ours, or a third host's) are stripped.
        let mut dirty = parsed.names.clone();
        dirty.insert("evil".to_string(), mesh_ip(ours, 9));
        dirty.insert("star".to_string(), Ipv6Addr::LOCALHOST);
        let clean = sanitize_registry(theirs, dirty);
        assert_eq!(clean.len(), 2);
        assert!(clean.contains_key("db"));
        assert!(!clean.contains_key("evil"));
        assert!(!clean.contains_key("star"));
        // Every surviving addr is in the announcer's prefix.
        assert!(clean.values().all(|a| in_prefix(theirs, *a)));
    }

    #[test]
    fn registry_rejects_bad_names_and_caps_size() {
        let theirs = Ipv6Addr::new(0xfd51, 0x0b83, 0x5157, 0, 0, 0, 0, 0);
        let mut names = std::collections::BTreeMap::new();
        // Invalid labels: empty, dotted, >63 chars, weird bytes.
        names.insert("".to_string(), mesh_ip(theirs, 1));
        names.insert("a.b".to_string(), mesh_ip(theirs, 2));
        names.insert("x".repeat(64), mesh_ip(theirs, 3));
        names.insert("bad name".to_string(), mesh_ip(theirs, 4));
        // Valid labels survive.
        names.insert("db-1".to_string(), mesh_ip(theirs, 5));
        names.insert("web_2".to_string(), mesh_ip(theirs, 6));
        let clean = sanitize_registry(theirs, names);
        assert_eq!(clean.len(), 2);
        assert!(clean.contains_key("db-1"));
        assert!(clean.contains_key("web_2"));

        // Cap: a flood of valid entries is bounded at 1024.
        let flood: std::collections::BTreeMap<String, Ipv6Addr> = (0..5000u32)
            .map(|i| (format!("pod{i}"), mesh_ip(theirs, i % 200 + 1)))
            .collect();
        assert_eq!(sanitize_registry(theirs, flood).len(), 1024);
    }

    /// A socket bound to a specific ULA addr — the DNS/gossip bind
    /// pattern — must actually receive datagrams sent to that addr.
    #[tokio::test]
    async fn bound_host_addr_receives() {
        // Binding a real ULA needs the addr on an interface, which the
        // test env may not grant — emulate with ::1 semantics on lo.
        let rx = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        let port = rx.local_addr().unwrap().port();
        let tx = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        tx.send_to(b"x", (Ipv6Addr::LOCALHOST, port)).await.unwrap();
        let mut buf = [0u8; 4];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), rx.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"x");
    }
}
