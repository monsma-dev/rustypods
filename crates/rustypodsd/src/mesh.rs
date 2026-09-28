//! Multi-host pod mesh (Wave I): userspace WireGuard via BoringTun.
//!
//! Each daemon derives a stable ULA /48 from its own WG pubkey —
//! `fd` plus 40 bits of sha256(pubkey), with two Global-ID bits
//! forced (see `prefix_of`) — so every pod mesh address is
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
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{watch, Mutex};

use crate::net;
use crate::state::{MeshConf, MeshPeerConf};

pub const TUN_NAME: &str = "rp-mesh0";
pub const DEFAULT_PORT: u16 = 51820;

/// `0` means "keep the default". Anything outside `1..=65535` is an
/// error — a bare `as u16` would wrap 70000 to 4464.
pub fn checked_listen_port(listen_port: u32) -> Result<Option<u16>, &'static str> {
    if listen_port == 0 {
        return Ok(None);
    }
    match u16::try_from(listen_port) {
        Ok(p) => Ok(Some(p)),
        Err(_) => Err("listen_port must be 1..=65535"),
    }
}
/// The host's own mesh address: `fd<host>::1/128` on rp-mesh0. Hosts
/// speak host-to-host control protocols (gossip, DNS) at this addr;
/// pods live at `:<idx>::2`.
pub const HOST_SUFFIX: u128 = 1;
/// Registry gossip between daemons — JSON over the tunnel.
const GOSSIP_PORT: u16 = 5305;
/// Pod-facing DNS on the host mesh addr.
const DNS_PORT: u16 = 53;
/// Concurrent UDP queries. Each may block up to 3s on upstream; the
/// recv loop must not await them inline or one slow resolver stalls
/// every pod.
const DNS_UDP_INFLIGHT: usize = 64;
/// Simultaneous DNS-over-TCP clients. Extra accepts are dropped.
const DNS_TCP_MAX_CONNS: usize = 32;
/// RFC 1035 length prefix cap. Matches the UDP buffer so a client
/// can't force a 64KiB allocation per connection.
const DNS_TCP_MAX_MSG: usize = 4096;
/// Per-read idle timeout on a DNS TCP connection.
const DNS_TCP_IDLE: Duration = Duration::from_secs(5);
/// Announce cadence; remote names expire after 3 intervals.
const ANNOUNCE_EVERY: Duration = Duration::from_secs(30);
const NAME_TTL: Duration = Duration::from_secs(95);
/// Signed gossip datagram cap. 1200 stays under a 1420-byte WireGuard
/// path MTU once the HMAC wrapper is included, so a chunk is never
/// fragmented inside the tunnel.
const GOSSIP_MAX_FRAME: usize = 1200;
/// Unknown WireGuard sources may attempt this many handshakes per second.
const UNKNOWN_HANDSHAKES_PER_SEC: u8 = 5;
/// Curve25519 decapsulations tried for one unknown datagram. The rest of
/// the peer set waits for a later packet, so one frame cannot walk every
/// session while the pump holds the peer lock.
const HANDSHAKE_SCAN_BUDGET: usize = 4;
/// Cap on tracked unknown sources. A fresh address past the cap evicts one
/// existing entry so the map cannot grow with spoofed source IPs.
const HANDSHAKE_SOURCE_CAP: usize = 4096;
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

/// Load the host WireGuard key from `conf/mesh.conf`, or mint one and
/// persist it. A later `mesh init` reuses this key, so the /48 stamped
/// into a signed leaf still matches. This does not create a CA.
pub fn ensure_identity(data_dir: &Path) -> Result<String> {
    let mut conf = crate::state::load_mesh(data_dir)?.unwrap_or_default();
    if conf.private_key.trim().is_empty() {
        let (priv_key, _) = keygen();
        conf.private_key = priv_key;
        crate::state::save_mesh(data_dir, &conf)?;
    }
    pubkey_of(&conf.private_key)
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

/// Impreza-class DPI fingerprints WireGuard's first 4 bytes (type 1..=4)
/// and kills the flow. XOR with a key derived from the cluster token
/// makes the UDP look like noise. Empty token = identity so unit tests
/// and a node that has not joined yet still speak raw WG.
fn cloak_key(token: &str) -> Option<[u8; 32]> {
    if token.is_empty() {
        return None;
    }
    let mut h = Sha256::new();
    h.update(b"wg-obfs-v1|");
    h.update(token.as_bytes());
    Some(h.finalize().into())
}

fn xor_keystream(buf: &mut [u8], key: &[u8; 32]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= key[i & 31];
    }
}

fn cloak(dgram: &[u8], token: &str) -> Vec<u8> {
    let mut out = dgram.to_vec();
    if let Some(key) = cloak_key(token) {
        xor_keystream(&mut out, &key);
    }
    out
}

fn uncloak(dgram: &[u8], token: &str) -> Vec<u8> {
    cloak(dgram, token)
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
    // RFC 4193: fd00::/8 is fc00::/7 with the L bit already 1. The next
    // 40 bits are the Global ID. This mask does NOT set L — the high
    // byte is forced to 0xfd below. It clears two bits of the Global
    // ID (and sets one). Kept as-is: changing it would move every
    // existing host's /48 and break its peers.
    s[0] &= 0x3f;
    s[0] |= 0x40;
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
    prefix_key(addr) == prefix_key(prefix)
}

/// First 48 bits, the route key for a peer prefix and every address under it.
fn prefix_key(addr: Ipv6Addr) -> [u16; 3] {
    let s = addr.segments();
    [s[0], s[1], s[2]]
}

/// pod name → mesh address.
type NameMap = std::collections::BTreeMap<String, Ipv6Addr>;

/// One announced pod. `seen` is refreshed by every chunk that names it.
struct RemotePod {
    addr: Ipv6Addr,
    seen: Instant,
}

type RemoteReg = HashMap<String, RemotePod>;

struct SrcTokens {
    tokens: u8,
    updated: Instant,
}

/// Token bucket per unknown WireGuard source, plus the rotating cursor
/// for the bounded handshake scan.
#[derive(Default)]
struct HandshakeGate {
    sources: HashMap<SocketAddr, SrcTokens>,
    cursor: usize,
}

impl HandshakeGate {
    /// One handshake attempt. A new source starts with
    /// [`UNKNOWN_HANDSHAKES_PER_SEC`] tokens; they refill at that rate.
    fn allow(&mut self, src: SocketAddr, now: Instant) -> bool {
        if !self.sources.contains_key(&src) && self.sources.len() >= HANDSHAKE_SOURCE_CAP {
            if let Some(old) = self.sources.keys().next().copied() {
                self.sources.remove(&old);
            }
        }
        let entry = self.sources.entry(src).or_insert(SrcTokens {
            tokens: UNKNOWN_HANDSHAKES_PER_SEC,
            updated: now,
        });
        let per = Duration::from_millis(1000 / u64::from(UNKNOWN_HANDSHAKES_PER_SEC));
        let elapsed = now.saturating_duration_since(entry.updated);
        let steps = elapsed.as_millis() / per.as_millis();
        if steps > 0 {
            let credit = steps.min(u128::from(UNKNOWN_HANDSHAKES_PER_SEC));
            entry.tokens = entry
                .tokens
                .saturating_add(credit as u8)
                .min(UNKNOWN_HANDSHAKES_PER_SEC);
            let remainder = Duration::from_millis((elapsed.as_millis() % per.as_millis()) as u64);
            entry.updated = now.checked_sub(remainder).unwrap_or(now);
        }
        if entry.tokens == 0 {
            return false;
        }
        entry.tokens -= 1;
        true
    }

    /// Index of the first peer to try. Advances by the scan budget so the
    /// next unknown datagram continues where this one stopped.
    fn scan_start(&mut self, len: usize) -> usize {
        if len == 0 {
            return 0;
        }
        let start = self.cursor % len;
        self.cursor = self.cursor.wrapping_add(HANDSHAKE_SCAN_BUDGET);
        start
    }
}

/// Per-peer WG session + its announced endpoint.
struct Peer {
    tunn: Tunn,
    endpoint: SocketAddr,
    pubkey_b64: String,
    prefix: Ipv6Addr,
}

/// Sessions keyed by WG pubkey, plus a /48 index so outbound routing
/// does not scan every peer.
#[derive(Default)]
struct PeerSet {
    by_key: HashMap<[u8; 32], Peer>,
    by_prefix: HashMap<[u16; 3], [u8; 32]>,
}

impl PeerSet {
    fn len(&self) -> usize {
        self.by_key.len()
    }

    fn insert(&mut self, pk: [u8; 32], peer: Peer) -> Option<Peer> {
        let route = prefix_key(peer.prefix);
        let old = self.by_key.insert(pk, peer);
        if let Some(prev) = &old {
            let prev_route = prefix_key(prev.prefix);
            if prev_route != route {
                self.by_prefix.remove(&prev_route);
            }
        }
        self.by_prefix.insert(route, pk);
        old
    }

    fn remove(&mut self, pk: &[u8; 32]) -> Option<Peer> {
        let old = self.by_key.remove(pk)?;
        let route = prefix_key(old.prefix);
        if self.by_prefix.get(&route) == Some(pk) {
            self.by_prefix.remove(&route);
        }
        Some(old)
    }

    fn get_mut(&mut self, pk: &[u8; 32]) -> Option<&mut Peer> {
        self.by_key.get_mut(pk)
    }

    fn contains_key(&self, pk: &[u8; 32]) -> bool {
        self.by_key.contains_key(pk)
    }

    fn keys(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.by_key.keys()
    }

    fn values(&self) -> impl Iterator<Item = &Peer> {
        self.by_key.values()
    }

    fn values_mut(&mut self) -> impl Iterator<Item = &mut Peer> {
        self.by_key.values_mut()
    }

    /// The peer that owns `dst`'s /48.
    fn by_dst(&mut self, dst: Ipv6Addr) -> Option<&mut Peer> {
        let pk = *self.by_prefix.get(&prefix_key(dst))?;
        self.by_key.get_mut(&pk)
    }

    /// True when `src` is exactly `fd<peer>::1` for a live session.
    fn is_daemon_source(&self, src: Ipv6Addr) -> bool {
        let Some(pk) = self.by_prefix.get(&prefix_key(src)) else {
            return false;
        };
        self.by_key
            .get(pk)
            .is_some_and(|p| host_addr(p.prefix) == src)
    }
}

/// Owned pump output. Copied out of the reusable encapsulate buffer so
/// the peer lock can drop before the socket or TUN write.
enum Outbound {
    Udp(Vec<u8>, SocketAddr),
    Tun(Vec<u8>),
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
    /// Current and previous cluster tokens. A std lock so the mesh-RPC
    /// interceptor can compare both without awaiting `conf`.
    cluster_tokens: std::sync::RwLock<(String, String)>,
    peers: Mutex<PeerSet>,
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
    /// TUN writes dropped because the device returned EAGAIN.
    pub tun_drops: std::sync::atomic::AtomicU64,
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
    /// peer /48 → pod name → addr and last refresh. A chunk refreshes
    /// only the names it carries; the rest keep their own timestamps and
    /// drop out after NAME_TTL.
    remote_names: Mutex<HashMap<Ipv6Addr, RemoteReg>>,
    /// Per-source handshake tokens and the rotating scan cursor. Checked
    /// before `peers` is locked.
    handshake: std::sync::Mutex<HandshakeGate>,
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
    // SAFETY: req is a valid IfReq we own, and TUNSETIFF writes the
    // kernel's interface name back into req.name. It must be &mut —
    // a shared reference would be UB once the kernel stores through it.
    if unsafe { libc::ioctl(f.as_raw_fd(), TUNSETIFF, &mut req) } < 0 {
        return Err(std::io::Error::last_os_error()).context("TUNSETIFF rp-mesh0");
    }
    Ok(f)
}

impl Mesh {
    /// Bring the mesh up on the standard `rp-mesh0` device.
    pub async fn start(data_dir: &Path, conf: MeshConf) -> Result<Arc<Mesh>> {
        Self::start_as(data_dir, conf, crate::ha::Role::Host).await
    }

    /// Same as [`start`](Self::start). A witness with an empty `mesh-pki`
    /// refuses to come up, so it cannot mint a CA.
    pub async fn start_as(
        data_dir: &Path,
        conf: MeshConf,
        role: crate::ha::Role,
    ) -> Result<Arc<Mesh>> {
        if role == crate::ha::Role::Witness {
            crate::meshca::reject_witness_mint(data_dir)?;
        }
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
        // Identity for anything that crosses the NIC. Local UDS auth is
        // unchanged. A failure here refuses to bring the tunnel up.
        crate::meshca::ensure(data_dir, &pubkey, host_addr(prefix)).context("mesh identity CA")?;
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

        let mut peers = PeerSet::default();
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
        let token_pair = (conf.cluster_token.clone(), conf.cluster_token_prev.clone());
        let mesh = Arc::new(Mesh {
            prefix,
            pubkey,
            port,
            data_dir: data_dir.to_path_buf(),
            conf: Mutex::new(conf),
            cluster_tokens: std::sync::RwLock::new(token_pair),
            peers: Mutex::new(peers),
            endpoints: Mutex::new(endpoints),
            tun: AsyncFd::new(tun)?,
            udp,
            tun_name: tun_name.to_string(),
            pump_ticks: Default::default(),
            udp_pkts: Default::default(),
            tun_pkts: Default::default(),
            tun_drops: Default::default(),
            pump_where: Default::default(),
            shutdown_tx,
            supervisor: Mutex::new(None),
            host_addr: host,
            dns,
            dns_tcp,
            gossip,
            local_names: Mutex::new(Default::default()),
            remote_names: Mutex::new(Default::default()),
            handshake: std::sync::Mutex::new(HandshakeGate::default()),
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
        // Each runs under a supervisor (a panic would otherwise die on
        // a dropped JoinHandle and take DNS or gossip down for good).
        // shutdown() awaits these handles; the inner tasks exit when
        // the watch channel flips.
        let mut tasks = mesh.tasks.lock().await;
        tasks.push(supervise_loop(
            "gossip",
            mesh.shutdown_tx.subscribe(),
            Duration::from_secs(1),
            {
                let m = mesh.clone();
                move || tokio::spawn(m.clone().gossip_rx())
            },
        ));
        tasks.push(supervise_loop(
            "announcer",
            mesh.shutdown_tx.subscribe(),
            Duration::from_secs(1),
            {
                let m = mesh.clone();
                move || tokio::spawn(m.clone().announcer())
            },
        ));
        tasks.push(supervise_loop(
            "dns",
            mesh.shutdown_tx.subscribe(),
            Duration::from_secs(1),
            {
                let m = mesh.clone();
                move || tokio::spawn(m.clone().dns_server())
            },
        ));
        tasks.push(supervise_loop(
            "dns-tcp",
            mesh.shutdown_tx.subscribe(),
            Duration::from_secs(1),
            {
                let m = mesh.clone();
                move || tokio::spawn(m.clone().dns_tcp_server())
            },
        ));
        drop(tasks);
        Ok(mesh)
    }

    /// Cluster-admin credential used by mesh-RPC and authenticated gossip.
    pub async fn cluster_token(&self) -> String {
        self.conf.lock().await.cluster_token.clone()
    }

    /// Current token, then the grace token. Cheap clone for the interceptor.
    pub fn cluster_tokens(&self) -> (String, String) {
        self.cluster_tokens
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn wg_token(&self) -> String {
        self.cluster_tokens().0
    }

    async fn udp_send(&self, dgram: &[u8], endpoint: SocketAddr) -> std::io::Result<usize> {
        let wire = cloak(dgram, &self.wg_token());
        self.udp.send_to(&wire, endpoint).await
    }

    fn store_tokens(&self, conf: &MeshConf) {
        let mut guard = self
            .cluster_tokens
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *guard = (conf.cluster_token.clone(), conf.cluster_token_prev.clone());
    }

    /// Move the current token into the grace slot and install `next`.
    /// An empty `next` mints a new token. Passing the current token is a
    /// no-op so a retry does not demote it into the grace slot.
    pub async fn rotate_cluster_token(&self, next: &str) -> Result<String> {
        let next = next.trim();
        let mut conf = self.conf.lock().await;
        if !next.is_empty() && next == conf.cluster_token {
            self.store_tokens(&conf);
            return Ok(conf.cluster_token.clone());
        }
        let mut updated = conf.clone();
        updated.cluster_token_prev = std::mem::take(&mut updated.cluster_token);
        updated.cluster_token = if next.is_empty() {
            let mut raw = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut raw);
            raw.iter().map(|b| format!("{b:02x}")).collect()
        } else {
            next.to_string()
        };
        crate::state::save_mesh(&self.data_dir, &updated)?;
        self.store_tokens(&updated);
        let token = updated.cluster_token.clone();
        *conf = updated;
        Ok(token)
    }

    /// Drop the grace token. Mesh-RPC and gossip then accept only the
    /// current token.
    pub async fn retire_cluster_token(&self) -> Result<()> {
        let mut conf = self.conf.lock().await;
        if conf.cluster_token_prev.is_empty() {
            return Ok(());
        }
        let mut updated = conf.clone();
        updated.cluster_token_prev.clear();
        crate::state::save_mesh(&self.data_dir, &updated)?;
        self.store_tokens(&updated);
        *conf = updated;
        Ok(())
    }

    /// Older mesh.conf files have no token. Mint and persist one exactly once
    /// when the cluster-plane listener first starts.
    pub async fn ensure_cluster_token(&self) -> Result<String> {
        let mut conf = self.conf.lock().await;
        if conf.cluster_token.is_empty() {
            let mut raw = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut raw);
            conf.cluster_token = raw.iter().map(|b| format!("{b:02x}")).collect();
            crate::state::save_mesh(&self.data_dir, &conf)?;
        }
        self.store_tokens(&conf);
        Ok(conf.cluster_token.clone())
    }

    /// Resolve an operator selector to a peer daemon's fd…::1 address.
    /// Accepted forms: alias, pubkey, /48 prefix, or host address.
    pub async fn resolve_peer(&self, selector: &str) -> Option<(String, Ipv6Addr)> {
        let selector = selector.trim().trim_matches(['[', ']']);
        let conf = self.conf.lock().await;
        let mut found = None;
        for peer in &conf.peers {
            let prefix = prefix_of(&peer.pubkey).ok()?;
            let addr = host_addr(prefix);
            let prefix_text = format!("{prefix}/48");
            let name = peer.name.as_deref().unwrap_or_default();
            if name == selector
                || peer.pubkey == selector
                || prefix.to_string() == selector
                || prefix_text == selector
                || addr.to_string() == selector
            {
                if found.is_some() {
                    return None;
                }
                let display = if name.is_empty() {
                    addr.to_string()
                } else {
                    name.to_string()
                };
                found = Some((display, addr));
            }
        }
        found
    }

    /// WireGuard public key of the peer whose host address is `host`.
    pub async fn pubkey_for_host(&self, host: std::net::Ipv6Addr) -> Option<String> {
        let conf = self.conf.lock().await;
        conf.peers.iter().find_map(|peer| {
            let prefix = prefix_of(&peer.pubkey).ok()?;
            (host_addr(prefix) == host).then(|| peer.pubkey.clone())
        })
    }

    /// Add/replace a peer live: session, endpoint map, route, conf.
    pub async fn add_peer(
        &self,
        endpoint: &str,
        pubkey_b64: &str,
        name: Option<&str>,
        is_witness: bool,
    ) -> Result<()> {
        let pk = parse_pubkey(pubkey_b64)?;
        let _ep: SocketAddr = canon_ep(
            endpoint
                .parse()
                .with_context(|| format!("invalid endpoint '{endpoint}' — want ip:port"))?,
        );
        let priv_b64 = { self.conf.lock().await.private_key.clone() };
        let priv_bytes: [u8; 32] = WG_B64
            .decode(priv_b64.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("mesh private key must decode to 32 bytes"))?;
        let secret = StaticSecret::from(priv_bytes);
        let name = name
            .map(rustypods_proto::validate_name)
            .transpose()
            .context("invalid peer name")?
            .map(str::to_string);
        let pc = MeshPeerConf {
            endpoint: endpoint.to_string(),
            pubkey: pubkey_b64.to_string(),
            name,
            is_witness,
        };
        if let Some(name) = pc.name.as_deref() {
            let conf = self.conf.lock().await;
            if conf
                .peers
                .iter()
                .any(|p| p.pubkey != pubkey_b64 && p.name.as_deref() == Some(name))
            {
                anyhow::bail!("mesh peer name '{name}' is already in use");
            }
        }
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

    /// Host addresses of peers registered with `is_witness`. A workload
    /// must never be placed on one of these.
    pub async fn witness_ids(&self) -> std::collections::BTreeSet<String> {
        let conf = self.conf.lock().await;
        conf.peers
            .iter()
            .filter(|p| p.is_witness)
            .filter_map(|p| {
                let prefix = prefix_of(&p.pubkey).ok()?;
                Some(host_addr(prefix).to_string())
            })
            .collect()
    }

    /// `fd<peer>::1` for every live session. The nft guard accepts only
    /// these sources; duplicates collapse so the set stays stable.
    pub(crate) async fn peer_host_addrs(&self) -> Vec<Ipv6Addr> {
        let peers = self.peers.lock().await;
        let mut addrs: Vec<Ipv6Addr> = peers.values().map(|p| host_addr(p.prefix)).collect();
        addrs.sort();
        addrs.dedup();
        addrs
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
        let pending = {
            let mut peers = self.peers.lock().await;
            let Some(p) = peers.get_mut(&pk) else {
                return;
            };
            match p.tunn.format_handshake_initiation(&mut buf, false) {
                TunnResult::WriteToNetwork(d) => Some((d.to_vec(), p.endpoint)),
                _ => None,
            }
        };
            if let Some((dgram, endpoint)) = pending {
            let _ = self.udp_send(&dgram, endpoint).await;
        }
    }

    /// Snapshot for `mesh status` / REST.
    pub async fn status(&self) -> rustypods_proto::rpc::MeshStatus {
        let conf = self.conf.lock().await.clone();
        let aliases: HashMap<&str, &str> = conf
            .peers
            .iter()
            .filter_map(|p| p.name.as_deref().map(|name| (p.pubkey.as_str(), name)))
            .collect();
        let witnesses: std::collections::HashSet<&str> = conf
            .peers
            .iter()
            .filter(|p| p.is_witness)
            .map(|p| p.pubkey.as_str())
            .collect();
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
                    name: aliases
                        .get(p.pubkey_b64.as_str())
                        .copied()
                        .unwrap_or_default()
                        .to_string(),
                    grpc_addr: host_addr(p.prefix).to_string(),
                    is_witness: witnesses.contains(p.pubkey_b64.as_str()),
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
            tun_drops: self.tun_drops.load(std::sync::atomic::Ordering::Relaxed),
            names: self.names().await.into_iter().collect(),
            conf_error: String::new(),
            // Never put the join token on the status wire. `mesh status`,
            // the GUI and /metrics all share this message.
            cluster_token: String::new(),
            grpc_addr: self.host_addr.to_string(),
            // The caller (GetMeshStatus) fills this from the raft lock —
            // Mesh has no reference to the Raft node.
            raft: None,
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
                        // SAFETY: tun_buf is a live Vec we exclusively
                        // borrow for this read; the fd is the TUN we opened.
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
                        let plain = uncloak(&udp_buf[..n], &self.wg_token());
                        self.handle_udp(&plain, src, &mut out).await;
                    }
                }
            }
        }
    }

    async fn tun_write(&self, pkt: &[u8]) {
        // SAFETY: pkt is a valid slice for this write; the fd is the
        // nonblocking TUN opened above. A short write or EAGAIN drops
        // the packet — the TUN queue is best-effort.
        let n = unsafe {
            libc::write(
                self.tun.get_ref().as_raw_fd(),
                pkt.as_ptr() as *const _,
                pkt.len(),
            )
        };
        if n < 0 {
            note_tun_io_err(&std::io::Error::last_os_error(), &self.tun_drops);
        }
    }

    /// TUN → wire: the /48 index names the peer, encapsulate, then send
    /// after the peer lock is released. Holding that lock across
    /// `send_to` stalls handshake handling for every other peer.
    async fn route_out(&self, pkt: &[u8], out: &mut [u8]) {
        let Some(IpAddr::V6(dst)) = Tunn::dst_address(pkt) else {
            return; // v4 has no place on the mesh — pods speak ULA v6
        };
        if in_prefix(self.prefix, dst) {
            return; // local space never re-enters the tunnel
        }
        let pending = {
            let mut peers = self.peers.lock().await;
            let Some(p) = peers.by_dst(dst) else {
                tracing::trace!("mesh: no peer route for {dst}");
                return;
            };
            match p.tunn.encapsulate(pkt, out) {
                TunnResult::WriteToNetwork(dgram) => Some((dgram.to_vec(), p.endpoint)),
                TunnResult::Err(e) => {
                    tracing::debug!("mesh encapsulate: {e:?}");
                    None
                }
                _ => None,
            }
        };
        if let Some((dgram, endpoint)) = pending {
            if let Err(e) = self.udp_send(&dgram, endpoint).await {
                tracing::debug!("mesh udp send {endpoint}: {e}");
            }
        }
    }

    fn allow_unknown_handshake(&self, src: SocketAddr) -> bool {
        let mut gate = self.handshake.lock().unwrap_or_else(|err| err.into_inner());
        gate.allow(src, Instant::now())
    }

    fn handshake_scan_start(&self, len: usize) -> usize {
        let mut gate = self.handshake.lock().unwrap_or_else(|err| err.into_inner());
        gate.scan_start(len)
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
        // Unknown sources spend a handshake token before the peer lock.
        // A flood of junk never reaches Curve25519.
        if key.is_none() && !self.allow_unknown_handshake(src) {
            tracing::debug!("mesh: handshake budget exceeded for {src}");
            return;
        }
        let mut outbound = Vec::new();
        let mut peers = self.peers.lock().await;
        // Resolve which peer this datagram belongs to: known endpoint
        // first; unknown sources try a bounded window of sessions — only
        // the right key will verify. On success we (re)bind the endpoint
        // (roaming). The window rotates so a later packet tries the peers
        // this one skipped.
        let pk = match key {
            Some(k) if peers.contains_key(&k) => Some(k),
            _ => {
                let mut found = None;
                let keys: Vec<[u8; 32]> = peers.keys().copied().collect();
                let start = self.handshake_scan_start(keys.len());
                let mut tried = 0usize;
                for offset in 0..keys.len() {
                    if tried >= HANDSHAKE_SCAN_BUDGET {
                        break;
                    }
                    let k = keys[(start + offset) % keys.len()];
                    let Some(p) = peers.get_mut(&k) else { continue };
                    tried += 1;
                    match p.tunn.decapsulate(Some(src.ip()), dgram, out) {
                        TunnResult::Err(_) => continue,
                        r => {
                            if let Some(item) = self.classify(r, src) {
                                outbound.push(item);
                            }
                            found = Some(k);
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
        let Some(pk) = pk else {
            drop(peers);
            self.flush(&outbound).await;
            return;
        };
        // We already consumed the datagram in the fallback branch; for
        // the known-endpoint path decapsulate it now.
        if key.is_some() {
            let Some(p) = peers.get_mut(&pk) else {
                drop(peers);
                self.flush(&outbound).await;
                return;
            };
            let r = p.tunn.decapsulate(Some(src.ip()), dgram, out);
            if let Some(item) = self.classify(r, src) {
                outbound.push(item);
            }
        }
        // Drain queued protocol messages until Done (boringtun contract).
        if let Some(p) = peers.get_mut(&pk) {
            loop {
                match p.tunn.decapsulate(None, &[], out) {
                    TunnResult::Done => break,
                    r => {
                        if let Some(item) = self.classify(r, src) {
                            outbound.push(item);
                        }
                    }
                }
            }
        }
        drop(peers);
        self.flush(&outbound).await;
    }

    /// Copy one TunnResult out of the reusable `out` buffer. The peer
    /// lock is still held here; the socket write happens in [`flush`].
    fn classify(&self, r: TunnResult<'_>, src: SocketAddr) -> Option<Outbound> {
        match r {
            TunnResult::WriteToNetwork(d) => Some(Outbound::Udp(d.to_vec(), src)),
            TunnResult::WriteToTunnelV6(pkt, _src_addr) => {
                if let Some(IpAddr::V6(dst)) = Tunn::dst_address(pkt) {
                    if in_prefix(self.prefix, dst) {
                        Some(Outbound::Tun(pkt.to_vec()))
                    } else {
                        tracing::warn!("mesh: dropping injected packet for foreign dst {dst}");
                        None
                    }
                } else {
                    None
                }
            }
            TunnResult::WriteToTunnelV4(_, _) => None, // v6-only mesh
            TunnResult::Err(e) => {
                tracing::debug!("mesh decapsulate: {e:?}");
                None
            }
            TunnResult::Done => None,
        }
    }

    async fn flush(&self, items: &[Outbound]) {
        for item in items {
            match item {
                Outbound::Udp(dgram, dst) => {
                    let _ = self.udp_send(dgram, *dst).await;
                }
                Outbound::Tun(pkt) => self.tun_write(pkt).await,
            }
        }
    }

    /// Per-second timer pass — drives rekey, keepalive and handshake
    /// retransmits for every peer.
    async fn update_timers(&self, out: &mut [u8]) {
        let pending = {
            let mut peers = self.peers.lock().await;
            let mut batch = Vec::new();
            for p in peers.values_mut() {
                if let TunnResult::WriteToNetwork(d) = p.tunn.update_timers(out) {
                    batch.push((d.to_vec(), p.endpoint));
                }
            }
            batch
        };
        for (dgram, endpoint) in pending {
            let _ = self.udp_send(&dgram, endpoint).await;
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
        let now = Instant::now();
        let r = self.remote_names.lock().await;
        r.iter()
            .filter_map(|(p, reg)| {
                let pod = reg.get(name)?;
                (now.saturating_duration_since(pod.seen) < NAME_TTL).then_some((*p, pod.addr))
            })
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
        let now = Instant::now();
        let remote = self.remote_names.lock().await;
        let mut remotes: Vec<_> = remote.iter().map(|(p, v)| (*p, v)).collect();
        remotes.sort_by_key(|(p, _)| *p);
        for (_, reg) in remotes {
            for (n, pod) in reg {
                if now.saturating_duration_since(pod.seen) < NAME_TTL {
                    out.entry(n.clone()).or_insert_with(|| pod.addr.to_string());
                }
            }
        }
        out
    }

    /// Push the local registry to every peer as HMAC-signed chunks of at
    /// most [`GOSSIP_MAX_FRAME`] bytes. Each chunk is a subset. A name
    /// that stops being announced expires on its own TTL, so a lost
    /// chunk does not wipe the names that did arrive. The cluster token
    /// is cloned before the peer lock, and destinations are snapshotted
    /// before the sends.
    async fn send_announces(&self) {
        let names = self.local_names.lock().await.clone();
        let token = self.cluster_token().await;
        let frames = gossip_chunks(&token, &names);
        if frames.is_empty() {
            return;
        }
        let dsts: Vec<SocketAddr> = {
            let peers = self.peers.lock().await;
            peers
                .values()
                .map(|p| SocketAddr::new(IpAddr::V6(host_addr(p.prefix)), GOSSIP_PORT))
                .collect()
        };
        for dst in dsts {
            for frame in &frames {
                if let Err(e) = self.gossip.send_to(frame, dst).await {
                    tracing::debug!("mesh gossip → {dst}: {e}");
                }
            }
        }
    }

    /// Receive peers' registries. Tunnel decapsulation and an exact
    /// `fd<peer>::1` source are not enough: a pod inside that peer's
    /// /48 can forge the source. The HMAC (cluster token) binds the
    /// payload to the cluster. A missing or wrong tag is dropped
    /// before the registry JSON is parsed.
    async fn gossip_rx(self: Arc<Self>) {
        // One byte past the cap so a truncated oversized datagram is
        // distinguishable from a frame that fits.
        let mut buf = vec![0u8; GOSSIP_MAX_FRAME + 1];
        let mut shutdown = self.shutdown_tx.subscribe();
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                r = self.gossip.recv_from(&mut buf) => {
                    let Ok((n, src)) = r else { continue };
                    let IpAddr::V6(src6) = src.ip() else { continue };
                    let from_peer = {
                        let peers = self.peers.lock().await;
                        peers.is_daemon_source(src6)
                    };
                    if !from_peer {
                        tracing::debug!("mesh gossip: dropped non-peer src {src}");
                        continue;
                    }
                    let peer_prefix = {
                        let segs = src6.segments();
                        Ipv6Addr::new(segs[0], segs[1], segs[2], 0, 0, 0, 0, 0)
                    };
                    if n > GOSSIP_MAX_FRAME {
                        tracing::debug!("mesh gossip: dropped oversized frame from {src}");
                        continue;
                    }
                    let (token, prev) = self.cluster_tokens();
                    let Some(payload) = open_signed_gossip_keys(&token, &prev, &buf[..n]) else {
                        tracing::debug!("mesh gossip: rejected frame from {src}");
                        continue;
                    };
                    match serde_json::from_str::<Ann>(&payload) {
                        Ok(a) => {
                            let names = sanitize_registry(peer_prefix, a.names);
                            let mut remote = self.remote_names.lock().await;
                            let reg = remote.entry(peer_prefix).or_default();
                            refresh_remote(reg, names, Instant::now());
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
                    {
                        let mut remote = self.remote_names.lock().await;
                        expire_remote(&mut remote, Instant::now());
                    }
                    self.send_announces().await;
                }
            }
        }
    }

    /// Pod-facing DNS on [fd<host>::1]:53. Mesh names answer locally
    /// (AAAA → addr, A → NODATA); everything else relays upstream so a
    /// pod's resolv.conf can point only at us without losing real DNS.
    /// Queries run on spawned tasks behind `DNS_UDP_INFLIGHT` so a slow
    /// upstream (dns_forward waits up to 3s) cannot stall the socket.
    async fn dns_server(self: Arc<Self>) {
        let sem = Arc::new(tokio::sync::Semaphore::new(DNS_UDP_INFLIGHT));
        let mut buf = vec![0u8; 4096];
        let mut shutdown = self.shutdown_tx.subscribe();
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                r = self.dns.recv_from(&mut buf) => {
                    let Ok((n, src)) = r else { continue };
                    let pkt = buf[..n].to_vec();
                    let Ok(permit) = sem.clone().try_acquire_owned() else {
                        tracing::debug!("mesh dns: udp inflight cap, dropping {src}");
                        continue;
                    };
                    let m = self.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Some(rep) = m.answer_query(&pkt).await {
                            let _ = m.dns.send_to(&rep, src).await;
                        }
                    });
                }
            }
        }
    }

    /// DNS-over-TCP on the same addr — RFC requires it for truncated
    /// answers and some resolvers probe TCP first. 2-byte length
    /// prefix framing per RFC 1035 §4.2.2. Connections are capped and
    /// each read is idle-bounded so a client can't pin an fd forever.
    async fn dns_tcp_server(self: Arc<Self>) {
        let sem = Arc::new(tokio::sync::Semaphore::new(DNS_TCP_MAX_CONNS));
        let mut shutdown = self.shutdown_tx.subscribe();
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                r = self.dns_tcp.accept() => {
                    let Ok((s, peer)) = r else { continue };
                    let Ok(permit) = sem.clone().try_acquire_owned() else {
                        tracing::debug!("mesh dns: tcp conn cap, dropping {peer}");
                        continue;
                    };
                    let m = self.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        dns_tcp_conn(m, s).await;
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

/// Accept a DNS-over-TCP length prefix, or None when it is empty or
/// above `DNS_TCP_MAX_MSG`.
fn dns_tcp_payload_len(n: u16) -> Option<usize> {
    let n = n as usize;
    if n == 0 || n > DNS_TCP_MAX_MSG {
        None
    } else {
        Some(n)
    }
}

/// One DNS TCP client. Returns on idle timeout, a short read, or an
/// oversize length prefix — the connection is then dropped.
async fn dns_tcp_conn(m: Arc<Mesh>, mut s: tokio::net::TcpStream) {
    let mut len = [0u8; 2];
    loop {
        if tokio::time::timeout(DNS_TCP_IDLE, s.read_exact(&mut len))
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_none()
        {
            return;
        }
        let Some(n) = dns_tcp_payload_len(u16::from_be_bytes(len)) else {
            return;
        };
        let mut q = vec![0u8; n];
        if tokio::time::timeout(DNS_TCP_IDLE, s.read_exact(&mut q))
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_none()
        {
            return;
        }
        if let Some(rep) = m.answer_query(&q).await {
            if rep.len() > u16::MAX as usize {
                return;
            }
            let l = (rep.len() as u16).to_be_bytes();
            let write = async {
                s.write_all(&l).await?;
                s.write_all(&rep).await?;
                Ok::<(), std::io::Error>(())
            };
            if tokio::time::timeout(DNS_TCP_IDLE, write)
                .await
                .ok()
                .and_then(|r| r.ok())
                .is_none()
            {
                return;
            }
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
        pkt.get(i)?;
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
    pkt.get(..12)?;
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

/// Wire format on UDP 5305. `payload` is the registry JSON; `signature`
/// is the lowercase hex HMAC-SHA256 of that exact string.
#[derive(serde::Serialize, serde::Deserialize)]
struct SignedGossip {
    payload: String,
    signature: String,
}

/// Registry body carried inside [`SignedGossip::payload`].
#[derive(serde::Deserialize)]
struct Ann {
    names: NameMap,
}

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256(cluster_token, payload), lowercase hex. `None` when the
/// token is missing — gossip stays unsigned-never, not unsigned-ok.
fn gossip_mac(token: &str, payload: &str) -> Option<String> {
    if token.is_empty() {
        return None;
    }
    let mut mac = HmacSha256::new_from_slice(token.as_bytes()).ok()?;
    mac.update(payload.as_bytes());
    let tag = mac.finalize().into_bytes();
    Some(hex_encode(&tag))
}

/// Signed frames for `names`, each at most [`GOSSIP_MAX_FRAME`] bytes.
/// The union of the chunks is `names`. An empty map sends nothing; removed
/// pods disappear when their TTL elapses.
fn gossip_chunks(token: &str, names: &NameMap) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    let mut batch = NameMap::new();
    for (name, addr) in names {
        batch.insert(name.clone(), *addr);
        let Some(frame) = sealed_names(token, &batch) else {
            return Vec::new();
        };
        if frame.len() <= GOSSIP_MAX_FRAME {
            continue;
        }
        batch.remove(name);
        if let Some(prev) = sealed_names(token, &batch) {
            frames.push(prev);
        }
        batch.clear();
        batch.insert(name.clone(), *addr);
        match sealed_names(token, &batch) {
            Some(one) if one.len() <= GOSSIP_MAX_FRAME => {}
            _ => batch.clear(),
        }
    }
    if let Some(frame) = sealed_names(token, &batch) {
        if frame.len() <= GOSSIP_MAX_FRAME {
            frames.push(frame);
        }
    }
    frames
}

fn sealed_names(token: &str, names: &NameMap) -> Option<Vec<u8>> {
    if names.is_empty() {
        return None;
    }
    let payload = serde_json::json!({ "names": names }).to_string();
    seal_gossip(token, &payload)
}

/// Refresh the names a chunk carried. Names absent from this chunk keep
/// the timestamp of the chunk that last mentioned them.
fn refresh_remote(reg: &mut RemoteReg, names: NameMap, now: Instant) {
    for (name, addr) in names {
        reg.insert(name, RemotePod { addr, seen: now });
    }
}

/// Drop pods that have not been refreshed within [`NAME_TTL`].
fn expire_remote(regs: &mut HashMap<Ipv6Addr, RemoteReg>, now: Instant) {
    for reg in regs.values_mut() {
        reg.retain(|_, pod| now.saturating_duration_since(pod.seen) < NAME_TTL);
    }
    regs.retain(|_, reg| !reg.is_empty());
}

/// Wrap `payload` in a [`SignedGossip`] frame. Fails closed without a token.
fn seal_gossip(token: &str, payload: &str) -> Option<Vec<u8>> {
    let signature = gossip_mac(token, payload)?;
    serde_json::to_vec(&SignedGossip {
        payload: payload.to_string(),
        signature,
    })
    .ok()
}

#[cfg(test)]
fn open_signed_gossip(token: &str, frame: &[u8]) -> Option<String> {
    open_signed_gossip_keys(token, "", frame)
}

/// Split a frame and check the tag against the current token and, when
/// set, the grace token. Both tags are verified. The payload string is
/// returned only after a tag matches — callers parse the registry JSON
/// from that string, never from the raw datagram.
fn open_signed_gossip_keys(current: &str, previous: &str, frame: &[u8]) -> Option<String> {
    if current.is_empty() && previous.is_empty() {
        return None;
    }
    let frame: SignedGossip = serde_json::from_slice(frame).ok()?;
    let sig = hex_decode_32(&frame.signature)?;
    let ok_cur = gossip_tag_ok(current, frame.payload.as_bytes(), &sig);
    let ok_prev = gossip_tag_ok(previous, frame.payload.as_bytes(), &sig);
    if ok_cur || ok_prev {
        Some(frame.payload)
    } else {
        None
    }
}

/// HMAC-SHA256 verify. An empty token still runs the MAC against a
/// stand-in key and then rejects, so a missing grace token does not
/// skip the second check.
fn gossip_tag_ok(token: &str, payload: &[u8], sig: &[u8]) -> bool {
    let key: &[u8] = if token.is_empty() {
        b"\0"
    } else {
        token.as_bytes()
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(payload);
    mac.verify_slice(sig).is_ok() && !token.is_empty()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Exactly 32 bytes of lowercase hex. Anything else is a bad tag.
fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let raw = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_val(raw[i * 2])?;
        let lo = hex_val(raw[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
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

/// Count a failed TUN write. EAGAIN/EWOULDBLOCK is expected on a
/// nonblocking device and is surfaced via `MeshStatus.tun_drops`;
/// the log is power-of-two so a full queue doesn't flood the journal.
fn note_tun_io_err(err: &std::io::Error, drops: &std::sync::atomic::AtomicU64) {
    if err.kind() == std::io::ErrorKind::WouldBlock {
        let n = drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if n == 1 || n.is_power_of_two() {
            tracing::warn!("mesh tun write EAGAIN, dropped {n} packet(s)");
        }
    } else {
        tracing::debug!("mesh tun write: {err}");
    }
}

/// Restart `spawn` until it returns normally or `shutdown` is set.
/// A panic sleeps `backoff` (doubled each time, capped at 30s) and
/// tries again — the same idea as the pump supervisor, so a DNS or
/// gossip panic does not stay dead until the daemon restarts.
fn supervise_loop(
    name: &'static str,
    shutdown: watch::Receiver<bool>,
    mut backoff: Duration,
    spawn: impl Fn() -> tokio::task::JoinHandle<()> + Send + Sync + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if *shutdown.borrow() {
                break;
            }
            match spawn().await {
                Ok(()) => break,
                Err(e) => {
                    tracing::error!("mesh {name} panicked: {e}; restarting in {backoff:?}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    })
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
    );
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
    fn cloak_hides_the_wg_type_byte_and_round_trips() {
        let wg = [1u8, 0, 0, 0, 0x11, 0x22, 0x33];
        let token = "cluster-secret";
        let wire = cloak(&wg, token);
        assert_ne!(wire[0], 1, "DPI fingerprints WireGuard type=1");
        assert_eq!(uncloak(&wire, token), wg);
        assert_eq!(cloak(&wg, ""), wg);
    }

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

    #[test]
    fn route_index_resolves_a_prefix_and_drops_it_on_remove() {
        let (priv_b64, _) = keygen();
        let raw: [u8; 32] = WG_B64.decode(priv_b64).unwrap().try_into().unwrap();
        let secret = StaticSecret::from(raw);
        let (_, pub_a) = keygen();
        let (_, pub_b) = keygen();
        let a = MeshPeerConf {
            endpoint: "192.0.2.1:51820".into(),
            pubkey: pub_a,
            name: None,
            is_witness: false,
        };
        let b = MeshPeerConf {
            endpoint: "192.0.2.2:51820".into(),
            pubkey: pub_b,
            name: None,
            is_witness: false,
        };
        let (peer_a, _) = build_peer(&secret, &a, 0).unwrap();
        let (peer_b, _) = build_peer(&secret, &b, 1).unwrap();
        let prefix_a = peer_a.prefix;
        let mut set = PeerSet::default();
        let key_a = parse_pubkey(&a.pubkey).unwrap();
        set.insert(key_a, peer_a);
        set.insert(parse_pubkey(&b.pubkey).unwrap(), peer_b);
        let dst = mesh_ip(prefix_a, 9);
        assert_eq!(set.by_dst(dst).unwrap().pubkey_b64, a.pubkey);
        assert!(set.is_daemon_source(host_addr(prefix_a)));
        assert!(!set.is_daemon_source(dst));
        set.remove(&key_a);
        assert!(set.by_dst(dst).is_none());
        assert!(!set.is_daemon_source(host_addr(prefix_a)));
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

    #[test]
    fn ensure_identity_is_stable() {
        let dir = std::env::temp_dir().join(format!(
            "rp-ident-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let first = ensure_identity(&dir).unwrap();
        let second = ensure_identity(&dir).unwrap();
        assert_eq!(first, second);
        assert!(!first.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn listen_port_rejects_overflow() {
        assert_eq!(checked_listen_port(0).unwrap(), None);
        assert_eq!(checked_listen_port(51820).unwrap(), Some(51820));
        assert_eq!(checked_listen_port(65535).unwrap(), Some(65535));
        assert!(checked_listen_port(70000).is_err());
        assert!(checked_listen_port(u32::MAX).is_err());
    }

    #[test]
    fn tun_eagain_is_counted() {
        let drops = std::sync::atomic::AtomicU64::new(0);
        let err = std::io::Error::from_raw_os_error(libc::EAGAIN);
        note_tun_io_err(&err, &drops);
        note_tun_io_err(&err, &drops);
        assert_eq!(drops.load(std::sync::atomic::Ordering::Relaxed), 2);
        let other = std::io::Error::from_raw_os_error(libc::EIO);
        note_tun_io_err(&other, &drops);
        assert_eq!(drops.load(std::sync::atomic::Ordering::Relaxed), 2);
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
    fn dns_tcp_rejects_empty_and_oversize_lengths() {
        assert_eq!(dns_tcp_payload_len(0), None);
        assert_eq!(dns_tcp_payload_len(1), Some(1));
        assert_eq!(
            dns_tcp_payload_len(DNS_TCP_MAX_MSG as u16),
            Some(DNS_TCP_MAX_MSG)
        );
        assert_eq!(
            dns_tcp_payload_len((DNS_TCP_MAX_MSG as u16).saturating_add(1)),
            None
        );
        assert_eq!(DNS_UDP_INFLIGHT, 64);
        const _: () = assert!(DNS_TCP_MAX_CONNS > 0 && DNS_TCP_MAX_CONNS <= DNS_UDP_INFLIGHT);
        assert_eq!(DNS_TCP_IDLE, Duration::from_secs(5));
    }

    /// A panicked background task is restarted; a clean return ends the
    /// supervisor. Shutdown set before the next spawn also ends it.
    #[tokio::test]
    async fn supervisor_restarts_then_stops() {
        let runs = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let runs2 = runs.clone();
        let (_tx, rx) = watch::channel(false);
        let h = supervise_loop("test", rx, Duration::from_millis(20), move || {
            let runs = runs2.clone();
            tokio::spawn(async move {
                if runs.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
                    panic!("mesh task boom");
                }
            })
        });
        tokio::time::timeout(Duration::from_secs(2), h)
            .await
            .expect("supervisor hung")
            .unwrap();
        assert_eq!(runs.load(std::sync::atomic::Ordering::Relaxed), 2);

        let (_tx2, rx2) = watch::channel(true);
        let h = supervise_loop("test-stop", rx2, Duration::from_secs(30), || {
            tokio::spawn(async { panic!("should not run") })
        });
        tokio::time::timeout(Duration::from_secs(1), h)
            .await
            .expect("shutdown did not stop supervisor")
            .unwrap();
    }

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

    #[test]
    fn gossip_frame_verifies_and_rejects_tampering() {
        let token = "cluster-token";
        let payload = serde_json::json!({ "names": { "db": "fdab:1:2:3::2" } }).to_string();
        let frame = seal_gossip(token, &payload).expect("signed frame");
        assert_eq!(
            open_signed_gossip(token, &frame).as_deref(),
            Some(payload.as_str())
        );

        // Inner registry JSON is only parsed after the tag checks out.
        let ann: Ann = serde_json::from_str(&open_signed_gossip(token, &frame).unwrap()).unwrap();
        assert!(ann.names.contains_key("db"));

        let mut tampered: SignedGossip = serde_json::from_slice(&frame).unwrap();
        tampered.payload.push(' ');
        let bad_payload = serde_json::to_vec(&tampered).unwrap();
        assert!(open_signed_gossip(token, &bad_payload).is_none());

        let mut sig = tampered.signature.into_bytes();
        sig[0] = if sig[0] == b'a' { b'b' } else { b'a' };
        tampered.payload = payload.clone();
        tampered.signature = String::from_utf8(sig).unwrap();
        let bad_sig = serde_json::to_vec(&tampered).unwrap();
        assert!(open_signed_gossip(token, &bad_sig).is_none());

        // Unsigned registry JSON never reaches the name map.
        assert!(open_signed_gossip(token, payload.as_bytes()).is_none());
        assert!(open_signed_gossip("", &frame).is_none());
        assert!(seal_gossip("", &payload).is_none());
        // During rotation the previous token still opens a frame the
        // peer sealed before it adopted the new token.
        assert_eq!(
            open_signed_gossip_keys("new-token", token, &frame).as_deref(),
            Some(payload.as_str())
        );
        assert!(open_signed_gossip_keys("new-token", "", &frame).is_none());
        assert!(open_signed_gossip_keys("new-token", "other", &frame).is_none());
    }

    #[test]
    fn gossip_chunks_fit_the_tunnel_and_cover_every_name() {
        let token = "cluster-token";
        let mut names = NameMap::new();
        for i in 0..200u16 {
            names.insert(
                format!("pod{i:04}"),
                Ipv6Addr::new(0xfdab, 0x1, 0x2, i, 0, 0, 0, 2),
            );
        }
        let frames = gossip_chunks(token, &names);
        assert!(frames.len() > 1, "200 names must span more than one MTU");
        let mut got = NameMap::new();
        for frame in &frames {
            assert!(frame.len() <= GOSSIP_MAX_FRAME, "{}", frame.len());
            let payload = open_signed_gossip(token, frame).unwrap();
            let ann: Ann = serde_json::from_str(&payload).unwrap();
            got.extend(ann.names);
        }
        assert_eq!(got, names);
        assert!(gossip_chunks("", &names).is_empty());
    }

    #[test]
    fn gossip_chunk_refreshes_without_erasing_other_names() {
        let peer = Ipv6Addr::new(0xfdab, 0x1, 0x2, 0, 0, 0, 0, 0);
        let mut regs = HashMap::new();
        let t0 = Instant::now();
        let mut first = NameMap::new();
        first.insert("db".into(), Ipv6Addr::LOCALHOST);
        refresh_remote(regs.entry(peer).or_default(), first, t0);
        let mut second = NameMap::new();
        second.insert("web".into(), Ipv6Addr::LOCALHOST);
        refresh_remote(regs.entry(peer).or_default(), second, t0);
        assert!(regs[&peer].contains_key("db"));
        assert!(regs[&peer].contains_key("web"));
        expire_remote(&mut regs, t0 + NAME_TTL);
        assert!(regs.is_empty());
    }

    #[test]
    fn unknown_handshake_budget_is_five_per_second_and_bounded() {
        let mut gate = HandshakeGate::default();
        let src: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..UNKNOWN_HANDSHAKES_PER_SEC {
            assert!(gate.allow(src, t0));
        }
        assert!(!gate.allow(src, t0));
        let later = t0 + Duration::from_millis(200);
        assert!(gate.allow(src, later));
        assert!(!gate.allow(src, later));

        let start = gate.scan_start(10);
        assert_eq!(start, 0);
        assert_eq!(gate.scan_start(10), HANDSHAKE_SCAN_BUDGET);

        for i in 0..HANDSHAKE_SOURCE_CAP + 32 {
            let addr = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(
                    203,
                    0,
                    (i / 256) as u8,
                    (i % 256) as u8,
                )),
                1,
            );
            gate.allow(addr, t0);
        }
        assert!(gate.sources.len() <= HANDSHAKE_SOURCE_CAP);
    }
}
