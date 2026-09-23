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
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::net;
use crate::state::{MeshConf, MeshPeerConf};

pub const TUN_NAME: &str = "rp-mesh0";
pub const DEFAULT_PORT: u16 = 51820;
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

/// Whether `addr` sits under `prefix` (/48 = first 6 bytes).
pub fn in_prefix(prefix: Ipv6Addr, addr: Ipv6Addr) -> bool {
    addr.segments()[..3] == prefix.segments()[..3]
}

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
    pub async fn start_named(
        data_dir: &Path,
        conf: MeshConf,
        tun_name: &str,
    ) -> Result<Arc<Mesh>> {
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

        let udp = UdpSocket::bind(("::", port))
            .await
            .with_context(|| format!("bind mesh udp :{port}"))?;

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
        });
        // Supervised pump: a panic inside the spawned task would
        // otherwise die silently (dropped JoinHandle) leaving Recv-Q
        // to grow while `mesh status` still looks alive.
        let sup = mesh.clone();
        tokio::spawn(async move {
            loop {
                let h = tokio::spawn(sup.clone().pump());
                match h.await {
                    Ok(()) => {
                        tracing::error!("mesh pump exited; not restarting");
                        break;
                    }
                    Err(e) => {
                        tracing::error!("mesh pump panicked: {e}; restarting");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
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
                &["-6", "route", "replace", &format!("{prefix}/48"), "dev", &tn],
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
                    IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
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
        }
    }

    /// The packet pump: TUN ↔ BoringTun ↔ UDP, plus a 1s timer pass for
    /// rekey/keepalive. Runs until the daemon dies.
    async fn pump(self: Arc<Self>) {
        let mut tun_buf = vec![0u8; 2048];
        let mut udp_buf = vec![0u8; 2048];
        let mut out = vec![0u8; 2048];
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        use std::sync::atomic::Ordering::Relaxed;
        loop {
            self.pump_ticks.fetch_add(1, Relaxed);
            self.pump_where.store(0, Relaxed);
            tokio::select! {
                _ = tick.tick() => {
                    self.pump_where.store(5, Relaxed);
                    self.update_timers(&mut out).await;
                    let _ = std::fs::write(
                        self.data_dir.join("mesh-pump.status"),
                        format!(
                            "ticks={} where={} udp={} tun={}\n",
                            self.pump_ticks.load(Relaxed),
                            self.pump_where.load(Relaxed),
                            self.udp_pkts.load(Relaxed),
                            self.tun_pkts.load(Relaxed)
                        ),
                    );
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
                    self.endpoints.lock().await.insert(src, k);
                    if let Some(p) = peers.get_mut(&k) {
                        if p.endpoint != src {
                            tracing::info!("mesh peer {} roamed → {src}", p.pubkey_b64);
                            p.endpoint = src;
                        }
                    }
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
}
