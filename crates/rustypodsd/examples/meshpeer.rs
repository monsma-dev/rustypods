//! meshpeer — a second mesh endpoint for single-host testing.
//!
//! Usage: `sudo ./meshpeer <data_dir> [--fake-pod]`
//!
//! `<data_dir>/conf/mesh.conf` must hold a WG private key, a distinct
//! listen_port, and the real daemon as a peer (endpoint
//! 127.0.0.1:<daemon-port>, pubkey from `rustypods mesh status`). The
//! peer brings up its own TUN (rp-mesh1) and the same BoringTun pump
//! the daemon runs — packets then traverse real kernel routes + real
//! WireGuard crypto on one machine:
//!
//!   pod → ve-* → host route fd<B>::/48 → rp-mesh0 → daemon UDP
//!     → 127.0.0.1:51821 → meshpeer → decap → rp-mesh1 → kernel route
//!     → fd<B>:1::2/128 on lo → ICMP reply → reverse path back.
//!
//! `--fake-pod` announces fd<peer>:1::2/128 on lo so the endpoint has
//! something answering pings inside its own /48.

use rustypodsd::mesh;
use rustypodsd::state;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let data_dir = std::env::args()
        .nth(1)
        .expect("usage: meshpeer <data_dir> [--fake-pod]");
    let fake_pod = std::env::args().any(|a| a == "--fake-pod");
    let tun = "rp-mesh1";
    let conf = state::load_mesh(std::path::Path::new(&data_dir))
        .expect("conf/mesh.conf failed to parse — fix or remove it, do not mint a new key")
        .expect("no conf/mesh.conf (or empty private_key) in data_dir");
    let m = mesh::Mesh::start_named(std::path::Path::new(&data_dir), conf, tun).await?;
    println!(
        "meshpeer up: pubkey={} prefix={} port={} dev={}",
        m.pubkey, m.prefix, m.port, tun
    );
    // The pubkey lands where the unprivileged test driver can read it —
    // the conf itself is (correctly) 0600 root.
    let _ = std::fs::write(format!("{data_dir}/pubkey"), &m.pubkey);
    if fake_pod {
        // In a fresh netns lo is DOWN — bring it up before addressing.
        let st = std::process::Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()?;
        anyhow::ensure!(st.success(), "ip link set lo up");
        // A "pod" on this fake host: /128 on lo answers ICMP for
        // fd<peer>:1::2. CRITICAL: `noprefixroute` — a plain /128 add
        // installs a connected route in the MAIN table that beats the
        // peer's /48-over-TUN, shortcutting packets through lo without
        // ever touching WireGuard. With noprefixroute the addr lives
        // only in the `local` table: inbound decrypted packets still
        // deliver, but outbound lookups fall through to the /48.
        let addr = mesh::mesh_ip(m.prefix, 1);
        let st = std::process::Command::new("ip")
            .args([
                "-6",
                "addr",
                "replace",
                &format!("{addr}/128"),
                "dev",
                "lo",
                "noprefixroute",
            ])
            .status()?;
        anyhow::ensure!(st.success(), "ip addr add {addr} dev lo");
        println!("fake pod: {addr} on lo");
        // Announce it in the gossip registry so the real daemon's pods
        // can resolve `fakepod` via Mesh-DNS.
        let mut names = std::collections::BTreeMap::new();
        names.insert("fakepod".to_string(), addr);
        m.set_local_names(names).await;
    }
    // Heartbeat: status snapshot every 2s where the unprivileged test
    // driver can read it — the unit's stdout goes to the root journal.
    let m2 = m.clone();
    let hb = format!("{data_dir}/status");
    tokio::spawn(async move {
        loop {
            let st = m2.status().await;
            let mut s = format!(
                "pubkey={} prefix={} listen={} pump_ticks={} udp_pkts={} tun_pkts={} pump_where={}\n",
                st.pubkey,
                st.prefix,
                st.listen,
                m2.pump_ticks.load(std::sync::atomic::Ordering::Relaxed),
                m2.udp_pkts.load(std::sync::atomic::Ordering::Relaxed),
                m2.tun_pkts.load(std::sync::atomic::Ordering::Relaxed),
                m2.pump_where.load(std::sync::atomic::Ordering::Relaxed)
            );
            for p in &st.peers {
                s.push_str(&format!(
                    "peer {} {} handshake={}s tx={} rx={}\n",
                    p.endpoint, p.prefix, p.handshake_secs_ago, p.tx_bytes, p.rx_bytes
                ));
            }
            for (n, a) in &st.names {
                s.push_str(&format!("name {n} {a}\n"));
            }
            let _ = std::fs::write(&hb, s);
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
    // Park forever — the pump task inside Mesh does the work.
    std::future::pending::<()>().await;
    Ok(())
}
