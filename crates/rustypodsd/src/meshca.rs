//! Mesh identity CA. Separate from the ingress PKI in `<data>/pki`.
//!
//! The root may sign leaves only, and only names under
//! `node.mesh.rustypods` plus Unique Local addresses (`fd00::/8`).
//! A node certificate names `sha256(wireguard pubkey)` and the host's
//! `fd<host>::1` address, with both server and client auth, and lasts
//! seven days. Renewal keeps the previous certificate acceptable until
//! `retire_previous`, the same overlap as the cluster-token grace.
//!
//! The private key in a CSR is the node's TLS key. The names on that
//! CSR are ignored: the CA stamps the WireGuard identity itself.

use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::Engine;

/// DNS zone this CA is allowed to issue. Not the ingress zone.
pub use rustypods_proto::MESH_NODE_ZONE;
const NODE_DAYS: i64 = 7;
const RENEW_WITHIN_DAYS: i64 = 1;

/// Files under `<data>/mesh-pki`. `node_prev_crt` is absent outside a
/// rotation window.
#[derive(Debug, Clone)]
pub struct MeshCa {
    pub dir: PathBuf,
    pub ca_crt: PathBuf,
    pub ca_key: PathBuf,
    pub node_crt: PathBuf,
    pub node_key: PathBuf,
    pub node_prev_crt: PathBuf,
}

impl MeshCa {
    fn at(dir: PathBuf) -> Self {
        Self {
            ca_crt: dir.join("ca.crt"),
            ca_key: dir.join("ca.key"),
            node_crt: dir.join("node.crt"),
            node_key: dir.join("node.key"),
            node_prev_crt: dir.join("node.prev.crt"),
            dir,
        }
    }

    fn required(&self) -> [&PathBuf; 4] {
        [&self.ca_crt, &self.ca_key, &self.node_crt, &self.node_key]
    }
}

/// DNS name bound to a WireGuard public key. The label is hex, so it
/// cannot carry the base64 key itself, and it stays under 63 characters.
pub fn node_dns(wg_pubkey_b64: &str) -> String {
    rustypods_proto::node_dns(wg_pubkey_b64)
}

fn ca_params() -> Result<rcgen::CertificateParams> {
    use rcgen::{BasicConstraints, CidrSubnet, DnType, IsCa, KeyUsagePurpose};
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "RustyPods Mesh CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.name_constraints = Some(rcgen::NameConstraints {
        permitted_subtrees: vec![
            rcgen::GeneralSubtree::DnsName(MESH_NODE_ZONE.into()),
            rcgen::GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)),
                8,
            )),
        ],
        excluded_subtrees: vec![],
    });
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(3650);
    Ok(params)
}

fn node_params(wg_pubkey_b64: &str, host: Ipv6Addr) -> Result<rcgen::CertificateParams> {
    use rcgen::{ExtendedKeyUsagePurpose, IsCa, SanType};
    let dns = node_dns(wg_pubkey_b64);
    if !dns.ends_with(&format!(".{MESH_NODE_ZONE}")) {
        bail!("mesh CA refuses to sign {dns}");
    }
    let mut params = rcgen::CertificateParams::new(vec![dns])?;
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V6(host)));
    params.is_ca = IsCa::ExplicitNoCa;
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(NODE_DAYS);
    Ok(params)
}

fn pem_der(pem: &str) -> Result<Vec<u8>> {
    let mut b64 = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("-----") {
            continue;
        }
        b64.push_str(line);
    }
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("mesh certificate is not valid PEM")
}

fn check_required(paths: &MeshCa) -> Result<()> {
    for path in paths.required() {
        let md =
            std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if !md.file_type().is_file() {
            bail!("{} is not a regular file", path.display());
        }
        if md.len() == 0 {
            bail!("{} is empty", path.display());
        }
    }
    // ca.key never leaves the daemon. node.key may be 0640 so the
    // operator uid can present it on `rustypods --host`; share_node_key
    // sets that mode after the listener is up, and the next boot must
    // still accept it. Group write and any other-access stay refused.
    key_not_open(&paths.ca_key, 0o077, "group/other-readable")?;
    key_not_open(&paths.node_key, 0o037, "group-writable or other-accessible")?;
    Ok(())
}

fn key_not_open(path: &Path, forbidden: u32, why: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let md = std::fs::symlink_metadata(path)?;
    if md.permissions().mode() & forbidden != 0 {
        bail!(
            "{} is {why} — fix permissions or delete and re-init",
            path.display()
        );
    }
    Ok(())
}

fn load_issuer(paths: &MeshCa) -> Result<rcgen::Issuer<'static, rcgen::KeyPair>> {
    let ca_pem = std::fs::read_to_string(&paths.ca_crt)
        .with_context(|| format!("read {}", paths.ca_crt.display()))?;
    let ca_key = std::fs::read_to_string(&paths.ca_key)
        .with_context(|| format!("read {}", paths.ca_key.display()))?;
    let key = rcgen::KeyPair::from_pem(&ca_key).context("parse mesh CA key")?;
    rcgen::Issuer::from_ca_cert_pem(&ca_pem, key).context("mesh CA issuer")
}

fn sign_node(
    issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
    key: &rcgen::KeyPair,
    wg_pubkey_b64: &str,
    host: Ipv6Addr,
) -> Result<rcgen::Certificate> {
    node_params(wg_pubkey_b64, host)?
        .signed_by(key, issuer)
        .context("sign mesh node certificate")
}

#[derive(PartialEq, Eq)]
enum Layout {
    Empty,
    Root,
    Leaf,
    Corrupt,
}

/// Root is the four-file CA. Leaf is a joiner: `ca.crt`, `node.crt`,
/// `node.key`, and no `ca.key`. Anything in between is corrupt — never
/// mint a CA over a half-written set.
fn layout(paths: &MeshCa) -> Layout {
    match (
        paths.ca_crt.exists(),
        paths.ca_key.exists(),
        paths.node_crt.exists(),
        paths.node_key.exists(),
    ) {
        (false, false, false, false) => Layout::Empty,
        (true, true, true, true) => Layout::Root,
        (true, false, true, true) => Layout::Leaf,
        _ => Layout::Corrupt,
    }
}

fn node_cert_matches(crt_pem: &str, wg_pubkey_b64: &str) -> Result<()> {
    let der = pem_der(crt_pem)?;
    let dns = node_dns(wg_pubkey_b64);
    if !der.windows(dns.len()).any(|w| w == dns.as_bytes()) {
        bail!("mesh node certificate is not for this WireGuard identity ({dns})");
    }
    Ok(())
}

fn check_files(paths: &[&PathBuf]) -> Result<()> {
    for path in paths {
        let md =
            std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if !md.file_type().is_file() {
            bail!("{} is not a regular file", path.display());
        }
        if md.len() == 0 {
            bail!("{} is empty", path.display());
        }
    }
    Ok(())
}

const STAGING: &str = ".mesh-pki.tmp";
const BACKUP: &str = ".mesh-pki.bak";

/// A crash between parking the live directory and installing the new
/// one leaves `.mesh-pki.bak` and no `mesh-pki`. Put the backup back.
/// A leftover staging directory is incomplete and is removed.
fn recover_mesh_pki(data_dir: &Path) -> Result<()> {
    let live = data_dir.join("mesh-pki");
    let bak = data_dir.join(BACKUP);
    let tmp = data_dir.join(STAGING);
    if !live.exists() && bak.exists() {
        std::fs::rename(&bak, &live)
            .with_context(|| format!("restore {} from {}", live.display(), bak.display()))?;
    } else if live.exists() && bak.exists() {
        std::fs::remove_dir_all(&bak).with_context(|| format!("remove {}", bak.display()))?;
    }
    if tmp.exists() {
        std::fs::remove_dir_all(&tmp).with_context(|| format!("remove {}", tmp.display()))?;
    }
    Ok(())
}

/// A witness with an empty `mesh-pki` must not mint a CA. A partial
/// set is left for [`ensure`] to refuse as corrupt.
pub fn reject_witness_mint(data_dir: &Path) -> Result<()> {
    recover_mesh_pki(data_dir)?;
    let paths = MeshCa::at(data_dir.join("mesh-pki"));
    if layout(&paths) == Layout::Empty {
        bail!("a witness does not mint a mesh CA — bootstrap with mesh create-csr");
    }
    Ok(())
}

/// Write a complete PKI into `.mesh-pki.tmp`, then rename it into
/// place. The previous directory is parked as `.mesh-pki.bak` and
/// removed only after the new directory is the live one. A crash
/// leaves either the original directory or no directory plus the
/// backup, which the next [`ensure`] restores.
fn install_mesh_pki(data_dir: &Path, files: &[(&str, &[u8], u32)]) -> Result<MeshCa> {
    use std::os::unix::fs::PermissionsExt;
    let live = data_dir.join("mesh-pki");
    let tmp = data_dir.join(STAGING);
    let bak = data_dir.join(BACKUP);
    if tmp.exists() {
        std::fs::remove_dir_all(&tmp).context("clear mesh-pki staging")?;
    }
    std::fs::create_dir(&tmp).context("create mesh-pki staging")?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700))
        .context("mode mesh-pki staging")?;
    for (name, bytes, mode) in files {
        crate::pki::atomic_write(&tmp.join(name), bytes, *mode)?;
    }
    if bak.exists() {
        std::fs::remove_dir_all(&bak).context("clear mesh-pki backup")?;
    }
    let had_live = live.exists();
    if had_live {
        std::fs::rename(&live, &bak).context("park mesh-pki")?;
    }
    if let Err(e) = std::fs::rename(&tmp, &live) {
        if had_live {
            let _ = std::fs::rename(&bak, &live);
        }
        return Err(e).context("install mesh-pki");
    }
    if bak.exists() {
        std::fs::remove_dir_all(&bak).context("drop mesh-pki backup")?;
    }
    Ok(MeshCa::at(live))
}

/// Create the mesh CA and this host's node certificate, or reuse them.
/// A root whose node certificate is inside the renewal window is rotated
/// in place. A leaf is accepted as-is: this host has no `ca.key`, so it
/// cannot mint or rotate, and a near-expiry leaf waits for a new
/// `sign-csr` from the root.
pub fn ensure(data_dir: &Path, wg_pubkey_b64: &str, host: Ipv6Addr) -> Result<MeshCa> {
    recover_mesh_pki(data_dir)?;
    let dir = data_dir.join("mesh-pki");
    crate::pki::ensure_dir(&dir)?;
    let paths = MeshCa::at(dir);
    match layout(&paths) {
        Layout::Root => {
            check_required(&paths)?;
            let crt = std::fs::read_to_string(&paths.node_crt)?;
            node_cert_matches(&crt, wg_pubkey_b64)?;
            let expiry = crate::pki::cert_not_after(&crt)?;
            let renew_at =
                time::OffsetDateTime::now_utc() + time::Duration::days(RENEW_WITHIN_DAYS);
            if expiry < renew_at {
                return rotate_node(data_dir, wg_pubkey_b64, host);
            }
            Ok(paths)
        }
        Layout::Leaf => {
            check_files(&[&paths.ca_crt, &paths.node_crt, &paths.node_key])?;
            key_not_open(&paths.node_key, 0o037, "group-writable or other-accessible")?;
            let crt = std::fs::read_to_string(&paths.node_crt)?;
            node_cert_matches(&crt, wg_pubkey_b64)?;
            Ok(paths)
        }
        Layout::Empty => {
            let ca_key = rcgen::KeyPair::generate().context("generate mesh CA key")?;
            let ca_params = ca_params()?;
            let ca_cert = ca_params
                .self_signed(&ca_key)
                .context("self-sign mesh CA")?;
            let ca_key_pem = ca_key.serialize_pem();
            let ca_pem = ca_cert.pem();
            let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_pem, ca_key)
                .context("mesh CA issuer")?;
            let node_key = rcgen::KeyPair::generate().context("generate mesh node key")?;
            let node_cert = sign_node(&issuer, &node_key, wg_pubkey_b64, host)?;
            let node_pem = node_cert.pem();
            let key_pem = node_key.serialize_pem();
            install_mesh_pki(
                data_dir,
                &[
                    ("ca.crt", ca_pem.as_bytes(), 0o644),
                    ("ca.key", ca_key_pem.as_bytes(), 0o600),
                    ("node.crt", node_pem.as_bytes(), 0o644),
                    ("node.key", key_pem.as_bytes(), 0o600),
                ],
            )
        }
        Layout::Corrupt => bail!(
            "corrupt mesh PKI at {} — a root holds ca.crt, ca.key, node.crt and node.key; a leaf holds ca.crt, node.crt and node.key",
            paths.dir.display()
        ),
    }
}

/// Write `node.key` at mode 0640 when it is absent, and return a CSR for
/// that key. An existing key is reused so a second run does not orphan a
/// certificate the root already signed. Names in the CSR are placeholders;
/// the signing root discards them.
pub fn create_node_csr(data_dir: &Path) -> Result<String> {
    let dir = data_dir.join("mesh-pki");
    crate::pki::ensure_dir(&dir)?;
    let paths = MeshCa::at(dir);
    if paths.node_key.exists() {
        let pem = std::fs::read_to_string(&paths.node_key)
            .with_context(|| format!("read {}", paths.node_key.display()))?;
        let key = rcgen::KeyPair::from_pem(&pem).context("parse mesh node key")?;
        return csr_pem(&key);
    }
    if paths.node_crt.exists() || paths.ca_crt.exists() || paths.ca_key.exists() {
        bail!(
            "corrupt mesh PKI at {} — refusing to mint a node key under an incomplete certificate set",
            paths.dir.display()
        );
    }
    let key = rcgen::KeyPair::generate().context("generate mesh node key")?;
    crate::pki::atomic_write(&paths.node_key, key.serialize_pem().as_bytes(), 0o640)?;
    csr_pem(&key)
}

fn csr_pem(key: &rcgen::KeyPair) -> Result<String> {
    let params = rcgen::CertificateParams::new(vec!["ignored.invalid".to_string()])?;
    params
        .serialize_request(key)
        .context("build mesh CSR")?
        .pem()
        .context("encode mesh CSR")
}

/// Issue a new node certificate and keep the current one as the grace
/// certificate. The CA root stays.
pub fn rotate_node(data_dir: &Path, wg_pubkey_b64: &str, host: Ipv6Addr) -> Result<MeshCa> {
    let paths = MeshCa::at(data_dir.join("mesh-pki"));
    check_required(&paths)?;
    let previous = std::fs::read(&paths.node_crt)?;
    let ca_crt = std::fs::read(&paths.ca_crt)?;
    let ca_key = std::fs::read(&paths.ca_key)?;
    let issuer = load_issuer(&paths)?;
    let node_key = rcgen::KeyPair::generate().context("generate mesh node key")?;
    let node_cert = sign_node(&issuer, &node_key, wg_pubkey_b64, host)?;
    let node_pem = node_cert.pem();
    let key_pem = node_key.serialize_pem();
    install_mesh_pki(
        data_dir,
        &[
            ("ca.crt", &ca_crt, 0o644),
            ("ca.key", &ca_key, 0o600),
            ("node.crt", node_pem.as_bytes(), 0o644),
            ("node.key", key_pem.as_bytes(), 0o600),
            ("node.prev.crt", &previous, 0o644),
        ],
    )
}

/// Drop the grace certificate. Peers still presenting it are rejected.
pub fn retire_previous(data_dir: &Path) -> Result<()> {
    let path = data_dir.join("mesh-pki").join("node.prev.crt");
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove {}", path.display())),
    }
}

/// Sign a joiner's TLS public key for `wg_pubkey_b64` at `host`.
/// Names inside the CSR are discarded.
pub fn issue_from_csr(
    data_dir: &Path,
    csr_pem: &str,
    wg_pubkey_b64: &str,
    host: Ipv6Addr,
) -> Result<String> {
    let paths = MeshCa::at(data_dir.join("mesh-pki"));
    check_required(&paths)?;
    let mut csr = rcgen::CertificateSigningRequestParams::from_pem(csr_pem)
        .map_err(|e| anyhow::anyhow!("mesh CSR rejected: {e}"))?;
    csr.params = node_params(wg_pubkey_b64, host)?;
    let issuer = load_issuer(&paths)?;
    let cert = csr
        .signed_by(&issuer)
        .map_err(|e| anyhow::anyhow!("mesh CA refused the CSR: {e}"))?;
    Ok(cert.pem())
}

/// Accept a presented node certificate when it is the current or the
/// grace certificate for this WireGuard identity, and chains to the mesh CA.
/// Both slots are always compared. An empty grace slot authorizes nothing.
pub fn accept_presented(
    ca_pem: &str,
    presented_pem: &str,
    current_pem: &str,
    previous_pem: &str,
    wg_pubkey_b64: &str,
    host: Ipv6Addr,
) -> Result<()> {
    let current_ok = crate::http::token_eq(presented_pem, current_pem) && !current_pem.is_empty();
    let previous_ok =
        crate::http::token_eq(presented_pem, previous_pem) && !previous_pem.is_empty();
    let chained = verify_node(ca_pem, presented_pem, wg_pubkey_b64, host).is_ok();
    if (current_ok || previous_ok) && chained {
        Ok(())
    } else {
        bail!("mesh peer certificate rejected")
    }
}

fn verify_node(
    ca_pem: &str,
    presented_pem: &str,
    wg_pubkey_b64: &str,
    host: Ipv6Addr,
) -> Result<()> {
    use rustls::client::{verify_server_cert_signed_by_trust_anchor, verify_server_name};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::server::ParsedCertificate;
    use rustls::RootCertStore;

    let ca_der = pem_der(ca_pem)?;
    let leaf_der = pem_der(presented_pem)?;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der))
        .map_err(|e| anyhow::anyhow!("mesh CA rejected: {e}"))?;
    let leaf = CertificateDer::from(leaf_der);
    let parsed = ParsedCertificate::try_from(&leaf)
        .map_err(|e| anyhow::anyhow!("mesh node certificate rejected: {e}"))?;
    let algs = rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .all;
    verify_server_cert_signed_by_trust_anchor(&parsed, &roots, &[], UnixTime::now(), algs)
        .map_err(|e| anyhow::anyhow!("mesh node certificate rejected: {e}"))?;
    let dns = node_dns(wg_pubkey_b64);
    let dns_name = ServerName::try_from(dns.as_str())
        .map_err(|_| anyhow::anyhow!("mesh node name {dns} is not a DNS name"))?;
    verify_server_name(&parsed, &dns_name)
        .map_err(|_| anyhow::anyhow!("mesh node certificate rejected"))?;
    let ip_name = ServerName::IpAddress(IpAddr::V6(host).into());
    verify_server_name(&parsed, &ip_name)
        .map_err(|_| anyhow::anyhow!("mesh node certificate rejected"))?;
    Ok(())
}

/// PEM the mesh listener and outbound dials present.
pub struct MeshMaterial {
    pub ca_crt: Vec<u8>,
    pub node_crt: Vec<u8>,
    pub node_key: Vec<u8>,
}

pub fn load_material(data_dir: &Path) -> Result<MeshMaterial> {
    let paths = MeshCa::at(data_dir.join("mesh-pki"));
    Ok(MeshMaterial {
        ca_crt: std::fs::read(&paths.ca_crt).context("mesh ca.crt")?,
        node_crt: std::fs::read(&paths.node_crt).context("mesh node.crt")?,
        node_key: std::fs::read(&paths.node_key).context("mesh node.key")?,
    })
}

/// Identity rustls already proved was signed by the mesh CA. The DNS
/// label is the WireGuard binding; the address is `fd<host>::1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshNodeId {
    pub dns: String,
    pub addr: Ipv6Addr,
}

pub fn identity_from_der(der: &[u8]) -> Result<MeshNodeId> {
    use x509_parser::certificate::X509Certificate;
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::FromDer;
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| anyhow::anyhow!("peer cert: {e}"))?;
    let san = cert
        .tbs_certificate
        .subject_alternative_name()
        .map_err(|e| anyhow::anyhow!("peer SAN: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("peer certificate has no SAN"))?;
    let mut dns = None;
    let mut addr = None;
    for name in &san.value.general_names {
        match name {
            GeneralName::DNSName(n) => {
                if dns.is_some() {
                    bail!("peer certificate has multiple DNS names");
                }
                dns = Some((*n).to_string());
            }
            GeneralName::IPAddress(ip) if ip.len() == 16 => {
                if addr.is_some() {
                    bail!("peer certificate has multiple IP names");
                }
                let mut oct = [0u8; 16];
                oct.copy_from_slice(ip);
                addr = Some(Ipv6Addr::from(oct));
            }
            _ => bail!("peer certificate has an unexpected SAN"),
        }
    }
    let dns = dns.ok_or_else(|| anyhow::anyhow!("peer certificate has no DNS SAN"))?;
    let addr = addr.ok_or_else(|| anyhow::anyhow!("peer certificate has no IP SAN"))?;
    let Some(label) = dns.strip_suffix(&format!(".{MESH_NODE_ZONE}")) else {
        bail!("peer DNS name is outside the mesh zone");
    };
    if label.len() != 30 || label.contains('.') || !label.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("peer DNS name is outside the mesh zone");
    }
    if addr.octets()[0] != 0xfd {
        bail!("peer IP is outside fd00::/8");
    }
    Ok(MeshNodeId { dns, addr })
}

/// Let `--allowed-uid` read `node.key` so `rustypods --host` can present
/// it. `ca.key` stays mode 0600. Uid 0 needs no change.
pub fn share_node_key(data_dir: &Path, uid: u32) -> Result<()> {
    if uid == 0 {
        return Ok(());
    }
    let gid = primary_gid(uid)?;
    let dir = data_dir.join("mesh-pki");
    crate::pki::ensure_dir(&dir)?;
    chown_mode(&dir, gid, 0o750)?;
    chown_mode(&dir.join("node.key"), gid, 0o640)?;
    Ok(())
}

fn primary_gid(uid: u32) -> Result<u32> {
    let text = std::fs::read_to_string("/etc/passwd").context("read /etc/passwd")?;
    gid_from_passwd(&text, uid).with_context(|| format!("uid {uid} has no primary group"))
}

pub(crate) fn gid_from_passwd(text: &str, uid: u32) -> Option<u32> {
    let want = uid.to_string();
    for line in text.lines() {
        let mut parts = line.split(':');
        let (Some(_), Some(_), Some(u), Some(g)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if u == want {
            return g.parse().ok();
        }
    }
    None
}

fn chown_mode(path: &Path, gid: u32, mode: u32) -> Result<()> {
    use std::os::unix::fs::{chown, PermissionsExt};
    chown(path, Some(0), Some(gid)).with_context(|| format!("chown {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rp-meshca-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ensure_is_idempotent_and_constrained() {
        let dir = scratch();
        let host = Ipv6Addr::new(0xfd12, 0x3456, 0x789a, 0, 0, 0, 0, 1);
        let paths = ensure(&dir, "pubkey-a", host).unwrap();
        let ca = std::fs::read(&paths.ca_crt).unwrap();
        let again = ensure(&dir, "pubkey-a", host).unwrap();
        assert_eq!(std::fs::read(&again.ca_crt).unwrap(), ca);
        let ca_pem = std::fs::read_to_string(&paths.ca_crt).unwrap();
        assert!(
            !crate::pki::ca_is_unconstrained(&ca_pem),
            "mesh CA must be name- and path-constrained"
        );
        assert!(!dir.join("pki").exists(), "ingress PKI stays untouched");
        use std::os::unix::fs::PermissionsExt;
        let dir_mode = std::fs::metadata(&paths.dir).unwrap().permissions().mode() & 0o777;
        let key_mode = std::fs::metadata(&paths.ca_key)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(key_mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn csr_names_are_replaced_and_rotation_overlaps() {
        let dir = scratch();
        let host = Ipv6Addr::new(0xfdab, 1, 2, 0, 0, 0, 0, 1);
        let paths = ensure(&dir, "local-key", host).unwrap();
        let joiner_key = rcgen::KeyPair::generate().unwrap();
        let asked = rcgen::CertificateParams::new(vec!["evil.example".to_string()]).unwrap();
        let csr = asked.serialize_request(&joiner_key).unwrap().pem().unwrap();
        let issued = issue_from_csr(&dir, &csr, "joiner-key", host).unwrap();
        assert!(!issued.contains("evil.example"));
        let dns = node_dns("joiner-key");
        let der = pem_der(&issued).unwrap();
        assert!(
            der.windows(dns.len()).any(|w| w == dns.as_bytes()),
            "issued cert must carry the WireGuard identity"
        );
        let ca = std::fs::read_to_string(&paths.ca_crt).unwrap();
        accept_presented(&ca, &issued, &issued, "", "joiner-key", host).unwrap();
        assert!(accept_presented(&ca, &issued, &issued, "", "local-key", host).is_err());

        let before = std::fs::read_to_string(&paths.node_crt).unwrap();
        let rotated = rotate_node(&dir, "local-key", host).unwrap();
        let after = std::fs::read_to_string(&rotated.node_crt).unwrap();
        let prev = std::fs::read_to_string(&rotated.node_prev_crt).unwrap();
        assert_eq!(prev, before);
        assert_ne!(after, before);
        accept_presented(&ca, &before, &after, &prev, "local-key", host).unwrap();
        accept_presented(&ca, &after, &after, &prev, "local-key", host).unwrap();
        retire_previous(&dir).unwrap();
        assert!(accept_presented(&ca, &before, &after, "", "local-key", host).is_err());
        accept_presented(&ca, &after, &after, "", "local-key", host).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn partial_mesh_pki_is_refused() {
        let dir = scratch();
        let pki = dir.join("mesh-pki");
        std::fs::create_dir(&pki).unwrap();
        std::fs::write(pki.join("ca.crt"), "x").unwrap();
        let err = ensure(&dir, "k", Ipv6Addr::LOCALHOST).unwrap_err();
        assert!(err.to_string().contains("corrupt"), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leaf_set_does_not_mint_a_ca_and_a_gap_is_corrupt() {
        use std::os::unix::fs::PermissionsExt;
        let root_dir = scratch();
        let host = Ipv6Addr::new(0xfd12, 0x3456, 0x789a, 0, 0, 0, 0, 1);
        let root = ensure(&root_dir, "leader-key", host).unwrap();
        let before = std::fs::read(&root.node_crt).unwrap();

        let join_dir = scratch();
        let (priv_key, pub_key) = crate::mesh::keygen();
        let _ = priv_key;
        let join_host = crate::mesh::host_addr(crate::mesh::prefix_of(&pub_key).unwrap());
        let csr = create_node_csr(&join_dir).unwrap();
        assert!(csr.contains("BEGIN CERTIFICATE REQUEST"));
        let key_before = std::fs::read(join_dir.join("mesh-pki/node.key")).unwrap();
        let again = create_node_csr(&join_dir).unwrap();
        assert!(again.contains("BEGIN CERTIFICATE REQUEST"));
        assert_eq!(
            std::fs::read(join_dir.join("mesh-pki/node.key")).unwrap(),
            key_before,
            "a second CSR must reuse node.key"
        );
        let key_mode = std::fs::metadata(join_dir.join("mesh-pki/node.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(key_mode, 0o640);
        let err = ensure(&join_dir, &pub_key, join_host).unwrap_err();
        assert!(
            format!("{err:#}").contains("corrupt"),
            "node.key alone is not a leaf, got {err:#}"
        );

        let node_crt = issue_from_csr(&root_dir, &csr, &pub_key, join_host).unwrap();
        assert!(!node_crt.contains("ignored.invalid"));
        assert_eq!(std::fs::read(&root.node_crt).unwrap(), before);
        let pki = join_dir.join("mesh-pki");
        std::fs::write(pki.join("ca.crt"), std::fs::read(&root.ca_crt).unwrap()).unwrap();
        std::fs::write(pki.join("node.crt"), &node_crt).unwrap();
        let leaf = ensure(&join_dir, &pub_key, join_host).unwrap();
        assert!(!leaf.ca_key.exists(), "a leaf must not gain a CA key");
        let kept = std::fs::read_to_string(&leaf.node_crt).unwrap();
        ensure(&join_dir, &pub_key, join_host).unwrap();
        assert_eq!(std::fs::read_to_string(&leaf.node_crt).unwrap(), kept);

        std::fs::remove_file(&leaf.node_crt).unwrap();
        let err = ensure(&join_dir, &pub_key, join_host).unwrap_err();
        assert!(format!("{err:#}").contains("corrupt"), "{err:#}");
        let _ = std::fs::remove_dir_all(&root_dir);
        let _ = std::fs::remove_dir_all(&join_dir);
    }

    #[test]
    fn leaf_identity_matches_wireguard_san() {
        let dir = scratch();
        let host: Ipv6Addr = "fd12:3456:789a::1".parse().unwrap();
        let paths = ensure(&dir, "pubkey", host).unwrap();
        let pem = std::fs::read_to_string(&paths.node_crt).unwrap();
        let id = identity_from_der(&pem_der(&pem).unwrap()).unwrap();
        assert_eq!(id.dns, node_dns("pubkey"));
        assert_eq!(id.addr, host);
        assert!(identity_from_der(b"not-a-cert").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shared_node_key_restarts_and_loose_modes_do_not() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch();
        let host = Ipv6Addr::new(0xfd12, 0x3456, 0x789a, 0, 0, 0, 0, 1);
        let paths = ensure(&dir, "pubkey-a", host).unwrap();
        std::fs::set_permissions(&paths.node_key, std::fs::Permissions::from_mode(0o640)).unwrap();
        ensure(&dir, "pubkey-a", host).unwrap();
        std::fs::set_permissions(&paths.node_key, std::fs::Permissions::from_mode(0o660)).unwrap();
        let err = ensure(&dir, "pubkey-a", host).unwrap_err();
        assert!(
            format!("{err:#}").contains("node.key"),
            "group-writable node key must be refused, got {err:#}"
        );
        std::fs::set_permissions(&paths.node_key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&paths.ca_key, std::fs::Permissions::from_mode(0o640)).unwrap();
        let err = ensure(&dir, "pubkey-a", host).unwrap_err();
        assert!(
            format!("{err:#}").contains("ca.key"),
            "group-readable CA key must be refused, got {err:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_witness_with_an_empty_pki_cannot_mint_a_ca() {
        let dir = std::env::temp_dir().join(format!(
            "rp-meshca-witness-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let err = reject_witness_mint(&dir).unwrap_err();
        assert!(
            format!("{err:#}").contains("create-csr"),
            "empty witness must refuse to mint, got {err:#}"
        );
        assert!(!dir.join("mesh-pki").join("ca.key").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_parked_pki_is_restored_and_staging_does_not_survive() {
        let dir = std::env::temp_dir().join(format!(
            "rp-meshca-atomic-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let host = Ipv6Addr::new(0xfd7e, 0x0f0a, 0xd1ae, 0, 0, 0, 0, 1);
        let paths = ensure(&dir, "pubkey-a", host).unwrap();
        let ca = std::fs::read(&paths.ca_crt).unwrap();
        std::fs::rename(&paths.dir, dir.join(".mesh-pki.bak")).unwrap();
        std::fs::create_dir(dir.join(".mesh-pki.tmp")).unwrap();
        let again = ensure(&dir, "pubkey-a", host).unwrap();
        assert_eq!(std::fs::read(&again.ca_crt).unwrap(), ca);
        assert!(!dir.join(".mesh-pki.bak").exists());
        assert!(!dir.join(".mesh-pki.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn passwd_gid_lookup() {
        let text = "root:x:0:0:root:/root:/bin/bash\nnick:x:1000:1000::/home/nick:/bin/bash\n";
        assert_eq!(super::gid_from_passwd(text, 1000), Some(1000));
        assert_eq!(super::gid_from_passwd(text, 0), Some(0));
        assert_eq!(super::gid_from_passwd(text, 7), None);
    }
}
