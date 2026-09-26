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
use sha2::{Digest, Sha256};

/// DNS zone this CA is allowed to issue. Not the ingress zone.
pub const MESH_NODE_ZONE: &str = "node.mesh.rustypods";
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
    let dig = Sha256::digest(wg_pubkey_b64.trim().as_bytes());
    let mut label = String::with_capacity(30);
    for byte in &dig[..15] {
        label.push_str(&format!("{byte:02x}"));
    }
    format!("{label}.{MESH_NODE_ZONE}")
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
    use std::os::unix::fs::PermissionsExt;
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
    for path in [&paths.ca_key, &paths.node_key] {
        let md = std::fs::symlink_metadata(path)?;
        if md.permissions().mode() & 0o077 != 0 {
            bail!(
                "{} is group/other-readable — fix permissions or delete and re-init",
                path.display()
            );
        }
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

/// Create the mesh CA and this host's node certificate, or reuse them.
/// A node certificate inside the renewal window is rotated in place and
/// the previous one stays acceptable.
pub fn ensure(data_dir: &Path, wg_pubkey_b64: &str, host: Ipv6Addr) -> Result<MeshCa> {
    let dir = data_dir.join("mesh-pki");
    crate::pki::ensure_dir(&dir)?;
    let paths = MeshCa::at(dir);
    let present = paths.required().into_iter().filter(|p| p.exists()).count();
    match present {
        4 => {
            check_required(&paths)?;
            let crt = std::fs::read_to_string(&paths.node_crt)?;
            let der = pem_der(&crt)?;
            let dns = node_dns(wg_pubkey_b64);
            if !der.windows(dns.len()).any(|w| w == dns.as_bytes()) {
                bail!(
                    "mesh node certificate is not for this WireGuard identity ({dns})"
                );
            }
            let expiry = crate::pki::cert_not_after(&crt)?;
            let renew_at = time::OffsetDateTime::now_utc() + time::Duration::days(RENEW_WITHIN_DAYS);
            if expiry < renew_at {
                return rotate_node(data_dir, wg_pubkey_b64, host);
            }
            Ok(paths)
        }
        0 => {
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
            crate::pki::atomic_write(&paths.ca_crt, ca_pem.as_bytes(), 0o644)?;
            crate::pki::atomic_write(&paths.ca_key, ca_key_pem.as_bytes(), 0o600)?;
            crate::pki::atomic_write(&paths.node_crt, node_cert.pem().as_bytes(), 0o644)?;
            crate::pki::atomic_write(&paths.node_key, node_key.serialize_pem().as_bytes(), 0o600)?;
            Ok(paths)
        }
        n => bail!(
            "partial mesh PKI at {} ({n} of 4 files) — remove the whole set or restore the missing files",
            paths.dir.display()
        ),
    }
}

/// Issue a new node certificate and keep the current one as the grace
/// certificate. The CA root stays.
pub fn rotate_node(data_dir: &Path, wg_pubkey_b64: &str, host: Ipv6Addr) -> Result<MeshCa> {
    let paths = MeshCa::at(data_dir.join("mesh-pki"));
    check_required(&paths)?;
    let previous = std::fs::read(&paths.node_crt)?;
    let issuer = load_issuer(&paths)?;
    let node_key = rcgen::KeyPair::generate().context("generate mesh node key")?;
    let node_cert = sign_node(&issuer, &node_key, wg_pubkey_b64, host)?;
    crate::pki::atomic_write(&paths.node_prev_crt, &previous, 0o644)?;
    crate::pki::atomic_write(&paths.node_key, node_key.serialize_pem().as_bytes(), 0o600)?;
    crate::pki::atomic_write(&paths.node_crt, node_cert.pem().as_bytes(), 0o644)?;
    Ok(paths)
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
        assert!(err.to_string().contains("partial"), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
