//! Local development PKI for the ingress gateway: a self-signed CA plus
//! a wildcard leaf for *.rustypods.localhost. Generated once under
//! <data>/pki, root-only, and reused thereafter — the CA key NEVER
//! leaves the host (only the leaf pair is copied into the gateway pod).

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// The four managed files under `<data>/pki`.
#[derive(Debug, Clone)]
pub struct PkiPaths {
    pub ca_crt: PathBuf,
    pub ca_key: PathBuf,
    pub tls_crt: PathBuf,
    pub tls_key: PathBuf,
}

impl PkiPaths {
    fn at(dir: &Path) -> Self {
        Self {
            ca_crt: dir.join("ca.crt"),
            ca_key: dir.join("ca.key"),
            tls_crt: dir.join("tls.crt"),
            tls_key: dir.join("tls.key"),
        }
    }

    fn all(&self) -> [&PathBuf; 4] {
        [&self.ca_crt, &self.ca_key, &self.tls_crt, &self.tls_key]
    }
}

/// Cert shapes, kept as functions so tests can inspect the parameters
/// without parsing DER.
fn ca_params() -> Result<rcgen::CertificateParams> {
    use rcgen::{
        BasicConstraints, DnType, IsCa, KeyUsagePurpose,
    };
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new())?;
    p.distinguished_name
        .push(DnType::CommonName, "RustyPods Local Development CA");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::days(1);
    p.not_after = now + time::Duration::days(3650); // ~10y local CA
    Ok(p)
}

fn leaf_params() -> Result<rcgen::CertificateParams> {
    use rcgen::{ExtendedKeyUsagePurpose, IsCa};
    let mut p = rcgen::CertificateParams::new(vec![
        "*.rustypods.localhost".to_string(),
        "rustypods.localhost".to_string(),
    ])?;
    p.is_ca = IsCa::ExplicitNoCa;
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::days(1);
    // CA/B forum maximum for public certs — good hygiene for local too.
    p.not_after = now + time::Duration::days(825);
    Ok(p)
}

/// Durably write one file: temp + fsync + rename + dir fsync, mode set
/// at create time, never following a planted symlink (O_NOFOLLOW).
fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = path
        .parent()
        .with_context(|| format!("{} has no parent", path.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let write = || -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(data)
            .and_then(|()| f.sync_all())
            .with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("rename {}", tmp.display()))?;
        // Persist the rename itself.
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .with_context(|| format!("fsync {}", dir.display()))?;
        Ok(())
    };
    let res = write();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// The pki dir must be a REAL directory owned by root with 0700 — a
/// symlink or a mode that leaks the CA key fails closed.
fn ensure_dir(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(md) => {
            if !md.file_type().is_dir() {
                bail!("{} exists but is not a real directory", dir.display());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(dir).with_context(|| format!("mkdir {}", dir.display()))?;
        }
        Err(e) => return Err(e).with_context(|| format!("stat {}", dir.display())),
    }
    // Owned by the daemon's own uid (root in production): a foreign-owned
    // dir could be swapped under us between checks.
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
    if md.uid() != unsafe { libc::geteuid() } {
        bail!("{} is owned by uid {} — PKI dir must be daemon-owned", dir.display(), md.uid());
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    Ok(())
}

/// Validate an existing complete set: real regular files, nonempty, and
/// private keys with no group/other bits.
fn check_existing(paths: &PkiPaths) -> Result<()> {
    for p in paths.all() {
        let md = std::fs::symlink_metadata(p)
            .with_context(|| format!("stat {}", p.display()))?;
        if !md.file_type().is_file() {
            bail!("{} is not a regular file", p.display());
        }
        if md.len() == 0 {
            bail!("{} is empty", p.display());
        }
    }
    for p in [&paths.ca_key, &paths.tls_key] {
        let md = std::fs::symlink_metadata(p).unwrap();
        if md.permissions().mode() & 0o077 != 0 {
            bail!(
                "{} is group/other-readable — fix permissions or delete and re-init",
                p.display()
            );
        }
    }
    Ok(())
}

/// Idempotent PKI state: all four files present → validate and return;
/// all absent → generate a fresh CA + wildcard leaf atomically; a
/// partial set fails closed (never auto-delete someone's material).
pub fn ensure(data_dir: &Path) -> Result<PkiPaths> {
    let dir = data_dir.join("pki");
    ensure_dir(&dir)?;
    let paths = PkiPaths::at(&dir);
    let present: Vec<&PathBuf> = paths
        .all()
        .into_iter()
        .filter(|p| p.exists())
        .collect();
    match present.len() {
        4 => {
            check_existing(&paths)?;
            Ok(paths)
        }
        0 => {
            // Generate in memory first — nothing hits disk until every
            // PEM exists, then each file lands atomically.
            let ca_key = rcgen::KeyPair::generate().context("generate CA key")?;
            let ca_p = ca_params()?;
            let ca_cert = ca_p.self_signed(&ca_key).context("self-sign CA")?;
            let ca_key_pem = ca_key.serialize_pem();
            let issuer = rcgen::Issuer::new(ca_p, ca_key);
            let tls_key = rcgen::KeyPair::generate().context("generate leaf key")?;
            let tls_cert = leaf_params()?
                .signed_by(&tls_key, &issuer)
                .context("sign leaf by CA")?;
            atomic_write(&paths.ca_crt, ca_cert.pem().as_bytes(), 0o644)?;
            atomic_write(&paths.ca_key, ca_key_pem.as_bytes(), 0o600)?;
            atomic_write(&paths.tls_crt, tls_cert.pem().as_bytes(), 0o644)?;
            atomic_write(&paths.tls_key, tls_key.serialize_pem().as_bytes(), 0o600)?;
            Ok(paths)
        }
        n => bail!(
            "partial PKI at {} ({} of 4 files) — remove the whole set or restore the missing files",
            dir.display(),
            n
        ),
    }
}

/// Which distro family this /etc/os-release belongs to → trust-store
/// destination + update command (parsed as DATA, never sourced).
fn trust_target(os_release: &str) -> Option<(PathBuf, &'static str, Vec<&'static str>)> {
    let mut id = "";
    let mut id_like = "";
    for line in os_release.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"').trim_matches('\'');
        match k {
            "ID" => id = v,
            "ID_LIKE" => id_like = v,
            _ => {}
        }
    }
    let debian = ["debian", "ubuntu", "linuxmint", "pop"];
    let rhel = [
        "fedora", "rhel", "centos", "almalinux", "rocky", "ol", "fedora-asahi-remix",
    ];
    let arch = ["arch", "manjaro", "endeavouros", "garuda"];
    let has_like = |set: &[&str]| id_like.split_whitespace().any(|t| set.contains(&t));
    if debian.contains(&id) || has_like(&debian) {
        Some((
            PathBuf::from("/usr/local/share/ca-certificates/rustypods-local-ca.crt"),
            "update-ca-certificates",
            vec![],
        ))
    } else if rhel.contains(&id) || has_like(&rhel) {
        Some((
            PathBuf::from("/etc/pki/ca-trust/source/anchors/rustypods-local-ca.crt"),
            "update-ca-trust",
            vec!["extract"],
        ))
    } else if arch.contains(&id) || has_like(&arch) {
        // p11-kit trust store (ca-certificates-utils).
        Some((
            PathBuf::from("/etc/ca-certificates/trust-source/anchors/rustypods-local-ca.crt"),
            "update-ca-trust",
            vec!["extract"],
        ))
    } else {
        None
    }
}

/// Install the CA cert into the HOST trust store (explicit --install-ca
/// authorization). Atomic-ish: existing destination is backed up and
/// restored on update-command failure; a symlinked destination is
/// refused outright.
pub fn install_host_trust(paths: &PkiPaths) -> Result<PathBuf> {
    let os_release = std::fs::read_to_string("/etc/os-release")
        .context("read /etc/os-release")?;
    let Some((dest, cmd, args)) = trust_target(&os_release) else {
        bail!("unsupported distro family for system CA trust install");
    };
    if let Ok(md) = std::fs::symlink_metadata(&dest) {
        if md.file_type().is_symlink() {
            bail!("{} is a symlink — refusing to write through it", dest.display());
        }
    }
    let ca_pem = std::fs::read(&paths.ca_crt)
        .with_context(|| format!("read {}", paths.ca_crt.display()))?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let backup = dest.with_extension("crt.rustypods-bak");
    let had_prior = dest.exists();
    if had_prior {
        std::fs::copy(&dest, &backup)
            .with_context(|| format!("backup {}", dest.display()))?;
    }
    let write = atomic_write(&dest, &ca_pem, 0o644);
    let run = write.and_then(|()| {
        let st = std::process::Command::new(cmd)
            .args(&args)
            .status()
            .with_context(|| format!("run {cmd}"))?;
        if !st.success() {
            bail!("{cmd} exited {st}");
        }
        Ok(())
    });
    if let Err(e) = run {
        // Roll back: restore the backup or remove what we wrote, then
        // refresh the store best-effort so nothing is half-registered.
        if had_prior {
            let _ = std::fs::rename(&backup, &dest);
        } else {
            let _ = std::fs::remove_file(&dest);
        }
        let _ = std::process::Command::new(cmd).args(&args).status();
        return Err(e);
    }
    if had_prior {
        let _ = std::fs::remove_file(&backup);
    }
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rp-pki-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn ensure_generates_then_reuses() {
        let d = tmp("fresh");
        let p = ensure(&d).unwrap();
        // Dir 0700, certs 0644, keys 0600.
        assert_eq!(mode(&d.join("pki")), 0o700);
        assert_eq!(mode(&p.ca_crt), 0o644);
        assert_eq!(mode(&p.ca_key), 0o600);
        assert_eq!(mode(&p.tls_crt), 0o644);
        assert_eq!(mode(&p.tls_key), 0o600);
        let ca = std::fs::read(&p.ca_crt).unwrap();
        assert!(ca.starts_with(b"-----BEGIN CERTIFICATE-----"));
        // Second call validates and returns THE SAME material.
        let p2 = ensure(&d).unwrap();
        assert_eq!(std::fs::read(&p2.ca_crt).unwrap(), ca);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ensure_fails_on_partial() {
        let d = tmp("partial");
        let p = ensure(&d).unwrap();
        std::fs::remove_file(&p.tls_key).unwrap();
        assert!(ensure(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ensure_refuses_symlinked_key_and_loose_modes() {
        let d = tmp("symlink");
        let p = ensure(&d).unwrap();
        // Swap the CA key for a symlink — must not be followed.
        std::fs::remove_file(&p.ca_key).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", &p.ca_key).unwrap();
        assert!(ensure(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);

        let d = tmp("mode");
        let p = ensure(&d).unwrap();
        std::fs::set_permissions(&p.tls_key, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(ensure(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ensure_refuses_symlinked_dir() {
        let d = tmp("dirlink");
        let real = d.join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, d.join("pki")).unwrap();
        assert!(ensure(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn leaf_carries_wildcard_and_apex_sans() {
        let p = leaf_params().unwrap();
        let sans: Vec<String> = p
            .subject_alt_names
            .iter()
            .map(|s| match s {
                rcgen::SanType::DnsName(n) => n.to_string(),
                _ => "other".into(),
            })
            .collect();
        assert!(sans.contains(&"*.rustypods.localhost".to_string()));
        assert!(sans.contains(&"rustypods.localhost".to_string()));
        // And the params really sign — the CA/leaf path is exercised.
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_p = ca_params().unwrap();
        let ca = ca_p.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_p, ca_key);
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = leaf_params().unwrap().signed_by(&leaf_key, &issuer).unwrap();
        assert!(ca.pem().contains("BEGIN CERTIFICATE"));
        assert!(leaf.pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn trust_target_families() {
        let (d, c, a) = trust_target("ID=debian\n").unwrap();
        assert_eq!(d.to_str().unwrap(), "/usr/local/share/ca-certificates/rustypods-local-ca.crt");
        assert_eq!(c, "update-ca-certificates");
        assert!(a.is_empty());
        let (_, c, a) = trust_target("ID=\"fedora\"\n").unwrap();
        assert_eq!(c, "update-ca-trust");
        assert_eq!(a, ["extract"]);
        // ID_LIKE routing covers derivatives.
        assert!(trust_target("ID=ubuntu\nID_LIKE=debian\n").is_some());
        assert!(trust_target("ID=rocky\nID_LIKE=\"rhel centos fedora\"\n").is_some());
        let (d, c, _) = trust_target("ID=arch\n").unwrap();
        assert_eq!(
            d.to_str().unwrap(),
            "/etc/ca-certificates/trust-source/anchors/rustypods-local-ca.crt"
        );
        assert_eq!(c, "update-ca-trust");
        assert!(trust_target("ID=manjaro\nID_LIKE=arch\n").is_some());
        assert!(trust_target("ID=nixos\n").is_none());
    }
}
