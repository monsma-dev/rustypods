//! OCI registry pull — no external tools. `oci-client` speaks the
//! distribution protocol (manifest + blobs, anonymous auth), and layers are
//! decompressed (flate2/zstd/plain) and untarred in-process.
//!
//! This code runs as root on untrusted archives, so extraction is paranoid:
//! entry paths are normalized (no `..`, no absolute paths), only
//! Regular/Directory/Symlink/Hardlink entries are written, hardlink targets
//! must resolve in-tree, and `entry.unpack_in` re-validates the final path
//! against already-extracted symlinks (tar-slip). OCI whiteouts
//! (`.wh.<name>`, `.wh..wh..opq`) are applied per layer, in order.

use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::manifest::OciDescriptor;
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};

/// The parts of an OCI image config that drive `start` (non-boot payload).
#[derive(Debug, Default)]
pub struct ImageConfig {
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    /// "K=V" entries — becomes nspawn --setenv.
    pub env: Vec<String>,
    /// Empty = unset.
    pub working_dir: String,
}

/// Default image name for `pull` without --name: "<repo-basename>-<tag>",
/// slugged into a valid pod/image name. "node:20-alpine" → "node-20-alpine",
/// "ghcr.io/org/tool:v1" → "tool-v1".
pub fn default_name(reference: &str) -> Result<String> {
    let r = Reference::from_str(reference)
        .with_context(|| format!("invalid image reference '{reference}'"))?;
    let repo = r.repository();
    let base = repo.rsplit('/').next().unwrap_or(repo);
    let raw = format!("{base}-{}", r.tag().unwrap_or("latest"));
    let mut slug = String::new();
    for c in raw.chars().flat_map(|c| c.to_lowercase()) {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            slug.push(c);
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
    }
    // Name limit is 32 (validate_name); trim so truncation can't end in '-'.
    let slug: String = slug.trim_end_matches('-').chars().take(32).collect();
    let slug = slug.trim_end_matches('-').to_string();
    rustypods_proto::validate_name(&slug)
        .with_context(|| format!("cannot derive an image name from '{reference}' — pass --name"))?;
    Ok(slug)
}

/// Pull `reference` into `dest` (an existing empty dir/subvol) and return
/// the image's runtime config. Anonymous auth; multi-arch indexes resolve
/// to the native linux/<arch> manifest (oci-client's default resolver).
pub async fn pull(reference: &str, dest: &Path) -> Result<ImageConfig> {
    let image = Reference::from_str(reference)
        .with_context(|| format!("invalid image reference '{reference}'"))?;
    let client = Client::new(ClientConfig {
        protocol: ClientProtocol::Https,
        ..Default::default()
    });
    let auth = RegistryAuth::Anonymous;
    let (manifest, digest, config_json) = client
        .pull_manifest_and_config(&image, &auth)
        .await
        .with_context(|| format!("pulling manifest for {image}"))?;
    tracing::info!("{image}: manifest {digest}, {} layer(s)", manifest.layers.len());
    let cfg = parse_config(&config_json);
    for layer in &manifest.layers {
        pull_layer(&client, &image, layer, dest).await?;
    }
    write_machine_id(dest)?;
    Ok(cfg)
}

/// Same convention as sanitize_rootfs: an empty etc/machine-id marks the
/// rootfs uninitialized so the container generates its own. But `etc` may
/// be an image-planted symlink (e.g. `etc -> /host/dir`): only write when
/// it resolves to a real directory *inside* the rootfs — never follow the
/// link out and clobber a host file.
fn write_machine_id(dest: &Path) -> Result<()> {
    let etc = dest.join("etc");
    let real_dir = match std::fs::symlink_metadata(&etc) {
        // Absent → create a real dir ourselves (create_dir_all can't plant
        // a symlink at the final component; a symlinked earlier component
        // is caught by the canonicalize check below).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir_all(&etc)
            .and_then(|_| std::fs::symlink_metadata(&etc))
            .map(|m| m.is_dir())
            .unwrap_or(false),
        Ok(md) => md.is_dir(),
        Err(_) => false,
    };
    let inside_dest = matches!(
        (etc.canonicalize(), dest.canonicalize()),
        (Ok(e), Ok(d)) if e.starts_with(&d)
    );
    if real_dir && inside_dest {
        std::fs::write(etc.join("machine-id"), b"")?;
    } else {
        tracing::warn!(
            "image 'etc' is a symlink or escapes the rootfs — skipping machine-id write"
        );
    }
    Ok(())
}

/// Fetch one layer blob to a temp file next to `dest` (same fs, cheap),
/// then decompress+untar it on a blocking thread. `pull_blob` verifies the
/// blob against the layer digest itself.
async fn pull_layer(
    client: &Client,
    image: &Reference,
    layer: &OciDescriptor,
    dest: &Path,
) -> Result<()> {
    tracing::info!(
        "{image}: layer {} ({}, {} bytes)",
        layer.digest,
        layer.media_type,
        layer.size
    );
    let tmp = dest
        .parent()
        .unwrap_or(dest)
        .join(format!(".layer-{}", layer.digest.replace(':', "-")));
    let res = async {
        let mut f = tokio::fs::File::create(&tmp)
            .await
            .with_context(|| format!("create {}", tmp.display()))?;
        client.pull_blob(image, layer, &mut f).await?;
        anyhow::Ok(())
    }
    .await;
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("pulling layer {}", layer.digest));
    }
    let tmp2 = tmp.clone();
    let dest2 = dest.to_path_buf();
    let mt = layer.media_type.clone();
    let res = tokio::task::spawn_blocking(move || unpack_layer(&tmp2, &mt, &dest2)).await;
    let _ = std::fs::remove_file(&tmp);
    res.context("untar task")?
        .with_context(|| format!("unpacking layer {}", layer.digest))
}

/// Decompress by media type and untar. Covers the OCI + docker layer types:
/// `.tar` plain, `+gzip`/`.gzip`, `+zstd`/`.zstd`.
fn unpack_layer(blob: &Path, media_type: &str, dest: &Path) -> Result<()> {
    let f = std::fs::File::open(blob).with_context(|| format!("open {}", blob.display()))?;
    let mt = media_type.to_ascii_lowercase();
    let reader: Box<dyn Read> = if mt.ends_with("+gzip") || mt.ends_with(".gzip") {
        Box::new(flate2::read::GzDecoder::new(f))
    } else if mt.ends_with("+zstd") || mt.ends_with(".zstd") || mt.ends_with(".zst") {
        Box::new(zstd::stream::read::Decoder::new(f)?)
    } else if mt.ends_with("tar") {
        Box::new(f)
    } else {
        bail!("unsupported layer media type '{media_type}'");
    };
    unpack_tar(reader, dest)
}

/// Normalize a tar entry path to an in-tree relative path: `.` is dropped,
/// absolute paths and `..` (anything escaping dest) are rejected → None.
fn normalize_entry_path(raw: &[u8]) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in Path::new(OsStr::from_bytes(raw)).components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

/// Delete a file/dir/symlink if present. symlink_metadata keeps us from
/// following a malicious symlink into a directory we shouldn't touch.
fn remove_path(p: &Path) {
    match std::fs::symlink_metadata(p) {
        Ok(md) if md.is_dir() => {
            let _ = std::fs::remove_dir_all(p);
        }
        Ok(_) => {
            let _ = std::fs::remove_file(p);
        }
        Err(_) => {}
    }
}

/// `.wh..wh..opq`: the dir is opaque — everything a lower layer put in it
/// is gone; the dir itself stays.
fn remove_children(dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            remove_path(&e.path());
        }
    }
}

/// Stream-untar one layer into `dest`, applying whiteouts. Entry order in
/// the tar is preserved (whiteouts land where the spec puts them).
fn unpack_tar<R: Read>(reader: R, dest: &Path) -> Result<()> {
    let mut ar = tar::Archive::new(reader);
    // Keep recorded uids/modes — only meaningful (and only permitted) when
    // the daemon runs as root; a rootless run just gets extractor-owned files.
    ar.set_preserve_ownerships(crate::euid() == 0);
    ar.set_preserve_permissions(true);
    // Canonicalized once: unpack_in resolves against this, so an entry like
    // "link/evil" after "link -> /etc" still lands Ok(false) — skipped.
    let dest = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());
    for e in ar.entries()? {
        let mut e = e?;
        let Some(rel) = normalize_entry_path(&e.path_bytes()) else {
            tracing::warn!("skipping unsafe tar path {:?}", e.path_bytes());
            continue;
        };
        if let Some(name) = rel
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix(".wh."))
        {
            // The whiteout's parent may traverse an in-rootfs symlink a
            // previous layer planted (d -> /tmp/x, then d/.wh.victim) —
            // deleting through it would erase files OUTSIDE the rootfs.
            // Canonicalize and require the resolved parent to stay inside
            // dest and to be a real directory (not a symlink) first.
            let parent = dest.join(rel.parent().unwrap_or(Path::new("")));
            let safe = match parent.canonicalize() {
                Ok(canon) => {
                    canon.starts_with(&dest)
                        && std::fs::symlink_metadata(&parent)
                            .map(|m| m.is_dir())
                            .unwrap_or(false)
                }
                // Doesn't exist → nothing to whiteout anyway.
                Err(_) => false,
            };
            if !safe {
                tracing::warn!("skipping whiteout via unsafe path {}", rel.display());
                continue;
            }
            if name == ".wh..opq" {
                remove_children(&parent);
            } else if !name.is_empty() {
                remove_path(&parent.join(name));
            }
            continue;
        }
        match e.header().entry_type() {
            tar::EntryType::Regular | tar::EntryType::Directory | tar::EntryType::Symlink => {}
            tar::EntryType::Link => {
                // Hardlink target must itself normalize to an in-tree path
                // (unpack_in refuses escapes too, but do it up front).
                let ok = matches!(
                    e.link_name_bytes(),
                    Some(l) if normalize_entry_path(&l).is_some()
                );
                if !ok {
                    tracing::warn!("skipping hardlink {} with out-of-tree target", rel.display());
                    continue;
                }
            }
            t => {
                // Devices, fifos, char/block specials, GNU sparse — never.
                tracing::debug!("skipping {t:?} entry {}", rel.display());
                continue;
            }
        }
        if !e.unpack_in(&dest).context("untar entry")? {
            tracing::warn!("skipping entry escaping dest: {}", rel.display());
        }
    }
    Ok(())
}

// --- image config JSON --------------------------------------------------

#[derive(serde::Deserialize)]
struct ConfigFileJson {
    #[serde(default)]
    config: ConfigJson,
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct ConfigJson {
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    env: Option<Vec<String>>,
    working_dir: Option<String>,
}

/// Best-effort parse: a broken config leaves the image runnable nowhere, so
/// warn + empty rather than fail the whole pull.
fn parse_config(json: &str) -> ImageConfig {
    match serde_json::from_str::<ConfigFileJson>(json) {
        Ok(f) => ImageConfig {
            entrypoint: f.config.entrypoint.unwrap_or_default(),
            cmd: f.config.cmd.unwrap_or_default(),
            env: f
                .config
                .env
                .unwrap_or_default()
                .into_iter()
                .filter(|kv| kv.contains('='))
                .collect(),
            working_dir: f.config.working_dir.unwrap_or_default(),
        },
        Err(e) => {
            tracing::warn!("image config unparseable ({e}) — empty entrypoint/cmd recorded");
            ImageConfig::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_slugs() {
        assert_eq!(default_name("node:20-alpine").unwrap(), "node-20-alpine");
        assert_eq!(default_name("busybox").unwrap(), "busybox-latest");
        assert_eq!(default_name("busybox:latest").unwrap(), "busybox-latest");
        assert_eq!(default_name("ghcr.io/org/tool:v1").unwrap(), "tool-v1");
        assert_eq!(
            default_name("docker.io/library/nginx:1.27").unwrap(),
            "nginx-1-27"
        );
        assert_eq!(
            default_name("registry.k8s.io/pause:3.9").unwrap(),
            "pause-3-9"
        );
    }

    #[test]
    fn entry_path_normalization() {
        assert_eq!(
            normalize_entry_path(b"etc/passwd"),
            Some(PathBuf::from("etc/passwd"))
        );
        assert_eq!(
            normalize_entry_path(b"./etc/passwd"),
            Some(PathBuf::from("etc/passwd"))
        );
        assert_eq!(normalize_entry_path(b"/etc/passwd"), None);
        assert_eq!(normalize_entry_path(b"../evil"), None);
        assert_eq!(normalize_entry_path(b"a/../b"), None);
        assert_eq!(normalize_entry_path(b"."), None);
        assert_eq!(normalize_entry_path(b""), None);
    }

    /// Minimal raw tar entry (ustar header + data, 512-padded). tar::Builder
    /// refuses `..` in paths — exactly what we need to test — so hostile
    /// entries are written as raw header bytes instead.
    fn tar_entry(name: &[u8], typeflag: u8, link: &[u8], data: &[u8]) -> Vec<u8> {
        let mut h = [0u8; 512];
        let n = name.len().min(100);
        h[..n].copy_from_slice(&name[..n]);
        let put_octal = |h: &mut [u8; 512], off: usize, len: usize, v: u64| {
            let s = format!("{:0width$o} ", v, width = len - 1);
            h[off..off + len].copy_from_slice(s.as_bytes());
        };
        // mode: dirs need +x or nothing can be created inside them.
        put_octal(&mut h, 100, 8, if typeflag == b'5' { 0o755 } else { 0o644 });
        put_octal(&mut h, 108, 8, 0); // uid
        put_octal(&mut h, 116, 8, 0); // gid
        put_octal(&mut h, 124, 12, data.len() as u64); // size
        put_octal(&mut h, 136, 12, 1_700_000_000); // mtime
        h[156] = typeflag;
        let l = link.len().min(100);
        h[157..157 + l].copy_from_slice(&link[..l]);
        for b in &mut h[148..156] {
            *b = b' ';
        }
        let sum: u64 = h.iter().map(|b| *b as u64).sum();
        let s = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(s.as_bytes());
        let mut out = h.to_vec();
        out.extend_from_slice(data);
        out.resize(out.len() + (512 - data.len() % 512) % 512, 0);
        out
    }

    /// A crafted hostile tar: dirs, a file, escape attempts, a fifo, a good
    /// symlink+hardlink, and a hardlink to an out-of-tree target.
    #[test]
    fn untar_safety() {
        let dest = std::env::temp_dir().join(format!("rp-oci-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).unwrap();

        let mut t = Vec::new();
        t.extend(tar_entry(b"d/", b'5', b"", b""));
        t.extend(tar_entry(b"d/f.txt", b'0', b"", b"hey"));
        // Escapes — must all be skipped.
        t.extend(tar_entry(b"../evil", b'0', b"", b"x"));
        t.extend(tar_entry(b"/abs", b'0', b"", b"x"));
        t.extend(tar_entry(b"d/../../evil2", b'0', b"", b"x"));
        // fifo — skipped outright.
        t.extend(tar_entry(b"d/pipe", b'6', b"", b""));
        // in-tree symlink and hardlink — unpacked.
        t.extend(tar_entry(b"d/sy", b'2', b"f.txt", b""));
        t.extend(tar_entry(b"d/hl-ok", b'1', b"d/f.txt", b""));
        // hardlink to an out-of-tree target — skipped.
        t.extend(tar_entry(b"d/hl-bad", b'1', b"../outside", b""));
        t.resize(t.len() + 1024, 0); // tar end-of-archive blocks
        unpack_tar(&t[..], &dest).unwrap();

        assert_eq!(std::fs::read_to_string(dest.join("d/f.txt")).unwrap(), "hey");
        assert!(dest.join("d/sy").is_symlink());
        assert_eq!(std::fs::read(dest.join("d/hl-ok")).unwrap(), b"hey");
        assert!(!dest.join("d/pipe").exists());
        assert!(!dest.join("d/hl-bad").exists());
        assert!(!dest.join("abs").exists(), "absolute path dropped");
        assert!(
            !dest.parent().unwrap().join("evil").exists()
                && !dest.parent().unwrap().join("evil2").exists(),
            "no .. escapes"
        );
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn whiteouts() {
        let dest = std::env::temp_dir().join(format!("rp-oci-wh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        // Lower-layer content: d/keep, d/gone, opq/{a,b}.
        std::fs::create_dir_all(dest.join("d")).unwrap();
        std::fs::create_dir_all(dest.join("opq")).unwrap();
        std::fs::write(dest.join("d/keep"), b"k").unwrap();
        std::fs::write(dest.join("d/gone"), b"g").unwrap();
        std::fs::write(dest.join("opq/a"), b"a").unwrap();
        std::fs::write(dest.join("opq/b"), b"b").unwrap();

        let mut tw = tar::Builder::new(Vec::new());
        for p in ["d/.wh.gone", "opq/.wh..wh..opq"] {
            let mut hdr = tar::Header::new_gnu();
            hdr.set_entry_type(tar::EntryType::Regular);
            hdr.set_mode(0o644);
            hdr.set_size(0);
            hdr.set_cksum();
            tw.append_data(&mut hdr, p, std::io::empty()).unwrap();
        }
        let tar_bytes = tw.into_inner().unwrap();
        unpack_tar(&tar_bytes[..], &dest).unwrap();

        assert!(dest.join("d/keep").exists());
        assert!(!dest.join("d/gone").exists());
        assert!(dest.join("opq").is_dir());
        assert!(!dest.join("opq/a").exists() && !dest.join("opq/b").exists());
        let _ = std::fs::remove_dir_all(&dest);
    }

    /// A whiteout under an in-rootfs symlink must NOT delete files outside
    /// the rootfs: layer1 plants `d` -> <outside>, layer2 carries
    /// `d/.wh.victim` — the real victim file must survive.
    #[test]
    fn whiteout_symlink_escape() {
        let base = std::env::temp_dir().join(format!("rp-oci-whesc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dest = base.join("rootfs");
        let outside = base.join("wh-escape-target");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("victim"), b"v").unwrap();

        // Layer 1: a symlink pointing out of the rootfs.
        let mut t1 = tar::Builder::new(Vec::new());
        let mut hdr = tar::Header::new_gnu();
        hdr.set_entry_type(tar::EntryType::Symlink);
        hdr.set_mode(0o777);
        hdr.set_size(0);
        t1.append_link(&mut hdr, "d", &outside).unwrap();
        let layer1 = t1.into_inner().unwrap();
        unpack_tar(&layer1[..], &dest).unwrap();
        assert!(dest.join("d").is_symlink());

        // Layer 2: whiteout through that symlink — must be skipped.
        let mut t2 = tar::Builder::new(Vec::new());
        let mut hdr = tar::Header::new_gnu();
        hdr.set_entry_type(tar::EntryType::Regular);
        hdr.set_mode(0o644);
        hdr.set_size(0);
        hdr.set_cksum();
        t2.append_data(&mut hdr, "d/.wh.victim", std::io::empty())
            .unwrap();
        let layer2 = t2.into_inner().unwrap();
        unpack_tar(&layer2[..], &dest).unwrap();

        assert_eq!(
            std::fs::read(outside.join("victim")).unwrap(),
            b"v",
            "whiteout escaped the rootfs through a symlink"
        );
        // The whiteout marker itself must not linger inside the rootfs.
        assert!(!dest.join("d/.wh.victim").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// `pull()` writes etc/machine-id — but never through an image-planted
    /// `etc` symlink pointing outside the rootfs.
    #[test]
    fn machine_id_write_skips_symlinked_etc() {
        let base = std::env::temp_dir().join(format!("rp-oci-mid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dest = base.join("rootfs");
        let outside = base.join("outside-etc");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, dest.join("etc")).unwrap();

        write_machine_id(&dest).unwrap();
        assert!(
            !outside.join("machine-id").exists(),
            "machine-id write followed the etc symlink out of the rootfs"
        );

        // A real etc dir still gets the file.
        let dest2 = base.join("rootfs2");
        std::fs::create_dir_all(&dest2).unwrap();
        write_machine_id(&dest2).unwrap();
        assert_eq!(
            std::fs::read(dest2.join("etc/machine-id")).unwrap(),
            b""
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn config_parsing() {
        let json = r#"{"architecture":"amd64","config":{"Entrypoint":["/bin/sh"],"Cmd":["-c","x"],"Env":["PATH=/bin","BAD"],"WorkingDir":"/app"},"rootfs":{"type":"layers"}}"#;
        let c = parse_config(json);
        assert_eq!(c.entrypoint, vec!["/bin/sh"]);
        assert_eq!(c.cmd, vec!["-c", "x"]);
        assert_eq!(c.env, vec!["PATH=/bin"]); // "BAD" (no '=') dropped
        assert_eq!(c.working_dir, "/app");
        // Missing config object → defaults, not an error.
        let c = parse_config("{}");
        assert!(c.entrypoint.is_empty() && c.working_dir.is_empty());
        let c = parse_config("not json");
        assert!(c.entrypoint.is_empty());
    }
}
