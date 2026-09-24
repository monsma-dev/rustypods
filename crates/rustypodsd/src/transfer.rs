//! Pod export/import container format (Wave H).
//!
//! A pod archive is one opaque stream. New archives are version 2:
//!
//!   [8B magic "RPEX0002"][u32 LE manifest_len][manifest JSON]
//!   [payload][8B "RPEXEND1"][u64 LE payload_len][32B SHA-256(payload)]
//!
//! Version 1 (`RPEX0001`, no trailer) still loads, with a warning that
//! nothing checked the payload bytes.
//!
//! The payload is a btrfs send stream (multiple subvolumes, requires
//! read-only sources) on btrfs hosts, or a tar archive elsewhere. Both
//! use the same entry layout: one top-level entry named after the pod
//! (the rootfs) plus one entry per attached named volume named after
//! the volume. `btrfs receive`/`tar -x` both recreate those names in
//! the staging dir, so the import side is format-agnostic past the
//! unpacker choice.
//!
//! Host-bound state does NOT travel. Without `--trust` the pod conf is
//! also stripped of host-root grants (binds, published ports, host
//! access, autostart, restart, healthchecks, pod env, user namespace
//! off). `--trust` keeps the exported conf aside from per-host net
//! state. Image confs DO travel — a pod merges its image's
//! entrypoint/env at start, and the image may not exist on the target
//! host (the pod rootfs itself is complete, so the image tree is never
//! sent).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::state::PodMeta;

/// Version 1: header + manifest + payload, no integrity trailer.
pub const MAGIC_V1: &[u8; 8] = b"RPEX0001";
/// Version 2: header + manifest + payload + trailer.
pub const MAGIC_V2: &[u8; 8] = b"RPEX0002";
/// Magic written by [`header`].
pub const MAGIC: &[u8; 8] = MAGIC_V2;
/// Trailer tag. 8 + 8 + 32 = [`TRAILER_LEN`].
pub const TRAILER_MAGIC: &[u8; 8] = b"RPEXEND1";
pub const TRAILER_LEN: usize = 48;
/// Confs are kilobytes; a megabyte of manifest is already absurd.
pub const MAX_MANIFEST: usize = 1 << 20;
/// Wire chunk size for ExportChunk/ImportChunk data frames.
pub const CHUNK: usize = 1 << 20;
/// Default cap on payload bytes accepted by import (64 GiB).
pub const DEFAULT_IMPORT_MAX_BYTES: u64 = 64 << 30;

/// Bounded stderr captured from `btrfs send` / `tar` so a stuck pipe
/// cannot grow without limit and a failure still has a reason.
pub const STDERR_CAP: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// "btrfs" | "tar" — how to interpret the payload bytes.
    pub format: String,
    /// PodMeta TOML, as persisted under conf/pods/.
    pub pod_conf: String,
    /// ImageMeta TOML when the pod references an OCI image. The image
    /// rootfs is never sent — the pod rootfs is already complete — but
    /// the conf carries entrypoint/cmd/env/workdir needed at start.
    #[serde(default)]
    pub image_conf: Option<String>,
    /// name → VolumeMeta TOML for every attached named volume.
    #[serde(default)]
    pub volume_confs: BTreeMap<String, String>,
    #[serde(default)]
    pub exported_unix: u64,
    /// Operator-visible notes recorded at export (freeze missed, …).
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Parsed archive header. `version` is 1 or 2; only 2 has a trailer.
#[derive(Debug, Clone)]
pub struct ParsedHeader {
    pub manifest: Manifest,
    pub payload_off: usize,
    pub version: u8,
}

/// magic+len+manifest — the first archive bytes. Always version 2.
pub fn header(m: &Manifest) -> Result<Vec<u8>> {
    let j = serde_json::to_vec(m).context("encode manifest")?;
    if j.len() > MAX_MANIFEST {
        bail!("manifest {}B exceeds {MAX_MANIFEST}B cap", j.len());
    }
    let mut out = Vec::with_capacity(12 + j.len());
    out.extend_from_slice(MAGIC_V2);
    out.extend_from_slice(&(j.len() as u32).to_le_bytes());
    out.extend_from_slice(&j);
    Ok(out)
}

/// Parse header+manifest from `buf` (starting at archive offset 0).
/// Ok(None) = need more bytes.
pub fn parse_header(buf: &[u8]) -> Result<Option<ParsedHeader>> {
    if buf.len() < 12 {
        return Ok(None);
    }
    let version = if buf[..8] == *MAGIC_V1 {
        1
    } else if buf[..8] == *MAGIC_V2 {
        2
    } else {
        bail!("not a rustypods pod archive (bad magic)");
    };
    let mut len_b = [0u8; 4];
    len_b.copy_from_slice(&buf[8..12]);
    let len = u32::from_le_bytes(len_b) as usize;
    if len > MAX_MANIFEST {
        bail!("manifest {len}B exceeds {MAX_MANIFEST}B cap");
    }
    if buf.len() < 12 + len {
        return Ok(None);
    }
    let m: Manifest = serde_json::from_slice(&buf[12..12 + len]).context("decode manifest")?;
    match m.format.as_str() {
        "btrfs" | "tar" => {}
        f => bail!("unknown payload format '{f}'"),
    }
    Ok(Some(ParsedHeader {
        manifest: m,
        payload_off: 12 + len,
        version,
    }))
}

/// `RPEXEND1` + payload length + SHA-256 of the payload bytes only
/// (not the header, not the trailer).
pub fn encode_trailer(payload_len: u64, digest: &[u8; 32]) -> [u8; TRAILER_LEN] {
    let mut out = [0u8; TRAILER_LEN];
    out[..8].copy_from_slice(TRAILER_MAGIC);
    out[8..16].copy_from_slice(&payload_len.to_le_bytes());
    out[16..48].copy_from_slice(digest);
    out
}

pub fn decode_trailer(buf: &[u8]) -> Result<(u64, [u8; 32])> {
    if buf.len() != TRAILER_LEN {
        bail!(
            "integrity trailer is {} bytes, expected {TRAILER_LEN}",
            buf.len()
        );
    }
    if buf[..8] != *TRAILER_MAGIC {
        bail!("archive truncated or corrupt: bad trailer magic");
    }
    let mut len_b = [0u8; 8];
    len_b.copy_from_slice(&buf[8..16]);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&buf[16..48]);
    Ok((u64::from_le_bytes(len_b), digest))
}

/// Running SHA-256 of payload bytes, used on the export side.
#[derive(Clone)]
pub struct PayloadHasher {
    hasher: Sha256,
    len: u64,
}

impl PayloadHasher {
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.len += data.len() as u64;
    }

    pub fn trailer(&self) -> [u8; TRAILER_LEN] {
        let digest: [u8; 32] = self.hasher.clone().finalize().into();
        encode_trailer(self.len, &digest)
    }
}

impl Default for PayloadHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Import-side accumulator. Version 2 holds back the last
/// [`TRAILER_LEN`] bytes so they are never treated as payload. `push`
/// returns the bytes that are definitely payload and should be written
/// to the staging file.
pub struct PayloadWriter {
    version: u8,
    hasher: Sha256,
    len: u64,
    /// Every byte seen on the stream, including a version-2 trailer.
    seen: u64,
    tail: Vec<u8>,
    max: u64,
}

impl PayloadWriter {
    pub fn new(version: u8, max_bytes: u64) -> Self {
        Self {
            version,
            hasher: Sha256::new(),
            len: 0,
            seen: 0,
            tail: Vec::new(),
            max: max_bytes,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        // Count as the bytes arrive. Version 2 may still be holding the
        // trailer, so the budget is payload cap + one trailer.
        let budget = if self.version >= 2 {
            self.max.saturating_add(TRAILER_LEN as u64)
        } else {
            self.max
        };
        self.seen = self.seen.saturating_add(chunk.len() as u64);
        if self.seen > budget {
            bail!(
                "import payload exceeds cap of {} bytes (RUSTYPODS_IMPORT_MAX_BYTES)",
                self.max
            );
        }
        if self.version < 2 {
            self.hasher.update(chunk);
            self.len += chunk.len() as u64;
            return Ok(chunk.to_vec());
        }
        self.tail.extend_from_slice(chunk);
        if self.tail.len() <= TRAILER_LEN {
            return Ok(Vec::new());
        }
        let emit = self.tail.len() - TRAILER_LEN;
        let out = self.tail[..emit].to_vec();
        self.tail.drain(..emit);
        self.hasher.update(&out);
        self.len += out.len() as u64;
        Ok(out)
    }

    pub fn payload_len(&self) -> u64 {
        self.len
    }

    /// Finish the stream. Version 1 has no trailer (caller should warn).
    /// Version 2 checks magic, length and digest before any commit.
    pub fn finish(&self) -> Result<()> {
        if self.version < 2 {
            return Ok(());
        }
        if self.tail.len() != TRAILER_LEN {
            bail!(
                "archive truncated: integrity trailer missing ({} bytes at end, expected {TRAILER_LEN})",
                self.tail.len()
            );
        }
        let (claimed, digest) = decode_trailer(&self.tail)?;
        let got: [u8; 32] = self.hasher.clone().finalize().into();
        if claimed != self.len || digest != got {
            bail!(
                "archive integrity check failed (payload {} bytes, trailer claims {claimed})",
                self.len
            );
        }
        Ok(())
    }
}

/// `RUSTYPODS_IMPORT_MAX_BYTES`, or [`DEFAULT_IMPORT_MAX_BYTES`] when
/// unset, empty, or not a positive integer.
pub fn import_max_bytes() -> u64 {
    match std::env::var("RUSTYPODS_IMPORT_MAX_BYTES") {
        Ok(s) => s.parse::<u64>().ok().filter(|n| *n > 0),
        Err(_) => None,
    }
    .unwrap_or(DEFAULT_IMPORT_MAX_BYTES)
}

/// `requested` is `""` (auto), `"tar"`, or `"btrfs"`. Returns whether
/// the payload should be a btrfs send stream.
pub fn export_uses_btrfs(requested: &str, host_is_btrfs: bool) -> Result<bool> {
    match requested {
        "" => Ok(host_is_btrfs),
        "tar" => Ok(false),
        "btrfs" if host_is_btrfs => Ok(true),
        "btrfs" => bail!("--format btrfs requires a btrfs data directory"),
        other => bail!("unknown export format '{other}' (expected tar or btrfs)"),
    }
}

/// btrfs-send payloads cannot be received on XFS/ext4. Fail before the
/// payload is written so the operator gets the tar suggestion immediately.
pub fn reject_incompatible_payload(archive_format: &str, host_storage: &str) -> Result<()> {
    if archive_format == "btrfs" && host_storage != "btrfs" {
        bail!(
            "archive payload is a btrfs send stream, but this host's storage is {host_storage} — re-export with `rustypods export <pod> --format tar`"
        );
    }
    Ok(())
}

/// GNU tar create flags: numeric ids, every xattr, POSIX ACLs.
/// Shell quotes around `*` are not part of the argv.
pub fn tar_create_flags() -> &'static [&'static str] {
    &[
        "--numeric-owner",
        "--xattrs",
        "--xattrs-include=*",
        "--acls",
    ]
}

/// GNU tar extract flags. Leading `/` is stripped by GNU tar unless
/// `--absolute-names` is passed — we never pass it. `--no-overwrite-dir`
/// keeps metadata of directories that already exist in staging.
/// `--no-same-permissions` is intentionally absent: a rootfs needs the
/// setuid bits the image shipped (sudo, ping). Device nodes are a
/// separate filter ([`entry_allowed`]), not a permission flag.
pub fn tar_extract_flags() -> &'static [&'static str] {
    &[
        "--numeric-owner",
        "--xattrs",
        "--xattrs-include=*",
        "--acls",
        "--no-overwrite-dir",
    ]
}

/// Character, block and fifo nodes are skipped unless the archive is
/// `--trust`ed. nspawn supplies /dev; a device node in an untrusted
/// rootfs is a host-root primitive (`mknod`).
pub fn entry_allowed(kind: tar::EntryType, trust: bool) -> bool {
    match kind {
        tar::EntryType::Regular
        | tar::EntryType::Directory
        | tar::EntryType::Symlink
        | tar::EntryType::Link => true,
        tar::EntryType::Char | tar::EntryType::Block | tar::EntryType::Fifo => trust,
        _ => false,
    }
}

/// Extract a tar payload into `dest`. Untrusted archives skip device
/// nodes and fifos. Paths that escape `dest` are skipped (`unpack_in`).
/// Ownership is preserved only when the process may chown; tests run
/// unprivileged and still check modes and skips.
pub fn unpack_tar_payload<R: Read>(reader: R, dest: &Path, trust: bool) -> Result<()> {
    let mut ar = tar::Archive::new(reader);
    ar.set_preserve_ownerships(crate::euid() == 0);
    ar.set_preserve_permissions(true);
    let dest = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());
    for ent in ar.entries()? {
        let mut ent = ent?;
        let kind = ent.header().entry_type();
        if !entry_allowed(kind, trust) {
            tracing::warn!("skipping {:?} tar entry (untrusted import)", kind);
            continue;
        }
        if matches!(kind, tar::EntryType::Link) {
            let ok = ent
                .link_name_bytes()
                .map(|b| tar_path_stays_inside(&b))
                .unwrap_or(false);
            if !ok {
                tracing::warn!("skipping hardlink with out-of-tree target");
                continue;
            }
        }
        let rel = ent.path_bytes();
        if !tar_path_stays_inside(&rel) {
            tracing::warn!("skipping tar path that escapes staging");
            continue;
        }
        if !ent.unpack_in(&dest).context("untar entry")? {
            tracing::warn!("skipping entry escaping dest");
        }
    }
    Ok(())
}

fn tar_path_stays_inside(raw: &[u8]) -> bool {
    let s = String::from_utf8_lossy(raw);
    let p = Path::new(s.as_ref());
    if p.is_absolute() {
        return false;
    }
    !p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
}

/// What [`sanitize_import`] removed or forced. Printed by the CLI and
/// returned on the import response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SanitizeReport {
    pub notes: Vec<String>,
}

/// Rewrite an exported PodMeta for THIS host.
///
/// Always: started=false, net_index=0, stack cleared, ingress gateway
/// dropped — those are per-host.
///
/// `trust == false` (default): also force `private_users`, drop binds,
/// ports, ingress, host_access, autostart, restart policy, healthcheck
/// and pod-level env. The image conf's env still applies at start.
/// `trust == true` keeps the exported workload conf.
pub fn sanitize_import(
    mut m: PodMeta,
    rename: Option<&str>,
    trust: bool,
) -> Result<(PodMeta, SanitizeReport)> {
    let mut notes = Vec::new();
    if let Some(r) = rename {
        m.name = rustypods_proto::validate_name(r)?.to_string();
    }
    if m.started {
        notes.push("started reset (pod is imported stopped)".into());
    }
    m.started = false;
    if m.net_index != 0 {
        notes.push(format!(
            "net_index {} dropped (addresses are per-host)",
            m.net_index
        ));
    }
    m.net_index = 0;
    if !m.stack.is_empty() {
        notes.push(format!("stack '{}' dropped (netns is per-host)", m.stack));
    }
    m.stack = String::new();
    if m.ingress_gateway {
        notes.push("ingress_gateway cleared (run init-ingress on this host)".into());
    }
    m.ingress_gateway = false;

    if !trust {
        if !m.private_users {
            notes.push("private_users forced on (archive had user-namespace off)".into());
        }
        m.private_users = true;
        if !m.binds.is_empty() {
            notes.push(format!("binds removed ({})", m.binds.join(", ")));
            m.binds.clear();
        }
        if !m.ports.is_empty() {
            notes.push(format!("ports removed ({})", m.ports.join(", ")));
            m.ports.clear();
        }
        if !m.ingress.is_empty() {
            notes.push("ingress rules removed".into());
            m.ingress.clear();
        }
        if m.host_access {
            notes.push("host_access cleared".into());
        }
        m.host_access = false;
        if m.autostart {
            notes.push("autostart cleared".into());
        }
        m.autostart = false;
        if !m.restart.is_empty() && m.restart != "no" {
            notes.push(format!("restart policy '{}' cleared", m.restart));
        }
        m.restart = String::new();
        if !m.healthcheck.kind.is_empty() {
            notes.push(format!("healthcheck '{}' removed", m.healthcheck.kind));
        }
        m.healthcheck = Default::default();
        if !m.env.is_empty() {
            notes.push(format!(
                "pod env removed ({} keys); image env still applies at start",
                m.env.len()
            ));
            m.env.clear();
        }
        notes.push("untrusted import: pass --trust to keep the exported conf".into());
    }
    Ok((m, SanitizeReport { notes }))
}

static STAGING_SEQ: AtomicU64 = AtomicU64::new(1);

/// `.import-<pid>-<counter>-<8 hex>` / `.export-…`. The counter plus
/// urandom suffix cannot collide inside one second the way
/// `.import-<unix>` did.
pub fn unique_staging_name(kind: &str) -> String {
    let n = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
    format!(".{kind}-{}-{n}-{}", std::process::id(), rand_suffix())
}

fn rand_suffix() -> String {
    let mut b = [0u8; 4];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if std::io::Read::read_exact(&mut f, &mut b).is_ok() {
            return b.iter().map(|x| format!("{x:02x}")).collect();
        }
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{nanos:08x}")
}

pub fn is_staging_dir_name(name: &str) -> bool {
    name.strip_prefix(".import-")
        .or_else(|| name.strip_prefix(".export-"))
        .is_some_and(|rest| !rest.is_empty())
}

/// Delete `.import-*` / `.export-*` directories under `data_dir` whose
/// mtime is strictly before `before`. Symlinks are logged and left
/// alone so a planted link cannot redirect the delete.
pub fn sweep_stale_before(data_dir: &Path, before: SystemTime) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    let Ok(rd) = std::fs::read_dir(data_dir) else {
        return removed;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_staging_dir_name(name) {
            continue;
        }
        let path = e.path();
        let Ok(md) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if md.file_type().is_symlink() {
            tracing::warn!(
                "refusing to sweep staging symlink {} (not a directory)",
                path.display()
            );
            continue;
        }
        if !md.is_dir() {
            continue;
        }
        let Ok(modified) = md.modified() else {
            continue;
        };
        if modified >= before {
            continue;
        }
        tracing::warn!("removing stale staging dir {}", path.display());
        remove_tree(&path);
        removed.push(path);
    }
    removed
}

fn remove_tree(dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            // Received subvolumes refuse rmdir. Best-effort; missing
            // `btrfs` (non-btrfs hosts, unit tests) just falls through.
            let _ = std::process::Command::new("btrfs")
                .args(["subvolume", "delete", "--"])
                .arg(&p)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            if p.is_dir() {
                remove_tree(&p);
            } else {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Startup sweep: anything older than this process is leftover from a
/// daemon that died mid-export/import.
pub fn sweep_stale_staging(data_dir: &Path) -> Vec<PathBuf> {
    let before = process_start().unwrap_or_else(SystemTime::now);
    sweep_stale_before(data_dir, before)
}

fn process_start() -> Option<SystemTime> {
    // /proc/self/stat field 22 is starttime in clock ticks. `comm` may
    // contain spaces, so the count starts after the last ')'.
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let after = stat.rfind(')')?;
    let fields: Vec<&str> = stat[after + 1..].split_whitespace().collect();
    // field 22 → index 19 once field 3 (state) is index 0
    let ticks: u64 = fields.get(19)?.parse().ok()?;
    let up = std::fs::read_to_string("/proc/uptime").ok()?;
    let up_secs: f64 = up.split_whitespace().next()?.parse().ok()?;
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz <= 0 {
        return None;
    }
    let boot = SystemTime::now().checked_sub(std::time::Duration::from_secs_f64(up_secs))?;
    boot.checked_add(std::time::Duration::from_secs_f64(ticks as f64 / hz as f64))
}

/// Write `"0"` to a cgroup.freeze file, retrying a few times. Returns
/// false when every attempt failed — the caller logs that loudly.
pub fn unfreeze_cgroup(path: &Path, attempts: u32) -> bool {
    let n = attempts.max(1);
    for i in 0..n {
        if std::fs::write(path, "0").is_ok() {
            return true;
        }
        if i + 1 < n {
            std::thread::sleep(std::time::Duration::from_millis(20 * (i as u64 + 1)));
        }
    }
    false
}

/// Append to a capped byte buffer. Extra bytes are dropped.
pub fn push_capped(buf: &mut Vec<u8>, data: &[u8], cap: usize) {
    let room = cap.saturating_sub(buf.len());
    if room == 0 {
        return;
    }
    let n = data.len().min(room);
    buf.extend_from_slice(&data[..n]);
}

/// Read all of `r` into at most `cap` bytes.
pub fn read_capped<R: Read>(r: &mut R, cap: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 512];
    loop {
        match r.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => push_capped(&mut buf, &tmp[..n], cap),
        }
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn manifest() -> Manifest {
        Manifest {
            format: "btrfs".into(),
            pod_conf: "name = \"web\"\n".into(),
            image_conf: None,
            volume_confs: BTreeMap::new(),
            exported_unix: 1,
            warnings: Vec::new(),
        }
    }

    fn sample_pod() -> PodMeta {
        toml::from_str(
            r#"name = "web"
image = "nginx"
created_unix = 1
started = true
net_index = 7
stack = "mystack"
ingress_gateway = true
autostart = true
private_users = false
host_access = true
restart = "always"
binds = ["/root:/root", "/home"]
ports = ["127.0.0.1:8080:80"]
env = ["SECRET=1", "OTHER=2"]
cmd = ["nginx"]

[healthcheck]
kind = "exec"
argv = ["/bin/true"]
"#,
        )
        .unwrap()
    }

    #[test]
    fn header_roundtrip_v2() {
        let mut m = manifest();
        m.volume_confs
            .insert("data".into(), "name = \"data\"\n".into());
        m.warnings.push("freeze failed".into());
        let bytes = header(&m).unwrap();
        assert_eq!(&bytes[..8], MAGIC_V2);
        let got = parse_header(&bytes).unwrap().unwrap();
        assert_eq!(got.payload_off, bytes.len());
        assert_eq!(got.version, 2);
        assert_eq!(got.manifest.format, "btrfs");
        assert_eq!(got.manifest.volume_confs.len(), 1);
        assert_eq!(got.manifest.warnings, vec!["freeze failed".to_string()]);
        assert!(parse_header(&bytes[..bytes.len() - 1]).unwrap().is_none());
        assert!(parse_header(&bytes[..5]).unwrap().is_none());
    }

    #[test]
    fn header_still_reads_v1() {
        let m = manifest();
        let j = serde_json::to_vec(&m).unwrap();
        let mut bytes = MAGIC_V1.to_vec();
        bytes.extend_from_slice(&(j.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&j);
        let got = parse_header(&bytes).unwrap().unwrap();
        assert_eq!(got.version, 1);
        assert_eq!(got.manifest.format, "btrfs");
    }

    #[test]
    fn header_rejects_bad_magic_and_oversize() {
        assert!(parse_header(b"XXXX0001rest").is_err());
        let mut buf = MAGIC_V2.to_vec();
        buf.extend_from_slice(&((MAX_MANIFEST as u32 + 1).to_le_bytes()));
        assert!(parse_header(&buf).is_err());
    }

    #[test]
    fn trailer_roundtrip_and_mismatch() {
        let payload = b"hello payload";
        let mut h = PayloadHasher::new();
        h.update(payload);
        let t = h.trailer();
        assert_eq!(&t[..8], TRAILER_MAGIC);
        let (len, dig) = decode_trailer(&t).unwrap();
        assert_eq!(len, payload.len() as u64);
        assert_eq!(dig.len(), 32);

        let mut w = PayloadWriter::new(2, DEFAULT_IMPORT_MAX_BYTES);
        let mut stored = w.push(payload).unwrap();
        stored.extend(w.push(&t).unwrap());
        assert_eq!(stored, payload);
        w.finish().unwrap();

        let mut bad = t;
        bad[20] ^= 0xff;
        let mut w = PayloadWriter::new(2, DEFAULT_IMPORT_MAX_BYTES);
        let _ = w.push(payload).unwrap();
        let _ = w.push(&bad).unwrap();
        assert!(w.finish().is_err());

        let mut trunc = PayloadWriter::new(2, DEFAULT_IMPORT_MAX_BYTES);
        let _ = trunc.push(payload).unwrap();
        assert!(trunc.finish().is_err(), "missing trailer must fail");
    }

    #[test]
    fn v1_writer_has_no_trailer() {
        let mut w = PayloadWriter::new(1, 100);
        let out = w.push(b"abc").unwrap();
        assert_eq!(out, b"abc");
        w.finish().unwrap();
    }

    #[test]
    fn payload_cap_counts_streamed_bytes() {
        let mut w = PayloadWriter::new(1, 4);
        assert!(w.push(b"1234").is_ok());
        assert!(w.push(b"x").is_err());
        let mut w = PayloadWriter::new(2, 4);
        // trailer is not payload, so 4 payload bytes + trailer fits
        let mut h = PayloadHasher::new();
        h.update(b"1234");
        let stored = w.push(b"1234").unwrap();
        assert!(stored.is_empty() || stored.len() <= 4);
        let more = w.push(&h.trailer()).unwrap();
        let mut all = stored;
        all.extend(more);
        assert_eq!(all, b"1234");
        w.finish().unwrap();
        let mut over = PayloadWriter::new(2, 3);
        let err = over
            .push(&[0u8; 4 + TRAILER_LEN])
            .expect_err("cap must trip as bytes arrive");
        assert!(err.to_string().contains("exceeds cap"));
    }

    #[test]
    fn export_format_override() {
        assert!(export_uses_btrfs("", true).unwrap());
        assert!(!export_uses_btrfs("", false).unwrap());
        assert!(!export_uses_btrfs("tar", true).unwrap());
        assert!(export_uses_btrfs("btrfs", false).is_err());
        assert!(export_uses_btrfs("zip", true).is_err());
    }

    #[test]
    fn btrfs_archive_rejected_on_other_fs() {
        assert!(reject_incompatible_payload("btrfs", "xfs").is_err());
        assert!(reject_incompatible_payload("tar", "xfs").is_ok());
        assert!(reject_incompatible_payload("btrfs", "btrfs").is_ok());
    }

    #[test]
    fn tar_flags_cover_ownership_xattrs_acls() {
        let c = tar_create_flags().join(" ");
        assert!(c.contains("--numeric-owner"));
        assert!(c.contains("--xattrs-include=*"));
        assert!(c.contains("--acls"));
        let e = tar_extract_flags().join(" ");
        assert!(e.contains("--numeric-owner"));
        assert!(e.contains("--no-overwrite-dir"));
        assert!(!e.contains("--absolute-names"));
        assert!(!e.contains("--no-same-permissions"));
    }

    #[test]
    fn special_entries_skipped_unless_trusted() {
        assert!(!entry_allowed(tar::EntryType::Fifo, false));
        assert!(!entry_allowed(tar::EntryType::Char, false));
        assert!(!entry_allowed(tar::EntryType::Block, false));
        assert!(entry_allowed(tar::EntryType::Fifo, true));
        assert!(entry_allowed(tar::EntryType::Regular, false));
    }

    #[test]
    fn untrusted_unpack_skips_fifo_and_dotdot() {
        let base = std::env::temp_dir().join(format!("rp-xfer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let dest = base.join("stage");
        std::fs::create_dir_all(&dest).unwrap();
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("marker"), b"keep").unwrap();

        let mut t = tar::Builder::new(Vec::new());
        let mut file = tar::Header::new_gnu();
        file.set_entry_type(tar::EntryType::Regular);
        file.set_mode(0o644);
        file.set_size(3);
        file.set_cksum();
        t.append_data(&mut file, "pod/hello", std::io::Cursor::new(b"abc"))
            .unwrap();
        let mut fifo = tar::Header::new_gnu();
        fifo.set_entry_type(tar::EntryType::Fifo);
        fifo.set_mode(0o644);
        fifo.set_size(0);
        fifo.set_cksum();
        t.append_data(&mut fifo, "pod/pipe", std::io::empty())
            .unwrap();
        let mut esc = tar::Header::new_gnu();
        esc.set_entry_type(tar::EntryType::Regular);
        esc.set_mode(0o644);
        esc.set_size(1);
        esc.set_cksum();
        t.append_data(&mut esc, "pod/ok", std::io::Cursor::new(b"x"))
            .unwrap();
        let mut bytes = t.into_inner().unwrap();
        // Builder refuses `..` at append time. Patch the `pod/ok` header
        // name (ustar name is the first 100 bytes) and recompute cksum.
        let evil = b"pod/../../outside/pwn";
        let hdr_at = bytes
            .windows(b"pod/ok".len())
            .position(|w| w == b"pod/ok")
            .expect("pod/ok header");
        bytes[hdr_at..hdr_at + 100].fill(0);
        bytes[hdr_at..hdr_at + evil.len()].copy_from_slice(evil);
        bytes[hdr_at + 148..hdr_at + 156].fill(b' ');
        let sum: u32 = bytes[hdr_at..hdr_at + 512].iter().map(|b| *b as u32).sum();
        let ck = format!("{sum:06o}\0 ");
        bytes[hdr_at + 148..hdr_at + 156].copy_from_slice(ck.as_bytes());
        unpack_tar_payload(Cursor::new(bytes), &dest, false).unwrap();
        assert_eq!(std::fs::read(dest.join("pod/hello")).unwrap(), b"abc");
        assert!(!dest.join("pod/pipe").exists());
        assert_eq!(std::fs::read(outside.join("marker")).unwrap(), b"keep");
        assert!(!outside.join("pwn").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn sanitize_untrusted_strips_host_root_grants() {
        let (m, report) = sanitize_import(sample_pod(), Some("web2"), false).unwrap();
        assert_eq!(m.name, "web2");
        assert!(!m.started);
        assert_eq!(m.net_index, 0);
        assert!(m.stack.is_empty());
        assert!(!m.ingress_gateway);
        assert!(m.private_users);
        assert!(m.binds.is_empty());
        assert!(m.ports.is_empty());
        assert!(!m.host_access);
        assert!(!m.autostart);
        assert!(m.restart.is_empty());
        assert!(m.healthcheck.kind.is_empty());
        assert!(m.env.is_empty());
        assert_eq!(m.cmd, vec!["nginx".to_string()]);
        let text = report.notes.join("\n");
        assert!(text.contains("binds removed"));
        assert!(text.contains("--trust"));
    }

    #[test]
    fn sanitize_trust_keeps_workload_conf() {
        let (m, report) = sanitize_import(sample_pod(), None, true).unwrap();
        assert_eq!(m.name, "web");
        assert!(!m.started);
        assert_eq!(m.net_index, 0);
        assert!(!m.private_users);
        assert_eq!(m.binds.len(), 2);
        assert!(m.autostart);
        assert_eq!(m.env.len(), 2);
        assert!(!report.notes.iter().any(|n| n.contains("binds removed")));
    }

    #[test]
    fn sanitize_rejects_bad_rename() {
        let m: PodMeta =
            toml::from_str("name = \"web\"\nimage = \"x\"\ncreated_unix = 1\n").unwrap();
        assert!(sanitize_import(m, Some("bad name!"), false).is_err());
    }

    #[test]
    fn staging_names_are_unique_and_recognized() {
        let a = unique_staging_name("import");
        let b = unique_staging_name("import");
        assert_ne!(a, b);
        assert!(is_staging_dir_name(&a));
        assert!(is_staging_dir_name(".export-1"));
        assert!(!is_staging_dir_name(".import-"));
        assert!(!is_staging_dir_name("pods"));
        assert!(!is_staging_dir_name(".import"));
    }

    #[test]
    fn sweep_removes_only_old_staging_dirs() {
        let base = std::env::temp_dir().join(format!("rp-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join(".import-old")).unwrap();
        std::fs::create_dir_all(base.join(".export-old")).unwrap();
        std::fs::create_dir_all(base.join("pods")).unwrap();
        std::fs::write(base.join(".import-file"), b"x").unwrap();
        let old = base.join(".import-old");
        let f = std::fs::File::open(&old).unwrap();
        f.set_modified(UNIX_EPOCH).unwrap();
        let old_e = base.join(".export-old");
        std::fs::File::open(&old_e)
            .unwrap()
            .set_modified(UNIX_EPOCH)
            .unwrap();
        let removed = sweep_stale_before(&base, SystemTime::now());
        assert!(removed.iter().any(|p| p.ends_with(".import-old")));
        assert!(removed.iter().any(|p| p.ends_with(".export-old")));
        assert!(!base.join(".import-old").exists());
        assert!(base.join("pods").is_dir());
        assert!(base.join(".import-file").is_file());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn unfreeze_rewrites_freeze_file() {
        let p = std::env::temp_dir().join(format!("rp-freeze-{}", std::process::id()));
        std::fs::write(&p, "1").unwrap();
        assert!(unfreeze_cgroup(&p, 3));
        assert_eq!(std::fs::read(&p).unwrap(), b"0");
        let missing = std::env::temp_dir().join(format!(
            "rp-freeze-missing-{}-nosuch/cgroup.freeze",
            std::process::id()
        ));
        assert!(!unfreeze_cgroup(&missing, 1));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn capped_read_stops() {
        let mut c = Cursor::new(vec![1u8, 2, 3, 4, 5]);
        let b = read_capped(&mut c, 3);
        assert_eq!(b, vec![1, 2, 3]);
    }
}
