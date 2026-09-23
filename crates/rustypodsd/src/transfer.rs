//! Pod export/import container format (Wave H).
//!
//! A pod archive is one opaque stream:
//!
//!   [8B magic "RPEX0001"][u32 LE manifest_len][manifest JSON][payload]
//!
//! The payload is a btrfs send stream (multiple subvolumes, requires
//! read-only sources) on btrfs hosts, or a tar archive elsewhere. Both
//! use the same entry layout: one top-level entry named after the pod
//! (the rootfs) plus one entry per attached named volume named after
//! the volume. `btrfs receive`/`tar -x` both recreate those names in
//! the staging dir, so the import side is format-agnostic past the
//! unpacker choice.
//!
//! Host-bound state does NOT travel: on import the pod conf is
//! sanitized (net_index → re-allocated at first start, stack/netns and
//! gateway role dropped, started=false). Image confs DO travel — a pod
//! merges its image's entrypoint/env at start, and the image may not
//! exist on the target host (the pod rootfs itself is complete, so the
//! image tree is never sent).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::state::PodMeta;

/// Archive magic + format version, all in one 8-byte tag.
pub const MAGIC: &[u8; 8] = b"RPEX0001";
/// Confs are kilobytes; a megabyte of manifest is already absurd.
pub const MAX_MANIFEST: usize = 1 << 20;
/// Wire chunk size for ExportChunk/ImportChunk data frames.
pub const CHUNK: usize = 1 << 20;

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
}

/// magic+len+manifest — the first archive bytes.
pub fn header(m: &Manifest) -> Result<Vec<u8>> {
    let j = serde_json::to_vec(m).context("encode manifest")?;
    if j.len() > MAX_MANIFEST {
        bail!("manifest {}B exceeds {MAX_MANIFEST}B cap", j.len());
    }
    let mut out = Vec::with_capacity(12 + j.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(j.len() as u32).to_le_bytes());
    out.extend_from_slice(&j);
    Ok(out)
}

/// Parse header+manifest from `buf` (starting at archive offset 0).
/// Ok(None) = need more bytes; Ok(Some((m, off))) = `off` is where the
/// payload begins inside buf.
pub fn parse_header(buf: &[u8]) -> Result<Option<(Manifest, usize)>> {
    if buf.len() < 12 {
        return Ok(None);
    }
    if buf[..8] != *MAGIC {
        bail!("not a rustypods pod archive (bad magic)");
    }
    let len = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
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
    Ok(Some((m, 12 + len)))
}

/// Rewrite an exported PodMeta for THIS host. Everything host-bound is
/// stripped; everything describing the workload is kept verbatim.
pub fn sanitize_import(mut m: PodMeta, rename: Option<&str>) -> Result<PodMeta> {
    if let Some(r) = rename {
        m.name = rustypods_proto::validate_name(r)?.to_string();
    }
    // Runtime-host bindings: net_index re-allocates at first start
    // (two pods may not share a /30); stack netns and the managed
    // gateway are per-host infrastructure.
    m.started = false;
    m.net_index = 0;
    m.stack = String::new();
    m.ingress_gateway = false;
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            format: "btrfs".into(),
            pod_conf: "name = \"web\"\n".into(),
            image_conf: None,
            volume_confs: BTreeMap::new(),
            exported_unix: 1,
        }
    }

    #[test]
    fn header_roundtrip() {
        let mut m = manifest();
        m.volume_confs
            .insert("data".into(), "name = \"data\"\n".into());
        let bytes = header(&m).unwrap();
        assert_eq!(&bytes[..8], MAGIC);
        let (got, off) = parse_header(&bytes).unwrap().unwrap();
        assert_eq!(off, bytes.len());
        assert_eq!(got.format, "btrfs");
        assert_eq!(got.volume_confs.len(), 1);
        // Truncated → incomplete, not an error.
        assert!(parse_header(&bytes[..bytes.len() - 1]).unwrap().is_none());
        assert!(parse_header(&bytes[..5]).unwrap().is_none());
    }

    #[test]
    fn header_rejects_bad_magic_and_oversize() {
        assert!(parse_header(b"XXXX0001rest").is_err());
        let mut buf = MAGIC.to_vec();
        buf.extend_from_slice(&((MAX_MANIFEST as u32 + 1).to_le_bytes()));
        assert!(parse_header(&buf).is_err());
    }

    #[test]
    fn sanitize_strips_host_state() {
        let mut m: PodMeta = toml::from_str(
            r#"name = "web"
image = "nginx"
created_unix = 1
started = true
net_index = 7
stack = "mystack"
ingress_gateway = true
autostart = true
"#,
        )
        .unwrap();
        m = sanitize_import(m, Some("web2")).unwrap();
        assert_eq!(m.name, "web2");
        assert!(!m.started);
        assert_eq!(m.net_index, 0);
        assert_eq!(m.stack, "");
        assert!(!m.ingress_gateway);
        assert!(m.autostart, "workload config must survive");
    }

    #[test]
    fn sanitize_rejects_bad_rename() {
        let m: PodMeta =
            toml::from_str("name = \"web\"\nimage = \"x\"\ncreated_unix = 1\n").unwrap();
        assert!(sanitize_import(m, Some("bad name!")).is_err());
    }
}
