//! Stack definitions — `rustypods apply stack.toml`.
//!
//! A stack is a set of pods that share ONE named network namespace
//! (rustypods-<stack>), the Kubernetes pod model: members reach each other
//! on 127.0.0.1 and publish ports through the stack's single IP.
//!
//! ```toml
//! name = "demo"
//!
//! [pods.web]
//! image = "arch-base"
//! ports = ["8080:80"]
//!
//! [pods.db]
//! image = "arch-base"
//! storage_max = "5G"
//!
//! [pods.db.limits]
//! memory_max = "1G"
//! ```

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::state::LimitsSpec;

#[derive(Debug, Deserialize)]
pub struct StackDef {
    pub name: String,
    #[serde(default)]
    pub pods: BTreeMap<String, StackPod>,
}

#[derive(Debug, Deserialize)]
pub struct StackPod {
    pub image: String,
    /// "hostPort:podPort[/proto]" — published on the shared stack IP.
    #[serde(default)]
    pub ports: Vec<String>,
    /// Btrfs quota cap on this member's rootfs, e.g. "5G".
    #[serde(rename = "storage_max", default, with = "crate::state::bytes_field")]
    pub storage_max_bytes: u64,
    #[serde(default)]
    pub limits: LimitsSpec,
    /// Snapshot GC: keep at most N commits (0 = unlimited).
    #[serde(default)]
    pub snap_keep_last: u32,
    /// Snapshot GC: drop commits older than this, e.g. "7d" (0 = unlimited).
    #[serde(
        rename = "snap_max_age",
        default,
        with = "crate::state::duration_field"
    )]
    pub snap_max_age_secs: u64,
    /// Payload override for this member — replaces the image
    /// entrypoint+cmd and forces non-boot mode.
    #[serde(default)]
    pub cmd: Vec<String>,
    /// Ingress rules, "<host>.rustypods.localhost:<port>". Hostnames must
    /// be unique across all members of the stack AND all other pods.
    #[serde(default)]
    pub ingress: Vec<String>,
    /// Pod-level env "KEY=value" — merged over the image env at start.
    #[serde(default)]
    pub env: Vec<String>,
    /// Named-volume mounts "name:/pod/path[:ro]".
    #[serde(default)]
    pub volumes: Vec<String>,
    /// Let this member open connections to host-local addresses.
    #[serde(default)]
    pub host_access: bool,
    /// Drop forwarded traffic between this member and other pod veths.
    #[serde(default)]
    pub isolated: bool,
    /// Mesh placement: a peer name/pubkey/prefix from `mesh status`.
    /// Handled entirely CLI-side — the CLI fans the stack out over the
    /// cluster plane and sends each daemon a rewritten toml without this
    /// key. Daemons reject a toml that still carries it.
    #[serde(default)]
    pub placement: Option<String>,
    /// `pinned` (default) stays on the host that created it. `movable`
    /// may be restarted on the surviving host after a quorum failure
    /// of its own host. A volume, published port, ingress name, or
    /// host socket cannot be movable.
    #[serde(default)]
    pub ha: crate::ha::HaMode,
    /// `snapshot` is a local Btrfs copy and does not survive a lost
    /// datacenter. `mesh` means this member replicates its own bytes
    /// over the mesh (MySQL, Postgres). RustyPods does not copy them.
    #[serde(default)]
    pub replicates: crate::ha::Replication,
    /// DNS name shared by a primary and its mesh replica. Traffic
    /// follows whichever of them is on a live host.
    #[serde(default)]
    pub serves: Option<String>,
    /// When several members `serve` one name and more than one host
    /// is alive, this one wins.
    #[serde(default)]
    pub primary: bool,
}

/// Full pod name of a stack member: <stack>-<member>.
pub fn member_name(stack: &str, member: &str) -> String {
    format!("{stack}-{member}")
}

/// Parse + validate a stack.toml. Every member's image is checked against
/// `image_exists`; host ports must be unique across the whole stack (they
/// all DNAT to the same shared IP).
pub fn parse(toml_text: &str, image_exists: impl Fn(&str) -> bool) -> Result<StackDef> {
    let def: StackDef = toml::from_str(toml_text).context("parsing stack.toml")?;
    rustypods_proto::validate_name(&def.name)
        .with_context(|| format!("invalid stack name '{}'", def.name))?;
    if def.pods.is_empty() {
        bail!(
            "stack '{}' has no pods — add a [pods.<name>] table",
            def.name
        );
    }
    let mut host_ports: BTreeSet<(String, u16, &'static str)> = BTreeSet::new();
    let mut ingress_hosts: BTreeSet<String> = BTreeSet::new();
    for (member, p) in &def.pods {
        let full = member_name(&def.name, member);
        rustypods_proto::validate_name(&full)
            .with_context(|| format!("invalid pod name '{full}' (stack + member ≤ 32 chars)"))?;
        if p.image.is_empty() {
            bail!("pods.{member}: image is required");
        }
        rustypods_proto::validate_name(&p.image)
            .with_context(|| format!("pods.{member}: invalid image name"))?;
        if !image_exists(&p.image) {
            bail!("pods.{member}: image '{}' not found", p.image);
        }
        if !p.cmd.is_empty() {
            rustypods_proto::validate_argv(&p.cmd)
                .with_context(|| format!("pods.{member}: invalid cmd"))?;
        }
        for spec in &p.ports {
            rustypods_proto::validate_port(spec).with_context(|| format!("pods.{member}"))?;
            let (bind, hp, proto) = host_port_key(spec);
            if !host_ports.insert((bind.clone(), hp, proto)) {
                bail!("pods.{member}: {bind}:{hp}/{proto} is already used by another member");
            }
        }
        for spec in &p.ingress {
            let rule = rustypods_proto::parse_ingress_rule(spec)
                .with_context(|| format!("pods.{member}"))?;
            if !ingress_hosts.insert(rule.host.clone()) {
                bail!(
                    "pods.{member}: ingress host '{}' is already used by another member",
                    rule.host
                );
            }
        }
        rustypods_proto::validate_env(&p.env)
            .with_context(|| format!("pods.{member}: invalid env"))?;
        for spec in &p.volumes {
            rustypods_proto::parse_volume_spec(spec)
                .with_context(|| format!("pods.{member}: invalid volume"))?;
        }
        crate::ha::admit(&crate::ha::MemberShape {
            ha: p.ha,
            replicates: p.replicates,
            serves: p.serves.as_deref(),
            primary: p.primary,
            has_volume: !p.volumes.is_empty(),
            has_publish: !p.ports.is_empty() || !p.ingress.is_empty(),
            host_access: p.host_access,
        })
        .with_context(|| format!("pods.{member}"))?;
    }
    let mut primaries: BTreeMap<&str, u32> = BTreeMap::new();
    for (member, p) in &def.pods {
        let Some(name) = p.serves.as_deref() else {
            continue;
        };
        let n = primaries.entry(name).or_insert(0);
        if p.primary {
            *n += 1;
        }
        if *n > 1 {
            bail!("pods.{member}: service '{name}' already has a primary");
        }
    }
    Ok(def)
}

fn host_port_key(spec: &str) -> (String, u16, &'static str) {
    match rustypods_proto::parse_port(spec) {
        Ok(p) => (p.bind_addr().to_string(), p.host_port, p.proto),
        Err(_) => (String::new(), 0, "tcp"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img(_: &str) -> bool {
        true
    }

    #[test]
    fn parses_minimal_stack() {
        let d = parse(
            "name = \"demo\"\n\n[pods.web]\nimage = \"arch-base\"\n",
            img,
        )
        .unwrap();
        assert_eq!(d.name, "demo");
        assert_eq!(d.pods["web"].image, "arch-base");
        assert!(d.pods["web"].ports.is_empty());
    }

    #[test]
    fn parses_full_stack() {
        let t = r#"
name = "shop"
[pods.web]
image = "arch-base"
ports = ["8080:80", "53:53/udp"]
[pods.db]
image = "arch-base"
storage_max = "5G"
snap_keep_last = 3
snap_max_age = "7d"
[pods.db.limits]
memory_max = "1G"
cpu_quota_percent = 50
"#;
        let d = parse(t, img).unwrap();
        assert_eq!(d.pods.len(), 2);
        assert_eq!(d.pods["db"].storage_max_bytes, 5 << 30);
        assert_eq!(d.pods["db"].limits.memory_max_bytes, 1 << 30);
        assert_eq!(d.pods["db"].snap_max_age_secs, 7 * 86400);
        assert_eq!(d.pods["db"].snap_keep_last, 3);
        assert_eq!(member_name("shop", "web"), "shop-web");
    }

    #[test]
    fn a_volume_cannot_be_movable_and_a_mesh_replica_can_be_pinned() {
        let movable = "name = \"s\"\n[pods.db]\nimage = \"i\"\nha = \"movable\"\nvolumes = [\"data:/var/lib/mysql\"]\n";
        let err = parse(movable, img).unwrap_err();
        assert!(format!("{err:#}").contains("volume"), "{err:#}");
        let replica = "name = \"s\"\n[pods.db]\nimage = \"i\"\nreplicates = \"mesh\"\nserves = \"orders\"\nprimary = true\n";
        let d = parse(replica, img).unwrap();
        assert_eq!(d.pods["db"].replicates, crate::ha::Replication::Mesh);
        assert!(d.pods["db"].primary);
    }

    #[test]
    fn parses_and_dedups_ingress() {
        let ok = r#"
name = "shop"
[pods.web]
image = "arch-base"
ingress = ["web.rustypods.localhost:8080", "api.rustypods.localhost:443"]
[pods.db]
image = "arch-base"
"#;
        let d = parse(ok, img).unwrap();
        assert_eq!(d.pods["web"].ingress.len(), 2);
        // Same host claimed by two members of one stack.
        let dup = r#"
name = "dup"
[pods.a]
image = "arch-base"
ingress = ["web.rustypods.localhost:80"]
[pods.b]
image = "arch-base"
ingress = ["web.rustypods.localhost:8080"]
"#;
        assert!(parse(dup, img).is_err());
        // Same host twice on ONE member.
        let self_dup = r#"
name = "selfdup"
[pods.a]
image = "arch-base"
ingress = ["web.rustypods.localhost:80", "web.rustypods.localhost:443"]
"#;
        assert!(parse(self_dup, img).is_err());
        // Bad grammar surfaces the parse error.
        let bad =
            "name = \"x\"\n[pods.a]\nimage = \"i\"\ningress = [\"WEB.rustypods.localhost:80\"]\n";
        assert!(parse(bad, img).is_err());
    }

    #[test]
    fn rejects_duplicate_host_ports() {
        let t = r#"
name = "dup"
[pods.a]
image = "arch-base"
ports = ["8080:80"]
[pods.b]
image = "arch-base"
ports = ["8080:8080"]
"#;
        assert!(parse(t, img).is_err());
    }

    #[test]
    fn rejects_missing_image_and_empty_stack() {
        assert!(parse("name = \"x\"\n[pods.a]\nimage = \"nope\"\n", |_| false).is_err());
        assert!(parse("name = \"x\"\n", img).is_err());
        assert!(parse("name = \"Bad Name\"\n[pods.a]\nimage=\"i\"\n", img).is_err());
    }
}
