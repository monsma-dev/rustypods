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
    #[serde(rename = "snap_max_age", default, with = "crate::state::duration_field")]
    pub snap_max_age_secs: u64,
    /// Payload override for this member — replaces the image
    /// entrypoint+cmd and forces non-boot mode.
    #[serde(default)]
    pub cmd: Vec<String>,
    /// Ingress rules, "<host>.rustypods.localhost:<port>". Hostnames must
    /// be unique across all members of the stack AND all other pods.
    #[serde(default)]
    pub ingress: Vec<String>,
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
        bail!("stack '{}' has no pods — add a [pods.<name>] table", def.name);
    }
    let mut host_ports: BTreeSet<(u16, &str)> = BTreeSet::new();
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
            let (hp, proto) = host_port_key(spec);
            if !host_ports.insert((hp, proto)) {
                bail!("pods.{member}: host port {hp}/{proto} is already used by another member");
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
    }
    Ok(def)
}

fn host_port_key(spec: &str) -> (u16, &'static str) {
    let (ports, proto) = spec.split_once('/').unwrap_or((spec, "tcp"));
    let proto = match proto {
        "udp" => "udp",
        _ => "tcp",
    };
    let hp = ports.split(':').next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (hp, proto)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img(_: &str) -> bool {
        true
    }

    #[test]
    fn parses_minimal_stack() {
        let d = parse("name = \"demo\"\n\n[pods.web]\nimage = \"arch-base\"\n", img).unwrap();
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
        let bad = "name = \"x\"\n[pods.a]\nimage = \"i\"\ningress = [\"WEB.rustypods.localhost:80\"]\n";
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
