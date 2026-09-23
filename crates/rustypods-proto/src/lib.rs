//! Shared API surface for RustyPods: generated gRPC code plus the few
//! constants and validators both the daemon and the CLI need.

use anyhow::Context as _;
use std::path::PathBuf;

pub mod rpc {
    tonic::include_proto!("rustypods.v1");
}

pub const SOCKET_PATH: &str = "/run/rustypods/daemon.sock";
pub const DATA_DIR: &str = "/var/lib/rustypods";

pub fn images_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("images")
}
pub fn pods_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("pods")
}
/// Named volumes — each a btrfs subvolume under volumes/<name>.
pub fn volumes_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("volumes")
}
pub fn logs_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("logs")
}
pub fn bin_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("bin")
}
pub fn shm_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("shm")
}
/// Per-pod channel dir, bound rw into the pod at /run/rustypods/run.
pub fn run_dir(data_dir: &std::path::Path, pod: &str) -> PathBuf {
    data_dir.join("run").join(pod)
}
/// Host side of the SHM dataplane — tmpfs, bound rw to /run/rustypods/shm.
pub fn shm_host_dir(pod: &str) -> PathBuf {
    PathBuf::from("/dev/shm/rustypods").join(pod)
}
/// Per-entity TOML confs: conf/pods/<name>.conf, conf/images/<name>.conf.
/// Hand-editable; `rustypods reload <pod>` rereads them.
pub fn conf_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("conf")
}

/// In-pod paths (container side of the binds).
pub const POD_RUN_DIR: &str = "/run/rustypods/run";
pub const POD_AGENT_SOCK: &str = "/run/rustypods/run/agent.sock";
/// In-pod control socket path of the rustypods-ingress gateway — the
/// daemon reaches it at [`ingress_socket`] on the host side.
pub const POD_INGRESS_SOCK: &str = "/run/rustypods/run/ingress.sock";
pub const POD_SHM_DIR: &str = "/run/rustypods/shm";

/// The managed gateway pod's reserved name.
pub const INGRESS_POD: &str = "rustypods-ingress";
/// Host path of the gateway's control socket (inside the pod it is
/// [`POD_INGRESS_SOCK`] on the bound run dir).
pub fn ingress_socket(data_dir: &std::path::Path) -> PathBuf {
    run_dir(data_dir, INGRESS_POD).join("ingress.sock")
}

/// Pod/image names double as nspawn machine names and directory names.
/// Keep them to a strict hostname-ish slug.
pub fn validate_name(name: &str) -> anyhow::Result<&str> {
    let ok = !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        && name
            .chars()
            .next()
            .map(|c| c.is_ascii_lowercase())
            .unwrap_or(false);
    if ok {
        Ok(name)
    } else {
        anyhow::bail!(
            "invalid name '{name}' — use [a-z][a-z0-9-_]{{0,31}} (must start with a letter)"
        )
    }
}

/// Snapshot ids are "<unix_ts>[-slug]" — digits, then optionally "-" + [a-z0-9-]{1,40}.
pub fn validate_snapshot_id(id: &str) -> anyhow::Result<&str> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && !id.contains('/')
        && id
            .chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase() || c == '-')
        && id
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false);
    if ok {
        Ok(id)
    } else {
        anyhow::bail!("invalid snapshot id '{id}' — expected <unix_ts>[-slug]")
    }
}

/// A distrobox/podman container reference — the podman name charset
/// ([A-Za-z0-9][A-Za-z0-9_.-]*), so a leading '-' (option injection) is out.
pub fn validate_container_ref(s: &str) -> anyhow::Result<&str> {
    let ok = !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        && s.chars()
            .next()
            .map(|c| c.is_ascii_alphanumeric())
            .unwrap_or(false);
    if ok {
        Ok(s)
    } else {
        anyhow::bail!("invalid container ref '{s}' — use [A-Za-z0-9][A-Za-z0-9_.-]{{0,63}}")
    }
}

/// Look up the login name for `uid` in passwd(5)-format text. Shared by the
/// daemon (`--import-user` default) and the CLI (`import`/`shell` fallback).
pub fn username_for_uid(text: &str, uid: u32) -> Option<String> {
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        f.next()?; // password field
        let u: u32 = f.next()?.parse().ok()?;
        (u == uid && !name.is_empty()).then(|| name.to_string())
    })
}

/// A Unix login name: ^[a-z_][a-z0-9_-]{0,31}$.
pub fn validate_unix_user(u: &str) -> anyhow::Result<&str> {
    let ok = !u.is_empty()
        && u.len() <= 32
        && u.chars()
            .next()
            .map(|c| c.is_ascii_lowercase() || c == '_')
            .unwrap_or(false)
        && u.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if ok {
        Ok(u)
    } else {
        anyhow::bail!("invalid unix user '{u}' — use [a-z_][a-z0-9_-]{{0,31}}")
    }
}

/// Validate "hostPort:podPort[/proto]" — both ports must be 1..=65535.
pub fn validate_port(spec: &str) -> anyhow::Result<()> {
    let (ports, proto) = match spec.split_once('/') {
        Some((p, pr)) => (p, Some(pr)),
        None => (spec, None),
    };
    let ok = matches!(proto, None | Some("tcp") | Some("udp"))
        && ports.split(':').count() == 2
        && ports
            .split(':')
            .all(|s| s.parse::<u16>().map(|n| n > 0).unwrap_or(false));
    if ok {
        Ok(())
    } else {
        anyhow::bail!("invalid port mapping '{spec}' — expected hostPort:podPort[/tcp|/udp]")
    }
}

/// The domain suffix every ingress hostname must live under.
pub const INGRESS_SUFFIX: &str = ".rustypods.localhost";

/// "<host>:<port>" → a typed ingress rule. Split on the LAST colon so a
/// stray colon in the host can't smuggle extra fields; the grammar itself
/// (validate_ingress_rule) forbids them anyway.
pub fn parse_ingress_rule(spec: &str) -> anyhow::Result<rpc::IngressRule> {
    let Some((host, port)) = spec.rsplit_once(':') else {
        anyhow::bail!("invalid ingress '{spec}' — expected <host>{INGRESS_SUFFIX}:<port>");
    };
    if host.is_empty() || port.is_empty() {
        anyhow::bail!("invalid ingress '{spec}' — expected <host>{INGRESS_SUFFIX}:<port>");
    }
    let pod_port: u32 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid ingress '{spec}' — port '{port}' is not numeric"))?;
    let rule = rpc::IngressRule {
        host: host.to_string(),
        pod_port,
    };
    validate_ingress_rule(&rule)
        .map_err(|e| anyhow::anyhow!("invalid ingress '{spec}' — {e:#}"))?;
    Ok(rule)
}

/// Ingress rule grammar: a lowercase DNS name under .rustypods.localhost
/// (at least one label in front, RFC-1035 label rules, no wildcards, no
/// IPs, no Unicode) plus a pod port in 1..=65535. Hostnames are matched by
/// a future L7 proxy — anything looser would be a routing ambiguity.
pub fn validate_ingress_rule(rule: &rpc::IngressRule) -> anyhow::Result<()> {
    if !(1..=65535).contains(&rule.pod_port) {
        anyhow::bail!("pod port {} out of range (1..=65535)", rule.pod_port);
    }
    validate_ingress_host(&rule.host)
}

fn validate_ingress_host(host: &str) -> anyhow::Result<()> {
    if host.is_empty() || host.len() > 253 {
        anyhow::bail!("host '{host}' must be 1..=253 characters");
    }
    if !host.is_ascii() {
        anyhow::bail!("host '{host}' must be ASCII");
    }
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        anyhow::bail!("host '{host}' must be lowercase");
    }
    let Some(prefix) = host.strip_suffix(INGRESS_SUFFIX) else {
        anyhow::bail!("host '{host}' must end with {INGRESS_SUFFIX}");
    };
    if prefix.is_empty() {
        anyhow::bail!("host '{host}' needs at least one label before {INGRESS_SUFFIX}");
    }
    // Exactly ONE label: the local TLS cert carries a single wildcard SAN
    // (*.rustypods.localhost), which only matches first-level names.
    if prefix.contains('.') {
        anyhow::bail!("host '{host}' must be exactly one label before {INGRESS_SUFFIX}");
    }
    for label in prefix.split('.') {
        if label.is_empty() {
            anyhow::bail!("host '{host}' has an empty label");
        }
        if label.len() > 63 {
            anyhow::bail!("host '{host}': label '{label}' is longer than 63 characters");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            anyhow::bail!("host '{host}': label '{label}' may only contain [a-z0-9-]");
        }
        let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        if !alnum(*label.as_bytes().first().unwrap()) || !alnum(*label.as_bytes().last().unwrap()) {
            anyhow::bail!(
                "host '{host}': label '{label}' must start and end with a letter or digit"
            );
        }
    }
    Ok(())
}

/// A parsed bind-mount spec (`host[:pod][:ro]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindSpec {
    pub host: String,
    pub pod: String,
    pub ro: bool,
}

fn clean_abs_path(p: &str) -> bool {
    p.starts_with('/')
        && (p == "/" || !p.ends_with('/'))
        && p.split('/')
            .skip(1)
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

fn under(path: &str, prefix: &str) -> bool {
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

/// Validate "host[:pod][:ro]": both paths absolute, no empty/dot components,
/// no trailing slash. The host path is canonicalized — `/var/run` resolves
/// to `/run`, `/bin` to `/usr/bin`, etc. — and the deny-lists are checked
/// against BOTH the literal and the resolved path, so symlink aliases can't
/// slip past. The host path must exist at validation time.
/// Host may not be exactly a system root ("/", "/proc", "/sys", "/dev",
/// "/boot", "/usr", "/etc", "/var", "/var/lib", "/run", "/root", "/var/run",
/// "/var/spool", "/var/cron"). Read-write binds under /run, /root,
/// /var/lib/rustypods, /etc, /usr, /boot, /proc, /sys, /dev are refused —
/// those are :ro-only (a pod's init system considers e.g. /run/user/<uid>
/// "theirs" and rm -rf's it; see AGENTS.md).
pub fn validate_bind(spec: &str) -> anyhow::Result<BindSpec> {
    let mut parts: Vec<&str> = spec.split(':').collect();
    let ro = parts.last() == Some(&"ro");
    if ro {
        parts.pop();
    }
    let bad = |spec: &str| {
        anyhow::anyhow!("invalid bind '{spec}' — expected host[:pod][:ro], absolute paths")
    };
    let (host, pod) = match parts.as_slice() {
        [h] => (*h, *h),
        [h, p] => (*h, *p),
        _ => return Err(bad(spec)),
    };
    if !clean_abs_path(host) || !clean_abs_path(pod) {
        return Err(bad(spec));
    }
    // Resolve symlink aliases (/var/run → /run, /bin → /usr/bin) so the
    // deny-lists can't be bypassed by spelling a denied path differently.
    // Nonexistent host paths are rejected here — pods can't bind paths that
    // don't exist yet.
    let resolved = std::fs::canonicalize(host)
        .map_err(|_| anyhow::anyhow!("invalid bind '{spec}' — host path {host} does not exist"))?;
    let host_resolved = resolved.to_string_lossy().into_owned();
    const EXACT_DENY: &[&str] = &[
        "/",
        "/proc",
        "/sys",
        "/dev",
        "/boot",
        "/usr",
        "/etc",
        "/var",
        "/var/lib",
        "/run",
        "/root",
        "/var/run",
        "/var/spool",
        "/var/cron",
    ];
    if EXACT_DENY.contains(&host) || EXACT_DENY.contains(&host_resolved.as_str()) {
        return Err(anyhow::anyhow!(
            "invalid bind '{spec}' — host path {host} may not be bound wholesale"
        ));
    }
    const RW_DENY: &[&str] = &[
        "/run",
        "/var/lib/rustypods",
        "/etc",
        "/usr",
        "/boot",
        "/proc",
        "/sys",
        "/dev",
        "/root",
        "/var/run",
    ];
    if !ro
        && (RW_DENY.iter().any(|p| under(host, p))
            || RW_DENY.iter().any(|p| under(&host_resolved, p)))
    {
        return Err(anyhow::anyhow!(
            "invalid bind '{spec}' — {host} is read-only territory, add ':ro'"
        ));
    }
    Ok(BindSpec {
        host: host_resolved,
        pod: pod.to_string(),
        ro,
    })
}

/// Largest value parse_bytes/parse_duration will produce: u64 results
/// cross a JSON/ts-proto boundary where numbers are f64 — anything past
/// 2^53 loses integer precision (and u64::MAX breaks i64 consumers).
const MAX_PARSED: u64 = 1 << 53;

/// f64 → u64 with sanity: NaN/±inf and negatives parse as f64 but are not
/// sizes, and the saturating `as` cast would silently turn them into 0 or
/// u64::MAX.
fn f64_to_u64(v: f64, mult: u64, what: &str, s: &str) -> anyhow::Result<u64> {
    if !(v.is_finite() && v >= 0.0) {
        anyhow::bail!("invalid {what} '{s}'");
    }
    let r = v * mult as f64;
    if !(r.is_finite() && r <= MAX_PARSED as f64) {
        anyhow::bail!("{what} '{s}' out of range (max {} )", MAX_PARSED);
    }
    Ok(r as u64)
}

/// Validate a payload argv (pod cmd override): non-empty vec, argv[0]
/// non-empty, no NUL bytes anywhere (they'd truncate at exec).
pub fn validate_argv(argv: &[String]) -> anyhow::Result<()> {
    if argv.is_empty() || argv[0].is_empty() {
        anyhow::bail!("invalid cmd — argv[0] must be non-empty");
    }
    if argv.iter().any(|a| a.contains('\0')) {
        anyhow::bail!("invalid cmd — argv entries may not contain NUL bytes");
    }
    Ok(())
}

/// A parsed "name:/pod/path[:ro]" volume mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeSpec {
    pub name: String,
    pub target: String,
    pub ro: bool,
}

/// Parse+validate a named-volume mount spec. The volume name shares the
/// pod-name grammar (it becomes a directory under volumes/); the target
/// is an absolute in-pod path without '..'.
pub fn parse_volume_spec(spec: &str) -> anyhow::Result<VolumeSpec> {
    let (name, rest) = spec
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid volume '{spec}' — want name:/pod/path[:ro]"))?;
    validate_name(name).with_context(|| format!("invalid volume name '{name}'"))?;
    let (target, ro) = match rest.strip_suffix(":ro") {
        Some(t) => (t, true),
        None => (rest, false),
    };
    if !target.starts_with('/') || target.len() < 2 {
        anyhow::bail!("invalid volume target '{target}' — must be an absolute path");
    }
    // ':' inside the target would make the ":ro" suffix ambiguous
    // ("data:/a:b" vs "data:/a:b:ro"), so it's rejected outright.
    if target.contains("..")
        || target.contains('\0')
        || target.contains(':')
        || target.ends_with('/')
    {
        anyhow::bail!("invalid volume target '{target}' — no '..', ':', NUL or trailing '/'");
    }
    Ok(VolumeSpec {
        name: name.into(),
        target: target.into(),
        ro,
    })
}

/// Validate "KEY=value" env entries: POSIX-ish key, no NUL anywhere.
/// Same rules exec.rs applies to client-supplied env — sharing them
/// keeps conf-time validation honest with exec-time.
pub fn validate_env(entries: &[String]) -> anyhow::Result<()> {
    for kv in entries {
        let Some((key, _)) = kv.split_once('=') else {
            anyhow::bail!("invalid env entry '{kv}' — want KEY=value");
        };
        let key_ok = !key.is_empty()
            && key
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '_')
                .unwrap_or(false)
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !key_ok {
            anyhow::bail!("invalid env key '{key}'");
        }
        if kv.contains('\0') {
            anyhow::bail!("invalid env entry '{kv}' — NUL byte");
        }
    }
    Ok(())
}

/// Restart policy names — "" normalizes to "no".
pub const RESTART_POLICIES: [&str; 3] = ["no", "on-failure", "always"];

/// Validate a restart policy name ("" and "no" are equivalent).
pub fn validate_restart(s: &str) -> anyhow::Result<()> {
    if s.is_empty() || RESTART_POLICIES.contains(&s) {
        Ok(())
    } else {
        anyhow::bail!("invalid restart policy '{s}' — expected no|on-failure|always");
    }
}

/// Validate a healthcheck spec: kind must be a known probe, and each
/// kind's target shape is checked so a malformed spec can't be
/// persisted into a conf the supervisor will silently misprobe.
pub fn validate_healthcheck(h: &rpc::HealthCheck) -> anyhow::Result<()> {
    match h.kind.as_str() {
        "" | "none" => {}
        "exec" => validate_argv(&h.argv)?,
        "tcp" => {
            let t = h.target.trim();
            // ":8080" (pod IP) or "host:port".
            let port = t
                .rsplit_once(':')
                .map(|(_, p)| p)
                .unwrap_or(t)
                .parse::<u16>()
                .map_err(|_| {
                    anyhow::anyhow!("invalid tcp probe target '{t}' — want :port or host:port")
                })?;
            if port == 0 {
                anyhow::bail!("invalid tcp probe target '{t}' — port 0");
            }
        }
        "http" => {
            let t = h.target.trim();
            if t.starts_with('/') {
                // "/path" on the pod's own veth address :80.
            } else if let Some(rest) = t.strip_prefix("http://") {
                // The daemon dials numeric hosts only — never DNS.
                let auth = rest.split('/').next().unwrap_or("");
                let host = auth.rsplit_once(':').map(|(h, _)| h).unwrap_or(auth);
                if host.parse::<std::net::IpAddr>().is_err() {
                    anyhow::bail!("invalid http probe target '{t}' — host must be a numeric IP");
                }
            } else {
                anyhow::bail!(
                    "invalid http probe target '{t}' — want /path or http://ip:port/path"
                );
            }
        }
        other => anyhow::bail!("invalid healthcheck kind '{other}' — exec|tcp|http"),
    }
    if h.interval_secs > 3600 || h.timeout_secs > 3600 || h.retries > 100 {
        anyhow::bail!("healthcheck timing fields out of range");
    }
    Ok(())
}

/// Parse "10G", "512M", "1024" (bytes) into a byte count.
pub fn parse_bytes(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.as_bytes().last() {
        Some(b'G') | Some(b'g') => (&s[..s.len() - 1], 1u64 << 30),
        Some(b'M') | Some(b'm') => (&s[..s.len() - 1], 1u64 << 20),
        Some(b'K') | Some(b'k') => (&s[..s.len() - 1], 1u64 << 10),
        Some(b'B') | Some(b'b') => (&s[..s.len() - 1], 1u64),
        _ => (s, 1u64),
    };
    let v: f64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid size '{s}'"))?;
    f64_to_u64(v, mult, "size", s)
}

pub fn fmt_bytes(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.1}G", b as f64 / (1u64 << 30) as f64)
    } else if b >= 1 << 20 {
        format!("{:.1}M", b as f64 / (1u64 << 20) as f64)
    } else {
        format!("{b}B")
    }
}

/// Parse "7d", "24h", "30m", "60s", or a bare second count into seconds.
pub fn parse_duration(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.as_bytes().last() {
        Some(b'd') | Some(b'D') => (&s[..s.len() - 1], 86400u64),
        Some(b'h') | Some(b'H') => (&s[..s.len() - 1], 3600),
        Some(b'm') | Some(b'M') => (&s[..s.len() - 1], 60),
        Some(b's') | Some(b'S') => (&s[..s.len() - 1], 1),
        _ => (s, 1u64),
    };
    let v: f64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration '{s}'"))?;
    f64_to_u64(v, mult, "duration", s)
}

/// Seconds back to the coarsest whole unit: 604800 → "7d", 3600 → "1h".
pub fn fmt_duration(secs: u64) -> String {
    if secs == 0 {
        "0s".into()
    } else if secs % 86400 == 0 {
        format!("{}d", secs / 86400)
    } else if secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validation() {
        assert!(validate_name("arch-dev").is_ok());
        assert!(validate_name("a").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("1bad").is_err());
        assert!(validate_name("Bad").is_err());
        assert!(validate_name("bad name").is_err());
        assert!(validate_name(&"x".repeat(33)).is_err());
    }

    #[test]
    fn snapshot_id_validation() {
        assert!(validate_snapshot_id("1789836285").is_ok());
        assert!(validate_snapshot_id("1789836285-before-experiment").is_ok());
        assert!(validate_snapshot_id("").is_err());
        assert!(validate_snapshot_id("../x").is_err());
        assert!(validate_snapshot_id("a/b").is_err());
        assert!(validate_snapshot_id("1789836285/../../pods").is_err());
        assert!(validate_snapshot_id("-x").is_err());
        assert!(validate_snapshot_id("Bad").is_err());
    }

    #[test]
    fn container_ref_and_unix_user() {
        assert!(validate_container_ref("arch").is_ok());
        assert!(validate_container_ref("-o/tmp/x").is_err());
        assert!(validate_container_ref("a b").is_err());
        assert!(validate_unix_user("nick").is_ok());
        assert!(validate_unix_user("root").is_ok());
        assert!(validate_unix_user("-u").is_err());
    }

    #[test]
    fn username_for_uid_parses_passwd() {
        let text = "root:x:0:0:root:/root:/bin/bash\n\
                    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                    nick:x:1000:1000:Nick:/home/nick:/bin/bash\n";
        assert_eq!(username_for_uid(text, 1000).as_deref(), Some("nick"));
        assert_eq!(username_for_uid(text, 0).as_deref(), Some("root"));
        assert_eq!(username_for_uid(text, 1234), None);
        // Malformed lines are skipped, not fatal.
        assert_eq!(
            username_for_uid("badline\nnick:x:1000:g:::", 1000).as_deref(),
            Some("nick")
        );
        assert_eq!(username_for_uid("", 1000), None);
    }

    #[test]
    fn restart_policy_validation() {
        assert!(validate_restart("").is_ok());
        assert!(validate_restart("no").is_ok());
        assert!(validate_restart("on-failure").is_ok());
        assert!(validate_restart("always").is_ok());
        assert!(validate_restart("unless-stopped").is_err());
        assert!(validate_restart("sometimes").is_err());
    }

    #[test]
    fn healthcheck_validation() {
        let hc = |kind: &str, target: &str, argv: &[&str]| rpc::HealthCheck {
            kind: kind.into(),
            target: target.into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        // Disabled / none always pass.
        assert!(validate_healthcheck(&hc("", "", &[])).is_ok());
        assert!(validate_healthcheck(&hc("none", "", &[])).is_ok());
        // exec needs argv; tcp/http need their target shape.
        assert!(validate_healthcheck(&hc("exec", "", &["sh", "-c", "true"])).is_ok());
        assert!(validate_healthcheck(&hc("exec", "", &[])).is_err());
        assert!(validate_healthcheck(&hc("tcp", ":8080", &[])).is_ok());
        assert!(validate_healthcheck(&hc("tcp", "10.0.0.1:53", &[])).is_ok());
        assert!(validate_healthcheck(&hc("tcp", ":0", &[])).is_err());
        assert!(validate_healthcheck(&hc("tcp", "noport", &[])).is_err());
        assert!(validate_healthcheck(&hc("http", "/healthz", &[])).is_ok());
        assert!(validate_healthcheck(&hc("http", "http://10.0.0.1:8080/h", &[])).is_ok());
        assert!(validate_healthcheck(&hc("http", "example.com", &[])).is_err());
        assert!(validate_healthcheck(&hc("grpc", "", &[])).is_err());
        // Timing bounds.
        let mut h = hc("tcp", ":1", &[]);
        h.interval_secs = 3601;
        assert!(validate_healthcheck(&h).is_err());
        h.interval_secs = 60;
        h.retries = 101;
        assert!(validate_healthcheck(&h).is_err());
        h.retries = 3;
        assert!(validate_healthcheck(&h).is_ok());
    }

    #[test]
    fn bind_validation() {
        let b = validate_bind("/var/tmp").unwrap();
        assert_eq!(
            b,
            BindSpec {
                host: "/var/tmp".into(),
                pod: "/var/tmp".into(),
                ro: false
            }
        );
        assert!(validate_bind("/tmp").is_ok());
        // /run itself may not be bound wholesale, not even read-only;
        // subpaths are :ro-only.
        assert!(validate_bind("/run").is_err());
        assert!(validate_bind("/run:ro").is_err());
        assert!(validate_bind("/etc").is_err());
        assert!(validate_bind("home/nick").is_err());
        assert!(validate_bind("/a/../b").is_err());
        assert!(validate_bind("/var/tmp:/mnt/data").is_ok());
        assert!(validate_bind("/var/tmp:/mnt/data:ro").unwrap().ro);
        assert!(validate_bind("/x:rel").is_err());
        // Host path must exist — no binding not-yet-created paths.
        assert!(validate_bind("/definitely-not-here-rp").is_err());
        // Symlink aliases resolve before the deny-lists run:
        // /var/run → /run, /bin → /usr/bin on any usr-merged system.
        assert!(validate_bind("/var/run").is_err());
        assert!(validate_bind("/var/run:ro").is_err());
        assert!(validate_bind("/var/run/lock:ro").unwrap().ro);
        if std::path::Path::new("/bin/sh").exists() {
            assert!(validate_bind("/bin/sh").is_err());
            assert!(validate_bind("/bin/sh:ro").unwrap().ro);
        }
        assert!(validate_bind("/root").is_err());
    }

    #[test]
    fn argv_validation() {
        assert!(validate_argv(&["sleep".into(), "infinity".into()]).is_ok());
        assert!(validate_argv(&[]).is_err());
        assert!(validate_argv(&["".into()]).is_err());
        assert!(validate_argv(&["sh".into(), "a\0b".into()]).is_err());
    }

    #[test]
    fn ingress_parsing_and_validation() {
        let r = parse_ingress_rule("web.rustypods.localhost:8080").unwrap();
        assert_eq!(r.host, "web.rustypods.localhost");
        assert_eq!(r.pod_port, 8080);
        // Exactly one label: nested names can't match the wildcard SAN.
        assert!(parse_ingress_rule("api.dev.rustypods.localhost:443").is_err());
        // Suffix-only, no label in front.
        assert!(parse_ingress_rule(".rustypods.localhost:80").is_err());
        assert!(parse_ingress_rule("rustypods.localhost:80").is_err());
        // Uppercase, wildcard, underscore, bad hyphens, empty labels.
        assert!(parse_ingress_rule("Web.rustypods.localhost:80").is_err());
        assert!(parse_ingress_rule("*.rustypods.localhost:80").is_err());
        assert!(parse_ingress_rule("my_app.rustypods.localhost:80").is_err());
        assert!(parse_ingress_rule("-web.rustypods.localhost:80").is_err());
        assert!(parse_ingress_rule("web-.rustypods.localhost:80").is_err());
        assert!(parse_ingress_rule("a..b.rustypods.localhost:80").is_err());
        assert!(parse_ingress_rule("wéb.rustypods.localhost:80").is_err());
        assert!(parse_ingress_rule("web.rustypods.localhost.:80").is_err());
        // Wrong suffix, IP literal, over-long label / host.
        assert!(parse_ingress_rule("web.example.com:80").is_err());
        assert!(parse_ingress_rule("10.0.0.1:80").is_err());
        assert!(parse_ingress_rule(&format!("{}.rustypods.localhost:80", "a".repeat(64))).is_err());
        assert!(
            parse_ingress_rule(&format!("{}.rustypods.localhost:80", "a".repeat(240))).is_err()
        );
        // Ports: 0, >65535, non-numeric, missing.
        assert!(parse_ingress_rule("web.rustypods.localhost:0").is_err());
        assert!(parse_ingress_rule("web.rustypods.localhost:65536").is_err());
        assert!(parse_ingress_rule("web.rustypods.localhost:http").is_err());
        assert!(parse_ingress_rule("web.rustypods.localhost").is_err());
        assert!(parse_ingress_rule("web.rustypods.localhost:").is_err());
        // Boundary ports are fine.
        assert!(parse_ingress_rule("web.rustypods.localhost:1").is_ok());
        assert!(parse_ingress_rule("web.rustypods.localhost:65535").is_ok());
    }

    #[test]
    fn port_validation() {
        assert!(validate_port("2222:22").is_ok());
        assert!(validate_port("53:53/udp").is_ok());
        assert!(validate_port("0:80").is_err());
        assert!(validate_port("8080").is_err());
        assert!(validate_port("1:2/sctp").is_err());
    }

    #[test]
    fn byte_parsing() {
        assert_eq!(parse_bytes("10G").unwrap(), 10 << 30);
        assert_eq!(parse_bytes("512m").unwrap(), 512 << 20);
        assert_eq!(parse_bytes("1024").unwrap(), 1024);
        assert!(parse_bytes("abc").is_err());
        // f64 parse accepts these — they must be rejected, not saturated.
        assert!(parse_bytes("NaN").is_err());
        assert!(parse_bytes("nan").is_err());
        assert!(parse_bytes("inf").is_err());
        assert!(parse_bytes("-5").is_err());
        assert!(parse_bytes("-5G").is_err());
        assert!(parse_bytes("1e30").is_err()); // > 2^53
        assert!(parse_bytes("9007199T").is_err()); // 'T' isn't a suffix → parse error
        assert_eq!(parse_bytes("9007199254740992").unwrap(), 1 << 53); // == 2^53 ok
        assert!(parse_bytes("10000000000000000").is_err()); // 1e16 > 2^53
        assert!(parse_bytes("").is_err());
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration("7d").unwrap(), 7 * 86400);
        assert_eq!(parse_duration("24h").unwrap(), 24 * 3600);
        assert_eq!(parse_duration("30m").unwrap(), 30 * 60);
        assert_eq!(parse_duration("60s").unwrap(), 60);
        assert_eq!(parse_duration("120").unwrap(), 120);
        assert_eq!(parse_duration("0").unwrap(), 0);
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("-5d").is_err());
        assert!(parse_duration("").is_err());
        // Same f64 traps as parse_bytes: NaN/inf parse fine, and a giant
        // multiplier can push a sane-looking number past 2^53.
        assert!(parse_duration("NaN").is_err());
        assert!(parse_duration("inf").is_err());
        assert!(parse_duration("-inf").is_err());
        assert!(parse_duration("99999999999999d").is_err());
    }

    #[test]
    fn volume_spec_parsing() {
        let v = parse_volume_spec("data:/var/lib/pg").unwrap();
        assert_eq!(v.name, "data");
        assert_eq!(v.target, "/var/lib/pg");
        assert!(!v.ro);
        let v = parse_volume_spec("conf:/etc/app:ro").unwrap();
        assert!(v.ro);
        // RW must not carry the suffix; bad names/targets rejected.
        assert!(parse_volume_spec("data:/x").is_ok());
        assert!(parse_volume_spec("data").is_err()); // no target
        assert!(parse_volume_spec("data:relative").is_err()); // not absolute
        assert!(parse_volume_spec("data:/x:rw").is_err()); // unknown flag
        assert!(parse_volume_spec("bad name:/x").is_err());
        assert!(parse_volume_spec("../x:/x").is_err());
        assert!(parse_volume_spec("data:/").is_err()); // can't mount over /
        assert!(parse_volume_spec("data:/x:ro:extra").is_err());
    }

    #[test]
    fn env_validation() {
        assert!(validate_env(&["A=1".into(), "B_TWO=x=y".into()]).is_ok());
        assert!(validate_env(&[]).is_ok());
        assert!(validate_env(&["=x".into()]).is_err()); // empty key
        assert!(validate_env(&["NOEQ".into()]).is_err()); // no '='
        assert!(validate_env(&["A".into()]).is_err());
        assert!(validate_env(&["1A=x".into()]).is_err()); // key starts digit
        assert!(validate_env(&["A-B=x".into()]).is_err()); // bad key char
        assert!(validate_env(&["_A=x".into()]).is_ok()); // '_' ok
        assert!(validate_env(&["A=".into()]).is_ok()); // empty value ok
                                                       // Duplicate keys are legal — the pod-level merge keeps the last.
        assert!(validate_env(&["A=1".into(), "A=2".into()]).is_ok());
    }

    #[test]
    fn duration_formatting() {
        assert_eq!(fmt_duration(7 * 86400), "7d");
        assert_eq!(fmt_duration(24 * 3600), "1d"); // coarsest whole unit wins
        assert_eq!(fmt_duration(36 * 3600), "36h");
        assert_eq!(fmt_duration(30 * 60), "30m");
        assert_eq!(fmt_duration(45), "45s");
        assert_eq!(fmt_duration(0), "0s");
    }
}
