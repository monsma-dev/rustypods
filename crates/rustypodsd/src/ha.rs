//! Availability across sites.
//!
//! Four decisions, and nothing else. A Btrfs snapshot is a local copy.
//! It is not a second datacenter. RustyPods does not replicate database
//! rows; a member that sets `replicates = "mesh"` is promising that its
//! own engine (MySQL, Postgres) does, over the mesh.
//!
//! A plan is published only when a majority of voters is alive. Two
//! hosts therefore need a witness. Without that majority the previous
//! DNS and the previous placement stay; neither side gets to decide.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Result};

/// Where a member is allowed to run after its host disappears.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HaMode {
    /// Stays on the host where it was created.
    #[default]
    Pinned,
    /// May restart on the single surviving host.
    Movable,
}

/// What happens to the bytes when the host is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Replication {
    /// Local CoW snapshot. Lost with the datacenter.
    #[default]
    Snapshot,
    /// The member's own engine replicates over the mesh.
    Mesh,
}

/// A voter. A witness counts toward quorum and runs no pods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Role {
    #[default]
    Host,
    Witness,
}

/// A witness may vote. It does not restart a pod and it does not
/// publish a DNS generation.
pub fn local_effect(mut decision: Decision, role: Role) -> Decision {
    if role == Role::Witness {
        decision.restart.clear();
        decision.dns = None;
        decision.stranded.clear();
    }
    decision
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Voter {
    pub id: String,
    pub role: Role,
}

/// Facts `admit` checks before a stack is accepted.
#[derive(Debug, Clone, Copy)]
pub struct MemberShape<'a> {
    pub ha: HaMode,
    pub replicates: Replication,
    pub serves: Option<&'a str>,
    pub primary: bool,
    pub has_volume: bool,
    pub has_publish: bool,
    pub host_access: bool,
}

/// One member of the desired set. `host` is the voter that runs it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workload {
    pub name: String,
    pub host: String,
    pub ha: HaMode,
    pub replicates: Replication,
    pub serves: Option<String>,
    pub primary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restart {
    pub name: String,
    pub from: String,
    pub to: String,
}

/// What a quorum is allowed to publish. `dns` is `None` when there is
/// no majority: callers keep the previous generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub quorum: bool,
    pub restart: Vec<Restart>,
    /// Service name → voter id. Absent names are withdrawn.
    pub dns: Option<BTreeMap<String, String>>,
    /// Pinned members on a dead host with no live mesh replica.
    pub stranded: Vec<String>,
}

/// Refuse combinations that would look like failover and are not.
pub fn admit(member: &MemberShape<'_>) -> Result<()> {
    if member.ha == HaMode::Movable {
        if member.has_volume {
            bail!("a volume cannot move; leave ha = \"pinned\"");
        }
        if member.has_publish {
            bail!("a published port or ingress name cannot move; leave ha = \"pinned\"");
        }
        if member.host_access {
            bail!("host access cannot move; leave ha = \"pinned\"");
        }
        if member.replicates == Replication::Mesh {
            bail!("mesh replication stays on its host; leave ha = \"pinned\"");
        }
    }
    if member.primary && member.serves.is_none() {
        bail!("primary requires serves");
    }
    Ok(())
}

/// `alive` is the set of voter ids this view can reach.
pub fn plan(voters: &[Voter], alive: &BTreeSet<String>, workloads: &[Workload]) -> Decision {
    let majority = voters.len() / 2 + 1;
    let reached = voters.iter().filter(|v| alive.contains(&v.id)).count();
    if voters.is_empty() || reached < majority {
        return Decision {
            quorum: false,
            restart: Vec::new(),
            dns: None,
            stranded: Vec::new(),
        };
    }
    // Placement looks only at hosts. A witness counts for quorum and
    // is never a restart target.
    let survivors: Vec<&Voter> = voters
        .iter()
        .filter(|v| v.role == Role::Host && alive.contains(&v.id))
        .collect();
    let dead_hosts: BTreeSet<&str> = voters
        .iter()
        .filter(|v| v.role == Role::Host && !alive.contains(&v.id))
        .map(|v| v.id.as_str())
        .collect();

    let mut restart = Vec::new();
    if survivors.len() == 1 {
        let to = &survivors[0].id;
        for w in workloads {
            if w.ha == HaMode::Movable && dead_hosts.contains(w.host.as_str()) {
                restart.push(Restart {
                    name: w.name.clone(),
                    from: w.host.clone(),
                    to: to.clone(),
                });
            }
        }
    }

    let mut dns: BTreeMap<String, Vec<&Workload>> = BTreeMap::new();
    for w in workloads {
        let key = w.serves.clone().unwrap_or_else(|| w.name.clone());
        dns.entry(key).or_default().push(w);
    }
    let mut published = BTreeMap::new();
    let mut stranded = Vec::new();
    for (name, group) in dns {
        let live: Vec<&Workload> = group
            .iter()
            .copied()
            .filter(|w| host_live(w, &dead_hosts, &restart))
            .collect();
        if let Some(chosen) = pick(&live) {
            let host = running_host(chosen, &restart);
            if voters
                .iter()
                .any(|v| v.id == host && v.role == Role::Witness)
            {
                continue;
            }
            published.insert(name, host);
            continue;
        }
        if let Some(pinned) = group
            .iter()
            .find(|w| w.ha == HaMode::Pinned && dead_hosts.contains(w.host.as_str()))
        {
            stranded.push(pinned.name.clone());
        }
    }
    stranded.sort();
    Decision {
        quorum: true,
        restart,
        dns: Some(published),
        stranded,
    }
}

fn running_host(w: &Workload, restart: &[Restart]) -> String {
    restart
        .iter()
        .find(|r| r.name == w.name)
        .map(|r| r.to.clone())
        .unwrap_or_else(|| w.host.clone())
}

fn host_live(w: &Workload, dead_hosts: &BTreeSet<&str>, restart: &[Restart]) -> bool {
    if !dead_hosts.contains(w.host.as_str()) {
        return true;
    }
    restart.iter().any(|r| r.name == w.name)
}

fn pick<'a>(live: &[&'a Workload]) -> Option<&'a Workload> {
    live.iter()
        .copied()
        .find(|w| w.primary)
        .or_else(|| live.first().copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn voters() -> Vec<Voter> {
        vec![
            Voter {
                id: "a".into(),
                role: Role::Host,
            },
            Voter {
                id: "b".into(),
                role: Role::Host,
            },
            Voter {
                id: "witness".into(),
                role: Role::Witness,
            },
        ]
    }

    fn alive(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| (*s).to_string()).collect()
    }

    fn web() -> Workload {
        Workload {
            name: "web".into(),
            host: "a".into(),
            ha: HaMode::Movable,
            replicates: Replication::Snapshot,
            serves: None,
            primary: false,
        }
    }

    fn db(host: &str, primary: bool) -> Workload {
        Workload {
            name: format!("orders-{host}"),
            host: host.into(),
            ha: HaMode::Pinned,
            replicates: Replication::Mesh,
            serves: Some("orders".into()),
            primary,
        }
    }

    #[test]
    fn a_dead_quorum_restarts_the_movable_pod_and_points_dns_at_b() {
        let d = plan(&voters(), &alive(&["b", "witness"]), &[web()]);
        assert!(d.quorum);
        assert_eq!(
            d.restart,
            vec![Restart {
                name: "web".into(),
                from: "a".into(),
                to: "b".into(),
            }]
        );
        assert_eq!(d.dns.unwrap().get("web").map(String::as_str), Some("b"));
        assert!(d.stranded.is_empty());
    }

    #[test]
    fn orders_follow_the_live_mesh_replica_and_the_primary_is_not_restarted() {
        let d = plan(
            &voters(),
            &alive(&["b", "witness"]),
            &[db("a", true), db("b", false)],
        );
        assert!(d.restart.is_empty());
        assert_eq!(d.dns.unwrap().get("orders").map(String::as_str), Some("b"));
        assert!(d.stranded.is_empty());
    }

    #[test]
    fn witnesses_hold_quorum_and_receive_no_workload() {
        let voters = vec![
            Voter {
                id: "a".into(),
                role: Role::Host,
            },
            Voter {
                id: "w1".into(),
                role: Role::Witness,
            },
            Voter {
                id: "w2".into(),
                role: Role::Witness,
            },
        ];
        let parked = Workload {
            name: "orders-w1".into(),
            host: "w1".into(),
            ha: HaMode::Pinned,
            replicates: Replication::Mesh,
            serves: Some("orders".into()),
            primary: true,
        };
        let d = plan(&voters, &alive(&["w1", "w2"]), &[web(), parked]);
        assert!(d.quorum);
        assert!(d.restart.is_empty(), "a witness is not a restart target");
        assert!(
            d.dns.as_ref().is_some_and(|m| m.is_empty()),
            "a witness is not a published address"
        );
    }

    #[test]
    fn a_snapshot_is_not_a_second_copy() {
        let mut only = db("a", true);
        only.replicates = Replication::Snapshot;
        let d = plan(&voters(), &alive(&["b", "witness"]), &[only]);
        assert!(d.restart.is_empty());
        assert!(!d.dns.unwrap().contains_key("orders"));
        assert_eq!(d.stranded, vec!["orders-a".to_string()]);
    }

    #[test]
    fn one_survivor_without_the_witness_does_not_decide() {
        let d = plan(&voters(), &alive(&["b"]), &[web(), db("a", true)]);
        assert!(!d.quorum);
        assert!(d.restart.is_empty());
        assert!(d.dns.is_none());
    }

    #[test]
    fn two_hosts_without_a_witness_lose_quorum_when_one_dies() {
        let pair = &voters()[..2];
        let d = plan(pair, &alive(&["b"]), &[web()]);
        assert!(!d.quorum);
        assert!(d.dns.is_none());
    }

    #[test]
    fn both_sides_of_a_split_hold() {
        let left = plan(&voters(), &alive(&["a"]), &[web()]);
        let right = plan(&voters(), &alive(&["b"]), &[web()]);
        assert!(!left.quorum);
        assert!(!right.quorum);
    }

    #[test]
    fn admit_refuses_a_movable_database() {
        let shape = MemberShape {
            ha: HaMode::Movable,
            replicates: Replication::Snapshot,
            serves: None,
            primary: false,
            has_volume: true,
            has_publish: false,
            host_access: false,
        };
        assert!(admit(&shape).is_err());
        let mut published = shape;
        published.has_volume = false;
        published.has_publish = true;
        assert!(admit(&published).is_err());
        let mut replicated = shape;
        replicated.has_volume = false;
        replicated.replicates = Replication::Mesh;
        assert!(admit(&replicated).is_err());
        let mut pinned = shape;
        pinned.ha = HaMode::Pinned;
        assert!(admit(&pinned).is_ok());
    }
}
