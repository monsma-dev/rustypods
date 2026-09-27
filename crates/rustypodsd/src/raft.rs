//! Raft election state for the mesh.
//!
//! `current_term` and `voted_for` are the only fields that must survive
//! a crash: a node grants at most one vote per term. Heartbeats are
//! empty `AppendEntries`. The replicated command log is not here yet;
//! a non-empty append is rejected so a leader cannot pretend an entry
//! was stored.
//!
//! Quorum is a majority of voters, counting this node. One ack from the
//! witness is enough in a three-voter cluster, and not enough when more
//! voters are silent.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const ELECTION_MIN: Duration = Duration::from_millis(150);
pub const ELECTION_MAX: Duration = Duration::from_millis(300);
const STATE_NAME: &str = "raft.state";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Persistent {
    pub current_term: u64,
    pub voted_for: Option<String>,
}

impl Persistent {
    pub fn fresh() -> Self {
        Self {
            current_term: 0,
            voted_for: None,
        }
    }

    /// Grant `candidate` in `term`, or refuse. A higher term forgets the
    /// previous vote. The same candidate may retry; a second candidate
    /// in this term may not.
    pub fn request_vote(&mut self, term: u64, candidate: &str) -> (u64, bool) {
        if term < self.current_term {
            return (self.current_term, false);
        }
        if term > self.current_term {
            self.current_term = term;
            self.voted_for = None;
        }
        let grant = match &self.voted_for {
            None => true,
            Some(id) if id == candidate => true,
            Some(_) => false,
        };
        if grant {
            self.voted_for = Some(candidate.to_string());
        }
        (self.current_term, grant)
    }

    /// Start an election. The node votes for itself and must store this
    /// before it asks anyone else.
    pub fn begin_election(&mut self, self_id: &str) -> u64 {
        self.current_term = self.current_term.saturating_add(1);
        self.voted_for = Some(self_id.to_string());
        self.current_term
    }

    /// Heartbeat and append. A higher term steps this node out of an
    /// election. Only an empty append at predecessor 0 matches, because
    /// there is no stored log yet.
    pub fn append_entries(&mut self, term: u64, prev_index: u64, entries: usize) -> (u64, bool) {
        if term < self.current_term {
            return (self.current_term, false);
        }
        if term > self.current_term {
            self.current_term = term;
            self.voted_for = None;
        }
        if entries > 0 || prev_index != 0 {
            return (self.current_term, false);
        }
        (self.current_term, true)
    }
}

/// In-memory election role plus the durable fields.
#[derive(Clone, Debug)]
pub struct Node {
    pub persistent: Persistent,
    leader: bool,
    quorum: bool,
    last_from_leader: Instant,
    path: PathBuf,
}

impl Node {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join(STATE_NAME);
        let persistent = if path.is_file() {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?
        } else {
            Persistent::fresh()
        };
        Ok(Self {
            persistent,
            leader: false,
            quorum: false,
            last_from_leader: Instant::now()
                .checked_sub(Duration::from_secs(3600))
                .unwrap_or_else(Instant::now),
            path,
        })
    }

    pub fn is_leader(&self) -> bool {
        self.leader
    }

    pub fn has_quorum(&self) -> bool {
        self.quorum
    }

    pub fn set_leader(&mut self, leader: bool) {
        self.leader = leader;
        if !leader {
            self.quorum = false;
        }
    }

    pub fn set_quorum(&mut self, quorum: bool) {
        self.quorum = quorum;
    }

    pub fn heard_leader(&mut self) {
        self.last_from_leader = Instant::now();
        self.leader = false;
        self.quorum = false;
    }

    /// Wait a full election timeout before trying again.
    pub fn arm_timer(&mut self) {
        self.last_from_leader = Instant::now();
    }

    pub fn leader_silent(&self, timeout: Duration) -> bool {
        self.last_from_leader.elapsed() >= timeout
    }

    pub fn state_path(&self) -> &Path {
        &self.path
    }

    pub fn save(&self) -> Result<()> {
        let body = serde_json::to_vec(&self.persistent)?;
        crate::pki::atomic_write(&self.path, &body, 0o600)
    }
}

/// fsync `state` without holding the election mutex. `tokio::fs::write`
/// returns before the bytes are durable, so a crash could grant the
/// same term twice.
pub async fn persist(path: &Path, state: &Persistent) -> Result<()> {
    let body = serde_json::to_vec(state)?;
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::pki::atomic_write(&path, &body, 0o600))
        .await
        .context("raft state write")?
}

/// `jitter` is any integer. The result stays inside 150–300ms.
pub fn election_timeout(jitter: u64) -> Duration {
    let span = ELECTION_MAX.as_millis() as u64 - ELECTION_MIN.as_millis() as u64;
    Duration::from_millis(ELECTION_MIN.as_millis() as u64 + (jitter % (span + 1)))
}

pub fn jitter() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0)
}

/// `acks` counts other voters that accepted this heartbeat. This node
/// is the remaining vote.
pub fn leader_has_quorum(voters: usize, acks: usize) -> bool {
    if voters == 0 {
        return false;
    }
    let majority = voters / 2 + 1;
    1 + acks >= majority
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_term_grants_one_candidate_and_remembers_it() {
        let mut s = Persistent::fresh();
        let (term, ok) = s.request_vote(1, "a");
        assert!(ok);
        assert_eq!(term, 1);
        let (_, again) = s.request_vote(1, "a");
        assert!(again);
        let (_, other) = s.request_vote(1, "b");
        assert!(!other);
        assert_eq!(s.voted_for.as_deref(), Some("a"));
    }

    #[test]
    fn a_higher_term_forgets_the_previous_vote() {
        let mut s = Persistent::fresh();
        s.request_vote(1, "a");
        let (term, ok) = s.request_vote(2, "b");
        assert!(ok);
        assert_eq!(term, 2);
        assert_eq!(s.voted_for.as_deref(), Some("b"));
        let (term, ok) = s.request_vote(1, "a");
        assert!(!ok);
        assert_eq!(term, 2);
    }

    #[test]
    fn begin_election_votes_for_self_before_anyone_else_can() {
        let mut s = Persistent::fresh();
        assert_eq!(s.begin_election("self"), 1);
        let (_, ok) = s.request_vote(1, "other");
        assert!(!ok);
    }

    #[test]
    fn an_empty_heartbeat_matches_and_a_log_entry_does_not() {
        let mut s = Persistent::fresh();
        let (term, ok) = s.append_entries(3, 0, 0);
        assert!(ok);
        assert_eq!(term, 3);
        let (_, ok) = s.append_entries(3, 0, 1);
        assert!(!ok);
        let (term, ok) = s.append_entries(2, 0, 0);
        assert!(!ok);
        assert_eq!(term, 3);
    }

    #[test]
    fn state_survives_a_reopen() {
        let dir = std::env::temp_dir().join(format!("rp-raft-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut node = Node::open(&dir).unwrap();
        node.persistent.begin_election("fd7e::1");
        node.save().unwrap();
        let again = Node::open(&dir).unwrap();
        assert_eq!(again.persistent.current_term, 1);
        assert_eq!(again.persistent.voted_for.as_deref(), Some("fd7e::1"));
        let (_, ok) = {
            let mut p = again.persistent.clone();
            p.request_vote(1, "other")
        };
        assert!(!ok);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn election_timeout_stays_inside_the_window() {
        assert_eq!(election_timeout(0), ELECTION_MIN);
        assert_eq!(election_timeout(150), ELECTION_MAX);
        assert_eq!(election_timeout(151), ELECTION_MIN);
    }

    #[test]
    fn one_witness_ack_is_quorum_for_three_voters_and_not_for_five() {
        assert!(!leader_has_quorum(3, 0));
        assert!(leader_has_quorum(3, 1));
        assert!(!leader_has_quorum(5, 1));
        assert!(leader_has_quorum(5, 2));
        assert!(leader_has_quorum(1, 0));
    }
}
