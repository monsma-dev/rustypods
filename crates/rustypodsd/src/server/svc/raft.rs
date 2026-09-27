//! Raft votes and heartbeats on the mesh listener.
//!
//! The certificate check already happened. These handlers also require
//! the claimed id to be the certificate's IP SAN, so a peer cannot ask
//! for a vote under someone else's name.

use super::super::*;
use std::net::Ipv6Addr;
use std::time::Duration;

use tokio::sync::watch;

const RPC_BOUND: Duration = Duration::from_millis(2000);
const TICK: Duration = Duration::from_millis(50);
/// WAN meshes run at tens of ms RTT; a fresh mTLS channel per call
/// makes each append ~3 RTTs. Pace heartbeats well under the election
/// floor so followers stay silent without drowning the link.
const HEARTBEAT_EVERY: Duration = Duration::from_millis(500);

fn attested(req: &Request<impl Sized>) -> Result<Ipv6Addr, Status> {
    req.extensions()
        .get::<crate::meshca::MeshNodeId>()
        .map(|id| id.addr)
        .ok_or_else(|| Status::unauthenticated("raft requires a mesh peer certificate"))
}

/// Election snapshot for `GetMeshStatus`. Independent of the
/// heartbeat/campaign path: it takes its own short lock rather than
/// threading a result out of `run`, so a GUI poll never waits on an
/// in-flight election.
pub(crate) async fn status(svc: &Svc) -> RaftState {
    let (current_term, voted_for, is_leader, has_quorum) = {
        let node = svc.raft.lock().await;
        (
            node.persistent.current_term,
            node.persistent.voted_for.clone().unwrap_or_default(),
            node.is_leader(),
            node.has_quorum(),
        )
    };
    // Configured voters (self + peers), not live acks — `has_quorum` is
    // the "is a majority reachable right now" signal. Falls back to a
    // plain conf read when the mesh isn't up, so the count is still
    // meaningful right after `mesh init` and before the tunnel starts.
    let peer_count = match svc.mesh() {
        Some(m) => m.peer_host_addrs().await.len(),
        None => crate::state::load_mesh(&svc.cfg.data_dir)
            .ok()
            .flatten()
            .map(|c| c.peers.len())
            .unwrap_or(0),
    };
    RaftState {
        current_term,
        is_leader,
        voted_for,
        quorum_size: (peer_count + 1) as u32,
        has_quorum,
        role: match svc.cfg.role {
            crate::ha::Role::Host => RaftRole::Host as i32,
            crate::ha::Role::Witness => RaftRole::Witness as i32,
        },
    }
}

pub(crate) async fn request_vote(
    svc: &Svc,
    req: Request<RequestVoteRequest>,
) -> Result<Response<RequestVoteResponse>, Status> {
    let peer = attested(&req)?;
    let body = req.into_inner();
    if body.candidate_id != peer.to_string() {
        return Err(Status::unauthenticated(
            "candidate id does not match the peer certificate",
        ));
    }
    let (term, granted, previous, snap, path) = {
        let mut node = svc.raft.lock().await;
        let previous = node.persistent.clone();
        let (term, granted) = node.persistent.request_vote(body.term, &body.candidate_id);
        let snap = node.persistent.clone();
        let path = node.state_path().to_path_buf();
        (term, granted, previous, snap, path)
    };
    commit_state(svc, previous, snap, path).await?;
    Ok(Response::new(RequestVoteResponse {
        term,
        vote_granted: granted,
    }))
}

/// Persist `snap` after the mutex is released. A failed write puts
/// `previous` back when memory still holds `snap`, and the caller must
/// not send the vote.
async fn commit_state(
    svc: &Svc,
    previous: crate::raft::Persistent,
    snap: crate::raft::Persistent,
    path: std::path::PathBuf,
) -> Result<(), Status> {
    if previous == snap {
        return Ok(());
    }
    if let Err(e) = crate::raft::persist(&path, &snap).await {
        let mut node = svc.raft.lock().await;
        if node.persistent == snap {
            node.persistent = previous;
        }
        return Err(Status::internal(format!("raft state: {e:#}")));
    }
    Ok(())
}

pub(crate) async fn append_entries(
    svc: &Svc,
    req: Request<AppendEntriesRequest>,
) -> Result<Response<AppendEntriesResponse>, Status> {
    let peer = attested(&req)?;
    let body = req.into_inner();
    if body.leader_id != peer.to_string() {
        return Err(Status::unauthenticated(
            "leader id does not match the peer certificate",
        ));
    }
    let (term, success, previous, snap, path) = {
        let mut node = svc.raft.lock().await;
        let previous = node.persistent.clone();
        let (term, success) =
            node.persistent
                .append_entries(body.term, body.prev_log_index, body.entries.len());
        let snap = node.persistent.clone();
        let path = node.state_path().to_path_buf();
        (term, success, previous, snap, path)
    };
    commit_state(svc, previous, snap, path).await?;
    if success {
        let mut node = svc.raft.lock().await;
        if node.persistent.current_term == term {
            node.heard_leader();
        }
    }
    Ok(Response::new(AppendEntriesResponse { term, success }))
}

/// Runs until the mesh listener is told to stop. A missed heartbeat
/// starts an election. A leader that hears a majority, counting itself,
/// records quorum. A witness keeps that bit and publishes nothing.
pub(crate) async fn run(svc: Svc, mut stop: watch::Receiver<bool>) {
    let mut timeout = crate::raft::election_timeout(crate::raft::jitter());
    let mut last_beat = std::time::Instant::now()
        .checked_sub(HEARTBEAT_EVERY)
        .unwrap_or_else(std::time::Instant::now);
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = tokio::time::sleep(TICK) => {}
        }
        if svc.mesh().is_none() {
            return;
        }
        let (leader, silent) = {
            let node = svc.raft.lock().await;
            (node.is_leader(), node.leader_silent(timeout))
        };
        if leader {
            if last_beat.elapsed() >= HEARTBEAT_EVERY {
                last_beat = std::time::Instant::now();
                if let Err(e) = heartbeat(&svc).await {
                    tracing::debug!("raft heartbeat: {e}");
                }
            }
            continue;
        }
        if silent {
            if let Err(e) = campaign(&svc).await {
                tracing::debug!("raft election: {e}");
            }
            timeout = crate::raft::election_timeout(crate::raft::jitter());
        }
    }
}

async fn campaign(svc: &Svc) -> Result<(), Status> {
    let Some(me) = self_id(svc) else {
        return Ok(());
    };
    let (term, previous, snap, path) = {
        let mut node = svc.raft.lock().await;
        let previous = node.persistent.clone();
        let term = node.persistent.begin_election(&me);
        node.set_leader(false);
        let snap = node.persistent.clone();
        let path = node.state_path().to_path_buf();
        (term, previous, snap, path)
    };
    commit_state(svc, previous, snap, path).await?;
    let peers = peer_addrs(svc).await;
    let mut grants = 0usize;
    for addr in &peers {
        match vote_one(svc, *addr, term, &me).await {
            Vote::Grant => grants += 1,
            Vote::Deny => {}
            Vote::Stop => {
                let mut node = svc.raft.lock().await;
                node.arm_timer();
                return Ok(());
            }
        }
    }
    let voters = 1 + peers.len();
    let mut node = svc.raft.lock().await;
    if node.persistent.current_term != term {
        return Ok(());
    }
    if crate::raft::leader_has_quorum(voters, grants) {
        node.set_leader(true);
        node.set_quorum(true);
        tracing::info!("raft leader term {term} quorum ({grants} other votes)");
    }
    node.arm_timer();
    Ok(())
}

async fn heartbeat(svc: &Svc) -> Result<(), Status> {
    let Some(me) = self_id(svc) else {
        return Ok(());
    };
    let term = svc.raft.lock().await.persistent.current_term;
    let peers = peer_addrs(svc).await;
    let mut acked = Vec::new();
    let mut step_down = false;
    for addr in &peers {
        match append_one(svc, *addr, term, &me).await {
            Append::Ack => acked.push(*addr),
            Append::HigherTerm => step_down = true,
            Append::Miss => {}
        }
    }
    let voters = 1 + peers.len();
    let roles = voters_of(svc, &me, &peers).await;
    let mut node = svc.raft.lock().await;
    if step_down || node.persistent.current_term != term {
        node.set_leader(false);
        return Ok(());
    }
    let quorum = crate::raft::leader_has_quorum(voters, acked.len());
    let was = node.has_quorum();
    node.set_quorum(quorum);
    if quorum && !was {
        tracing::info!("raft quorum held ({voters} voters, {} acks)", acked.len());
    }
    if quorum {
        let alive = alive_ids(&me, &acked);
        let decision = crate::ha::plan(&roles, &alive, &[]);
        // Publishing the resulting DNS waits until the log carries workloads.
        // The witness drops the generation here; a host leader keeps it.
        let _effect = crate::ha::local_effect(decision, svc.cfg.role);
    }
    Ok(())
}

async fn voters_of(svc: &Svc, me: &str, peers: &[Ipv6Addr]) -> Vec<crate::ha::Voter> {
    let witnesses = match svc.mesh() {
        Some(m) => m.witness_ids().await,
        None => std::collections::BTreeSet::new(),
    };
    let mut out = vec![crate::ha::Voter {
        id: me.to_string(),
        role: svc.cfg.role,
    }];
    for addr in peers {
        let id = addr.to_string();
        let role = if witnesses.contains(&id) {
            crate::ha::Role::Witness
        } else {
            crate::ha::Role::Host
        };
        out.push(crate::ha::Voter { id, role });
    }
    out
}

fn alive_ids(me: &str, acked: &[Ipv6Addr]) -> std::collections::BTreeSet<String> {
    let mut alive = std::collections::BTreeSet::new();
    alive.insert(me.to_string());
    for addr in acked {
        alive.insert(addr.to_string());
    }
    alive
}

enum Append {
    Ack,
    HigherTerm,
    Miss,
}

enum Vote {
    Grant,
    Deny,
    /// A higher term was seen. Do not send another RequestVote and do
    /// not become leader in the term we just campaigned for.
    Stop,
}

async fn vote_one(svc: &Svc, addr: Ipv6Addr, term: u64, me: &str) -> Vote {
    let call = async {
        let ch = svc.mesh_channel(addr, RPC_BOUND).await?;
        let mut client = rustypods_proto::rpc::pod_control_client::PodControlClient::new(ch);
        let res = client
            .request_vote(RequestVoteRequest {
                term,
                candidate_id: me.to_string(),
                last_log_index: 0,
                last_log_term: 0,
            })
            .await?
            .into_inner();
        Ok::<_, Status>(res)
    };
    match tokio::time::timeout(RPC_BOUND, call).await {
        Ok(Ok(res)) => {
            if res.term > term {
                let (previous, snap, path) = {
                    let mut node = svc.raft.lock().await;
                    if res.term > node.persistent.current_term {
                        let previous = node.persistent.clone();
                        node.persistent.current_term = res.term;
                        node.persistent.voted_for = None;
                        node.set_leader(false);
                        (
                            previous,
                            node.persistent.clone(),
                            node.state_path().to_path_buf(),
                        )
                    } else {
                        let same = node.persistent.clone();
                        (same.clone(), same, node.state_path().to_path_buf())
                    }
                };
                let _ = commit_state(svc, previous, snap, path).await;
                Vote::Stop
            } else if res.vote_granted {
                Vote::Grant
            } else {
                Vote::Deny
            }
        }
        _ => Vote::Deny,
    }
}

async fn append_one(svc: &Svc, addr: Ipv6Addr, term: u64, me: &str) -> Append {
    let call = async {
        let ch = svc.mesh_channel(addr, RPC_BOUND).await?;
        let mut client = rustypods_proto::rpc::pod_control_client::PodControlClient::new(ch);
        let res = client
            .append_entries(AppendEntriesRequest {
                term,
                leader_id: me.to_string(),
                prev_log_index: 0,
                prev_log_term: 0,
                entries: Vec::new(),
                leader_commit: 0,
            })
            .await?
            .into_inner();
        Ok::<_, Status>(res)
    };
    match tokio::time::timeout(RPC_BOUND, call).await {
        Ok(Ok(res)) if res.term > term => Append::HigherTerm,
        Ok(Ok(res)) if res.success => Append::Ack,
        _ => Append::Miss,
    }
}

fn self_id(svc: &Svc) -> Option<String> {
    svc.mesh().map(|m| m.host_addr.to_string())
}

async fn peer_addrs(svc: &Svc) -> Vec<Ipv6Addr> {
    match svc.mesh() {
        Some(m) => m.peer_host_addrs().await,
        None => Vec::new(),
    }
}
