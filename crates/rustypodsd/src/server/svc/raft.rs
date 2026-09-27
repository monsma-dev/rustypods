//! Raft votes and heartbeats on the mesh listener.
//!
//! The certificate check already happened. These handlers also require
//! the claimed id to be the certificate's IP SAN, so a peer cannot ask
//! for a vote under someone else's name.

use super::super::*;
use std::net::Ipv6Addr;
use std::time::Duration;

use tokio::sync::watch;

const RPC_BOUND: Duration = Duration::from_millis(200);
const TICK: Duration = Duration::from_millis(50);

fn attested(req: &Request<impl Sized>) -> Result<Ipv6Addr, Status> {
    req.extensions()
        .get::<crate::meshca::MeshNodeId>()
        .map(|id| id.addr)
        .ok_or_else(|| Status::unauthenticated("raft requires a mesh peer certificate"))
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
    let (term, granted) = {
        let mut node = svc.raft.lock().await;
        let previous = node.persistent.clone();
        let answer = node.persistent.request_vote(body.term, &body.candidate_id);
        if let Err(e) = node.save() {
            node.persistent = previous;
            return Err(Status::internal(format!("raft state: {e:#}")));
        }
        answer
    };
    Ok(Response::new(RequestVoteResponse {
        term,
        vote_granted: granted,
    }))
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
    let (term, success) = {
        let mut node = svc.raft.lock().await;
        let previous = node.persistent.clone();
        let answer =
            node.persistent
                .append_entries(body.term, body.prev_log_index, body.entries.len());
        if let Err(e) = node.save() {
            node.persistent = previous;
            return Err(Status::internal(format!("raft state: {e:#}")));
        }
        if answer.1 {
            node.heard_leader();
        }
        answer
    };
    Ok(Response::new(AppendEntriesResponse { term, success }))
}

/// Runs until the mesh listener is told to stop. A missed heartbeat
/// starts an election. A leader that hears a majority, counting itself,
/// records quorum. A witness keeps that bit and publishes nothing.
pub(crate) async fn run(svc: Svc, mut stop: watch::Receiver<bool>) {
    let mut timeout = crate::raft::election_timeout(crate::raft::jitter());
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
            if let Err(e) = heartbeat(&svc).await {
                tracing::debug!("raft heartbeat: {e}");
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
    let term = {
        let mut node = svc.raft.lock().await;
        let previous = node.persistent.clone();
        let term = node.persistent.begin_election(&me);
        if let Err(e) = node.save() {
            node.persistent = previous;
            return Err(Status::internal(format!("raft state: {e:#}")));
        }
        node.set_leader(false);
        term
    };
    let peers = peer_addrs(svc).await;
    let mut grants = 0usize;
    for addr in &peers {
        if vote_one(svc, *addr, term, &me).await {
            grants += 1;
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
        let decision = crate::ha::plan(&voters_of(&me, &peers), &alive, &[]);
        // Publishing the resulting DNS waits until the log carries workloads.
        // The witness drops the generation here; a host leader keeps it.
        let _effect = crate::ha::local_effect(decision, svc.cfg.role);
    }
    Ok(())
}

fn voters_of(me: &str, peers: &[Ipv6Addr]) -> Vec<crate::ha::Voter> {
    let mut out = vec![crate::ha::Voter {
        id: me.to_string(),
        role: crate::ha::Role::Host,
    }];
    for addr in peers {
        out.push(crate::ha::Voter {
            id: addr.to_string(),
            role: crate::ha::Role::Host,
        });
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

async fn vote_one(svc: &Svc, addr: Ipv6Addr, term: u64, me: &str) -> bool {
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
                let mut node = svc.raft.lock().await;
                if res.term > node.persistent.current_term {
                    node.persistent.current_term = res.term;
                    node.persistent.voted_for = None;
                    node.set_leader(false);
                    let _ = node.save();
                }
                false
            } else {
                res.vote_granted
            }
        }
        _ => false,
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
