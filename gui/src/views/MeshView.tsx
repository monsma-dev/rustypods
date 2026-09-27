import { useCallback, useEffect, useState } from "react";
import * as api from "../api";
import type { MeshStatus } from "../api";
import { RaftRole } from "../api";
import AddPeerDialog from "../AddPeerDialog";
import { Group, Row } from "../ui/Group";
import { Badge } from "../ui/Badge";
import Button from "../ui/Button";
import { EmptyState } from "../ui/EmptyState";
import { NetworkIcon, ShieldIcon, PlusIcon } from "../ui/icons";

/** Resolve raft.votedFor (a mesh gRPC addr) to a peer name / "itself". */
function votedForLabel(status: MeshStatus): string | null {
  const votedFor = status.raft?.votedFor;
  if (!votedFor) return null;
  if (votedFor === status.grpcAddr) return "itself";
  return status.peers.find((p) => p.grpcAddr === votedFor)?.name || votedFor;
}

function peerLabel(p: { name: string; pubkey: string }): string {
  if (p.name) return p.name;
  return p.pubkey.length > 12 ? `${p.pubkey.slice(0, 12)}…` : p.pubkey;
}

export default function MeshView() {
  const [status, setStatus] = useState<MeshStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [addPeerOpen, setAddPeerOpen] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setStatus(await api.getMeshStatus());
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 2000);
    return () => clearInterval(t);
  }, [refresh]);

  const raft = status?.raft;
  const isWitness = raft?.role === RaftRole.RAFT_ROLE_WITNESS;

  return (
    <div className="space-y-5">
      {error && (
        <div className="mb-3 rounded-lg border border-err/40 bg-err/10 px-3 py-2 text-[13px] text-err">
          {error}
        </div>
      )}

      {status === null && !error && (
        <p className="text-[13px] text-muted">Loading…</p>
      )}

      {status !== null && !status.enabled && (
        <EmptyState
          icon={<NetworkIcon size={26} />}
          title="Mesh not initialized"
          description={
            <>
              <span>
                Run <span className="font-mono">rustypods mesh init</span> on this host to bring
                the WireGuard mesh up. There is no GUI action for that yet.
              </span>
              {status.confError ? (
                <p className="mt-2 text-[13px] text-err">{status.confError}</p>
              ) : null}
            </>
          }
        />
      )}

      {status !== null && status.enabled && (
        <>
          <Group title="This host">
            <Row label="Identity" sub="WireGuard public key" value={status.pubkey} />
            <Row label="Prefix" sub="routed /48" value={status.prefix} />
            <Row label="gRPC" sub="mesh address" value={status.grpcAddr} />
            <Row label="Listen" value={status.listen} />
            <Row
              label="Raft"
              value={
                <Badge tone={raft?.isLeader ? "ok" : "muted"}>
                  {raft?.isLeader ? "Leader" : "Follower"}
                </Badge>
              }
              mono={false}
            />
            <Row
              label="Quorum"
              value={
                <Badge tone={raft?.hasQuorum ? "ok" : "err"}>
                  {raft?.hasQuorum ? "yes" : "no"} ({raft?.quorumSize ?? 0} voters)
                </Badge>
              }
              mono={false}
            />
            <Row label="Term" value={String(raft?.currentTerm ?? 0)} />
            <Row label="Voted for" value={votedForLabel(status) ?? "—"} />
            <Row
              label="Role"
              value={
                <Badge tone={isWitness ? "accent" : "muted"}>
                  {isWitness ? "Witness" : "Host"}
                </Badge>
              }
              mono={false}
            />
          </Group>

          <div>
            <div className="mb-2 flex items-center justify-between">
              <h3 className="gn-heading px-1">Peers</h3>
              <Button variant="suggested" onClick={() => setAddPeerOpen(true)}>
                <PlusIcon size={14} />
                Add peer
              </Button>
            </div>

            {status.peers.length === 0 ? (
              <EmptyState
                icon={<ShieldIcon size={26} />}
                title="No peers yet"
                description="Add a peer's endpoint and WireGuard public key to join the mesh."
                action={
                  <Button variant="suggested" shape="pill" onClick={() => setAddPeerOpen(true)}>
                    <PlusIcon size={14} />
                    Add your first peer
                  </Button>
                }
              />
            ) : (
              <Group>
                {status.peers.map((p) => (
                  <div
                    key={p.pubkey || p.endpoint}
                    className="flex items-center justify-between gap-3 px-4 py-2.5"
                  >
                    <div className="min-w-0 flex items-center gap-2">
                      <span className="truncate text-[13px] font-medium">{peerLabel(p)}</span>
                      {p.isWitness && <Badge tone="accent">witness</Badge>}
                      <Badge tone={p.handshakeSecsAgo >= 0 ? "ok" : "err"}>
                        {p.handshakeSecsAgo >= 0
                          ? `handshake ${p.handshakeSecsAgo}s ago`
                          : "no handshake"}
                      </Badge>
                    </div>
                    <span className="shrink-0 font-mono text-[11px] text-muted">
                      {p.grpcAddr || p.endpoint}
                    </span>
                  </div>
                ))}
              </Group>
            )}
          </div>
        </>
      )}

      {addPeerOpen && (
        <AddPeerDialog onClose={() => setAddPeerOpen(false)} onAdded={refresh} />
      )}
    </div>
  );
}
