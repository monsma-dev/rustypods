import { fmtBytesShort, isRunning, limitsOf, useMetrics, type PodAct } from "../lib";
import * as api from "../api";
import type { Pod } from "../api";
import { StateBadge } from "../ui/StateBadge";
import Button from "../ui/Button";
import { EmptyState } from "../ui/EmptyState";
import { PlusIcon, PodsIcon } from "../ui/icons";

/** Tiny inline sparkline for datagrid cells (w=72 fixed). */
function MiniSpark({ data, max }: { data: number[]; max: number }) {
  if (data.length < 2) return null;
  const w = 72,
    h = 14;
  const pts = data
    .map(
      (v, i) =>
        `${((i / (data.length - 1)) * w).toFixed(1)},${(h - Math.min(1, v / max) * (h - 1)).toFixed(1)}`
    )
    .join(" ");
  return (
    <svg width={w} height={h} className="inline-block align-middle">
      <polyline points={pts} fill="none" stroke="#3584e4" strokeWidth={1} />
    </svg>
  );
}

function PodRow({
  pod,
  act,
  busy,
  onOpen,
}: {
  pod: Pod;
  act: PodAct;
  busy: boolean;
  onOpen: (p: Pod) => void;
}) {
  const running = isRunning(pod);
  const lim = limitsOf(pod);
  const samples = useMetrics(pod.name, running);
  const last = samples[samples.length - 1];
  const memMax = Math.max(
    lim.memoryMaxBytes,
    lim.memoryHighBytes,
    ...samples.map((m) => m.memBytes),
    1
  );
  const limits = [
    lim.memoryMaxBytes > 0 && `≤${fmtBytesShort(lim.memoryMaxBytes)}`,
    lim.cpuQuotaPercent > 0 && `${lim.cpuQuotaPercent}%`,
    pod.storageMaxBytes > 0 && `${fmtBytesShort(pod.storageMaxBytes)}`,
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <tr
      onClick={() => onOpen(pod)}
      className="h-9 cursor-pointer border-b border-white/5 transition-colors hover:bg-white/[0.04]"
    >
      <td className="px-3 py-1">
        <span className="font-medium">{pod.name}</span>
        <span className="ml-2 text-[11px] text-muted">
          {pod.image}
          {pod.stack && ` · ${pod.stack}`}
        </span>
      </td>
      <td className="px-3 py-1">
        <StateBadge state={pod.state} />
        {running && (
          <span className="ml-2 font-mono text-[11px] text-muted">{pod.leaderPid}</span>
        )}
      </td>
      <td className="px-3 py-1">
        {running && last ? (
          <span className="flex items-center gap-2">
            <MiniSpark data={samples.map((m) => m.memBytes)} max={memMax} />
            <span className="font-mono text-[11px] text-muted">
              {fmtBytesShort(last.memBytes)}
            </span>
          </span>
        ) : (
          <span className="text-[11px] text-muted">—</span>
        )}
      </td>
      <td className="px-3 py-1 font-mono text-[11px]">
        {running && last ? (
          <span
            className={
              lim.cpuQuotaPercent > 0 && last.cpuPct > lim.cpuQuotaPercent
                ? "text-warn"
                : "text-muted"
            }
          >
            {last.cpuPct.toFixed(0)}%
          </span>
        ) : (
          <span className="text-muted">—</span>
        )}
      </td>
      <td className="px-3 py-1 text-[11px] text-muted">{limits || "—"}</td>
      <td className="px-3 py-1 font-mono text-[11px] text-muted">
        {pod.ports.join(", ") || "—"}
      </td>
      <td className="px-3 py-1 text-right">
        {running ? (
          <Button
            variant="destructive"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              act([pod.name], () => api.stopPod(pod.name));
            }}
            disabled={busy}
          >
            {busy ? "Stopping…" : "Stop"}
          </Button>
        ) : (
          <Button
            variant="suggested"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              act([pod.name], () => api.startPod(pod.name));
            }}
            disabled={busy}
          >
            {busy ? "Starting…" : "Start"}
          </Button>
        )}
      </td>
    </tr>
  );
}

export default function PodsView({
  pods,
  act,
  busy,
  onOpen,
  onNew,
}: {
  pods: Pod[];
  act: PodAct;
  busy: Set<string>;
  onOpen: (p: Pod) => void;
  onNew: () => void;
}) {
  return (
    <>
      <div className="mb-2 flex items-center justify-end">
        <Button variant="suggested" onClick={onNew}>
          <PlusIcon size={14} />
          New Pod
        </Button>
      </div>
      {pods.length === 0 ? (
        <EmptyState
          icon={<PodsIcon size={26} />}
          title="No pods yet"
          description="Create one from an image, or run rustypods create <name> --image <image> from a terminal."
          action={
            <Button variant="suggested" shape="pill" onClick={onNew}>
              <PlusIcon size={14} />
              Create your first pod
            </Button>
          }
        />
      ) : (
        <table className="w-full text-left text-[13px]">
          <thead className="sticky top-0 bg-bg text-[10px] uppercase tracking-wider text-muted">
            <tr className="border-b border-white/10">
              <th className="px-3 py-1.5 font-medium">Pod</th>
              <th className="px-3 py-1.5 font-medium">Status</th>
              <th className="px-3 py-1.5 font-medium">Memory</th>
              <th className="px-3 py-1.5 font-medium">CPU</th>
              <th className="px-3 py-1.5 font-medium">Limits</th>
              <th className="px-3 py-1.5 font-medium">Ports</th>
              <th className="px-3 py-1.5 text-right font-medium"></th>
            </tr>
          </thead>
          <tbody>
            {pods.map((p) => (
              <PodRow key={p.name} pod={p} act={act} busy={busy.has(p.name)} onOpen={onOpen} />
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
