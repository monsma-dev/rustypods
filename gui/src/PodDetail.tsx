import { useEffect, useState } from "react";
import * as api from "./api";
import type { Metric, Pod } from "./api";
import { fmtBytesShort, fmtGib, GIB, isRunning, limitsOf, type PodAct } from "./lib";
import TermPane from "./TermPane";
import LogPane from "./LogPane";
import { StateBadge } from "./ui/StateBadge";
import { Group, Row } from "./ui/Group";
import { LimitSlider } from "./ui/LimitSlider";
import { NumberInput, TextInput } from "./ui/inputs";
import Button from "./ui/Button";
import { SlideOver, DialogHeader, DialogFooter } from "./ui/Dialog";
import { PlusIcon } from "./ui/icons";

export type DetailTab = "settings" | "logs" | "terminal";

/* ---------- live metrics ---------- */

/** Tiny SVG sparkline — one or more series, optional dashed limit markers. */
function Spark({
  series,
  colors,
  max,
  marks = [],
  h = 52,
}: {
  series: number[][];
  colors: string[];
  max: number;
  marks?: { v: number; color: string }[];
  h?: number;
}) {
  const w = 344;
  const y = (v: number) => h - Math.min(1, v / max) * (h - 2) - 1;
  const path = (data: number[]) =>
    data
      .map(
        (v, i) =>
          `${i === 0 ? "M" : "L"}${((i / Math.max(1, data.length - 1)) * w).toFixed(1)},${y(v).toFixed(1)}`
      )
      .join(" ");
  return (
    <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      {marks.map((m, i) => (
        <line
          key={i}
          x1={0}
          x2={w}
          y1={y(m.v)}
          y2={y(m.v)}
          stroke={m.color}
          strokeWidth={1}
          strokeDasharray="4 3"
          opacity={0.7}
        />
      ))}
      {series.map((data, i) => (
        <path
          key={i}
          d={path(data)}
          fill="none"
          stroke={colors[i]}
          strokeWidth={1.5}
          strokeLinejoin="round"
        />
      ))}
    </svg>
  );
}

function MetricsSection({ pod, lean }: { pod: Pod; lean: boolean }) {
  const [samples, setSamples] = useState<Metric[]>([]);

  useEffect(() => {
    let un: (() => void) | undefined;
    let dead = false;
    api
      .onMetrics(pod.name, (m) => {
        if (!dead) setSamples((s) => [...s.slice(-59), m]);
      })
      .then((u) => (dead ? u() : (un = u)));
    api.watchMetrics(pod.name);
    return () => {
      dead = true;
      un?.();
      api.unwatchMetrics(pod.name);
    };
  }, [pod.name]);

  const lim = limitsOf(pod);
  const last = samples[samples.length - 1];
  const noData = !last || (last.memBytes === 0 && last.tsUnixMs === 0);
  const peak = (f: (m: Metric) => number) => Math.max(1, ...samples.map(f));

  return (
    <Group title="Live metrics">
      {noData ? (
        <p className="px-4 py-3 text-[13px] text-muted">
          No agent telemetry — the rustypods-agent reports only while the pod runs.
        </p>
      ) : lean ? (
        // Lean/RPi: text-only, no SVG work.
        <>
          <Row label="Memory" value={`${fmtBytesShort(last.memBytes)} used`} />
          <Row label="CPU" value={`${last.cpuPct.toFixed(0)}%`} />
          <Row
            label="PSI (mem / io / cpu)"
            value={`${last.memPsiAvg10.toFixed(1)} / ${last.ioPsiAvg10.toFixed(1)} / ${last.cpuPsiAvg10.toFixed(1)}`}
          />
          <Row label="PIDs" value={String(last.pids)} />
        </>
      ) : (
        <>
          <div className="px-4 py-3">
            <div className="mb-1 flex justify-between text-[11px]">
              <span className="font-medium">Memory</span>
              <span className="font-mono text-muted">
                {fmtBytesShort(last.memBytes)}
                {lim.memoryMaxBytes > 0 && ` / ${fmtBytesShort(lim.memoryMaxBytes)}`}
              </span>
            </div>
            <Spark
              series={[samples.map((m) => m.memBytes)]}
              colors={["#3584e4"]}
              max={Math.max(
                lim.memoryMaxBytes,
                lim.memoryHighBytes,
                peak((m) => m.memBytes) * 1.15
              )}
              marks={[
                lim.memoryHighBytes > 0 && { v: lim.memoryHighBytes, color: "#f6d32d" },
                lim.memoryMaxBytes > 0 && { v: lim.memoryMaxBytes, color: "#e01b24" },
              ].filter(Boolean) as { v: number; color: string }[]}
            />
          </div>
          <div className="px-4 py-3">
            <div className="mb-1 flex justify-between text-[11px]">
              <span className="font-medium">CPU</span>
              <span className="font-mono text-muted">
                {last.cpuPct.toFixed(0)}%
                {lim.cpuQuotaPercent > 0 && ` / ${lim.cpuQuotaPercent}%`}
              </span>
            </div>
            <Spark
              series={[samples.map((m) => m.cpuPct)]}
              colors={["#33d17a"]}
              max={Math.max(lim.cpuQuotaPercent || 100, peak((m) => m.cpuPct) * 1.15)}
              marks={
                lim.cpuQuotaPercent > 0 ? [{ v: lim.cpuQuotaPercent, color: "#f6d32d" }] : []
              }
            />
          </div>
          <div className="px-4 py-3">
            <div className="mb-1 flex justify-between text-[11px]">
              <span className="font-medium">Pressure stall (avg10)</span>
              <span className="flex gap-2 font-mono text-muted">
                <span className="text-accent">mem {last.memPsiAvg10.toFixed(1)}</span>
                <span className="text-warn">io {last.ioPsiAvg10.toFixed(1)}</span>
                <span className="text-err">cpu {last.cpuPsiAvg10.toFixed(1)}</span>
              </span>
            </div>
            <Spark
              series={[
                samples.map((m) => m.memPsiAvg10),
                samples.map((m) => m.ioPsiAvg10),
                samples.map((m) => m.cpuPsiAvg10),
              ]}
              colors={["#3584e4", "#f6d32d", "#e01b24"]}
              max={Math.max(
                10,
                peak((m) => m.memPsiAvg10),
                peak((m) => m.ioPsiAvg10),
                peak((m) => m.cpuPsiAvg10)
              )}
            />
          </div>
        </>
      )}
    </Group>
  );
}

/* ---------- pod detail slide-over ---------- */

interface PortRow {
  host: string;
  pod: string;
  proto: "tcp" | "udp";
}

const parsePort = (spec: string): PortRow => {
  const [ports, proto] = spec.split("/");
  const [host, pod] = ports.split(":");
  return { host: host ?? "", pod: pod ?? "", proto: proto === "udp" ? "udp" : "tcp" };
};

const serializePort = (r: PortRow) => `${r.host}:${r.pod}${r.proto === "udp" ? "/udp" : ""}`;

/** "7d"/"24h"/"30m"/"60s" or bare seconds → seconds; null = empty/invalid. */
const parseAgeSecs = (s: string): number | null => {
  const m = /^(\d+)([smhd]?)$/.exec(s.trim());
  if (!m) return null;
  const mult = { "": 1, s: 1, m: 60, h: 3600, d: 86400 }[m[2]]!;
  return Number(m[1]) * mult;
};

/** Seconds → the shortest unit string ("7d", "24h", "90s"); 0 → "". */
const fmtAgeSecs = (secs: number): string => {
  if (secs === 0) return "";
  for (const [u, n] of [
    ["d", 86400],
    ["h", 3600],
    ["m", 60],
  ] as const)
    if (secs % n === 0) return `${secs / n}${u}`;
  return `${secs}s`;
};

export default function PodDetail({
  pod,
  lean,
  onClose,
  act,
  busy,
  initialTab,
}: {
  pod: Pod;
  lean: boolean;
  onClose: () => void;
  act: PodAct;
  busy: boolean;
  initialTab: DetailTab;
}) {
  const [tab, setTab] = useState<DetailTab>(initialTab);
  const lim = limitsOf(pod);
  const [memHigh, setMemHigh] = useState(lim.memoryHighBytes);
  const [memMax, setMemMax] = useState(lim.memoryMaxBytes);
  const [cpu, setCpu] = useState(lim.cpuQuotaPercent);
  const [disk, setDisk] = useState(pod.storageMaxBytes);
  const [ports, setPorts] = useState<PortRow[]>(pod.ports.map(parsePort));
  const [newPort, setNewPort] = useState<PortRow>({ host: "", pod: "", proto: "tcp" });
  // Snapshot retention — Max age stays a raw string so "7d" can be typed.
  const [snapKeep, setSnapKeep] = useState(pod.snapKeepLast);
  const [snapAge, setSnapAge] = useState(fmtAgeSecs(pod.snapMaxAgeSecs));

  // Empty age field = keep current; a parsed value that differs = change;
  // "0" clears the rule.
  const snapAgeSecs = parseAgeSecs(snapAge);
  const snapAgeValid = snapAge.trim() === "" || snapAgeSecs !== null;
  const snapKeepDirty = snapKeep !== pod.snapKeepLast;
  const snapAgeDirty = snapAgeSecs !== null && snapAgeSecs !== pod.snapMaxAgeSecs;

  const dirty =
    memHigh !== lim.memoryHighBytes ||
    memMax !== lim.memoryMaxBytes ||
    cpu !== lim.cpuQuotaPercent ||
    disk !== pod.storageMaxBytes ||
    ports.map(serializePort).join(",") !== pod.ports.join(",") ||
    snapKeepDirty ||
    snapAgeDirty;

  const running = isRunning(pod);

  const apply = () =>
    act([pod.name], () =>
      api.updatePodConfig({
        name: pod.name,
        limits: {
          memoryHighBytes: memHigh,
          memoryMaxBytes: memMax,
          cpuQuotaPercent: cpu,
        },
        storageMaxBytes: disk,
        ports: ports.map(serializePort),
        // Unchanged fields stay absent (None → daemon keeps the conf value).
        snapKeepLast: snapKeepDirty ? snapKeep : undefined,
        snapMaxAgeSecs: snapAgeDirty ? snapAgeSecs! : undefined,
      })
    );

  const validNew =
    /^\d+$/.test(newPort.host) &&
    /^\d+$/.test(newPort.pod) &&
    +newPort.host > 0 &&
    +newPort.host <= 65535 &&
    +newPort.pod > 0 &&
    +newPort.pod <= 65535;

  return (
    <SlideOver onClose={onClose}>
      <DialogHeader
        title={
          <>
            <div className="flex items-center gap-2">
              <h2 className="truncate text-sm font-bold">{pod.name}</h2>
              <StateBadge state={pod.state} />
            </div>
            <p className="mt-0.5 truncate text-[11px] text-muted">
              {pod.image}
              {running && ` · pid ${pod.leaderPid}`}
              {pod.stack && ` · stack ${pod.stack}`}
            </p>
          </>
        }
        onClose={onClose}
        extra={
          running ? (
            <Button
              variant="destructive"
              onClick={() => act([pod.name], () => api.stopPod(pod.name))}
              disabled={busy}
            >
              {busy ? "Stopping…" : "Stop"}
            </Button>
          ) : (
            <Button
              variant="suggested"
              onClick={() => act([pod.name], () => api.startPod(pod.name))}
              disabled={busy}
            >
              {busy ? "Starting…" : "Start"}
            </Button>
          )
        }
      />

      {/* tab switcher — same segmented style as the wizard's Isolation */}
      <div className="px-4 pt-3">
        <div className="grid grid-cols-3 gap-1 rounded-[var(--radius-control)] border border-white/[0.08] bg-bg p-1">
          {(["settings", "logs", "terminal"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`gn-focus rounded-md px-2.5 py-1.5 text-[13px] font-medium capitalize transition-colors ${
                tab === t ? "bg-accent/15 text-accent" : "text-fg/80 hover:bg-white/5"
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* body */}
      {tab === "terminal" ? (
        <div className="min-h-0 flex-1 p-4 pt-3">
          <TermPane pod={pod.name} running={running} />
        </div>
      ) : tab === "logs" ? (
        <div className="min-h-0 flex-1 p-4 pt-3">
          <LogPane pod={pod.name} running={running} />
        </div>
      ) : (
        <div className="flex-1 space-y-5 overflow-y-auto p-4">
          <MetricsSection pod={pod} lean={lean} />
          <Group title="Resources">
            <LimitSlider
              label="Memory high"
              hint="throttle above this"
              value={memHigh}
              onChange={setMemHigh}
              max={32 * GIB}
              step={GIB / 2}
              scale={GIB}
              unit="GiB"
              fmt={fmtGib}
            />
            <LimitSlider
              label="Memory max"
              hint="OOM-kill above this"
              value={memMax}
              onChange={setMemMax}
              max={32 * GIB}
              step={GIB / 2}
              scale={GIB}
              unit="GiB"
              fmt={fmtGib}
            />
            <LimitSlider
              label="CPU quota"
              hint="100% = 1 core"
              value={cpu}
              onChange={setCpu}
              max={800}
              step={25}
              scale={1}
              unit="%"
              fmt={(v) => `${v}%`}
            />
          </Group>

          <Group title="Storage">
            <LimitSlider
              label="Disk quota"
              hint="btrfs qgroup, hot-applied"
              value={disk}
              onChange={setDisk}
              max={100 * GIB}
              step={GIB}
              scale={GIB}
              unit="GiB"
              fmt={fmtGib}
            />
          </Group>

          <Group title="Snapshots">
            <div className="flex items-center justify-between gap-4 px-4 py-3">
              <div className="min-w-0">
                <div className="text-[13px] font-medium">Keep last</div>
                <div className="gn-caption mt-0.5">commits kept per pod — 0 keeps all</div>
              </div>
              <NumberInput
                min={0}
                value={snapKeep}
                onChange={(e) => setSnapKeep(Math.max(0, Number(e.target.value)))}
                className="w-24"
              />
            </div>
            <div className="flex items-center justify-between gap-4 px-4 py-3">
              <div className="min-w-0">
                <div className="text-[13px] font-medium">Max age</div>
                <div className="gn-caption mt-0.5">
                  7d / 24h / 30m / 60s — 0 clears, empty keeps
                </div>
              </div>
              <TextInput
                value={snapAge}
                placeholder="7d"
                onChange={(e) => setSnapAge(e.target.value)}
                mono
                invalid={!snapAgeValid}
                className="w-24 text-right"
              />
            </div>
          </Group>

          <Group title="Sandbox">
            <Row
              label="User namespace"
              sub="root in the pod is not root on the host"
              value={pod.privateUsers ? "on" : "off"}
            />
            <Row
              label="Bind mounts"
              sub="host paths visible inside the pod"
              value={pod.binds.length ? pod.binds.join(", ") : "none"}
            />
          </Group>

          <Group title="Port forwarding">
            {ports.length === 0 && (
              <p className="px-4 py-3 text-[13px] text-muted">
                No published ports — traffic stays on the pod's own network.
              </p>
            )}
            {ports.map((r, i) => (
              <div key={i} className="flex items-center gap-2 px-4 py-2">
                <code className="flex-1 text-[13px]">
                  host :{r.host} → pod :{r.pod}
                  <span className="text-muted">/{r.proto}</span>
                </code>
                <Button
                  variant="flat"
                  tone="danger"
                  size="sm"
                  onClick={() => setPorts(ports.filter((_, j) => j !== i))}
                >
                  Remove
                </Button>
              </div>
            ))}
            <div className="flex items-center gap-2 px-4 py-2.5">
              <TextInput
                placeholder="host"
                value={newPort.host}
                onChange={(e) => setNewPort({ ...newPort, host: e.target.value })}
                mono
                className="w-20"
              />
              <span className="text-[13px] text-muted">→</span>
              <TextInput
                placeholder="pod"
                value={newPort.pod}
                onChange={(e) => setNewPort({ ...newPort, pod: e.target.value })}
                mono
                className="w-20"
              />
              <select
                value={newPort.proto}
                onChange={(e) =>
                  setNewPort({ ...newPort, proto: e.target.value as "tcp" | "udp" })
                }
                className="gn-focus rounded-[var(--radius-control)] border border-white/10 bg-bg px-3 py-2 text-sm focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40"
              >
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
              </select>
              <Button
                variant="default"
                size="sm"
                disabled={!validNew}
                onClick={() => {
                  setPorts([...ports, newPort]);
                  setNewPort({ host: "", pod: "", proto: "tcp" });
                }}
                className="ml-auto"
              >
                <PlusIcon size={12} />
                Add
              </Button>
            </div>
          </Group>
        </div>
      )}

      {/* footer — config actions only make sense on the Settings tab */}
      {tab === "settings" && (
        <DialogFooter status={dirty ? "Unsaved changes" : "Applied live — no restart needed"}>
          <Button
            variant="default"
            onClick={() => {
              setMemHigh(lim.memoryHighBytes);
              setMemMax(lim.memoryMaxBytes);
              setCpu(lim.cpuQuotaPercent);
              setDisk(pod.storageMaxBytes);
              setPorts(pod.ports.map(parsePort));
              setSnapKeep(pod.snapKeepLast);
              setSnapAge(fmtAgeSecs(pod.snapMaxAgeSecs));
            }}
            disabled={!dirty}
          >
            Reset
          </Button>
          <Button variant="suggested" onClick={apply} disabled={!dirty || !snapAgeValid}>
            Apply
          </Button>
        </DialogFooter>
      )}
    </SlideOver>
  );
}
