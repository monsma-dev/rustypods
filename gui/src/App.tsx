import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import type { DaemonStatus, ImageInfo, MetricSample, PodInfo } from "./types";

type View = "pods" | "stacks" | "images" | "settings";

const NAV: { id: View; label: string; icon: string }[] = [
  { id: "pods", label: "Pods", icon: "▣" },
  { id: "stacks", label: "Stacks", icon: "⧉" },
  { id: "images", label: "Images", icon: "◈" },
  { id: "settings", label: "Settings", icon: "⚙" },
];

const GIB = 2 ** 30;

const fmtGib = (bytes: number) =>
  bytes === 0 ? "unlimited" : `${(bytes / GIB).toFixed(1)} GiB`;

/** Live metric ring buffer (30 samples) for one pod — only when running. */
function useMetrics(pod: string, active: boolean): MetricSample[] {
  const [samples, setSamples] = useState<MetricSample[]>([]);
  useEffect(() => {
    if (!active) {
      setSamples([]);
      return;
    }
    let un: (() => void) | undefined;
    let dead = false;
    api
      .onMetrics(pod, (m) => {
        if (!dead) setSamples((s) => [...s.slice(-29), m]);
      })
      .then((u) => (un = u));
    api.watchMetrics(pod);
    return () => {
      dead = true;
      un?.();
      api.unwatchMetrics(pod);
    };
  }, [pod, active]);
  return samples;
}

/* ---------- headerbar (frameless window chrome) ---------- */

function WinBtn({
  label,
  onClick,
  danger = false,
}: {
  label: string;
  onClick: () => void;
  danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex h-7 w-9 items-center justify-center text-xs text-muted transition-colors hover:bg-white/10 ${
        danger ? "hover:bg-err hover:text-white" : ""
      }`}
      aria-label={label}
    >
      {label}
    </button>
  );
}

function HeaderBar({ title }: { title: string }) {
  const win = api.inTauri
    ? () => import("@tauri-apps/api/window").then((m) => m.getCurrentWindow())
    : null;
  const act = (f: (w: any) => void) => () => win?.().then(f);
  return (
    <header
      data-tauri-drag-region
      className="flex h-9 shrink-0 items-center justify-between border-b border-white/10 bg-bg2 select-none"
    >
      <div
        data-tauri-drag-region
        className="flex items-center gap-2 px-3 text-[12px] font-semibold"
      >
        <span data-tauri-drag-region className="text-accent">◆</span>
        RustyPods
        <span data-tauri-drag-region className="font-normal text-muted">— {title}</span>
      </div>
      <div className="flex h-full items-stretch">
        <WinBtn label="–" onClick={act((w) => w.minimize())} />
        <WinBtn label="▢" onClick={act((w) => w.toggleMaximize())} />
        <WinBtn label="✕" danger onClick={act((w) => w.close())} />
      </div>
    </header>
  );
}

/* ---------- atoms ---------- */

function StateBadge({ state }: { state: PodInfo["state"] }) {
  const cls =
    state === "running"
      ? "bg-ok/15 text-ok"
      : state === "failed"
        ? "bg-err/15 text-err"
        : "bg-white/5 text-muted";
  return (
    <span className={`rounded-md px-1.5 py-0.5 text-[11px] font-medium ${cls}`}>
      {state}
    </span>
  );
}

/** Libadwaita "inset list group": bordered card with divided rows. */
function Group({
  title,
  children,
}: {
  title?: string;
  children: React.ReactNode;
}) {
  return (
    <section>
      {title && (
        <h3 className="mb-1.5 px-1 text-[11px] font-semibold uppercase tracking-wider text-muted">
          {title}
        </h3>
      )}
      <div className="divide-y divide-white/5 rounded-xl border border-white/10 bg-card">
        {children}
      </div>
    </section>
  );
}

function Row({
  label,
  value,
  mono = true,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-2.5">
      <span className="text-xs text-muted">{label}</span>
      <span className={`truncate text-xs ${mono ? "font-mono" : ""}`}>
        {value}
      </span>
    </div>
  );
}

/** Slider + numeric input bound to a raw value (0 = unlimited). `scale` is raw
 *  units per displayed unit (e.g. GiB→bytes); `step` the slider granularity. */
function LimitSlider({
  label,
  hint,
  value,
  onChange,
  max,
  step,
  scale,
  unit,
  fmt,
}: {
  label: string;
  hint?: string;
  value: number;
  onChange: (v: number) => void;
  max: number;
  step: number;
  scale: number;
  unit: string;
  fmt: (v: number) => string;
}) {
  return (
    <div className="px-4 py-3">
      <div className="mb-2 flex items-baseline justify-between">
        <div>
          <span className="text-xs font-medium">{label}</span>
          {hint && <span className="ml-2 text-[10px] text-muted">{hint}</span>}
        </div>
        <div className="flex items-center gap-1.5">
          <input
            type="number"
            min={0}
            max={max / scale}
            step={step / scale}
            value={value / scale}
            onChange={(e) =>
              onChange(
                Math.min(max, Math.max(0, Number(e.target.value) * scale))
              )
            }
            className="w-16 rounded-md border border-white/10 bg-bg px-1.5 py-0.5 text-right font-mono text-xs focus:border-accent focus:outline-none"
          />
          <span className="w-16 text-[10px] text-muted">
            {value === 0 ? "unlimited" : unit}
          </span>
        </div>
      </div>
      <input
        type="range"
        min={0}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="slider w-full"
        aria-label={label}
      />
      <div className="mt-0.5 flex justify-between text-[9px] text-muted">
        <span>0</span>
        <span>{fmt(max)}</span>
      </div>
    </div>
  );
}

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

const fmtBytesShort = (b: number) => {
  if (b >= GIB) return `${(b / GIB).toFixed(1)}G`;
  if (b >= 2 ** 20) return `${(b / 2 ** 20).toFixed(0)}M`;
  return `${(b / 2 ** 10).toFixed(0)}K`;
};

function MetricsSection({ pod, lean }: { pod: PodInfo; lean: boolean }) {
  const [samples, setSamples] = useState<MetricSample[]>([]);

  useEffect(() => {
    let un: (() => void) | undefined;
    let dead = false;
    api
      .onMetrics(pod.name, (m) => {
        if (!dead) setSamples((s) => [...s.slice(-59), m]);
      })
      .then((u) => (un = u));
    api.watchMetrics(pod.name);
    return () => {
      dead = true;
      un?.();
      api.unwatchMetrics(pod.name);
    };
  }, [pod.name]);

  const last = samples[samples.length - 1];
  const noData = !last || (last.mem_bytes === 0 && last.ts_unix_ms === 0);
  const peak = (f: (m: MetricSample) => number) =>
    Math.max(1, ...samples.map(f));

  return (
    <Group title="Live metrics">
      {noData ? (
        <p className="px-4 py-3 text-xs text-muted">
          No agent telemetry — the rustypods-agent reports only while the pod
          runs.
        </p>
      ) : lean ? (
        // Lean/RPi: text-only, no SVG work.
        <>
          <Row label="Memory" value={`${fmtBytesShort(last.mem_bytes)} used`} />
          <Row label="CPU" value={`${last.cpu_pct.toFixed(0)}%`} />
          <Row
            label="PSI (mem / io / cpu)"
            value={`${last.mem_psi_avg10.toFixed(1)} / ${last.io_psi_avg10.toFixed(1)} / ${last.cpu_psi_avg10.toFixed(1)}`}
          />
          <Row label="PIDs" value={String(last.pids)} />
        </>
      ) : (
        <>
          <div className="px-4 py-3">
            <div className="mb-1 flex justify-between text-[11px]">
              <span className="font-medium">Memory</span>
              <span className="font-mono text-muted">
                {fmtBytesShort(last.mem_bytes)}
                {pod.memory_max_bytes > 0 && ` / ${pod.memory_max}`}
              </span>
            </div>
            <Spark
              series={[samples.map((m) => m.mem_bytes)]}
              colors={["#3584e4"]}
              max={Math.max(
                pod.memory_max_bytes,
                pod.memory_high_bytes,
                peak((m) => m.mem_bytes) * 1.15
              )}
              marks={[
                pod.memory_high_bytes > 0 && { v: pod.memory_high_bytes, color: "#f6d32d" },
                pod.memory_max_bytes > 0 && { v: pod.memory_max_bytes, color: "#e01b24" },
              ].filter(Boolean) as { v: number; color: string }[]}
            />
          </div>
          <div className="px-4 py-3">
            <div className="mb-1 flex justify-between text-[11px]">
              <span className="font-medium">CPU</span>
              <span className="font-mono text-muted">
                {last.cpu_pct.toFixed(0)}%
                {pod.cpu_quota_percent > 0 && ` / ${pod.cpu_quota_percent}%`}
              </span>
            </div>
            <Spark
              series={[samples.map((m) => m.cpu_pct)]}
              colors={["#33d17a"]}
              max={Math.max(
                pod.cpu_quota_percent || 100,
                peak((m) => m.cpu_pct) * 1.15
              )}
              marks={
                pod.cpu_quota_percent > 0
                  ? [{ v: pod.cpu_quota_percent, color: "#f6d32d" }]
                  : []
              }
            />
          </div>
          <div className="px-4 py-3">
            <div className="mb-1 flex justify-between text-[11px]">
              <span className="font-medium">Pressure stall (avg10)</span>
              <span className="flex gap-2 font-mono text-muted">
                <span className="text-accent">mem {last.mem_psi_avg10.toFixed(1)}</span>
                <span className="text-warn">io {last.io_psi_avg10.toFixed(1)}</span>
                <span className="text-err">cpu {last.cpu_psi_avg10.toFixed(1)}</span>
              </span>
            </div>
            <Spark
              series={[
                samples.map((m) => m.mem_psi_avg10),
                samples.map((m) => m.io_psi_avg10),
                samples.map((m) => m.cpu_psi_avg10),
              ]}
              colors={["#3584e4", "#f6d32d", "#e01b24"]}
              max={Math.max(
                10,
                peak((m) => m.mem_psi_avg10),
                peak((m) => m.io_psi_avg10),
                peak((m) => m.cpu_psi_avg10)
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

const serializePort = (r: PortRow) =>
  `${r.host}:${r.pod}${r.proto === "udp" ? "/udp" : ""}`;

function PodDetail({
  pod,
  lean,
  onClose,
  act,
}: {
  pod: PodInfo;
  lean: boolean;
  onClose: () => void;
  act: (f: () => Promise<unknown>) => void;
}) {
  const [memHigh, setMemHigh] = useState(pod.memory_high_bytes);
  const [memMax, setMemMax] = useState(pod.memory_max_bytes);
  const [cpu, setCpu] = useState(pod.cpu_quota_percent);
  const [disk, setDisk] = useState(pod.storage_max_bytes);
  const [ports, setPorts] = useState<PortRow[]>(pod.ports.map(parsePort));
  const [newPort, setNewPort] = useState<PortRow>({ host: "", pod: "", proto: "tcp" });

  const dirty =
    memHigh !== pod.memory_high_bytes ||
    memMax !== pod.memory_max_bytes ||
    cpu !== pod.cpu_quota_percent ||
    disk !== pod.storage_max_bytes ||
    ports.map(serializePort).join(",") !== pod.ports.join(",");

  const running = pod.state === "running";

  const apply = () =>
    act(() =>
      api.updatePodConfig({
        name: pod.name,
        memory_high_bytes: memHigh,
        memory_max_bytes: memMax,
        cpu_quota_percent: cpu,
        storage_max_bytes: disk,
        ports: ports.map(serializePort),
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
    <div className="fixed inset-0 z-40" onClick={onClose}>
      <div className="absolute inset-0 bg-black/40" />
      <aside
        className="absolute right-0 top-0 flex h-full w-[400px] flex-col border-l border-white/10 bg-bg2 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* header */}
        <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="truncate text-sm font-bold">{pod.name}</h2>
              <StateBadge state={pod.state} />
            </div>
            <p className="mt-0.5 truncate text-[11px] text-muted">
              {pod.image}
              {running && ` · pid ${pod.leader_pid}`}
              {pod.stack && ` · stack ${pod.stack}`}
            </p>
          </div>
          <div className="flex items-center gap-1.5">
            {running ? (
              <button
                onClick={() => act(() => api.stopPod(pod.name))}
                className="rounded-lg bg-err/15 px-3 py-1.5 text-xs font-medium text-err transition-colors hover:bg-err/25"
              >
                Stop
              </button>
            ) : (
              <button
                onClick={() => act(() => api.startPod(pod.name))}
                className="rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accentHover"
              >
                Start
              </button>
            )}
            <button
              onClick={onClose}
              className="rounded-lg px-2 py-1.5 text-sm text-muted transition-colors hover:bg-white/5"
              aria-label="Close"
            >
              ✕
            </button>
          </div>
        </div>

        {/* body */}
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

          <Group title="Port forwarding">
            {ports.length === 0 && (
              <p className="px-4 py-3 text-xs text-muted">
                No published ports — traffic stays on the pod's own network.
              </p>
            )}
            {ports.map((r, i) => (
              <div key={i} className="flex items-center gap-2 px-4 py-2">
                <code className="flex-1 text-xs">
                  host :{r.host} → pod :{r.pod}
                  <span className="text-muted">/{r.proto}</span>
                </code>
                <button
                  onClick={() => setPorts(ports.filter((_, j) => j !== i))}
                  className="rounded-md px-2 py-0.5 text-xs text-muted transition-colors hover:bg-err/15 hover:text-err"
                >
                  Remove
                </button>
              </div>
            ))}
            <div className="flex items-center gap-1.5 px-4 py-2.5">
              <input
                placeholder="host"
                value={newPort.host}
                onChange={(e) => setNewPort({ ...newPort, host: e.target.value })}
                className="w-16 rounded-md border border-white/10 bg-bg px-1.5 py-1 font-mono text-xs focus:border-accent focus:outline-none"
              />
              <span className="text-xs text-muted">→</span>
              <input
                placeholder="pod"
                value={newPort.pod}
                onChange={(e) => setNewPort({ ...newPort, pod: e.target.value })}
                className="w-16 rounded-md border border-white/10 bg-bg px-1.5 py-1 font-mono text-xs focus:border-accent focus:outline-none"
              />
              <select
                value={newPort.proto}
                onChange={(e) =>
                  setNewPort({ ...newPort, proto: e.target.value as "tcp" | "udp" })
                }
                className="rounded-md border border-white/10 bg-bg px-1.5 py-1 text-xs focus:border-accent focus:outline-none"
              >
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
              </select>
              <button
                disabled={!validNew}
                onClick={() => {
                  setPorts([...ports, newPort]);
                  setNewPort({ host: "", pod: "", proto: "tcp" });
                }}
                className="ml-auto rounded-lg bg-white/10 px-2.5 py-1 text-xs font-medium transition-colors hover:bg-white/15 disabled:opacity-40"
              >
                Add
              </button>
            </div>
          </Group>
        </div>

        {/* footer */}
        <div className="flex items-center justify-between border-t border-white/10 px-4 py-3">
          <span className="text-[11px] text-muted">
            {dirty ? "Unsaved changes" : "Applied live — no restart needed"}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => {
                setMemHigh(pod.memory_high_bytes);
                setMemMax(pod.memory_max_bytes);
                setCpu(pod.cpu_quota_percent);
                setDisk(pod.storage_max_bytes);
                setPorts(pod.ports.map(parsePort));
              }}
              disabled={!dirty}
              className="rounded-lg px-3 py-1.5 text-xs text-muted transition-colors hover:bg-white/5 disabled:opacity-40"
            >
              Reset
            </button>
            <button
              onClick={apply}
              disabled={!dirty}
              className="rounded-lg bg-accent px-4 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accentHover disabled:opacity-40"
            >
              Apply
            </button>
          </div>
        </div>
      </aside>
    </div>
  );
}

/* ---------- views ---------- */

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
  onOpen,
}: {
  pod: PodInfo;
  act: (f: () => Promise<unknown>) => void;
  onOpen: (p: PodInfo) => void;
}) {
  const running = pod.state === "running";
  const samples = useMetrics(pod.name, running);
  const last = samples[samples.length - 1];
  const memMax = Math.max(
    pod.memory_max_bytes,
    pod.memory_high_bytes,
    ...samples.map((m) => m.mem_bytes),
    1
  );
  const limits = [
    pod.memory_max_bytes > 0 && `≤${pod.memory_max}`,
    pod.cpu_quota_percent > 0 && `${pod.cpu_quota_percent}%`,
    pod.storage_max_bytes > 0 && `${pod.storage_max}`,
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
          <span className="ml-2 font-mono text-[11px] text-muted">
            {pod.leader_pid}
          </span>
        )}
      </td>
      <td className="px-3 py-1">
        {running && last ? (
          <span className="flex items-center gap-2">
            <MiniSpark data={samples.map((m) => m.mem_bytes)} max={memMax} />
            <span className="font-mono text-[11px] text-muted">
              {fmtBytesShort(last.mem_bytes)}
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
              pod.cpu_quota_percent > 0 && last.cpu_pct > pod.cpu_quota_percent
                ? "text-warn"
                : "text-muted"
            }
          >
            {last.cpu_pct.toFixed(0)}%
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
          <button
            onClick={(e) => {
              e.stopPropagation();
              act(() => api.stopPod(pod.name));
            }}
            className="rounded-md bg-err/15 px-2 py-0.5 text-[11px] font-medium text-err transition-colors hover:bg-err/25"
          >
            Stop
          </button>
        ) : (
          <button
            onClick={(e) => {
              e.stopPropagation();
              act(() => api.startPod(pod.name));
            }}
            className="rounded-md bg-accent px-2 py-0.5 text-[11px] font-medium text-white transition-colors hover:bg-accentHover"
          >
            Start
          </button>
        )}
      </td>
    </tr>
  );
}

function PodsView({
  pods,
  act,
  onOpen,
}: {
  pods: PodInfo[];
  act: (f: () => Promise<unknown>) => void;
  onOpen: (p: PodInfo) => void;
}) {
  if (pods.length === 0) {
    return (
      <p className="mt-10 text-center text-xs text-muted">
        No pods — create one with <code>rustypods create …</code>
      </p>
    );
  }
  return (
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
          <PodRow key={p.name} pod={p} act={act} onOpen={onOpen} />
        ))}
      </tbody>
    </table>
  );
}

function StacksView({
  pods,
  onOpen,
}: {
  pods: PodInfo[];
  onOpen: (p: PodInfo) => void;
}) {
  const groups = new Map<string, PodInfo[]>();
  for (const p of pods.filter((p) => p.stack)) {
    groups.set(p.stack, [...(groups.get(p.stack) ?? []), p]);
  }
  if (groups.size === 0) {
    return (
      <p className="mt-10 text-center text-sm text-muted">
        No stacks — apply one with <code>rustypods apply stack.toml</code>
      </p>
    );
  }
  return (
    <div className="space-y-4">
      {[...groups.entries()].map(([stack, members]) => (
        <Group key={stack} title={`${stack} · shared netns`}>
          {members.map((p) => (
            <button
              key={p.name}
              onClick={() => onOpen(p)}
              className="flex w-full items-center justify-between px-4 py-2.5 text-left transition-colors hover:bg-white/[0.04]"
            >
              <span className="text-[13px] font-medium">{p.name}</span>
              <span className="flex items-center gap-3">
                <span className="font-mono text-[11px] text-muted">
                  {p.ports.join(", ")}
                </span>
                <StateBadge state={p.state} />
              </span>
            </button>
          ))}
        </Group>
      ))}
    </div>
  );
}

function ImagesView({ images }: { images: ImageInfo[] }) {
  if (images.length === 0) {
    return (
      <p className="mt-10 text-center text-sm text-muted">
        No images — <code>rustypods import --from-distrobox …</code>
      </p>
    );
  }
  return (
    <Group>
      {images.map((i) => (
        <div key={i.name} className="flex items-center justify-between px-4 py-2.5">
          <div>
            <div className="text-[13px] font-medium">{i.name}</div>
            <div className="font-mono text-[11px] text-muted">{i.path}</div>
          </div>
          <span className="text-xs text-muted">{i.source}</span>
        </div>
      ))}
    </Group>
  );
}

function SettingsView({
  info,
  intervalMs,
  setIntervalMs,
  reduceMotion,
  setReduceMotion,
}: {
  info: DaemonStatus | null;
  intervalMs: number;
  setIntervalMs: (v: number) => void;
  reduceMotion: boolean;
  setReduceMotion: (v: boolean) => void;
}) {
  return (
    <div className="max-w-xl space-y-5">
      <Group title="Daemon">
        {info ? (
          <>
            <Row label="Version" value={info.version} />
            <Row label="Socket" value={info.socket_path} />
            <Row label="Data dir" value={info.data_dir} />
            <Row label="Runtime engine" value={info.runtime_engine} />
            <Row label="machined" value={String(info.machined)} />
          </>
        ) : (
          <p className="px-4 py-3 text-xs text-muted">daemon unreachable</p>
        )}
      </Group>

      <Group title="Interface">
        <div className="flex items-center justify-between px-4 py-3">
          <div>
            <div className="text-[13px] font-medium">Refresh interval</div>
            <div className="text-[11px] text-muted">
              How often pod state is polled. Higher = lighter on slow hardware.
            </div>
          </div>
          <select
            value={intervalMs}
            onChange={(e) => setIntervalMs(Number(e.target.value))}
            className="rounded-lg border border-white/10 bg-bg px-2 py-1 text-xs focus:border-accent focus:outline-none"
          >
            <option value={1000}>1 s</option>
            <option value={2000}>2 s</option>
            <option value={5000}>5 s</option>
            <option value={10000}>10 s</option>
          </select>
        </div>
        <label className="flex cursor-pointer items-center justify-between px-4 py-3">
          <div>
            <div className="text-[13px] font-medium">Reduce motion</div>
            <div className="text-[11px] text-muted">
              Disable animations — recommended on Raspberry Pi.
            </div>
          </div>
          <input
            type="checkbox"
            checked={reduceMotion}
            onChange={(e) => setReduceMotion(e.target.checked)}
            className="h-5 w-9 cursor-pointer accent-accent"
          />
        </label>
      </Group>

      <Group title="Storage">
        <Row label="Driver" value={info?.storage_driver ?? "—"} />
        <Row
          label="Quotas"
          value={
            info?.storage_driver === "btrfs"
              ? "btrfs qgroups — hot-applied"
              : "unavailable (non-btrfs)"
          }
          mono={false}
        />
        <Row
          label="Snapshots"
          value={
            info?.storage_driver === "btrfs"
              ? "instant CoW (commit / rollback)"
              : "reflink copy fallback"
          }
          mono={false}
        />
      </Group>
    </div>
  );
}

/* ---------- app ---------- */

export default function App() {
  const [view, setView] = useState<View>(() => {
    const v = new URLSearchParams(location.search).get("view");
    return v === "stacks" || v === "images" || v === "settings" ? v : "pods";
  });
  const [pods, setPods] = useState<PodInfo[]>([]);
  const [images, setImages] = useState<ImageInfo[]>([]);
  const [info, setInfo] = useState<DaemonStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [intervalMs, setIntervalMs] = useState(2000);
  const [reduceMotion, setReduceMotion] = useState(false);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<string | null>(
    () => new URLSearchParams(location.search).get("detail")
  );

  const refresh = useCallback(async () => {
    try {
      const [p, i, d] = await Promise.all([
        api.getPods(),
        api.getImages(),
        api.getDaemonInfo(),
      ]);
      setPods(p);
      setImages(i);
      setInfo(d);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, intervalMs);
    return () => clearInterval(t);
  }, [refresh, intervalMs]);

  const act = useCallback(
    async (f: () => Promise<unknown>) => {
      setBusy(true);
      try {
        await f();
        await refresh();
      } catch (e) {
        setError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [refresh]
  );

  const selectedPod = useMemo(
    () => pods.find((p) => p.name === selected) ?? null,
    [pods, selected]
  );

  const titles: Record<View, string> = {
    pods: "Pods",
    stacks: "Stacks",
    images: "Images",
    settings: "Settings",
  };

  return (
    <div
      className={`flex h-screen flex-col overflow-hidden ${reduceMotion ? "lean" : ""}`}
    >
      <HeaderBar
        title={`${titles[view]}${busy ? " · working…" : ""}${info && !info.machined ? " · machined degraded" : ""}`}
      />
      <div className="flex min-h-0 flex-1">
        <aside className="flex w-48 shrink-0 flex-col border-r border-white/10 bg-bg2">
          <nav className="flex-1 space-y-px overflow-y-auto p-1.5">
            {NAV.map((n) => (
              <button
                key={n.id}
                onClick={() => setView(n.id)}
                className={`flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-[13px] transition-colors ${
                  view === n.id
                    ? "bg-accent/15 font-medium text-accent"
                    : "text-fg/80 hover:bg-white/5"
                }`}
              >
                <span className="w-4 text-center">{n.icon}</span>
                {n.label}
                {n.id === "pods" && pods.length > 0 && (
                  <span className="ml-auto rounded bg-white/5 px-1.5 text-[10px] text-muted">
                    {pods.length}
                  </span>
                )}
              </button>
            ))}
          </nav>
          <div className="border-t border-white/10 px-3 py-2 text-[10px] text-muted">
            {info ? (
              <span className="font-mono">
                v{info.version} · {info.storage_driver}
              </span>
            ) : (
              "daemon offline"
            )}
          </div>
        </aside>

        <main className="flex-1 overflow-y-auto">
          <div className="p-3">
            {error && (
              <div className="mb-3 rounded-lg border border-err/40 bg-err/10 px-3 py-1.5 text-xs text-err">
                {error}
              </div>
            )}
            {view === "pods" && (
              <PodsView
                pods={pods}
                act={act}
                onOpen={(p) => setSelected(p.name)}
              />
            )}
            {view === "stacks" && (
              <StacksView pods={pods} onOpen={(p) => setSelected(p.name)} />
            )}
            {view === "images" && <ImagesView images={images} />}
            {view === "settings" && (
              <SettingsView
                info={info}
                intervalMs={intervalMs}
                setIntervalMs={setIntervalMs}
                reduceMotion={reduceMotion}
                setReduceMotion={setReduceMotion}
              />
            )}
          </div>
        </main>
      </div>

      {selectedPod && (
        <PodDetail
          key={selectedPod.name}
          pod={selectedPod}
          lean={reduceMotion || intervalMs >= 5000}
          onClose={() => setSelected(null)}
          act={act}
        />
      )}
    </div>
  );
}
