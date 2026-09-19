import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import type { DaemonInfo, Image, Limits, Metric, Pod } from "./api";
import { PodState, podStateToJSON } from "./proto/rustypods";

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

const ZERO_LIMITS: Limits = {
  memoryHighBytes: 0,
  memoryMaxBytes: 0,
  cpuQuotaPercent: 0,
};
const limitsOf = (p: Pod): Limits => p.limits ?? ZERO_LIMITS;
const isRunning = (p: Pod) => p.state === PodState.POD_STATE_RUNNING;

/** Live metric ring buffer (30 samples) for one pod — only when running. */
function useMetrics(pod: string, active: boolean): Metric[] {
  const [samples, setSamples] = useState<Metric[]>([]);
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

function StateBadge({ state }: { state: PodState }) {
  const cls =
    state === PodState.POD_STATE_RUNNING
      ? "bg-ok/15 text-ok"
      : state === PodState.POD_STATE_FAILED
        ? "bg-err/15 text-err"
        : "bg-white/5 text-muted";
  return (
    <span className={`rounded-md px-1.5 py-0.5 text-[11px] font-medium ${cls}`}>
      {podStateToJSON(state).replace("POD_STATE_", "").toLowerCase()}
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

function MetricsSection({ pod, lean }: { pod: Pod; lean: boolean }) {
  const [samples, setSamples] = useState<Metric[]>([]);

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

  const lim = limitsOf(pod);
  const last = samples[samples.length - 1];
  const noData = !last || (last.memBytes === 0 && last.tsUnixMs === 0);
  const peak = (f: (m: Metric) => number) =>
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
              max={Math.max(
                lim.cpuQuotaPercent || 100,
                peak((m) => m.cpuPct) * 1.15
              )}
              marks={
                lim.cpuQuotaPercent > 0
                  ? [{ v: lim.cpuQuotaPercent, color: "#f6d32d" }]
                  : []
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

const serializePort = (r: PortRow) =>
  `${r.host}:${r.pod}${r.proto === "udp" ? "/udp" : ""}`;

function PodDetail({
  pod,
  lean,
  onClose,
  act,
}: {
  pod: Pod;
  lean: boolean;
  onClose: () => void;
  act: (f: () => Promise<unknown>) => void;
}) {
  const lim = limitsOf(pod);
  const [memHigh, setMemHigh] = useState(lim.memoryHighBytes);
  const [memMax, setMemMax] = useState(lim.memoryMaxBytes);
  const [cpu, setCpu] = useState(lim.cpuQuotaPercent);
  const [disk, setDisk] = useState(pod.storageMaxBytes);
  const [ports, setPorts] = useState<PortRow[]>(pod.ports.map(parsePort));
  const [newPort, setNewPort] = useState<PortRow>({ host: "", pod: "", proto: "tcp" });

  const dirty =
    memHigh !== lim.memoryHighBytes ||
    memMax !== lim.memoryMaxBytes ||
    cpu !== lim.cpuQuotaPercent ||
    disk !== pod.storageMaxBytes ||
    ports.map(serializePort).join(",") !== pod.ports.join(",");

  const running = isRunning(pod);

  const apply = () =>
    act(() =>
      api.updatePodConfig({
        name: pod.name,
        limits: {
          memoryHighBytes: memHigh,
          memoryMaxBytes: memMax,
          cpuQuotaPercent: cpu,
        },
        storageMaxBytes: disk,
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
              {running && ` · pid ${pod.leaderPid}`}
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
                className="rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent-hover"
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

          <Group title="Sandbox">
            <Row
              label="User namespace"
              value={
                pod.privateUsers ? "on (uid 0 ≠ host root)" : "off (shares host uids)"
              }
            />
            <Row
              label="Bind mounts"
              value={pod.binds.length ? pod.binds.join(", ") : "none"}
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
                setMemHigh(lim.memoryHighBytes);
                setMemMax(lim.memoryMaxBytes);
                setCpu(lim.cpuQuotaPercent);
                setDisk(pod.storageMaxBytes);
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
              className="rounded-lg bg-accent px-4 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-40"
            >
              Apply
            </button>
          </div>
        </div>
      </aside>
    </div>
  );
}

/* ---------- create pod wizard ---------- */

function NewPodDialog({
  images,
  onClose,
  onCreated,
}: {
  images: Image[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState("");
  const [image, setImage] = useState(images[0]?.name ?? "");
  const [memHigh, setMemHigh] = useState(0);
  const [memMax, setMemMax] = useState(0);
  const [cpu, setCpu] = useState(0);
  const [disk, setDisk] = useState(0);
  const [desktop, setDesktop] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [deploying, setDeploying] = useState(false);

  // Images may still be loading when the dialog opens (?newpod=1 deep link).
  useEffect(() => {
    if (!image && images.length > 0) setImage(images[0].name);
  }, [images, image]);

  const valid = name.trim().length > 0 && image.length > 0;

  const deploy = async () => {
    if (!valid || deploying) return;
    setDeploying(true);
    setErr(null);
    try {
      await api.createPod({
        name: name.trim(),
        image,
        limits: {
          memoryHighBytes: memHigh,
          memoryMaxBytes: memMax,
          cpuQuotaPercent: cpu,
        },
        storageMaxBytes: disk,
        ports: [],
        binds: [],
        desktop,
      });
      // start_pod sends private_users: None — the create-time isolation
      // choice is persisted in the pod conf and kept.
      await api.startPod(name.trim());
      onCreated();
      onClose();
    } catch (e) {
      setErr(String(e));
    } finally {
      setDeploying(false);
    }
  };

  return (
    <div className="fixed inset-0 z-40" onClick={onClose}>
      <div className="absolute inset-0 bg-black/40" />
      <div
        className="absolute left-1/2 top-1/2 flex max-h-[85vh] w-96 -translate-x-1/2 -translate-y-1/2 flex-col rounded-xl border border-white/10 bg-bg2 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
          <h2 className="text-sm font-bold">New Pod</h2>
          <button
            onClick={onClose}
            className="rounded-lg px-2 py-1 text-sm text-muted transition-colors hover:bg-white/5"
            aria-label="Close"
          >
            ✕
          </button>
        </div>

        <div className="flex-1 space-y-5 overflow-y-auto p-4">
          <div>
            <label className="mb-1 block text-xs font-medium">Name</label>
            <input
              autoFocus
              placeholder="my-pod"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded-md border border-white/10 bg-bg px-2.5 py-1.5 font-mono text-xs focus:border-accent focus:outline-none"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium">Image</label>
            <select
              value={image}
              onChange={(e) => setImage(e.target.value)}
              className="w-full rounded-md border border-white/10 bg-bg px-2 py-1.5 text-xs focus:border-accent focus:outline-none"
            >
              {images.length === 0 && <option value="">(no images)</option>}
              {images.map((i) => (
                <option key={i.name} value={i.name}>
                  {i.name}
                </option>
              ))}
            </select>
          </div>

          <div className="divide-y divide-white/5 rounded-xl border border-white/10 bg-card">
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
            <LimitSlider
              label="Disk quota"
              hint="btrfs qgroup"
              value={disk}
              onChange={setDisk}
              max={100 * GIB}
              step={GIB}
              scale={GIB}
              unit="GiB"
              fmt={fmtGib}
            />
          </div>

          <div>
            <span className="text-xs font-medium">Isolation</span>
            <div className="mt-1.5 grid grid-cols-2 gap-1 rounded-lg border border-white/10 bg-bg p-1">
              {[
                {
                  v: false,
                  title: "Hermetic",
                  desc: "user namespace — pod root is not host root",
                },
                {
                  v: true,
                  title: "Desktop mode",
                  desc: "mounts home + /tmp, shares host uids",
                },
              ].map((o) => (
                <button
                  key={o.title}
                  onClick={() => setDesktop(o.v)}
                  className={`rounded-md px-2.5 py-1.5 text-left transition-colors ${
                    desktop === o.v
                      ? "bg-accent/15 text-accent"
                      : "text-fg/80 hover:bg-white/5"
                  }`}
                >
                  <div className="text-xs font-medium">{o.title}</div>
                  <div className="mt-0.5 text-[10px] leading-tight text-muted">
                    {o.desc}
                  </div>
                </button>
              ))}
            </div>
          </div>

          {err && <p className="text-xs text-err">{err}</p>}
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-white/10 px-4 py-3">
          <button
            onClick={onClose}
            className="rounded-lg px-3 py-1.5 text-xs text-muted transition-colors hover:bg-white/5"
          >
            Cancel
          </button>
          <button
            onClick={deploy}
            disabled={!valid || deploying}
            className="rounded-lg bg-accent px-4 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-40"
          >
            {deploying ? "Deploying…" : "Deploy"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ---------- apply stack dialog ---------- */

const STACK_TOML_EXAMPLE = `# stack.toml — members become pods named <stack>-<member>
# on one shared netns (they see each other on 127.0.0.1).
name = "demo"

[pods.web]
image = "arch-base"
ports = ["8080:80"]

[pods.db]
image = "arch-base"
`;

function ApplyStackDialog({
  onClose,
  onApplied,
}: {
  onClose: () => void;
  onApplied: () => void;
}) {
  const [toml, setToml] = useState(STACK_TOML_EXAMPLE);
  const [err, setErr] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);

  const apply = async () => {
    if (applying || !toml.trim()) return;
    setApplying(true);
    setErr(null);
    try {
      await api.applyStack(toml);
      onApplied();
      onClose();
    } catch (e) {
      setErr(String(e));
    } finally {
      setApplying(false);
    }
  };

  return (
    <div className="fixed inset-0 z-40" onClick={onClose}>
      <div className="absolute inset-0 bg-black/40" />
      <div
        className="absolute left-1/2 top-1/2 flex max-h-[85vh] w-[28rem] -translate-x-1/2 -translate-y-1/2 flex-col rounded-xl border border-white/10 bg-bg2 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
          <h2 className="text-sm font-bold">Apply Stack</h2>
          <button
            onClick={onClose}
            className="rounded-lg px-2 py-1 text-sm text-muted transition-colors hover:bg-white/5"
            aria-label="Close"
          >
            ✕
          </button>
        </div>

        <div className="flex-1 space-y-3 overflow-y-auto p-4">
          <div>
            <label className="mb-1 block text-xs font-medium">stack.toml</label>
            <textarea
              autoFocus
              spellCheck={false}
              value={toml}
              onChange={(e) => setToml(e.target.value)}
              className="h-48 w-full resize-none rounded-md border border-white/10 bg-bg px-2.5 py-1.5 font-mono text-xs focus:border-accent focus:outline-none"
            />
          </div>
          {err && <p className="text-xs text-err">{err}</p>}
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-white/10 px-4 py-3">
          <button
            onClick={onClose}
            className="rounded-lg px-3 py-1.5 text-xs text-muted transition-colors hover:bg-white/5"
          >
            Cancel
          </button>
          <button
            onClick={apply}
            disabled={!toml.trim() || applying}
            className="rounded-lg bg-accent px-4 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-40"
          >
            {applying ? "Applying…" : "Apply"}
          </button>
        </div>
      </div>
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
  pod: Pod;
  act: (f: () => Promise<unknown>) => void;
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
          <span className="ml-2 font-mono text-[11px] text-muted">
            {pod.leaderPid}
          </span>
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
            className="rounded-md bg-accent px-2 py-0.5 text-[11px] font-medium text-white transition-colors hover:bg-accent-hover"
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
  onNew,
}: {
  pods: Pod[];
  act: (f: () => Promise<unknown>) => void;
  onOpen: (p: Pod) => void;
  onNew: () => void;
}) {
  return (
    <>
      <div className="mb-2 flex items-center justify-end">
        <button
          onClick={onNew}
          className="rounded-md bg-accent px-2 py-1 text-xs font-medium text-white transition-colors hover:bg-accent-hover"
        >
          + New Pod
        </button>
      </div>
      {pods.length === 0 ? (
        <p className="mt-10 text-center text-xs text-muted">
          No pods — create one above or with <code>rustypods create …</code>
        </p>
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
              <PodRow key={p.name} pod={p} act={act} onOpen={onOpen} />
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function StacksView({
  pods,
  act,
  onOpen,
  onNew,
}: {
  pods: Pod[];
  act: (f: () => Promise<unknown>) => void;
  onOpen: (p: Pod) => void;
  onNew: () => void;
}) {
  // Which stack group is showing the inline "Destroy? [yes] [no]" confirm.
  const [confirming, setConfirming] = useState<string | null>(null);
  const groups = new Map<string, Pod[]>();
  for (const p of pods.filter((p) => p.stack)) {
    groups.set(p.stack, [...(groups.get(p.stack) ?? []), p]);
  }
  return (
    <>
      <div className="mb-2 flex items-center justify-end">
        <button
          onClick={onNew}
          className="rounded-md bg-accent px-2 py-1 text-xs font-medium text-white transition-colors hover:bg-accent-hover"
        >
          + Apply stack.toml
        </button>
      </div>
      {groups.size === 0 ? (
        <p className="mt-10 text-center text-sm text-muted">
          No stacks — apply one with <code>rustypods apply stack.toml</code>
        </p>
      ) : (
        <div className="space-y-4">
          {[...groups.entries()].map(([stack, members]) => (
            <Group
              key={stack}
              title={`${stack} · shared netns rustypods-${stack}`}
            >
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
              <div className="flex items-center gap-1.5 px-4 py-2">
                <button
                  onClick={() =>
                    act(async () => {
                      for (const p of members.filter((p) => !isRunning(p)))
                        await api.startPod(p.name);
                    })
                  }
                  className="rounded-md px-2 py-1 text-xs font-medium text-muted transition-colors hover:bg-white/5 hover:text-fg"
                >
                  Start all
                </button>
                <button
                  onClick={() =>
                    act(async () => {
                      for (const p of members.filter(isRunning))
                        await api.stopPod(p.name);
                    })
                  }
                  className="rounded-md px-2 py-1 text-xs font-medium text-muted transition-colors hover:bg-white/5 hover:text-fg"
                >
                  Stop all
                </button>
                {confirming === stack ? (
                  <span className="ml-auto flex items-center gap-1.5 text-xs font-medium text-err">
                    Destroy?
                    <button
                      onClick={() => {
                        setConfirming(null);
                        act(() => api.destroyStack(stack));
                      }}
                      className="rounded-md bg-err/15 px-2 py-1 text-xs font-medium text-err transition-colors hover:bg-err/25"
                    >
                      yes
                    </button>
                    <button
                      onClick={() => setConfirming(null)}
                      className="rounded-md px-2 py-1 text-xs text-muted transition-colors hover:bg-white/5"
                    >
                      no
                    </button>
                  </span>
                ) : (
                  <button
                    onClick={() => setConfirming(stack)}
                    className="ml-auto rounded-md px-2 py-1 text-xs font-medium text-err/80 transition-colors hover:bg-err/15 hover:text-err"
                  >
                    Destroy
                  </button>
                )}
              </div>
            </Group>
          ))}
        </div>
      )}
    </>
  );
}

function ImagesView({ images }: { images: Image[] }) {
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
  info: DaemonInfo | null;
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
            <Row label="Socket" value={info.socketPath} />
            <Row label="Data dir" value={info.dataDir} />
            <Row label="Runtime engine" value={info.runtimeEngine} />
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
        <Row label="Driver" value={info?.storageDriver ?? "—"} />
        <Row
          label="Quotas"
          value={
            info?.btrfs
              ? "btrfs qgroups — hot-applied"
              : "unavailable (non-btrfs)"
          }
          mono={false}
        />
        <Row
          label="Snapshots"
          value={
            info?.btrfs
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
  const [pods, setPods] = useState<Pod[]>([]);
  const [images, setImages] = useState<Image[]>([]);
  const [info, setInfo] = useState<DaemonInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [intervalMs, setIntervalMs] = useState(2000);
  const [reduceMotion, setReduceMotion] = useState(false);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<string | null>(
    () => new URLSearchParams(location.search).get("detail")
  );
  const [newPodOpen, setNewPodOpen] = useState(
    () => new URLSearchParams(location.search).has("newpod")
  );
  const [applyStackOpen, setApplyStackOpen] = useState(
    () => new URLSearchParams(location.search).has("newstack")
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
                v{info.version} · {info.storageDriver}
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
                onNew={() => setNewPodOpen(true)}
              />
            )}
            {view === "stacks" && (
              <StacksView
                pods={pods}
                act={act}
                onOpen={(p) => setSelected(p.name)}
                onNew={() => setApplyStackOpen(true)}
              />
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

      {newPodOpen && (
        <NewPodDialog
          images={images}
          onClose={() => setNewPodOpen(false)}
          onCreated={refresh}
        />
      )}
      {applyStackOpen && (
        <ApplyStackDialog
          onClose={() => setApplyStackOpen(false)}
          onApplied={refresh}
        />
      )}
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
