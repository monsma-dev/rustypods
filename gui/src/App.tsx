import { useCallback, useEffect, useState } from "react";
import * as api from "./api";
import type { DaemonStatus, ImageInfo, PodInfo } from "./types";

type View = "pods" | "stacks" | "images" | "settings";

const NAV: { id: View; label: string; icon: string }[] = [
  { id: "pods", label: "Pods", icon: "▣" },
  { id: "stacks", label: "Stacks", icon: "⧉" },
  { id: "images", label: "Images", icon: "◈" },
  { id: "settings", label: "Settings", icon: "⚙" },
];

function StateBadge({ state }: { state: PodInfo["state"] }) {
  const cls =
    state === "running"
      ? "bg-ok/15 text-ok"
      : state === "failed"
        ? "bg-err/15 text-err"
        : "bg-muted/15 text-muted";
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${cls}`}>
      {state}
    </span>
  );
}

function PodCard({
  pod,
  busy,
  onStart,
  onStop,
}: {
  pod: PodInfo;
  busy: boolean;
  onStart: () => void;
  onStop: () => void;
}) {
  const running = pod.state === "running";
  const details = [
    pod.memory_max !== "0B" && `max ${pod.memory_max}`,
    pod.cpu_quota_percent > 0 && `cpu ${pod.cpu_quota_percent}%`,
    pod.storage_max !== "0B" && `disk ${pod.storage_max}`,
    pod.ports.length > 0 && `ports ${pod.ports.join(", ")}`,
    pod.stack && `stack ${pod.stack}`,
    pod.ephemeral && "ephemeral",
  ].filter(Boolean);
  return (
    <div className="rounded-xl border border-border bg-card p-4 transition-colors hover:bg-cardHover">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="truncate text-sm font-semibold">{pod.name}</h3>
          <p className="truncate text-xs text-muted">{pod.image}</p>
        </div>
        <StateBadge state={pod.state} />
      </div>
      {details.length > 0 && (
        <p className="mt-2 truncate text-xs text-muted">{details.join(" · ")}</p>
      )}
      <div className="mt-3 flex items-center justify-between">
        <span className="text-xs text-muted">
          {running ? `pid ${pod.leader_pid}` : "—"}
        </span>
        {running ? (
          <button
            disabled={busy}
            onClick={onStop}
            className="rounded-lg bg-err/15 px-3 py-1 text-xs font-medium text-err transition-colors hover:bg-err/25 disabled:opacity-40"
          >
            Stop
          </button>
        ) : (
          <button
            disabled={busy}
            onClick={onStart}
            className="rounded-lg bg-accent px-3 py-1 text-xs font-medium text-white transition-colors hover:bg-accentHover disabled:opacity-40"
          >
            Start
          </button>
        )}
      </div>
    </div>
  );
}

function PodsView({ pods, act }: { pods: PodInfo[]; act: (f: () => Promise<unknown>) => void }) {
  if (pods.length === 0) {
    return (
      <p className="mt-10 text-center text-sm text-muted">
        No pods — create one with <code>rustypods create …</code>
      </p>
    );
  }
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {pods.map((p) => (
        <PodCard
          key={p.name}
          pod={p}
          busy={false}
          onStart={() => act(() => api.startPod(p.name))}
          onStop={() => act(() => api.stopPod(p.name))}
        />
      ))}
    </div>
  );
}

function StacksView({ pods }: { pods: PodInfo[] }) {
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
        <div key={stack} className="rounded-xl border border-border bg-card p-4">
          <h3 className="mb-2 text-sm font-semibold">
            {stack} <span className="text-xs font-normal text-muted">shared netns · {members.length} pods</span>
          </h3>
          <div className="flex flex-wrap gap-2">
            {members.map((p) => (
              <div key={p.name} className="flex items-center gap-2 rounded-lg bg-bg2 px-3 py-1.5 text-xs">
                <span>{p.name}</span>
                <StateBadge state={p.state} />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function ImagesView({ images }: { images: ImageInfo[] }) {
  if (images.length === 0) {
    return <p className="mt-10 text-center text-sm text-muted">No images — <code>rustypods import --from-distrobox …</code></p>;
  }
  return (
    <div className="overflow-hidden rounded-xl border border-border">
      <table className="w-full text-left text-sm">
        <thead className="bg-bg2 text-xs text-muted">
          <tr>
            <th className="px-4 py-2 font-medium">Name</th>
            <th className="px-4 py-2 font-medium">Source</th>
            <th className="px-4 py-2 font-medium">Path</th>
          </tr>
        </thead>
        <tbody>
          {images.map((i) => (
            <tr key={i.name} className="border-t border-border">
              <td className="px-4 py-2 font-medium">{i.name}</td>
              <td className="px-4 py-2 text-muted">{i.source}</td>
              <td className="px-4 py-2 font-mono text-xs text-muted">{i.path}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SettingsView({
  info,
  lean,
  setLean,
}: {
  info: DaemonStatus | null;
  lean: boolean;
  setLean: (v: boolean) => void;
}) {
  return (
    <div className="max-w-lg space-y-4">
      <div className="rounded-xl border border-border bg-card p-4">
        <h3 className="mb-3 text-sm font-semibold">Daemon</h3>
        {info ? (
          <dl className="grid grid-cols-2 gap-y-1 text-xs">
            <dt className="text-muted">version</dt><dd className="font-mono">{info.version}</dd>
            <dt className="text-muted">socket</dt><dd className="font-mono truncate">{info.socket_path}</dd>
            <dt className="text-muted">engine</dt><dd className="font-mono">{info.runtime_engine}</dd>
            <dt className="text-muted">storage</dt><dd className="font-mono">{info.storage_driver}</dd>
            <dt className="text-muted">machined</dt><dd className="font-mono">{String(info.machined)}</dd>
          </dl>
        ) : (
          <p className="text-xs text-muted">daemon unreachable</p>
        )}
      </div>
      <div className="rounded-xl border border-border bg-card p-4">
        <label className="flex cursor-pointer items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold">Lean mode</h3>
            <p className="text-xs text-muted">
              Raspberry-Pi mode: 5s polling, no animations.
            </p>
          </div>
          <input
            type="checkbox"
            checked={lean}
            onChange={(e) => setLean(e.target.checked)}
            className="h-5 w-9 cursor-pointer accent-accent"
          />
        </label>
      </div>
    </div>
  );
}

export default function App() {
  const [view, setView] = useState<View>("pods");
  const [pods, setPods] = useState<PodInfo[]>([]);
  const [images, setImages] = useState<ImageInfo[]>([]);
  const [info, setInfo] = useState<DaemonStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lean, setLean] = useState(false);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [p, i, d] = await Promise.all([api.getPods(), api.getImages(), api.getDaemonInfo()]);
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
    const t = setInterval(refresh, lean ? 5000 : 2000);
    return () => clearInterval(t);
  }, [refresh, lean]);

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

  const titles: Record<View, string> = {
    pods: "Pods",
    stacks: "Stacks",
    images: "Images",
    settings: "Settings",
  };

  return (
    <div className={`flex h-screen ${lean ? "lean" : ""}`}>
      <aside className="flex w-48 flex-col border-r border-border bg-bg2">
        <div className="px-4 py-4">
          <h1 className="text-base font-bold tracking-tight">RustyPods</h1>
          <p className="text-[10px] text-muted">bare-metal pods</p>
        </div>
        <nav className="flex-1 space-y-0.5 px-2">
          {NAV.map((n) => (
            <button
              key={n.id}
              onClick={() => setView(n.id)}
              className={`flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors ${
                view === n.id ? "bg-accent/15 text-accent" : "text-fg hover:bg-card"
              }`}
            >
              <span className="w-4 text-center">{n.icon}</span>
              {n.label}
            </button>
          ))}
        </nav>
        <div className="px-4 py-3 text-[10px] text-muted">
          {info ? `v${info.version} · ${info.storage_driver}` : "offline"}
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto p-6">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">{titles[view]}</h2>
          {busy && <span className="text-xs text-muted">working…</span>}
        </div>
        {error && (
          <div className="mb-4 rounded-xl border border-err/40 bg-err/10 px-4 py-2 text-xs text-err">
            {error}
          </div>
        )}
        {view === "pods" && <PodsView pods={pods} act={act} />}
        {view === "stacks" && <StacksView pods={pods} />}
        {view === "images" && <ImagesView images={images} />}
        {view === "settings" && <SettingsView info={info} lean={lean} setLean={setLean} />}
      </main>
    </div>
  );
}
