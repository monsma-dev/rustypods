import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import type { DaemonInfo, Image, Pod } from "./api";
import PodDetail, { type DetailTab } from "./PodDetail";
import NewPodDialog from "./NewPodDialog";
import ApplyStackDialog from "./ApplyStackDialog";
import PodsView from "./views/PodsView";
import StacksView from "./views/StacksView";
import ImagesView from "./views/ImagesView";
import MeshView from "./views/MeshView";
import SettingsView from "./views/SettingsView";
import Tutorial, { tutorialSeen } from "./Tutorial";
import { IconButton } from "./ui/Button";
import {
  CloseIcon,
  HelpIcon,
  ImagesIcon,
  MaximizeIcon,
  MinimizeIcon,
  NetworkIcon,
  PodsIcon,
  SettingsIcon,
  StacksIcon,
  type IconProps,
} from "./ui/icons";
import type { PodAct } from "./lib";

type View = "pods" | "stacks" | "images" | "mesh" | "settings";

const NAV: { id: View; label: string; Icon: (p: IconProps) => JSX.Element }[] = [
  { id: "pods", label: "Pods", Icon: PodsIcon },
  { id: "stacks", label: "Stacks", Icon: StacksIcon },
  { id: "images", label: "Images", Icon: ImagesIcon },
  { id: "mesh", label: "Mesh", Icon: NetworkIcon },
  { id: "settings", label: "Settings", Icon: SettingsIcon },
];

/* ---------- headerbar (frameless window chrome) ---------- */

function HeaderBar({ title, onHelp }: { title: string; onHelp: () => void }) {
  const win = api.inTauri
    ? () => import("@tauri-apps/api/window").then((m) => m.getCurrentWindow())
    : null;
  const act = (f: (w: any) => void) => () => win?.().then(f);
  return (
    <header
      data-tauri-drag-region
      className="flex h-10 shrink-0 items-center justify-between border-b border-white/[0.08] bg-bg2 select-none"
    >
      <div
        data-tauri-drag-region
        className="flex items-center gap-2 px-3 text-[12px] font-semibold"
      >
        <span data-tauri-drag-region className="text-accent">
          ◆
        </span>
        RustyPods
        <span data-tauri-drag-region className="font-normal text-muted">
          — {title}
        </span>
      </div>
      <div className="flex h-full items-center gap-1 px-1.5">
        <IconButton onClick={onHelp} aria-label="Show welcome tour" size={26}>
          <HelpIcon size={14} />
        </IconButton>
        <div className="mx-1 h-4 w-px bg-white/10" />
        <IconButton onClick={act((w) => w.minimize())} aria-label="Minimize" shape="square" size={26}>
          <MinimizeIcon size={13} />
        </IconButton>
        <IconButton
          onClick={act((w) => w.toggleMaximize())}
          aria-label="Maximize"
          shape="square"
          size={26}
        >
          <MaximizeIcon size={12} />
        </IconButton>
        <IconButton
          onClick={act((w) => w.close())}
          aria-label="Close"
          tone="danger"
          shape="square"
          size={26}
        >
          <CloseIcon size={13} />
        </IconButton>
      </div>
    </header>
  );
}

/* ---------- app ---------- */

export default function App() {
  const [view, setView] = useState<View>(() => {
    const v = new URLSearchParams(location.search).get("view");
    return v === "stacks" || v === "images" || v === "mesh" || v === "settings" ? v : "pods";
  });
  const [pods, setPods] = useState<Pod[]>([]);
  const [images, setImages] = useState<Image[]>([]);
  const [info, setInfo] = useState<DaemonInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [intervalMs, setIntervalMs] = useState(2000);
  const [reduceMotion, setReduceMotion] = useState(false);
  const [busy, setBusy] = useState(false);
  // Per-pod in-flight actions — buttons show "Starting…/Stopping…" until the
  // invoke + refresh settle (optimistic UX; polling confirms the real state).
  const [busyPods, setBusyPods] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<string | null>(
    () => new URLSearchParams(location.search).get("detail")
  );
  const [detailTab] = useState<DetailTab>(() => {
    const t = new URLSearchParams(location.search).get("tab");
    return t === "terminal" || t === "logs" ? t : "settings";
  });
  const [newPodOpen, setNewPodOpen] = useState(
    () => new URLSearchParams(location.search).has("newpod")
  );
  const [applyStackOpen, setApplyStackOpen] = useState(
    () => new URLSearchParams(location.search).has("newstack")
  );
  // Shown once automatically on first launch; replayable from the header
  // `?` button and Settings → Help → Replay.
  const [tutorialOpen, setTutorialOpen] = useState(() => !tutorialSeen());

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

  /** act() plus per-pod busy marking — cleared once invoke+refresh settle. */
  const podAct: PodAct = useCallback(
    (names, f) => {
      setBusyPods((s) => new Set([...s, ...names]));
      void act(f).finally(() =>
        setBusyPods((s) => {
          const n = new Set(s);
          for (const name of names) n.delete(name);
          return n;
        })
      );
    },
    [act]
  );

  const selectedPod = useMemo(
    () => pods.find((p) => p.name === selected) ?? null,
    [pods, selected]
  );

  const titles: Record<View, string> = {
    pods: "Pods",
    stacks: "Stacks",
    images: "Images",
    mesh: "Mesh",
    settings: "Settings",
  };

  return (
    <div className={`flex h-screen flex-col overflow-hidden ${reduceMotion ? "lean" : ""}`}>
      <HeaderBar
        title={`${titles[view]}${busy ? " · working…" : ""}${info && !info.machined ? " · machined degraded" : ""}`}
        onHelp={() => setTutorialOpen(true)}
      />
      <div className="flex min-h-0 flex-1">
        <aside className="flex w-48 shrink-0 flex-col border-r border-white/[0.08] bg-bg2">
          <nav className="flex-1 space-y-0.5 overflow-y-auto p-2">
            {NAV.map((n) => (
              <button
                key={n.id}
                onClick={() => setView(n.id)}
                className={`gn-focus flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] transition-colors ${
                  view === n.id
                    ? "bg-accent/15 font-medium text-accent"
                    : "text-fg/80 hover:bg-white/5"
                }`}
              >
                <n.Icon size={15} />
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
              <div className="mb-3 rounded-lg border border-err/40 bg-err/10 px-3 py-2 text-[13px] text-err">
                {error}
              </div>
            )}
            {view === "pods" && (
              <PodsView
                pods={pods}
                act={podAct}
                busy={busyPods}
                onOpen={(p) => setSelected(p.name)}
                onNew={() => setNewPodOpen(true)}
              />
            )}
            {view === "stacks" && (
              <StacksView
                pods={pods}
                act={podAct}
                onOpen={(p) => setSelected(p.name)}
                onNew={() => setApplyStackOpen(true)}
              />
            )}
            {view === "images" && <ImagesView images={images} />}
            {view === "mesh" && <MeshView />}
            {view === "settings" && (
              <SettingsView
                info={info}
                intervalMs={intervalMs}
                setIntervalMs={setIntervalMs}
                reduceMotion={reduceMotion}
                setReduceMotion={setReduceMotion}
                onReplayTutorial={() => setTutorialOpen(true)}
              />
            )}
          </div>
        </main>
      </div>

      {newPodOpen && (
        <NewPodDialog images={images} onClose={() => setNewPodOpen(false)} onCreated={refresh} />
      )}
      {applyStackOpen && (
        <ApplyStackDialog onClose={() => setApplyStackOpen(false)} onApplied={refresh} />
      )}
      {selectedPod && (
        <PodDetail
          key={selectedPod.name}
          pod={selectedPod}
          lean={reduceMotion || intervalMs >= 5000}
          onClose={() => setSelected(null)}
          act={podAct}
          busy={busyPods.has(selectedPod.name)}
          initialTab={detailTab}
        />
      )}
      {tutorialOpen && <Tutorial onClose={() => setTutorialOpen(false)} />}
    </div>
  );
}
