import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { DaemonStatus, ImageInfo, MetricSample, PodInfo } from "./types";

// Outside the Tauri webview (plain `npm run dev` in a browser) there is no IPC
// bridge — serve mock data so the UI stays demoable/testable.
export const inTauri = "__TAURI_INTERNALS__" in window;

const MOCK_PODS: PodInfo[] = [
  {
    name: "dev",
    image: "arch-base",
    state: "running",
    leader_pid: 95458,
    created_unix: 1789800000,
    memory_high: "10.0G",
    memory_max: "12.0G",
    memory_high_bytes: 10 * 2 ** 30,
    memory_max_bytes: 12 * 2 ** 30,
    cpu_quota_percent: 400,
    storage_max: "20.0G",
    storage_max_bytes: 20 * 2 ** 30,
    ports: ["2222:22/tcp"],
    stack: "",
    ephemeral: false,
  },
  {
    name: "dev-clone",
    image: "arch-base",
    state: "stopped",
    leader_pid: 0,
    created_unix: 1789810000,
    memory_high: "10.0G",
    memory_max: "12.0G",
    memory_high_bytes: 10 * 2 ** 30,
    memory_max_bytes: 12 * 2 ** 30,
    cpu_quota_percent: 400,
    storage_max: "20.0G",
    storage_max_bytes: 20 * 2 ** 30,
    ports: [],
    stack: "",
    ephemeral: false,
  },
  {
    name: "demo-web",
    image: "arch-base",
    state: "running",
    leader_pid: 81201,
    created_unix: 1789820000,
    memory_high: "0B",
    memory_max: "0B",
    memory_high_bytes: 0,
    memory_max_bytes: 0,
    cpu_quota_percent: 0,
    storage_max: "0B",
    storage_max_bytes: 0,
    ports: ["8081:8080/tcp"],
    stack: "demo",
    ephemeral: false,
  },
  {
    name: "demo-api",
    image: "arch-base",
    state: "running",
    leader_pid: 81244,
    created_unix: 1789820000,
    memory_high: "0B",
    memory_max: "0B",
    memory_high_bytes: 0,
    memory_max_bytes: 0,
    cpu_quota_percent: 0,
    storage_max: "0B",
    storage_max_bytes: 0,
    ports: [],
    stack: "demo",
    ephemeral: false,
  },
];

const MOCK_IMAGES: ImageInfo[] = [
  {
    name: "arch-base",
    path: "/var/lib/rustypods/images/arch-base",
    source: "distrobox-import",
    created_unix: 1789700000,
  },
];

const MOCK_INFO: DaemonStatus = {
  version: "0.1.0",
  socket_path: "/run/rustypods/daemon.sock",
  data_dir: "/var/lib/rustypods",
  machined: true,
  storage_driver: "btrfs",
  runtime_engine: "systemd-nspawn",
};

const delay = (ms = 80) => new Promise((r) => setTimeout(r, ms));

export const getPods = async (): Promise<PodInfo[]> =>
  inTauri ? invoke<PodInfo[]>("get_pods") : (await delay(), MOCK_PODS);

export const getImages = async (): Promise<ImageInfo[]> =>
  inTauri ? invoke<ImageInfo[]>("get_images") : (await delay(), MOCK_IMAGES);

export const getDaemonInfo = async (): Promise<DaemonStatus> =>
  inTauri ? invoke<DaemonStatus>("get_daemon_info") : (await delay(), MOCK_INFO);

export const startPod = async (name: string): Promise<PodInfo> => {
  if (inTauri) return invoke<PodInfo>("start_pod", { name });
  await delay();
  const p = MOCK_PODS.find((p) => p.name === name)!;
  p.state = "running";
  p.leader_pid = 90000;
  return p;
};

export const stopPod = async (name: string): Promise<PodInfo> => {
  if (inTauri) return invoke<PodInfo>("stop_pod", { name });
  await delay();
  const p = MOCK_PODS.find((p) => p.name === name)!;
  p.state = "stopped";
  p.leader_pid = 0;
  return p;
};

export interface PodConfigUpdate {
  name: string;
  memory_high_bytes: number;
  memory_max_bytes: number;
  cpu_quota_percent: number;
  storage_max_bytes: number;
  ports?: string[];
}

// ---- live metrics (daemon stream → "pod-metrics" Tauri event) ----

export const watchMetrics = async (name: string): Promise<void> => {
  if (inTauri) {
    await invoke("watch_metrics", { name });
    return;
  }
  mockWatch(name);
};

export const unwatchMetrics = async (name: string): Promise<void> => {
  if (inTauri) {
    await invoke("unwatch_metrics", { name });
    return;
  }
  mockUnwatch(name);
};

/** Subscribe to MetricSamples for one pod. Returns an unsubscribe fn. */
export const onMetrics = async (
  pod: string,
  cb: (m: MetricSample) => void
): Promise<() => void> => {
  if (inTauri) {
    const un = await listen<MetricSample>("pod-metrics", (e) => {
      if (e.payload.pod === pod) cb(e.payload);
    });
    return un;
  }
  return mockSubscribe(pod, cb);
};

// --- mock metrics for browser dev ---

const mockSubs = new Map<string, Set<(m: MetricSample) => void>>();
let mockTimer: ReturnType<typeof setInterval> | null = null;
let mockT = 0;

function mockSample(pod: string, t: number, now: number): MetricSample | null {
  const p = MOCK_PODS.find((p) => p.name === pod);
  if (!p || p.state !== "running") return null;
  const w = Math.sin(t / 6);
  return {
    pod,
    ts_unix_ms: now,
    mem_bytes: (4 + w * 1.5 + Math.random()) * 2 ** 30,
    mem_high_bytes: p.memory_high_bytes,
    cpu_pct: Math.max(0, 120 + w * 90 + Math.random() * 40),
    pids: 42,
    mem_psi_avg10: Math.max(0, 3 + w * 2 + Math.random()),
    io_psi_avg10: Math.max(0, 1 + w + Math.random() * 0.5),
    cpu_psi_avg10: Math.max(0, 5 + w * 3 + Math.random() * 1.5),
  };
}

function mockEmit() {
  mockT += 1;
  for (const pod of mockSubs.keys()) {
    const m = mockSample(pod, mockT, Date.now());
    if (m) mockSubs.get(pod)?.forEach((cb) => cb(m));
  }
}

function mockSubscribe(pod: string, cb: (m: MetricSample) => void) {
  let set = mockSubs.get(pod);
  if (!set) mockSubs.set(pod, (set = new Set()));
  set.add(cb);
  // Backfill ~40s of history so the sparkline has shape immediately.
  for (let t = mockT - 20; t < mockT; t++) {
    const m = mockSample(pod, t, Date.now() - (mockT - t) * 2000);
    if (m) cb(m);
  }
  return () => set.delete(cb);
}

function mockWatch(pod: string) {
  if (!mockTimer) mockTimer = setInterval(mockEmit, 2000);
  void pod;
}

function mockUnwatch(pod: string) {
  mockSubs.delete(pod);
  if (mockSubs.size === 0 && mockTimer) {
    clearInterval(mockTimer);
    mockTimer = null;
  }
}

export const updatePodConfig = async (u: PodConfigUpdate): Promise<PodInfo> => {
  if (inTauri)
    return invoke<PodInfo>("update_pod_config", {
      name: u.name,
      memoryHighBytes: u.memory_high_bytes,
      memoryMaxBytes: u.memory_max_bytes,
      cpuQuotaPercent: u.cpu_quota_percent,
      storageMaxBytes: u.storage_max_bytes,
      ports: u.ports,
    });
  await delay();
  const p = MOCK_PODS.find((p) => p.name === u.name)!;
  p.memory_high_bytes = u.memory_high_bytes;
  p.memory_max_bytes = u.memory_max_bytes;
  p.cpu_quota_percent = u.cpu_quota_percent;
  p.storage_max_bytes = u.storage_max_bytes;
  if (u.ports) p.ports = u.ports;
  return p;
};
