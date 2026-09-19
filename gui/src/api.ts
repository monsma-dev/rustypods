import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  DaemonInfo,
  Image,
  Limits,
  Metric,
  Pod,
  PodState,
} from "./proto/rustypods";

// The wire contract is crates/rustypods-proto/proto/rustypods.proto — Tauri
// commands return proto messages as camelCase JSON, decoded here via the
// generated fromJSON. No hand-maintained mirrors.
export type { DaemonInfo, Image, Limits, Metric, Pod };
export { PodState };

// Outside the Tauri webview (plain `npm run dev` in a browser) there is no IPC
// bridge — serve mock data so the UI stays demoable/testable.
export const inTauri = "__TAURI_INTERNALS__" in window;

const MOCK_PODS: Pod[] = [
  Pod.fromPartial({
    name: "dev",
    image: "arch-base",
    state: PodState.POD_STATE_RUNNING,
    leaderPid: 95458,
    createdUnix: 1789800000,
    limits: {
      memoryHighBytes: 10 * 2 ** 30,
      memoryMaxBytes: 12 * 2 ** 30,
      cpuQuotaPercent: 400,
    },
    storageMaxBytes: 20 * 2 ** 30,
    ports: ["2222:22/tcp"],
  }),
  Pod.fromPartial({
    name: "dev-clone",
    image: "arch-base",
    state: PodState.POD_STATE_STOPPED,
    createdUnix: 1789810000,
    limits: {
      memoryHighBytes: 10 * 2 ** 30,
      memoryMaxBytes: 12 * 2 ** 30,
      cpuQuotaPercent: 400,
    },
    storageMaxBytes: 20 * 2 ** 30,
  }),
  Pod.fromPartial({
    name: "demo-web",
    image: "arch-base",
    state: PodState.POD_STATE_RUNNING,
    leaderPid: 81201,
    createdUnix: 1789820000,
    ports: ["8081:8080/tcp"],
    stack: "demo",
  }),
  Pod.fromPartial({
    name: "demo-api",
    image: "arch-base",
    state: PodState.POD_STATE_RUNNING,
    leaderPid: 81244,
    createdUnix: 1789820000,
    stack: "demo",
  }),
];

const MOCK_IMAGES: Image[] = [
  Image.fromPartial({
    name: "arch-base",
    path: "/var/lib/rustypods/images/arch-base",
    source: "distrobox-import",
    createdUnix: 1789700000,
  }),
];

const MOCK_INFO: DaemonInfo = DaemonInfo.fromPartial({
  version: "0.1.0",
  socketPath: "/run/rustypods/daemon.sock",
  dataDir: "/var/lib/rustypods",
  machined: true,
  btrfs: true,
  storageDriver: "btrfs",
  runtimeEngine: "systemd-nspawn",
});

const delay = (ms = 80) => new Promise((r) => setTimeout(r, ms));

export const getPods = async (): Promise<Pod[]> =>
  inTauri
    ? invoke<unknown[]>("get_pods").then((l) => l.map(Pod.fromJSON))
    : (await delay(), MOCK_PODS);

export const getImages = async (): Promise<Image[]> =>
  inTauri
    ? invoke<unknown[]>("get_images").then((l) => l.map(Image.fromJSON))
    : (await delay(), MOCK_IMAGES);

export const getDaemonInfo = async (): Promise<DaemonInfo> =>
  inTauri
    ? invoke<unknown>("get_daemon_info").then(DaemonInfo.fromJSON)
    : (await delay(), MOCK_INFO);

export const startPod = async (name: string): Promise<Pod> => {
  if (inTauri) return invoke<unknown>("start_pod", { name }).then(Pod.fromJSON);
  await delay();
  const p = MOCK_PODS.find((p) => p.name === name)!;
  p.state = PodState.POD_STATE_RUNNING;
  p.leaderPid = 90000;
  return p;
};

export const stopPod = async (name: string): Promise<Pod> => {
  if (inTauri) return invoke<unknown>("stop_pod", { name }).then(Pod.fromJSON);
  await delay();
  const p = MOCK_PODS.find((p) => p.name === name)!;
  p.state = PodState.POD_STATE_STOPPED;
  p.leaderPid = 0;
  return p;
};

export interface PodConfigUpdate {
  name: string;
  limits: Limits;
  storageMaxBytes: number;
  ports?: string[];
}

export const updatePodConfig = async (u: PodConfigUpdate): Promise<Pod> => {
  if (inTauri)
    return invoke<unknown>("update_pod_config", {
      name: u.name,
      memoryHighBytes: u.limits.memoryHighBytes,
      memoryMaxBytes: u.limits.memoryMaxBytes,
      cpuQuotaPercent: u.limits.cpuQuotaPercent,
      storageMaxBytes: u.storageMaxBytes,
      ports: u.ports,
    }).then(Pod.fromJSON);
  await delay();
  const p = MOCK_PODS.find((p) => p.name === u.name)!;
  p.limits = { ...u.limits };
  p.storageMaxBytes = u.storageMaxBytes;
  if (u.ports) p.ports = u.ports;
  return p;
};

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

/** Subscribe to Metrics for one pod. Returns an unsubscribe fn. */
export const onMetrics = async (
  pod: string,
  cb: (m: Metric) => void
): Promise<() => void> => {
  if (inTauri) {
    // Payload is the Metric message flattened plus a `pod` routing key.
    const un = await listen<Record<string, unknown>>("pod-metrics", (e) => {
      if (e.payload.pod === pod) cb(Metric.fromJSON(e.payload));
    });
    return un;
  }
  return mockSubscribe(pod, cb);
};

// --- mock metrics for browser dev ---

const mockSubs = new Map<string, Set<(m: Metric) => void>>();
let mockTimer: ReturnType<typeof setInterval> | null = null;
let mockT = 0;

function mockSample(pod: string, t: number, now: number): Metric | null {
  const p = MOCK_PODS.find((p) => p.name === pod);
  if (!p || p.state !== PodState.POD_STATE_RUNNING) return null;
  const w = Math.sin(t / 6);
  return Metric.fromPartial({
    tsUnixMs: now,
    memBytes: (4 + w * 1.5 + Math.random()) * 2 ** 30,
    memHighBytes: p.limits?.memoryHighBytes ?? 0,
    cpuPct: Math.max(0, 120 + w * 90 + Math.random() * 40),
    pids: 42,
    memPsiAvg10: Math.max(0, 3 + w * 2 + Math.random()),
    ioPsiAvg10: Math.max(0, 1 + w + Math.random() * 0.5),
    cpuPsiAvg10: Math.max(0, 5 + w * 3 + Math.random() * 1.5),
  });
}

function mockEmit() {
  mockT += 1;
  for (const pod of mockSubs.keys()) {
    const m = mockSample(pod, mockT, Date.now());
    if (m) mockSubs.get(pod)?.forEach((cb) => cb(m));
  }
}

function mockSubscribe(pod: string, cb: (m: Metric) => void) {
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
