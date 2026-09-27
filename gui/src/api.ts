import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  ApplyStackResponse,
  DaemonInfo,
  Image,
  Limits,
  MeshCreateCsrResponse,
  MeshPeerInfo,
  MeshSignCsrResponse,
  MeshStatus,
  Metric,
  Pod,
  PodState,
  RaftRole,
  RaftState,
} from "./proto/rustypods";

// The wire contract is crates/rustypods-proto/proto/rustypods.proto — Tauri
// commands return proto messages as camelCase JSON, decoded here via the
// generated fromJSON. No hand-maintained mirrors — a MeshView built
// against these types can't drift from what the daemon actually sends.
export type {
  ApplyStackResponse,
  DaemonInfo,
  Image,
  Limits,
  MeshCreateCsrResponse,
  MeshPeerInfo,
  MeshSignCsrResponse,
  MeshStatus,
  Metric,
  Pod,
  RaftState,
};
export { PodState, RaftRole };

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
    snapKeepLast: 5,
    snapMaxAgeSecs: 7 * 24 * 3600,
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

// Two-voter mesh: self (leader, term 3) plus one witness peer that has
// acked the current heartbeat — enough shape for a MeshView to render
// every state (leader/follower badge, quorum yes/no, witness peer) in
// the browser dev server, no daemon attached.
const MOCK_MESH_STATUS: MeshStatus = MeshStatus.fromPartial({
  enabled: true,
  pubkey: "ccj3lueeVyPYRT/gC4XHhS0yd3tLA23GL1tKAcserFE=",
  listen: "[::]:51820",
  prefix: "fd7e:f0a:d1ae::/48",
  grpcAddr: "fd7e:f0a:d1ae::1",
  pumpTicks: 128_400,
  udpPkts: 9_812,
  tunPkts: 6_640,
  tunDrops: 0,
  clusterToken: "",
  confError: "",
  names: {},
  peers: [
    MeshPeerInfo.fromPartial({
      endpoint: "203.0.113.9:51820",
      pubkey: "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM=",
      prefix: "fd9a:1c2e:88f0::/48",
      handshakeSecsAgo: 14,
      txBytes: 48_200,
      rxBytes: 51_900,
      name: "witness",
      grpcAddr: "fd9a:1c2e:88f0::1",
      isWitness: true,
    }),
  ],
  raft: RaftState.fromPartial({
    currentTerm: 3,
    isLeader: true,
    votedFor: "fd7e:f0a:d1ae::1",
    quorumSize: 2,
    hasQuorum: true,
    role: RaftRole.RAFT_ROLE_HOST,
  }),
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

// ---- mesh + raft ----

/** Same payload the CLI's `mesh status` prints, `raft` included — poll
 *  this for the Mesh view the way PodsView polls getPods. */
export const getMeshStatus = async (): Promise<MeshStatus> =>
  inTauri
    ? invoke<unknown>("get_mesh_status").then(MeshStatus.fromJSON)
    : (await delay(), MOCK_MESH_STATUS);

/** Joiner half of the out-of-band PKI bootstrap: mints (or reuses)
 *  node.key locally and returns a CSR + this host's WireGuard pubkey.
 *  Never touches the mesh listener. */
export const meshCreateCsr = async (): Promise<MeshCreateCsrResponse> =>
  inTauri
    ? invoke<unknown>("mesh_create_csr").then(MeshCreateCsrResponse.fromJSON)
    : (await delay(),
      MeshCreateCsrResponse.fromPartial({
        wgPubkey: MOCK_MESH_STATUS.pubkey,
        csrPem: "-----BEGIN CERTIFICATE REQUEST-----\n(mock — no daemon attached)\n-----END CERTIFICATE REQUEST-----",
      }));

/** Root half: sign a joiner's CSR. Returns ca.crt then node.crt — never
 *  ca.key. `wgPubkey` is the joiner's `meshCreateCsr()` output; names
 *  inside the CSR itself are discarded by the daemon. */
export const meshSignCsr = async (
  wgPubkey: string,
  csrPem: string
): Promise<MeshSignCsrResponse> => {
  if (inTauri)
    return invoke<unknown>("mesh_sign_csr", { wgPubkey, csrPem }).then(
      MeshSignCsrResponse.fromJSON
    );
  await delay();
  return MeshSignCsrResponse.fromPartial({
    caCrt: "-----BEGIN CERTIFICATE-----\n(mock ca.crt — no daemon attached)\n-----END CERTIFICATE-----",
    nodeCrt: "-----BEGIN CERTIFICATE-----\n(mock node.crt — no daemon attached)\n-----END CERTIFICATE-----",
  });
};

/** Register a peer host. `witness: true` marks a voter that counts
 *  toward quorum and must never receive a workload (see ha.rs). */
export const meshAddPeer = async (
  endpoint: string,
  pubkey: string,
  name: string | undefined,
  witness: boolean
): Promise<MeshStatus> => {
  if (inTauri)
    return invoke<unknown>("mesh_add_peer", { endpoint, pubkey, name, witness }).then(
      MeshStatus.fromJSON
    );
  await delay();
  MOCK_MESH_STATUS.peers.push(
    MeshPeerInfo.fromPartial({
      endpoint,
      pubkey,
      name: name ?? "",
      isWitness: witness,
      handshakeSecsAgo: -1,
    })
  );
  return MOCK_MESH_STATUS;
};

export interface CreatePodSpec {
  name: string;
  image: string;
  limits: Limits;
  storageMaxBytes: number;
  ports: string[];
  binds: string[];
  desktop: boolean;
}

export const createPod = async (spec: CreatePodSpec): Promise<Pod> => {
  if (inTauri)
    return invoke<unknown>("create_pod", {
      name: spec.name,
      image: spec.image,
      memoryHighBytes: spec.limits.memoryHighBytes,
      memoryMaxBytes: spec.limits.memoryMaxBytes,
      cpuQuotaPercent: spec.limits.cpuQuotaPercent,
      storageMaxBytes: spec.storageMaxBytes,
      ports: spec.ports,
      binds: spec.binds,
      desktop: spec.desktop,
    }).then(Pod.fromJSON);
  await delay();
  const p = Pod.fromPartial({
    name: spec.name,
    image: spec.image,
    state: PodState.POD_STATE_CREATED,
    createdUnix: Math.floor(Date.now() / 1000),
    limits: { ...spec.limits },
    storageMaxBytes: spec.storageMaxBytes,
    ports: spec.ports,
    binds: spec.binds,
    privateUsers: !spec.desktop,
  });
  MOCK_PODS.push(p);
  return p;
};

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

export const destroyPod = async (name: string): Promise<void> => {
  if (inTauri) {
    await invoke("destroy_pod", { name });
    return;
  }
  await delay();
  const i = MOCK_PODS.findIndex((p) => p.name === name);
  if (i >= 0) MOCK_PODS.splice(i, 1);
};

// ---- stacks ----

/** Apply a stack.toml: members are created as pods named <stack>-<member>. */
export const applyStack = async (toml: string): Promise<ApplyStackResponse> => {
  if (inTauri)
    return invoke<unknown>("apply_stack", { toml }).then(
      ApplyStackResponse.fromJSON
    );
  await delay();
  // Mock: scrape the stack name + [pods.<member>] tables out of the TOML.
  const stack = /^\s*name\s*=\s*"([^"]+)"/m.exec(toml)?.[1] ?? "stack";
  const created: Pod[] = [];
  for (const m of toml.matchAll(/^\s*\[pods\.([^\]]+)\]/gm)) {
    const p = Pod.fromPartial({
      name: `${stack}-${m[1]}`,
      stack,
      image: "arch-base",
      state: PodState.POD_STATE_CREATED,
      createdUnix: Math.floor(Date.now() / 1000),
    });
    MOCK_PODS.push(p);
    created.push(p);
  }
  return ApplyStackResponse.fromPartial({ name: stack, pods: created });
};

/** Destroy a stack: every member pod + the shared netns. */
export const destroyStack = async (name: string): Promise<void> => {
  if (inTauri) {
    await invoke("destroy_stack", { name });
    return;
  }
  await delay();
  for (let i = MOCK_PODS.length - 1; i >= 0; i--)
    if (MOCK_PODS[i].stack === name) MOCK_PODS.splice(i, 1);
};

export interface PodConfigUpdate {
  name: string;
  limits: Limits;
  storageMaxBytes: number;
  ports?: string[];
  // proto `optional` fields: undefined = keep current, 0 = clear the rule.
  snapKeepLast?: number;
  snapMaxAgeSecs?: number;
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
      snapKeepLast: u.snapKeepLast,
      snapMaxAgeSecs: u.snapMaxAgeSecs,
    }).then(Pod.fromJSON);
  await delay();
  const p = MOCK_PODS.find((p) => p.name === u.name)!;
  p.limits = { ...u.limits };
  p.storageMaxBytes = u.storageMaxBytes;
  if (u.ports) p.ports = u.ports;
  if (u.snapKeepLast !== undefined) p.snapKeepLast = u.snapKeepLast;
  if (u.snapMaxAgeSecs !== undefined) p.snapMaxAgeSecs = u.snapMaxAgeSecs;
  return p;
};

// ---- live metrics (daemon stream → "pod-metrics" Tauri event) ----

// watch_metrics opens ONE daemon stream per pod in the Tauri backend —
// the PodRow sparkline and the PodDetail MetricsSection both subscribe,
// and an unwatch kills the shared stream for everyone. Refcount so the
// backend watch lives until the LAST subscriber unsubscribes.
const metricsWatchers = new Map<string, number>();

export const watchMetrics = async (name: string): Promise<void> => {
  const n = metricsWatchers.get(name) ?? 0;
  if (n > 0) {
    metricsWatchers.set(name, n + 1);
    return;
  }
  // First subscriber: invoke BEFORE bumping the refcount. If the invoke
  // rejects (daemon down), the map must stay empty — a phantom count
  // would make every later call early-return without ever re-opening
  // the backend stream.
  if (inTauri) {
    await invoke("watch_metrics", { name });
    metricsWatchers.set(name, 1);
    return;
  }
  metricsWatchers.set(name, 1);
  mockWatch(name);
};

export const unwatchMetrics = async (name: string): Promise<void> => {
  const n = (metricsWatchers.get(name) ?? 0) - 1;
  if (n > 0) {
    metricsWatchers.set(name, n);
    return;
  }
  metricsWatchers.delete(name);
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

// ---- pod logs (StreamLogs → "log-<pod>" Tauri event) ----

export const watchLogs = async (name: string): Promise<void> => {
  if (inTauri) {
    await invoke("watch_logs", { name });
    return;
  }
  mockLogWatch(name);
};

export const unwatchLogs = async (name: string): Promise<void> => {
  if (inTauri) {
    await invoke("unwatch_logs", { name });
    return;
  }
  mockLogSubs.delete(name);
};

/** Subscribe to log lines for one pod. Returns an unsubscribe fn. */
export const onLog = async (
  pod: string,
  cb: (line: string) => void
): Promise<() => void> => {
  if (inTauri) return listen<string>(`log-${pod}`, (e) => cb(e.payload));
  let set = mockLogSubs.get(pod);
  if (!set) mockLogSubs.set(pod, (set = new Set()));
  set.add(cb);
  return () => {
    set.delete(cb);
  };
};

// --- mock logs for browser dev ---
const mockLogSubs = new Map<string, Set<(l: string) => void>>();

function mockLogWatch(pod: string) {
  const p = MOCK_PODS.find((p) => p.name === pod);
  if (!p || p.state !== PodState.POD_STATE_RUNNING) return;
  const lines = [
    `systemd[1]: Starting ${pod}.service — rustypods pod boot`,
    `systemd[1]: Reached target basic.target`,
    `systemd-networkd[42]: host0: Gained carrier`,
    `rustypods-agent[77]: telemetry online — cgroup v2, PSI`,
    `systemd[1]: Reached target multi-user.target`,
    `sshd[90]: Server listening on 0.0.0.0 port 22`,
    `sudo[112]:     nick : TTY=pts/0 ; PWD=/home/nick ; COMMAND=/bin/true`,
    `systemd[1]: ${pod}: boot finished, idle`,
  ];
  lines.forEach((l, i) =>
    setTimeout(
      () => mockLogSubs.get(pod)?.forEach((cb) => cb(l)),
      120 + i * 220
    )
  );
}

// ---- exec terminal (bidi Exec RPC → "pty-out-<pod>" / "pty-exit-<pod>") ----

/** Open a login-shell PTY in the pod. Stdout arrives via onPtyOut. */
export const openPty = async (
  pod: string,
  cols: number,
  rows: number
): Promise<void> => {
  if (inTauri) {
    await invoke("open_pty", { pod, cols, rows });
    return;
  }
  void cols;
  void rows;
  // Mock: announce a fake shell once listeners are in place.
  setTimeout(() => {
    const banner = new TextEncoder().encode(
      "\r\nrustypods exec — mock terminal, no daemon attached\r\n\r\n$ "
    );
    mockPtySubs.get(pod)?.forEach((cb) => cb(banner));
  }, 60);
};

/** Feed keystrokes into the pod's PTY stdin. */
export const writePty = async (pod: string, data: Uint8Array): Promise<void> => {
  if (inTauri) {
    await invoke("write_pty", { pod, data: Array.from(data) });
    return;
  }
  // Mock: local echo, plus a fresh prompt on Enter.
  const cbs = mockPtySubs.get(pod);
  if (!cbs) return;
  cbs.forEach((cb) => cb(data));
  if (data.includes(0x0d)) {
    const prompt = new TextEncoder().encode("\r\n$ ");
    setTimeout(() => cbs.forEach((cb) => cb(prompt)), 60);
  }
};

export const resizePty = async (
  pod: string,
  cols: number,
  rows: number
): Promise<void> => {
  if (inTauri) await invoke("resize_pty", { pod, cols, rows });
};

export const closePty = async (pod: string): Promise<void> => {
  if (inTauri) await invoke("close_pty", { pod });
};

/** Raw PTY output for one pod. Returns an unsubscribe fn. */
export const onPtyOut = async (
  pod: string,
  cb: (bytes: Uint8Array) => void
): Promise<() => void> => {
  if (inTauri)
    return listen<number[]>(`pty-out-${pod}`, (e) =>
      cb(new Uint8Array(e.payload))
    );
  let set = mockPtySubs.get(pod);
  if (!set) mockPtySubs.set(pod, (set = new Set()));
  set.add(cb);
  return () => {
    set.delete(cb);
  };
};

/** Fires once when the exec'd process exits (payload = exit code). */
export const onPtyExit = async (
  pod: string,
  cb: (code: number) => void
): Promise<() => void> => {
  if (inTauri) return listen<number>(`pty-exit-${pod}`, (e) => cb(e.payload));
  return () => {};
};

// --- mock pty for browser dev ---
const mockPtySubs = new Map<string, Set<(b: Uint8Array) => void>>();
