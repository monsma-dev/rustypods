export interface PodInfo {
  name: string;
  image: string;
  state: "running" | "stopped" | "created" | "failed";
  leader_pid: number;
  created_unix: number;
  memory_high: string;
  memory_max: string;
  memory_high_bytes: number;
  memory_max_bytes: number;
  cpu_quota_percent: number;
  storage_max: string;
  storage_max_bytes: number;
  ports: string[];
  stack: string;
  ephemeral: boolean;
}

export interface ImageInfo {
  name: string;
  path: string;
  source: string;
  created_unix: number;
}

export interface MetricSample {
  pod: string;
  ts_unix_ms: number;
  mem_bytes: number;
  mem_high_bytes: number;
  cpu_pct: number;
  pids: number;
  mem_psi_avg10: number;
  io_psi_avg10: number;
  cpu_psi_avg10: number;
}

export interface DaemonStatus {
  version: string;
  socket_path: string;
  data_dir: string;
  machined: boolean;
  storage_driver: string;
  runtime_engine: string;
}
