export interface PodInfo {
  name: string;
  image: string;
  state: "running" | "stopped" | "created" | "failed";
  leader_pid: number;
  created_unix: number;
  memory_high: string;
  memory_max: string;
  cpu_quota_percent: number;
  storage_max: string;
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

export interface DaemonStatus {
  version: string;
  socket_path: string;
  data_dir: string;
  machined: boolean;
  storage_driver: string;
  runtime_engine: string;
}
