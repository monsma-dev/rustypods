import { invoke } from "@tauri-apps/api/core";
import type { DaemonStatus, ImageInfo, PodInfo } from "./types";

export const getPods = () => invoke<PodInfo[]>("get_pods");
export const getImages = () => invoke<ImageInfo[]>("get_images");
export const getDaemonInfo = () => invoke<DaemonStatus>("get_daemon_info");
export const startPod = (name: string) => invoke<PodInfo>("start_pod", { name });
export const stopPod = (name: string) => invoke<PodInfo>("stop_pod", { name });
