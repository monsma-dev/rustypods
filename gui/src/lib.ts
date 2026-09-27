import { useEffect, useState } from "react";
import * as api from "./api";
import type { Limits, Metric, Pod } from "./api";
import { PodState } from "./proto/rustypods";

/** Shared across views/dialogs — pulled out of the old monolithic
 *  App.tsx so PodsView, StacksView, PodDetail and NewPodDialog all
 *  agree on one formatting/typing story instead of each re-deriving it. */

export const GIB = 2 ** 30;

export const fmtGib = (bytes: number) =>
  bytes === 0 ? "unlimited" : `${(bytes / GIB).toFixed(1)} GiB`;

export const fmtBytesShort = (b: number) => {
  if (b >= GIB) return `${(b / GIB).toFixed(1)}G`;
  if (b >= 2 ** 20) return `${(b / 2 ** 20).toFixed(0)}M`;
  return `${(b / 2 ** 10).toFixed(0)}K`;
};

export const ZERO_LIMITS: Limits = {
  memoryHighBytes: 0,
  memoryMaxBytes: 0,
  cpuQuotaPercent: 0,
};
export const limitsOf = (p: Pod): Limits => p.limits ?? ZERO_LIMITS;
export const isRunning = (p: Pod) => p.state === PodState.POD_STATE_RUNNING;

export type PodAct = (names: string[], f: () => Promise<unknown>) => void;

/** Live metric ring buffer (30 samples) for one pod — only when running. */
export function useMetrics(pod: string, active: boolean): Metric[] {
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
      // The listen() promise can resolve after cleanup ran — then the
      // unsubscribe fn must be invoked immediately or it leaks.
      .then((u) => (dead ? u() : (un = u)));
    api.watchMetrics(pod);
    return () => {
      dead = true;
      un?.();
      api.unwatchMetrics(pod);
    };
  }, [pod, active]);
  return samples;
}
