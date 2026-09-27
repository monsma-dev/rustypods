import type { ReactNode } from "react";

/**
 * Generic status pill — same visual language as `StateBadge` (dot +
 * rounded label) but not tied to `PodState`. Use this for anything
 * that isn't a pod: Raft leader/follower, quorum yes/no, witness/host,
 * peer handshake up/down.
 */
export function Badge({
  tone,
  children,
}: {
  tone: "ok" | "warn" | "err" | "muted" | "accent";
  children: ReactNode;
}) {
  const cls = {
    ok: "bg-ok/15 text-ok",
    warn: "bg-warn/15 text-warn",
    err: "bg-err/15 text-err",
    muted: "bg-white/5 text-muted",
    accent: "bg-accent/15 text-accent",
  }[tone];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-medium ${cls}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {children}
    </span>
  );
}
