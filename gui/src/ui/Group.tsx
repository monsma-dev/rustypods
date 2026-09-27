import type { ReactNode } from "react";

/** Libadwaita "boxed list" — bordered card with divided rows. Title uses
 *  the HIG `heading` style (sentence case, no letter-spacing) — current
 *  GNOME preference groups aren't set in all-caps; the HIG is explicit
 *  that apps shouldn't capitalize every letter. */
export function Group({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section>
      {title && <h3 className="gn-heading mb-1.5 px-1">{title}</h3>}
      <div className="divide-y divide-white/5 rounded-[var(--radius-card)] border border-white/[0.08] bg-white/[0.05]">
        {children}
      </div>
    </section>
  );
}

/** GNOME-Settings row: medium title (+ optional muted subtitle) left,
 *  value right. */
export function Row({
  label,
  sub,
  value,
  mono = true,
}: {
  label: string;
  sub?: string;
  value: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-3">
      <div className="min-w-0">
        <div className="text-[13px] font-medium">{label}</div>
        {sub && <div className="gn-caption mt-0.5">{sub}</div>}
      </div>
      <span className={`shrink-0 truncate text-[13px] text-muted ${mono ? "font-mono" : ""}`}>
        {value}
      </span>
    </div>
  );
}
