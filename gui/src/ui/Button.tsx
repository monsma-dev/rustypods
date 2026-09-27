import type { ButtonHTMLAttributes, ReactNode } from "react";

/**
 * One button component for the whole app. Variants mirror libadwaita's
 * style classes (`.suggested-action`, `.destructive-action`, `.pill`,
 * `.flat`) instead of each dialog hand-rolling its own
 * `rounded-lg bg-accent px-4 py-2 …` string — that copy had already
 * drifted (some buttons had no visible keyboard focus ring at all).
 */

type Variant = "default" | "suggested" | "destructive" | "flat";
type Shape = "normal" | "pill";
type Size = "sm" | "md";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  /** Red-tinted text/hover on an otherwise neutral variant — e.g. a
   *  flat "Remove"/"Destroy" trigger before its own confirm step. Kept
   *  as a lookup (not a separately-appended className) so two utility
   *  classes never fight over the same color/background property. */
  tone?: "default" | "danger";
  shape?: Shape;
  size?: Size;
}

const VARIANT: Record<Variant, Record<"default" | "danger", string>> = {
  default: {
    default: "bg-white/[0.06] text-fg/90 hover:bg-white/10",
    danger: "bg-white/[0.06] text-err hover:bg-err/15",
  },
  suggested: {
    default: "bg-accent text-white hover:bg-accent-hover",
    danger: "bg-accent text-white hover:bg-accent-hover",
  },
  destructive: {
    default: "bg-err/15 text-err hover:bg-err/25",
    danger: "bg-err/15 text-err hover:bg-err/25",
  },
  flat: {
    default: "bg-transparent text-fg/80 hover:bg-white/5",
    danger: "bg-transparent text-err/80 hover:bg-err/15 hover:text-err",
  },
};

const SIZE: Record<Size, string> = {
  sm: "px-2.5 py-1 text-[11px] gap-1",
  md: "px-3 py-2 text-[13px] gap-1.5",
};

export default function Button({
  variant = "default",
  tone = "default",
  shape = "normal",
  size = "md",
  className = "",
  ...rest
}: ButtonProps) {
  const shapeCls = shape === "pill" ? "rounded-full" : "rounded-[var(--radius-control)]";
  return (
    <button
      className={`gn-focus inline-flex items-center justify-center font-medium transition-colors disabled:pointer-events-none disabled:opacity-40 ${VARIANT[variant][tone]} ${SIZE[size]} ${shapeCls} ${className}`}
      {...rest}
    />
  );
}

/** Icon-only button — window controls, dialog close, "?" help. `circle`
 *  (the default) suits a lone button like a dialog's close "x"; `square`
 *  suits a row of adjacent controls, like the window min/max/close
 *  cluster, where a full circle would look odd packed edge to edge. */
export function IconButton({
  tone = "default",
  shape = "circle",
  size = 28,
  className = "",
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  tone?: "default" | "danger";
  shape?: "circle" | "square";
  size?: number;
  children: ReactNode;
}) {
  const toneCls =
    tone === "danger"
      ? "text-muted hover:bg-err hover:text-white"
      : "text-muted hover:bg-white/10 hover:text-fg";
  return (
    <button
      style={{ width: size, height: size }}
      className={`gn-focus inline-flex shrink-0 items-center justify-center transition-colors ${
        shape === "circle" ? "rounded-full" : "rounded-md"
      } ${toneCls} ${className}`}
      {...rest}
    >
      {children}
    </button>
  );
}
