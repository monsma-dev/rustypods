import type {
  HTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
} from "react";

/**
 * One definition of the text/number/select look, instead of the same
 * `rounded-lg border border-white/10 bg-bg px-3 py-2 text-sm
 * focus:border-accent focus:outline-none focus:ring-1
 * focus:ring-accent/40` string copied 15+ times across the old
 * `App.tsx`. Inputs keep an Adwaita-style accent border on focus
 * (rather than the outline `Button`/nav use) because there's already a
 * border to react to.
 */
// No width here on purpose — callers add w-full or a fixed w-N per
// context (a wizard field wants full width, an inline port/interval
// picker wants its own content width).
const fieldBase =
  "rounded-[var(--radius-control)] border border-white/10 bg-bg px-3 py-2 text-sm text-fg placeholder:text-muted/60 transition-colors focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40 disabled:opacity-40";

export function TextInput({
  className = "",
  mono = false,
  invalid = false,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { mono?: boolean; invalid?: boolean }) {
  return (
    <input
      type="text"
      className={`${fieldBase} ${mono ? "font-mono" : ""} ${
        invalid ? "border-err focus:border-err focus:ring-err/40" : ""
      } ${className}`}
      {...rest}
    />
  );
}

export function NumberInput({
  className = "",
  ...rest
}: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      type="number"
      className={`${fieldBase} text-right font-mono ${className}`}
      {...rest}
    />
  );
}

export function SelectInput({
  className = "",
  children,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={`${fieldBase} ${className}`} {...rest}>
      {children}
    </select>
  );
}

/** Label + optional hint above a field — the shared "Name"/"Image"/…
 *  block from the New Pod wizard, reusable anywhere. */
export function Field({
  label,
  hint,
  children,
  ...rest
}: HTMLAttributes<HTMLDivElement> & {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div {...rest}>
      <div className="mb-1 flex items-baseline gap-2">
        <span className="text-[13px] font-medium">{label}</span>
        {hint && <span className="gn-caption">{hint}</span>}
      </div>
      {children}
    </div>
  );
}
