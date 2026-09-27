import type { ReactNode, SVGProps } from "react";

export type IconProps = SVGProps<SVGSVGElement> & { size?: number };

/**
 * Symbolic icon base — 16px, `currentColor` stroke, one visual weight.
 * Matches the GNOME "symbolic" icon convention (monochrome, inherits the
 * surrounding text/button color) and replaces the Unicode glyphs
 * (▣ ⧉ ◈ ⚙ ✕ – ▢) that used to stand in for icons: those render
 * differently per font/platform and don't sit on a pixel grid the way
 * an SVG does.
 */
function Icon({ size = 16, children, ...props }: IconProps & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.4}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      {children}
    </svg>
  );
}

/* ---------- nav ---------- */

export const PodsIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M8 1.5 14 5v6l-6 3.5L2 11V5z" />
    <path d="M2 5l6 3.5L14 5" />
    <path d="M8 8.5V15" />
  </Icon>
);

export const StacksIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M8 2 14 5 8 8 2 5z" />
    <path d="M2 8l6 3 6-3" />
    <path d="M2 11l6 3 6-3" />
  </Icon>
);

export const ImagesIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="8" cy="8" r="6" />
    <circle cx="8" cy="8" r="1.5" fill="currentColor" stroke="none" />
  </Icon>
);

export const SettingsIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="4.5" cy="5" r="1.3" />
    <path d="M2 5h1.6M6.4 5H14" />
    <circle cx="10.5" cy="9.5" r="1.3" />
    <path d="M2 9.5h7M12.4 9.5H14" />
    <circle cx="6" cy="13" r="1.3" />
    <path d="M2 13h2.5M7.9 13H14" />
  </Icon>
);

/* ---------- future: mesh / HA (used by the settings/mesh work that
 * follows this refactor — stocked now so those views don't start
 * their own icon dialect). ---------- */

export const NetworkIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="8" cy="3.2" r="1.6" />
    <circle cx="3" cy="12.6" r="1.6" />
    <circle cx="13" cy="12.6" r="1.6" />
    <path d="M7.1 4.5 4.3 11M8.9 4.5l2.8 6.5M4.6 12.6h6.8" />
  </Icon>
);

export const TerminalIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="1.5" y="2.5" width="13" height="11" rx="1.5" />
    <path d="M4.2 6.2 6.6 8l-2.4 1.8" />
    <path d="M8 10.5h3.5" />
  </Icon>
);

export const ShieldIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M8 1.5 13.5 3.5V8c0 3.6-2.3 5.9-5.5 6.6C4.8 13.9 2.5 11.6 2.5 8V3.5z" />
  </Icon>
);

/* ---------- chrome ---------- */

export const CloseIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 4l8 8M12 4l-8 8" />
  </Icon>
);

export const MinimizeIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M3.5 8h9" />
  </Icon>
);

export const MaximizeIcon = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3.5" y="3.5" width="9" height="9" rx="1.5" />
  </Icon>
);

/* ---------- controls ---------- */

export const ChevronLeftIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M10 3 5.5 8 10 13" />
  </Icon>
);

export const ChevronRightIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M6 3l4.5 5L6 13" />
  </Icon>
);

export const PlusIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M8 3v10M3 8h10" />
  </Icon>
);

export const HelpIcon = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="8" cy="8" r="6.25" />
    <path d="M6.1 6.3a1.9 1.9 0 1 1 2.7 1.7c-.6.3-.8.6-.8 1.3v.3" />
    <circle cx="8" cy="11.6" r="0.6" fill="currentColor" stroke="none" />
  </Icon>
);

export const CheckIcon = (p: IconProps) => (
  <Icon {...p}>
    <path d="M3.5 8.5l3 3 6-7" />
  </Icon>
);
