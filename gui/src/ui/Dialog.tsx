import type { ReactNode } from "react";
import { CloseIcon } from "./icons";
import { IconButton } from "./Button";

/**
 * Shared modal chrome. Three dialogs (`PodDetail`, `NewPodDialog`,
 * `ApplyStackDialog`) used to hand-roll their own
 * `fixed inset-0 z-40` + scrim + `stopPropagation` — one copy here means
 * every dialog opens, closes and aligns identically, including the
 * welcome tour.
 */
function Overlay({ onClose, children }: { onClose: () => void; children: ReactNode }) {
  return (
    <div className="fixed inset-0 z-40" onClick={onClose}>
      <div className="absolute inset-0 bg-black/40" />
      {children}
    </div>
  );
}

/** Centered modal panel — wizards and forms. */
export function Dialog({
  onClose,
  width = "w-96",
  children,
}: {
  onClose: () => void;
  width?: string;
  children: ReactNode;
}) {
  return (
    <Overlay onClose={onClose}>
      <div
        className={`absolute left-1/2 top-1/2 flex max-h-[85vh] ${width} -translate-x-1/2 -translate-y-1/2 flex-col rounded-[var(--radius-card)] border border-white/10 bg-bg2 shadow-2xl`}
        onClick={(e) => e.stopPropagation()}
      >
        {children}
      </div>
    </Overlay>
  );
}

/** Right-anchored slide-over — pod detail. */
export function SlideOver({
  onClose,
  width = "w-[440px]",
  children,
}: {
  onClose: () => void;
  width?: string;
  children: ReactNode;
}) {
  return (
    <Overlay onClose={onClose}>
      <aside
        className={`absolute right-0 top-0 flex h-full ${width} flex-col border-l border-white/10 bg-bg2 shadow-2xl`}
        onClick={(e) => e.stopPropagation()}
      >
        {children}
      </aside>
    </Overlay>
  );
}

/** Title + close button, shared by every dialog header. `extra` slots
 *  in a Start/Stop-style primary action before the close button. */
export function DialogHeader({
  title,
  onClose,
  extra,
}: {
  title: ReactNode;
  onClose: () => void;
  extra?: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
      <div className="min-w-0">{title}</div>
      <div className="flex items-center gap-1.5">
        {extra}
        <IconButton onClick={onClose} aria-label="Close">
          <CloseIcon size={14} />
        </IconButton>
      </div>
    </div>
  );
}

/** Bottom action bar — `status` sits flush left, buttons flush right. */
export function DialogFooter({ status, children }: { status?: ReactNode; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2 border-t border-white/10 px-4 py-3">
      <span className="gn-caption">{status}</span>
      <div className="ml-auto flex gap-2">{children}</div>
    </div>
  );
}
