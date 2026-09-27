import { useState } from "react";
import { Dialog } from "./ui/Dialog";
import Button from "./ui/Button";
import {
  PodsIcon,
  SettingsIcon,
  StacksIcon,
  TerminalIcon,
  type IconProps,
} from "./ui/icons";

const SEEN_KEY = "rustypods.tutorial.seen";

/** True once, on first launch — the Settings page and the header `?`
 *  button stay available to replay it any time after. */
export function tutorialSeen(): boolean {
  try {
    return localStorage.getItem(SEEN_KEY) === "1";
  } catch {
    // Storage disabled (e.g. private mode) — show it every launch rather
    // than throwing.
    return false;
  }
}

function markSeen() {
  try {
    localStorage.setItem(SEEN_KEY, "1");
  } catch {
    /* best effort */
  }
}

interface Page {
  icon: (p: IconProps) => JSX.Element;
  title: string;
  body: string;
}

const PAGES: Page[] = [
  {
    icon: PodsIcon,
    title: "Welcome to RustyPods",
    body: "Pods are systemd-nspawn machines on Btrfs — no containerd, no overlayfs, no Docker daemon. This short tour covers the four things you'll use most.",
  },
  {
    icon: PodsIcon,
    title: "Pods",
    body: "Create a pod from an image, start it, and adjust memory, CPU and disk limits live — no restart needed. Commit takes an instant snapshot you can roll back to.",
  },
  {
    icon: StacksIcon,
    title: "Stacks",
    body: "Apply a stack.toml to run several pods on one shared network. They reach each other on 127.0.0.1, the same model Kubernetes uses for a pod.",
  },
  {
    icon: TerminalIcon,
    title: "Terminal & logs",
    body: "Open a pod's detail pane for a live shell and a log tail, both backed by the daemon's own exec and log-streaming API — no SSH required.",
  },
  {
    icon: SettingsIcon,
    title: "Settings & doctor",
    body: "Settings shows the daemon version, socket, and storage driver. From a terminal, rustypods doctor verifies the host satisfies every requirement.",
  },
];

/**
 * First-run welcome tour, modeled on GNOME's own onboarding pattern
 * (AdwCarousel of AdwStatusPage-style pages: icon, title, one line of
 * body text, dot pagination). Shown once automatically; replayable from
 * the header `?` button or Settings → "Replay welcome tour".
 */
export default function Tutorial({ onClose }: { onClose: () => void }) {
  const [i, setI] = useState(0);
  const page = PAGES[i];
  const last = i === PAGES.length - 1;

  const finish = () => {
    markSeen();
    onClose();
  };

  return (
    <Dialog onClose={finish} width="w-[440px]">
      <div className="flex flex-col items-center gap-4 px-8 pb-6 pt-10 text-center">
        <div className="flex h-16 w-16 items-center justify-center rounded-full bg-accent/15 text-accent">
          <page.icon size={30} />
        </div>
        <h2 className="gn-title">{page.title}</h2>
        <p className="text-[13px] leading-relaxed text-muted">{page.body}</p>
      </div>

      <div className="flex items-center justify-center gap-1.5 pb-5">
        {PAGES.map((_, n) => (
          <button
            key={n}
            aria-label={`Go to page ${n + 1}`}
            onClick={() => setI(n)}
            className={`gn-focus h-1.5 rounded-full transition-all ${
              n === i ? "w-5 bg-accent" : "w-1.5 bg-white/15 hover:bg-white/25"
            }`}
          />
        ))}
      </div>

      <div className="flex items-center justify-between border-t border-white/10 px-4 py-3">
        <Button variant="flat" size="sm" onClick={finish}>
          Skip
        </Button>
        <div className="flex gap-2">
          <Button
            variant="flat"
            size="sm"
            onClick={() => setI((n) => Math.max(0, n - 1))}
            disabled={i === 0}
          >
            Back
          </Button>
          {last ? (
            <Button variant="suggested" shape="pill" size="sm" onClick={finish}>
              Get started
            </Button>
          ) : (
            <Button variant="suggested" size="sm" onClick={() => setI((n) => n + 1)}>
              Next
            </Button>
          )}
        </div>
      </div>
    </Dialog>
  );
}
