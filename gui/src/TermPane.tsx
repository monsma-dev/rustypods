import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import * as api from "./api";

/**
 * Embedded exec terminal for one pod: xterm.js front end over the daemon's
 * bidi Exec RPC, bridged through Tauri events (pty-out/pty-exit per pod).
 */
export default function TermPane({
  pod,
  running,
}: {
  pod: string;
  running: boolean;
}) {
  const hostRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!running || !host) return;

    const term = new Terminal({
      fontFamily: "'Cascadia Mono','DejaVu Sans Mono',monospace",
      fontSize: 12,
      cursorBlink: true,
      theme: {
        background: "#00000000",
        foreground: "#d6d6d6",
        cursor: "#3584e4",
        selectionBackground: "#3584e455",
      },
      convertEol: false,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host);
    fit.fit();

    const enc = new TextEncoder();
    const dataSub = term.onData((d) => api.writePty(pod, enc.encode(d)));

    // Subscribe BEFORE openPty so the login shell's first prompt can't race
    // past the listener registration.
    const unsubs: (() => void)[] = [];
    let disposed = false;
    Promise.all([
      api.onPtyOut(pod, (b) => term.write(b)),
      api.onPtyExit(pod, () => term.write("\r\n[process exited]\r\n")),
    ]).then((us) => {
      if (disposed) {
        us.forEach((u) => u());
      } else {
        unsubs.push(...us);
        // A rejected open (pod not running, daemon down) must land IN the
        // terminal — an unhandled rejection leaves a silent dead pane.
        api.openPty(pod, term.cols, term.rows).catch((e) =>
          term.write(`\r\n[exec failed: ${String(e)}]\r\n`),
        );
      }
    });

    const ro = new ResizeObserver(() => {
      fit.fit();
      api.resizePty(pod, term.cols, term.rows);
    });
    ro.observe(host);

    return () => {
      disposed = true;
      unsubs.forEach((u) => u());
      ro.disconnect();
      dataSub.dispose();
      api.closePty(pod);
      term.dispose();
    };
  }, [pod, running]);

  if (!running) {
    return (
      <div className="flex h-full min-h-[300px] items-center justify-center rounded-lg border border-white/10 bg-black/40">
        <p className="text-xs text-muted">
          Start the pod to open a terminal
        </p>
      </div>
    );
  }

  return (
    <div
      ref={hostRef}
      className="h-full min-h-[300px] overflow-hidden rounded-lg border border-white/10 bg-black p-1"
    />
  );
}
