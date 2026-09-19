import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import * as api from "./api";

/**
 * Read-only log tail for one pod: the daemon's StreamLogs stream (journal
 * for booted pods, console log otherwise) bridged through `log-<pod>`
 * Tauri events into an xterm.js viewport.
 */
export default function LogPane({
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
      cursorBlink: false,
      disableStdin: true,
      scrollback: 2000,
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

    // Subscribe BEFORE watchLogs so the first backlog lines can't race past
    // the listener registration.
    let un: (() => void) | undefined;
    let disposed = false;
    api.onLog(pod, (line) => term.writeln(line)).then((u) => {
      if (disposed) {
        u();
      } else {
        un = u;
        api.watchLogs(pod);
      }
    });

    const ro = new ResizeObserver(() => fit.fit());
    ro.observe(host);

    return () => {
      disposed = true;
      un?.();
      ro.disconnect();
      api.unwatchLogs(pod);
      term.dispose();
    };
  }, [pod, running]);

  if (!running) {
    return (
      <div className="flex h-full min-h-[300px] items-center justify-center rounded-lg border border-white/10 bg-black/40">
        <p className="text-xs text-muted">Start the pod to view logs</p>
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
