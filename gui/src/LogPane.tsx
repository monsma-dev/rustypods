import { useEffect, useRef, useState } from "react";
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
  const termRef = useRef<Terminal | null>(null);
  const [copied, setCopied] = useState(false);

  // Dump the whole scrollback buffer (backlog + viewport) to the clipboard
  // so log output can be pasted into a bug report or an AI chat.
  const copyAll = async () => {
    const term = termRef.current;
    if (!term) return;
    const buf = term.buffer.active;
    const lines: string[] = [];
    for (let i = 0; i < buf.length; i++) {
      const s = buf.getLine(i)?.translateToString(true);
      if (s !== undefined) lines.push(s);
    }
    while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard unavailable (permissions) — leave the label unchanged.
    }
  };

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
    termRef.current = term;

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
      termRef.current = null;
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
    <div className="relative h-full min-h-[300px]">
      <div
        ref={hostRef}
        className="h-full overflow-hidden rounded-lg border border-white/10 bg-black p-1"
      />
      <button
        onClick={copyAll}
        className="absolute right-2 top-2 rounded-md bg-white/[0.08] px-2 py-1 text-xs text-muted transition-colors hover:bg-white/15 hover:text-fg"
      >
        {copied ? "Copied" : "Copy all"}
      </button>
    </div>
  );
}
