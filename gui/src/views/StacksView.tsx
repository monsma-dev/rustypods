import { useState } from "react";
import * as api from "../api";
import type { Pod } from "../api";
import { isRunning, type PodAct } from "../lib";
import { StateBadge } from "../ui/StateBadge";
import { Group } from "../ui/Group";
import Button from "../ui/Button";
import { EmptyState } from "../ui/EmptyState";
import { PlusIcon, StacksIcon } from "../ui/icons";

export default function StacksView({
  pods,
  act,
  onOpen,
  onNew,
}: {
  pods: Pod[];
  act: PodAct;
  onOpen: (p: Pod) => void;
  onNew: () => void;
}) {
  // Which stack group is showing the inline "Destroy? [yes] [no]" confirm.
  const [confirming, setConfirming] = useState<string | null>(null);
  const groups = new Map<string, Pod[]>();
  for (const p of pods.filter((p) => p.stack)) {
    groups.set(p.stack, [...(groups.get(p.stack) ?? []), p]);
  }
  return (
    <>
      <div className="mb-2 flex items-center justify-end">
        <Button variant="suggested" onClick={onNew}>
          <PlusIcon size={14} />
          Apply stack.toml
        </Button>
      </div>
      {groups.size === 0 ? (
        <EmptyState
          icon={<StacksIcon size={26} />}
          title="No stacks yet"
          description="A stack.toml runs several pods on one shared network — they reach each other on 127.0.0.1."
          action={
            <Button variant="suggested" shape="pill" onClick={onNew}>
              <PlusIcon size={14} />
              Apply your first stack
            </Button>
          }
        />
      ) : (
        <div className="space-y-4">
          {[...groups.entries()].map(([stack, members]) => (
            <Group key={stack} title={`${stack} · shared netns rustypods-${stack}`}>
              {members.map((p) => (
                <button
                  key={p.name}
                  onClick={() => onOpen(p)}
                  className="gn-focus flex w-full items-center justify-between px-4 py-2.5 text-left transition-colors hover:bg-white/[0.04]"
                >
                  <span className="text-[13px] font-medium">{p.name}</span>
                  <span className="flex items-center gap-3">
                    <span className="font-mono text-[11px] text-muted">
                      {p.ports.join(", ")}
                    </span>
                    <StateBadge state={p.state} />
                  </span>
                </button>
              ))}
              <div className="flex items-center gap-1.5 px-4 py-2">
                <Button
                  variant="default"
                  size="sm"
                  onClick={() =>
                    act(
                      members.filter((p) => !isRunning(p)).map((p) => p.name),
                      async () => {
                        for (const p of members.filter((p) => !isRunning(p)))
                          await api.startPod(p.name);
                      }
                    )
                  }
                >
                  Start all
                </Button>
                <Button
                  variant="default"
                  size="sm"
                  onClick={() =>
                    act(
                      members.filter(isRunning).map((p) => p.name),
                      async () => {
                        for (const p of members.filter(isRunning)) await api.stopPod(p.name);
                      }
                    )
                  }
                >
                  Stop all
                </Button>
                {confirming === stack ? (
                  <span className="ml-auto flex items-center gap-1.5 text-[13px] font-medium text-err">
                    Destroy?
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => {
                        setConfirming(null);
                        act(
                          members.map((p) => p.name),
                          () => api.destroyStack(stack)
                        );
                      }}
                    >
                      yes
                    </Button>
                    <Button variant="default" size="sm" onClick={() => setConfirming(null)}>
                      no
                    </Button>
                  </span>
                ) : (
                  <Button
                    variant="flat"
                    tone="danger"
                    size="sm"
                    onClick={() => setConfirming(stack)}
                    className="ml-auto"
                  >
                    Destroy
                  </Button>
                )}
              </div>
            </Group>
          ))}
        </div>
      )}
    </>
  );
}
