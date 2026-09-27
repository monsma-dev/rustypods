import type { DaemonInfo } from "../api";
import { Group, Row } from "../ui/Group";
import { SelectInput } from "../ui/inputs";
import Switch from "../ui/Switch";
import Button from "../ui/Button";
import { HelpIcon } from "../ui/icons";

export default function SettingsView({
  info,
  intervalMs,
  setIntervalMs,
  reduceMotion,
  setReduceMotion,
  onReplayTutorial,
}: {
  info: DaemonInfo | null;
  intervalMs: number;
  setIntervalMs: (v: number) => void;
  reduceMotion: boolean;
  setReduceMotion: (v: boolean) => void;
  onReplayTutorial: () => void;
}) {
  return (
    <div className="max-w-xl space-y-5">
      <Group title="Daemon">
        {info ? (
          <>
            <Row label="Version" sub="rustypodsd" value={info.version} />
            <Row label="Socket" sub="IPC endpoint" value={info.socketPath} />
            <Row label="Data dir" sub="images, pod rootfs, conf" value={info.dataDir} />
            <Row label="Runtime engine" sub="container launcher" value={info.runtimeEngine} />
            <Row
              label="machined"
              sub="systemd machine registration"
              value={String(info.machined)}
            />
          </>
        ) : (
          <p className="px-4 py-3 text-[13px] text-muted">daemon unreachable</p>
        )}
      </Group>

      <Group title="Interface">
        <div className="flex items-center justify-between px-4 py-3">
          <div>
            <div className="text-[13px] font-medium">Refresh interval</div>
            <div className="gn-caption">
              How often pod state is polled. Higher = lighter on slow hardware.
            </div>
          </div>
          <SelectInput value={intervalMs} onChange={(e) => setIntervalMs(Number(e.target.value))}>
            <option value={1000}>1 s</option>
            <option value={2000}>2 s</option>
            <option value={5000}>5 s</option>
            <option value={10000}>10 s</option>
          </SelectInput>
        </div>
        <div className="flex items-center justify-between px-4 py-3">
          <div>
            <div className="text-[13px] font-medium">Reduce motion</div>
            <div className="gn-caption">Disable animations — recommended on Raspberry Pi.</div>
          </div>
          <Switch checked={reduceMotion} onChange={setReduceMotion} label="Reduce motion" />
        </div>
      </Group>

      <Group title="Storage">
        <Row
          label="Driver"
          sub="filesystem backend for pod rootfs"
          value={info?.storageDriver ?? "—"}
        />
        <Row
          label="Quotas"
          sub="per-pod disk usage limits"
          value={info?.btrfs ? "btrfs qgroups — hot-applied" : "unavailable (non-btrfs)"}
          mono={false}
        />
        <Row
          label="Snapshots"
          sub="pod state commit / rollback"
          value={info?.btrfs ? "instant CoW (commit / rollback)" : "reflink copy fallback"}
          mono={false}
        />
      </Group>

      <Group title="Help">
        <div className="flex items-center justify-between px-4 py-3">
          <div>
            <div className="text-[13px] font-medium">Welcome tour</div>
            <div className="gn-caption">A short walkthrough of pods, stacks and the terminal.</div>
          </div>
          <Button variant="default" size="sm" onClick={onReplayTutorial}>
            <HelpIcon size={13} />
            Replay
          </Button>
        </div>
      </Group>
    </div>
  );
}
