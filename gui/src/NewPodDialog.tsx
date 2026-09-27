import { useEffect, useState } from "react";
import * as api from "./api";
import type { Image } from "./api";
import { fmtGib, GIB } from "./lib";
import { Dialog, DialogHeader, DialogFooter } from "./ui/Dialog";
import { Field, SelectInput, TextInput } from "./ui/inputs";
import { LimitSlider } from "./ui/LimitSlider";
import Button from "./ui/Button";

export default function NewPodDialog({
  images,
  onClose,
  onCreated,
}: {
  images: Image[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState("");
  const [image, setImage] = useState(images[0]?.name ?? "");
  const [memHigh, setMemHigh] = useState(0);
  const [memMax, setMemMax] = useState(0);
  const [cpu, setCpu] = useState(0);
  const [disk, setDisk] = useState(0);
  const [desktop, setDesktop] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [deploying, setDeploying] = useState(false);

  // Images may still be loading when the dialog opens (?newpod=1 deep link).
  useEffect(() => {
    if (!image && images.length > 0) setImage(images[0].name);
  }, [images, image]);

  const valid = name.trim().length > 0 && image.length > 0;

  const deploy = async () => {
    if (!valid || deploying) return;
    setDeploying(true);
    setErr(null);
    try {
      await api.createPod({
        name: name.trim(),
        image,
        limits: {
          memoryHighBytes: memHigh,
          memoryMaxBytes: memMax,
          cpuQuotaPercent: cpu,
        },
        storageMaxBytes: disk,
        ports: [],
        binds: [],
        desktop,
      });
      // start_pod sends private_users: None — the create-time isolation
      // choice is persisted in the pod conf and kept.
      await api.startPod(name.trim());
      onCreated();
      onClose();
    } catch (e) {
      setErr(String(e));
    } finally {
      setDeploying(false);
    }
  };

  return (
    <Dialog onClose={onClose}>
      <DialogHeader title={<h2 className="text-sm font-bold">New Pod</h2>} onClose={onClose} />

      <div className="flex-1 space-y-5 overflow-y-auto p-4">
        <Field label="Name">
          <TextInput
            autoFocus
            placeholder="my-pod"
            value={name}
            onChange={(e) => setName(e.target.value)}
            mono
            className="w-full"
          />
        </Field>
        <Field label="Image">
          <SelectInput value={image} onChange={(e) => setImage(e.target.value)} className="w-full">
            {images.length === 0 && <option value="">(no images)</option>}
            {images.map((i) => (
              <option key={i.name} value={i.name}>
                {i.name}
              </option>
            ))}
          </SelectInput>
        </Field>

        <div className="divide-y divide-white/5 rounded-[var(--radius-card)] border border-white/[0.08] bg-white/[0.05]">
          <LimitSlider
            label="Memory high"
            hint="throttle above this"
            value={memHigh}
            onChange={setMemHigh}
            max={32 * GIB}
            step={GIB / 2}
            scale={GIB}
            unit="GiB"
            fmt={fmtGib}
          />
          <LimitSlider
            label="Memory max"
            hint="OOM-kill above this"
            value={memMax}
            onChange={setMemMax}
            max={32 * GIB}
            step={GIB / 2}
            scale={GIB}
            unit="GiB"
            fmt={fmtGib}
          />
          <LimitSlider
            label="CPU quota"
            hint="100% = 1 core"
            value={cpu}
            onChange={setCpu}
            max={800}
            step={25}
            scale={1}
            unit="%"
            fmt={(v) => `${v}%`}
          />
          <LimitSlider
            label="Disk quota"
            hint="btrfs qgroup"
            value={disk}
            onChange={setDisk}
            max={100 * GIB}
            step={GIB}
            scale={GIB}
            unit="GiB"
            fmt={fmtGib}
          />
        </div>

        <div>
          <span className="text-[13px] font-medium">Isolation</span>
          <div className="mt-1.5 grid grid-cols-2 gap-1 rounded-[var(--radius-control)] border border-white/10 bg-bg p-1">
            {[
              {
                v: false,
                title: "Hermetic",
                desc: "user namespace — pod root is not host root",
              },
              {
                v: true,
                title: "Desktop mode",
                desc: "mounts home + /tmp, shares host uids",
              },
            ].map((o) => (
              <button
                key={o.title}
                onClick={() => setDesktop(o.v)}
                className={`gn-focus rounded-md px-2.5 py-1.5 text-left transition-colors ${
                  desktop === o.v ? "bg-accent/15 text-accent" : "text-fg/80 hover:bg-white/5"
                }`}
              >
                <div className="text-[13px] font-medium">{o.title}</div>
                <div className="mt-0.5 text-[11px] leading-tight text-muted">{o.desc}</div>
              </button>
            ))}
          </div>
        </div>

        {err && <p className="text-[13px] text-err">{err}</p>}
      </div>

      <DialogFooter>
        <Button variant="default" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="suggested" onClick={deploy} disabled={!valid || deploying}>
          {deploying ? "Deploying…" : "Deploy"}
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
