import { useState } from "react";
import * as api from "./api";
import { Dialog, DialogHeader, DialogFooter } from "./ui/Dialog";
import { Field, TextInput } from "./ui/inputs";
import Switch from "./ui/Switch";
import Button from "./ui/Button";

export default function AddPeerDialog({
  onClose,
  onAdded,
}: {
  onClose: () => void;
  onAdded: () => void;
}) {
  const [endpoint, setEndpoint] = useState("");
  const [pubkey, setPubkey] = useState("");
  const [name, setName] = useState("");
  const [witness, setWitness] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const valid = endpoint.trim().length > 0 && pubkey.trim().length > 0;

  const submit = async () => {
    if (!valid || submitting) return;
    setSubmitting(true);
    setErr(null);
    try {
      await api.meshAddPeer(
        endpoint.trim(),
        pubkey.trim(),
        name.trim() || undefined,
        witness
      );
      onAdded();
      onClose();
    } catch (e) {
      setErr(String(e));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog onClose={onClose}>
      <DialogHeader title={<h2 className="text-sm font-bold">Add Peer</h2>} onClose={onClose} />

      <div className="flex-1 space-y-5 overflow-y-auto p-4">
        <Field label="Endpoint">
          <TextInput
            autoFocus
            placeholder="203.0.113.9:51820 or [2001:db8::1]:51820"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            mono
            className="w-full"
          />
        </Field>
        <Field label="Public key">
          <TextInput
            placeholder="base64 WireGuard public key"
            value={pubkey}
            onChange={(e) => setPubkey(e.target.value)}
            mono
            className="w-full"
          />
        </Field>
        <Field label="Name" hint="optional alias">
          <TextInput
            placeholder="s2"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full"
          />
        </Field>
        <Field label="Role">
          <div className="flex items-center gap-3">
            <Switch checked={witness} onChange={setWitness} label="Witness" />
            <div>
              <div className="text-[13px] font-medium">Witness</div>
              <div className="text-[11px] leading-tight text-muted">
                Votes for quorum, never runs a workload
              </div>
            </div>
          </div>
        </Field>

        {err && <p className="text-[13px] text-err">{err}</p>}
      </div>

      <DialogFooter>
        <Button variant="default" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="suggested" onClick={submit} disabled={!valid || submitting}>
          {submitting ? "Adding…" : "Add peer"}
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
