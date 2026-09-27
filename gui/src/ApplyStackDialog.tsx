import { useState } from "react";
import * as api from "./api";
import { Dialog, DialogHeader, DialogFooter } from "./ui/Dialog";
import { Field } from "./ui/inputs";
import Button from "./ui/Button";

const STACK_TOML_EXAMPLE = `# stack.toml — members become pods named <stack>-<member>
# on one shared netns (they see each other on 127.0.0.1).
name = "demo"

[pods.web]
image = "arch-base"
ports = ["8080:80"]

[pods.db]
image = "arch-base"
`;

export default function ApplyStackDialog({
  onClose,
  onApplied,
}: {
  onClose: () => void;
  onApplied: () => void;
}) {
  const [toml, setToml] = useState(STACK_TOML_EXAMPLE);
  const [err, setErr] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);

  const apply = async () => {
    if (applying || !toml.trim()) return;
    setApplying(true);
    setErr(null);
    try {
      await api.applyStack(toml);
      onApplied();
      onClose();
    } catch (e) {
      setErr(String(e));
    } finally {
      setApplying(false);
    }
  };

  return (
    <Dialog onClose={onClose} width="w-[28rem]">
      <DialogHeader title={<h2 className="text-sm font-bold">Apply Stack</h2>} onClose={onClose} />

      <div className="flex-1 space-y-3 overflow-y-auto p-4">
        <Field label="stack.toml">
          <textarea
            autoFocus
            spellCheck={false}
            value={toml}
            onChange={(e) => setToml(e.target.value)}
            className="gn-focus h-48 w-full resize-none rounded-[var(--radius-control)] border border-white/10 bg-bg px-3 py-2 font-mono text-sm focus:border-accent"
          />
        </Field>
        {err && <p className="text-[13px] text-err">{err}</p>}
      </div>

      <DialogFooter>
        <Button variant="default" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="suggested" onClick={apply} disabled={!toml.trim() || applying}>
          {applying ? "Applying…" : "Apply"}
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
