import { PodState, podStateToJSON } from "../proto/rustypods";

export function StateBadge({ state }: { state: PodState }) {
  const cls =
    state === PodState.POD_STATE_RUNNING
      ? "bg-ok/15 text-ok"
      : state === PodState.POD_STATE_FAILED
        ? "bg-err/15 text-err"
        : state === PodState.POD_STATE_CREATED
          ? "bg-warn/15 text-warn"
          : "bg-white/5 text-muted";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-medium ${cls}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {podStateToJSON(state).replace("POD_STATE_", "").toLowerCase()}
    </span>
  );
}
