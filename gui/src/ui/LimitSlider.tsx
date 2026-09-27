import { NumberInput } from "./inputs";

/** Slider + numeric input bound to a raw value (0 = unlimited). `scale`
 *  is raw units per displayed unit (e.g. GiB→bytes); `step` the slider
 *  granularity. Shared by the New Pod wizard and the pod detail pane. */
export function LimitSlider({
  label,
  hint,
  value,
  onChange,
  max,
  step,
  scale,
  unit,
  fmt,
}: {
  label: string;
  hint?: string;
  value: number;
  onChange: (v: number) => void;
  max: number;
  step: number;
  scale: number;
  unit: string;
  fmt: (v: number) => string;
}) {
  return (
    <div className="px-4 py-3">
      <div className="mb-2 flex items-baseline justify-between">
        <div>
          <span className="text-[13px] font-medium">{label}</span>
          {hint && <span className="gn-caption ml-2">{hint}</span>}
        </div>
        <div className="flex items-center gap-1.5">
          <NumberInput
            min={0}
            max={max / scale}
            step={step / scale}
            value={value / scale}
            onChange={(e) => onChange(Math.min(max, Math.max(0, Number(e.target.value) * scale)))}
            className="w-20"
            aria-label={`${label} value`}
          />
          <span className="w-16 text-[11px] text-muted">{value === 0 ? "unlimited" : unit}</span>
        </div>
      </div>
      <input
        type="range"
        min={0}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="slider w-full"
        aria-label={label}
      />
      <div className="mt-0.5 flex justify-between text-[9px] text-muted">
        <span>0</span>
        <span>{fmt(max)}</span>
      </div>
    </div>
  );
}
