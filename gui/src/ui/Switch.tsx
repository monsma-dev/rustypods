/** Adwaita pill switch — replaces native checkboxes for booleans. */
export default function Switch({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={`gn-focus relative h-6 w-10 shrink-0 rounded-full transition-colors ${
        checked ? "bg-accent" : "bg-white/10"
      }`}
    >
      <span
        className={`absolute top-1 h-4 w-4 rounded-full bg-white shadow transition-all ${
          checked ? "left-5" : "left-1"
        }`}
      />
    </button>
  );
}
