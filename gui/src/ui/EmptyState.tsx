import type { ReactNode } from "react";

/**
 * GNOME `AdwStatusPage` pattern — icon, title, one line of description,
 * optional primary action. Replaces bare sentences like "No pods —
 * create one above or with `rustypods create …`", which only pointed
 * GUI users at the CLI.
 */
export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon: ReactNode;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-16 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-full bg-white/[0.06] text-muted">
        {icon}
      </div>
      <div className="space-y-1">
        <p className="text-[14px] font-semibold">{title}</p>
        {description && (
          <p className="mx-auto max-w-sm text-[13px] text-muted">{description}</p>
        )}
      </div>
      {action}
    </div>
  );
}
