import type { Image } from "../api";
import { Group } from "../ui/Group";
import { EmptyState } from "../ui/EmptyState";
import { ImagesIcon } from "../ui/icons";

export default function ImagesView({ images }: { images: Image[] }) {
  if (images.length === 0) {
    return (
      <EmptyState
        icon={<ImagesIcon size={26} />}
        title="No images yet"
        description={
          <>
            Pull one from a registry, or import an existing distrobox:{" "}
            <code>rustypods pull docker.io/library/debian:trixie</code>
          </>
        }
      />
    );
  }
  return (
    <Group>
      {images.map((i) => (
        <div key={i.name} className="flex items-center justify-between px-4 py-2.5">
          <div>
            <div className="text-[13px] font-medium">{i.name}</div>
            <div className="font-mono text-[11px] text-muted">{i.path}</div>
          </div>
          <span className="text-xs text-muted">{i.source}</span>
        </div>
      ))}
    </Group>
  );
}
