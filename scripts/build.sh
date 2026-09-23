#!/usr/bin/env bash
# Release build + tests. Prefers a local cargo (e.g. inside the `dev` pod),
# falls back to the `dev` rustypods pod, then the legacy `arch` distrobox.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

BUILD='RUSTFLAGS="-C link-arg=-fuse-ld=mold" cargo build --release && cargo test'

if command -v cargo >/dev/null 2>&1; then
  echo "==> building with local cargo"
  env RUSTFLAGS="-C link-arg=-fuse-ld=mold" cargo build --release
  cargo test
elif command -v rustypods >/dev/null 2>&1 \
  && rustypods ps 2>/dev/null | awk '$1 == "dev" && $3 == "running"' | grep -q .; then
  echo "==> building inside the dev pod"
  rustypods shell dev -w "$PWD" --strict -- bash -lc "$BUILD"
elif command -v podman >/dev/null 2>&1 && podman container exists arch 2>/dev/null; then
  echo "==> building inside the legacy arch distrobox"
  podman exec -u "$(id -un)" -w "$PWD" arch bash -lc \
    "export PATH=\"\$HOME/.cargo/bin:\$PATH\"; $BUILD"
else
  cat >&2 <<'EOF'
error: no usable build environment.
  - install a Rust toolchain, or
  - start the dev pod (`rustypods start dev`) — it has cargo on PATH, or
  - start the legacy distrobox: `podman start arch`
EOF
  exit 1
fi
