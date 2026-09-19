#!/usr/bin/env bash
# Build + test inside the arch distrobox (host has no Rust toolchain).
set -euo pipefail

BOX="${DISTROBOX_NAME:-arch}"
cd "$(dirname "$0")/.."

podman start "$BOX" >/dev/null 2>&1 || true
podman exec -u nick -w "$PWD" "$BOX" bash -lc \
  'export PATH="$HOME/.cargo/bin:$PATH"; RUSTFLAGS="-C link-arg=-fuse-ld=mold" cargo build --release && cargo test'
