#!/usr/bin/env bash
# Local and CI gate: fmt, clippy -D warnings, tests, then advisory scans
# when cargo-audit and cargo-deny are installed.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

echo "==> cargo fmt --check"
cargo fmt --all --check

echo "==> cargo clippy -D warnings"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> cargo test"
cargo test --workspace -- --test-threads=1

if command -v cargo-audit >/dev/null 2>&1; then
  echo "==> cargo audit"
  cargo audit
else
  echo "==> cargo audit skipped (cargo-audit not installed; cargo install --locked cargo-audit)"
fi

if command -v cargo-deny >/dev/null 2>&1; then
  echo "==> cargo deny"
  cargo deny check advisories bans licenses sources
else
  echo "==> cargo deny skipped (cargo-deny not installed; cargo install --locked cargo-deny)"
fi
