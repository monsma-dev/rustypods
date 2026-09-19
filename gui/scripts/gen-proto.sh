#!/usr/bin/env bash
# Regenerate src/proto/rustypods.ts from crates/rustypods-proto/proto.
# Uses system protoc when present, else the protoc-bin-vendored binary the
# Rust build already pulls in — one compiler for both codegen paths.
set -euo pipefail
cd "$(dirname "$0")/.."

PROTO_DIR="$(cd ../crates/rustypods-proto/proto && pwd)"

if command -v protoc >/dev/null 2>&1; then
  PROTOC=protoc
else
  PROTOC=$(find "${CARGO_HOME:-$HOME/.cargo}/registry/src" \
    -name protoc -type f -path '*linux-x86_64*' 2>/dev/null | sort -V | tail -1)
fi
[ -n "$PROTOC" ] || { echo "no protoc found (need protobuf or a cargo fetch of rustypods-proto)" >&2; exit 1; }

mkdir -p src/proto
"$PROTOC" \
  --plugin="protoc-gen-ts_proto=node_modules/.bin/protoc-gen-ts_proto" \
  --ts_proto_out=src/proto \
  --ts_proto_opt=env=browser,forceLong=number,useOptionals=messages,esModuleInterop=true,outputServices=generic-definitions,outputClientImpl=false \
  -I "$PROTO_DIR" "$PROTO_DIR/rustypods.proto"

echo "generated src/proto/rustypods.ts via $PROTOC"
