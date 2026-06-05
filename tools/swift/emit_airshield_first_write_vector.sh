#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="$ROOT/build/tools"
mkdir -p "$BUILD_DIR"

swiftc \
  "$ROOT/BandBridgeMac/Sources/DataXCodec.swift" \
  "$ROOT/tools/swift/EmitAirShieldFirstWriteVector.swift" \
  -o "$BUILD_DIR/EmitAirShieldFirstWriteVector"

"$BUILD_DIR/EmitAirShieldFirstWriteVector"
