#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="$ROOT/build/tools"
mkdir -p "$BUILD_DIR"

swiftc \
  "$ROOT/BandBridgeMac/Sources/DataXCodec.swift" \
  "$ROOT/BandBridgeMac/Sources/GestureDecoder.swift" \
  "$ROOT/BandBridgeMac/Sources/AirShieldSession.swift" \
  "$ROOT/tools/swift/SharedCoreValidation.swift" \
  -o "$BUILD_DIR/SharedCoreValidation"

"$BUILD_DIR/SharedCoreValidation"
