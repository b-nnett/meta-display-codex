#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="$ROOT/build/tools"
mkdir -p "$BUILD_DIR"

swiftc \
  "$ROOT/BandBridgeMac/Sources/BandScanner.swift" \
  "$ROOT/BandBridgeMac/Sources/GattSession.swift" \
  "$ROOT/BandBridgeMac/Sources/L2CAPSession.swift" \
  "$ROOT/BandBridgeMac/Sources/DataXCodec.swift" \
  "$ROOT/BandBridgeMac/Sources/GestureDecoder.swift" \
  "$ROOT/BandBridgeMac/Sources/LocalEventServer.swift" \
  "$ROOT/BandBridgeMac/Sources/EventForwarder.swift" \
  "$ROOT/BandBridgeMac/Sources/AirShieldSession.swift" \
  "$ROOT/tools/swift/DataXCodecValidation.swift" \
  -o "$BUILD_DIR/DataXCodecValidation"

"$BUILD_DIR/DataXCodecValidation"

swiftc \
  "$ROOT/BandBridgeMac/Sources/DataXCodec.swift" \
  "$ROOT/tools/swift/EmitAirShieldFirstWriteVector.swift" \
  -o "$BUILD_DIR/EmitAirShieldFirstWriteVector"

"$BUILD_DIR/EmitAirShieldFirstWriteVector" >/dev/null
