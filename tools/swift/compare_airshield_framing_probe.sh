#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 /path/to/airshield-framing-probe.json | --json /path/to/airshield-framing-probe.json | --self-test | --self-test-probe-json" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="$ROOT/build/tools"
TOOL="$BUILD_DIR/CompareAirShieldFramingProbe"
SOURCES=(
  "$ROOT/BandBridgeMac/Sources/DataXCodec.swift"
  "$ROOT/BandBridgeMac/Sources/GestureDecoder.swift"
  "$ROOT/BandBridgeMac/Sources/AirShieldSession.swift"
  "$ROOT/tools/swift/CompareAirShieldFramingProbe.swift"
)
mkdir -p "$BUILD_DIR"

if [[ ! -x "$TOOL" ]] || [[ "${SOURCES[0]}" -nt "$TOOL" ]] || [[ "${SOURCES[1]}" -nt "$TOOL" ]] || [[ "${SOURCES[2]}" -nt "$TOOL" ]] || [[ "${SOURCES[3]}" -nt "$TOOL" ]]; then
  swiftc "${SOURCES[@]}" -o "$TOOL"
fi

"$TOOL" "$@"
