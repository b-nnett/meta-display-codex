#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/tools/android-trace/airshield_datax_trace.js"
PACKAGE="${1:-com.facebook.stella}"
DEVICE_SERIAL="${DEVICE_SERIAL:-}"
FORCE_SPAWN="${FORCE_SPAWN:-0}"
FRIDA_SERVER_PATH="${FRIDA_SERVER_PATH:-/data/local/tmp/frida-server}"
OUT_DIR="$ROOT/reverse/captures"
STAMP="$(date +"%Y%m%d-%H%M%S")"
OUT_FILE="$OUT_DIR/airshield-datax-$STAMP.jsonl"
PY_USER_BIN="$(python3 - <<'PY'
import os
import site
print(os.path.join(site.USER_BASE, "bin"))
PY
)"
FRIDA_BIN="${FRIDA_BIN:-$(command -v frida || true)}"
if [[ -z "$FRIDA_BIN" && -x "$PY_USER_BIN/frida" ]]; then
  FRIDA_BIN="$PY_USER_BIN/frida"
fi

mkdir -p "$OUT_DIR"

if ! command -v adb >/dev/null 2>&1; then
  echo "adb not found. Install Android platform-tools or add adb to PATH." >&2
  exit 1
fi

if [[ -z "$FRIDA_BIN" ]]; then
  echo "frida not found. Install frida-tools, then start frida-server on the rooted emulator." >&2
  echo "Example: python3 -m pip install --user frida-tools" >&2
  exit 1
fi

if ! adb get-state >/dev/null 2>&1; then
  echo "No adb device is connected or authorized." >&2
  adb devices >&2 || true
  exit 1
fi

if [[ -z "$DEVICE_SERIAL" ]]; then
  DEVICE_SERIAL="$(adb devices | awk 'NR>1 && $2=="device" {print $1; exit}')"
fi

if [[ -z "$DEVICE_SERIAL" ]]; then
  echo "No adb device in device state." >&2
  adb devices >&2 || true
  exit 1
fi

if ! adb -s "$DEVICE_SERIAL" shell ps -A | grep -q '[f]rida-server'; then
  if adb -s "$DEVICE_SERIAL" shell test -x "$FRIDA_SERVER_PATH"; then
    echo "Starting frida-server on $DEVICE_SERIAL" >&2
    adb -s "$DEVICE_SERIAL" shell "nohup '$FRIDA_SERVER_PATH' >/data/local/tmp/frida-server.log 2>&1 &"
    sleep 1
  else
    echo "frida-server not running and not found at $FRIDA_SERVER_PATH on $DEVICE_SERIAL." >&2
    exit 1
  fi
fi

if [[ "$FORCE_SPAWN" == "1" ]]; then
  echo "Force-stopping $PACKAGE before spawn" >&2
  adb -s "$DEVICE_SERIAL" shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
fi

PID="$(adb -s "$DEVICE_SERIAL" shell pidof "$PACKAGE" | tr -d '\r' | awk '{print $1}')"

echo "Writing trace to $OUT_FILE" >&2
echo "Using adb device $DEVICE_SERIAL" >&2

if [[ -n "$PID" ]]; then
  echo "Attaching to $PACKAGE pid=$PID with $SCRIPT" >&2
  "$FRIDA_BIN" -D "$DEVICE_SERIAL" -p "$PID" -l "$SCRIPT" 2>&1 | tee "$OUT_FILE"
else
  echo "$PACKAGE is not running; spawning with $SCRIPT" >&2
  "$FRIDA_BIN" -D "$DEVICE_SERIAL" -f "$PACKAGE" -l "$SCRIPT" 2>&1 | tee "$OUT_FILE"
fi
