#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="Codex Band Bridge"
EXECUTABLE_NAME="CodexBandBridge"
BUNDLE_ID="com.example.codexbandbridge"
BUILD_DIR="$ROOT/build"
APP_DIR="$BUILD_DIR/$APP_NAME.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
IDENTITY="${CODE_SIGN_IDENTITY:-}"

if [[ -z "$IDENTITY" ]]; then
  IDENTITY="$(security find-identity -v -p codesigning | awk -F'\"' '/Apple Development/ { print $2; exit }')"
fi

if [[ -z "$IDENTITY" ]]; then
  echo "No Apple Development signing identity found. Set CODE_SIGN_IDENTITY." >&2
  exit 1
fi

rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

xcrun swiftc \
  -sdk "$SDK_PATH" \
  -target arm64-apple-macos14.0 \
  -parse-as-library \
  -O \
  -framework SwiftUI \
  -framework CoreBluetooth \
  -framework Combine \
  -framework AppKit \
  "$ROOT"/Sources/*.swift \
  -o "$MACOS_DIR/$EXECUTABLE_NAME"

cp "$ROOT/Resources/Info.plist" "$CONTENTS_DIR/Info.plist"
plutil -replace CFBundleIdentifier -string "$BUNDLE_ID" "$CONTENTS_DIR/Info.plist"

codesign --force --deep --timestamp=none --options runtime --sign "$IDENTITY" "$APP_DIR"
codesign --verify --strict --verbose=2 "$APP_DIR"

echo "$APP_DIR"
