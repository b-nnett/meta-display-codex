#!/usr/bin/env bash
set -euo pipefail

serial="${1:-2Y0YBYPJ0H0015}"
version="${2:-125.0.0.190.412}"

if [[ -z "${META_AUTHORIZATION:-}" ]]; then
  echo "META_AUTHORIZATION is not set" >&2
  exit 1
fi

candidates=(
  ota.hypernova.user
  ota.supernova.user
  ota.greatsupernova.user
  ota.paloma.user
  ota.spritz.user
  ota.aperolbellini.user
)

for device_type in "${candidates[@]}"; do
  echo "trying ${device_type}" >&2
  output="$(python3 "$(dirname "$0")/fetch_stella_ota.py" \
    --serial "$serial" \
    --version "$version" \
    --device-type "$device_type")"
  echo "$output"
  if grep -q '"has_ota": true' <<<"$output"; then
    echo "found OTA metadata with ${device_type}" >&2
    exit 0
  fi
done

echo "no OTA metadata found for candidate device types" >&2
exit 2
