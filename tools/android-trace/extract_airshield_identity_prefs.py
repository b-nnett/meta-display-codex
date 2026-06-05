#!/usr/bin/env python3
"""Extract redacted AirShield identity key-slot evidence from Android prefs XML."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


KEY_SLOTS = {
    "app-private-key": "Linked app manager app private key",
    "acdc-app-private-key": "ACDC/Constellation app private key",
    "constellation-manifest-authority-key": "Constellation manifest authority private key",
    "acdc-constellation-manifest-authority-public-key": "ACDC manifest authority public key",
}


def decode_base64(value: str) -> bytes | None:
    try:
        return base64.b64decode(value, validate=False)
    except Exception:
        return None


def fingerprint(data: bytes, prefix_bytes: int = 8) -> str:
    return hashlib.sha256(data).digest()[:prefix_bytes].hex()


def xml_strings(path: Path) -> dict[str, str]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return {}

    values: dict[str, str] = {}
    for child in root:
        if child.tag != "string":
            continue
        name = child.attrib.get("name")
        if not name:
            continue
        values[name] = child.text or ""
    return values


def scan_path(path: Path, show_base64: bool) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    values = xml_strings(path)
    for key, description in KEY_SLOTS.items():
        if key not in values:
            continue
        value = values[key]
        decoded = decode_base64(value)
        row: dict[str, object] = {
            "file": str(path),
            "slot": key,
            "description": description,
            "base64_length": len(value),
            "decoded_length": len(decoded) if decoded is not None else None,
            "sha256_prefix": fingerprint(decoded) if decoded is not None else None,
            "valid_base64": decoded is not None,
        }
        if show_base64:
            row["base64"] = value
        rows.append(row)
    return rows


def candidate_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.rglob("*.xml")))
        elif path.is_file():
            files.append(path)
    return files


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Find AirShield identity key slots in pulled Android SharedPreferences XML."
    )
    parser.add_argument("paths", nargs="+", type=Path, help="XML file or directory to scan")
    parser.add_argument(
        "--show-base64",
        action="store_true",
        help="Include raw Base64 values in output. Defaults to redacted fingerprints only.",
    )
    args = parser.parse_args()

    rows: list[dict[str, object]] = []
    for path in candidate_files(args.paths):
        rows.extend(scan_path(path, show_base64=args.show_base64))

    json.dump(rows, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
