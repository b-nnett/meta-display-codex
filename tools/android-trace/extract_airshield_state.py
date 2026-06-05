#!/usr/bin/env python3
"""Extract redacted AirShield/ACDC identity state from a rooted Android target.

Default output intentionally does not include private keys or raw credential
values. Use --include-secret-material only when saving to a local trusted path
for bridge development.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_PACKAGE = "com.facebook.stella"
DEFAULT_OUT_DIR = Path("reverse/extracted-state")
DEFAULT_ADB_TIMEOUT_SECONDS = 15.0
REPORT_SCHEMA = "codex_airshield_state_v2"

INTERESTING_PREFS = (
    "acdc-shared-pref",
    "acdc-shared-pref-encrypted",
    "rldrive_pairing_timestamp",
)

INTERESTING_LIGHT_PREF_RE = re.compile(
    r"(acdc|constellation|identity|pair|oobe|onboarding|hypernova|stella_settings)",
    re.IGNORECASE,
)

INTERESTING_KEY_RE = re.compile(
    r"("
    r"acdc-|"
    r"constellation-|"
    r"^key-|"
    r"owned-|"
    r"needs-provisioning-|"
    r"device-identity-|"
    r"device-public-key|"
    r"key-derivation-key-|"
    r"secondary-certificate-|"
    r"app-private-key"
    r")"
)

SECRET_KEY_RE = re.compile(
    r"("
    r"private-key|"
    r"^key-|"
    r"key-derivation-key|"
    r"device-identity-device-ec-kdk|"
    r"certificate|"
    r"manifest"
    r")"
)

IDENTITY_KEY_SLOTS = (
    "app-private-key",
    "acdc-app-private-key",
    "constellation-manifest-authority-key",
)


@dataclass
class ADB:
    serial: str | None
    timeout_seconds: float = DEFAULT_ADB_TIMEOUT_SECONDS

    def base(self) -> list[str]:
        cmd = ["adb"]
        if self.serial:
            cmd.extend(["-s", self.serial])
        return cmd

    def run(self, args: list[str], check: bool = False) -> subprocess.CompletedProcess[bytes]:
        return run_command_bytes(
            self.base() + args,
            check=check,
            timeout_seconds=self.timeout_seconds,
        )

    def shell(self, command: str) -> tuple[int, bytes, bytes]:
        proc = self.run(["shell", command])
        return proc.returncode, proc.stdout, proc.stderr

    def shell_root(self, command: str) -> tuple[int, bytes, bytes]:
        proc = self.run(["shell", "su", "-c", command])
        if proc.returncode == 0:
            return proc.returncode, proc.stdout, proc.stderr
        return self.shell(command)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_command_bytes(
    cmd: list[str],
    *,
    check: bool = False,
    timeout_seconds: float,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        return subprocess.CompletedProcess(
            cmd,
            124,
            stdout=error.stdout or b"",
            stderr=(error.stderr or b"") + f"\ncommand timed out after {timeout_seconds:.0f}s.".encode("utf-8"),
        )


def maybe_base64_decode(value: str) -> bytes | None:
    compact = "".join(value.split())
    if len(compact) < 8:
        return None
    try:
        padded = compact + ("=" * (-len(compact) % 4))
        decoded = base64.b64decode(padded, validate=False)
    except Exception:
        return None
    if not decoded:
        return None
    return decoded


def parse_prefs_xml(raw: bytes) -> dict[str, object]:
    root = ET.fromstring(raw)
    values: dict[str, object] = {}
    for child in root:
        name = child.attrib.get("name")
        if not name:
            continue
        if child.tag == "string":
            values[name] = child.text or ""
        elif child.tag in {"boolean", "int", "long", "float"}:
            values[name] = child.attrib.get("value")
        else:
            values[name] = {
                "tag": child.tag,
                "attributes": dict(child.attrib),
                "text": child.text or "",
            }
    return values


def redact_value(key: str, value: object, include_secret_material: bool) -> dict[str, object]:
    raw_text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    raw_bytes = raw_text.encode("utf-8")
    decoded = maybe_base64_decode(raw_text) if isinstance(value, str) else None
    is_interesting = bool(INTERESTING_KEY_RE.search(key))
    is_secret = bool(SECRET_KEY_RE.search(key))

    out: dict[str, object] = {
        "key": key,
        "interesting": is_interesting,
        "secret_material": is_secret,
        "value_type": type(value).__name__,
        "value_length": len(raw_text),
        "value_sha256": sha256_hex(raw_bytes),
    }
    if decoded is not None:
        out["base64_decoded_length"] = len(decoded)
        out["base64_decoded_sha256"] = sha256_hex(decoded)
    if include_secret_material or not is_secret:
        out["value"] = value
    else:
        out["value"] = "<redacted>"
    return out


def select_shared_pref_paths(raw_paths: list[str], pref_dir: str) -> list[str]:
    paths = [path for path in raw_paths if path.strip().endswith(".xml")]
    # Identity slots have moved across app revisions. Scan every SharedPreferences
    # XML and persist only matching AirShield/ACDC keys, so a renamed file does
    # not look like missing identity material.
    acdc_path = f"{pref_dir}/acdc-shared-pref.xml"
    if acdc_path not in paths:
        paths.append(acdc_path)
    return sorted(set(paths))


def list_pref_files(adb: ADB, package: str) -> list[str]:
    pref_dir = f"/data/data/{package}/shared_prefs"
    rc, stdout, _ = adb.shell_root(f"ls -1 {pref_dir}/*.xml 2>/dev/null")
    if rc != 0:
        return []
    paths = [line.strip() for line in stdout.decode("utf-8", "replace").splitlines()]
    return select_shared_pref_paths(paths, pref_dir)


def list_light_pref_files(adb: ADB, package: str) -> list[str]:
    pref_dir = f"/data/data/{package}/app_light_prefs/{package}"
    rc, stdout, _ = adb.shell_root(f"find {pref_dir} -maxdepth 1 -type f -print 2>/dev/null")
    if rc != 0:
        return []
    paths: list[str] = []
    for line in stdout.decode("utf-8", "replace").splitlines():
        path = line.strip()
        name = Path(path).name
        lower_name = name.lower()
        if "token" in lower_name or "session_store" in lower_name:
            continue
        if INTERESTING_LIGHT_PREF_RE.search(name):
            paths.append(path)
    return sorted(set(paths))


def read_device_file(adb: ADB, path: str) -> bytes | None:
    rc, stdout, stderr = adb.shell_root(f"cat {path} 2>/dev/null")
    if rc != 0 or not stdout:
        sys.stderr.write(f"skip unreadable {path}: {stderr.decode('utf-8', 'replace').strip()}\n")
        return None
    return stdout


def ascii_strings(data: bytes, minimum: int = 4) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for byte in data:
        if 0x20 <= byte <= 0x7e:
            current.append(byte)
        else:
            if len(current) >= minimum:
                strings.append(current.decode("ascii", "replace"))
            current = bytearray()
    if len(current) >= minimum:
        strings.append(current.decode("ascii", "replace"))
    return strings


def identity_slot_summary(files: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    summary: dict[str, dict[str, object]] = {
        slot: {"present": False}
        for slot in IDENTITY_KEY_SLOTS
    }
    for file_report in files:
        path = str(file_report.get("path") or "")
        entries = file_report.get("entries")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            key = str(entry.get("key") or "")
            if key not in summary:
                continue
            summary[key] = {
                "present": True,
                "path": path,
                "value_length": entry.get("value_length"),
                "value_sha256": entry.get("value_sha256"),
                "base64_decoded_length": entry.get("base64_decoded_length"),
                "base64_decoded_sha256": entry.get("base64_decoded_sha256"),
                "redacted": entry.get("value") == "<redacted>",
            }
    return summary


def has_identity_slot(summary: object) -> bool:
    if not isinstance(summary, dict):
        return False
    for slot in IDENTITY_KEY_SLOTS:
        value = summary.get(slot)
        if isinstance(value, dict) and value.get("present") is True:
            return True
    return False


def interesting_entry_count(files: object) -> int:
    if not isinstance(files, list):
        return 0
    total = 0
    for file_report in files:
        if not isinstance(file_report, dict):
            continue
        try:
            total += int(file_report.get("interesting_entry_count", 0))
        except (TypeError, ValueError):
            pass
    return total


def build_summary(report: dict[str, Any], output_path: Path) -> dict[str, Any]:
    slots = report.get("identity_key_slots")
    slots_present = has_identity_slot(slots)
    return {
        "schema": report.get("schema"),
        "output_path": str(output_path),
        "redacted": report.get("redacted"),
        "files_scanned": len(report.get("files", [])) if isinstance(report.get("files"), list) else 0,
        "interesting_entries": interesting_entry_count(report.get("files")),
        "scan_policy": report.get("scan_policy"),
        "identity_key_slots": slots,
        "identity_key_slot_present": slots_present,
        "next_step": (
            "Run prepare_airshield_identity_import.py on this report."
            if slots_present
            else "No AirShield identity slot was found. Confirm the Stella target is paired/logged in, then rerun this extractor."
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", default=DEFAULT_PACKAGE)
    parser.add_argument("--serial", help="adb device serial")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument(
        "--adb-timeout",
        type=float,
        default=DEFAULT_ADB_TIMEOUT_SECONDS,
        help=f"seconds to wait for each adb command before treating the target as unavailable; default {DEFAULT_ADB_TIMEOUT_SECONDS:.0f}",
    )
    parser.add_argument(
        "--include-secret-material",
        action="store_true",
        help="write raw key/certificate/manifest values into the local JSON report",
    )
    parser.add_argument(
        "--require-identity-slot",
        action="store_true",
        help="exit nonzero after writing the report if no app-private-key/acdc identity slot is present",
    )
    parser.add_argument("--self-test", action="store_true", help="run synthetic parser checks and exit")
    return parser.parse_args()


def self_test() -> None:
    timeout_result = run_command_bytes(
        [sys.executable, "-c", "import time; time.sleep(1)"],
        timeout_seconds=0.01,
    )
    if timeout_result.returncode != 124 or b"timed out" not in timeout_result.stderr:
        raise SystemExit("self-test: expected command timeout wrapper to return rc 124")
    selected_paths = select_shared_pref_paths(
        [
            "/data/data/com.facebook.stella/shared_prefs/com.facebook.stella_preferences.xml",
            "/data/data/com.facebook.stella/shared_prefs/renamed_identity_store.xml",
            "/data/data/com.facebook.stella/shared_prefs/not_xml.pb",
        ],
        "/data/data/com.facebook.stella/shared_prefs",
    )
    if "/data/data/com.facebook.stella/shared_prefs/renamed_identity_store.xml" not in selected_paths:
        raise SystemExit("self-test: expected renamed shared pref XML to be scanned")
    if "/data/data/com.facebook.stella/shared_prefs/acdc-shared-pref.xml" not in selected_paths:
        raise SystemExit("self-test: expected explicit ACDC fallback path")
    if any(path.endswith(".pb") for path in selected_paths):
        raise SystemExit("self-test: expected non-XML shared pref files to be skipped")
    secret_value = base64.b64encode(b"A" * 32).decode("ascii")
    raw = f"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
  <string name="acdc-app-private-key">{secret_value}</string>
  <string name="unrelated">ignored</string>
</map>
""".encode("utf-8")
    values = parse_prefs_xml(raw)
    entries = [
        redact_value(key, value, include_secret_material=False)
        for key, value in sorted(values.items())
        if INTERESTING_KEY_RE.search(key)
    ]
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "package": DEFAULT_PACKAGE,
        "redacted": True,
        "scan_policy": {
            "shared_prefs_xml": "all_xml_redacted_matching_entries_only",
            "app_light_prefs": "filtered_names_redacted_ascii_strings_only",
        },
        "files": [
            {
                "path": "/data/data/com.facebook.stella/shared_prefs/acdc-shared-pref.xml",
                "interesting_entry_count": len(entries),
                "entries": entries,
            }
        ],
    }
    report["identity_key_slots"] = identity_slot_summary(report["files"])
    slots = report["identity_key_slots"]
    if not has_identity_slot(slots):
        raise SystemExit("self-test: expected ACDC identity slot")
    slot = slots["acdc-app-private-key"]
    if slot.get("redacted") is not True:
        raise SystemExit("self-test: expected secret value to be redacted")
    if slot.get("base64_decoded_length") != 32:
        raise SystemExit("self-test: expected decoded key length")
    summary = build_summary(report, Path("state.json"))
    if summary["identity_key_slot_present"] is not True:
        raise SystemExit("self-test: expected summary slot presence")
    empty_summary = build_summary({"files": [], "identity_key_slots": identity_slot_summary([])}, Path("empty.json"))
    if empty_summary["identity_key_slot_present"] is not False:
        raise SystemExit("self-test: expected empty report to miss identity slot")
    print("self-test: OK")


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0

    adb = ADB(args.serial, timeout_seconds=args.adb_timeout)
    state = adb.run(["get-state"])
    if state.returncode != 0 or state.stdout.strip() != b"device":
        stderr = state.stderr.decode("utf-8", "replace").strip()
        detail = f": {stderr}" if stderr else ""
        sys.stderr.write(f"adb target is not in device state{detail}\n")
        return 2

    files = sorted(set(list_pref_files(adb, args.package) + list_light_pref_files(adb, args.package)))
    if not files:
        sys.stderr.write(f"no readable prefs/state files found for {args.package}\n")
        return 3

    report: dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "package": args.package,
        "serial": args.serial,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "redacted": not args.include_secret_material,
        "scan_policy": {
            "shared_prefs_xml": "all_xml_redacted_matching_entries_only",
            "app_light_prefs": "filtered_names_redacted_ascii_strings_only",
            "adb_timeout_seconds": args.adb_timeout,
        },
        "files": [],
        "identity_key_slots": {},
    }

    for path in files:
        raw = read_device_file(adb, path)
        if raw is None:
            continue
        if not path.endswith(".xml"):
            strings = ascii_strings(raw)
            report["files"].append({
                "path": path,
                "format": "app_light_pref_or_binary",
                "file_sha256": sha256_hex(raw),
                "file_length": len(raw),
                "interesting_entry_count": 0,
                "ascii_strings": strings[:200],
            })
            continue

        try:
            values = parse_prefs_xml(raw)
        except ET.ParseError as exc:
            report["files"].append({
                "path": path,
                "parse_error": str(exc),
                "xml_sha256": sha256_hex(raw),
                "xml_length": len(raw),
            })
            continue

        entries = [
            redact_value(key, value, args.include_secret_material)
            for key, value in sorted(values.items())
            if INTERESTING_KEY_RE.search(key)
        ]
        report["files"].append({
            "path": path,
            "xml_sha256": sha256_hex(raw),
            "xml_length": len(raw),
            "interesting_entry_count": len(entries),
            "entries": entries,
        })

    report["identity_key_slots"] = identity_slot_summary(report["files"])  # type: ignore[arg-type]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    suffix = "with-secrets" if args.include_secret_material else "redacted"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_path = out_dir / f"{args.package}-airshield-state-{suffix}-{stamp}.json"
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    summary = build_summary(report, out_path)  # type: ignore[arg-type]
    print(json.dumps(summary, indent=2, sort_keys=True))
    if args.require_identity_slot and not summary["identity_key_slot_present"]:
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
