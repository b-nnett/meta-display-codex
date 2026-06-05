#!/usr/bin/env python3
"""Prepare a local AirShield identity slot import from extracted Android state.

Default output is redacted. If the extracted-state JSON was created with
--include-secret-material, this helper can write the chosen Base64 slot to a
0600 local file for Mac bridge import without printing the secret.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


DEFAULT_OUT_DIR = Path("reverse/identity-imports")
DEFAULT_STATE_GLOB = "reverse/extracted-state/com.facebook.stella-airshield-state-*.json"
SLOT_ORDER = (
    "acdc-app-private-key",
    "app-private-key",
    "constellation-manifest-authority-key",
)
SLOT_NOTES = {
    "acdc-app-private-key": "preferred when Android trace shows the GCS/ACDC auth delegate",
    "app-private-key": "preferred when Android trace shows the GD5 linked-app auth delegate",
    "constellation-manifest-authority-key": "fallback evidence slot; do not prefer unless traces point at it",
}
CURRENT_STATE_SCHEMA = "codex_airshield_state_v2"
CURRENT_SHARED_PREF_SCAN_POLICY = "all_xml_redacted_matching_entries_only"


def sha256_prefix(data: bytes, prefix_bytes: int = 8) -> str:
    return hashlib.sha256(data).digest()[:prefix_bytes].hex()


def read_json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise SystemExit(f"{path} is not a JSON object")
    return loaded


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def latest_state_report(pattern: str = DEFAULT_STATE_GLOB) -> Path | None:
    root = repo_root()
    candidates = sorted(
        root.glob(pattern),
        key=lambda item: item.stat().st_mtime if item.exists() else 0,
        reverse=True,
    )
    return candidates[0] if candidates else None


def decoded_base64(value: str) -> bytes | None:
    compact = "".join(value.split())
    if not compact:
        return None
    try:
        padded = compact + ("=" * (-len(compact) % 4))
        return base64.b64decode(padded, validate=False)
    except Exception:
        return None


def find_slot_entry(report: dict[str, Any], slot: str) -> dict[str, Any] | None:
    files = report.get("files")
    if not isinstance(files, list):
        return None
    for file_report in files:
        if not isinstance(file_report, dict):
            continue
        entries = file_report.get("entries") or file_report.get("interesting_entries")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and entry.get("key") == slot:
                merged = dict(entry)
                merged["path"] = file_report.get("path")
                return merged
    return None


def slot_summary(report: dict[str, Any], slot: str) -> dict[str, Any]:
    entry = find_slot_entry(report, slot)
    summaries = report.get("identity_key_slots")
    if isinstance(summaries, dict) and isinstance(summaries.get(slot), dict):
        summary = dict(summaries[slot])
        if entry:
            for key in (
                "path",
                "value_length",
                "value_sha256",
                "base64_decoded_length",
                "base64_decoded_sha256",
                "redacted",
            ):
                if summary.get(key) is None and entry.get(key) is not None:
                    summary[key] = entry.get(key)
            if summary.get("redacted") is None:
                summary["redacted"] = entry.get("value") == "<redacted>"
        return summary
    if not entry:
        return {"present": False}
    return {
        "present": True,
        "path": entry.get("path"),
        "value_length": entry.get("value_length"),
        "value_sha256": entry.get("value_sha256"),
        "base64_decoded_length": entry.get("base64_decoded_length"),
        "base64_decoded_sha256": entry.get("base64_decoded_sha256"),
        "redacted": entry.get("value") == "<redacted>",
    }


def available_slots(report: dict[str, Any]) -> list[str]:
    return [slot for slot in SLOT_ORDER if slot_summary(report, slot).get("present") is True]


def choose_slot(report: dict[str, Any], requested: str | None) -> str | None:
    if requested:
        return requested if slot_summary(report, requested).get("present") is True else None
    slots = available_slots(report)
    return slots[0] if slots else None


def secret_value(report: dict[str, Any], slot: str) -> str | None:
    entry = find_slot_entry(report, slot)
    if not entry:
        return None
    value = entry.get("value")
    if not isinstance(value, str) or value == "<redacted>":
        return None
    return value


def write_secret_file(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value.strip())
            handle.write("\n")
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def state_report_is_current(report: dict[str, Any]) -> bool:
    scan_policy = report.get("scan_policy")
    shared_pref_policy = scan_policy.get("shared_prefs_xml") if isinstance(scan_policy, dict) else None
    return (
        report.get("schema") == CURRENT_STATE_SCHEMA
        and shared_pref_policy == CURRENT_SHARED_PREF_SCAN_POLICY
    )


def current_schema_gate_failed(report: dict[str, Any], require_current_schema: bool) -> bool:
    return require_current_schema and not state_report_is_current(report)


def build_report(input_path: Path, report: dict[str, Any], selected_slot: str | None, export_path: Path | None) -> dict[str, Any]:
    slots: dict[str, Any] = {}
    for slot in SLOT_ORDER:
        summary = slot_summary(report, slot)
        slots[slot] = {
            "present": summary.get("present") is True,
            "source_path": summary.get("path"),
            "value_length": summary.get("value_length"),
            "value_sha256": summary.get("value_sha256"),
            "base64_decoded_length": summary.get("base64_decoded_length"),
            "base64_decoded_sha256": summary.get("base64_decoded_sha256"),
            "redacted": summary.get("redacted"),
            "note": SLOT_NOTES[slot],
        }
    scan_policy = report.get("scan_policy") if isinstance(report.get("scan_policy"), dict) else {}
    current_state = state_report_is_current(report)
    if not current_state:
        next_step = "Rerun extract_airshield_state.py with --require-identity-slot using the current extractor before importing."
    elif export_path:
        next_step = "Import the exported Base64 file contents into the Mac bridge with the matching slot selected."
    else:
        next_step = "Run extract_airshield_state.py with --include-secret-material on a trusted local target, then rerun this helper with --export-base64."
    return {
        "schema": "codex_airshield_identity_import_plan_v1",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input_path": str(input_path),
        "input_schema": report.get("schema"),
        "input_scan_policy": scan_policy,
        "input_is_current_schema": current_state,
        "package": report.get("package"),
        "input_redacted": report.get("redacted"),
        "selected_slot": selected_slot,
        "selected_slot_note": SLOT_NOTES.get(selected_slot or "", "no identity slot selected"),
        "slots": slots,
        "base64_export_path": str(export_path) if export_path else None,
        "base64_exported": export_path is not None,
        "next_step": next_step,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare a redacted AirShield identity import plan from extracted state JSON.")
    parser.add_argument("state_json", nargs="?", type=Path, help="extract_airshield_state.py JSON report")
    parser.add_argument(
        "--latest",
        action="store_true",
        help="use the newest extracted-state report under reverse/extracted-state when state_json is omitted",
    )
    parser.add_argument("--slot", choices=SLOT_ORDER, help="identity slot to prepare; default chooses the first present preferred slot")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument(
        "--export-base64",
        action="store_true",
        help="write the chosen Base64 value to a 0600 local file when the input JSON includes secret material",
    )
    parser.add_argument(
        "--require-current-schema",
        action="store_true",
        help="exit nonzero before export if the state report was not produced by the current all-SharedPreferences extractor",
    )
    parser.add_argument("--self-test", action="store_true", help="run synthetic validation and exit")
    return parser.parse_args()


def self_test() -> None:
    value = base64.b64encode(b"A" * 32).decode("ascii")
    decoded = decoded_base64(value)
    assert decoded is not None
    report = {
        "schema": CURRENT_STATE_SCHEMA,
        "package": "com.facebook.stella",
        "redacted": False,
        "scan_policy": {"shared_prefs_xml": CURRENT_SHARED_PREF_SCAN_POLICY},
        "files": [
            {
                "path": "/data/data/com.facebook.stella/shared_prefs/acdc-shared-pref.xml",
                "entries": [
                    {
                        "key": "acdc-app-private-key",
                        "value": value,
                        "value_length": len(value),
                        "value_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
                        "base64_decoded_length": len(decoded),
                        "base64_decoded_sha256": hashlib.sha256(decoded).hexdigest(),
                    }
                ],
            }
        ],
        "identity_key_slots": {"acdc-app-private-key": {"present": True}},
    }
    if choose_slot(report, None) != "acdc-app-private-key":
        raise SystemExit("self-test: expected ACDC slot to be selected")
    if secret_value(report, "acdc-app-private-key") != value:
        raise SystemExit("self-test: expected secret value extraction")
    plan = build_report(Path("state.json"), report, "acdc-app-private-key", Path("slot.base64"))
    if plan["input_is_current_schema"] is not True:
        raise SystemExit("self-test: expected current state schema")
    if plan["slots"]["acdc-app-private-key"]["base64_decoded_length"] != 32:
        raise SystemExit("self-test: expected decoded length in plan")
    stale_plan = build_report(Path("old-state.json"), {"files": []}, None, None)
    if stale_plan["input_is_current_schema"] is not False:
        raise SystemExit("self-test: expected stale state schema to be flagged")
    if "Rerun extract_airshield_state.py" not in stale_plan["next_step"]:
        raise SystemExit("self-test: expected stale state rerun guidance")
    if current_schema_gate_failed(report, True):
        raise SystemExit("self-test: current report must pass current-schema gate")
    if not current_schema_gate_failed({"files": []}, True):
        raise SystemExit("self-test: stale report must fail current-schema gate")
    if current_schema_gate_failed({"files": []}, False):
        raise SystemExit("self-test: stale report should pass when current-schema gate is not required")
    original_latest_state_report = globals()["latest_state_report"]
    try:
        globals()["latest_state_report"] = lambda pattern=DEFAULT_STATE_GLOB: Path("latest-state.json")
        if resolve_state_path(None, latest=True) != Path("latest-state.json"):
            raise SystemExit("self-test: expected --latest to resolve latest report")
    finally:
        globals()["latest_state_report"] = original_latest_state_report
    try:
        globals()["latest_state_report"] = lambda pattern=DEFAULT_STATE_GLOB: None
        resolve_state_path(None, latest=True)
        raise SystemExit("self-test: expected missing --latest report to exit")
    except SystemExit as error:
        if str(error) != f"no extracted-state reports found for {DEFAULT_STATE_GLOB}":
            raise
    finally:
        globals()["latest_state_report"] = original_latest_state_report
    redacted = {"files": [{"entries": [{"key": "app-private-key", "value": "<redacted>"}]}]}
    if secret_value(redacted, "app-private-key") is not None:
        raise SystemExit("self-test: redacted value must not be exportable")
    print("self-test: OK")


def resolve_state_path(state_json: Path | None, *, latest: bool) -> Path:
    if state_json is not None:
        if latest:
            raise SystemExit("pass either state_json or --latest, not both")
        return state_json.expanduser()
    if latest:
        path = latest_state_report()
        if path is None:
            raise SystemExit(f"no extracted-state reports found for {DEFAULT_STATE_GLOB}")
        return path
    raise SystemExit("state_json is required unless --latest or --self-test is used")


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0

    input_path = resolve_state_path(args.state_json, latest=args.latest)
    report = read_json(input_path)
    selected = choose_slot(report, args.slot)
    if current_schema_gate_failed(report, args.require_current_schema):
        print(json.dumps(build_report(input_path, report, selected, None), indent=2, sort_keys=True))
        return 4
    if not selected:
        print(json.dumps(build_report(input_path, report, None, None), indent=2, sort_keys=True))
        return 2

    export_path: Path | None = None
    if args.export_base64:
        value = secret_value(report, selected)
        if value is None:
            print(json.dumps(build_report(input_path, report, selected, None), indent=2, sort_keys=True))
            return 3
        decoded = decoded_base64(value)
        if decoded is None:
            raise SystemExit(f"selected slot {selected} is not valid Base64")
        stamp = time.strftime("%Y%m%d-%H%M%S")
        export_path = args.out_dir / f"airshield-{selected}-{stamp}.base64"
        write_secret_file(export_path, value)

    print(json.dumps(build_report(input_path, report, selected, export_path), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
