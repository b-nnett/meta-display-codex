#!/usr/bin/env python3
"""Summarize the strongest local AirShield evidence across saved artifacts."""

from __future__ import annotations

import argparse
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from compare_airshield_identity import (
    android_trace_evidence,
    classify,
    fingerprint_matches,
    mac_session_evidence,
    native_probe_evidence,
    prefs_evidence,
)
from airshield_readiness import (
    Check,
    DEFAULT_GESTURE_EVENTS,
    DEFAULT_SESSIONS_DIR,
    android_checks,
    latest_session_jsonl,
    mac_checks,
    native_framing_probe_checks,
    native_private_key_probe_checks,
    event_name,
    read_jsonl,
)
from airshield_status import next_action as mac_status_next_action
from airshield_status import state_label as mac_status_state_label


DEFAULT_ANDROID_TRACE_GLOB = "reverse/captures/airshield-datax-*.jsonl"
DEFAULT_IDENTITY_STATE_GLOB = "reverse/extracted-state/com.facebook.stella-airshield-state-*.json"
DEFAULT_PRIVATE_KEY_PROBE_GLOB = "reverse/identity-probes/airshield-private-key-probe-*.json"
DEFAULT_FRAMING_PROBE_GLOB = "reverse/framing-probes/airshield-framing-probe-*.json"
DEFAULT_TARGET_PREFLIGHT_GLOB = "reverse/native-probe-targets/airshield-native-probe-target-*.json"
IDENTITY_SLOT_NAMES = {
    "app-private-key",
    "acdc-app-private-key",
    "constellation-manifest-authority-key",
}


@dataclass(frozen=True)
class ArtifactResult:
    kind: str
    path: Path
    ok_count: int
    total_count: int
    checks: list[Check]

    @property
    def missing(self) -> list[Check]:
        return [check for check in self.checks if not check.ok]

    @property
    def score(self) -> tuple[int, float, float]:
        ratio = self.ok_count / self.total_count if self.total_count else 0.0
        weighted_ok_count = self.ok_count
        if self.kind == "Mac BLE transport":
            checks_by_label = {check.label: check for check in self.checks}
            if checks_by_label.get("Target band selected/seen", Check("", False, "")).ok:
                weighted_ok_count += 100
            if checks_by_label.get("Exact band advertisement observed", Check("", False, "")).ok:
                weighted_ok_count += 60
            if checks_by_label.get("L2CAP opened", Check("", False, "")).ok:
                weighted_ok_count += 20
            if checks_by_label.get("GATT services discovered", Check("", False, "")).ok:
                weighted_ok_count += 10
            if checks_by_label.get("L2CAP write outcome observed", Check("", False, "")).ok:
                weighted_ok_count += 50
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            mtime = 0.0
        return (weighted_ok_count, ratio, mtime)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_json(path: Path) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _entry_list(file_report: dict[str, Any]) -> list[Any]:
    entries = file_report.get("entries")
    if isinstance(entries, list):
        return entries
    legacy_entries = file_report.get("interesting_entries")
    return legacy_entries if isinstance(legacy_entries, list) else []


def identity_state_checks(path: Path) -> list[Check]:
    loaded = load_json(path)
    files = loaded.get("files") if isinstance(loaded.get("files"), list) else []
    schema = loaded.get("schema")
    scan_policy = loaded.get("scan_policy") if isinstance(loaded.get("scan_policy"), dict) else {}
    shared_pref_policy = scan_policy.get("shared_prefs_xml")
    raw_slot_summary = loaded.get("identity_key_slots")
    has_slot_summary = isinstance(raw_slot_summary, dict)
    slot_summary = raw_slot_summary if has_slot_summary else {}
    interesting_entries = 0
    slot_entries = 0
    interesting_files = 0
    scanned_paths: list[str] = []
    for item in files:
        if not isinstance(item, dict):
            continue
        path_value = item.get("path")
        if isinstance(path_value, str):
            scanned_paths.append(path_value)
        try:
            item_interesting_entries = int(item.get("interesting_entry_count") or 0)
        except (TypeError, ValueError):
            item_interesting_entries = 0
        entries = _entry_list(item)
        if not item_interesting_entries and entries:
            item_interesting_entries = len(entries)
        interesting_entries += item_interesting_entries
        if item_interesting_entries:
            interesting_files += 1
        for entry in entries:
            if isinstance(entry, dict) and entry.get("key") in IDENTITY_SLOT_NAMES:
                slot_entries += 1
    slot_entries += sum(
        1
        for slot in IDENTITY_SLOT_NAMES
        if isinstance(slot_summary.get(slot), dict) and slot_summary[slot].get("present") is True
    )
    scanned_hint = "-"
    if scanned_paths:
        basenames = [Path(item).name for item in scanned_paths[:4]]
        suffix = "" if len(scanned_paths) <= 4 else f", +{len(scanned_paths) - 4} more"
        scanned_hint = ", ".join(basenames) + suffix
    return [
        Check("Extracted state readable", bool(loaded), f"schema={schema or '-'} package={loaded.get('package', '-')}"),
        Check("Extracted state has files", bool(files), f"{len(files)} files"),
        Check(
            "Current all-SharedPreferences scan used",
            schema == "codex_airshield_state_v2" and shared_pref_policy == "all_xml_redacted_matching_entries_only",
            f"schema={schema or '-'} shared_prefs_xml={shared_pref_policy or '-'}",
        ),
        Check("Identity slot summary present", has_slot_summary, f"present={has_slot_summary} scanned={scanned_hint}"),
        Check("Interesting AirShield entries found", interesting_entries > 0, f"{interesting_entries} entries across {interesting_files} files"),
        Check("Identity key slots found", slot_entries > 0, f"{slot_entries} key slots"),
    ]


def target_preflight_checks(path: Path) -> list[Check]:
    loaded = load_json(path)
    checks = loaded.get("checks") if isinstance(loaded.get("checks"), dict) else {}

    def item(name: str) -> dict[str, Any]:
        value = checks.get(name)
        return value if isinstance(value, dict) else {}

    adb_device = item("adb_device")
    boot = item("boot_completed")
    package = item("package_installed")
    frida_server = item("frida_server")
    frida_python = item("frida_python")
    java_bridge = item("frida_java_bridge")
    device_identity = item("device_identity")
    target = loaded.get("target") if isinstance(loaded.get("target"), dict) else {}
    return [
        Check(
            "Native probe target preflight readable",
            bool(loaded),
            f"schema={loaded.get('schema', '-')} serial={target.get('adbSerial', '-')}",
        ),
        Check("ADB device ready", adb_device.get("ok") is True, adb_device.get("detail") or adb_device.get("serial") or "-"),
        Check("Android boot completed", boot.get("ok") is True, f"value={boot.get('value', '-')}"),
        Check(
            "Target identity readable",
            bool(device_identity.get("abi") or device_identity.get("androidRelease")),
            f"abi={device_identity.get('abi', '-')} android={device_identity.get('androidRelease', '-')}",
        ),
        Check("Stella package installed", package.get("ok") is True, f"paths={len(package.get('paths') or [])}"),
        Check("frida-server ready", frida_server.get("ok") is True, str(frida_server.get("detail", "-"))),
        Check(
            "Mac Frida Python ready",
            frida_python.get("ok") is True,
            f"version={frida_python.get('version', '-')} error={frida_python.get('error', '-')}",
        ),
        Check(
            "Frida Java bridge available",
            java_bridge.get("ok") is True,
            f"hasJava={java_bridge.get('hasJava', '-')} arch={java_bridge.get('arch', '-') or '-'} error={java_bridge.get('error', '-')}",
        ),
    ]


def identity_match(left: list[Any], right: list[Any]) -> tuple[bool, str]:
    if not left or not right:
        return False, f"left={len(left)} right={len(right)}"
    for left_item in left:
        for right_item in right:
            if not fingerprint_matches(left_item.fingerprint, right_item.fingerprint):
                continue
            if (
                left_item.length is not None
                and right_item.length is not None
                and left_item.length != right_item.length
            ):
                continue
            return True, (
                f"{left_item.kind}({left_item.length or '-'}B) "
                f"<-> {right_item.kind}({right_item.length or '-'}B) "
                f"fp={left_item.fingerprint}"
            )
    return False, f"left={len(left)} right={len(right)} no matching fingerprint/length"


def load_identity_items(
    identity_path: Path | None,
    native_probe_path: Path | None,
    mac_session_path: Path | None,
    android_trace_path: Path | None,
) -> tuple[list[Any], list[Any], list[Any], list[Any]]:
    prefs_items = prefs_evidence(identity_path) if identity_path and identity_path.exists() else []
    probe_items = native_probe_evidence(native_probe_path) if native_probe_path and native_probe_path.exists() else []
    mac_items = mac_session_evidence(mac_session_path) if mac_session_path and mac_session_path.exists() else []
    trace_items = android_trace_evidence(android_trace_path) if android_trace_path and android_trace_path.exists() else []
    return prefs_items, probe_items, mac_items, trace_items


def identity_parity_checks(
    identity_path: Path | None,
    native_probe_path: Path | None,
    mac_session_path: Path | None,
    android_trace_path: Path | None = None,
) -> list[Check]:
    prefs_items, probe_items, mac_items, trace_items = load_identity_items(
        identity_path,
        native_probe_path,
        mac_session_path,
        android_trace_path,
    )
    prefs_private = prefs_items
    probe_private = (
        classify(probe_items, "private_key.input")
        + classify(probe_items, "private_key.set_raw")
        + classify(probe_items, "private_key.serialize")
    )
    probe_public = classify(probe_items, "recover_public_key")
    probe_accepted_public = classify(probe_items, "accepted_auth_public_key")
    trace_private = classify(trace_items, "private_key.set_raw") + classify(trace_items, "private_key.serialize")
    trace_public = (
        classify(trace_items, "recover_public_key")
        + classify(trace_items, "accept_key_candidate")
        + classify(trace_items, "acceptAuthentication")
    )
    mac_private = classify(mac_items, "private_key")
    mac_public = classify(mac_items, "public_key")
    prefs_probe_ok, prefs_probe_detail = identity_match(prefs_private, probe_private)
    probe_mac_private_ok, probe_mac_private_detail = identity_match(probe_private, mac_private)
    probe_mac_public_ok, probe_mac_public_detail = identity_match(probe_public, mac_public)
    probe_mac_accepted_ok, probe_mac_accepted_detail = identity_match(probe_accepted_public, mac_public)
    trace_mac_private_ok, trace_mac_private_detail = identity_match(trace_private, mac_private)
    trace_mac_public_ok, trace_mac_public_detail = identity_match(trace_public, mac_public)
    return [
        Check(
            "Identity parity inputs present",
            bool(prefs_items and probe_items and mac_items),
            f"prefs={len(prefs_items)} probe={len(probe_items)} mac={len(mac_items)} android_trace={len(trace_items)}",
        ),
        Check("Prefs slot matches native PrivateKey probe", prefs_probe_ok, prefs_probe_detail),
        Check("Native PrivateKey probe matches Mac private key", probe_mac_private_ok, probe_mac_private_detail),
        Check("Native recovered public key matches Mac candidate", probe_mac_public_ok, probe_mac_public_detail),
        Check("Native accepted-auth public key matches Mac candidate", probe_mac_accepted_ok, probe_mac_accepted_detail),
        Check(
            "Android trace private key matches Mac private key",
            trace_mac_private_ok,
            trace_mac_private_detail if trace_items else "no Android trace identity private-key events",
        ),
        Check(
            "Android trace public key matches Mac candidate",
            trace_mac_public_ok,
            trace_mac_public_detail if trace_items else "no Android trace identity public-key events",
        ),
    ]


def summary_path_for_session(path: Path) -> Path:
    if path.name.endswith("-summary.json"):
        return path
    if path.suffix == ".jsonl":
        return path.with_name(f"{path.stem}-summary.json")
    return path


def mac_transport_event_counts(path: Path) -> dict[str, int]:
    if path.suffix != ".jsonl" or not path.exists():
        return {}
    counts = {
        "l2cap_tx_success": 0,
        "l2cap_tx_zero": 0,
        "l2cap_tx_failed": 0,
        "direct_write_started": 0,
        "direct_write_finished": 0,
        "direct_write_timeout": 0,
        "direct_write_blocked": 0,
        "gatt_tx": 0,
        "probe_ready": 0,
    }
    for event in read_jsonl(path):
        name = event_name(event)
        label = event.get("label")
        if name == "l2cap.tx":
            try:
                byte_count = int(event.get("byte_count") or event.get("bytes_written") or 0)
            except (TypeError, ValueError):
                byte_count = 0
            if byte_count > 0:
                counts["l2cap_tx_success"] += 1
            else:
                counts["l2cap_tx_zero"] += 1
        elif name == "l2cap.tx_failed":
            counts["l2cap_tx_failed"] += 1
        elif name == "l2cap.direct_write_diagnostic_started":
            counts["direct_write_started"] += 1
        elif name == "l2cap.direct_write_diagnostic_finished":
            counts["direct_write_finished"] += 1
        elif name == "l2cap.direct_write_diagnostic_timeout":
            counts["direct_write_timeout"] += 1
        elif name == "l2cap.direct_write_diagnostic_blocked":
            counts["direct_write_blocked"] += 1
        elif name == "gatt.datax.tx" and label == "airshield.request_encryption.probe.gatt_fallback":
            counts["gatt_tx"] += 1
        elif name == "airshield.probe_state_ready":
            counts["probe_ready"] += 1
    return counts


def summary_with_transport_event_counts(summary: dict[str, Any], path: Path) -> dict[str, Any]:
    counts = mac_transport_event_counts(path)
    if not counts:
        return summary
    enriched = dict(summary)
    l2cap = dict(enriched.get("l2cap") if isinstance(enriched.get("l2cap"), dict) else {})
    gatt = dict(enriched.get("gatt") if isinstance(enriched.get("gatt"), dict) else {})
    airshield = dict(enriched.get("airshield") if isinstance(enriched.get("airshield"), dict) else {})
    l2cap["tx_frame_count"] = counts["l2cap_tx_success"]
    l2cap["tx_zero_byte_count"] = max(int(l2cap.get("tx_zero_byte_count") or 0), counts["l2cap_tx_zero"])
    l2cap["tx_failed_count"] = max(int(l2cap.get("tx_failed_count") or 0), counts["l2cap_tx_failed"])
    l2cap["direct_write_diagnostic_started_count"] = max(
        int(l2cap.get("direct_write_diagnostic_started_count") or 0),
        counts["direct_write_started"],
    )
    l2cap["direct_write_diagnostic_finished_count"] = max(
        int(l2cap.get("direct_write_diagnostic_finished_count") or 0),
        counts["direct_write_finished"],
    )
    l2cap["direct_write_diagnostic_timeout_count"] = max(
        int(l2cap.get("direct_write_diagnostic_timeout_count") or 0),
        counts["direct_write_timeout"],
    )
    l2cap["direct_write_diagnostic_blocked_count"] = max(
        int(l2cap.get("direct_write_diagnostic_blocked_count") or 0),
        counts["direct_write_blocked"],
    )
    gatt["datax_tx_count"] = max(int(gatt.get("datax_tx_count") or 0), counts["gatt_tx"])
    airshield["request_encryption_probe_ready_count"] = max(
        int(airshield.get("request_encryption_probe_ready_count") or 0),
        counts["probe_ready"],
    )
    enriched["l2cap"] = l2cap
    enriched["gatt"] = gatt
    enriched["airshield"] = airshield
    return enriched


def mac_transport_checks(path: Path) -> list[Check]:
    summary_path = summary_path_for_session(path)
    summary = summary_with_transport_event_counts(load_json(summary_path), path)
    connection = summary.get("connection") if isinstance(summary.get("connection"), dict) else {}
    device = summary.get("device") if isinstance(summary.get("device"), dict) else {}
    scan = summary.get("scan") if isinstance(summary.get("scan"), dict) else {}
    gatt = summary.get("gatt") if isinstance(summary.get("gatt"), dict) else {}
    l2cap = summary.get("l2cap") if isinstance(summary.get("l2cap"), dict) else {}
    last_exact_band = scan.get("last_exact_band") if isinstance(scan.get("last_exact_band"), dict) else {}
    services = gatt.get("services") if isinstance(gatt.get("services"), list) else []
    psm_values = gatt.get("psm_values") if isinstance(gatt.get("psm_values"), list) else []
    opened_psms = l2cap.get("opened_psms") if isinstance(l2cap.get("opened_psms"), list) else []
    state = mac_status_state_label(summary) if summary else "-"
    action = mac_status_next_action(summary) if summary else "-"
    exact_seen_count = int(scan.get("exact_band_seen_count") or 0)
    candidate_count = int(scan.get("candidate_count") or 0)
    scan_started_count = int(scan.get("started_count") or 0)
    scan_stopped_count = int(scan.get("stopped_count") or 0)
    l2cap_tx_count = int(l2cap.get("tx_frame_count") or 0)
    l2cap_tx_failed_count = int(l2cap.get("tx_failed_count") or 0)
    direct_write_started_count = int(l2cap.get("direct_write_diagnostic_started_count") or 0)
    direct_write_finished_count = int(l2cap.get("direct_write_diagnostic_finished_count") or 0)
    direct_write_timeout_count = int(l2cap.get("direct_write_diagnostic_timeout_count") or 0)
    gatt_tx_count = int(gatt.get("datax_tx_count") or 0)
    write_outcome_count = (
        l2cap_tx_count
        + l2cap_tx_failed_count
        + direct_write_started_count
        + direct_write_finished_count
        + direct_write_timeout_count
        + gatt_tx_count
    )
    target = str(summary.get("target_band_name") or "Meta Band 000J") if summary else "Meta Band 000J"
    names = {
        str(connection.get("name") or ""),
        str(device.get("name") or ""),
        str(last_exact_band.get("name") or ""),
    }
    transport_reset_state = state in {"STALE_PAIRING", "PAIRING_RESET_RECOMMENDED"}
    transport_connecting_state = state == "CONNECTING_TO_BAND"
    transport_write_blocked_state = state in {"L2CAP_CLOSED", "L2CAP_TX_BLOCKED", "L2CAP_TX_BLOCKED_GATT_FALLBACK_SENT"}
    return [
        Check("Mac transport summary readable", bool(summary), f"summary={summary_path}"),
        Check("Target band selected/seen", target in names, f"target={target} connection={connection.get('name', '-')} device={device.get('name', '-')}"),
        Check(
            "Exact band advertisement observed",
            exact_seen_count > 0,
            (
                f"exact={exact_seen_count} candidates={candidate_count} "
                f"started={scan_started_count} stopped={scan_stopped_count} "
                f"last={last_exact_band.get('name', '-')} rssi={last_exact_band.get('rssi', '-')}"
            ),
        ),
        Check("BLE connected", connection.get("event") == "ble.connected" or bool(device.get("peripheral_id")), f"event={connection.get('event', '-')} error={connection.get('error', '-')}"),
        Check("GATT services discovered", bool(services), f"{len(services)} services"),
        Check("DataX PSM discovered", bool(psm_values), f"{len(psm_values)} PSM values"),
        Check("L2CAP opened", bool(opened_psms), f"opened_psms={opened_psms or '-'}"),
        Check(
            "L2CAP write outcome observed",
            write_outcome_count > 0,
            (
                f"l2cap_tx={l2cap_tx_count} "
                f"l2cap_tx_failed={l2cap_tx_failed_count} "
                f"direct=start:{direct_write_started_count}/finish:{direct_write_finished_count}/timeout:{direct_write_timeout_count} "
                f"gatt_tx={gatt_tx_count}"
            ),
        ),
        Check(
            "Transport not blocked",
            not transport_reset_state and not transport_connecting_state and not transport_write_blocked_state,
            (
                f"state={state} l2cap_tx={l2cap_tx_count} "
                f"l2cap_tx_failed={l2cap_tx_failed_count} "
                f"gatt_tx={gatt_tx_count} next={action}"
            ),
        ),
    ]


def artifact_result(kind: str, path: Path, checks: list[Check]) -> ArtifactResult:
    ok_count = sum(1 for check in checks if check.ok)
    return ArtifactResult(kind=kind, path=path, ok_count=ok_count, total_count=len(checks), checks=checks)


def collect_results(
    *,
    kind: str,
    paths: list[Path],
    checker: Callable[[Path], list[Check]],
) -> list[ArtifactResult]:
    results: list[ArtifactResult] = []
    for path in paths:
        if not path.exists():
            continue
        results.append(artifact_result(kind, path, checker(path)))
    return sorted(results, key=lambda item: item.score, reverse=True)


def glob_paths(pattern: str) -> list[Path]:
    pattern_path = Path(pattern).expanduser()
    if pattern_path.is_absolute():
        base = Path("/")
        glob_pattern = str(pattern_path.relative_to("/"))
    else:
        base = repo_root()
        glob_pattern = pattern
    return sorted(base.glob(glob_pattern))


def session_paths(sessions_dir: Path, explicit_session: Path | None, *, latest: bool = False) -> list[Path]:
    if explicit_session:
        return [explicit_session.expanduser()]
    if latest:
        try:
            return [latest_session_jsonl(sessions_dir)]
        except SystemExit:
            return []
    if sessions_dir.exists():
        return sorted(path for path in sessions_dir.glob("session-*.jsonl") if not path.name.endswith("-summary.json"))
    return []


def print_result(result: ArtifactResult, *, missing_limit: int) -> None:
    relative = result.path
    try:
        relative = result.path.relative_to(repo_root())
    except ValueError:
        pass
    print(f"{result.kind}: {relative}")
    print(f"  evidence: {result.ok_count}/{result.total_count}")
    if result.kind in ("Native PrivateKey probe", "Native Framing probe"):
        loaded = load_json(result.path)
        native = loaded.get("native") if isinstance(loaded.get("native"), dict) else {}
        errors = native.get("errors") if isinstance(native.get("errors"), list) else []
        if loaded.get("probeStatus") or errors:
            print(f"  status: {loaded.get('probeStatus', '-')} errors={len(errors)}")
    if result.kind == "Mac BLE transport":
        summary = summary_with_transport_event_counts(load_json(summary_path_for_session(result.path)), result.path)
        if summary:
            scan = summary.get("scan") if isinstance(summary.get("scan"), dict) else {}
            last_exact_band = scan.get("last_exact_band") if isinstance(scan.get("last_exact_band"), dict) else {}
            print(f"  state: {mac_status_state_label(summary)}")
            print(f"  next: {mac_status_next_action(summary)}")
            if scan:
                print(
                    "  scan: "
                    f"active={str(bool(scan.get('active'))).lower()} "
                    f"started={int(scan.get('started_count') or 0)} "
                    f"stopped={int(scan.get('stopped_count') or 0)} "
                    f"candidates={int(scan.get('candidate_count') or 0)} "
                    f"exact={int(scan.get('exact_band_seen_count') or 0)} "
                    f"last_exact={last_exact_band.get('name', '-')} "
                    f"rssi={last_exact_band.get('rssi', '-')}"
                )
    if result.missing:
        print("  missing:")
        for check in result.missing[:missing_limit]:
            print(f"    - {check.label}: {check.detail}")
        if len(result.missing) > missing_limit:
            print(f"    - ... {len(result.missing) - missing_limit} more")
    else:
        print("  missing: none")


def print_group(title: str, results: list[ArtifactResult], *, missing_limit: int) -> None:
    print(title)
    if not results:
        print("  no artifacts found")
        print()
        return
    print_result(results[0], missing_limit=missing_limit)
    if len(results) > 1:
        print(f"  other artifacts scanned: {len(results) - 1}")
    print()


def overall_complete(groups: list[list[ArtifactResult]]) -> bool:
    return all(
        bool(results) and results[0].ok_count == results[0].total_count
        for results in groups
    )


def self_test() -> None:
    ok = Check("ok", True, "ok")
    missing = Check("missing", False, "missing")
    complete_group = [artifact_result("complete", Path("complete.json"), [ok])]
    incomplete_group = [artifact_result("incomplete", Path("incomplete.json"), [ok, missing])]
    if overall_complete([complete_group, complete_group]) is not True:
        raise SystemExit("self-test: expected complete groups to pass")
    if overall_complete([complete_group, []]) is not False:
        raise SystemExit("self-test: expected missing group to fail")
    if overall_complete([complete_group, incomplete_group]) is not False:
        raise SystemExit("self-test: expected incomplete group to fail")
    failed_preflight = {
        "schema": "codex_airshield_native_probe_target_preflight_v1",
        "target": {"adbSerial": None, "package": "com.facebook.stella"},
        "checks": {"adb_device": {"ok": False, "detail": "no adb device in device state"}},
    }
    synthetic_path = Path("__synthetic_native_probe_target_preflight__.json")
    original_load_json = globals()["load_json"]
    try:
        globals()["load_json"] = lambda path: failed_preflight if path == synthetic_path else original_load_json(path)
        preflight_checks = target_preflight_checks(synthetic_path)
    finally:
        globals()["load_json"] = original_load_json
    if preflight_checks[0].ok is not True:
        raise SystemExit("self-test: expected readable synthetic preflight")
    if all(check.ok for check in preflight_checks):
        raise SystemExit("self-test: expected failed preflight checks to remain incomplete")
    extracted_state = {
        "schema": "codex_airshield_state_v2",
        "package": "com.facebook.stella",
        "scan_policy": {
            "shared_prefs_xml": "all_xml_redacted_matching_entries_only",
        },
        "files": [
            {
                "interesting_entry_count": 1,
                "entries": [
                    {
                        "key": "acdc-app-private-key",
                        "value_length": 44,
                        "base64_decoded_length": 32,
                    }
                ],
            }
        ],
        "identity_key_slots": {
            "acdc-app-private-key": {"present": True},
            "app-private-key": {"present": False},
            "constellation-manifest-authority-key": {"present": False},
        },
    }
    try:
        globals()["load_json"] = lambda path: extracted_state if path == synthetic_path else original_load_json(path)
        identity_checks = identity_state_checks(synthetic_path)
    finally:
        globals()["load_json"] = original_load_json
    if not all(check.ok for check in identity_checks):
        raise SystemExit("self-test: expected current extracted-state schema to pass identity checks")
    stale_extracted_state = {
        "package": "com.facebook.stella",
        "files": [
            {
                "path": "/data/data/com.facebook.stella/app_light_prefs/com.facebook.stella/device_assets_prepair_2Y",
                "format": "app_light_pref_or_binary",
                "interesting_entry_count": 0,
            }
        ],
    }
    try:
        globals()["load_json"] = lambda path: stale_extracted_state if path == synthetic_path else original_load_json(path)
        stale_identity_checks = identity_state_checks(synthetic_path)
    finally:
        globals()["load_json"] = original_load_json
    stale_by_label = {check.label: check for check in stale_identity_checks}
    if stale_by_label["Identity slot summary present"].ok is not False:
        raise SystemExit("self-test: expected stale extracted state to miss slot summary")
    if "device_assets_prepair_2Y" not in stale_by_label["Identity slot summary present"].detail:
        raise SystemExit("self-test: expected stale extracted state to include scanned file hint")
    private_fp = "aabbccddeeff0011"
    public_fp = "1122334455667788"
    accepted_public_fp = "9988776655443322"
    with (
        tempfile.NamedTemporaryFile("w", suffix="-identity.json", delete=True, encoding="utf-8") as identity_handle,
        tempfile.NamedTemporaryFile("w", suffix="-probe.json", delete=True, encoding="utf-8") as probe_handle,
        tempfile.NamedTemporaryFile("w", suffix="-mac.jsonl", delete=True, encoding="utf-8") as mac_handle,
        tempfile.NamedTemporaryFile("w", suffix="-trace.jsonl", delete=True, encoding="utf-8") as trace_handle,
    ):
        json.dump(
            {
                "identity_key_slots": {
                    "acdc-app-private-key": {
                        "present": True,
                        "base64_decoded_length": 32,
                        "base64_decoded_sha256": private_fp,
                    }
                }
            },
            identity_handle,
        )
        identity_handle.flush()
        json.dump(
            {
                "slot": "acdc-app-private-key",
                "input": {"length": 32, "sha256PrefixHex": private_fp},
                "native": {
                    "inputRawPrivateKey": {"length": 32, "sha256PrefixHex": private_fp},
                    "nativeSerialize": {"length": 32, "sha256PrefixHex": private_fp},
                    "nativeRecoverPublicKey": {"length": 64, "sha256PrefixHex": public_fp},
                    "acceptedAuthenticationPublicKey": {"length": 64, "sha256PrefixHex": accepted_public_fp},
                },
            },
            probe_handle,
        )
        probe_handle.flush()
        mac_handle.write(json.dumps({
            "type": "airshield.identity.imported",
            "slot": "acdc-app-private-key",
            "private_key_fingerprint": private_fp,
            "raw_private_key_length": 32,
            "public_key_fingerprint": public_fp,
            "raw_public_key_length": 64,
            "accepted_auth_public_key_fingerprint": accepted_public_fp,
            "accepted_auth_public_key_length": 64,
        }, sort_keys=True) + "\n")
        mac_handle.flush()
        for event in (
            {
                "event": "airshield.identity.private_key.set_raw",
                "rawPrivateKey": {"length": 32, "sha256PrefixHex": private_fp},
            },
            {
                "event": "airshield.identity.private_key.recover_public_key",
                "publicKey": {"length": 64, "sha256PrefixHex": public_fp},
            },
            {
                "event": "airshield.acceptAuthentication",
                "publicKey": {"length": 64, "sha256PrefixHex": accepted_public_fp},
            },
        ):
            trace_handle.write(json.dumps(event, sort_keys=True) + "\n")
        trace_handle.flush()
        parity_checks = identity_parity_checks(
            Path(identity_handle.name),
            Path(probe_handle.name),
            Path(mac_handle.name),
            Path(trace_handle.name),
        )
    if not all(check.ok for check in parity_checks):
        detail = "; ".join(f"{check.label}: {check.detail}" for check in parity_checks if not check.ok)
        raise SystemExit(f"self-test: expected identity parity checks to pass ({detail})")
    missing_parity_checks = identity_parity_checks(None, None, None, None)
    if all(check.ok for check in missing_parity_checks):
        raise SystemExit("self-test: expected missing identity parity inputs to fail")
    transport_summary = {
        "target_band_name": "Meta Band 000J",
        "connection": {
            "event": "ble.reconnect_skipped",
            "name": "Meta Band 000J",
            "skip_reason": "repeated_connect_timeouts",
            "consecutive_timeouts": 3,
        },
        "device": {},
        "scan": {
            "active": False,
            "started_count": 2,
            "stopped_count": 1,
            "candidate_count": 24,
            "exact_band_seen_count": 1,
            "last_exact_band": {
                "name": "Meta Band 000J",
                "rssi": -37,
            },
        },
        "gatt": {"services": [], "psm_values": []},
        "l2cap": {"opened_psms": []},
        "airshield": {},
        "wis": {},
    }
    try:
        globals()["load_json"] = lambda path: transport_summary if path == synthetic_path else original_load_json(path)
        transport_checks = mac_transport_checks(synthetic_path)
    finally:
        globals()["load_json"] = original_load_json
    checks_by_label = {check.label: check for check in transport_checks}
    if transport_checks[0].ok is not True or transport_checks[-1].ok is not False:
        raise SystemExit("self-test: expected transport diagnostic to show reset-recommended state")
    if checks_by_label["Exact band advertisement observed"].ok is not True:
        raise SystemExit("self-test: expected scan exact-band evidence to pass")
    if "rssi=-37" not in checks_by_label["Exact band advertisement observed"].detail:
        raise SystemExit("self-test: expected scan exact-band detail to include RSSI")
    blocked_transport_summary = {
        "target_band_name": "Meta Band 000J",
        "connection": {"event": "ble.connected", "name": "Meta Band 000J"},
        "device": {"name": "Meta Band 000J", "peripheral_id": "abc"},
        "scan": {
            "active": False,
            "started_count": 1,
            "stopped_count": 1,
            "candidate_count": 1,
            "exact_band_seen_count": 1,
            "last_exact_band": {"name": "Meta Band 000J", "rssi": -44},
        },
        "gatt": {
            "services": ["0000FEB8-0000-1000-8000-00805F9B34FB"],
            "psm_values": [{"psm": 255}],
            "datax_tx_count": 1,
        },
        "l2cap": {
            "active": True,
            "opened_psms": [255],
            "tx_frame_count": 0,
            "tx_failed_count": 1,
            "direct_write_diagnostic_started_count": 0,
            "direct_write_diagnostic_finished_count": 0,
            "direct_write_diagnostic_timeout_count": 0,
        },
        "airshield": {"request_encryption_probe_ready_count": 1},
        "wis": {},
    }
    try:
        globals()["load_json"] = lambda path: blocked_transport_summary if path == synthetic_path else original_load_json(path)
        blocked_transport_checks = mac_transport_checks(synthetic_path)
    finally:
        globals()["load_json"] = original_load_json
    if blocked_transport_checks[-1].ok is not False:
        raise SystemExit("self-test: expected L2CAP blocked transport to fail transport-not-blocked check")
    if "L2CAP_TX_BLOCKED_GATT_FALLBACK_SENT" not in blocked_transport_checks[-1].detail:
        raise SystemExit("self-test: expected blocked transport detail to include state")
    blocked_no_gatt_transport_summary = {
        "target_band_name": "Meta Band 000J",
        "connection": {"event": "ble.connected", "name": "Meta Band 000J"},
        "device": {"name": "Meta Band 000J", "peripheral_id": "abc"},
        "scan": {
            "active": False,
            "started_count": 1,
            "stopped_count": 1,
            "candidate_count": 1,
            "exact_band_seen_count": 1,
            "last_exact_band": {"name": "Meta Band 000J", "rssi": -44},
        },
        "gatt": {
            "services": ["0000FEB8-0000-1000-8000-00805F9B34FB"],
            "psm_values": [{"psm": 255}],
            "datax_tx_count": 0,
        },
        "l2cap": {
            "active": True,
            "opened_psms": [255],
            "tx_frame_count": 0,
            "tx_failed_count": 1,
        },
        "airshield": {"request_encryption_probe_ready_count": 1},
        "wis": {},
    }
    try:
        globals()["load_json"] = lambda path: blocked_no_gatt_transport_summary if path == synthetic_path else original_load_json(path)
        blocked_no_gatt_transport_checks = mac_transport_checks(synthetic_path)
    finally:
        globals()["load_json"] = original_load_json
    if blocked_no_gatt_transport_checks[-1].ok is not False:
        raise SystemExit("self-test: expected no-GATT L2CAP blocked transport to fail transport-not-blocked check")
    if "L2CAP_TX_BLOCKED" not in blocked_no_gatt_transport_checks[-1].detail:
        raise SystemExit("self-test: expected no-GATT blocked transport detail to include state")
    print("self-test: OK")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit saved Android/Mac AirShield artifacts and show the strongest available evidence."
    )
    parser.add_argument("--android-trace-glob", default=DEFAULT_ANDROID_TRACE_GLOB)
    parser.add_argument("--identity-state-glob", default=DEFAULT_IDENTITY_STATE_GLOB)
    parser.add_argument("--native-probe-glob", default=DEFAULT_PRIVATE_KEY_PROBE_GLOB)
    parser.add_argument("--native-framing-probe-glob", default=DEFAULT_FRAMING_PROBE_GLOB)
    parser.add_argument("--target-preflight-glob", default=DEFAULT_TARGET_PREFLIGHT_GLOB)
    parser.add_argument("--sessions-dir", type=Path, default=DEFAULT_SESSIONS_DIR)
    parser.add_argument("--mac-session", type=Path)
    parser.add_argument("--gesture-events", type=Path, default=DEFAULT_GESTURE_EVENTS)
    parser.add_argument("--missing-limit", type=int, default=8)
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Use the newest Mac session for the Mac session/transport sections instead of ranking all saved sessions.",
    )
    parser.add_argument("--self-test", action="store_true", help="Run synthetic overall readiness checks and exit.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    missing_limit = max(1, args.missing_limit)

    android_results = collect_results(
        kind="Android trace",
        paths=glob_paths(args.android_trace_glob),
        checker=android_checks,
    )
    identity_results = collect_results(
        kind="Extracted identity state",
        paths=glob_paths(args.identity_state_glob),
        checker=identity_state_checks,
    )
    private_key_probe_results = collect_results(
        kind="Native PrivateKey probe",
        paths=glob_paths(args.native_probe_glob),
        checker=native_private_key_probe_checks,
    )
    framing_probe_results = collect_results(
        kind="Native Framing probe",
        paths=glob_paths(args.native_framing_probe_glob),
        checker=native_framing_probe_checks,
    )
    target_preflight_results = collect_results(
        kind="Native Probe Target preflight",
        paths=glob_paths(args.target_preflight_glob),
        checker=target_preflight_checks,
    )
    mac_results = collect_results(
        kind="Mac session",
        paths=session_paths(args.sessions_dir.expanduser(), args.mac_session, latest=args.latest),
        checker=lambda path: mac_checks(path, args.gesture_events.expanduser()),
    )
    mac_transport_results = collect_results(
        kind="Mac BLE transport",
        paths=session_paths(args.sessions_dir.expanduser(), args.mac_session, latest=args.latest),
        checker=mac_transport_checks,
    )
    identity_parity_results = [
        artifact_result(
            "Identity parity",
            Path("identity-parity"),
            identity_parity_checks(
                identity_results[0].path if identity_results else None,
                private_key_probe_results[0].path if private_key_probe_results else None,
                mac_results[0].path if mac_results else None,
                android_results[0].path if android_results else None,
            ),
        )
    ]

    print_group("Best Android Trace", android_results, missing_limit=missing_limit)
    print_group("Best Extracted Identity State", identity_results, missing_limit=missing_limit)
    print_group("Best Native Probe Target Preflight", target_preflight_results, missing_limit=missing_limit)
    print_group("Best Native PrivateKey Probe", private_key_probe_results, missing_limit=missing_limit)
    print_group("Best Native Framing Probe", framing_probe_results, missing_limit=missing_limit)
    print_group("Identity Parity", identity_parity_results, missing_limit=missing_limit)
    print_group("Best Mac BLE Transport", mac_transport_results, missing_limit=missing_limit)
    print_group("Best Mac Session", mac_results, missing_limit=missing_limit)

    latest = None
    try:
        latest = latest_session_jsonl(args.sessions_dir.expanduser())
    except SystemExit:
        pass
    if latest:
        print(f"Latest Mac session: {latest}")

    complete = overall_complete([
        android_results,
        identity_results,
        private_key_probe_results,
        framing_probe_results,
        identity_parity_results,
        mac_results,
    ])
    print("Overall:", "READY_FOR_PARITY_DECISION" if complete else "EVIDENCE_INCOMPLETE")
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
