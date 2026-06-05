#!/usr/bin/env python3
"""Print live AirShield validation status from CodexBandBridge session summaries."""

from __future__ import annotations

import argparse
import io
import json
import sys
import time
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_SESSIONS_DIR = Path.home() / "Library/Logs/CodexBandBridge/sessions"


def read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
    except FileNotFoundError:
        raise SystemExit(f"Summary file not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Could not parse JSON from {path}: {exc}") from None
    if not isinstance(loaded, dict):
        raise SystemExit(f"Summary JSON root is not an object: {path}")
    return loaded


def latest_summary_path(sessions_dir: Path) -> Path:
    candidates = sorted(
        sessions_dir.glob("session-*-summary.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise SystemExit(f"No session summaries found in {sessions_dir}")
    return candidates[0]


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def short_value(value: Any, missing: str = "-") -> str:
    if value is None:
        return missing
    text = str(value)
    return text if text else missing


def first_value(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value is not None:
            return value
    return None


def count_summary(summary: dict[str, Any]) -> tuple[int, int, int, int, int, int, int, int, int, int, int, int, int, int, int]:
    airshield = as_dict(summary.get("airshield"))
    return (
        as_int(airshield.get("rx_candidate_match_count")),
        as_int(airshield.get("rx_candidate_miss_count")),
        as_int(airshield.get("identity_loaded_count")),
        as_int(airshield.get("identity_imported_count")),
        as_int(airshield.get("request_encryption_probe_ready_count")),
        as_int(airshield.get("enable_trust_candidate_prepared_count")),
        as_int(airshield.get("enable_trust_candidate_unavailable_count")),
        as_int(airshield.get("enable_inputs_ready_count")),
        as_int(airshield.get("enable_trust_gate_loaded_count")),
        as_int(airshield.get("enable_trust_tx_ready_count")),
        as_int(airshield.get("enable_trust_tx_sent_count")),
        as_int(airshield.get("end_link_setup_tx_ready_count")),
        as_int(airshield.get("end_link_setup_tx_sent_count")),
        as_int(airshield.get("gesture_enable_tx_ready_count")),
        as_int(airshield.get("gesture_enable_tx_sent_count")),
    )


def wis_count_summary(summary: dict[str, Any]) -> tuple[int, int, int, int]:
    wis = as_dict(summary.get("wis"))
    return (
        as_int(wis.get("stream_control_response_count")),
        as_int(wis.get("stream_control_update_count")),
        as_int(wis.get("gesture_stream_active_count")),
        as_int(wis.get("decoded_gesture_count")),
    )


def protected_gatt_error_count(summary: dict[str, Any]) -> int:
    gatt = as_dict(summary.get("gatt"))
    return as_int(gatt.get("protected_access_error_count"))


def l2cap_is_active(l2cap: dict[str, Any]) -> bool:
    active = l2cap.get("active")
    if isinstance(active, bool):
        return active
    if active is not None:
        return str(active).lower() in {"1", "true", "yes"}
    return bool(as_list(l2cap.get("opened_psms"))) and not as_dict(l2cap.get("last_closed"))


def l2cap_direct_write_summary(summary: dict[str, Any]) -> tuple[int, int, int, int, int]:
    l2cap = as_dict(summary.get("l2cap"))
    return (
        as_int(l2cap.get("tx_failed_count")),
        as_int(l2cap.get("direct_write_diagnostic_started_count")),
        as_int(l2cap.get("direct_write_diagnostic_finished_count")),
        as_int(l2cap.get("direct_write_diagnostic_timeout_count")),
        as_int(l2cap.get("direct_write_diagnostic_blocked_count")),
    )


def gatt_datax_summary(summary: dict[str, Any]) -> tuple[int, int, int]:
    gatt = as_dict(summary.get("gatt"))
    return (
        as_int(gatt.get("datax_rx_count")),
        as_int(gatt.get("datax_tx_count")),
        as_int(gatt.get("datax_tx_failed_count")),
    )


def scan_summary(summary: dict[str, Any]) -> tuple[bool, int, int, int, int]:
    scan = as_dict(summary.get("scan"))
    return (
        bool(scan.get("active")),
        as_int(scan.get("started_count")),
        as_int(scan.get("stopped_count")),
        as_int(scan.get("candidate_count")),
        as_int(scan.get("exact_band_seen_count")),
    )


def control_summary(summary: dict[str, Any]) -> tuple[int, int, int, int, int, int]:
    control = as_dict(summary.get("control"))
    return (
        as_int(control.get("direct_write_trigger_ready_count")),
        as_int(control.get("direct_write_trigger_received_count")),
        as_int(control.get("direct_write_trigger_blocked_count")),
        as_int(control.get("rescan_trigger_ready_count")),
        as_int(control.get("rescan_trigger_received_count")),
        as_int(control.get("rescan_trigger_blocked_count")),
    )


def state_label(summary: dict[str, Any]) -> str:
    connection = as_dict(summary.get("connection"))
    if connection.get("skip_reason") == "stale_pairing":
        return "STALE_PAIRING"
    if connection.get("skip_reason") == "repeated_connect_timeouts":
        return "PAIRING_RESET_RECOMMENDED"
    if connection.get("event") in {
        "ble.connect_requested",
        "ble.reconnect_attempt",
        "ble.connect_timeout",
        "ble.reconnect_scheduled",
    }:
        l2cap = as_dict(summary.get("l2cap"))
        if not l2cap_is_active(l2cap):
            return "CONNECTING_TO_BAND"
    if protected_gatt_error_count(summary) > 0:
        l2cap = as_dict(summary.get("l2cap"))
        if not l2cap_is_active(l2cap):
            return "PAIRING_REQUIRED_FOR_PROTECTED_GATT"
    (
        matches,
        misses,
        identity_loaded,
        identity_imported,
        probe_ready,
        auth_candidates,
        _auth_candidates_unavailable,
        enable_inputs,
        auth_gate,
        auth_ready,
        auth_sent,
        end_ready,
        end_sent,
        gesture_ready,
        gesture_sent,
    ) = count_summary(summary)
    _, _, stream_active, decoded_gestures = wis_count_summary(summary)
    if decoded_gestures > 0:
        return "GESTURES_DECODED"
    if stream_active > 0:
        return "GESTURE_STREAM_ACTIVE"
    l2cap = as_dict(summary.get("l2cap"))
    if as_list(l2cap.get("opened_psms")) and not l2cap_is_active(l2cap):
        return "L2CAP_CLOSED"
    if gesture_sent > 0:
        return "GESTURE_ENABLE_SENT"
    if gesture_ready > 0:
        return "READY_TO_SEND_GESTURE_ENABLE"
    if end_sent > 0:
        return "END_LINK_SETUP_SENT"
    if end_ready > 0:
        return "READY_TO_SEND_END_LINK_SETUP"
    if auth_sent > 0:
        return "ENABLE_TRUST_SENT"
    if auth_ready > 0:
        return "READY_TO_SEND_ENABLE_TRUST"
    if auth_gate > 0:
        return "AUTH_GATE_LOADED"
    if matches > 0:
        return "AIRSHIELD_RX_VALIDATED"
    if misses > 0:
        return "CANDIDATE_MISSES_ONLY"
    if enable_inputs > 0:
        return "ENABLE_INPUTS_READY"
    if auth_candidates > 0:
        return "AUTH_CANDIDATES_STAGED"
    if probe_ready > 0:
        gatt = as_dict(summary.get("gatt"))
        l2cap_tx_failed, *_ = l2cap_direct_write_summary(summary)
        l2cap_tx_count = as_int(l2cap.get("tx_frame_count"))
        gatt_tx_count = as_int(gatt.get("datax_tx_count"))
        if l2cap_tx_count == 0 and l2cap_tx_failed > 0 and gatt_tx_count > 0:
            return "L2CAP_TX_BLOCKED_GATT_FALLBACK_SENT"
        if l2cap_tx_count == 0 and l2cap_tx_failed > 0:
            return "L2CAP_TX_BLOCKED"
        return "REQUEST_ENCRYPTION_SENT"
    if identity_loaded + identity_imported > 0:
        return "IDENTITY_READY"
    scan_active, *_ = scan_summary(summary)
    if scan_active:
        return "SCANNING_FOR_BAND"
    return "WAITING_FOR_AIRSHIELD_VALIDATION"


def next_action(summary: dict[str, Any]) -> str:
    state = state_label(summary)
    l2cap = as_dict(summary.get("l2cap"))
    actions = {
        "STALE_PAIRING": "Forget the band in macOS Bluetooth settings, put it back in pairing mode, then scan again.",
        "PAIRING_RESET_RECOMMENDED": "Reset/forget the band pairing in macOS Bluetooth settings, put it back in pairing mode, then scan again.",
        "PAIRING_REQUIRED_FOR_PROTECTED_GATT": "Put the band in pairing mode, accept the macOS Bluetooth pairing prompt, then rediscover services.",
        "CONNECTING_TO_BAND": "Wait for CoreBluetooth to connect. If this repeats, reset macOS pairing for the band and scan again.",
        "SCANNING_FOR_BAND": "Put the band in pairing mode and wait for the exact Meta Band advertisement, or run request_rescan.py after resetting pairing.",
        "L2CAP_CLOSED": "Reopen the detected L2CAP PSM, or reconnect the band if the open button does not recover the stream.",
        "GESTURES_DECODED": "Run gesture replay/action coverage validation and exercise any missing mapped gestures.",
        "GESTURE_STREAM_ACTIVE": "Perform mapped gestures and watch for decoded gesture events.",
        "GESTURE_ENABLE_SENT": "Wait for WIS stream-control active evidence or decoded gesture frames.",
        "READY_TO_SEND_GESTURE_ENABLE": "Press Enable Gestures in the Mac bridge.",
        "END_LINK_SETUP_SENT": "Wait for the gesture-enable candidate to become ready.",
        "READY_TO_SEND_END_LINK_SETUP": "Press End Setup in the Mac bridge.",
        "ENABLE_TRUST_SENT": "Wait for EnableEncryption and passive encrypted-frame validation.",
        "READY_TO_SEND_ENABLE_TRUST": "Press Send Auth in the Mac bridge.",
        "AUTH_GATE_LOADED": "Send or repeat the RequestEncryption probe until the gated candidate is staged and Send Auth becomes enabled.",
        "AIRSHIELD_RX_VALIDATED": "Press End Setup once the matching encrypted EndLinkSetup candidate is enabled.",
        "CANDIDATE_MISSES_ONLY": "Do not send encrypted candidates yet; compare native/Mac framing evidence and capture more encrypted RX data.",
        "ENABLE_INPUTS_READY": "Wait for an encrypted RX frame to validate against the staged candidates before sending End Setup.",
        "AUTH_CANDIDATES_STAGED": "Run the auth-flow comparator with Android evidence, write/load an eligible gate, then wait for Send Auth to enable.",
        "L2CAP_TX_BLOCKED": "L2CAP has not accepted a write. Reconnect the band or use a host path that can write to the LE L2CAP socket.",
        "L2CAP_TX_BLOCKED_GATT_FALLBACK_SENT": "L2CAP has not accepted a write. Treat the GATT fallback as diagnostic only; use a working L2CAP host or native Android trace for handshake progress.",
        "REQUEST_ENCRYPTION_SENT": "Wait for EnableEncryption or auth-delegate traffic from the band.",
        "IDENTITY_READY": "Open the band L2CAP channel and press Send Probe.",
    }
    if state == "WAITING_FOR_AIRSHIELD_VALIDATION":
        if l2cap_is_active(l2cap):
            return "Press Send Probe or enable Attempt DataX handshake for the open L2CAP channel."
        return "Connect the band and open its DataX L2CAP PSM before sending a probe."
    return actions.get(state, "Continue collecting session evidence.")


def format_psms(l2cap: dict[str, Any]) -> str:
    psms = as_list(l2cap.get("opened_psms"))
    return ", ".join(str(psm) for psm in psms) if psms else "-"


def field_line(label: str, value: Any) -> str:
    return f"{label}: {short_value(value)}"


def format_l2cap_closed(l2cap: dict[str, Any]) -> list[str]:
    last = as_dict(l2cap.get("last_closed"))
    if not last:
        return ["Last L2CAP close: -"]
    return [
        "Last L2CAP close:",
        f"  reason: {short_value(last.get('reason'))}",
        f"  event: {short_value(last.get('event'))}",
    ]


def format_match(match: dict[str, Any]) -> list[str]:
    if not match:
        return ["Last match: -"]
    return [
        "Last match:",
        f"  source: {short_value(first_value(match, 'shared_material_source', 'material_source', 'source'))}",
        f"  counter: {short_value(first_value(match, 'frame_counter'))} (+{short_value(first_value(match, 'counter_search_offset'), '0')})",
        f"  plaintext length: {short_value(first_value(match, 'plaintext_length', 'plaintext_len'))}",
        f"  decoded frames: {short_value(match.get('decoded_frame_count'))}",
        f"  validation prefix: {short_value(first_value(match, 'validation_prefix_hex', 'validation_prefix'))}",
        f"  plaintext fp: {short_value(match.get('plaintext_fingerprint'))}",
        f"  cipher fp: {short_value(first_value(match, 'cipher_payload_fingerprint', 'cipher_fingerprint'))}",
    ]


def format_miss(miss: dict[str, Any]) -> list[str]:
    if not miss:
        return ["Last miss: -"]
    return [
        "Last miss:",
        f"  outer length: {short_value(first_value(miss, 'outer_frame_length', 'outer_length', 'length'))}",
        f"  outer fp: {short_value(first_value(miss, 'outer_frame_fingerprint', 'outer_fingerprint'))}",
        f"  candidate count: {short_value(miss.get('candidate_count'))}",
    ]


def format_l2cap_diagnostic(l2cap: dict[str, Any]) -> list[str]:
    last = as_dict(l2cap.get("last_direct_write_diagnostic"))
    if not last:
        return ["Last L2CAP Direct Write diagnostic: -"]
    return [
        "Last L2CAP Direct Write diagnostic:",
        f"  event: {short_value(last.get('event'))}",
        f"  label: {short_value(last.get('label'))}",
        f"  byte count: {short_value(first_value(last, 'byte_count', 'bytes_requested', 'attempted_byte_count'))}",
        f"  written: {short_value(first_value(last, 'bytes_written', 'written'))}",
        f"  frame fp: {short_value(last.get('frame_fingerprint'))}",
        f"  stream: {short_value(last.get('stream_status_description'))}",
        f"  has space: {short_value(last.get('has_space_available'))}",
        f"  error: {short_value(first_value(last, 'stream_error', 'error'))}",
        f"  reason: {short_value(last.get('reason'))}",
        f"  action: {short_value(last.get('action'))}",
    ]


def format_l2cap_tx_failed(l2cap: dict[str, Any]) -> list[str]:
    last = as_dict(l2cap.get("last_tx_failed"))
    if not last:
        return ["Last L2CAP TX failure: -"]
    return [
        "Last L2CAP TX failure:",
        f"  label: {short_value(last.get('label'))}",
        f"  reason: {short_value(last.get('reason'))}",
        f"  requested: {short_value(last.get('bytes_requested'))}",
        f"  written: {short_value(last.get('bytes_written'))}",
        f"  frame fp: {short_value(last.get('frame_fingerprint'))}",
        f"  stream: {short_value(last.get('stream_status_description'))}",
        f"  error: {short_value(last.get('error'))}",
    ]


def format_gatt_datax(gatt: dict[str, Any]) -> list[str]:
    last_tx = as_dict(gatt.get("last_datax_tx"))
    last_failure = as_dict(gatt.get("last_datax_tx_failed"))
    if not last_tx and not last_failure:
        return ["Last GATT DataX TX: -"]
    lines = ["Last GATT DataX TX:"]
    if last_tx:
        lines.extend([
            f"  sent label: {short_value(last_tx.get('label'))}",
            f"  sent chunk: {short_value(last_tx.get('chunk_index'))}/{short_value(last_tx.get('chunk_count'))}",
            f"  sent bytes: {short_value(last_tx.get('byte_count'))}",
            f"  characteristic: {short_value(last_tx.get('characteristic_uuid'))}",
        ])
    if last_failure:
        lines.extend([
            f"  failed label: {short_value(last_failure.get('label'))}",
            f"  failed reason: {short_value(last_failure.get('reason'))}",
            f"  failed characteristic: {short_value(last_failure.get('characteristic_uuid'))}",
        ])
    return lines


def format_direct_write_trigger(control: dict[str, Any]) -> list[str]:
    ready = as_dict(control.get("last_direct_write_trigger_ready"))
    received = as_dict(control.get("last_direct_write_trigger_received"))
    blocked = as_dict(control.get("last_direct_write_trigger_blocked"))
    if not ready and not received and not blocked:
        return ["Last Direct Write trigger: -"]
    lines = ["Last Direct Write trigger:"]
    if ready:
        lines.append(f"  path: {short_value(ready.get('path'))}")
    if received:
        lines.extend([
            f"  received path: {short_value(received.get('path'))}",
            f"  payload: {short_value(received.get('payload_prefix'))}",
        ])
    if blocked:
        lines.extend([
            f"  blocked reason: {short_value(blocked.get('reason'))}",
            f"  blocked error: {short_value(blocked.get('error'))}",
        ])
    return lines


def format_scan(scan: dict[str, Any]) -> list[str]:
    if not scan:
        return ["Last scan: -"]
    last_started = as_dict(scan.get("last_started"))
    last_stopped = as_dict(scan.get("last_stopped"))
    last_exact = as_dict(scan.get("last_exact_band"))
    last_candidate = as_dict(scan.get("last_candidate"))
    lines = [
        "Last scan:",
        f"  active: {short_value(scan.get('active'))}",
        f"  started/stopped: {as_int(scan.get('started_count'))}/{as_int(scan.get('stopped_count'))}",
        f"  candidates/exact: {as_int(scan.get('candidate_count'))}/{as_int(scan.get('exact_band_seen_count'))}",
    ]
    if last_started:
        lines.append(f"  started target: {short_value(last_started.get('exact_target'))}")
    if last_stopped:
        lines.append(f"  stopped event: {short_value(last_stopped.get('event'))}")
    if last_exact:
        lines.append(f"  last exact: {short_value(last_exact.get('name'))} rssi={short_value(last_exact.get('rssi'))}")
    elif last_candidate:
        lines.append(f"  last candidate: {short_value(last_candidate.get('name'))} rssi={short_value(last_candidate.get('rssi'))}")
    return lines


def format_rescan_trigger(control: dict[str, Any]) -> list[str]:
    ready = as_dict(control.get("last_rescan_trigger_ready"))
    received = as_dict(control.get("last_rescan_trigger_received"))
    blocked = as_dict(control.get("last_rescan_trigger_blocked"))
    if not ready and not received and not blocked:
        return ["Last Rescan trigger: -"]
    lines = ["Last Rescan trigger:"]
    if ready:
        lines.append(f"  path: {short_value(ready.get('path'))}")
    if received:
        lines.extend([
            f"  received path: {short_value(received.get('path'))}",
            f"  payload: {short_value(received.get('payload_prefix'))}",
        ])
    if blocked:
        lines.extend([
            f"  blocked reason: {short_value(blocked.get('reason'))}",
            f"  blocked error/state: {short_value(first_value(blocked, 'error', 'state'))}",
        ])
    return lines


def format_enable_inputs(inputs: dict[str, Any]) -> list[str]:
    if not inputs:
        return ["Last EnableEncryption inputs-ready: -"]
    candidates = as_list(inputs.get("normal_material_candidates"))
    primary = short_value(first_value(inputs, "normal_material_shared_source"))
    derivation = short_value(first_value(inputs, "normal_material_key_derivation_mode"))
    context = short_value(first_value(inputs, "normal_material_expansion_context_source"))
    end_candidate = as_dict(inputs.get("normal_material_end_link_setup_frame_candidate"))
    gesture_candidate = as_dict(inputs.get("normal_material_gesture_enable_frame_candidate"))
    return [
        "Last EnableEncryption inputs-ready:",
        f"  base: {short_value(inputs.get('base'))} parameters: {short_value(inputs.get('parameters'))} hkdf: {short_value(inputs.get('uses_hkdf'))}",
        f"  quirks: {short_value(inputs.get('quirks'))} phased: {short_value(inputs.get('phased_link_setup_supported'))}",
        f"  services: {short_value(inputs.get('supported_link_setup_services'))} link switch: {short_value(inputs.get('link_switch_version_supported'))}",
        f"  candidate count: {len(candidates)} primary: {primary}",
        f"  derivation: {derivation} context: {context}",
        f"  shared secret fp: {short_value(inputs.get('shared_secret_fingerprint'))}",
        f"  local challenge fp: {short_value(inputs.get('local_challenge_fingerprint'))}",
        f"  peer public key fp: {short_value(inputs.get('peer_public_key_fingerprint'))}",
        f"  seed fp: {short_value(inputs.get('seed_fingerprint'))}",
        f"  iv fp: {short_value(inputs.get('iv_fingerprint'))}",
        f"  work area fp: {short_value(inputs.get('normal_material_work_area_fingerprint'))}",
        f"  validation key fp: {short_value(inputs.get('normal_material_validation_key_fingerprint'))}",
        f"  cipher key fp: {short_value(inputs.get('normal_material_cipher_key_fingerprint'))}",
        f"  key sources: validation={short_value(inputs.get('normal_material_validation_key_source'))} cipher={short_value(inputs.get('normal_material_cipher_key_source'))}",
        f"  initial counter fp: {short_value(inputs.get('normal_material_initial_counter_block_fingerprint'))}",
        f"  EndLinkSetup candidate: counter={short_value(end_candidate.get('frame_counter'))} outer_fp={short_value(end_candidate.get('outer_frame_fingerprint'))}",
        f"  gesture-enable candidate: counter={short_value(gesture_candidate.get('frame_counter'))} outer_fp={short_value(gesture_candidate.get('outer_frame_fingerprint'))}",
    ]


def format_identity(identity: dict[str, Any], source: Any) -> list[str]:
    if not identity:
        return ["Last AirShield identity: -"]
    candidates = as_list(identity.get("public_key_candidates"))
    return [
        "Last AirShield identity:",
        f"  source: {short_value(source)} slot: {short_value(identity.get('slot'))}",
        f"  private key fp: {short_value(identity.get('private_key_fingerprint'))}",
        f"  public key fp: {short_value(identity.get('public_key_fingerprint'))}",
        f"  accepted auth public key fp: {short_value(identity.get('accepted_auth_public_key_fingerprint'))}",
        f"  public key candidates: {len(candidates)}",
    ]


def format_probe(probe: dict[str, Any]) -> list[str]:
    if not probe:
        return ["Last RequestEncryption probe: -"]
    identity = as_dict(probe.get("identity"))
    lines = [
        "Last RequestEncryption probe:",
        f"  public key length: {short_value(probe.get('public_key_length'))}",
        f"  challenge length: {short_value(probe.get('challenge_length'))}",
        f"  identity loaded: {short_value(probe.get('identity_loaded'))}",
    ]
    if identity:
        lines.extend([
            f"  identity slot: {short_value(identity.get('slot'))}",
            f"  identity public key fp: {short_value(identity.get('public_key_fingerprint'))}",
        ])
    return lines


def format_auth_candidates(candidates: dict[str, Any], unavailable: dict[str, Any]) -> list[str]:
    if candidates:
        return [
            "Last EnableTrust candidates:",
            f"  slot: {short_value(candidates.get('slot'))}",
            f"  candidate count: {short_value(candidates.get('candidate_count'))}",
            f"  staged frame count: {short_value(candidates.get('staged_frame_count'))}",
            f"  private key fp: {short_value(candidates.get('private_key_fingerprint'))}",
        ]
    if unavailable:
        return [
            "Last EnableTrust candidates:",
            f"  unavailable reason: {short_value(unavailable.get('reason'))}",
            f"  slot: {short_value(unavailable.get('slot'))}",
            f"  private key fp: {short_value(unavailable.get('private_key_fingerprint'))}",
        ]
    return ["Last EnableTrust candidates: -"]


def format_tx_ready(tx_ready: dict[str, Any]) -> list[str]:
    if not tx_ready:
        return ["Last gesture enable tx-ready: -"]
    return [
        "Last gesture enable tx-ready:",
        f"  source: {short_value(first_value(tx_ready, 'shared_material_source', 'material_source', 'source'))}",
        f"  frame counter: {short_value(first_value(tx_ready, 'frame_counter'))}",
        f"  outer length: {short_value(first_value(tx_ready, 'outer_frame_length', 'outer_length', 'length'))}",
        f"  validation prefix: {short_value(first_value(tx_ready, 'validation_prefix_hex', 'validation_prefix'))}",
        f"  outer fp: {short_value(first_value(tx_ready, 'outer_frame_fingerprint', 'outer_fingerprint'))}",
    ]


def format_tx_sent(label: str, tx_sent: dict[str, Any]) -> list[str]:
    if not tx_sent:
        return [f"{label}: -"]
    return [
        f"{label}:",
        f"  source: {short_value(first_value(tx_sent, 'shared_material_source', 'material_source', 'source'))}",
        f"  frame counter: {short_value(first_value(tx_sent, 'frame_counter'))}",
        f"  outer length: {short_value(first_value(tx_sent, 'outer_frame_length', 'outer_length', 'length'))}",
        f"  validation prefix: {short_value(first_value(tx_sent, 'validation_prefix_hex', 'validation_prefix'))}",
        f"  outer fp: {short_value(first_value(tx_sent, 'outer_frame_fingerprint', 'outer_fingerprint'))}",
    ]


def format_end_link_ready(tx_ready: dict[str, Any]) -> list[str]:
    if not tx_ready:
        return ["Last EndLinkSetup tx-ready: -"]
    return [
        "Last EndLinkSetup tx-ready:",
        f"  source: {short_value(first_value(tx_ready, 'shared_material_source', 'material_source', 'source'))}",
        f"  frame counter: {short_value(first_value(tx_ready, 'frame_counter'))}",
        f"  local uuid: {short_value(first_value(tx_ready, 'local_uuid'))}",
        f"  outer length: {short_value(first_value(tx_ready, 'outer_frame_length', 'outer_length', 'length'))}",
        f"  validation prefix: {short_value(first_value(tx_ready, 'validation_prefix_hex', 'validation_prefix'))}",
        f"  outer fp: {short_value(first_value(tx_ready, 'outer_frame_fingerprint', 'outer_fingerprint'))}",
    ]


def format_auth_gate(gate: dict[str, Any]) -> list[str]:
    if not gate:
        return ["Last EnableTrust gate loaded: -"]
    return [
        "Last EnableTrust gate loaded:",
        f"  candidate id: {short_value(gate.get('candidate_id'))}",
        f"  can send: {short_value(gate.get('can_send'))}",
        f"  frame fp: {short_value(gate.get('frame_fingerprint'))}",
        f"  path: {short_value(gate.get('path'))}",
    ]


def format_auth_tx(label: str, tx: dict[str, Any]) -> list[str]:
    if not tx:
        return [f"{label}: -"]
    return [
        f"{label}:",
        f"  candidate id: {short_value(tx.get('candidate_id'))}",
        f"  frame length: {short_value(tx.get('frame_length'))}",
        f"  frame fp: {short_value(tx.get('frame_fingerprint'))}",
    ]


def format_stream_active(active: dict[str, Any]) -> list[str]:
    if not active:
        return ["Last gesture stream active: -"]
    stream_states = as_list(active.get("stream_states"))
    state_text = "-"
    if stream_states:
        state_text = ", ".join(
            f"{short_value(item.get('stream_type_name'))}={short_value(item.get('stream_state_name'))}"
            for item in stream_states
            if isinstance(item, dict)
        ) or "-"
    return [
        "Last gesture stream active:",
        f"  source: {short_value(active.get('source'))}",
        f"  notification: {short_value(active.get('notification'))}",
        f"  sequence: {short_value(active.get('sequence_number'))}",
        f"  enabled gestures: {short_value(active.get('enabled_gestures'))}",
        f"  states: {state_text}",
    ]


def format_decoded_gesture(gesture: dict[str, Any]) -> list[str]:
    if not gesture:
        return ["Last decoded gesture: -"]
    return [
        "Last decoded gesture:",
        f"  action: {short_value(first_value(gesture, 'normalized_action', 'action'))}",
        f"  finger: {short_value(gesture.get('finger'))}",
        f"  frame source: {short_value(gesture.get('frame_source'))}",
        f"  sequence: {short_value(gesture.get('sequence_number'))}",
        f"  timestamp: {short_value(gesture.get('timestamp'))}",
        f"  payload hex: {short_value(gesture.get('frame_payload_hex'))}",
    ]


def selected_status(summary: dict[str, Any], path: Path) -> dict[str, Any]:
    connection = as_dict(summary.get("connection"))
    device = as_dict(summary.get("device"))
    scan = as_dict(summary.get("scan"))
    l2cap = as_dict(summary.get("l2cap"))
    airshield = as_dict(summary.get("airshield"))
    wis = as_dict(summary.get("wis"))
    gatt = as_dict(summary.get("gatt"))
    control = as_dict(summary.get("control"))
    (
        matches,
        misses,
        identity_loaded,
        identity_imported,
        probe_ready,
        auth_candidates,
        auth_candidates_unavailable,
        enable_inputs,
        auth_gate,
        auth_ready,
        auth_sent,
        end_ready,
        end_sent,
        gesture_ready,
        gesture_sent,
    ) = count_summary(summary)
    wis_responses, wis_updates, stream_active, decoded_gestures = wis_count_summary(summary)
    scan_active, scan_started, scan_stopped, scan_candidates, scan_exact = scan_summary(summary)
    (
        l2cap_tx_failed,
        l2cap_direct_started,
        l2cap_direct_finished,
        l2cap_direct_timeout,
        l2cap_direct_blocked,
    ) = l2cap_direct_write_summary(summary)
    gatt_rx, gatt_tx, gatt_tx_failed = gatt_datax_summary(summary)
    (
        trigger_ready,
        trigger_received,
        trigger_blocked,
        rescan_ready,
        rescan_received,
        rescan_blocked,
    ) = control_summary(summary)
    return {
        "summary_path": str(path),
        "session_id": summary.get("session_id"),
        "started_at": summary.get("started_at"),
        "target_band_name": summary.get("target_band_name"),
        "state": state_label(summary),
        "next_action": next_action(summary),
        "connection": connection,
        "scan": {
            "active": scan_active,
            "started_count": scan_started,
            "stopped_count": scan_stopped,
            "candidate_count": scan_candidates,
            "exact_band_seen_count": scan_exact,
            "last_started": as_dict(scan.get("last_started")),
            "last_stopped": as_dict(scan.get("last_stopped")),
            "last_candidate": as_dict(scan.get("last_candidate")),
            "last_exact_band": as_dict(scan.get("last_exact_band")),
        },
        "device": device,
        "l2cap": l2cap,
        "l2cap_diagnostics": {
            "tx_failed_count": l2cap_tx_failed,
            "direct_write_diagnostic_started_count": l2cap_direct_started,
            "direct_write_diagnostic_finished_count": l2cap_direct_finished,
            "direct_write_diagnostic_timeout_count": l2cap_direct_timeout,
            "direct_write_diagnostic_blocked_count": l2cap_direct_blocked,
            "last_direct_write_diagnostic": as_dict(l2cap.get("last_direct_write_diagnostic")),
            "last_tx_failed": as_dict(l2cap.get("last_tx_failed")),
        },
        "gatt_diagnostics": {
            "datax_rx_count": gatt_rx,
            "datax_tx_count": gatt_tx,
            "datax_tx_failed_count": gatt_tx_failed,
            "last_datax_tx": as_dict(gatt.get("last_datax_tx")),
            "last_datax_tx_failed": as_dict(gatt.get("last_datax_tx_failed")),
        },
        "control": {
            "direct_write_trigger_ready_count": trigger_ready,
            "direct_write_trigger_received_count": trigger_received,
            "direct_write_trigger_blocked_count": trigger_blocked,
            "rescan_trigger_ready_count": rescan_ready,
            "rescan_trigger_received_count": rescan_received,
            "rescan_trigger_blocked_count": rescan_blocked,
            "last_direct_write_trigger_ready": as_dict(
                control.get("last_direct_write_trigger_ready")
            ),
            "last_direct_write_trigger_received": as_dict(
                control.get("last_direct_write_trigger_received")
            ),
            "last_direct_write_trigger_blocked": as_dict(
                control.get("last_direct_write_trigger_blocked")
            ),
            "last_rescan_trigger_ready": as_dict(
                control.get("last_rescan_trigger_ready")
            ),
            "last_rescan_trigger_received": as_dict(
                control.get("last_rescan_trigger_received")
            ),
            "last_rescan_trigger_blocked": as_dict(
                control.get("last_rescan_trigger_blocked")
            ),
        },
        "airshield": {
            "state": state_label(summary),
            "rx_candidate_match_count": matches,
            "rx_candidate_miss_count": misses,
            "identity_loaded_count": identity_loaded,
            "identity_imported_count": identity_imported,
            "request_encryption_probe_ready_count": probe_ready,
            "enable_trust_candidate_prepared_count": auth_candidates,
            "enable_trust_candidate_unavailable_count": auth_candidates_unavailable,
            "enable_inputs_ready_count": enable_inputs,
            "enable_trust_gate_loaded_count": auth_gate,
            "enable_trust_tx_ready_count": auth_ready,
            "enable_trust_tx_sent_count": auth_sent,
            "end_link_setup_tx_ready_count": end_ready,
            "end_link_setup_tx_sent_count": end_sent,
            "gesture_enable_tx_ready_count": gesture_ready,
            "gesture_enable_tx_sent_count": gesture_sent,
            "last_rx_match": as_dict(airshield.get("last_rx_match")),
            "last_rx_miss": as_dict(airshield.get("last_rx_miss")),
            "last_identity_source": airshield.get("last_identity_source"),
            "last_identity": as_dict(airshield.get("last_identity")),
            "last_request_encryption_probe": as_dict(
                airshield.get("last_request_encryption_probe")
            ),
            "last_enable_trust_candidates_prepared": as_dict(
                airshield.get("last_enable_trust_candidates_prepared")
            ),
            "last_enable_trust_candidates_unavailable": as_dict(
                airshield.get("last_enable_trust_candidates_unavailable")
            ),
            "last_enable_inputs_ready": as_dict(
                airshield.get("last_enable_inputs_ready")
            ),
            "last_enable_trust_gate_loaded": as_dict(
                airshield.get("last_enable_trust_gate_loaded")
            ),
            "last_enable_trust_tx_ready": as_dict(
                airshield.get("last_enable_trust_tx_ready")
            ),
            "last_enable_trust_tx_sent": as_dict(
                airshield.get("last_enable_trust_tx_sent")
            ),
            "last_end_link_setup_tx_ready": as_dict(
                airshield.get("last_end_link_setup_tx_ready")
            ),
            "last_end_link_setup_tx_sent": as_dict(
                airshield.get("last_end_link_setup_tx_sent")
            ),
            "last_gesture_enable_tx_ready": as_dict(
                airshield.get("last_gesture_enable_tx_ready")
            ),
            "last_gesture_enable_tx_sent": as_dict(
                airshield.get("last_gesture_enable_tx_sent")
            ),
        },
        "wis": {
            "stream_control_response_count": wis_responses,
            "stream_control_update_count": wis_updates,
            "gesture_stream_active_count": stream_active,
            "decoded_gesture_count": decoded_gestures,
            "last_gesture_stream_active": as_dict(wis.get("last_gesture_stream_active")),
            "last_decoded_gesture": as_dict(wis.get("last_decoded_gesture")),
        },
    }


def print_status(summary: dict[str, Any], path: Path) -> None:
    connection = as_dict(summary.get("connection"))
    device = as_dict(summary.get("device"))
    scan = as_dict(summary.get("scan"))
    l2cap = as_dict(summary.get("l2cap"))
    airshield = as_dict(summary.get("airshield"))
    wis = as_dict(summary.get("wis"))
    gatt = as_dict(summary.get("gatt"))
    control = as_dict(summary.get("control"))
    (
        matches,
        misses,
        identity_loaded,
        identity_imported,
        probe_ready,
        auth_candidates,
        auth_candidates_unavailable,
        enable_inputs,
        auth_gate,
        auth_ready,
        auth_sent,
        end_ready,
        end_sent,
        gesture_ready,
        gesture_sent,
    ) = count_summary(summary)
    wis_responses, wis_updates, stream_active, decoded_gestures = wis_count_summary(summary)
    scan_active, scan_started, scan_stopped, scan_candidates, scan_exact = scan_summary(summary)
    (
        l2cap_tx_failed,
        l2cap_direct_started,
        l2cap_direct_finished,
        l2cap_direct_timeout,
        l2cap_direct_blocked,
    ) = l2cap_direct_write_summary(summary)
    gatt_rx, gatt_tx, gatt_tx_failed = gatt_datax_summary(summary)
    (
        trigger_ready,
        trigger_received,
        trigger_blocked,
        rescan_ready,
        rescan_received,
        rescan_blocked,
    ) = control_summary(summary)

    print(f"Summary: {path}")
    print(field_line("State", state_label(summary)))
    print(field_line("Next", next_action(summary)))
    print(field_line("Session", summary.get("session_id")))
    print(field_line("Started", summary.get("started_at")))
    print(field_line("Target", summary.get("target_band_name")))
    print(
        "Connection: "
        f"event={short_value(connection.get('event'))} "
        f"name={short_value(connection.get('name'))} "
        f"skip={short_value(connection.get('skip_reason'))} "
        f"timeouts={short_value(connection.get('consecutive_timeouts'))} "
        f"error={short_value(connection.get('error'))}"
    )
    print(
        "Scan: "
        f"active={str(scan_active).lower()} "
        f"started={scan_started} "
        f"stopped={scan_stopped} "
        f"candidates={scan_candidates} "
        f"exact={scan_exact}"
    )
    print(
        "Device: "
        f"name={short_value(device.get('name'))} "
        f"serial={short_value(device.get('serial'))} "
        f"firmware={short_value(device.get('firmware'))}"
    )
    print(
        "L2CAP: "
        f"active={str(l2cap_is_active(l2cap)).lower()} "
        f"psms={format_psms(l2cap)} "
        f"closed={as_int(l2cap.get('closed_count'))} "
        f"rx={as_int(l2cap.get('rx_frame_count'))} "
        f"tx={as_int(l2cap.get('tx_frame_count'))} "
        f"tx_failed={l2cap_tx_failed} "
        f"direct=start:{l2cap_direct_started}/finish:{l2cap_direct_finished}/timeout:{l2cap_direct_timeout}/blocked:{l2cap_direct_blocked}"
    )
    print(
        "GATT: "
        f"protected_errors={as_int(gatt.get('protected_access_error_count'))} "
        f"datax_rx={gatt_rx} "
        f"datax_tx={gatt_tx} "
        f"datax_tx_failed={gatt_tx_failed}"
    )
    print(
        "AirShield: "
        f"matches={matches} misses={misses} "
        f"identity_loaded={identity_loaded} identity_imported={identity_imported} "
        f"probe_ready={probe_ready} auth_candidates={auth_candidates} "
        f"auth_candidates_unavailable={auth_candidates_unavailable} "
        f"enable_inputs={enable_inputs} "
        f"auth_gate={auth_gate} auth_ready={auth_ready} auth_sent={auth_sent} "
        f"end_link_ready={end_ready} end_link_sent={end_sent} "
        f"gesture_ready={gesture_ready} gesture_sent={gesture_sent}"
    )
    print(
        "WIS: "
        f"stream_responses={wis_responses} stream_updates={wis_updates} "
        f"stream_active={stream_active} decoded_gestures={decoded_gestures}"
    )
    print(
        "Control: "
        f"direct_trigger_ready={trigger_ready} "
        f"direct_trigger_received={trigger_received} "
        f"direct_trigger_blocked={trigger_blocked} "
        f"rescan_trigger_ready={rescan_ready} "
        f"rescan_trigger_received={rescan_received} "
        f"rescan_trigger_blocked={rescan_blocked}"
    )
    print()
    for line in format_scan(scan):
        print(line)
    print()
    for line in format_match(as_dict(airshield.get("last_rx_match"))):
        print(line)
    print()
    for line in format_miss(as_dict(airshield.get("last_rx_miss"))):
        print(line)
    print()
    for line in format_l2cap_diagnostic(l2cap):
        print(line)
    print()
    for line in format_l2cap_closed(l2cap):
        print(line)
    print()
    for line in format_l2cap_tx_failed(l2cap):
        print(line)
    print()
    for line in format_gatt_datax(gatt):
        print(line)
    print()
    for line in format_direct_write_trigger(control):
        print(line)
    print()
    for line in format_rescan_trigger(control):
        print(line)
    print()
    for line in format_identity(
        as_dict(airshield.get("last_identity")),
        airshield.get("last_identity_source"),
    ):
        print(line)
    print()
    for line in format_probe(as_dict(airshield.get("last_request_encryption_probe"))):
        print(line)
    print()
    for line in format_auth_candidates(
        as_dict(airshield.get("last_enable_trust_candidates_prepared")),
        as_dict(airshield.get("last_enable_trust_candidates_unavailable")),
    ):
        print(line)
    print()
    for line in format_enable_inputs(as_dict(airshield.get("last_enable_inputs_ready"))):
        print(line)
    print()
    for line in format_auth_gate(as_dict(airshield.get("last_enable_trust_gate_loaded"))):
        print(line)
    print()
    for line in format_auth_tx(
        "Last EnableTrust tx-ready",
        as_dict(airshield.get("last_enable_trust_tx_ready")),
    ):
        print(line)
    print()
    for line in format_auth_tx(
        "Last EnableTrust tx-sent",
        as_dict(airshield.get("last_enable_trust_tx_sent")),
    ):
        print(line)
    print()
    for line in format_end_link_ready(as_dict(airshield.get("last_end_link_setup_tx_ready"))):
        print(line)
    print()
    for line in format_tx_sent(
        "Last EndLinkSetup tx-sent",
        as_dict(airshield.get("last_end_link_setup_tx_sent")),
    ):
        print(line)
    print()
    for line in format_tx_ready(as_dict(airshield.get("last_gesture_enable_tx_ready"))):
        print(line)
    print()
    for line in format_tx_sent(
        "Last gesture enable tx-sent",
        as_dict(airshield.get("last_gesture_enable_tx_sent")),
    ):
        print(line)
    print()
    for line in format_stream_active(as_dict(wis.get("last_gesture_stream_active"))):
        print(line)
    print()
    for line in format_decoded_gesture(as_dict(wis.get("last_decoded_gesture"))):
        print(line)


def load_selected_summary(args: argparse.Namespace) -> tuple[dict[str, Any], Path]:
    if args.summary:
        path = Path(args.summary).expanduser()
    else:
        path = latest_summary_path(Path(args.sessions_dir).expanduser())
    return read_json(path), path


def print_once(args: argparse.Namespace) -> None:
    summary, path = load_selected_summary(args)
    if args.json:
        print(json.dumps(selected_status(summary, path), indent=2, sort_keys=True))
    else:
        print_status(summary, path)


def watch(args: argparse.Namespace) -> None:
    while True:
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"--- {stamp} ---")
        print_once(args)
        sys.stdout.flush()
        time.sleep(args.watch)


def synthetic_summary(**airshield_overrides: int) -> dict[str, Any]:
    opened_psms = airshield_overrides.pop("opened_psms", 0)
    l2cap_active = airshield_overrides.pop("l2cap_active", opened_psms)
    closed_count = airshield_overrides.pop("closed_count", 0)
    l2cap_tx_count = airshield_overrides.pop("l2cap_tx_count", 0)
    l2cap_tx_failed = airshield_overrides.pop("l2cap_tx_failed", 0)
    gatt_tx_count = airshield_overrides.pop("gatt_tx_count", 0)
    stream_active = airshield_overrides.pop("stream_active", 0)
    decoded_gestures = airshield_overrides.pop("decoded_gestures", 0)
    protected_gatt_errors = airshield_overrides.pop("protected_gatt_errors", 0)
    scan_active = airshield_overrides.pop("scan_active", 0)
    scan_started = airshield_overrides.pop("scan_started", 1 if scan_active else 0)
    scan_stopped = airshield_overrides.pop("scan_stopped", 0)
    scan_candidates = airshield_overrides.pop("scan_candidates", 0)
    scan_exact = airshield_overrides.pop("scan_exact", 0)
    airshield = {
        "rx_candidate_match_count": 0,
        "rx_candidate_miss_count": 0,
        "identity_loaded_count": 0,
        "identity_imported_count": 0,
        "request_encryption_probe_ready_count": 0,
        "enable_trust_candidate_prepared_count": 0,
        "enable_trust_candidate_unavailable_count": 0,
        "enable_inputs_ready_count": 0,
        "enable_trust_gate_loaded_count": 0,
        "enable_trust_tx_ready_count": 0,
        "enable_trust_tx_sent_count": 0,
        "end_link_setup_tx_ready_count": 0,
        "end_link_setup_tx_sent_count": 0,
        "gesture_enable_tx_ready_count": 0,
        "gesture_enable_tx_sent_count": 0,
    }
    airshield.update(airshield_overrides)
    return {
        "session_id": "self-test",
        "started_at": "2026-06-05T00:00:00Z",
        "target_band_name": "Meta Band 000J",
        "scan": {
            "active": bool(scan_active),
            "started_count": scan_started,
            "stopped_count": scan_stopped,
            "candidate_count": scan_candidates,
            "exact_band_seen_count": scan_exact,
        },
        "device": {},
        "gatt": {
            "protected_access_error_count": protected_gatt_errors,
            "datax_rx_count": 0,
            "datax_tx_count": gatt_tx_count,
            "datax_tx_failed_count": 0,
        },
        "l2cap": {
            "active": bool(l2cap_active),
            "opened_psms": [255] if opened_psms else [],
            "rx_frame_count": 0,
            "tx_frame_count": l2cap_tx_count,
            "closed_count": closed_count,
            "tx_failed_count": l2cap_tx_failed,
            "direct_write_diagnostic_started_count": 0,
            "direct_write_diagnostic_finished_count": 0,
            "direct_write_diagnostic_timeout_count": 0,
            "direct_write_diagnostic_blocked_count": 0,
        },
        "airshield": airshield,
        "wis": {
            "stream_control_response_count": 0,
            "stream_control_update_count": 0,
            "gesture_stream_active_count": stream_active,
            "decoded_gesture_count": decoded_gestures,
        },
        "control": {
            "direct_write_trigger_ready_count": 0,
            "direct_write_trigger_received_count": 0,
            "direct_write_trigger_blocked_count": 0,
            "rescan_trigger_ready_count": 0,
            "rescan_trigger_received_count": 0,
            "rescan_trigger_blocked_count": 0,
        },
    }


def self_test() -> None:
    cases: list[tuple[str, dict[str, int], str, str]] = [
        (
            "scanning_for_band",
            {"scan_active": 1},
            "SCANNING_FOR_BAND",
            "pairing mode",
        ),
        (
            "waiting_no_l2cap",
            {},
            "WAITING_FOR_AIRSHIELD_VALIDATION",
            "Connect the band",
        ),
        (
            "waiting_l2cap_open",
            {"opened_psms": 1},
            "WAITING_FOR_AIRSHIELD_VALIDATION",
            "Press Send Probe",
        ),
        (
            "pairing_required_for_protected_gatt",
            {"protected_gatt_errors": 1},
            "PAIRING_REQUIRED_FOR_PROTECTED_GATT",
            "accept the macOS Bluetooth pairing prompt",
        ),
        (
            "identity_ready",
            {"identity_loaded_count": 1},
            "IDENTITY_READY",
            "press Send Probe",
        ),
        (
            "probe_sent",
            {"request_encryption_probe_ready_count": 1},
            "REQUEST_ENCRYPTION_SENT",
            "Wait for EnableEncryption",
        ),
        (
            "l2cap_blocked_gatt_fallback",
            {
                "request_encryption_probe_ready_count": 1,
                "opened_psms": 1,
                "l2cap_tx_failed": 1,
                "gatt_tx_count": 1,
            },
            "L2CAP_TX_BLOCKED_GATT_FALLBACK_SENT",
            "working L2CAP host",
        ),
        (
            "auth_candidates",
            {"enable_trust_candidate_prepared_count": 1},
            "AUTH_CANDIDATES_STAGED",
            "auth-flow comparator",
        ),
        (
            "enable_inputs",
            {"enable_inputs_ready_count": 1},
            "ENABLE_INPUTS_READY",
            "Wait for an encrypted RX frame",
        ),
        (
            "candidate_misses",
            {"rx_candidate_miss_count": 1},
            "CANDIDATE_MISSES_ONLY",
            "Do not send encrypted candidates",
        ),
        (
            "auth_gate_loaded",
            {"enable_trust_gate_loaded_count": 1},
            "AUTH_GATE_LOADED",
            "Send or repeat the RequestEncryption probe",
        ),
        (
            "auth_ready",
            {"enable_trust_tx_ready_count": 1},
            "READY_TO_SEND_ENABLE_TRUST",
            "Press Send Auth",
        ),
        (
            "auth_sent",
            {"enable_trust_tx_sent_count": 1},
            "ENABLE_TRUST_SENT",
            "Wait for EnableEncryption",
        ),
        (
            "end_ready",
            {"end_link_setup_tx_ready_count": 1},
            "READY_TO_SEND_END_LINK_SETUP",
            "Press End Setup",
        ),
        (
            "end_sent",
            {"end_link_setup_tx_sent_count": 1},
            "END_LINK_SETUP_SENT",
            "gesture-enable candidate",
        ),
        (
            "gesture_ready",
            {"gesture_enable_tx_ready_count": 1},
            "READY_TO_SEND_GESTURE_ENABLE",
            "Press Enable Gestures",
        ),
        (
            "gesture_sent",
            {"gesture_enable_tx_sent_count": 1},
            "GESTURE_ENABLE_SENT",
            "Wait for WIS",
        ),
        (
            "stream_active",
            {"stream_active": 1},
            "GESTURE_STREAM_ACTIVE",
            "Perform mapped gestures",
        ),
        (
            "gestures_decoded",
            {"decoded_gestures": 1},
            "GESTURES_DECODED",
            "Run gesture replay",
        ),
    ]
    for name, overrides, expected_state, expected_action_substring in cases:
        summary = synthetic_summary(**overrides)
        actual_state = state_label(summary)
        action = next_action(summary)
        if actual_state != expected_state:
            raise SystemExit(f"self-test {name}: expected state {expected_state}, got {actual_state}")
        if expected_action_substring not in action:
            raise SystemExit(
                f"self-test {name}: expected action containing {expected_action_substring!r}, got {action!r}"
            )
    stale_summary = synthetic_summary()
    stale_summary["connection"] = {
        "event": "ble.reconnect_skipped",
        "skip_reason": "stale_pairing",
        "error": "Peer removed pairing information",
    }
    if state_label(stale_summary) != "STALE_PAIRING":
        raise SystemExit("self-test stale_pairing: expected STALE_PAIRING")
    if "Forget the band" not in next_action(stale_summary):
        raise SystemExit("self-test stale_pairing: expected pairing reset next action")
    timeout_summary = synthetic_summary()
    timeout_summary["connection"] = {
        "event": "ble.reconnect_skipped",
        "skip_reason": "repeated_connect_timeouts",
        "consecutive_timeouts": 3,
    }
    if state_label(timeout_summary) != "PAIRING_RESET_RECOMMENDED":
        raise SystemExit("self-test repeated_connect_timeouts: expected PAIRING_RESET_RECOMMENDED")
    if "Reset/forget" not in next_action(timeout_summary):
        raise SystemExit("self-test repeated_connect_timeouts: expected reset next action")
    connecting_summary = synthetic_summary()
    connecting_summary["connection"] = {
        "event": "ble.reconnect_attempt",
        "name": "Meta Band 000J",
    }
    if state_label(connecting_summary) != "CONNECTING_TO_BAND":
        raise SystemExit("self-test connecting_to_band: expected CONNECTING_TO_BAND")
    if "CoreBluetooth" not in next_action(connecting_summary):
        raise SystemExit("self-test connecting_to_band: expected CoreBluetooth next action")
    closed_summary = synthetic_summary(opened_psms=1)
    closed_summary["l2cap"]["active"] = False
    closed_summary["l2cap"]["closed_count"] = 1
    closed_summary["l2cap"]["last_closed"] = {
        "event": "l2cap.closed",
        "reason": "stream error",
    }
    if state_label(closed_summary) != "L2CAP_CLOSED":
        raise SystemExit("self-test closed_l2cap: expected L2CAP_CLOSED")
    if "Reopen the detected L2CAP PSM" not in next_action(closed_summary):
        raise SystemExit("self-test closed_l2cap: expected reopen next action")
    rendered = io.StringIO()
    with redirect_stdout(rendered):
        print_status(synthetic_summary(protected_gatt_errors=1), Path("self-test-summary.json"))
    rendered_text = rendered.getvalue()
    if "GATT: protected_errors=1 datax_rx=0 datax_tx=0 datax_tx_failed=0" not in rendered_text:
        raise SystemExit("self-test print_status: expected protected GATT error line")
    if (
        "Control: direct_trigger_ready=0 direct_trigger_received=0 direct_trigger_blocked=0 "
        "rescan_trigger_ready=0 rescan_trigger_received=0 rescan_trigger_blocked=0"
        not in rendered_text
    ):
        raise SystemExit("self-test print_status: expected control line")
    if "Last L2CAP TX failure: -" not in rendered_text:
        raise SystemExit("self-test print_status: expected missing L2CAP TX failure line")
    trigger_summary = synthetic_summary()
    trigger_summary["control"]["direct_write_trigger_ready_count"] = 1
    trigger_summary["control"]["direct_write_trigger_received_count"] = 1
    trigger_summary["control"]["last_direct_write_trigger_ready"] = {
        "path": "/tmp/direct-write-request.json",
    }
    trigger_summary["control"]["last_direct_write_trigger_received"] = {
        "path": "/tmp/direct-write-request.json",
        "payload_prefix": "{\"action\":\"test\"}",
    }
    trigger_rendered = io.StringIO()
    with redirect_stdout(trigger_rendered):
        print_status(trigger_summary, Path("self-test-summary.json"))
    trigger_text = trigger_rendered.getvalue()
    if "direct_trigger_received=1" not in trigger_text or "received path: /tmp/direct-write-request.json" not in trigger_text:
        raise SystemExit("self-test print_status: expected Direct Write trigger details")
    rescan_summary = synthetic_summary()
    rescan_summary["control"]["rescan_trigger_ready_count"] = 1
    rescan_summary["control"]["rescan_trigger_received_count"] = 1
    rescan_summary["control"]["last_rescan_trigger_ready"] = {
        "path": "/tmp/rescan-request.json",
    }
    rescan_summary["control"]["last_rescan_trigger_received"] = {
        "path": "/tmp/rescan-request.json",
        "payload_prefix": "{\"action\":\"scan\"}",
    }
    rescan_rendered = io.StringIO()
    with redirect_stdout(rescan_rendered):
        print_status(rescan_summary, Path("self-test-summary.json"))
    rescan_text = rescan_rendered.getvalue()
    if "rescan_trigger_received=1" not in rescan_text or "received path: /tmp/rescan-request.json" not in rescan_text:
        raise SystemExit("self-test print_status: expected Rescan trigger details")
    l2cap_failure_summary = synthetic_summary()
    l2cap_failure_summary["l2cap"]["last_tx_failed"] = {
        "label": "probe",
        "reason": "stream_has_no_space",
        "bytes_requested": 100,
        "frame_fingerprint": "abcd",
        "stream_status_description": "open",
    }
    l2cap_failure_rendered = io.StringIO()
    with redirect_stdout(l2cap_failure_rendered):
        print_status(l2cap_failure_summary, Path("self-test-summary.json"))
    l2cap_failure_text = l2cap_failure_rendered.getvalue()
    if "reason: stream_has_no_space" not in l2cap_failure_text or "frame fp: abcd" not in l2cap_failure_text:
        raise SystemExit("self-test print_status: expected L2CAP failure details")
    direct_summary = synthetic_summary()
    direct_summary["l2cap"]["last_direct_write_diagnostic"] = {
        "event": "l2cap.direct_write_diagnostic_finished",
        "label": "probe.direct",
        "bytes_requested": 100,
        "bytes_written": 100,
        "frame_fingerprint": "abcd",
        "stream_error": "nil",
    }
    direct_rendered = io.StringIO()
    with redirect_stdout(direct_rendered):
        print_status(direct_summary, Path("self-test-summary.json"))
    direct_text = direct_rendered.getvalue()
    if (
        "label: probe.direct" not in direct_text
        or "written: 100" not in direct_text
        or "frame fp: abcd" not in direct_text
        or "error: nil" not in direct_text
    ):
        raise SystemExit("self-test print_status: expected Direct Write byte/fingerprint details")
    gatt_failure_summary = synthetic_summary()
    gatt_failure_summary["gatt"]["datax_tx_failed_count"] = 1
    gatt_failure_summary["gatt"]["last_datax_tx_failed"] = {
        "label": "probe",
        "reason": "no_write_characteristic",
    }
    gatt_failure_rendered = io.StringIO()
    with redirect_stdout(gatt_failure_rendered):
        print_status(gatt_failure_summary, Path("self-test-summary.json"))
    if "failed reason: no_write_characteristic" not in gatt_failure_rendered.getvalue():
        raise SystemExit("self-test print_status: expected GATT failure details")
    print("self-test: OK")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read CodexBandBridge AirShield status from session summaries."
    )
    parser.add_argument(
        "--sessions-dir",
        default=str(DEFAULT_SESSIONS_DIR),
        help=f"Session summary directory. Default: {DEFAULT_SESSIONS_DIR}",
    )
    parser.add_argument("--summary", help="Specific session summary JSON file to read.")
    parser.add_argument(
        "--watch",
        type=float,
        default=0,
        metavar="SECONDS",
        help="Poll and print status repeatedly.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a compact JSON status object instead of text.",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Compatibility alias; status uses the latest session summary when --summary is omitted.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run synthetic status/next_action coverage and exit.",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if args.watch and args.watch > 0:
        watch(args)
    else:
        print_once(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
