#!/usr/bin/env python3
"""Checklist AirShield evidence needed for the Neural Band bridge validation."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from validate_gesture_events import (
    FORWARDED_SCHEMA,
    LIVE_BAND_ACTIONS,
    is_gesture_event,
    validate_event,
    validate_forwarded_schema,
)
from validate_decrypted_datax_shape import analyze as analyze_decrypted_datax_shape


DEFAULT_SESSIONS_DIR = Path.home() / "Library/Logs/CodexBandBridge/sessions"
DEFAULT_GESTURE_EVENTS = Path.home() / "Library/Logs/CodexBandBridge/gesture-events.jsonl"
DEFAULT_NATIVE_PROBE_GLOB = "reverse/identity-probes/airshield-private-key-probe-*.json"
DEFAULT_NATIVE_FRAMING_PROBE_GLOB = "reverse/framing-probes/airshield-framing-probe-*.json"


@dataclass(frozen=True)
class Check:
    label: str
    ok: bool
    detail: str


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                loaded = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(loaded, dict):
                yield loaded


def read_json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def latest_session_jsonl(sessions_dir: Path) -> Path:
    candidates = sorted(
        sessions_dir.glob("session-*.jsonl"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    candidates = [path for path in candidates if not path.name.endswith("-summary.json")]
    if not candidates:
        raise SystemExit(f"No session JSONL logs found in {sessions_dir}")
    return candidates[0]


def latest_repo_artifact(pattern: str, *, label: str) -> Path:
    candidates = sorted(
        repo_root().glob(pattern),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise SystemExit(f"No {label} artifacts found for {pattern}")
    return candidates[0]


def event_name(event: dict[str, Any]) -> str:
    return str(event.get("event") or event.get("type") or "unknown")


def parse_raw_varint(data: bytes, offset: int, limit: int | None = None) -> tuple[int, int]:
    if limit is None:
        limit = len(data)
    value = 0
    shift = 0
    position = offset
    while position < limit:
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, position
        shift += 7
        if shift >= 64:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


def request_encryption_payload_summary(payload: bytes) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "public_key_length": None,
        "challenge_length": None,
        "elliptic_curve": None,
        "supported_parameters": None,
        "unknown_fields": 0,
    }
    position = 0
    while position < len(payload):
        key, position = parse_raw_varint(payload, position)
        field_number = key >> 3
        wire_type = key & 0x07
        if wire_type == 0:
            value, position = parse_raw_varint(payload, position)
            if field_number == 3:
                summary["elliptic_curve"] = value
            elif field_number == 4:
                summary["supported_parameters"] = value
            else:
                summary["unknown_fields"] = int(summary["unknown_fields"]) + 1
        elif wire_type == 1:
            if position + 8 > len(payload):
                raise ValueError("truncated fixed64 field")
            position += 8
            summary["unknown_fields"] = int(summary["unknown_fields"]) + 1
        elif wire_type == 2:
            length, position = parse_raw_varint(payload, position)
            end = position + length
            if end > len(payload):
                raise ValueError("truncated length-delimited field")
            if field_number == 1:
                summary["public_key_length"] = length
            elif field_number == 2:
                summary["challenge_length"] = length
            else:
                summary["unknown_fields"] = int(summary["unknown_fields"]) + 1
            position = end
        elif wire_type == 5:
            if position + 4 > len(payload):
                raise ValueError("truncated fixed32 field")
            position += 4
            summary["unknown_fields"] = int(summary["unknown_fields"]) + 1
        else:
            raise ValueError(f"unsupported protobuf wire type {wire_type}")
    return summary


def request_encryption_datax_validation(event: dict[str, Any]) -> tuple[bool, str]:
    hex_value = event.get("hex")
    if not isinstance(hex_value, str) or not hex_value:
        fingerprint = event.get("frame_fingerprint")
        suffix = f" frame_fp={fingerprint}" if fingerprint else ""
        return False, f"missing tx hex{suffix}"
    try:
        frame = bytes.fromhex(hex_value)
    except ValueError as error:
        return False, f"invalid tx hex: {error}"
    if len(frame) < 4:
        return False, f"frame too short len={len(frame)}"
    descriptor = int.from_bytes(frame[0:2], "big")
    body_length = descriptor & 0x3FFF
    has_extensions = (descriptor & 0x8000) != 0
    if len(frame) != body_length + 4:
        return False, f"length mismatch frame={len(frame)} body={body_length}"
    if not has_extensions:
        return False, "frame has no DataX extensions"
    base_id = int.from_bytes(frame[2:4], "big")
    position = 4
    extensions: list[dict[str, int | bool]] = []
    while True:
        if position + 4 > len(frame):
            return False, "truncated DataX extension"
        word = frame[position:position + 4]
        position += 4
        has_continuation = (word[0] & 0x80) != 0
        extensions.append({
            "type": word[0] & 0x7F,
            "has_continuation": has_continuation,
            "auxiliary": word[1],
            "value": int.from_bytes(word[2:4], "big"),
        })
        if not has_continuation:
            break
    payload_end = 4 + body_length
    payload = frame[position:payload_end]
    service_id = next(
        (item["value"] for item in extensions if item["type"] == 1),
        None,
    )
    typed_buffer_type = next(
        (item["value"] for item in extensions if item["type"] == 2),
        None,
    )
    route_detail = (
        f"base={base_id} service={service_id} type={typed_buffer_type} "
        f"payload_len={len(payload)}"
    )
    if service_id != 5 or typed_buffer_type != 1:
        return False, f"wrong DataX route {route_detail}"
    try:
        payload_summary = request_encryption_payload_summary(payload)
    except ValueError as error:
        return False, f"RequestEncryption protobuf parse failed: {error}; {route_detail}"
    public_key_length = payload_summary["public_key_length"]
    challenge_length = payload_summary["challenge_length"]
    elliptic_curve = payload_summary["elliptic_curve"]
    supported_parameters = payload_summary["supported_parameters"]
    hkdf_enabled = isinstance(supported_parameters, int) and (supported_parameters & 1) == 1
    field_detail = (
        f"{route_detail} public_key={public_key_length} "
        f"challenge={challenge_length} curve={elliptic_curve} "
        f"params={supported_parameters} unknown={payload_summary['unknown_fields']}"
    )
    if public_key_length != 64:
        return False, f"unexpected public key length; {field_detail}"
    if challenge_length != 16:
        return False, f"unexpected challenge length; {field_detail}"
    if elliptic_curve != 0:
        return False, f"unexpected elliptic curve; {field_detail}"
    if not hkdf_enabled:
        return False, f"HKDF supported-parameters bit not set; {field_detail}"
    return True, field_detail


def request_encryption_tx_summary_validation(event: dict[str, Any]) -> tuple[bool, str]:
    if event_name(event) != "datax.tx_frame":
        return False, "not a decoded TX frame"
    if event.get("transport") != "l2cap":
        return False, f"wrong transport={event.get('transport', '-')}"
    if event.get("label") != "airshield.request_encryption.probe":
        return False, f"wrong label={event.get('label', '-')}"
    request = event.get("airshield_request_encryption")
    if not isinstance(request, dict):
        return False, "missing decoded RequestEncryption summary"
    service_id = event.get("channel_alias")
    typed_buffer_type = event.get("typed_buffer_type")
    public_key_length = request.get("public_key_length")
    challenge_length = request.get("challenge_length")
    elliptic_curve = request.get("elliptic_curve")
    supported_parameters = request.get("supported_parameters")
    uses_hkdf = request.get("uses_hkdf")
    detail = (
        f"base={event.get('base_id', '-')} service={service_id} "
        f"type={typed_buffer_type} payload_len={event.get('payload_length', '-')} "
        f"public_key={public_key_length} challenge={challenge_length} "
        f"curve={elliptic_curve} params={supported_parameters}"
    )
    if service_id != 5 or typed_buffer_type != 1:
        return False, f"wrong DataX route {detail}"
    if public_key_length != 64:
        return False, f"unexpected public key length; {detail}"
    if challenge_length != 16:
        return False, f"unexpected challenge length; {detail}"
    if elliptic_curve != 0:
        return False, f"unexpected elliptic curve; {detail}"
    if uses_hkdf is not True:
        return False, f"HKDF supported-parameters bit not set; {detail}"
    return True, detail


def summary_fingerprint(summary: Any) -> str | None:
    if not isinstance(summary, dict):
        return None
    value = summary.get("sha256PrefixHex") or summary.get("sha256_prefix")
    return str(value) if value else None


def summary_length(summary: Any) -> int | None:
    if not isinstance(summary, dict):
        return None
    value = summary.get("length") or summary.get("decoded_length")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def count_events(events: list[dict[str, Any]]) -> Counter[str]:
    return Counter(event_name(event) for event in events)


def nested_candidates(events: list[dict[str, Any]], candidate_key: str) -> int:
    count = 0
    for event in events:
        if event_name(event) not in ("airshield.enable_inputs_ready", "airshield.link_setup.rx"):
            continue
        for material in event.get("normal_material_candidates") or []:
            if isinstance(material, dict) and material.get(candidate_key):
                count += 1
        top_level_key = f"normal_material_{candidate_key}"
        if event.get(top_level_key):
            count += 1
    return count


def mac_identity_candidate_count(events: list[dict[str, Any]]) -> int:
    count = 0
    for event in events:
        name = event_name(event)
        if name not in ("airshield.identity.imported", "airshield.identity.loaded", "airshield.probe_state_ready"):
            continue
        identity = event.get("identity") if name == "airshield.probe_state_ready" else event
        if not isinstance(identity, dict):
            continue
        if identity.get("public_key_fingerprint") and identity.get("public_key_fingerprint") != "nil":
            count += 1
        if identity.get("accepted_auth_public_key_fingerprint") and identity.get("accepted_auth_public_key_fingerprint") != "nil":
            count += 1
        for candidate in identity.get("public_key_candidates") or []:
            if isinstance(candidate, dict) and candidate.get("public_key_fingerprint"):
                count += 1
            if isinstance(candidate, dict) and candidate.get("accepted_auth_public_key_fingerprint"):
                count += 1
    return count


def mac_native_enable_trust_candidate_count(events: list[dict[str, Any]]) -> int:
    count = 0
    for event in events:
        if event_name(event) != "airshield.identity.enable_trust_candidates_prepared":
            continue
        for candidate in event.get("candidates") or []:
            if not isinstance(candidate, dict):
                continue
            if candidate.get("signature_format") != "security_p256_ecdsa_raw64_digest_challenge_hash_native_format":
                continue
            if candidate.get("payload_fingerprint") and candidate.get("payload_length"):
                count += 1
    return count


def mac_native_enable_trust_channel_ids(events: list[dict[str, Any]]) -> set[int]:
    channel_ids: set[int] = set()
    for event in events:
        if event_name(event) != "airshield.identity.enable_trust_candidates_prepared":
            continue
        for candidate in event.get("candidates") or []:
            if not isinstance(candidate, dict):
                continue
            if candidate.get("signature_format") != "security_p256_ecdsa_raw64_digest_challenge_hash_native_format":
                continue
            if not candidate.get("payload_fingerprint") or not candidate.get("frame_fingerprint"):
                continue
            try:
                channel_ids.add(int(candidate.get("local_channel_id")))
            except (TypeError, ValueError):
                continue
    return channel_ids


def mac_kdf_input_fingerprint_names(events: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for event in events:
        if event_name(event) not in ("airshield.enable_inputs_ready", "airshield.link_setup.rx"):
            continue
        if event.get("local_challenge_fingerprint"):
            names.add("challenge")
        if event.get("seed_fingerprint"):
            names.add("seed")
        if event.get("peer_public_key_fingerprint"):
            names.add("remote_public_key")
        if event.get("iv_fingerprint"):
            names.add("initialization_vector")
    return names


def android_accept_auth_public_key_count(events: list[dict[str, Any]]) -> int:
    count = 0
    for event in events:
        name = event_name(event)
        if name == "airshield.auth.accept_key_candidate":
            public_key = event.get("originalPublicKey")
            if isinstance(public_key, dict) and public_key.get("sha256PrefixHex"):
                count += 1
        elif name == "airshield.acceptAuthentication":
            public_key = event.get("publicKey")
            if (
                (isinstance(public_key, dict) and public_key.get("sha256PrefixHex"))
                or event.get("pubKeyFingerprint")
            ):
                count += 1
    return count


def android_preamble_challenge_summary_count(events: list[dict[str, Any]]) -> int:
    count = 0
    for event in events:
        name = event_name(event)
        if name == "airshield.auth.delegate.register_services":
            for key in ("txChallenge", "rxChallenge"):
                summary = event.get(key)
                if isinstance(summary, dict) and summary.get("sha256PrefixHex"):
                    count += 1
        elif name in (
            "airshield.preamble.getTxChallenge",
            "airshield.preamble.getRxChallenge",
            "airshield.cipher_builder.build_tx_challenge",
            "airshield.cipher_builder.build_rx_challenge",
            "airshield.cipher_builder.build_tx_challenge_native",
            "airshield.cipher_builder.build_rx_challenge_native",
        ):
            summary = event.get("challenge")
            if isinstance(summary, dict) and summary.get("sha256PrefixHex"):
                count += 1
    return count


def android_cipher_builder_input_names(events: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for event in events:
        name = event_name(event)
        if name == "airshield.cipher_builder.set_challenge":
            summary = event.get("challenge")
            if isinstance(summary, dict) and summary.get("sha256PrefixHex"):
                names.add("challenge")
        elif name == "airshield.cipher_builder.set_seed":
            summary = event.get("seed")
            if isinstance(summary, dict) and summary.get("sha256PrefixHex"):
                names.add("seed")
        elif name == "airshield.cipher_builder.set_remote_public_key":
            summary = event.get("publicKey")
            if isinstance(summary, dict) and summary.get("sha256PrefixHex"):
                names.add("remote_public_key")
        elif name == "airshield.cipher_builder.set_initialization_vector":
            summary = event.get("initializationVector")
            if isinstance(summary, dict) and summary.get("sha256PrefixHex"):
                names.add("initialization_vector")
    return names


def android_checks(path: Path) -> list[Check]:
    events = list(read_jsonl(path))
    counts = count_events(events)
    method_calls = sum(1 for event in events if event_name(event) == "native.airshield.method.enter")
    pack_count = counts["airshield.framing.pack"]
    unpack_count = counts["airshield.framing.unpack"]
    accepted_public_keys = android_accept_auth_public_key_count(events)
    preamble_challenge_summaries = android_preamble_challenge_summary_count(events)
    builder_inputs = android_cipher_builder_input_names(events)
    return [
        Check("Android trace readable", bool(events), f"{len(events)} JSON events"),
        Check("AirShield start observed", counts["airshield.start"] > 0, f"{counts['airshield.start']} events"),
        Check("Preamble ready observed", counts["airshield.preambleReady"] > 0, f"{counts['airshield.preambleReady']} events"),
        Check("Auth delegate observed", counts["airshield.auth.delegate.start"] > 0, f"{counts['airshield.auth.delegate.start']} events"),
        Check("Preamble challenge fingerprints observed", preamble_challenge_summaries >= 2, f"{preamble_challenge_summaries} tx/rx summaries"),
        Check("CipherBuilder input fingerprints observed", {"challenge", "seed", "remote_public_key", "initialization_vector"}.issubset(builder_inputs), ", ".join(sorted(builder_inputs)) or "none"),
        Check("Native shared-hash derive observed", counts["airshield.identity.private_key.derive"] > 0, f"{counts['airshield.identity.private_key.derive']} events"),
        Check("Native state setup input snapshot", counts["native.airshield.state_setup_inputs"] > 0, f"{counts['native.airshield.state_setup_inputs']} events"),
        Check("Native framing expansion observed", counts["native.airshield.framing_expansion"] > 0, f"{counts['native.airshield.framing_expansion']} events"),
        Check("Native framing expansion output observed", counts["native.airshield.framing_expansion_output"] > 0, f"{counts['native.airshield.framing_expansion_output']} events"),
        Check("Native private-key load/serialize observed", counts["airshield.identity.private_key.set_raw"] > 0 or counts["airshield.identity.private_key.serialize"] > 0, f"set_raw={counts['airshield.identity.private_key.set_raw']} serialize={counts['airshield.identity.private_key.serialize']}"),
        Check("Accepted auth public key observed", accepted_public_keys > 0, f"{accepted_public_keys} fingerprinted events"),
        Check("Native identity public-key recovery observed", counts["airshield.identity.private_key.recover_public_key"] > 0, f"{counts['airshield.identity.private_key.recover_public_key']} events"),
        Check("Secure stream ready observed", counts["airshield.streamReady"] > 0, f"{counts['airshield.streamReady']} events"),
        Check("Native method calls observed", method_calls > 0, f"{method_calls} calls"),
        Check("Native framing config fingerprint", counts["native.airshield.framing_config"] > 0, f"{counts['native.airshield.framing_config']} events"),
        Check("Native cipher setup fingerprint", counts["native.airshield.cipher_context_setup"] > 0, f"{counts['native.airshield.cipher_context_setup']} events"),
        Check("Native pack/unpack frame bytes", (pack_count + unpack_count) > 0, f"pack={pack_count} unpack={unpack_count}"),
    ]


def native_private_key_probe_checks(path: Path) -> list[Check]:
    loaded = read_json(path)
    native = loaded.get("native") if isinstance(loaded.get("native"), dict) else {}
    input_summary = loaded.get("input") if isinstance(loaded.get("input"), dict) else {}
    set_raw_summary = native.get("inputRawPrivateKey") if isinstance(native.get("inputRawPrivateKey"), dict) else {}
    serialize_summary = native.get("nativeSerialize") if isinstance(native.get("nativeSerialize"), dict) else {}
    recover_summary = native.get("nativeRecoverPublicKey") if isinstance(native.get("nativeRecoverPublicKey"), dict) else {}
    accepted_summary = native.get("acceptedAuthenticationPublicKey") if isinstance(native.get("acceptedAuthenticationPublicKey"), dict) else {}
    input_fp = summary_fingerprint(input_summary)
    set_raw_fp = summary_fingerprint(set_raw_summary)
    serialize_fp = summary_fingerprint(serialize_summary)
    errors = native.get("errors") if isinstance(native.get("errors"), list) else []
    return [
        Check(
            "Native private-key probe readable",
            bool(loaded),
            f"schema={loaded.get('schema', '-')} status={loaded.get('probeStatus', '-')}",
        ),
        Check("Native PrivateKey.setRaw succeeded", bool(native.get("nativeSetRawSucceeded")), f"errors={len(errors)}"),
        Check("Probe input fingerprint present", bool(input_fp), f"len={summary_length(input_summary)} fp={input_fp or '-'}"),
        Check("Native setRaw input matches probe input", bool(input_fp and set_raw_fp and input_fp == set_raw_fp), f"input={input_fp or '-'} set_raw={set_raw_fp or '-'}"),
        Check("Native PrivateKey.serialize fingerprint present", bool(serialize_fp), f"len={summary_length(serialize_summary)} fp={serialize_fp or '-'}"),
        Check("Native serialize matches probe input", bool(input_fp and serialize_fp and input_fp == serialize_fp), f"input={input_fp or '-'} serialize={serialize_fp or '-'}"),
        Check("Native recoverPublicKey fingerprint present", bool(summary_fingerprint(recover_summary)), f"len={summary_length(recover_summary)} fp={summary_fingerprint(recover_summary) or '-'}"),
        Check("Accepted-auth public key fingerprint present", bool(summary_fingerprint(accepted_summary)), f"len={summary_length(accepted_summary)} fp={summary_fingerprint(accepted_summary) or '-'}"),
    ]


def native_framing_probe_checks(path: Path) -> list[Check]:
    loaded = read_json(path)
    native = loaded.get("native") if isinstance(loaded.get("native"), dict) else {}
    pack = native.get("pack") if isinstance(native.get("pack"), dict) else {}
    inputs = loaded.get("inputs") if isinstance(loaded.get("inputs"), dict) else {}
    secret = loaded.get("secretMaterial") if isinstance(loaded.get("secretMaterial"), dict) else {}
    outer = pack.get("outerFrame") if isinstance(pack.get("outerFrame"), dict) else {}
    cipher = pack.get("cipherPayload") if isinstance(pack.get("cipherPayload"), dict) else {}
    errors = native.get("errors") if isinstance(native.get("errors"), list) else []
    comparison = swift_framing_probe_comparison(path)
    comparison_best = comparison.get("best") if isinstance(comparison.get("best"), dict) else {}
    comparison_error = comparison.get("error") if isinstance(comparison.get("error"), str) else None
    comparison_detail = (
        f"score={comparison_best.get('score', '-')} "
        f"source={comparison_best.get('source', '-')} "
        f"matches={','.join(comparison_best.get('matches') or []) or '-'} "
        f"mismatches={','.join(comparison_best.get('mismatches') or []) or '-'}"
        if comparison_best else (comparison_error or "no comparison")
    )
    plaintext_length = summary_length(inputs.get("plaintext"))
    expected_padded_length = int_or_none(pack.get("expectedPaddedPlaintextLength"))
    expected_cipher_length = int_or_none(pack.get("expectedCipherPayloadLength"))
    actual_cipher_length = int_or_none(pack.get("actualCipherPayloadLength"))
    expected_outer_length = int_or_none(pack.get("expectedOuterFrameLength"))
    actual_outer_length = int_or_none(pack.get("actualOuterFrameLength"))
    expected_indicator = int_or_none(pack.get("expectedSizeIndicator"))
    actual_indicator = int_or_none(pack.get("actualSizeIndicator"))
    input_position = int_or_none(pack.get("inputPosition"))
    return [
        Check(
            "Native framing probe readable",
            bool(loaded),
            f"schema={loaded.get('schema', '-')} status={loaded.get('probeStatus', '-')}",
        ),
        Check("Native framing probe has synthetic inputs", bool(inputs), f"keys={len(inputs)}"),
        Check("Native framing probe has secretMaterial for Swift comparison", bool(secret), f"keys={len(secret)}"),
        Check("Native framing probe completed without errors", not errors, f"errors={len(errors)}"),
        Check("Native Framing.pack status present", bool(pack.get("status")), f"status={pack.get('status', '-')}"),
        Check(
            "Native Framing.pack consumed plaintext",
            pack.get("inputFullyConsumed") is True,
            f"position={input_position} plaintext_len={plaintext_length}",
        ),
        Check(
            "Native Framing.pack padded length recorded",
            expected_padded_length is not None and expected_padded_length == expected_cipher_length,
            f"padded={expected_padded_length} cipher={expected_cipher_length}",
        ),
        Check(
            "Native Framing.pack cipher length matches expected",
            pack.get("cipherPayloadLengthMatchesExpected") is True,
            f"expected={expected_cipher_length} actual={actual_cipher_length}",
        ),
        Check(
            "Native Framing.pack outer length matches expected",
            pack.get("outputLengthMatchesExpected") is True,
            f"expected={expected_outer_length} actual={actual_outer_length}",
        ),
        Check(
            "Native Framing.pack size indicator matches expected",
            pack.get("sizeIndicatorMatchesExpected") is True,
            f"expected={expected_indicator} actual={actual_indicator}",
        ),
        Check("Native Framing.pack validation prefix present", bool(pack.get("validationPrefixHex")), f"prefix={pack.get('validationPrefixHex', '-')}"),
        Check("Native Framing.pack outer fingerprint present", bool(summary_fingerprint(outer)), f"len={summary_length(outer)} fp={summary_fingerprint(outer) or '-'}"),
        Check("Native Framing.pack cipher fingerprint present", bool(summary_fingerprint(cipher)), f"len={summary_length(cipher)} fp={summary_fingerprint(cipher) or '-'}"),
        Check("Native framing tx/rx challenge fingerprints present", bool(summary_fingerprint(native.get("txChallenge")) and summary_fingerprint(native.get("rxChallenge"))), f"tx={summary_fingerprint(native.get('txChallenge')) or '-'} rx={summary_fingerprint(native.get('rxChallenge')) or '-'}"),
        Check("Native framing public-key fingerprints present", bool(summary_fingerprint(native.get("localPublicKey")) and summary_fingerprint(native.get("remotePublicKey"))), f"local={summary_fingerprint(native.get('localPublicKey')) or '-'} remote={summary_fingerprint(native.get('remotePublicKey')) or '-'}"),
        Check("Swift framing probe comparator ran", bool(comparison_best), comparison_detail),
        Check("Swift/native framing fingerprints fully match", comparison_best.get("full_match") is True, comparison_detail),
    ]


def swift_framing_probe_comparison(path: Path) -> dict[str, Any]:
    script = repo_root() / "tools/swift/compare_airshield_framing_probe.sh"
    try:
        proc = subprocess.run(
            [str(script), "--json", str(path)],
            cwd=repo_root(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"error": str(error)}
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip().splitlines()
        return {"error": detail[0] if detail else f"comparator exited {proc.returncode}"}
    try:
        loaded = json.loads(proc.stdout)
    except json.JSONDecodeError as error:
        return {"error": f"invalid comparator JSON: {error}"}
    return loaded if isinstance(loaded, dict) else {"error": "comparator JSON root is not an object"}


def swift_self_test_probe_json() -> str:
    script = repo_root() / "tools/swift/compare_airshield_framing_probe.sh"
    proc = subprocess.run(
        [str(script), "--self-test-probe-json"],
        cwd=repo_root(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise SystemExit(f"Swift framing self-test probe generation failed: {detail}")
    return proc.stdout


def self_test() -> None:
    with tempfile.TemporaryDirectory() as temp_root:
        root_path = Path(temp_root)
        older = root_path / "reverse/identity-probes/airshield-private-key-probe-old.json"
        newer = root_path / "reverse/identity-probes/airshield-private-key-probe-new.json"
        newer.parent.mkdir(parents=True, exist_ok=True)
        older.write_text("{}", encoding="utf-8")
        newer.write_text("{}", encoding="utf-8")
        older.touch()
        newer.touch()
        original_repo_root = globals()["repo_root"]
        try:
            globals()["repo_root"] = lambda: root_path
            selected = latest_repo_artifact(
                "reverse/identity-probes/airshield-private-key-probe-*.json",
                label="native PrivateKey probe",
            )
            if selected != newer:
                raise SystemExit("self-test: FAIL (latest native probe artifact selection)")
            try:
                latest_repo_artifact("reverse/framing-probes/missing-*.json", label="native Framing probe")
                raise SystemExit("self-test: FAIL (missing latest artifact should exit)")
            except SystemExit as error:
                if "No native Framing probe artifacts found" not in str(error):
                    raise
        finally:
            globals()["repo_root"] = original_repo_root
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=True, encoding="utf-8") as handle:
        handle.write(swift_self_test_probe_json())
        handle.flush()
        checks = native_framing_probe_checks(Path(handle.name))
    synthetic_events = [
        {
            "type": "airshield.identity.enable_trust_candidates_prepared",
            "candidates": [
                {
                    "signature_format": "security_p256_ecdsa_raw64_digest_challenge_hash_native_format",
                    "payload_fingerprint": "payload",
                    "frame_fingerprint": f"frame{channel_id}",
                    "local_channel_id": channel_id,
                }
                for channel_id in (0, 1, 2)
            ],
        }
    ]
    if mac_native_enable_trust_channel_ids(synthetic_events) != {0, 1, 2}:
        raise SystemExit("self-test: FAIL (Mac EnableTrust channel variant extraction)")
    missing = [check for check in checks if not check.ok]
    if missing:
        detail = "; ".join(f"{check.label}: {check.detail}" for check in missing)
        raise SystemExit(f"self-test: FAIL ({detail})")
    request_encryption_vector_hex = (
        "8060800081000005020000010a400102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
        "2c2d2e2f303132333435363738393a3b3c3d3e3f401210a0a1a2a3"
        "a4a5a6a7a8a9aaabacadaeaf18002001"
    )
    route_ok, route_detail = request_encryption_datax_validation({
        "type": "l2cap.tx",
        "label": "airshield.request_encryption.probe",
        "hex": request_encryption_vector_hex,
    })
    if not route_ok:
        raise SystemExit(f"self-test: FAIL (RequestEncryption route vector did not validate: {route_detail})")
    missing_hex_ok, missing_hex_detail = request_encryption_datax_validation({
        "type": "l2cap.tx",
        "label": "airshield.request_encryption.probe",
        "frame_fingerprint": "abcd",
    })
    if missing_hex_ok or "missing tx hex" not in missing_hex_detail:
        raise SystemExit("self-test: FAIL (RequestEncryption route validation should fail closed without hex)")
    wrong_route_ok, wrong_route_detail = request_encryption_datax_validation({
        "type": "l2cap.tx",
        "label": "airshield.request_encryption.probe",
        "hex": request_encryption_vector_hex.replace("02000001", "02000002", 1),
    })
    if wrong_route_ok or "wrong DataX route" not in wrong_route_detail:
        raise SystemExit("self-test: FAIL (RequestEncryption route validation should reject wrong typed-buffer)")
    summary_ok, summary_detail = request_encryption_tx_summary_validation({
        "type": "datax.tx_frame",
        "transport": "l2cap",
        "label": "airshield.request_encryption.probe",
        "base_id": 32768,
        "channel_alias": 5,
        "typed_buffer_type": 1,
        "payload_length": 88,
        "airshield_request_encryption": {
            "public_key_length": 64,
            "challenge_length": 16,
            "elliptic_curve": 0,
            "supported_parameters": 1,
            "uses_hkdf": True,
        },
    })
    if not summary_ok:
        raise SystemExit(f"self-test: FAIL (RequestEncryption TX summary did not validate: {summary_detail})")
    synthetic_gestures = [
        ("082a10e707180120032801587b6001", "tap", "thumb", 1, 3, 1),
        ("180120042802", "double_tap", "thumb", 1, 4, 2),
        ("180420062805", "swipe_up", "not_applicable", 4, 6, 5),
        ("180420072806", "swipe_down", "not_applicable", 4, 7, 6),
        ("1801200b", "swipe_in", "thumb", 1, 11, None),
        ("1801200c", "swipe_out", "thumb", 1, 12, None),
        ("180320012809", "press", "middle", 3, 1, 9),
        ("180320012803", "hold", "middle", 3, 1, 3),
        ("180320022804", "release", "middle", 3, 2, 4),
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=True, encoding="utf-8") as session_handle, tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=True, encoding="utf-8") as forwarded_handle:
        for payload_hex, action, finger, raw_finger, raw_action, derived_action in synthetic_gestures:
            session_event = {
                "type": "datax.gesture_decoded",
                "frame_source": "airshield.decrypted",
                "frame_payload_hex": payload_hex,
                "normalized_action": action,
                "action": action,
                "finger": finger,
                "raw_finger": raw_finger,
                "raw_action": raw_action,
            }
            forwarded_event = {
                "schema": FORWARDED_SCHEMA,
                "event_type": "gesture",
                "ts": "2026-06-05T12:00:00Z",
                "source": "self-test",
                "frame_base_id": 32768,
                "app_id": 2,
                "message_type": 13,
                "frame_payload_hex": payload_hex,
                "normalized_action": action,
                "action": action,
                "finger": finger,
                "raw_finger": raw_finger,
                "raw_action": raw_action,
            }
            if derived_action is not None:
                session_event["derived_action"] = derived_action
                forwarded_event["derived_action"] = derived_action
            session_handle.write(json.dumps({
                "type": "datax.frame_source",
                "source": "airshield.decrypted",
                "app_id": 2,
                "message_type": 13,
                "payload_length": len(bytes.fromhex(payload_hex)),
                "payload_fingerprint": "selftest",
            }, sort_keys=True) + "\n")
            session_handle.write(json.dumps(session_event, sort_keys=True) + "\n")
            forwarded_handle.write(json.dumps(forwarded_event, sort_keys=True) + "\n")
        session_handle.flush()
        forwarded_handle.flush()
        replay_checks = mac_checks(
            Path(session_handle.name),
            Path(forwarded_handle.name),
            expected_gesture_actions=LIVE_BAND_ACTIONS,
            require_forwarded_schema=True,
        )
        decrypted_shape = analyze_decrypted_datax_shape(Path(session_handle.name))
    replay_by_label = {check.label: check for check in replay_checks}
    route_check = replay_by_label.get("RequestEncryption DataX route validates")
    if route_check is None or route_check.ok is not False or "no L2CAP RequestEncryption TX" not in route_check.detail:
        raise SystemExit("self-test: FAIL (Mac readiness should report missing RequestEncryption route evidence)")
    required_replay_labels = [
        "Normalized gesture replay validates",
        "Decrypted inner DataX routes recognized",
        "Decrypted gesture replay validates",
        "Expected decrypted gesture actions covered",
        "Forwarded gesture schema validates",
    ]
    replay_missing = [
        replay_by_label[label]
        for label in required_replay_labels
        if not replay_by_label.get(label, Check(label, False, "missing")).ok
    ]
    if decrypted_shape["decrypted_gesture_count"] != len(synthetic_gestures):
        raise SystemExit("self-test: expected decrypted-shape validator to count synthetic decrypted gestures")
    if replay_missing:
        detail = "; ".join(f"{check.label}: {check.detail}" for check in replay_missing)
        raise SystemExit(f"self-test: FAIL ({detail})")
    print("self-test: OK")


def forwarded_gesture_count(path: Path | None) -> int:
    if path is None or not path.exists():
        return 0
    return sum(1 for event in read_jsonl(path) if event.get("action") and event.get("finger"))


def validated_gesture_replay_count(
    events: Iterable[dict[str, Any]],
    required_frame_source: str | None = None,
) -> tuple[int, int, Counter[str]]:
    validated = 0
    failures = 0
    actions: Counter[str] = Counter()
    for event in events:
        if not is_gesture_event(event):
            continue
        if required_frame_source is not None and event.get("frame_source") != required_frame_source:
            continue
        gesture, mismatches = validate_event(event)
        if gesture is not None and not mismatches:
            validated += 1
            actions[gesture.normalized_action] += 1
        else:
            failures += 1
    return validated, failures, actions


def validated_forwarded_gesture_replay_count(
    path: Path | None,
    require_forwarded_schema: bool = False,
) -> tuple[int, int, Counter[str]]:
    if path is None or not path.exists():
        return (0, 0, Counter())
    validated = 0
    failures = 0
    actions: Counter[str] = Counter()
    for event in read_jsonl(path):
        if not is_gesture_event(event):
            continue
        gesture, mismatches = validate_event(event)
        if gesture is None or mismatches:
            failures += 1
            continue
        if event.get("schema") == FORWARDED_SCHEMA:
            forwarded_mismatches = validate_forwarded_schema(event, gesture)
            if forwarded_mismatches:
                failures += 1
                continue
        elif require_forwarded_schema:
            failures += 1
            continue
        validated += 1
        actions[gesture.normalized_action] += 1
    return validated, failures, actions


def mac_checks(
    path: Path,
    gesture_events_path: Path | None = None,
    expected_gesture_actions: list[str] | None = None,
    require_forwarded_schema: bool = False,
) -> list[Check]:
    events = list(read_jsonl(path))
    counts = count_events(events)
    end_link_candidate_count = nested_candidates(events, "end_link_setup_frame_candidate")
    gesture_candidate_count = nested_candidates(events, "gesture_enable_frame_candidate")
    candidate_count = end_link_candidate_count + gesture_candidate_count
    identity_event_count = counts["airshield.identity.imported"] + counts["airshield.identity.loaded"]
    identity_candidate_count = mac_identity_candidate_count(events)
    enable_trust_candidate_events = counts["airshield.identity.enable_trust_candidates_prepared"]
    enable_trust_gate_loaded = counts["airshield.identity.enable_trust_gate_loaded"]
    enable_trust_ready = counts["airshield.identity.enable_trust.tx_ready"]
    enable_trust_sent = counts["airshield.identity.enable_trust.tx_sent"]
    end_link_ready = counts["airshield.end_link_setup.tx_ready"]
    end_link_sent = counts["airshield.end_link_setup.tx_sent"]
    gesture_ready = counts["airshield.gesture_enable.tx_ready"]
    gesture_sent = counts["airshield.gesture_enable.tx_sent"]
    stream_control_response_active = [
        event for event in events
        if event_name(event) == "wis.stream_control.response"
        and event.get("gesture_stream_active") is True
    ]
    stream_control_update_active = [
        event for event in events
        if event_name(event) == "wis.stream_control.update"
        and event.get("gesture_stream_active") is True
    ]
    stream_control_active = stream_control_response_active + stream_control_update_active
    decrypted_stream_control_active = [
        event for event in stream_control_active
        if event.get("source") == "airshield.decrypted"
    ]
    native_enable_trust_candidate_count = mac_native_enable_trust_candidate_count(events)
    native_enable_trust_channel_ids = mac_native_enable_trust_channel_ids(events)
    kdf_inputs = mac_kdf_input_fingerprint_names(events)
    gesture_frames = [
        event for event in events
        if event_name(event) == "datax.frame_source"
        and event.get("app_id") == 2
        and event.get("message_type") == 13
    ]
    decrypted_datax_frames = [
        event for event in events
        if event_name(event) == "datax.frame_source"
        and event.get("source") == "airshield.decrypted"
    ]
    decrypted_gesture_frames = [
        event for event in decrypted_datax_frames
        if event.get("app_id") == 2
        and event.get("message_type") == 13
    ]
    gesture_tx = [
        event for event in events
        if event_name(event) == "l2cap.tx"
        and event.get("label") == "airshield.gesture_enable.encrypted_candidate"
    ]
    end_link_tx = [
        event for event in events
        if event_name(event) == "l2cap.tx"
        and event.get("label") == "airshield.end_link_setup.encrypted_candidate"
    ]
    auth_tx = [
        event for event in events
        if event_name(event) == "l2cap.tx"
        and event.get("label") == "airshield.identity.enable_trust.gated_candidate"
    ]
    request_encryption_l2cap_tx = [
        event for event in events
        if event_name(event) == "l2cap.tx"
        and event.get("label") == "airshield.request_encryption.probe"
    ]
    request_encryption_gatt_fallback_tx = [
        event for event in events
        if event_name(event) == "gatt.datax.tx"
        and event.get("label") == "airshield.request_encryption.probe.gatt_fallback"
    ]
    request_encryption_tx_summaries = [
        event for event in events
        if event_name(event) == "datax.tx_frame"
        and event.get("transport") == "l2cap"
        and event.get("label") == "airshield.request_encryption.probe"
    ]
    request_encryption_route_results = [
        request_encryption_datax_validation(event)
        for event in request_encryption_l2cap_tx
    ] + [
        request_encryption_tx_summary_validation(event)
        for event in request_encryption_tx_summaries
    ]
    request_encryption_route_matches = [
        detail
        for ok, detail in request_encryption_route_results
        if ok
    ]
    request_encryption_route_failures = [
        detail
        for ok, detail in request_encryption_route_results
        if not ok
    ]
    forwarded_gestures = forwarded_gesture_count(gesture_events_path)
    session_replayed_gestures, session_replay_failures, _ = validated_gesture_replay_count(events)
    decrypted_replayed_gestures, decrypted_replay_failures, decrypted_action_counts = validated_gesture_replay_count(
        events,
        required_frame_source="airshield.decrypted",
    )
    forwarded_replayed_gestures, forwarded_replay_failures, _ = validated_forwarded_gesture_replay_count(
        gesture_events_path,
        require_forwarded_schema=require_forwarded_schema,
    )
    decrypted_shape = analyze_decrypted_datax_shape(path)
    decrypted_route_counts = decrypted_shape.get("route_counts") if isinstance(decrypted_shape.get("route_counts"), dict) else {}
    decrypted_route_detail = ", ".join(
        f"{route}:{count}" for route, count in sorted(decrypted_route_counts.items())
    ) or "none"
    replayed_gestures = session_replayed_gestures + forwarded_replayed_gestures
    replay_failures = session_replay_failures + forwarded_replay_failures
    decoded_gesture_count = len(gesture_frames) + forwarded_gestures
    checks = [
        Check("Mac session readable", bool(events), f"{len(events)} JSON events"),
        Check("Mac identity loaded/imported", identity_event_count > 0, f"{identity_event_count} events"),
        Check("Mac identity public-key candidates", identity_candidate_count > 0, f"{identity_candidate_count} candidates"),
        Check("Mac EnableTrust auth candidates prepared", enable_trust_candidate_events > 0, f"{enable_trust_candidate_events} events"),
        Check("Mac native-format EnableTrust candidate prepared", native_enable_trust_candidate_count > 0, f"{native_enable_trust_candidate_count} candidates"),
        Check(
            "Mac native-format EnableTrust channel variants",
            {0, 1, 2}.issubset(native_enable_trust_channel_ids),
            ", ".join(str(value) for value in sorted(native_enable_trust_channel_ids)) or "none",
        ),
        Check("Mac EnableTrust auth gate loaded", enable_trust_gate_loaded > 0, f"{enable_trust_gate_loaded} events"),
        Check("Mac EnableTrust auth frame ready", enable_trust_ready > 0, f"{enable_trust_ready} events"),
        Check("Mac EnableTrust auth frame sent", enable_trust_sent > 0 and bool(auth_tx), f"ready={enable_trust_ready} sent={enable_trust_sent} tx={len(auth_tx)}"),
        Check(
            "RequestEncryption probe sent over L2CAP",
            bool(request_encryption_l2cap_tx),
            (
                f"prepared={counts['airshield.probe_state_ready']} "
                f"l2cap_tx={len(request_encryption_l2cap_tx)} "
                f"gatt_fallback_tx={len(request_encryption_gatt_fallback_tx)}"
            ),
        ),
        Check(
            "RequestEncryption DataX route validates",
            bool(request_encryption_route_matches),
            (
                request_encryption_route_matches[0]
                if request_encryption_route_matches
                else (
                    f"attempts={len(request_encryption_l2cap_tx)} "
                    f"summaries={len(request_encryption_tx_summaries)} "
                    + ("; ".join(request_encryption_route_failures[:2]) if request_encryption_route_failures else "no L2CAP RequestEncryption TX")
                )
            ),
        ),
        Check("EnableEncryption decoded", counts["airshield.enable_inputs_ready"] > 0, f"{counts['airshield.enable_inputs_ready']} events"),
        Check("Swift KDF input fingerprints logged", {"challenge", "seed", "remote_public_key", "initialization_vector"}.issubset(kdf_inputs), ", ".join(sorted(kdf_inputs)) or "none"),
        Check("Swift setup candidates logged", candidate_count > 0, f"end_link={end_link_candidate_count} gesture={gesture_candidate_count}"),
        Check("Passive encrypted decrypt matched", counts["airshield.encrypted.rx_candidate_matched"] > 0, f"{counts['airshield.encrypted.rx_candidate_matched']} events"),
        Check("EndLinkSetup frame ready", end_link_ready > 0, f"{end_link_ready} events"),
        Check("EndLinkSetup frame sent", end_link_sent > 0 and bool(end_link_tx), f"ready={end_link_ready} sent={end_link_sent} tx={len(end_link_tx)}"),
        Check("Gesture-enable frame ready", gesture_ready > 0, f"{gesture_ready} events"),
        Check("Gesture-enable frame sent", gesture_sent > 0 and bool(gesture_tx), f"ready={gesture_ready} sent={gesture_sent} tx={len(gesture_tx)}"),
        Check(
            "Gesture stream active",
            bool(stream_control_active),
            f"responses={len(stream_control_response_active)} updates={len(stream_control_update_active)}",
        ),
        Check(
            "Decrypted gesture stream active",
            bool(decrypted_stream_control_active),
            f"{len(decrypted_stream_control_active)} active stream-control events from airshield.decrypted",
        ),
        Check("Decoded DataX frames", counts["datax.frame_source"] > 0, f"{counts['datax.frame_source']} decoded frame source events"),
        Check(
            "Decrypted DataX frames",
            bool(decrypted_datax_frames),
            f"{len(decrypted_datax_frames)} decrypted frame source events",
        ),
        Check(
            "Decrypted inner DataX routes recognized",
            decrypted_shape.get("decrypted_frame_count", 0) > 0
            and decrypted_shape.get("unknown_decrypted_frame_count", 0) == 0,
            (
                f"frames={decrypted_shape.get('decrypted_frame_count', 0)} "
                f"known={decrypted_shape.get('known_decrypted_frame_count', 0)} "
                f"unknown={decrypted_shape.get('unknown_decrypted_frame_count', 0)} "
                f"routes={decrypted_route_detail}"
            ),
        ),
        Check(
            "Decoded gesture frames",
            decoded_gesture_count > 0,
            f"{len(gesture_frames)} frame source events, {forwarded_gestures} forwarded events",
        ),
        Check(
            "Normalized gesture replay validates",
            replayed_gestures > 0 and replay_failures == 0,
            f"session={session_replayed_gestures} forwarded={forwarded_replayed_gestures} failures={replay_failures}",
        ),
        Check(
            "Decrypted gesture replay validates",
            decrypted_replayed_gestures > 0 and decrypted_replay_failures == 0,
            f"frames={len(decrypted_gesture_frames)} replayed={decrypted_replayed_gestures} failures={decrypted_replay_failures}",
        ),
    ]
    if expected_gesture_actions:
        expected = list(dict.fromkeys(expected_gesture_actions))
        missing = [action for action in expected if decrypted_action_counts[action] == 0]
        checks.append(Check(
            "Expected decrypted gesture actions covered",
            not missing and decrypted_replayed_gestures > 0 and decrypted_replay_failures == 0,
            "missing=" + (",".join(missing) if missing else "none")
        ))
    if require_forwarded_schema:
        checks.append(Check(
            "Forwarded gesture schema validates",
            forwarded_replayed_gestures > 0 and forwarded_replay_failures == 0,
            f"schema={FORWARDED_SCHEMA} replayed={forwarded_replayed_gestures} failures={forwarded_replay_failures}",
        ))
    return checks


def print_checks(title: str, checks: list[Check]) -> bool:
    print(title)
    all_ok = True
    for check in checks:
        all_ok = all_ok and check.ok
        marker = "OK" if check.ok else "MISSING"
        print(f"  [{marker}] {check.label}: {check.detail}")
    print()
    return all_ok


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check whether Android/Mac logs contain the evidence needed for AirShield validation."
    )
    parser.add_argument("--android-trace", type=Path, help="Android Frida JSONL capture.")
    parser.add_argument("--native-probe", type=Path, help="Native PrivateKey probe JSON from probe_airshield_private_key.py.")
    parser.add_argument("--native-framing-probe", type=Path, help="Native Framing.pack probe JSON from probe_airshield_framing.py.")
    parser.add_argument(
        "--latest-native-probes",
        action="store_true",
        help="Inspect the newest saved native PrivateKey and Framing probe artifacts from the repo.",
    )
    parser.add_argument("--native-probe-glob", default=DEFAULT_NATIVE_PROBE_GLOB)
    parser.add_argument("--native-framing-probe-glob", default=DEFAULT_NATIVE_FRAMING_PROBE_GLOB)
    parser.add_argument("--mac-session", type=Path, help="Mac bridge session JSONL log.")
    parser.add_argument(
        "--gesture-events",
        type=Path,
        default=DEFAULT_GESTURE_EVENTS,
        help=f"Forwarded gesture JSONL log. Default: {DEFAULT_GESTURE_EVENTS}",
    )
    parser.add_argument(
        "--sessions-dir",
        type=Path,
        default=DEFAULT_SESSIONS_DIR,
        help=f"Mac session directory used when --mac-session is omitted. Default: {DEFAULT_SESSIONS_DIR}",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Inspect the latest Mac bridge session from --sessions-dir.",
    )
    parser.add_argument(
        "--expect-live-band-actions",
        action="store_true",
        help="Require the TODO live gesture set: tap, double_tap, up/down, in/out, press, hold, release.",
    )
    parser.add_argument(
        "--expect-forwarded-schema",
        action="store_true",
        help="Require forwarded gesture JSONL events to use codex_band_bridge.gesture.v1 with the EMG_IMU/GESTURE route.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run synthetic native-framing readiness checks and exit.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0

    any_input = False
    all_ok = True

    if args.android_trace:
        any_input = True
        all_ok = print_checks(f"Android trace: {args.android_trace}", android_checks(args.android_trace)) and all_ok

    native_probe = args.native_probe
    native_framing_probe = args.native_framing_probe
    if args.latest_native_probes:
        if native_probe is None:
            native_probe = latest_repo_artifact(args.native_probe_glob, label="native PrivateKey probe")
        if native_framing_probe is None:
            native_framing_probe = latest_repo_artifact(args.native_framing_probe_glob, label="native Framing probe")

    if native_probe:
        any_input = True
        all_ok = print_checks(
            f"Native PrivateKey probe: {native_probe}",
            native_private_key_probe_checks(native_probe.expanduser()),
        ) and all_ok

    if native_framing_probe:
        any_input = True
        all_ok = print_checks(
            f"Native Framing probe: {native_framing_probe}",
            native_framing_probe_checks(native_framing_probe.expanduser()),
        ) and all_ok

    mac_session = args.mac_session
    if args.latest and mac_session is None:
        mac_session = latest_session_jsonl(args.sessions_dir.expanduser())
    if mac_session is None and not args.android_trace and not native_probe and not native_framing_probe:
        mac_session = latest_session_jsonl(args.sessions_dir.expanduser())
    if mac_session:
        any_input = True
        expected_gesture_actions = LIVE_BAND_ACTIONS if args.expect_live_band_actions else None
        all_ok = print_checks(
            f"Mac session: {mac_session}",
            mac_checks(
                mac_session.expanduser(),
                args.gesture_events.expanduser(),
                expected_gesture_actions,
                require_forwarded_schema=args.expect_forwarded_schema,
            ),
        ) and all_ok

    if not any_input:
        raise SystemExit("Provide --android-trace, --mac-session, or run without args to inspect the latest Mac session.")

    print("Overall:", "READY_FOR_PARITY_DECISION" if all_ok else "EVIDENCE_INCOMPLETE")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
