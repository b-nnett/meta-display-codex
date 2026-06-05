#!/usr/bin/env python3
"""Summarize the redacted Android AirShield authentication flow."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


HEX_RE = re.compile(r"^[0-9a-fA-F]+(?:\.\.\.)?$")

AUTH_TYPED_BUFFER_TYPES = {
    36: {
        4096: "ENABLE_TRUST",
        4097: "ENABLE_TRUST_EC",
        8192: "SKIP_CHALLENGE",
        8193: "SKIP_CHALLENGE_RESPONSE",
        8194: "START_CHANGE_OWNER",
        8195: "START_CHANGE_OWNER_RESPONSE",
        8196: "FINISH_CHANGE_OWNER",
        8197: "FINISH_CHANGE_OWNER_RESPONSE",
        12288: "IDENTITY_REQUEST",
        12289: "IDENTITY_RESPONSE",
        16384: "NUX_REGISTRATION_CHALLENGE",
        16385: "NUX_REGISTRATION_CHALLENGE_RESPONSE",
        16386: "NUX_INSTALL_DEVICE_IDENTITY",
        16387: "NUX_INSTALL_DEVICE_IDENTITY_RESPONSE",
        20480: "MANIFEST_KEY",
        20481: "ENABLE_EC_AUTH",
    },
    77: {
        4096: "ENABLE_TRUST",
        8192: "REGISTER_KEY",
        8193: "KEY_ACCEPTED",
    },
}

AUTH_SERVICE_NAMES = {
    36: "identity",
    77: "prototype_identity",
}

CHALLENGE_RETURN_EVENTS = {
    "airshield.preamble.getTxChallenge": "txChallenge",
    "airshield.preamble.getRxChallenge": "rxChallenge",
    "airshield.cipher_builder.build_tx_challenge": "txChallenge",
    "airshield.cipher_builder.build_rx_challenge": "rxChallenge",
    "airshield.cipher_builder.build_tx_challenge_native": "txChallenge",
    "airshield.cipher_builder.build_rx_challenge_native": "rxChallenge",
}

BUILDER_INPUT_EVENTS = {
    "airshield.cipher_builder.set_challenge": ("challenge", "challenge"),
    "airshield.cipher_builder.set_seed": ("seed", "seed"),
    "airshield.cipher_builder.set_remote_public_key": ("remote_public_key", "publicKey"),
    "airshield.cipher_builder.set_initialization_vector": ("initialization_vector", "initializationVector"),
}


def read_jsonl(path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                loaded = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(loaded, dict):
                yield line_no, loaded


def event_name(event: dict[str, Any]) -> str:
    return str(event.get("event") or event.get("type") or "unknown")


def int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def clean_hex(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        return b""
    text = value.replace("...", "")
    if len(text) % 2:
        text = text[:-1]
    if not HEX_RE.match(text):
        return b""
    return bytes.fromhex(text)


def summary_fingerprint(summary: Any) -> str | None:
    if not isinstance(summary, dict):
        return None
    value = summary.get("sha256PrefixHex") or summary.get("sha256_prefix") or summary.get("sha256_12")
    return str(value) if value else None


def summary_length(summary: Any) -> int | None:
    if not isinstance(summary, dict):
        return None
    return int_or_none(summary.get("length") or summary.get("decoded_length") or summary.get("len"))


def str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def fingerprint_matches(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    left = left.lower()
    right = right.lower()
    return left.startswith(right) or right.startswith(left)


def payload_summary(event: dict[str, Any]) -> tuple[int, str | None]:
    data = clean_hex(event.get("hex"))
    if not data and isinstance(event.get("bytes"), dict):
        data = clean_hex(event["bytes"].get("hex"))
    if data:
        return len(data), hashlib.sha256(data).hexdigest()[:16]
    length = int_or_none(event.get("length"))
    if length is not None:
        return length, None
    if isinstance(event.get("bytes"), dict):
        return summary_length(event["bytes"]) or 0, summary_fingerprint(event["bytes"])
    return 0, None


def auth_type_name(service: int | None, type_value: int | None) -> str | None:
    if service is None or type_value is None:
        return None
    return AUTH_TYPED_BUFFER_TYPES.get(service, {}).get(type_value)


def compact_event(event: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    return {key: event.get(key) for key in keys if event.get(key) is not None}


def summary_brief(summary: Any) -> str:
    if not isinstance(summary, dict):
        return str(summary)
    parts = []
    length = summary_length(summary)
    fingerprint = summary_fingerprint(summary)
    if length is not None:
        parts.append(f"len={length}")
    if fingerprint:
        parts.append(f"fp={fingerprint}")
    if summary.get("error"):
        parts.append(f"error={summary['error']}")
    return " ".join(parts) if parts else str(summary)


def summarize_trace(path: Path) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    delegates: list[dict[str, Any]] = []
    service_events: list[dict[str, Any]] = []
    typed_buffers: list[dict[str, Any]] = []
    accepted_keys: list[dict[str, Any]] = []
    result_callbacks: list[dict[str, Any]] = []
    challenge_returns: list[dict[str, Any]] = []
    builder_inputs: list[dict[str, Any]] = []
    channel_services: dict[int, int] = {}
    auth_services_seen: Counter[int] = Counter()

    event_count = 0
    for line_no, event in read_jsonl(path):
        event_count += 1
        name = event_name(event)
        counts[name] += 1

        if name in ("airshield.auth.delegate.start", "airshield.auth.delegate.register_services"):
            delegates.append({
                "line_no": line_no,
                "event": name,
                **compact_event(event, [
                    "className",
                    "delegate",
                    "allowOffload",
                    "retryAttempt",
                    "prototypeRetryAttempt",
                    "hasIdentity",
                    "hasIdentityDelegate",
                    "hasPrototypeIdentity",
                    "hasConstellationAuth",
                    "hasChallenges",
                    "txChallenge",
                    "rxChallenge",
                    "tag",
                ]),
            })

        if name in CHALLENGE_RETURN_EVENTS:
            challenge = event.get("challenge")
            challenge_returns.append({
                "line_no": line_no,
                "event": name,
                "role": str_or_none(event.get("role")) or CHALLENGE_RETURN_EVENTS[name],
                "length": summary_length(challenge),
                "fingerprint": summary_fingerprint(challenge),
            })

        if name in BUILDER_INPUT_EVENTS:
            input_name, summary_key = BUILDER_INPUT_EVENTS[name]
            summary = event.get(summary_key)
            builder_inputs.append({
                "line_no": line_no,
                "event": name,
                "input": input_name,
                "length": summary_length(summary),
                "fingerprint": summary_fingerprint(summary),
            })

        if name in ("datax.registerService", "datax.openChannel", "datax.localChannel.init"):
            service = int_or_none(event.get("serviceID") or event.get("service"))
            channel_id = int_or_none(event.get("channelId"))
            if service is not None and service in AUTH_SERVICE_NAMES:
                auth_services_seen[service] += 1
            if service is not None and channel_id is not None:
                channel_services[channel_id] = service
            service_events.append({
                "line_no": line_no,
                "event": name,
                "service": service,
                "service_name": AUTH_SERVICE_NAMES.get(service),
                "channel_id": channel_id,
            })

        if name in ("datax.localChannel.send", "datax.remoteChannel.send"):
            service = int_or_none(event.get("service"))
            channel_id = int_or_none(event.get("channelId"))
            service_inferred = False
            if service is None and channel_id is not None and channel_id in channel_services:
                service = channel_services[channel_id]
                service_inferred = True
            if service is not None and service in AUTH_SERVICE_NAMES:
                auth_services_seen[service] += 1
            type_value = int_or_none(event.get("type"))
            type_name = auth_type_name(service, type_value)
            if type_name:
                payload_len, payload_fp = payload_summary(event)
                typed_buffers.append({
                    "line_no": line_no,
                    "event": name,
                    "service": service,
                    "service_name": AUTH_SERVICE_NAMES.get(service),
                    "channel_id": channel_id,
                    "service_inferred": service_inferred,
                    "type": type_value,
                    "type_name": type_name,
                    "payload_len": payload_len,
                    "payload_fingerprint": payload_fp,
                })

        if name == "airshield.auth.accept_key_candidate":
            public_key = event.get("originalPublicKey")
            accepted_keys.append({
                "line_no": line_no,
                "event": name,
                "variant": event.get("variant"),
                "as_main": event.get("asMain"),
                "length": summary_length(public_key),
                "fingerprint": summary_fingerprint(public_key),
            })
        elif name == "airshield.acceptAuthentication":
            public_key = event.get("publicKey")
            accepted_keys.append({
                "line_no": line_no,
                "event": name,
                "length": summary_length(public_key) or int_or_none(event.get("pubKeyLength")),
                "fingerprint": summary_fingerprint(public_key) or event.get("pubKeyFingerprint"),
            })
        elif name == "airshield.auth.result_callback":
            carried_key = event.get("carriedPublicKey")
            result_callbacks.append({
                "line_no": line_no,
                "event": name,
                "variant": event.get("variant"),
                "path": event.get("path"),
                "allowOffload": event.get("allowOffload"),
                "carried_key_length": summary_length(carried_key),
                "carried_key_fingerprint": summary_fingerprint(carried_key),
            })

    return {
        "path": str(path),
        "event_count": event_count,
        "counts": counts,
        "delegates": delegates,
        "service_events": service_events,
        "auth_services_seen": dict(auth_services_seen),
        "typed_buffers": typed_buffers,
        "accepted_keys": accepted_keys,
        "result_callbacks": result_callbacks,
        "challenge_returns": challenge_returns,
        "builder_inputs": builder_inputs,
        "stream_ready_count": counts["airshield.streamReady"],
        "accept_authentication_count": counts["airshield.acceptAuthentication"],
    }


def mac_enable_trust_candidates(path: Path) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for line_no, event in read_jsonl(path):
        if event_name(event) != "airshield.identity.enable_trust_candidates_prepared":
            continue
        slot = str_or_none(event.get("slot"))
        private_key_fingerprint = str_or_none(event.get("private_key_fingerprint"))
        for index, candidate in enumerate(event.get("candidates") or []):
            if not isinstance(candidate, dict):
                continue
            candidates.append({
                "path": str(path),
                "line_no": line_no,
                "candidate_index": index,
                "candidate_id": str_or_none(candidate.get("candidate_id")),
                "slot": slot,
                "private_key_fingerprint": private_key_fingerprint,
                "scalar_source": str_or_none(candidate.get("scalar_source")),
                "identifier_source": str_or_none(candidate.get("identifier_source")),
                "identifier_fingerprint": str_or_none(candidate.get("identifier_fingerprint")),
                "challenge_hash_source": str_or_none(candidate.get("challenge_hash_source")),
                "challenge_hash_fingerprint": str_or_none(candidate.get("challenge_hash_fingerprint")),
                "signature_format": str_or_none(candidate.get("signature_format")),
                "signature_fingerprint": str_or_none(candidate.get("signature_fingerprint")),
                "payload_length": int_or_none(candidate.get("payload_length")),
                "payload_fingerprint": str_or_none(candidate.get("payload_fingerprint")),
                "frame_length": int_or_none(candidate.get("frame_length")),
                "frame_fingerprint": str_or_none(candidate.get("frame_fingerprint")),
                "transmit_state": str_or_none(candidate.get("transmit_state")),
            })
    return candidates


def compare_enable_trust_candidates(summary: dict[str, Any], mac_candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    android_enable_trust = [
        item for item in summary["typed_buffers"]
        if item.get("service") == 36 and item.get("type") == 4096
    ]
    comparisons: list[dict[str, Any]] = []
    for android_item in android_enable_trust:
        ranked: list[dict[str, Any]] = []
        for candidate in mac_candidates:
            points = 0
            matches: list[str] = []
            mismatches: list[str] = []
            if fingerprint_matches(android_item.get("payload_fingerprint"), candidate.get("payload_fingerprint")):
                points += 8
                matches.append("payload_fingerprint")
            elif android_item.get("payload_fingerprint") and candidate.get("payload_fingerprint"):
                points -= 4
                mismatches.append("payload_fingerprint")
            if android_item.get("payload_len") and candidate.get("payload_length"):
                if android_item["payload_len"] == candidate["payload_length"]:
                    points += 1
                    matches.append("payload_length")
                else:
                    mismatches.append("payload_length")
            if candidate.get("signature_format") == "security_p256_ecdsa_raw64_digest_challenge_hash_native_format":
                points += 1
                matches.append("native_raw_digest_signature_format")
            ranked.append({
                "score": points,
                "matches": matches,
                "mismatches": mismatches,
                "android": android_item,
                "mac": candidate,
            })
        ranked.sort(key=lambda item: item["score"], reverse=True)
        comparisons.extend(ranked[:5])
    return comparisons


def preamble_challenge_summaries(summary: dict[str, Any]) -> list[dict[str, Any]]:
    challenges: list[dict[str, Any]] = []
    for item in summary["delegates"]:
        if item.get("event") != "airshield.auth.delegate.register_services":
            continue
        for role in ("txChallenge", "rxChallenge"):
            challenge = item.get(role)
            fingerprint = summary_fingerprint(challenge)
            if not fingerprint:
                continue
            challenges.append({
                "line_no": item.get("line_no"),
                "delegate": item.get("delegate"),
                "className": item.get("className"),
                "role": role,
                "length": summary_length(challenge),
                "fingerprint": fingerprint,
            })
    for item in summary.get("challenge_returns", []):
        fingerprint = item.get("fingerprint")
        if not fingerprint:
            continue
        challenges.append({
            "line_no": item.get("line_no"),
            "delegate": None,
            "className": item.get("event"),
            "role": item.get("role"),
            "length": item.get("length"),
            "fingerprint": fingerprint,
        })
    return challenges


def compare_challenge_candidates(summary: dict[str, Any], mac_candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    comparisons: list[dict[str, Any]] = []
    for challenge in preamble_challenge_summaries(summary):
        ranked: list[dict[str, Any]] = []
        for candidate in mac_candidates:
            points = 0
            matches: list[str] = []
            mismatches: list[str] = []
            if challenge["role"] == "txChallenge":
                points += 2
                matches.append("production_identity_signs_tx_challenge")
            else:
                points -= 2
                mismatches.append("production_identity_does_not_sign_rx_challenge")
            if fingerprint_matches(challenge.get("fingerprint"), candidate.get("challenge_hash_fingerprint")):
                points += 8
                matches.append("challenge_hash_fingerprint")
            elif challenge.get("fingerprint") and candidate.get("challenge_hash_fingerprint"):
                points -= 4
                mismatches.append("challenge_hash_fingerprint")
            if challenge.get("length") == 32:
                points += 1
                matches.append("java_hash_to_byte_array_length_32")
            if candidate.get("signature_format") == "security_p256_ecdsa_raw64_digest_challenge_hash_native_format":
                points += 1
                matches.append("native_raw_digest_signature_format")
            ranked.append({
                "score": points,
                "matches": matches,
                "mismatches": mismatches,
                "android_challenge": challenge,
                "mac": candidate,
            })
        ranked.sort(key=lambda item: item["score"], reverse=True)
        comparisons.extend(ranked[:5])
    return comparisons


def candidate_key(candidate: dict[str, Any]) -> tuple[Any, ...]:
    return (
        candidate.get("path"),
        candidate.get("line_no"),
        candidate.get("candidate_index"),
        candidate.get("candidate_id"),
        candidate.get("payload_fingerprint"),
        candidate.get("frame_fingerprint"),
    )


def recommend_enable_trust_candidate(
    summary: dict[str, Any],
    mac_candidates: list[dict[str, Any]],
    payload_comparisons: list[dict[str, Any]],
    challenge_comparisons: list[dict[str, Any]],
) -> dict[str, Any]:
    if not mac_candidates:
        return {
            "status": "NO_MAC_CANDIDATES",
            "eligible_for_manual_mac_auth_transmit": False,
            "reason": "No Mac EnableTrust candidates were supplied."
        }

    tx_challenge_matches = [
        item for item in challenge_comparisons
        if item.get("android_challenge", {}).get("role") == "txChallenge"
        and "challenge_hash_fingerprint" in item.get("matches", [])
        and item.get("mac", {}).get("signature_format") == "security_p256_ecdsa_raw64_digest_challenge_hash_native_format"
    ]
    tx_challenge_matches.sort(key=lambda item: item.get("score", 0), reverse=True)
    if not tx_challenge_matches:
        return {
            "status": "NO_TX_CHALLENGE_MATCH",
            "eligible_for_manual_mac_auth_transmit": False,
            "reason": "No native-format raw64 Mac candidate matched an Android TX challenge fingerprint."
        }

    android_enable_trust_payloads = [
        item for item in summary.get("typed_buffers", [])
        if item.get("service") == 36 and item.get("type") == 4096
    ]
    payload_matches_by_candidate = {
        candidate_key(item["mac"]): item
        for item in payload_comparisons
        if "payload_fingerprint" in item.get("matches", [])
        and item.get("mac", {}).get("signature_format") == "security_p256_ecdsa_raw64_digest_challenge_hash_native_format"
    }

    best_challenge = tx_challenge_matches[0]
    best_key = candidate_key(best_challenge["mac"])
    payload_match = payload_matches_by_candidate.get(best_key)
    status = "PAYLOAD_AND_TX_CHALLENGE_MATCH" if payload_match else "TX_CHALLENGE_MATCH_ONLY"
    eligible = payload_match is not None
    reason = (
        "Same native-format raw64 candidate matched Android TX challenge and ENABLE_TRUST payload fingerprints."
        if eligible else
        "Candidate matched Android TX challenge, but no matching Android ENABLE_TRUST payload fingerprint was present."
    )
    if android_enable_trust_payloads and payload_match is None:
        reason = "Android ENABLE_TRUST payloads were present, but none matched the TX-challenge-selected Mac candidate."

    return {
        "status": status,
        "eligible_for_manual_mac_auth_transmit": eligible,
        "reason": reason,
        "android_enable_trust_payload_count": len(android_enable_trust_payloads),
        "challenge_match": best_challenge,
        "payload_match": payload_match,
        "recommended_mac_candidate": best_challenge["mac"],
    }


def build_auth_gate(
    summary: dict[str, Any],
    mac_session_paths: list[Path],
    recommendation: dict[str, Any],
) -> dict[str, Any]:
    candidate = recommendation.get("recommended_mac_candidate")
    challenge_match = recommendation.get("challenge_match")
    payload_match = recommendation.get("payload_match")
    if not isinstance(candidate, dict):
        raise ValueError("recommendation does not contain a Mac candidate")
    if not isinstance(challenge_match, dict):
        raise ValueError("recommendation does not contain a challenge match")
    if not isinstance(payload_match, dict):
        raise ValueError("recommendation does not contain a payload match")

    return {
        "schema": "codex_band_bridge_enable_trust_gate_v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": recommendation.get("status"),
        "eligible_for_manual_mac_auth_transmit": recommendation.get("eligible_for_manual_mac_auth_transmit"),
        "android_trace": summary.get("path"),
        "mac_sessions": [str(path) for path in mac_session_paths],
        "candidate_id": candidate.get("candidate_id"),
        "slot": candidate.get("slot"),
        "scalar_source": candidate.get("scalar_source"),
        "identifier_source": candidate.get("identifier_source"),
        "identifier_fingerprint": candidate.get("identifier_fingerprint"),
        "challenge_hash_source": candidate.get("challenge_hash_source"),
        "challenge_hash_fingerprint": candidate.get("challenge_hash_fingerprint"),
        "signature_format": candidate.get("signature_format"),
        "signature_fingerprint": candidate.get("signature_fingerprint"),
        "payload_length": candidate.get("payload_length"),
        "payload_fingerprint": candidate.get("payload_fingerprint"),
        "frame_length": candidate.get("frame_length"),
        "frame_fingerprint": candidate.get("frame_fingerprint"),
        "transmit_state": "eligible_manual_only_requires_matching_live_candidate_id",
        "evidence": {
            "android_tx_challenge": challenge_match.get("android_challenge"),
            "android_enable_trust_payload": payload_match.get("android"),
            "challenge_comparison_score": challenge_match.get("score"),
            "challenge_comparison_matches": challenge_match.get("matches"),
            "payload_comparison_score": payload_match.get("score"),
            "payload_comparison_matches": payload_match.get("matches"),
        },
    }


def synthetic_auth_summary(payload: bytes, challenge_fingerprint: str, *, challenge_role: str = "txChallenge") -> dict[str, Any]:
    return {
        "path": "self-test-android-trace.jsonl",
        "event_count": 3,
        "counts": Counter(),
        "delegates": [],
        "service_events": [],
        "auth_services_seen": {36: 1},
        "typed_buffers": [
            {
                "line_no": 2,
                "event": "datax.localChannel.send",
                "service": 36,
                "service_name": "identity",
                "channel_id": 7,
                "service_inferred": False,
                "type": 4096,
                "type_name": "ENABLE_TRUST",
                "payload_len": len(payload),
                "payload_fingerprint": hashlib.sha256(payload).hexdigest()[:16],
            }
        ],
        "accepted_keys": [],
        "result_callbacks": [],
        "challenge_returns": [
            {
                "line_no": 1,
                "event": "airshield.preamble.getTxChallenge" if challenge_role == "txChallenge" else "airshield.preamble.getRxChallenge",
                "role": challenge_role,
                "length": 32,
                "fingerprint": challenge_fingerprint,
            }
        ],
        "builder_inputs": [],
        "stream_ready_count": 0,
        "accept_authentication_count": 0,
    }


def synthetic_mac_candidate(payload: bytes, challenge_fingerprint: str) -> dict[str, Any]:
    return {
        "path": "self-test-mac-session.jsonl",
        "line_no": 10,
        "candidate_index": 0,
        "candidate_id": "self-test-native-raw64",
        "slot": "acdc-app-private-key",
        "private_key_fingerprint": "privatefp",
        "scalar_source": "first32",
        "identifier_source": "hash_app_private_key_bytes",
        "identifier_fingerprint": "identifierfp",
        "challenge_hash_source": "txChallenge",
        "challenge_hash_fingerprint": challenge_fingerprint,
        "signature_format": "security_p256_ecdsa_raw64_digest_challenge_hash_native_format",
        "signature_fingerprint": "signaturefp",
        "payload_length": len(payload),
        "payload_fingerprint": hashlib.sha256(payload).hexdigest()[:16],
        "frame_length": len(payload) + 8,
        "frame_fingerprint": "framefp",
        "transmit_state": "staged_manual_only",
    }


def self_test() -> None:
    payload = b"self-test-enable-trust-payload"
    challenge_fingerprint = "0011223344556677"
    candidate = synthetic_mac_candidate(payload, challenge_fingerprint)
    summary = synthetic_auth_summary(payload, challenge_fingerprint)
    payload_comparisons = compare_enable_trust_candidates(summary, [candidate])
    challenge_comparisons = compare_challenge_candidates(summary, [candidate])
    recommendation = recommend_enable_trust_candidate(
        summary,
        [candidate],
        payload_comparisons,
        challenge_comparisons,
    )
    if recommendation.get("status") != "PAYLOAD_AND_TX_CHALLENGE_MATCH":
        raise SystemExit(f"self-test: expected eligible match, got {recommendation.get('status')}")
    if recommendation.get("eligible_for_manual_mac_auth_transmit") is not True:
        raise SystemExit("self-test: eligible match did not enable manual transmit")
    gate = build_auth_gate(summary, [Path("self-test-mac-session.jsonl")], recommendation)
    if gate.get("schema") != "codex_band_bridge_enable_trust_gate_v1":
        raise SystemExit("self-test: gate schema mismatch")
    if gate.get("candidate_id") != candidate["candidate_id"]:
        raise SystemExit("self-test: gate candidate_id mismatch")
    if gate.get("payload_fingerprint") != candidate["payload_fingerprint"]:
        raise SystemExit("self-test: gate payload fingerprint mismatch")

    no_payload_summary = synthetic_auth_summary(b"different-payload", challenge_fingerprint)
    no_payload_recommendation = recommend_enable_trust_candidate(
        no_payload_summary,
        [candidate],
        compare_enable_trust_candidates(no_payload_summary, [candidate]),
        compare_challenge_candidates(no_payload_summary, [candidate]),
    )
    if no_payload_recommendation.get("status") != "TX_CHALLENGE_MATCH_ONLY":
        raise SystemExit(
            "self-test: expected TX_CHALLENGE_MATCH_ONLY when payload fingerprint differs, "
            f"got {no_payload_recommendation.get('status')}"
        )
    if no_payload_recommendation.get("eligible_for_manual_mac_auth_transmit") is not False:
        raise SystemExit("self-test: mismatched payload was incorrectly eligible")

    rx_summary = synthetic_auth_summary(payload, challenge_fingerprint, challenge_role="rxChallenge")
    rx_recommendation = recommend_enable_trust_candidate(
        rx_summary,
        [candidate],
        compare_enable_trust_candidates(rx_summary, [candidate]),
        compare_challenge_candidates(rx_summary, [candidate]),
    )
    if rx_recommendation.get("status") != "NO_TX_CHALLENGE_MATCH":
        raise SystemExit(f"self-test: expected RX-only challenge to fail closed, got {rx_recommendation.get('status')}")
    print("self-test: OK")


def print_report(
    summary: dict[str, Any],
    mac_candidates: list[dict[str, Any]] | None = None,
    recommendation: dict[str, Any] | None = None,
) -> None:
    counts: Counter[str] = summary["counts"]
    print(f"Trace: {summary['path']}")
    print(f"JSON events: {summary['event_count']}")

    print("\nAuth delegates:")
    if summary["delegates"]:
        for item in summary["delegates"][:40]:
            detail = " ".join(
                f"{key}={summary_brief(value) if key in ('txChallenge', 'rxChallenge') else value}"
                for key, value in item.items()
                if key not in ("line_no", "event") and value is not None
            )
            print(f"  line {item['line_no']} {item['event']} {detail}".rstrip())
    else:
        print("  none")

    print("\nChallenge fingerprints:")
    challenge_items = preamble_challenge_summaries(summary)
    if challenge_items:
        for item in challenge_items[:60]:
            source = item.get("className") or item.get("delegate") or "unknown"
            print(
                f"  line {item.get('line_no')} {item.get('role')} "
                f"source={source} len={item.get('length')} fp={item.get('fingerprint')}"
            )
    else:
        print("  none")

    print("\nCipherBuilder inputs:")
    if summary["builder_inputs"]:
        for item in summary["builder_inputs"][:80]:
            print(
                f"  line {item.get('line_no')} {item.get('input')} "
                f"len={item.get('length')} fp={item.get('fingerprint') or '-'}"
            )
    else:
        print("  none")

    print("\nIdentity services/channels:")
    auth_service_events = [
        item for item in summary["service_events"]
        if item.get("service") in AUTH_SERVICE_NAMES
    ]
    if auth_service_events:
        for item in auth_service_events[:40]:
            context = []
            if item.get("service") is not None:
                context.append(f"service={item['service']} ({item.get('service_name')})")
            if item.get("channel_id") is not None:
                context.append(f"channel={item['channel_id']}")
            print(f"  line {item['line_no']} {item['event']} {' '.join(context)}")
    else:
        print("  none")

    print("\nAuth typed buffers:")
    if summary["typed_buffers"]:
        for item in summary["typed_buffers"][:60]:
            context = [
                f"service={item['service']} ({item['service_name']})",
                f"type={item['type']} ({item['type_name']})",
                f"len={item['payload_len']}",
            ]
            if item.get("payload_fingerprint"):
                context.append(f"fp={item['payload_fingerprint']}")
            if item.get("channel_id") is not None:
                context.append(f"channel={item['channel_id']}")
            if item.get("service_inferred"):
                context.append("service_inferred=true")
            print(f"  line {item['line_no']} {item['event']} {' '.join(context)}")
    else:
        print("  none")

    print("\nAccepted auth key path:")
    if summary["accepted_keys"]:
        for item in summary["accepted_keys"][:40]:
            detail = []
            if item.get("variant") is not None:
                detail.append(f"variant={item['variant']}")
            if item.get("as_main") is not None:
                detail.append(f"asMain={item['as_main']}")
            detail.append(f"len={item.get('length')}")
            detail.append(f"fp={item.get('fingerprint')}")
            print(f"  line {item['line_no']} {item['event']} {' '.join(detail)}")
    else:
        print("  none")

    print("\nAuth result callbacks:")
    if summary["result_callbacks"]:
        for item in summary["result_callbacks"][:40]:
            detail = []
            for key in ("variant", "path", "allowOffload"):
                if item.get(key) is not None:
                    detail.append(f"{key}={item[key]}")
            if item.get("carried_key_length") is not None:
                detail.append(f"carriedLen={item['carried_key_length']}")
            if item.get("carried_key_fingerprint"):
                detail.append(f"carriedFp={item['carried_key_fingerprint']}")
            print(f"  line {item['line_no']} {item['event']} {' '.join(detail)}")
    else:
        print("  none")

    if mac_candidates is not None:
        print("\nMac EnableTrust candidates:")
        if mac_candidates:
            for item in mac_candidates[:80]:
                detail = [
                    f"line={item['line_no']}",
                    f"id={item.get('candidate_id')}",
                    f"slot={item.get('slot')}",
                    f"scalar={item.get('scalar_source')}",
                    f"identifier={item.get('identifier_source')}",
                    f"challenge={item.get('challenge_hash_source')}",
                    f"signature={item.get('signature_format')}",
                    f"localChannel={item.get('local_channel_id')}",
                    f"baseID={item.get('base_id')}",
                    f"payloadLen={item.get('payload_length')}",
                    f"payloadFp={item.get('payload_fingerprint')}",
                    f"state={item.get('transmit_state')}",
                ]
                print(f"  {' '.join(detail)}")
        else:
            print("  none")

        print("\nAndroid ENABLE_TRUST payload vs Mac candidates:")
        comparisons = compare_enable_trust_candidates(summary, mac_candidates)
        if comparisons:
            for item in comparisons[:40]:
                android_item = item["android"]
                mac_item = item["mac"]
                print(
                    "  "
                    f"score={item['score']:>3} "
                    f"android line={android_item.get('line_no')} len={android_item.get('payload_len')} "
                    f"fp={android_item.get('payload_fingerprint') or '-'}"
                )
                print(
                    "            "
                    f"mac line={mac_item.get('line_no')} slot={mac_item.get('slot')} "
                    f"id={mac_item.get('candidate_id')} "
                    f"identifier={mac_item.get('identifier_source')} "
                    f"signature={mac_item.get('signature_format')} "
                    f"localChannel={mac_item.get('local_channel_id')} baseID={mac_item.get('base_id')} "
                    f"len={mac_item.get('payload_length')} fp={mac_item.get('payload_fingerprint') or '-'}"
                )
                print(f"    matches: {', '.join(item['matches']) if item['matches'] else '-'}")
                print(f"    mismatches: {', '.join(item['mismatches']) if item['mismatches'] else '-'}")
        else:
            print("  missing Android ENABLE_TRUST payloads or Mac candidates")

        print("\nAndroid preamble challenges vs Mac candidates:")
        challenge_comparisons = compare_challenge_candidates(summary, mac_candidates)
        if challenge_comparisons:
            for item in challenge_comparisons[:40]:
                android_item = item["android_challenge"]
                mac_item = item["mac"]
                print(
                    "  "
                    f"score={item['score']:>3} "
                    f"android line={android_item.get('line_no')} role={android_item.get('role')} "
                    f"len={android_item.get('length')} fp={android_item.get('fingerprint') or '-'}"
                )
                print(
                    "            "
                    f"mac line={mac_item.get('line_no')} slot={mac_item.get('slot')} "
                    f"id={mac_item.get('candidate_id')} "
                    f"challenge={mac_item.get('challenge_hash_source')} "
                    f"challengeFp={mac_item.get('challenge_hash_fingerprint') or '-'} "
                    f"signature={mac_item.get('signature_format')} "
                    f"localChannel={mac_item.get('local_channel_id')} baseID={mac_item.get('base_id')}"
                )
                print(f"    matches: {', '.join(item['matches']) if item['matches'] else '-'}")
                print(f"    mismatches: {', '.join(item['mismatches']) if item['mismatches'] else '-'}")
        else:
            print("  missing Android preamble challenge summaries or Mac candidates")

        if recommendation is not None:
            print("\nRecommended gated EnableTrust candidate:")
            print(
                "  "
                f"status={recommendation.get('status')} "
                f"eligible={recommendation.get('eligible_for_manual_mac_auth_transmit')} "
                f"reason={recommendation.get('reason')}"
            )
            candidate = recommendation.get("recommended_mac_candidate")
            if isinstance(candidate, dict):
                print(
                    "  "
                    f"mac line={candidate.get('line_no')} slot={candidate.get('slot')} "
                    f"id={candidate.get('candidate_id')} "
                    f"scalar={candidate.get('scalar_source')} identifier={candidate.get('identifier_source')} "
                    f"challenge={candidate.get('challenge_hash_source')} "
                    f"signature={candidate.get('signature_format')} "
                    f"localChannel={candidate.get('local_channel_id')} baseID={candidate.get('base_id')} "
                    f"payloadFp={candidate.get('payload_fingerprint') or '-'} "
                    f"frameFp={candidate.get('frame_fingerprint') or '-'}"
                )

    print("\nMilestones:")
    for name in (
        "airshield.preambleReady",
        "airshield.auth.delegate.register_services",
        "airshield.auth.delegate.start",
        "airshield.acceptAuthentication",
        "airshield.streamReady",
    ):
        print(f"  {name}: {counts[name]}")

    if summary["accept_authentication_count"] and summary["stream_ready_count"]:
        verdict = "AUTH_FLOW_COMPLETE"
    elif summary["accepted_keys"] or summary["typed_buffers"] or summary["delegates"]:
        verdict = "AUTH_FLOW_PARTIAL"
    else:
        verdict = "AUTH_FLOW_NOT_OBSERVED"
    print(f"\nOverall: {verdict}")


def json_ready(value: Any) -> Any:
    if isinstance(value, Counter):
        return dict(value)
    if isinstance(value, dict):
        return {key: json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_ready(item) for item in value]
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Report the redacted Android AirShield auth delegate/service/key path."
    )
    parser.add_argument("android_trace", nargs="?", type=Path, help="Android Frida JSONL trace.")
    parser.add_argument("--mac-session", action="append", type=Path, default=[], help="Mac bridge session JSONL log containing EnableTrust candidates.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--write-auth-gate", type=Path, help="Write an eligible manual Mac EnableTrust gate JSON file. Fails closed unless payload and TX-challenge evidence match the same candidate.")
    parser.add_argument("--self-test", action="store_true", help="Run synthetic eligible/fail-closed auth gate checks.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.android_trace is None:
        raise SystemExit("Provide an Android Frida JSONL trace or use --self-test.")
    summary = summarize_trace(args.android_trace.expanduser())
    mac_candidates = [item for path in args.mac_session for item in mac_enable_trust_candidates(path.expanduser())]
    enable_trust_comparisons = compare_enable_trust_candidates(summary, mac_candidates)
    challenge_comparisons = compare_challenge_candidates(summary, mac_candidates)
    recommendation = recommend_enable_trust_candidate(
        summary,
        mac_candidates,
        enable_trust_comparisons,
        challenge_comparisons,
    ) if args.mac_session else None
    if args.write_auth_gate:
        if recommendation is None:
            print("error: --write-auth-gate requires at least one --mac-session", file=sys.stderr)
            return 2
        if recommendation.get("eligible_for_manual_mac_auth_transmit") is not True:
            print(
                "error: refusing to write auth gate: "
                f"{recommendation.get('status')} - {recommendation.get('reason')}",
                file=sys.stderr,
            )
            return 2
        gate = build_auth_gate(summary, [path.expanduser() for path in args.mac_session], recommendation)
        gate_path = args.write_auth_gate.expanduser()
        gate_path.parent.mkdir(parents=True, exist_ok=True)
        gate_path.write_text(json.dumps(json_ready(gate), indent=2, sort_keys=True) + "\n")
    if args.json:
        summary["mac_enable_trust_candidates"] = mac_candidates
        summary["enable_trust_candidate_comparisons"] = enable_trust_comparisons
        summary["challenge_candidate_comparisons"] = challenge_comparisons
        if recommendation is not None:
            summary["recommended_enable_trust_candidate"] = recommendation
        print(json.dumps(json_ready(summary), indent=2, sort_keys=True))
    else:
        print_report(summary, mac_candidates if args.mac_session else None, recommendation)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
