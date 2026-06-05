#!/usr/bin/env python3
"""Compare Android native AirShield framing traces with Mac Swift candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


DEFAULT_ANDROID_TRACE_GLOB = "reverse/captures/airshield-datax-*.jsonl"
DEFAULT_NATIVE_FRAMING_PROBE_GLOB = "reverse/framing-probes/airshield-framing-probe-*.json"
DEFAULT_SESSIONS_DIR = Path.home() / "Library/Logs/CodexBandBridge/sessions"


@dataclass(frozen=True)
class NativeFrame:
    line_no: int
    event: str
    result: str
    direction: str
    plaintext_len: int | None
    outer_len: int | None
    outer_complete: bool
    validation_prefix: str | None
    cipher_payload_indicator: int | None
    cipher_payload_len: int | None
    cipher_payload_fingerprint: str | None
    outer_frame_fingerprint: str | None
    plaintext_fingerprint: str | None
    plaintext_datax_summary: str


@dataclass(frozen=True)
class SwiftFrame:
    line_no: int
    event: str
    direction: str
    candidate_kind: str
    shared_material_source: str
    plaintext_len: int | None
    padded_plaintext_len: int | None
    cipher_payload_len: int | None
    outer_len: int | None
    frame_counter: str | None
    validation_prefix: str | None
    cipher_payload_fingerprint: str | None
    outer_frame_fingerprint: str | None
    plaintext_fingerprint: str | None


@dataclass(frozen=True)
class NativeSetup:
    line_no: int
    validation_key_fingerprint: str | None
    cipher_key_fingerprint: str | None
    initial_counter_block_fingerprint: str | None
    frame_counter: str | None
    runtime_validation_mode: str | None


@dataclass(frozen=True)
class NativeBuilderInput:
    line_no: int
    input_name: str
    length: int | None
    fingerprint: str | None
    derived_name: str | None = None
    derived_length: int | None = None
    derived_fingerprint: str | None = None


@dataclass(frozen=True)
class NativeSharedHash:
    line_no: int
    length: int | None
    prefix_hex: str | None
    fingerprint: str | None
    public_key_length: int | None
    public_key_fingerprint: str | None


@dataclass(frozen=True)
class NativeStateSetupInput:
    line_no: int
    direction_flag: str | None
    transcript_challenge_window_fingerprint: str | None
    transcript_material_window_fingerprint: str | None
    selected_counter_input_fingerprint: str | None
    raw_challenge_fingerprint: str | None
    raw_seed_fingerprint: str | None
    raw_initialization_vector_fingerprint: str | None


@dataclass(frozen=True)
class NativeExpansionCall:
    line_no: int
    output_line_no: int | None
    output_pointer: str | None
    key_material_fingerprint: str | None
    context_source: str | None
    context_length: int | None
    context_fingerprint: str | None
    output_fingerprint: str | None
    output_inline_tag_u32: int | None


@dataclass(frozen=True)
class SwiftEnableInput:
    line_no: int
    input_name: str
    length: int | None
    fingerprint: str | None


@dataclass(frozen=True)
class SwiftSetup:
    line_no: int
    shared_material_source: str
    shared_material_prefix_hex: str | None
    shared_material_fingerprint: str | None
    shared_material_sha256_fingerprint: str | None
    validation_key_fingerprint: str | None
    cipher_key_fingerprint: str | None
    initial_counter_block_fingerprint: str | None
    frame_counter: str | None
    runtime_validation_mode: str | None
    transcript_challenge_window_fingerprint: str | None = None
    transcript_material_window_fingerprint: str | None = None
    transcript_digest_input_fingerprint: str | None = None
    key_derivation_mode: str | None = None
    expansion_context_source: str | None = None
    expansion_context_length: int | None = None
    expansion_context_fingerprint: str | None = None


@dataclass(frozen=True)
class IdentityFingerprint:
    line_no: int
    source: str
    fingerprint: str | None
    length: int | None
    candidate_source: str | None = None


HEX_CHARS = set("0123456789abcdefABCDEF")


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


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def latest_repo_artifact(pattern: str) -> Path | None:
    candidates = sorted(
        repo_root().glob(pattern),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def latest_mac_session(sessions_dir: Path) -> Path | None:
    candidates = sorted(
        sessions_dir.glob("session-*.jsonl"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def clean_hex(value: Any) -> bytes:
    if not isinstance(value, str):
        return b""
    value = value.replace("...", "")
    if len(value) % 2:
        value = value[:-1]
    if not value or any(ch not in HEX_CHARS for ch in value):
        return b""
    return bytes.fromhex(value)


def short_sha256(data: bytes, hex_chars: int = 16) -> str | None:
    if not data:
        return None
    return hashlib.sha256(data).hexdigest()[:hex_chars]


def int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def summary_fingerprint(summary: Any) -> str | None:
    if not isinstance(summary, dict):
        return None
    return str_or_none(summary.get("sha256PrefixHex") or summary.get("sha256_12"))


def summary_prefix_hex(summary: Any) -> str | None:
    if not isinstance(summary, dict):
        return None
    return str_or_none(summary.get("prefixHex"))


def summary_length(summary: Any) -> int | None:
    if not isinstance(summary, dict):
        return None
    return int_or_none(summary.get("length") or summary.get("len"))


def buffer_data(event: dict[str, Any], key: str) -> tuple[bytes, bool]:
    value = event.get(key)
    if not isinstance(value, dict):
        return b"", False
    data = clean_hex(value.get("hex"))
    complete = value.get("complete")
    if isinstance(complete, bool):
        return data, complete
    return data, len(data) == int_or_none(value.get("length"))


def buffer_fingerprint(event: dict[str, Any], key: str, data: bytes, complete: bool) -> str | None:
    value = event.get(key)
    if isinstance(value, dict):
        fingerprint = str_or_none(value.get("sha256PrefixHex") or value.get("sha256_12"))
        if fingerprint and not fingerprint.startswith("error:"):
            return fingerprint
    if complete:
        return short_sha256(data)
    return None


def decode_datax_summary(data: bytes) -> str:
    if len(data) < 4:
        return "-"
    descriptor = int.from_bytes(data[0:2], "big")
    body_len = descriptor & 0x3FFF
    total_len = 4 + body_len
    if total_len > len(data) or total_len < 4:
        return "-"
    base_id = int.from_bytes(data[2:4], "big")
    pos = 4
    extensions = []
    if descriptor & 0x8000:
        while pos + 4 <= total_len:
            word = data[pos:pos + 4]
            raw_type = word[0]
            extensions.append(f"{raw_type & 0x7f}:{int.from_bytes(word[2:4], 'big')}")
            pos += 4
            if not (raw_type & 0x80):
                break
    payload_len = max(0, total_len - pos)
    ext_text = ",".join(extensions) if extensions else "-"
    return f"base=0x{base_id:04x} payload={payload_len} ext={ext_text}"


def native_frames(path: Path) -> list[NativeFrame]:
    frames: list[NativeFrame] = []
    for line_no, event in read_jsonl(path):
        event_name = event.get("event")
        if event_name not in ("airshield.framing.pack", "airshield.framing.unpack"):
            continue
        direction = "pack" if event_name.endswith(".pack") else "unpack"
        outer, outer_complete = buffer_data(event, "outerFrame")
        plaintext, plaintext_complete = buffer_data(event, "plaintext")
        indicator = outer[8] if len(outer) >= 9 else None
        expected_outer_len = (indicator * 16 + 25) if indicator is not None else None
        cipher_payload = b""
        if expected_outer_len is not None and len(outer) >= min(expected_outer_len, 9):
            cipher_payload = outer[9:min(len(outer), expected_outer_len)]
        outer_fingerprint = buffer_fingerprint(event, "outerFrame", outer[:expected_outer_len] if expected_outer_len and len(outer) >= expected_outer_len else outer, outer_complete)
        frames.append(NativeFrame(
            line_no=line_no,
            event=str(event_name),
            result=str_or_none(event.get("result")) or "-",
            direction=direction,
            plaintext_len=int_or_none(event.get("plainConsumed" if direction == "pack" else "plainWritten")),
            outer_len=int_or_none(event.get("outerWritten" if direction == "pack" else "outerConsumed")),
            outer_complete=outer_complete,
            validation_prefix=outer[:8].hex() if len(outer) >= 8 else None,
            cipher_payload_indicator=indicator,
            cipher_payload_len=(expected_outer_len - 9) if expected_outer_len is not None else None,
            cipher_payload_fingerprint=short_sha256(cipher_payload) if outer_complete else None,
            outer_frame_fingerprint=outer_fingerprint,
            plaintext_fingerprint=buffer_fingerprint(event, "plaintext", plaintext, plaintext_complete),
            plaintext_datax_summary=decode_datax_summary(plaintext),
        ))
    return frames


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def native_probe_frames(path: Path) -> list[NativeFrame]:
    loaded = read_json(path)
    if not isinstance(loaded, dict):
        return []
    native = loaded.get("native")
    if not isinstance(native, dict):
        return []
    pack = native.get("pack")
    if not isinstance(pack, dict):
        return []
    outer_frame = pack.get("outerFrame") if isinstance(pack.get("outerFrame"), dict) else {}
    cipher_payload = pack.get("cipherPayload") if isinstance(pack.get("cipherPayload"), dict) else {}
    plaintext = loaded.get("inputs", {}).get("plaintext") if isinstance(loaded.get("inputs"), dict) else {}
    return [
        NativeFrame(
            line_no=0,
            event=f"native_probe:{path.name}",
            result=str_or_none(pack.get("status")) or "-",
            direction="pack",
            plaintext_len=summary_length(plaintext),
            outer_len=summary_length(outer_frame),
            outer_complete=True,
            validation_prefix=str_or_none(pack.get("validationPrefixHex")),
            cipher_payload_indicator=int(pack.get("sizeIndicatorHex"), 16) if isinstance(pack.get("sizeIndicatorHex"), str) else None,
            cipher_payload_len=summary_length(cipher_payload),
            cipher_payload_fingerprint=summary_fingerprint(cipher_payload),
            outer_frame_fingerprint=summary_fingerprint(outer_frame),
            plaintext_fingerprint=summary_fingerprint(plaintext),
            plaintext_datax_summary="synthetic_probe",
        )
    ]


def native_setups(path: Path) -> list[NativeSetup]:
    configs: list[tuple[int, dict[str, Any]]] = []
    ciphers: list[tuple[int, dict[str, Any]]] = []
    for line_no, event in read_jsonl(path):
        event_name = event.get("event")
        if event_name == "native.airshield.framing_config":
            configs.append((line_no, event))
        elif event_name == "native.airshield.cipher_context_setup":
            ciphers.append((line_no, event))

    count = max(len(configs), len(ciphers))
    setups: list[NativeSetup] = []
    for index in range(count):
        config_line, config = configs[index] if index < len(configs) else (0, {})
        cipher_line, cipher = ciphers[index] if index < len(ciphers) else (0, {})
        setups.append(NativeSetup(
            line_no=config_line or cipher_line,
            validation_key_fingerprint=str_or_none(config.get("validationKeyFingerprint")),
            cipher_key_fingerprint=str_or_none(cipher.get("cipherKeyFingerprint")),
            initial_counter_block_fingerprint=str_or_none(cipher.get("initialCounterBlockFingerprint")),
            frame_counter=str_or_none(config.get("frameCounter")),
            runtime_validation_mode=str_or_none(config.get("runtimeValidationMode")),
        ))
    return setups


def native_builder_inputs(path: Path) -> list[NativeBuilderInput]:
    input_events = {
        "airshield.cipher_builder.set_challenge": ("challenge", "challenge", "transcript_challenge_window", "transcriptChallengeWindow"),
        "airshield.cipher_builder.set_seed": ("seed", "seed", "transcript_material_window", "transcriptMaterialWindow"),
        "airshield.cipher_builder.set_remote_public_key": ("remote_public_key", "publicKey", None, None),
        "airshield.cipher_builder.set_initialization_vector": ("initialization_vector", "initializationVector", None, None),
    }
    inputs: list[NativeBuilderInput] = []
    for line_no, event in read_jsonl(path):
        event_name = str(event.get("event") or "")
        if event_name not in input_events:
            continue
        input_name, summary_key, derived_name, derived_key = input_events[event_name]
        summary = event.get(summary_key)
        derived = event.get(derived_key) if derived_key else None
        inputs.append(NativeBuilderInput(
            line_no=line_no,
            input_name=input_name,
            length=summary_length(summary),
            fingerprint=summary_fingerprint(summary),
            derived_name=derived_name,
            derived_length=summary_length(derived),
            derived_fingerprint=summary_fingerprint(derived),
        ))
    return [item for item in inputs if item.fingerprint]


def native_shared_hashes(path: Path) -> list[NativeSharedHash]:
    items: list[NativeSharedHash] = []
    for line_no, event in read_jsonl(path):
        if str(event.get("event") or "") != "airshield.identity.private_key.derive":
            continue
        shared_hash = event.get("sharedHash")
        public_key = event.get("publicKey")
        items.append(NativeSharedHash(
            line_no=line_no,
            length=summary_length(shared_hash),
            prefix_hex=summary_prefix_hex(shared_hash),
            fingerprint=summary_fingerprint(shared_hash),
            public_key_length=summary_length(public_key),
            public_key_fingerprint=summary_fingerprint(public_key),
        ))
    return [item for item in items if item.prefix_hex or item.fingerprint]


def native_state_setup_inputs(path: Path) -> list[NativeStateSetupInput]:
    items: list[NativeStateSetupInput] = []
    for line_no, event in read_jsonl(path):
        if str(event.get("event") or "") != "native.airshield.state_setup_inputs":
            continue
        items.append(NativeStateSetupInput(
            line_no=line_no,
            direction_flag=str_or_none(event.get("directionFlag")),
            transcript_challenge_window_fingerprint=str_or_none(event.get("transcriptChallengeWindowFingerprint")),
            transcript_material_window_fingerprint=str_or_none(event.get("transcriptMaterialWindowFingerprint")),
            selected_counter_input_fingerprint=str_or_none(event.get("selectedCounterInputFingerprint")),
            raw_challenge_fingerprint=str_or_none(event.get("rawChallengeFingerprint")),
            raw_seed_fingerprint=str_or_none(event.get("rawSeedFingerprint")),
            raw_initialization_vector_fingerprint=str_or_none(event.get("rawInitializationVectorFingerprint")),
        ))
    return items


def native_expansion_calls(path: Path) -> list[NativeExpansionCall]:
    entries: list[dict[str, Any]] = []
    for line_no, event in read_jsonl(path):
        event_name = str(event.get("event") or "")
        if event_name == "native.airshield.framing_expansion":
            entries.append({
                "line_no": line_no,
                "output_line_no": None,
                "output_pointer": str_or_none(event.get("outputPointer")),
                "key_material_fingerprint": str_or_none(event.get("keyMaterialFingerprint")),
                "context_source": str_or_none(event.get("contextSource")),
                "context_length": int_or_none(event.get("contextLength")),
                "context_fingerprint": str_or_none(event.get("contextFingerprint")),
                "output_fingerprint": None,
                "output_inline_tag_u32": None,
            })
        elif event_name == "native.airshield.framing_expansion_output":
            output_pointer = str_or_none(event.get("outputPointer"))
            matched = None
            for entry in reversed(entries):
                if entry.get("output_pointer") == output_pointer and entry.get("output_fingerprint") is None:
                    matched = entry
                    break
            if matched is None:
                entries.append({
                    "line_no": line_no,
                    "output_line_no": line_no,
                    "output_pointer": output_pointer,
                    "key_material_fingerprint": None,
                    "context_source": None,
                    "context_length": int_or_none(event.get("contextLength")),
                    "context_fingerprint": None,
                    "output_fingerprint": str_or_none(event.get("outputFingerprint")),
                    "output_inline_tag_u32": int_or_none(event.get("outputInlineTagU32")),
                })
            else:
                matched["output_line_no"] = line_no
                matched["output_fingerprint"] = str_or_none(event.get("outputFingerprint"))
                matched["output_inline_tag_u32"] = int_or_none(event.get("outputInlineTagU32"))
    return [
        NativeExpansionCall(
            line_no=int(entry["line_no"]),
            output_line_no=int_or_none(entry.get("output_line_no")),
            output_pointer=str_or_none(entry.get("output_pointer")),
            key_material_fingerprint=str_or_none(entry.get("key_material_fingerprint")),
            context_source=str_or_none(entry.get("context_source")),
            context_length=int_or_none(entry.get("context_length")),
            context_fingerprint=str_or_none(entry.get("context_fingerprint")),
            output_fingerprint=str_or_none(entry.get("output_fingerprint")),
            output_inline_tag_u32=int_or_none(entry.get("output_inline_tag_u32")),
        )
        for entry in entries
    ]


def native_identity_fingerprints(path: Path) -> list[IdentityFingerprint]:
    identities: list[IdentityFingerprint] = []
    for line_no, event in read_jsonl(path):
        event_name = str(event.get("event") or "")
        if event_name == "airshield.identity.private_key.recover_public_key":
            public_key = event.get("publicKey")
            identities.append(IdentityFingerprint(
                line_no=line_no,
                source=event_name,
                fingerprint=summary_fingerprint(public_key),
                length=summary_length(public_key),
            ))
        elif event_name in (
            "airshield.identity.public_key.set_raw",
            "airshield.identity.public_key.serialize",
        ):
            public_key = event.get("publicKey")
            identities.append(IdentityFingerprint(
                line_no=line_no,
                source=event_name,
                fingerprint=summary_fingerprint(public_key),
                length=summary_length(public_key),
            ))
        elif event_name == "airshield.auth.accept_key_candidate":
            public_key = event.get("originalPublicKey")
            identities.append(IdentityFingerprint(
                line_no=line_no,
                source=event_name,
                fingerprint=summary_fingerprint(public_key),
                length=summary_length(public_key),
                candidate_source=f"variant={event.get('variant')}",
            ))
        elif event_name == "airshield.acceptAuthentication":
            public_key = event.get("publicKey")
            identities.append(IdentityFingerprint(
                line_no=line_no,
                source=event_name,
                fingerprint=summary_fingerprint(public_key) or str_or_none(event.get("pubKeyFingerprint")),
                length=summary_length(public_key) or int_or_none(event.get("pubKeyLength")),
            ))
    return [item for item in identities if item.fingerprint]


def frame_from_candidate(
    line_no: int,
    event_name: str,
    direction: str,
    candidate: dict[str, Any],
    shared_material_source: str | None = None,
    candidate_kind: str | None = None,
) -> SwiftFrame:
    return SwiftFrame(
        line_no=line_no,
        event=event_name,
        direction=direction,
        candidate_kind=str_or_none(candidate_kind or candidate.get("plaintext_source")) or "-",
        shared_material_source=str_or_none(shared_material_source or candidate.get("shared_material_source")) or "-",
        plaintext_len=int_or_none(candidate.get("plaintext_length")),
        padded_plaintext_len=int_or_none(candidate.get("padded_plaintext_length")),
        cipher_payload_len=int_or_none(candidate.get("cipher_payload_length")),
        outer_len=int_or_none(candidate.get("outer_frame_length")),
        frame_counter=str_or_none(candidate.get("frame_counter")),
        validation_prefix=str_or_none(candidate.get("validation_prefix_hex")),
        cipher_payload_fingerprint=str_or_none(candidate.get("cipher_payload_fingerprint")),
        outer_frame_fingerprint=str_or_none(candidate.get("outer_frame_fingerprint")),
        plaintext_fingerprint=str_or_none(candidate.get("plaintext_fingerprint")),
    )


def swift_frames(path: Path) -> list[SwiftFrame]:
    frames: list[SwiftFrame] = []
    for line_no, event in read_jsonl(path):
        event_name = str(event.get("type") or event.get("event") or "")
        if event_name in ("airshield.enable_inputs_ready", "airshield.link_setup.rx"):
            for material in event.get("normal_material_candidates") or []:
                if not isinstance(material, dict):
                    continue
                for key, kind in (
                    ("end_link_setup_frame_candidate", "end_link_setup"),
                    ("gesture_enable_frame_candidate", "gesture_enable"),
                ):
                    candidate = material.get(key)
                    if isinstance(candidate, dict) and candidate:
                        frames.append(frame_from_candidate(
                            line_no,
                            event_name,
                            "pack",
                            candidate,
                            shared_material_source=material.get("shared_material_source"),
                            candidate_kind=kind,
                        ))
            for key, kind in (
                ("normal_material_end_link_setup_frame_candidate", "end_link_setup"),
                ("normal_material_gesture_enable_frame_candidate", "gesture_enable"),
            ):
                candidate = event.get(key)
                if isinstance(candidate, dict) and candidate:
                    frames.append(frame_from_candidate(
                        line_no,
                        event_name,
                        "pack",
                        candidate,
                        shared_material_source=event.get("normal_material_shared_source"),
                        candidate_kind=kind,
                    ))
        elif event_name in ("airshield.end_link_setup.tx_ready", "airshield.end_link_setup.tx_sent"):
            frames.append(frame_from_candidate(
                line_no,
                event_name,
                "pack",
                event,
                shared_material_source=event.get("shared_material_source"),
                candidate_kind="end_link_setup",
            ))
        elif event_name in ("airshield.gesture_enable.tx_ready", "airshield.gesture_enable.tx_sent"):
            frames.append(frame_from_candidate(
                line_no,
                event_name,
                "pack",
                event,
                shared_material_source=event.get("shared_material_source"),
                candidate_kind="gesture_enable",
            ))
        elif event_name == "airshield.encrypted.rx_candidate_matched":
            frames.append(frame_from_candidate(
                line_no,
                event_name,
                "unpack",
                event,
                shared_material_source=event.get("shared_material_source"),
                candidate_kind="rx_candidate_matched",
            ))
    return frames


def swift_setups(path: Path) -> list[SwiftSetup]:
    setups: list[SwiftSetup] = []
    for line_no, event in read_jsonl(path):
        event_name = str(event.get("type") or event.get("event") or "")
        if event_name not in ("airshield.enable_inputs_ready", "airshield.link_setup.rx"):
            continue
        for material in event.get("normal_material_candidates") or []:
            if not isinstance(material, dict):
                continue
            end_candidate = material.get("end_link_setup_frame_candidate")
            gesture_candidate = material.get("gesture_enable_frame_candidate")
            candidate = end_candidate if isinstance(end_candidate, dict) and end_candidate else gesture_candidate
            candidate = candidate if isinstance(candidate, dict) else {}
            setups.append(SwiftSetup(
                line_no=line_no,
                shared_material_source=str_or_none(material.get("shared_material_source")) or "-",
                shared_material_prefix_hex=str_or_none(material.get("shared_material_prefix_hex")),
                shared_material_fingerprint=str_or_none(material.get("shared_material_fingerprint")),
                shared_material_sha256_fingerprint=str_or_none(material.get("shared_material_sha256_fingerprint")),
                validation_key_fingerprint=str_or_none(material.get("validation_key_fingerprint")),
                cipher_key_fingerprint=str_or_none(material.get("cipher_key_fingerprint")),
                initial_counter_block_fingerprint=str_or_none(material.get("initial_counter_block_fingerprint")),
                frame_counter=str_or_none(candidate.get("frame_counter")),
                runtime_validation_mode=str_or_none(candidate.get("runtime_validation_mode")),
                transcript_challenge_window_fingerprint=str_or_none(material.get("transcript_challenge_window_fingerprint")),
                transcript_material_window_fingerprint=str_or_none(material.get("transcript_material_window_fingerprint")),
                transcript_digest_input_fingerprint=str_or_none(material.get("transcript_digest_input_fingerprint")),
                key_derivation_mode=str_or_none(material.get("key_derivation_mode")),
                expansion_context_source=str_or_none(material.get("expansion_context_source")),
                expansion_context_length=int_or_none(material.get("expansion_context_length")),
                expansion_context_fingerprint=str_or_none(material.get("expansion_context_fingerprint")),
            ))
    return setups


def swift_enable_inputs(path: Path) -> list[SwiftEnableInput]:
    inputs: list[SwiftEnableInput] = []
    for line_no, event in read_jsonl(path):
        event_name = str(event.get("type") or event.get("event") or "")
        if event_name not in ("airshield.enable_inputs_ready", "airshield.link_setup.rx"):
            continue
        for input_name, length_key, fingerprint_key in (
            ("challenge", "local_challenge_length", "local_challenge_fingerprint"),
            ("seed", "seed_length", "seed_fingerprint"),
            ("remote_public_key", "peer_public_key_length", "peer_public_key_fingerprint"),
            ("initialization_vector", "iv_length", "iv_fingerprint"),
        ):
            fingerprint = str_or_none(event.get(fingerprint_key))
            if not fingerprint:
                continue
            inputs.append(SwiftEnableInput(
                line_no=line_no,
                input_name=input_name,
                length=int_or_none(event.get(length_key)),
                fingerprint=fingerprint,
            ))
    return inputs


def swift_identity_fingerprints(path: Path) -> list[IdentityFingerprint]:
    identities: list[IdentityFingerprint] = []
    for line_no, event in read_jsonl(path):
        event_name = str(event.get("type") or event.get("event") or "")
        if event_name not in (
            "airshield.identity.imported",
            "airshield.identity.loaded",
            "airshield.probe_state_ready",
        ):
            continue

        identity_event = event.get("identity") if event_name == "airshield.probe_state_ready" else event
        if not isinstance(identity_event, dict):
            continue

        fingerprint = str_or_none(identity_event.get("public_key_fingerprint"))
        if fingerprint and fingerprint != "nil":
            identities.append(IdentityFingerprint(
                line_no=line_no,
                source=event_name,
                fingerprint=fingerprint,
                length=int_or_none(identity_event.get("raw_public_key_length")),
                candidate_source="primary",
            ))

        for candidate in identity_event.get("public_key_candidates") or []:
            if not isinstance(candidate, dict):
                continue
            candidate_fingerprint = str_or_none(candidate.get("public_key_fingerprint"))
            if not candidate_fingerprint or candidate_fingerprint == "nil":
                continue
            identities.append(IdentityFingerprint(
                line_no=line_no,
                source=event_name,
                fingerprint=candidate_fingerprint,
                length=int_or_none(candidate.get("raw_public_key_length")),
                candidate_source=str_or_none(candidate.get("source")),
            ))
    return identities


def fingerprint_matches(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    left = left.lower()
    right = right.lower()
    return left.startswith(right) or right.startswith(left)


def score(native: NativeFrame, swift: SwiftFrame) -> tuple[int, list[str], list[str]]:
    points = 0
    matches: list[str] = []
    mismatches: list[str] = []
    if native.direction != swift.direction:
        mismatches.append("direction")
        return -10, matches, mismatches

    checks = [
        ("outer_len", native.outer_len, swift.outer_len),
        ("plaintext_len", native.plaintext_len, swift.plaintext_len),
        ("cipher_payload_len", native.cipher_payload_len, swift.cipher_payload_len),
    ]
    for label, left, right in checks:
        if left is None or right is None:
            continue
        if left == right:
            points += 2
            matches.append(label)
        else:
            points -= 2
            mismatches.append(f"{label} native={left} swift={right}")

    if native.validation_prefix and swift.validation_prefix:
        if native.validation_prefix.lower() == swift.validation_prefix.lower():
            points += 5
            matches.append("validation_prefix")
        else:
            points -= 5
            mismatches.append(
                f"validation_prefix native={native.validation_prefix} swift={swift.validation_prefix}"
            )

    fp_checks = [
        ("outer_fp", native.outer_frame_fingerprint, swift.outer_frame_fingerprint),
        ("cipher_fp", native.cipher_payload_fingerprint, swift.cipher_payload_fingerprint),
        ("plaintext_fp", native.plaintext_fingerprint, swift.plaintext_fingerprint),
    ]
    for label, left, right in fp_checks:
        if fingerprint_matches(left, right):
            points += 4
            matches.append(label)
        elif left and right:
            points -= 3
            mismatches.append(f"{label} native={left} swift={right}")

    return points, matches, mismatches


def print_report(native: list[NativeFrame], swift: list[SwiftFrame]) -> None:
    print(f"Native framing frames: {len(native)}")
    print(f"Swift candidate frames: {len(swift)}")
    if not native:
        print("No Android native Framing.pack/unpack events found.")
    if not swift:
        print("No Mac AirShield candidate events found.")
    print()

    for item in native[:40]:
        print(
            f"native line {item.line_no} {item.direction} result={item.result} "
            f"plain={item.plaintext_len} outer={item.outer_len} "
            f"prefix={item.validation_prefix or '-'} outer_fp={item.outer_frame_fingerprint or '-'} "
            f"datax={item.plaintext_datax_summary}"
        )
    if native and swift:
        print()
        print("Best comparisons:")
        ranked = []
        for native_frame in native:
            for swift_frame in swift:
                ranked.append((score(native_frame, swift_frame), native_frame, swift_frame))
        ranked.sort(key=lambda item: item[0][0], reverse=True)
        for (points, matches, mismatches), native_frame, swift_frame in ranked[:20]:
            print(
                f"score={points:>3} native line {native_frame.line_no} {native_frame.direction} "
                f"<-> swift line {swift_frame.line_no} {swift_frame.candidate_kind} {swift_frame.shared_material_source}"
            )
            print(f"  matches: {', '.join(matches) if matches else '-'}")
            print(f"  mismatches: {', '.join(mismatches) if mismatches else '-'}")


def print_setup_report(native: list[NativeSetup], swift: list[SwiftSetup]) -> None:
    print()
    print(f"Native setup fingerprints: {len(native)}")
    print(f"Swift setup candidates: {len(swift)}")
    if not native:
        print("No Android native setup fingerprint events found.")
    if not swift:
        print("No Mac AirShield setup candidate events found.")
    if not native or not swift:
        return

    print("Setup fingerprint comparisons:")
    for native_setup in native[:20]:
        ranked = []
        for swift_setup in swift:
            matches = []
            mismatches = []
            points = 0
            for label, left, right in (
                ("validation_key", native_setup.validation_key_fingerprint, swift_setup.validation_key_fingerprint),
                ("cipher_key", native_setup.cipher_key_fingerprint, swift_setup.cipher_key_fingerprint),
                ("initial_counter", native_setup.initial_counter_block_fingerprint, swift_setup.initial_counter_block_fingerprint),
            ):
                if fingerprint_matches(left, right):
                    points += 4
                    matches.append(label)
                elif left and right and right != "nil":
                    points -= 3
                    mismatches.append(f"{label} native={left} swift={right}")
            for label, left, right in (
                ("frame_counter", native_setup.frame_counter, swift_setup.frame_counter),
                ("runtime_validation_mode", native_setup.runtime_validation_mode, swift_setup.runtime_validation_mode),
            ):
                if left is None or right is None:
                    continue
                if str(left) == str(right):
                    points += 2
                    matches.append(label)
                else:
                    points -= 2
                    mismatches.append(f"{label} native={left} swift={right}")
            ranked.append((points, matches, mismatches, swift_setup))
        ranked.sort(key=lambda item: item[0], reverse=True)
        for points, matches, mismatches, swift_setup in ranked[:5]:
            print(
                f"  score={points:>3} native line {native_setup.line_no} "
                f"counter={native_setup.frame_counter} mode={native_setup.runtime_validation_mode} "
                f"<-> swift line {swift_setup.line_no} {swift_setup.shared_material_source} "
                f"derivation={swift_setup.key_derivation_mode or '-'}"
            )
            print(f"    matches: {', '.join(matches) if matches else '-'}")
            print(f"    mismatches: {', '.join(mismatches) if mismatches else '-'}")


def print_kdf_input_report(native: list[NativeBuilderInput], swift: list[SwiftEnableInput], swift_setups: list[SwiftSetup]) -> None:
    print()
    print(f"Android CipherBuilder input fingerprints: {len(native)}")
    print(f"Swift EnableEncryption input fingerprints: {len(swift)}")
    if not native:
        print("No Android CipherBuilder setter fingerprints found.")
    if not swift:
        print("No Swift EnableEncryption input fingerprints found.")

    expected_lengths = {
        "challenge": 16,
        "seed": 32,
        "remote_public_key": 64,
        "initialization_vector": None,
    }
    input_names = sorted({item.input_name for item in native} | {item.input_name for item in swift})
    if input_names:
        print("KDF input presence:")
        for input_name in input_names:
            native_items = [item for item in native if item.input_name == input_name]
            swift_items = [item for item in swift if item.input_name == input_name]
            expected = expected_lengths.get(input_name)
            native_lengths = sorted({item.length for item in native_items if item.length is not None})
            swift_lengths = sorted({item.length for item in swift_items if item.length is not None})
            markers = []
            if native_items:
                markers.append(f"android={len(native_items)} len={native_lengths or '-'}")
            else:
                markers.append("android=missing")
            if swift_items:
                markers.append(f"swift={len(swift_items)} len={swift_lengths or '-'}")
            else:
                markers.append("swift=missing")
            if expected is not None:
                ok = (not native_lengths or expected in native_lengths) and (not swift_lengths or expected in swift_lengths)
                markers.append(f"expected={expected} {'ok' if ok else 'check'}")
            print(f"  {input_name}: {'; '.join(markers)}")

    native_windows = {
        item.derived_name: item.derived_fingerprint
        for item in native
        if item.derived_name and item.derived_fingerprint
    }
    if native_windows and swift_setups:
        print("Transcript window comparisons:")
        for setup in swift_setups[:20]:
            matches = []
            mismatches = []
            for label, native_fp, swift_fp in (
                (
                    "challenge_window",
                    native_windows.get("transcript_challenge_window"),
                    setup.transcript_challenge_window_fingerprint,
                ),
                (
                    "material_window",
                    native_windows.get("transcript_material_window"),
                    setup.transcript_material_window_fingerprint,
                ),
            ):
                if fingerprint_matches(native_fp, swift_fp):
                    matches.append(label)
                elif native_fp and swift_fp:
                    mismatches.append(f"{label} android={native_fp} swift={swift_fp}")
            print(
                f"  swift line {setup.line_no} {setup.shared_material_source} "
                f"matches={', '.join(matches) if matches else '-'} "
                f"mismatches={', '.join(mismatches) if mismatches else '-'}"
            )

    if swift_setups:
        print("Swift transcript candidates:")
        for setup in swift_setups[:20]:
            print(
                f"  line {setup.line_no} {setup.shared_material_source} "
                f"mode={setup.key_derivation_mode or '-'} "
                f"context={setup.expansion_context_source or '-'} "
                f"contextLen={setup.expansion_context_length if setup.expansion_context_length is not None else '-'} "
                f"challengeWindow={setup.transcript_challenge_window_fingerprint or '-'} "
                f"materialWindow={setup.transcript_material_window_fingerprint or '-'} "
                f"digestInput={setup.transcript_digest_input_fingerprint or '-'}"
            )


def print_shared_hash_report(native: list[NativeSharedHash], swift_setups: list[SwiftSetup]) -> None:
    print()
    print(f"Android PrivateKey.derive shared hashes: {len(native)}")
    if not native:
        print("No Android PrivateKey.derive shared-hash fingerprints found.")
        return
    if not swift_setups:
        print("No Swift shared-material candidates found.")
        return

    print("Shared-material comparisons:")
    for item in native[:20]:
        ranked = []
        for setup in swift_setups:
            swift_prefix = setup.shared_material_prefix_hex or setup.shared_material_fingerprint
            swift_sha256 = setup.shared_material_sha256_fingerprint
            points = 0
            matches = []
            mismatches = []
            if fingerprint_matches(item.prefix_hex, swift_prefix):
                points += 6
                matches.append("shared_material_prefix")
            elif item.prefix_hex and swift_prefix:
                points -= 4
                mismatches.append(
                    f"shared_material_prefix android={item.prefix_hex} swift={swift_prefix}"
                )
            if fingerprint_matches(item.fingerprint, swift_sha256):
                points += 6
                matches.append("shared_material_sha256")
            elif item.fingerprint and swift_sha256:
                points -= 4
                mismatches.append(
                    f"shared_material_sha256 android={item.fingerprint} swift={swift_sha256}"
                )
            if item.length == 32:
                points += 1
                matches.append("java_hash_length_32")
            ranked.append((points, matches, mismatches, setup))
        ranked.sort(key=lambda entry: entry[0], reverse=True)
        for points, matches, mismatches, setup in ranked[:5]:
            print(
                f"  score={points:>3} android line {item.line_no} "
                f"len={item.length} prefix={item.prefix_hex or '-'} sha256={item.fingerprint or '-'} "
                f"<-> swift line {setup.line_no} {setup.shared_material_source} "
                f"derivation={setup.key_derivation_mode or '-'}"
            )
            print(f"    matches: {', '.join(matches) if matches else '-'}")
            print(f"    mismatches: {', '.join(mismatches) if mismatches else '-'}")


def print_state_setup_input_report(native: list[NativeStateSetupInput], swift_setups: list[SwiftSetup]) -> None:
    print()
    print(f"Native state-setup input snapshots: {len(native)}")
    if not native:
        print("No Android native state setup input snapshots found.")
        return
    if not swift_setups:
        print("No Swift setup candidates found.")
        return

    print("State setup input comparisons:")
    for item in native[:20]:
        ranked = []
        for setup in swift_setups:
            points = 0
            matches = []
            mismatches = []
            for label, left, right in (
                ("challenge_window", item.transcript_challenge_window_fingerprint, setup.transcript_challenge_window_fingerprint),
                ("material_window", item.transcript_material_window_fingerprint, setup.transcript_material_window_fingerprint),
                ("selected_counter_input", item.selected_counter_input_fingerprint, setup.initial_counter_block_fingerprint),
            ):
                if fingerprint_matches(left, right):
                    points += 4
                    matches.append(label)
                elif left and right and right != "nil":
                    points -= 3
                    mismatches.append(f"{label} android={left} swift={right}")
            ranked.append((points, matches, mismatches, setup))
        ranked.sort(key=lambda entry: entry[0], reverse=True)
        for points, matches, mismatches, setup in ranked[:5]:
            print(
                f"  score={points:>3} android line {item.line_no} direction={item.direction_flag or '-'} "
                f"<-> swift line {setup.line_no} {setup.shared_material_source} "
                f"derivation={setup.key_derivation_mode or '-'}"
            )
            print(f"    matches: {', '.join(matches) if matches else '-'}")
            print(f"    mismatches: {', '.join(mismatches) if mismatches else '-'}")


def print_expansion_report(native: list[NativeExpansionCall], swift_setups: list[SwiftSetup]) -> None:
    print()
    print(f"Native framing expansion calls: {len(native)}")
    if not native:
        print("No Android db17b4 framing expansion calls found.")
        return
    for item in native[:40]:
        print(
            f"  android line {item.line_no} key={item.key_material_fingerprint or '-'} "
            f"context={item.context_source or '-'} len={item.context_length if item.context_length is not None else '-'} "
            f"contextFp={item.context_fingerprint or '-'} "
            f"output={item.output_fingerprint or '-'} outputLine={item.output_line_no or '-'}"
        )
    if not swift_setups:
        return

    print("Expansion context comparisons:")
    for item in native[:20]:
        ranked = []
        for setup in swift_setups:
            points = 0
            matches = []
            mismatches = []
            if fingerprint_matches(item.context_fingerprint, setup.expansion_context_fingerprint):
                points += 4
                matches.append("context_fingerprint")
            elif item.context_fingerprint and setup.expansion_context_fingerprint and setup.expansion_context_fingerprint != "nil":
                points -= 3
                mismatches.append(
                    f"context_fingerprint android={item.context_fingerprint} swift={setup.expansion_context_fingerprint}"
                )
            if item.context_length is not None and setup.expansion_context_length is not None:
                if item.context_length == setup.expansion_context_length:
                    points += 2
                    matches.append("context_length")
                else:
                    points -= 1
                    mismatches.append(
                        f"context_length android={item.context_length} swift={setup.expansion_context_length}"
                    )
            output_matched = False
            if fingerprint_matches(item.output_fingerprint, setup.validation_key_fingerprint):
                points += 5
                matches.append("output_validation_key")
                output_matched = True
            if fingerprint_matches(item.output_fingerprint, setup.cipher_key_fingerprint):
                points += 5
                matches.append("output_cipher_key")
                output_matched = True
            if item.output_fingerprint and not output_matched:
                points -= 3
                mismatches.append(
                    f"output android={item.output_fingerprint} "
                    f"swift_validation={setup.validation_key_fingerprint or '-'} "
                    f"swift_cipher={setup.cipher_key_fingerprint or '-'}"
                )
            if setup.key_derivation_mode:
                matches.append(f"swift_mode={setup.key_derivation_mode}")
            ranked.append((points, matches, mismatches, setup))
        ranked.sort(key=lambda entry: entry[0], reverse=True)
        for points, matches, mismatches, setup in ranked[:5]:
            print(
                f"  score={points:>3} android line {item.line_no} {item.context_source or '-'} "
                f"<-> swift line {setup.line_no} {setup.shared_material_source} "
                f"context={setup.expansion_context_source or '-'} "
                f"len={setup.expansion_context_length if setup.expansion_context_length is not None else '-'}"
            )
            print(f"    matches: {', '.join(matches) if matches else '-'}")
            print(f"    mismatches: {', '.join(mismatches) if mismatches else '-'}")


def print_identity_report(native: list[IdentityFingerprint], swift: list[IdentityFingerprint]) -> None:
    print()
    print(f"Android identity fingerprints: {len(native)}")
    print(f"Mac identity fingerprints: {len(swift)}")
    if not native:
        print("No Android identity public-key fingerprints found.")
    if not swift:
        print("No Mac imported identity public-key fingerprints found.")
    if not native or not swift:
        return

    print("Identity fingerprint comparisons:")
    for native_identity in native[:40]:
        ranked = []
        for swift_identity in swift:
            points = 0
            matches = []
            mismatches = []
            if fingerprint_matches(native_identity.fingerprint, swift_identity.fingerprint):
                points += 6
                matches.append("public_key_fingerprint")
            else:
                points -= 4
                mismatches.append(
                    f"public_key_fingerprint android={native_identity.fingerprint} mac={swift_identity.fingerprint}"
                )
            if native_identity.length is not None and swift_identity.length is not None:
                if native_identity.length == swift_identity.length:
                    points += 1
                    matches.append("length")
                else:
                    mismatches.append(f"length android={native_identity.length} mac={swift_identity.length}")
            ranked.append((points, matches, mismatches, swift_identity))
        ranked.sort(key=lambda item: item[0], reverse=True)
        for points, matches, mismatches, swift_identity in ranked[:5]:
            print(
                f"  score={points:>3} android line {native_identity.line_no} {native_identity.source} "
                f"len={native_identity.length or '-'} "
                f"<-> mac line {swift_identity.line_no} {swift_identity.source} "
                f"{swift_identity.candidate_source or '-'} len={swift_identity.length or '-'}"
            )
            print(f"    matches: {', '.join(matches) if matches else '-'}")
            print(f"    mismatches: {', '.join(mismatches) if mismatches else '-'}")


def self_test() -> None:
    synthetic_events = [
        {
            "type": "airshield.end_link_setup.tx_ready",
            "shared_material_source": "normal.default_label.raw_shared",
            "plaintext_source": "airshield_end_link_setup_state_1",
            "plaintext_length": 30,
            "padded_plaintext_length": 32,
            "cipher_payload_length": 32,
            "outer_frame_length": 41,
            "frame_counter": "9",
            "validation_prefix_hex": "0011223344556677",
            "plaintext_fingerprint": "plainfp",
            "cipher_payload_fingerprint": "cipherfp",
            "outer_frame_fingerprint": "outerfp",
        },
        {
            "type": "airshield.gesture_enable.tx_sent",
            "shared_material_source": "normal.default_label.raw_shared",
            "plaintext_source": "wis_gesture_enable_rpc_seq_1_datax_frame",
            "plaintext_length": 18,
            "padded_plaintext_length": 32,
            "cipher_payload_length": 32,
            "outer_frame_length": 41,
            "frame_counter": "10",
            "validation_prefix_hex": "8899aabbccddeeff",
            "plaintext_fingerprint": "gestureplain",
            "cipher_payload_fingerprint": "gesturecipher",
            "outer_frame_fingerprint": "gestureouter",
        },
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=True, encoding="utf-8") as handle:
        for event in synthetic_events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
        handle.flush()
        frames = swift_frames(Path(handle.name))
    if len(frames) != 2:
        raise SystemExit(f"self-test: expected 2 Swift frames, got {len(frames)}")
    end_frame = frames[0]
    if end_frame.candidate_kind != "end_link_setup" or end_frame.plaintext_fingerprint != "plainfp":
        raise SystemExit("self-test: EndLinkSetup tx_ready fingerprint extraction failed")
    if end_frame.plaintext_len != 30 or end_frame.cipher_payload_fingerprint != "cipherfp":
        raise SystemExit("self-test: EndLinkSetup tx_ready length/cipher extraction failed")
    gesture_frame = frames[1]
    if gesture_frame.candidate_kind != "gesture_enable" or gesture_frame.plaintext_fingerprint != "gestureplain":
        raise SystemExit("self-test: gesture tx_sent fingerprint extraction failed")
    if gesture_frame.outer_frame_fingerprint != "gestureouter" or gesture_frame.frame_counter != "10":
        raise SystemExit("self-test: gesture tx_sent outer/counter extraction failed")
    native = NativeFrame(
        line_no=1,
        event="airshield.framing.pack",
        result="ok",
        direction="pack",
        plaintext_len=30,
        outer_len=41,
        outer_complete=True,
        validation_prefix="0011223344556677",
        cipher_payload_indicator=1,
        cipher_payload_len=32,
        cipher_payload_fingerprint="cipherfp",
        outer_frame_fingerprint="outerfp",
        plaintext_fingerprint="plainfp",
        plaintext_datax_summary="self_test",
    )
    points, matches, mismatches = score(native, end_frame)
    if points <= 0 or {"plaintext_fp", "cipher_fp", "outer_fp", "validation_prefix"} - set(matches):
        raise SystemExit(f"self-test: expected native/swift score matches, got points={points} matches={matches} mismatches={mismatches}")
    with tempfile.TemporaryDirectory() as temp_root:
        root_path = Path(temp_root)
        older = root_path / "reverse/framing-probes/airshield-framing-probe-old.json"
        newer = root_path / "reverse/framing-probes/airshield-framing-probe-new.json"
        newer.parent.mkdir(parents=True, exist_ok=True)
        older.write_text("{}", encoding="utf-8")
        newer.write_text("{}", encoding="utf-8")
        older.touch()
        newer.touch()
        original_repo_root = globals()["repo_root"]
        try:
            globals()["repo_root"] = lambda: root_path
            if latest_repo_artifact(DEFAULT_NATIVE_FRAMING_PROBE_GLOB) != newer:
                raise SystemExit("self-test: expected latest native framing probe selection")
            if latest_repo_artifact("reverse/framing-probes/missing-*.json") is not None:
                raise SystemExit("self-test: expected missing latest artifact to return None")
        finally:
            globals()["repo_root"] = original_repo_root
    print("self-test: OK")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare Android AirShield Framing traces with Mac Swift AirShield candidates."
    )
    parser.add_argument("--android-trace", type=Path, action="append", default=[], help="Frida JSONL capture.")
    parser.add_argument("--native-framing-probe", type=Path, action="append", default=[], help="JSON from probe_airshield_framing.py.")
    parser.add_argument("--mac-session", type=Path, help="Mac session JSONL log.")
    parser.add_argument("--latest-artifacts", action="store_true", help="Use newest saved Android trace, native Framing probe, and Mac session when explicit paths are omitted.")
    parser.add_argument("--android-trace-glob", default=DEFAULT_ANDROID_TRACE_GLOB)
    parser.add_argument("--native-framing-probe-glob", default=DEFAULT_NATIVE_FRAMING_PROBE_GLOB)
    parser.add_argument("--sessions-dir", type=Path, default=DEFAULT_SESSIONS_DIR)
    parser.add_argument("--strict", action="store_true", help="Exit nonzero unless comparable native and Swift frame evidence is present.")
    parser.add_argument("--self-test", action="store_true", help="Run synthetic Swift-frame extraction checks and exit.")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    android_trace_paths = args.android_trace
    native_framing_probe_paths = args.native_framing_probe
    mac_session = args.mac_session
    if args.latest_artifacts:
        if not android_trace_paths:
            latest_trace = latest_repo_artifact(args.android_trace_glob)
            android_trace_paths = [latest_trace] if latest_trace is not None else []
        if not native_framing_probe_paths:
            latest_probe = latest_repo_artifact(args.native_framing_probe_glob)
            native_framing_probe_paths = [latest_probe] if latest_probe is not None else []
        if mac_session is None:
            mac_session = latest_mac_session(args.sessions_dir.expanduser())
    native_frame_items = [
        item for path in android_trace_paths for item in native_frames(path.expanduser())
    ] + [
        item for path in native_framing_probe_paths for item in native_probe_frames(path.expanduser())
    ]
    swift_frame_items = swift_frames(mac_session.expanduser()) if mac_session else []
    print_report(native_frame_items, swift_frame_items)
    strict_failed = args.strict and (not native_frame_items or not swift_frame_items)

    if mac_session and android_trace_paths:
        swift_setup_items = swift_setups(mac_session.expanduser())
        trace_paths = [path.expanduser() for path in android_trace_paths]
        print_kdf_input_report(
            [item for path in trace_paths for item in native_builder_inputs(path)],
            swift_enable_inputs(mac_session.expanduser()),
            swift_setup_items,
        )
        print_shared_hash_report(
            [item for path in trace_paths for item in native_shared_hashes(path)],
            swift_setup_items,
        )
        print_state_setup_input_report(
            [item for path in trace_paths for item in native_state_setup_inputs(path)],
            swift_setup_items,
        )
        print_expansion_report(
            [item for path in trace_paths for item in native_expansion_calls(path)],
            swift_setup_items,
        )
        print_setup_report(
            [item for path in trace_paths for item in native_setups(path)],
            swift_setup_items,
        )
        print_identity_report(
            [item for path in trace_paths for item in native_identity_fingerprints(path)],
            swift_identity_fingerprints(mac_session.expanduser()),
        )
    if strict_failed:
        print()
        print("Overall: FRAMING_MATCH_INCOMPLETE")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
