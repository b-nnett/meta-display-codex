#!/usr/bin/env python3
"""Generate a static evidence report for the first AirShield/DataX write."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Check:
    label: str
    passed: bool
    evidence: str


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def contains_check(label: str, text: str, needle: str, evidence: str | None = None) -> Check:
    return Check(label, needle in text, evidence or needle)


def regex_check(label: str, text: str, pattern: str, evidence: str) -> Check:
    return Check(label, re.search(pattern, text, re.S) is not None, evidence)


def enum_value(text: str, name: str) -> int | None:
    match = re.search(rf'new EnumC30461FtT\("{re.escape(name)}",\s*\d+,\s*(\d+)\)', text)
    if not match:
        return None
    return int(match.group(1))


def request_field_value(text: str, field_name: str) -> int | None:
    match = re.search(rf'public static final int {re.escape(field_name)}_FIELD_NUMBER = (\d+);', text)
    if not match:
        return None
    return int(match.group(1))


EXPECTED_FIRST_WRITE_VECTOR = {
    "schema": "codex_band_bridge.airshield_first_write_vector.v1",
    "base_id": 32768,
    "local_channel_id": 0,
    "service_id": 5,
    "typed_buffer_type": 1,
    "typed_buffer_name": "REQUEST_ENCRYPTION",
    "public_key_length": 64,
    "challenge_length": 16,
    "payload_length": 88,
    "payload_fingerprint": "5524a47ec81421ed",
    "frame_length": 100,
    "frame_fingerprint": "5168a633f4a35471",
    "frame_hex": (
        "8060800081000005020000010a400102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
        "2c2d2e2f303132333435363738393a3b3c3d3e3f401210a0a1a2a3"
        "a4a5a6a7a8a9aaabacadaeaf18002001"
    ),
}


def emit_swift_vector(root: Path) -> tuple[dict[str, object] | None, str | None]:
    script = root / "tools/swift/emit_airshield_first_write_vector.sh"
    try:
        proc = subprocess.run(
            [str(script)],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, str(error)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        return None, detail or f"exit={proc.returncode}"
    try:
        loaded = json.loads(proc.stdout)
    except json.JSONDecodeError as error:
        return None, f"invalid JSON from Swift vector emitter: {error}"
    if not isinstance(loaded, dict):
        return None, "Swift vector emitter did not return a JSON object"
    return loaded, None


def render(root: Path) -> tuple[str, list[Check]]:
    hic_path = root / "reverse/meta-ai-jadx/sources/X/HIc.java"
    hku_path = root / "reverse/meta-ai-jadx/sources/X/HKU.java"
    typed_path = root / "reverse/meta-ai-jadx/sources/X/EnumC30461FtT.java"
    curve_path = root / "reverse/meta-ai-jadx/sources/X/EnumC30621Fyb.java"
    request_path = root / "reverse/meta-ai-jadx/sources/com/oculus/atc/RequestEncryption.java"
    localchannel_path = root / "reverse/native-datax-localchannel-send.md"
    swift_path = root / "BandBridgeMac/Sources/DataXCodec.swift"
    validation_path = root / "tools/swift/DataXCodecValidation.swift"

    hic = read(hic_path)
    hku = read(hku_path)
    typed = read(typed_path)
    curve = read(curve_path)
    request = read(request_path)
    localchannel = read(localchannel_path)
    swift = read(swift_path)
    validation = read(validation_path)
    vector, vector_error = emit_swift_vector(root)

    checks: list[Check] = []
    checks.extend([
        regex_check(
            "Java initiator builds RequestEncryption before send",
            hic,
            r"RequestEncryption\.newBuilder\(\).*?setPublicKey.*?setChallenge.*?setEllipticCurve.*?supportedParameters_\s*=\s*1.*?A13\(localChannel,.*?EnumC30461FtT\.A09\.value\)",
            "HIc.java builder path sets publicKey, challenge, Secp256r1, supportedParameters=1, then sends typed buffer A09.",
        ),
        regex_check(
            "Java responder parses typed buffer A09 as RequestEncryption",
            hku,
            r"if \(i4 == EnumC30461FtT\.A09\.value\)\s*\{\s*from = RequestEncryption\.parseFrom",
            "HKU.java dispatch parses EnumC30461FtT.A09 as RequestEncryption.",
        ),
        regex_check(
            "Java responder feeds RequestEncryption challenge and public key into CipherBuilder",
            hku,
            r"setChallenge\(.*?requestEncryption\.challenge_.*?setRemotePublicKey\(.*?requestEncryption\.publicKey_",
            "HKU.java copies RequestEncryption.challenge_ and publicKey_ into CipherBuilder.",
        ),
        contains_check(
            "Swift encodes RequestEncryption public key field",
            swift,
            "data.appendProtoLengthDelimited(field: 1, publicKey)",
        ),
        contains_check(
            "Swift encodes RequestEncryption challenge field",
            swift,
            "data.appendProtoLengthDelimited(field: 2, challenge)",
        ),
        contains_check(
            "Swift encodes Secp256r1 curve value",
            swift,
            "data.appendProtoVarint(field: 3, 0) // Secp256r1",
        ),
        contains_check(
            "Swift encodes HKDF supported-parameters bit",
            swift,
            "data.appendProtoVarint(field: 4, 1) // supportedParameters bit 0 = HKDF",
        ),
        contains_check(
            "Swift sends AirShield service-5 RequestEncryption DataX extension",
            validation,
            "requestFrame.hexString == \"806080008100000502000001",
            "DataXCodecValidation fixture starts with service alias 5 and typed buffer 1.",
        ),
        regex_check(
            "Native LocalChannel send envelope matches Swift AirShield envelope",
            localchannel,
            r"base id = `localChannelID \^ 0x8000`.*?extension type `1`, value = service id.*?extension type `2`, value = typed-buffer type",
            "reverse/native-datax-localchannel-send.md records ext1 service id, ext2 typed-buffer id, and base id localChannelID ^ 0x8000.",
        ),
    ])

    if vector_error:
        checks.append(Check(
            "Deterministic Swift first-write vector is self-checking",
            False,
            vector_error,
        ))
    elif vector is None:
        checks.append(Check(
            "Deterministic Swift first-write vector is self-checking",
            False,
            "Swift vector emitter returned no report.",
        ))
    else:
        for key, expected in EXPECTED_FIRST_WRITE_VECTOR.items():
            actual = vector.get(key)
            checks.append(Check(
                f"Swift first-write vector {key} matches expected",
                actual == expected,
                f"{key}={actual}",
            ))

    expected_request_fields = {
        "PUBLICKEY": 1,
        "CHALLENGE": 2,
        "ELLIPTICCURVE": 3,
        "SUPPORTEDPARAMETERS": 4,
    }
    for field_name, expected in expected_request_fields.items():
        actual = request_field_value(request, field_name)
        checks.append(Check(
            f"RequestEncryption.{field_name.lower()} field number is {expected}",
            actual == expected,
            f"{field_name}_FIELD_NUMBER={actual}",
        ))

    expected_typed = {
        "REQUEST_ENCRYPTION": 1,
        "ENABLE_ENCRYPTION": 2,
        "END_LINK_SETUP": 4096,
    }
    for name, expected in expected_typed.items():
        actual = enum_value(typed, name)
        checks.append(Check(
            f"Typed message {name} value is {expected}",
            actual == expected,
            f"{name}={actual}",
        ))

    checks.append(regex_check(
        "Secp256r1 enum value is 0",
        curve,
        r"Secp256r1\(0\)",
        "EnumC30621Fyb.Secp256r1(0)",
    ))

    lines = [
        "# AirShield First Write Static Report",
        "",
        "This report verifies the static APK evidence for the first AirShield/DataX write and compares it to the Mac bridge encoder assumptions.",
        "",
        "## Result",
        "",
    ]
    failed = [check for check in checks if not check.passed]
    if failed:
        lines.append(f"- Status: `FAILED` ({len(failed)} check(s) failed)")
    else:
        lines.append("- Status: `OK`")
    lines.extend([
        "",
        "## Recovered First Write",
        "",
        "- Java initiator path: `X/HIc.java` constructs `RequestEncryption` with `publicKey`, `challenge`, `ellipticCurve = Secp256r1`, and `supportedParameters = 1`, then sends it on `EnumC30461FtT.A09.value`.",
        "- Typed-buffer map: `EnumC30461FtT.A09` is `REQUEST_ENCRYPTION = 1`; `A05` is `ENABLE_ENCRYPTION = 2`; `A06` is `END_LINK_SETUP = 4096`.",
        "- Responder path: `X/HKU.java` parses typed buffer `A09` as `RequestEncryption`, extracts `challenge_` and `publicKey_`, and feeds them into `CipherBuilder` before building encryption framing.",
        "- Mac encoder path: `AirShieldLinkSetup.encodeRequestEncryption` writes fields `1`, `2`, `3`, and `4`, and `encodeDataXFrame(.requestEncryption, ...)` wraps it as AirShield service `5`, typed buffer `1`.",
        "- Native DataX writer path: `datax::LocalChannel.open(service=5)` stores the service id in channel metadata, and `LocalChannel.send(type=1, ...)` emits base id `localChannelID ^ 0x8000`, extension type `1` value `5`, and extension type `2` value `1`.",
        "- Deterministic comparison vector: `tools/swift/emit_airshield_first_write_vector.sh` emits a non-secret fixed-input DataX frame with AirShield service `5`, typed buffer `REQUEST_ENCRYPTION = 1`, payload fingerprint `5524a47ec81421ed`, and frame fingerprint `5168a633f4a35471`.",
        "",
        "## Checks",
        "",
        "| Check | Status | Evidence |",
        "| --- | --- | --- |",
    ])
    for check in checks:
        status = "ok" if check.passed else "FAIL"
        evidence = check.evidence.replace("\n", " ")
        lines.append(f"| {check.label} | `{status}` | `{evidence}` |")

    lines.extend([
        "",
        "## Boundary",
        "",
        "This proves the equivalent static first AirShield/DataX write shape. It does not prove byte-for-byte parity with a live official-app transmit because the live official connection could choose a different local channel id before the AirShield service frame. The vector tool gives future live/native traces a stable route and fingerprint fixture for isolating channel-id differences from payload encoding differences.",
        "",
    ])
    return "\n".join(lines), checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AirShield first-write static evidence report.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("reverse/airshield-first-write-static.md"))
    args = parser.parse_args()

    report, checks = render(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(args.output)
    all_ok = all(check.passed for check in checks)
    print("Overall:", "FIRST_WRITE_STATIC_OK" if all_ok else "FIRST_WRITE_STATIC_FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
