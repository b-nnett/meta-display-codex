#!/usr/bin/env python3
"""Generate static evidence for WIS gesture-stream enable/routing."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Check:
    label: str
    passed: bool
    evidence: str


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def enum_values(text: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for name, value in re.findall(r'\b([A-Z][A-Z0-9_]*)\((-?\d+)\)', text):
        values[name] = int(value)
    for name, value in re.findall(r'new EnumC36239JnL\("([A-Z0-9_]+)",\s*\d+,\s*(-?\d+)\)', text):
        values[name] = int(value)
    for name, value in re.findall(r'A01\("([A-Z0-9_]+)",\s*\d+,\s*(-?\d+)\)', text):
        values[name] = int(value)
    return values


def swift_enum_values(swift: str, enum_name: str) -> dict[str, int]:
    match = re.search(rf"enum {re.escape(enum_name)}: [^{{]+ \{{(?P<body>.*?)\n\s*\}}", swift, re.S)
    if not match:
        return {}
    values: dict[str, int] = {}
    for name, value in re.findall(r"case\s+([A-Za-z0-9_]+)\s*=\s*(\d+)", match.group("body")):
        values[name] = int(value)
    return values


def contains_check(label: str, text: str, needle: str, evidence: str | None = None) -> Check:
    return Check(label, needle in text, evidence or needle)


def regex_check(label: str, text: str, pattern: str, evidence: str) -> Check:
    return Check(label, re.search(pattern, text, re.S) is not None, evidence)


def value_check(label: str, actual: int | None, expected: int, evidence_name: str) -> Check:
    return Check(label, actual == expected, f"{evidence_name}={actual!r}, expected={expected}")


def render(root: Path) -> tuple[str, list[Check]]:
    sources = root / "reverse/meta-ai-jadx/sources"
    app_id_path = sources / "X/EnumC36366JrI.java"
    msg_type_path = sources / "X/EnumC36239JnL.java"
    stream_state_path = sources / "X/EnumC36162JlZ.java"
    service_path = sources / "com/oculus/wearableinputservice/WearableInputService.java"
    stream_req_path = sources / "com/oculus/wearableinputservice/StreamControl$StreamControlReq.java"
    stream_resp_path = sources / "com/oculus/wearableinputservice/StreamControl$StreamControlResp.java"
    stream_update_path = sources / "com/oculus/wearableinputservice/StreamControl$StreamControlUpdate.java"
    rpc_req_path = sources / "com/oculus/wearableinputservice/Rpc$RpcRequest.java"
    rpc_resp_path = sources / "com/oculus/wearableinputservice/Rpc$RpcResponse.java"
    rpc_update_path = sources / "com/oculus/wearableinputservice/Rpc$RpcStreamUpdate.java"
    swift_path = root / "BandBridgeMac/Sources/DataXCodec.swift"
    validation_path = root / "tools/swift/DataXCodecValidation.swift"

    app_ids = enum_values(read(app_id_path))
    message_types = enum_values(read(msg_type_path))
    stream_states = enum_values(read(stream_state_path))
    service = read(service_path)
    stream_req = read(stream_req_path)
    stream_resp = read(stream_resp_path)
    stream_update = read(stream_update_path)
    rpc_req = read(rpc_req_path)
    rpc_resp = read(rpc_resp_path)
    rpc_update = read(rpc_update_path)
    swift = read(swift_path)
    validation = read(validation_path)
    swift_app_ids = swift_enum_values(swift, "AppID")
    swift_message_types = swift_enum_values(swift, "MessageType")

    expected_app_ids = {
        "EMG_IMU": ("emgImu", 2),
        "RPC": ("rpc", 3),
    }
    expected_message_types = {
        "GESTURE": ("gesture", 13),
        "REQUEST": ("request", 20),
        "RESPONSE": ("response", 21),
        "STREAM_UPDATE": ("streamUpdate", 22),
        "AUTHENTICATION": ("authentication", 23),
        "ENCRYPTION": ("encryption", 24),
        "RAW_EMG_IMU_BATCH": ("emgImuBatch", 41),
    }

    checks: list[Check] = []
    for apk_name, (swift_name, expected) in expected_app_ids.items():
        checks.append(value_check(f"APK AppID {apk_name}", app_ids.get(apk_name), expected, apk_name))
        checks.append(value_check(f"Swift AppID {swift_name}", swift_app_ids.get(swift_name), expected, swift_name))
    for apk_name, (swift_name, expected) in expected_message_types.items():
        checks.append(value_check(f"APK message type {apk_name}", message_types.get(apk_name), expected, apk_name))
        checks.append(value_check(f"Swift message type {swift_name}", swift_message_types.get(swift_name), expected, swift_name))

    checks.extend([
        regex_check(
            "WearableInputService gesture enable method sets only enableGestures",
            service,
            r"public final int AJx\(boolean z\).*?StreamControl\$StreamControlReq\.newBuilder\(\).*?setEnableGestures\(z\).*?WearableInputService\.A03",
            "AJx(boolean) builds StreamControlReq and calls setEnableGestures(z)",
        ),
        contains_check(
            "StreamControlReq has enableGestures field member",
            stream_req,
            "public boolean enableGestures_;",
        ),
        contains_check(
            "StreamControlReq enableGestures is protobuf field 3",
            stream_req,
            "ENABLEGESTURES_FIELD_NUMBER = 3",
            "ENABLEGESTURES_FIELD_NUMBER = 3",
        ),
        contains_check(
            "StreamControlResp streamStates is protobuf field 35",
            stream_resp,
            "STREAM_STATES_FIELD_NUMBER = 35",
            "STREAM_STATES_FIELD_NUMBER = 35",
        ),
        contains_check(
            "RpcRequest streamControlReq oneof uses field 4",
            rpc_req,
            "this.requestsCase_ = 4;",
            "RpcRequest.setStreamControlReq sets requestsCase_ = 4",
        ),
        contains_check(
            "RpcResponse streamControlResp oneof uses field 5",
            rpc_resp,
            "this.responsesCase_ = 5;",
            "RpcResponse.setStreamControlResp sets responsesCase_ = 5",
        ),
        contains_check(
            "RpcStreamUpdate streamControlUpdate oneof uses field 16",
            rpc_update,
            "this.updatesCase_ = 16;",
            "RpcStreamUpdate.setStreamControlUpdate sets updatesCase_ = 16",
        ),
        regex_check(
            "StreamControlUpdate active notification is field 3",
            stream_update,
            r'newMessageInfo\(DEFAULT_INSTANCE,\s*".*?\\u0003<\\u0000\\u0007',
            "StreamControlUpdate message info lists fields 1/2/3 resp oneofs and seq 7",
        ),
        value_check(
            "APK stream state ACTIVE",
            stream_states.get("STREAM_STATE_ACTIVE"),
            2,
            "STREAM_STATE_ACTIVE",
        ),
        Check(
            "Swift gesture-enable RPC fixture bytes",
            'Data([0x08, seq, 0x22, 0x02, 0x18, 0x01])' in swift,
            "RpcRequest { seq, field 4 streamControlReq { field 3 true } }",
        ),
        Check(
            "Swift DataX fixture uses RPC request route",
            "WISProtocol.dataXExtensions(appID: .rpc, messageType: .request)" in validation
            and 'payload.hexString == "080122021801"' in validation,
            "DataXCodecValidation covers payload 080122021801 on appID RPC/message REQUEST",
        ),
        Check(
            "Swift decodes gesture route from decrypted/plain DataX",
            "frame.decodedAppID == WISProtocol.AppID.emgImu.rawValue" in (root / "BandBridgeMac/Sources/BluetoothScanner.swift").read_text(encoding="utf-8")
            and "frame.decodedMessageType == WISProtocol.MessageType.gesture.rawValue" in (root / "BandBridgeMac/Sources/BluetoothScanner.swift").read_text(encoding="utf-8"),
            "BluetoothScanner routes appID=2/messageType=13 to GestureEventDecoder",
        ),
    ])

    failed = [check for check in checks if not check.passed]
    lines = [
        "# WIS Gesture Stream Static Report",
        "",
        "This report ties the Mac bridge's gesture-enable request and gesture-frame routing to the Meta AI APK's recovered WIS constants and protobuf wrappers.",
        "",
        "## Result",
        "",
        f"- Status: `{'FAILED' if failed else 'OK'}`" + (f" ({len(failed)} check(s) failed)" if failed else ""),
        "- Conclusion: static evidence supports the Mac bridge's current gesture-enable request shape and DataX routing constants.",
        "- Boundary: this does not prove the encrypted gesture-enable frame is accepted by the live band; live post-handshake validation remains required.",
        "",
        "## Route Constants",
        "",
        "| Purpose | APK source | APK value | Swift symbol | Swift value |",
        "| --- | --- | ---: | --- | ---: |",
    ]
    for apk_name, (swift_name, expected) in expected_app_ids.items():
        lines.append(f"| AppID `{apk_name}` | `{app_id_path.relative_to(root)}` | {app_ids.get(apk_name)} | `WISProtocol.AppID.{swift_name}` | {swift_app_ids.get(swift_name)} |")
    for apk_name, (swift_name, expected) in expected_message_types.items():
        lines.append(f"| Message `{apk_name}` | `{msg_type_path.relative_to(root)}` | {message_types.get(apk_name)} | `WISProtocol.MessageType.{swift_name}` | {swift_message_types.get(swift_name)} |")

    lines.extend([
        "",
        "## Gesture Enable Shape",
        "",
        "- `WearableInputService.AJx(boolean)` builds a `StreamControlReq`, calls `setEnableGestures(z)`, then submits it through the service RPC path.",
        "- `StreamControlReq.enableGestures` is field `3`; the minimal nested request body is `18 01`.",
        "- `RpcRequest.streamControlReq` is field `4`; with `seq = 1`, the minimal Mac payload is `08 01 22 02 18 01`.",
        "- The DataX route for that payload is app ID `3` (`RPC`) and message type `20` (`REQUEST`).",
        "",
        "## Active-State Decode Shape",
        "",
        "- `RpcResponse.streamControlResp` is field `5`.",
        "- `RpcStreamUpdate.streamControlUpdate` is field `16`.",
        "- `StreamControlUpdate.active` is field `3`; `seq` is field `7`.",
        "- `StreamControlResp.streamStates` is field `35`.",
        "- `STREAM_STATE_ACTIVE` is value `2`; the Mac bridge treats stream type `1` with state `2` as gesture stream active.",
        "",
        "## Checks",
        "",
        "| Check | Status | Evidence |",
        "| --- | --- | --- |",
    ])
    for check in checks:
        status = "ok" if check.passed else "FAIL"
        lines.append(f"| {check.label} | `{status}` | `{check.evidence}` |")

    lines.append("")
    return "\n".join(lines), checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze WIS gesture stream static evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("reverse/wis-gesture-stream-static.md"))
    args = parser.parse_args()

    report, checks = render(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(args.output)
    all_ok = all(check.passed for check in checks)
    print("Overall:", "WIS_GESTURE_STREAM_STATIC_OK" if all_ok else "WIS_GESTURE_STREAM_STATIC_FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
