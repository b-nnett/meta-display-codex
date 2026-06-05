#!/usr/bin/env python3
"""Generate static evidence for Neural Band gesture event mapping."""

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


@dataclass(frozen=True)
class EnumEntry:
    name: str
    value: int


EVENT_FIELDS = {
    1: "sequenceNumber_",
    2: "timestamp_",
    3: "finger_",
    4: "action_",
    5: "derivedAction_",
    6: "emgBatchIdLow_",
    7: "emgBatchIdHigh_",
    8: "imuSequenceNumber_",
    9: "deviceLatencyUs_",
    10: "inferenceTriggerEmgOffset_",
    11: "emgRawGestureId_",
    12: "isSyntheticGesture_",
}

FINGER_EXPECTED = {
    1: ("THUMB", "thumb"),
    2: ("INDEX", "index"),
    3: ("MIDDLE", "middle"),
    4: ("NOT_APPLICABLE", "not_applicable"),
}

ACTION_EXPECTED = {
    1: ("PRESS", "press"),
    2: ("RELEASE", "release"),
    3: ("TAP", "tap"),
    4: ("DOUBLETAP", "double_tap"),
    5: ("CLICK", "click"),
    6: ("UP", "swipe_up"),
    7: ("DOWN", "swipe_down"),
    8: ("LEFT", "swipe_left"),
    9: ("RIGHT", "swipe_right"),
    10: ("ACTION_WAKE", "wake"),
    11: ("SWIPE_IN", "swipe_in"),
    12: ("SWIPE_OUT", "swipe_out"),
    13: ("ACTION_IA", "meta_ai"),
    14: ("PARTIAL_PRESS", "partial_press"),
    15: ("PARTIAL_RELEASE", "partial_release"),
    16: ("PARTIAL_CLICK", "partial_click"),
    17: ("PARTIAL_UP", "partial_up"),
    18: ("PARTIAL_DOWN", "partial_down"),
    19: ("PARTIAL_LEFT", "partial_left"),
    20: ("PARTIAL_RIGHT", "partial_right"),
}

DERIVED_EXPECTED = {
    1: ("SINGLE_TAP", "tap"),
    2: ("DOUBLE_TAP", "double_tap"),
    3: ("BUTTON_HOLD", "hold"),
    4: ("BUTTON_RELEASE", "release"),
    5: ("BUTTON_UP", "swipe_up"),
    6: ("BUTTON_DOWN", "swipe_down"),
    7: ("BUTTON_LEFT", "swipe_left"),
    8: ("BUTTON_RIGHT", "swipe_right"),
    9: ("BUTTON_PRESS", "press"),
    10: ("BUTTON_HOLD_RELEASE", "hold_release"),
}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def parse_enum(path: Path) -> dict[int, str]:
    text = read(path)
    entries: dict[int, str] = {}
    for name, value in re.findall(r"\b([A-Z][A-Z0-9_]*)\((-?\d+)\)", text):
        if name != "UNRECOGNIZED":
            entries[int(value)] = name
    return entries


def swift_switch_map(swift: str, switch_name: str) -> dict[int, str]:
    pattern = rf"switch {re.escape(switch_name)} \{{(?P<body>.*?)\n\s*\}}"
    match = re.search(pattern, swift, re.S)
    if not match:
        return {}
    out: dict[int, str] = {}
    for value, label in re.findall(r'case\s+(\d+):\s+return\s+"([^"]+)"', match.group("body")):
        out[int(value)] = label
    return out


def swift_derived_map(swift: str) -> dict[int, str]:
    match = re.search(r"if let derivedAction \{.*?switch derivedAction \{(?P<body>.*?)\n\s*\}\n\s*\}", swift, re.S)
    if not match:
        return {}
    out: dict[int, str] = {}
    for value, label in re.findall(r'case\s+(\d+):\s+return\s+"([^"]+)"', match.group("body")):
        out[int(value)] = label
    return out


def expected_check(
    label: str,
    enum_map: dict[int, str],
    swift_map: dict[int, str],
    expected: dict[int, tuple[str, str]],
) -> Check:
    missing: list[str] = []
    for value, (enum_name, swift_label) in expected.items():
        if enum_map.get(value) != enum_name:
            missing.append(f"enum {value} expected {enum_name}, got {enum_map.get(value)}")
        if swift_map.get(value) != swift_label:
            missing.append(f"swift {value} expected {swift_label}, got {swift_map.get(value)}")
    return Check(label, not missing, "; ".join(missing) if missing else f"{len(expected)} value(s) match")


def event_field_check(event_java: str) -> Check:
    missing = []
    for number, field in EVENT_FIELDS.items():
        constant = field[:-1].upper()
        if field not in event_java:
            missing.append(field)
        if f"FIELD_NUMBER = {number}" not in event_java:
            missing.append(f"{constant} field {number}")
    return Check(
        "GestureEvent field numbers match recovered bridge proto",
        not missing,
        "all 12 fields present" if not missing else "missing: " + ", ".join(missing),
    )


def render(root: Path) -> tuple[str, list[Check]]:
    sources = root / "reverse/meta-ai-jadx/sources"
    event_path = sources / "com/oculus/wearableinputservice/EmgImu$GestureEvent.java"
    finger_path = sources / "X/EnumC36170Jlk.java"
    action_path = sources / "X/EnumC36173Jlo.java"
    derived_path = sources / "X/EnumC36168Jli.java"
    converter_path = sources / "X/C36169Jlj.java"
    protocol_converter_path = sources / "X/C36193JmH.java"
    swift_path = root / "BandBridgeMac/Sources/GestureDecoder.swift"
    validation_path = root / "tools/swift/DataXCodecValidation.swift"

    event_java = read(event_path)
    converter_java = read(converter_path)
    protocol_converter_java = read(protocol_converter_path)
    swift = read(swift_path)
    validation = read(validation_path)

    finger_enum = parse_enum(finger_path)
    action_enum = parse_enum(action_path)
    derived_enum = parse_enum(derived_path)
    swift_fingers = swift_switch_map(swift, "finger")
    swift_actions = swift_switch_map(swift, "action")
    swift_derived = swift_derived_map(swift)

    checks = [
        event_field_check(event_java),
        expected_check("Finger enum values match Swift labels", finger_enum, swift_fingers, FINGER_EXPECTED),
        expected_check("Action enum values match Swift labels", action_enum, swift_actions, ACTION_EXPECTED),
        expected_check("Derived-action enum values match Swift labels", derived_enum, swift_derived, DERIVED_EXPECTED),
        Check(
            "APK converter maps raw UP/DOWN/LEFT/RIGHT as swipe directions",
            all(label in converter_java for label in ("SWIPE_UP", "SWIPE_DOWN", "SWIPE_LEFT", "SWIPE_RIGHT")),
            "C36169Jlj.A01 emits SWIPE_UP/SWIPE_DOWN/SWIPE_LEFT/SWIPE_RIGHT",
        ),
        Check(
            "APK runtime preserves derivedAction separately from action",
            "emgImu$GestureEvent.derivedAction_" in protocol_converter_java and "emgImu$GestureEvent.getAction()" in protocol_converter_java,
            "C36193JmH.A04 builds UniqueEvent with both action and derivedAction",
        ),
        Check(
            "Swift validation covers every recovered action and derived-action label",
            all(name in validation for _, name in ACTION_EXPECTED.values())
            and all(name in validation for _, name in DERIVED_EXPECTED.values()),
            "DataXCodecValidation.swift enumerates all action/derived mappings",
        ),
    ]

    failed = [check for check in checks if not check.passed]
    lines = [
        "# Gesture Event Mapping Static Report",
        "",
        "This report ties the Mac bridge's normalized gesture labels back to the Meta AI APK's recovered wearable-input protobuf classes.",
        "",
        "## Result",
        "",
        f"- Status: `{'FAILED' if failed else 'OK'}`" + (f" ({len(failed)} check(s) failed)" if failed else ""),
        "- Conclusion: static evidence supports the high-level stream as enum-based gesture events, not geometry/raw motion commands.",
        "- Boundary: this does not prove the post-handshake live DataX app/message IDs or encrypted stream routing until a live decrypted gesture frame is captured.",
        "",
        "## Event Shape",
        "",
        f"- Source: `{event_path.relative_to(root)}`",
        "- The event payload has 12 protobuf fields: sequence, timestamp, finger enum, raw action enum, derived-action enum, EMG/IMU batch metadata, raw gesture id, and synthetic flag.",
        "- There are no coordinates, vectors, paths, quaternions, or glasses-display geometry fields in this high-level `GestureEvent` message.",
        "- The APK conversion path `C36193JmH.A04(...)` forwards the raw finger, raw action, derived action, timestamps, raw gesture id, and synthetic flag into its app-side `UniqueEvent` wrapper.",
        "",
        "## Finger Mapping",
        "",
        "| Value | APK enum | Mac label |",
        "| ---: | --- | --- |",
    ]
    for value, (enum_name, swift_label) in FINGER_EXPECTED.items():
        lines.append(f"| {value} | `{enum_name}` | `{swift_label}` |")

    lines.extend([
        "",
        "## Raw Action Mapping",
        "",
        "| Value | APK enum | APK helper label | Mac label | Note |",
        "| ---: | --- | --- | --- | --- |",
    ])
    helper_labels = {
        1: "PRESS",
        2: "RELEASE",
        3: "TAP",
        4: "DOUBLE_TAP",
        5: "CLICK",
        6: "SWIPE_UP",
        7: "SWIPE_DOWN",
        8: "SWIPE_LEFT",
        9: "SWIPE_RIGHT",
        10: "WAKE",
        11: "SWIPE_IN",
        12: "SWIPE_OUT",
        13: "IA",
    }
    for value, (enum_name, swift_label) in ACTION_EXPECTED.items():
        helper = helper_labels.get(value, "not named by C36169Jlj.A01")
        note = ""
        if value in (6, 7, 8, 9):
            note = "APK helper converts direction token to swipe label"
        elif value == 13:
            note = "Mac exposes product-facing alias for APK `IA`"
        elif value >= 14:
            note = "present in enum; helper string table only names values through 13"
        lines.append(f"| {value} | `{enum_name}` | `{helper}` | `{swift_label}` | {note} |")

    lines.extend([
        "",
        "## Derived Action Mapping",
        "",
        "| Value | APK enum | Mac label |",
        "| ---: | --- | --- |",
    ])
    for value, (enum_name, swift_label) in DERIVED_EXPECTED.items():
        lines.append(f"| {value} | `{enum_name}` | `{swift_label}` |")

    lines.extend([
        "",
        "## Checks",
        "",
        "| Check | Status | Evidence |",
        "| --- | --- | --- |",
    ])
    for check in checks:
        status = "ok" if check.passed else "FAIL"
        lines.append(f"| {check.label} | `{status}` | `{check.evidence}` |")

    lines.extend([
        "",
        "## MVP Implication",
        "",
        "- Once AirShield/DataX decrypt is live, the Mac bridge should be able to forward mapped actions directly as normalized events.",
        "- The glasses do not appear to be required to interpret geometry for these high-level events; the band/app protocol already contains named gesture actions.",
        "- Live validation still needs one decrypted gesture payload to confirm the stream app/message IDs and whether `derivedAction` is always preferred over `action` for the user's mapped controls.",
        "",
    ])
    return "\n".join(lines), checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze static gesture event mapping evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("reverse/gesture-event-mapping-static.md"))
    args = parser.parse_args()

    report, checks = render(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(args.output)
    return 0 if all(check.passed for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
