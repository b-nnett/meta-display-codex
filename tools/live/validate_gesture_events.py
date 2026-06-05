#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_GESTURE_EVENTS = Path.home() / "Library/Logs/CodexBandBridge/gesture-events.jsonl"

STANDARD_ACTIONS = [
    "tap",
    "double_tap",
    "swipe_up",
    "swipe_down",
    "swipe_left",
    "swipe_right",
    "press",
    "release",
]

LIVE_BAND_ACTIONS = [
    "tap",
    "double_tap",
    "swipe_up",
    "swipe_down",
    "swipe_in",
    "swipe_out",
    "press",
    "hold",
    "release",
]

FORWARDED_SCHEMA = "codex_band_bridge.gesture.v1"
FORWARDED_APP_ID_EMG_IMU = 2
FORWARDED_MESSAGE_TYPE_GESTURE = 13

FINGER_NAMES = {
    1: "thumb",
    2: "index",
    3: "middle",
    4: "not_applicable",
}

ACTION_NAMES = {
    1: "press",
    2: "release",
    3: "tap",
    4: "double_tap",
    5: "click",
    6: "swipe_up",
    7: "swipe_down",
    8: "swipe_left",
    9: "swipe_right",
    10: "wake",
    11: "swipe_in",
    12: "swipe_out",
    13: "meta_ai",
    14: "partial_press",
    15: "partial_release",
    16: "partial_click",
    17: "partial_up",
    18: "partial_down",
    19: "partial_left",
    20: "partial_right",
}

DERIVED_ACTION_NAMES = {
    1: "tap",
    2: "double_tap",
    3: "hold",
    4: "release",
    5: "swipe_up",
    6: "swipe_down",
    7: "swipe_left",
    8: "swipe_right",
    9: "press",
    10: "hold_release",
}


@dataclass
class Gesture:
    sequence_number: int | None = None
    timestamp: int | None = None
    raw_finger: int | None = None
    raw_action: int | None = None
    derived_action: int | None = None
    emg_batch_id_low: int | None = None
    emg_batch_id_high: int | None = None
    imu_sequence_number: int | None = None
    device_latency_micros: int | None = None
    inference_trigger_emg_offset: int | None = None
    emg_raw_gesture_id: int | None = None
    is_synthetic_gesture: bool | None = None

    @property
    def finger(self) -> str:
        if self.raw_finger is None:
            return "unknown"
        return FINGER_NAMES.get(self.raw_finger, f"finger_{self.raw_finger}")

    @property
    def normalized_action(self) -> str:
        if self.derived_action is not None:
            derived = DERIVED_ACTION_NAMES.get(self.derived_action)
            if derived is not None:
                return derived
        if self.raw_action is None:
            return "unknown"
        return ACTION_NAMES.get(self.raw_action, f"action_{self.raw_action}")


class ProtoReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read_byte(self) -> int | None:
        if self.offset >= len(self.data):
            return None
        value = self.data[self.offset]
        self.offset += 1
        return value

    def read_varint(self) -> int | None:
        value = 0
        shift = 0
        while shift < 64:
            byte = self.read_byte()
            if byte is None:
                return None
            value |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                return value
            shift += 7
        return None

    def skip(self, wire_type: int) -> bool:
        if wire_type == 0:
            return self.read_varint() is not None
        if wire_type == 1:
            self.offset += 8
            return self.offset <= len(self.data)
        if wire_type == 2:
            length = self.read_varint()
            if length is None:
                return False
            self.offset += length
            return self.offset <= len(self.data)
        if wire_type == 5:
            self.offset += 4
            return self.offset <= len(self.data)
        return False


def decode_gesture(payload: bytes) -> Gesture | None:
    reader = ProtoReader(payload)
    gesture = Gesture()
    saw_gesture_field = False
    while reader.offset < len(payload):
        key = reader.read_varint()
        if key is None:
            return None
        field_number = key >> 3
        wire_type = key & 0x07
        if wire_type != 0:
            if not reader.skip(wire_type):
                return None
            continue
        value = reader.read_varint()
        if value is None:
            return None
        if field_number == 1:
            gesture.sequence_number = value
            saw_gesture_field = True
        elif field_number == 2:
            gesture.timestamp = value
            saw_gesture_field = True
        elif field_number == 3:
            gesture.raw_finger = value
            saw_gesture_field = True
        elif field_number == 4:
            gesture.raw_action = value
            saw_gesture_field = True
        elif field_number == 5:
            gesture.derived_action = value
            saw_gesture_field = True
        elif field_number == 6:
            gesture.emg_batch_id_low = value
        elif field_number == 7:
            gesture.emg_batch_id_high = value
        elif field_number == 8:
            gesture.imu_sequence_number = value
        elif field_number == 9:
            gesture.device_latency_micros = value
        elif field_number == 10:
            gesture.inference_trigger_emg_offset = value
        elif field_number == 11:
            gesture.emg_raw_gesture_id = value
        elif field_number == 12:
            gesture.is_synthetic_gesture = value != 0
    return gesture if saw_gesture_field else None


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {error}") from error
            if isinstance(item, dict):
                item["_path"] = str(path)
                item["_line_no"] = line_no
                events.append(item)
    return events


def payload_hex(event: dict[str, Any]) -> str | None:
    value = event.get("frame_payload_hex") or event.get("payload_hex")
    return value if isinstance(value, str) and value else None


def is_gesture_event(event: dict[str, Any]) -> bool:
    if event.get("schema") == FORWARDED_SCHEMA:
        return True
    if event.get("type") == "datax.gesture_decoded":
        return True
    return event.get("event_type") == "gesture" and payload_hex(event) is not None


def int_field(event: dict[str, Any], key: str) -> int | None:
    value = event.get(key)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def validate_event(event: dict[str, Any]) -> tuple[Gesture | None, list[str]]:
    hex_value = payload_hex(event)
    if hex_value is None:
        return None, ["missing frame_payload_hex"]
    try:
        payload = bytes.fromhex(hex_value)
    except ValueError:
        return None, ["frame_payload_hex is not valid hex"]
    gesture = decode_gesture(payload)
    if gesture is None:
        return None, ["payload did not decode as EmgImu GestureEvent"]

    mismatches: list[str] = []
    expected_strings = {
        "normalized_action": gesture.normalized_action,
        "action": gesture.normalized_action,
        "finger": gesture.finger,
    }
    for key, expected in expected_strings.items():
        actual = event.get(key)
        if isinstance(actual, str) and actual != expected:
            mismatches.append(f"{key}: log={actual} decoded={expected}")

    expected_ints = {
        "sequence_number": gesture.sequence_number,
        "timestamp": gesture.timestamp,
        "raw_finger": gesture.raw_finger,
        "raw_action": gesture.raw_action,
        "derived_action": gesture.derived_action,
        "emg_batch_id_low": gesture.emg_batch_id_low,
        "emg_batch_id_high": gesture.emg_batch_id_high,
        "imu_sequence_number": gesture.imu_sequence_number,
        "device_latency_micros": gesture.device_latency_micros,
        "inference_trigger_emg_offset": gesture.inference_trigger_emg_offset,
        "emg_raw_gesture_id": gesture.emg_raw_gesture_id,
    }
    for key, expected in expected_ints.items():
        actual = int_field(event, key)
        if actual is not None and expected != actual:
            mismatches.append(f"{key}: log={actual} decoded={expected}")

    actual_synthetic = event.get("is_synthetic_gesture")
    if isinstance(actual_synthetic, bool) and gesture.is_synthetic_gesture != actual_synthetic:
        mismatches.append(
            f"is_synthetic_gesture: log={actual_synthetic} decoded={gesture.is_synthetic_gesture}"
        )
    return gesture, mismatches


def validate_forwarded_schema(event: dict[str, Any], gesture: Gesture) -> list[str]:
    """Validate the local JSONL/TCP/WS contract produced by EventForwarder."""
    mismatches: list[str] = []
    if event.get("schema") != FORWARDED_SCHEMA:
        mismatches.append(f"schema: expected {FORWARDED_SCHEMA}")
    if event.get("event_type") != "gesture":
        mismatches.append("event_type: expected gesture")

    for key in ("ts", "source", "frame_payload_hex"):
        value = event.get(key)
        if not isinstance(value, str) or not value:
            mismatches.append(f"{key}: expected non-empty string")

    for key, expected in (
        ("action", gesture.normalized_action),
        ("normalized_action", gesture.normalized_action),
        ("finger", gesture.finger),
    ):
        value = event.get(key)
        if not isinstance(value, str):
            mismatches.append(f"{key}: expected string {expected}")
        elif value != expected:
            mismatches.append(f"{key}: log={value} decoded={expected}")

    for key in ("frame_base_id", "app_id", "message_type"):
        if not isinstance(event.get(key), int):
            mismatches.append(f"{key}: expected integer")

    if isinstance(event.get("app_id"), int) and event["app_id"] != FORWARDED_APP_ID_EMG_IMU:
        mismatches.append(f"app_id: expected {FORWARDED_APP_ID_EMG_IMU}, got {event['app_id']}")
    if isinstance(event.get("message_type"), int) and event["message_type"] != FORWARDED_MESSAGE_TYPE_GESTURE:
        mismatches.append(
            f"message_type: expected {FORWARDED_MESSAGE_TYPE_GESTURE}, got {event['message_type']}"
        )

    for key in ("channel_alias", "typed_buffer_type"):
        value = event.get(key)
        if value is not None and not isinstance(value, int):
            mismatches.append(f"{key}: expected integer when present")

    return mismatches


def forwarded_fixture_events() -> list[dict[str, Any]]:
    def event(
        *,
        payload_hex_value: str,
        action: str,
        finger: str,
        raw_finger: int,
        raw_action: int,
        derived_action: int | None = None,
        sequence_number: int | None = None,
        timestamp: int | None = None,
        raw_gesture_id: int | None = None,
        synthetic: bool | None = None,
    ) -> dict[str, Any]:
        item: dict[str, Any] = {
            "schema": FORWARDED_SCHEMA,
            "event_type": "gesture",
            "frame_payload_hex": payload_hex_value,
            "normalized_action": action,
            "action": action,
            "finger": finger,
            "ts": "2026-06-05T12:00:00Z",
            "source": "fixture",
            "frame_base_id": 32768,
            "app_id": FORWARDED_APP_ID_EMG_IMU,
            "message_type": FORWARDED_MESSAGE_TYPE_GESTURE,
            "raw_finger": raw_finger,
            "raw_action": raw_action,
        }
        if derived_action is not None:
            item["derived_action"] = derived_action
        if sequence_number is not None:
            item["sequence_number"] = sequence_number
        if timestamp is not None:
            item["timestamp"] = timestamp
        if raw_gesture_id is not None:
            item["emg_raw_gesture_id"] = raw_gesture_id
        if synthetic is not None:
            item["is_synthetic_gesture"] = synthetic
        return item

    return [
        event(
            payload_hex_value="082a10e707180120032801587b6001",
            action="tap",
            finger="thumb",
            raw_finger=1,
            raw_action=3,
            derived_action=1,
            sequence_number=42,
            timestamp=999,
            raw_gesture_id=123,
            synthetic=True,
        ),
        event(
            payload_hex_value="180120042802",
            action="double_tap",
            finger="thumb",
            raw_finger=1,
            raw_action=4,
            derived_action=2,
        ),
        event(
            payload_hex_value="180420062805",
            action="swipe_up",
            finger="not_applicable",
            raw_finger=4,
            raw_action=6,
            derived_action=5,
        ),
        event(
            payload_hex_value="180420072806",
            action="swipe_down",
            finger="not_applicable",
            raw_finger=4,
            raw_action=7,
            derived_action=6,
        ),
        event(
            payload_hex_value="1801200b",
            action="swipe_in",
            finger="thumb",
            raw_finger=1,
            raw_action=11,
        ),
        event(
            payload_hex_value="1801200c",
            action="swipe_out",
            finger="thumb",
            raw_finger=1,
            raw_action=12,
        ),
        event(
            payload_hex_value="180320012809",
            action="press",
            finger="middle",
            raw_finger=3,
            raw_action=1,
            derived_action=9,
        ),
        event(
            payload_hex_value="180320012803",
            action="hold",
            finger="middle",
            raw_finger=3,
            raw_action=1,
            derived_action=3,
        ),
        event(
            payload_hex_value="180320022804",
            action="release",
            finger="middle",
            raw_finger=3,
            raw_action=2,
            derived_action=4,
        ),
    ]


def write_fixture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in forwarded_fixture_events():
            handle.write(json.dumps(event, sort_keys=True))
            handle.write("\n")


def self_test() -> bool:
    fixtures = [
        (event, event["normalized_action"], event["finger"])
        for event in forwarded_fixture_events()
    ]
    fixture_actions: set[str] = set()
    for fixture, expected_action, expected_finger in fixtures:
        gesture, mismatches = validate_event(fixture)
        if (
            gesture is None
            or mismatches
            or gesture.normalized_action != expected_action
            or gesture.finger != expected_finger
        ):
            return False
        fixture_actions.add(gesture.normalized_action)
        if validate_forwarded_schema(fixture, gesture):
            return False
    if not set(LIVE_BAND_ACTIONS).issubset(fixture_actions):
        return False
    forwarded_gesture, forwarded_mismatches = validate_event(fixtures[0][0])
    if forwarded_gesture is None or forwarded_mismatches:
        return False
    if validate_forwarded_schema(fixtures[0][0], forwarded_gesture):
        return False
    bad_forwarded = dict(fixtures[0][0])
    bad_forwarded["app_id"] = 3
    if not validate_forwarded_schema(bad_forwarded, forwarded_gesture):
        return False
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay Codex Band Bridge gesture JSONL logs and validate normalized names."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help=f"Gesture/session JSONL files. Default: {DEFAULT_GESTURE_EVENTS}",
    )
    parser.add_argument(
        "--expect-action",
        action="append",
        default=[],
        help="Require at least one decoded event with this normalized action. Repeatable.",
    )
    parser.add_argument(
        "--expect-standard-actions",
        action="store_true",
        help="Require the bridge's standard normalized actions: tap, double_tap, directional swipes, press, release.",
    )
    parser.add_argument(
        "--expect-live-band-actions",
        action="store_true",
        help="Require the live validation set from the TODO: tap, double_tap, up/down, in/out, press, hold, release.",
    )
    parser.add_argument(
        "--expect-forwarded-schema",
        action="store_true",
        help="Require every decoded gesture event to use the local codex_band_bridge.gesture.v1 forwarding schema.",
    )
    parser.add_argument(
        "--write-fixture",
        type=Path,
        help="Write a synthetic forwarded-schema JSONL fixture covering the live validation action set.",
    )
    parser.add_argument("--allow-empty", action="store_true", help="Exit OK when no gesture events are present.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable summary.")
    parser.add_argument("--self-test", action="store_true", help="Run the embedded Swift-parity fixture.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.write_fixture:
        write_fixture(args.write_fixture)
        if args.json:
            print(json.dumps({
                "fixture_path": str(args.write_fixture),
                "events": len(forwarded_fixture_events()),
            }, indent=2, sort_keys=True))
        else:
            print(f"Wrote fixture: {args.write_fixture}")
        if not args.paths and not args.self_test:
            return 0

    if args.self_test:
        ok = self_test()
        if args.json:
            print(json.dumps({"self_test": ok}, indent=2, sort_keys=True))
        else:
            print(f"self-test: {'OK' if ok else 'FAIL'}")
        if not ok:
            return 1
        if not args.paths:
            return 0

    paths = args.paths or [DEFAULT_GESTURE_EVENTS]
    all_events: list[dict[str, Any]] = []
    missing_paths = [path for path in paths if not path.expanduser().exists()]
    for path in paths:
        expanded = path.expanduser()
        if expanded.exists():
            all_events.extend(read_jsonl(expanded))

    gesture_events = [event for event in all_events if is_gesture_event(event)]
    decoded: list[tuple[dict[str, Any], Gesture]] = []
    forwarded_schema_events = 0
    failures: list[str] = []
    for event in gesture_events:
        gesture, mismatches = validate_event(event)
        location = f"{event.get('_path')}:{event.get('_line_no')}"
        if gesture is None:
            failures.append(f"{location}: {', '.join(mismatches)}")
            continue
        if mismatches:
            failures.append(f"{location}: " + "; ".join(mismatches))
        if event.get("schema") == FORWARDED_SCHEMA:
            forwarded_schema_events += 1
            forwarded_mismatches = validate_forwarded_schema(event, gesture)
            if forwarded_mismatches:
                failures.append(f"{location}: forwarded schema: " + "; ".join(forwarded_mismatches))
        elif args.expect_forwarded_schema:
            failures.append(f"{location}: expected forwarded schema {FORWARDED_SCHEMA}")
        decoded.append((event, gesture))

    action_counts = Counter(gesture.normalized_action for _, gesture in decoded)
    finger_counts = Counter(gesture.finger for _, gesture in decoded)
    expected_actions = list(args.expect_action)
    if args.expect_standard_actions:
        expected_actions.extend(STANDARD_ACTIONS)
    if args.expect_live_band_actions:
        expected_actions.extend(LIVE_BAND_ACTIONS)
    expected_actions = list(dict.fromkeys(expected_actions))
    missing_actions = [action for action in expected_actions if action_counts[action] == 0]
    if missing_actions:
        failures.append("missing expected actions: " + ", ".join(missing_actions))
    if missing_paths:
        failures.extend(f"missing path: {path}" for path in missing_paths)
    if not decoded and not args.allow_empty:
        failures.append("no gesture events decoded")

    summary = {
        "paths": [str(path.expanduser()) for path in paths],
        "gesture_events": len(gesture_events),
        "decoded_events": len(decoded),
        "forwarded_schema_events": forwarded_schema_events,
        "actions": dict(sorted(action_counts.items())),
        "expected_actions": expected_actions,
        "missing_actions": missing_actions,
        "fingers": dict(sorted(finger_counts.items())),
        "failures": failures,
    }
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"Gesture events: {summary['gesture_events']} found, {summary['decoded_events']} decoded")
        if action_counts:
            print("Actions: " + ", ".join(f"{key}={value}" for key, value in sorted(action_counts.items())))
        if finger_counts:
            print("Fingers: " + ", ".join(f"{key}={value}" for key, value in sorted(finger_counts.items())))
        print(f"Forwarded schema events: {forwarded_schema_events}")
        if failures:
            print("Failures:")
            for failure in failures:
                print(f"  - {failure}")
        else:
            print("Validation: OK")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
