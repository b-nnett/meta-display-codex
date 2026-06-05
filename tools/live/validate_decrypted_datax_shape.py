#!/usr/bin/env python3
"""Validate decrypted AirShield plaintext was routed as inner DataX/WIS traffic."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


KNOWN_ROUTES = {
    (2, 13): "emg_imu.gesture",
    (3, 20): "rpc.request",
    (3, 21): "rpc.response",
    (3, 22): "rpc.stream_update",
    (4, 23): "security.authentication",
    (4, 24): "security.encryption",
}


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


def event_name(event: dict[str, Any]) -> str:
    return str(event.get("event") or event.get("type") or "unknown")


def int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def route_name(app_id: int | None, message_type: int | None) -> str:
    if app_id is None or message_type is None:
        return "unknown"
    return KNOWN_ROUTES.get((app_id, message_type), f"app_{app_id}.message_{message_type}")


def analyze(path: Path) -> dict[str, Any]:
    events = list(read_jsonl(path))
    decrypted_frames = [
        event for event in events
        if event_name(event) == "datax.frame_source"
        and event.get("source") == "airshield.decrypted"
    ]
    route_counts: Counter[str] = Counter()
    unknown_routes = 0
    for event in decrypted_frames:
        app_id = int_or_none(event.get("app_id"))
        message_type = int_or_none(event.get("message_type"))
        name = route_name(app_id, message_type)
        route_counts[name] += 1
        if name == "unknown" or name.startswith("app_"):
            unknown_routes += 1
    decrypted_gestures = [
        event for event in events
        if event_name(event) == "datax.gesture_decoded"
        and event.get("frame_source") == "airshield.decrypted"
    ]
    active_stream_events = [
        event for event in events
        if event_name(event) in ("wis.stream_control.response", "wis.stream_control.update")
        and event.get("source") == "airshield.decrypted"
        and event.get("gesture_stream_active") is True
    ]
    return {
        "path": str(path),
        "event_count": len(events),
        "decrypted_frame_count": len(decrypted_frames),
        "known_decrypted_frame_count": len(decrypted_frames) - unknown_routes,
        "unknown_decrypted_frame_count": unknown_routes,
        "route_counts": dict(sorted(route_counts.items())),
        "decrypted_gesture_count": len(decrypted_gestures),
        "decrypted_active_stream_count": len(active_stream_events),
    }


def self_test() -> None:
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=True, encoding="utf-8") as handle:
        for event in (
            {"type": "datax.frame_source", "source": "airshield.decrypted", "app_id": 3, "message_type": 21},
            {"type": "wis.stream_control.response", "source": "airshield.decrypted", "gesture_stream_active": True},
            {"type": "datax.frame_source", "source": "airshield.decrypted", "app_id": 2, "message_type": 13},
            {"type": "datax.gesture_decoded", "frame_source": "airshield.decrypted", "normalized_action": "tap"},
        ):
            handle.write(json.dumps(event, sort_keys=True) + "\n")
        handle.flush()
        summary = analyze(Path(handle.name))
    if summary["decrypted_frame_count"] != 2:
        raise SystemExit("self-test: expected two decrypted DataX frames")
    if summary["route_counts"].get("rpc.response") != 1:
        raise SystemExit("self-test: expected RPC response route")
    if summary["route_counts"].get("emg_imu.gesture") != 1:
        raise SystemExit("self-test: expected gesture route")
    if summary["decrypted_gesture_count"] != 1:
        raise SystemExit("self-test: expected decrypted gesture event")
    if summary["decrypted_active_stream_count"] != 1:
        raise SystemExit("self-test: expected decrypted active stream event")
    print("self-test: OK")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate decrypted AirShield session plaintext as inner DataX/WIS traffic.")
    parser.add_argument("session", nargs="?", type=Path, help="Mac bridge session JSONL")
    parser.add_argument("--expect-gesture", action="store_true", help="Require at least one decrypted gesture decode.")
    parser.add_argument("--expect-active-stream", action="store_true", help="Require decrypted active WIS stream-control evidence.")
    parser.add_argument("--allow-unknown-routes", action="store_true", help="Do not fail on unknown decrypted app/message routes.")
    parser.add_argument("--json", action="store_true", help="Print JSON summary.")
    parser.add_argument("--self-test", action="store_true", help="Run synthetic validation and exit.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.session is None:
        raise SystemExit("session is required unless --self-test is used")
    summary = analyze(args.session.expanduser())
    failures: list[str] = []
    if summary["decrypted_frame_count"] <= 0:
        failures.append("no decrypted DataX frame_source events")
    if not args.allow_unknown_routes and summary["unknown_decrypted_frame_count"] > 0:
        failures.append(f"unknown decrypted routes={summary['unknown_decrypted_frame_count']}")
    if args.expect_gesture and summary["decrypted_gesture_count"] <= 0:
        failures.append("no decrypted gesture decode events")
    if args.expect_active_stream and summary["decrypted_active_stream_count"] <= 0:
        failures.append("no decrypted active stream-control events")
    if args.json:
        output = dict(summary)
        output["ok"] = not failures
        output["failures"] = failures
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print(f"Session: {summary['path']}")
        print(f"Events: {summary['event_count']}")
        print(f"Decrypted DataX frames: {summary['decrypted_frame_count']}")
        print(f"Known decrypted routes: {summary['known_decrypted_frame_count']}")
        print(f"Unknown decrypted routes: {summary['unknown_decrypted_frame_count']}")
        print("Routes:")
        for route, count in summary["route_counts"].items():
            print(f"  {route}: {count}")
        print(f"Decrypted gestures: {summary['decrypted_gesture_count']}")
        print(f"Decrypted active stream events: {summary['decrypted_active_stream_count']}")
        print("Overall:", "OK" if not failures else "INCOMPLETE")
        for failure in failures:
            print(f"  - {failure}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
