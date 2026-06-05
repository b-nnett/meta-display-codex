#!/usr/bin/env python3
"""Notify when CodexBandBridge reaches an actionable AirShield state."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


STATUS_SCRIPT = Path(__file__).with_name("airshield_status.py")
ACTIONABLE_STATES = {
    "STALE_PAIRING",
    "PAIRING_REQUIRED_FOR_PROTECTED_GATT",
    "PAIRING_RESET_RECOMMENDED",
    "L2CAP_TX_BLOCKED",
    "L2CAP_TX_BLOCKED_GATT_FALLBACK_SENT",
    "L2CAP_CLOSED",
    "READY_TO_SEND_ENABLE_TRUST",
    "READY_TO_SEND_END_LINK_SETUP",
    "READY_TO_SEND_GESTURE_ENABLE",
    "GESTURE_STREAM_ACTIVE",
    "GESTURES_DECODED",
}


def load_status(args: argparse.Namespace) -> dict[str, Any]:
    command = [sys.executable, str(STATUS_SCRIPT), "--json"]
    if args.summary:
        command.extend(["--summary", args.summary])
    else:
        command.append("--latest")
        if args.sessions_dir:
            command.extend(["--sessions-dir", args.sessions_dir])
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise SystemExit(detail or f"airshield_status.py failed with exit code {proc.returncode}")
    try:
        loaded = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Could not parse airshield_status.py JSON: {exc}") from None
    if not isinstance(loaded, dict):
        raise SystemExit("airshield_status.py JSON root is not an object")
    return loaded


def should_notify(status: dict[str, Any], *, all_states: bool = False) -> bool:
    state = str(status.get("state") or "")
    return bool(state) and (all_states or state in ACTIONABLE_STATES)


def notification_text(status: dict[str, Any]) -> tuple[str, str]:
    state = str(status.get("state") or "UNKNOWN")
    next_action = str(status.get("next_action") or "Open the bridge status for details.")
    target = status.get("target_band_name")
    suffix = f" ({target})" if target else ""
    return f"Codex Band Bridge: {state}", f"{next_action}{suffix}"


def notify(status: dict[str, Any], *, dry_run: bool) -> None:
    title, message = notification_text(status)
    print(f"{title} - {message}")
    if dry_run:
        return
    if platform.system() != "Darwin":
        return
    script = (
        "display notification "
        f"{json.dumps(message)} "
        "with title "
        f"{json.dumps(title)}"
    )
    subprocess.run(["osascript", "-e", script], check=False)


def notification_key(status: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(status.get("summary_path") or ""),
        str(status.get("state") or ""),
        str(status.get("next_action") or ""),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send a macOS notification when the latest AirShield status needs operator action."
    )
    parser.add_argument("--sessions-dir", help="Session summary directory passed to airshield_status.py.")
    parser.add_argument("--summary", help="Specific session summary JSON file passed to airshield_status.py.")
    parser.add_argument("--watch", type=float, default=0, metavar="SECONDS", help="Poll repeatedly.")
    parser.add_argument("--once", action="store_true", help="Check once and exit.")
    parser.add_argument("--all-states", action="store_true", help="Notify for any non-empty state, not only actionable states.")
    parser.add_argument("--dry-run", action="store_true", help="Print the notification text without calling osascript.")
    parser.add_argument("--self-test", action="store_true", help="Run local notifier selection tests and exit.")
    return parser.parse_args()


def self_test() -> None:
    actionable = {
        "state": "PAIRING_RESET_RECOMMENDED",
        "next_action": "Reset pairing",
        "summary_path": "/tmp/session-summary.json",
        "target_band_name": "Meta Band 000J",
    }
    passive = {
        "state": "WAITING_FOR_AIRSHIELD_VALIDATION",
        "next_action": "Wait",
        "summary_path": "/tmp/session-summary.json",
    }
    if not should_notify(actionable):
        raise SystemExit("self-test: expected pairing reset to notify")
    if should_notify(passive):
        raise SystemExit("self-test: expected passive wait state not to notify by default")
    if not should_notify(passive, all_states=True):
        raise SystemExit("self-test: expected all-states mode to notify")
    title, message = notification_text(actionable)
    if "PAIRING_RESET_RECOMMENDED" not in title or "Meta Band 000J" not in message:
        raise SystemExit("self-test: expected state and target in notification text")
    if notification_key(actionable) != (
        "/tmp/session-summary.json",
        "PAIRING_RESET_RECOMMENDED",
        "Reset pairing",
    ):
        raise SystemExit("self-test: expected stable notification key")
    print("self-test: OK")


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0

    interval = 0 if args.once else max(0, args.watch)
    sent_key: tuple[str, str, str] | None = None

    while True:
        status = load_status(args)
        key = notification_key(status)
        if should_notify(status, all_states=args.all_states) and key != sent_key:
            notify(status, dry_run=args.dry_run)
            sent_key = key
        if interval <= 0:
            return 0
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
