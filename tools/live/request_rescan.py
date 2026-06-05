#!/usr/bin/env python3
"""Request a CodexBandBridge rescan via its local trigger file."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_TRIGGER_PATH = Path.home() / "Library/Logs/CodexBandBridge/rescan-request.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create the CodexBandBridge rescan trigger file."
    )
    parser.add_argument(
        "--path",
        default=str(DEFAULT_TRIGGER_PATH),
        help=f"Trigger file path. Default: {DEFAULT_TRIGGER_PATH}",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    path = Path(args.path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "codex_band_bridge.rescan_request.v1",
        "requested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": "ble.rescan",
    }
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
