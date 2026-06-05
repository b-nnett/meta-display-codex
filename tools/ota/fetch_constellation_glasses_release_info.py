#!/usr/bin/env python3
"""Fetch Constellation smart-glasses firmware release metadata.

Auth is read from META_AUTHORIZATION only. Do not pass tokens on the command
line, because shell history and process listings can expose them.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


DEFAULT_HOST = "https://ar.graph.meta.com/graphql"
FETCH_FIRMWARE_RELEASE_INFO_CLIENT_DOC_ID = "318196474216952449187050460246"


def authorization_from_env() -> str:
    value = os.environ.get("META_AUTHORIZATION", "").strip()
    if not value:
        raise SystemExit("META_AUTHORIZATION is not set")
    if value.lower().startswith("oauth "):
        return value
    return f"OAuth {value}"


def request_json(url: str, variables: dict, authorization: str, timeout: int) -> dict:
    params = {
        "client_doc_id": FETCH_FIRMWARE_RELEASE_INFO_CLIENT_DOC_ID,
        "fb_api_req_friendly_name": "FetchFirmwareBuildReleaseNotes",
        "server_timestamps": "true",
        "variables": json.dumps(variables, separators=(",", ":")),
    }
    req = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(params).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": authorization,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "MetaAI/ota-static-check",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read()

    text = raw.decode("utf-8", "replace")
    if text.startswith("for (;;);"):
        text = text[len("for (;;);") :]
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = {"error": text}
    parsed["_http_status"] = status
    return parsed


def extract_info(response: dict) -> dict | None:
    try:
        return response["data"]["xar_constellation_firmware_info"]["firmware_update_info"]
    except (KeyError, TypeError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--version", required=True, help="Numeric current firmware version.")
    parser.add_argument("--device-type", required=True, help="Example: ota.hypernova.user")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--out-dir", default="firmware")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    variables = {
        "fetch_request": {
            "constellation_updates_request_info": [
                {
                    "device_type": args.device_type.lower(),
                    "device_serial": args.serial,
                    "device_firmware_version": str(args.version),
                    "device_feature_list": [],
                    "device_artifact_list": [],
                }
            ]
        }
    }
    response = request_json(args.host, variables, authorization_from_env(), args.timeout)

    stamp = time.strftime("%Y%m%d-%H%M%S") + f"-{time.time_ns() % 1_000_000_000:09d}"
    safe_type = args.device_type.lower().replace(".", "_")
    response_path = out_dir / f"glasses_release_info_{args.version}_{safe_type}_{stamp}_response.json"
    response_path.write_text(json.dumps(response, indent=2, sort_keys=True), encoding="utf-8")

    info = extract_info(response)
    summary = {
        "response_path": str(response_path),
        "http_status": response.get("_http_status", 200),
        "device_type": args.device_type.lower(),
        "has_firmware_update_info": info is not None,
    }
    if isinstance(info, dict):
        for key in (
            "target_version",
            "base_version",
            "file_size",
            "file_checksum",
            "release_tag",
            "release_channel_id",
            "build_number_display_name",
        ):
            if key in info:
                summary[key] = info[key]

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
