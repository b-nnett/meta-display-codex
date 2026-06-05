#!/usr/bin/env python3
"""Fetch Constellation system OTA firmware metadata and optionally download it.

Auth is read from META_AUTHORIZATION only. Do not pass tokens on the command
line, because shell history and process listings can expose them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


DEFAULT_HOST = "https://ar.graph.meta.com/graphql"
FETCH_SYSTEM_UPDATES_CLIENT_DOC_ID = "297447816511635678041173512248"


def authorization_from_env() -> str:
    value = os.environ.get("META_AUTHORIZATION", "").strip()
    if not value:
        raise SystemExit("META_AUTHORIZATION is not set")
    if value.lower().startswith("oauth "):
        return value
    return f"OAuth {value}"


def request_json(url: str, variables: dict, authorization: str, timeout: int) -> dict:
    params = {
        "client_doc_id": FETCH_SYSTEM_UPDATES_CLIENT_DOC_ID,
        "fb_api_req_friendly_name": "FetchSystemUpdates",
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


def extract_update(response: dict) -> dict | None:
    try:
        entries = response["data"]["xar_fetch_constellation_system_updates"]["fetch_update_info_list"]
    except (KeyError, TypeError):
        return None
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        update = entry.get("fetch_update_response")
        if isinstance(update, dict):
            return update
    return None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_file(url: str, dest: Path, timeout: int) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "MetaAI/ota-static-check"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, dest.open("wb") as out:
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--version", required=True, help="Numeric current firmware version.")
    parser.add_argument("--device-type", default="ota.ceres.user")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--out-dir", default="firmware")
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    variables = {
        "fetch_request": {
            "topology_fetch_update_info": [
                {
                    "custom_ota_fetch_type": "CERES_USER_INSIGHTS_NO_DEVICE_IDENTITY",
                    "device_serial_number": args.serial,
                    "device_type": args.device_type,
                    "full_update_only": True,
                    "fw_version": str(args.version),
                }
            ]
        }
    }
    response = request_json(args.host, variables, authorization_from_env(), args.timeout)

    stamp = time.strftime("%Y%m%d-%H%M%S") + f"-{time.time_ns() % 1_000_000_000:09d}"
    safe_type = args.device_type.replace(".", "_")
    response_path = out_dir / f"system_{args.serial}_{args.version}_{safe_type}_{stamp}_response.json"
    response_path.write_text(json.dumps(response, indent=2, sort_keys=True), encoding="utf-8")

    update = extract_update(response)
    summary = {
        "response_path": str(response_path),
        "http_status": response.get("_http_status", 200),
        "device_type": args.device_type,
        "has_update": update is not None,
    }
    if update:
        for key in (
            "target_version",
            "base_version",
            "file_size",
            "file_checksum",
            "release_tag",
            "release_channel_id",
            "build_number_display_name",
            "kek_id",
            "kek_hash",
        ):
            if key in update:
                summary[key] = update[key]
        file_uri = update.get("file_uri")
        if args.download and file_uri:
            dest = out_dir / f"system_{args.serial}_{update.get('target_version', args.version)}_ota.zip"
            download_file(file_uri, dest, args.timeout)
            digest = sha256_file(dest)
            expected = str(update.get("file_checksum") or "").lower()
            summary["download_path"] = str(dest)
            summary["download_sha256"] = digest
            summary["download_bytes"] = dest.stat().st_size
            if expected:
                summary["checksum_match"] = digest == expected
            if update.get("file_size"):
                summary["size_match"] = dest.stat().st_size == int(update["file_size"])

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
