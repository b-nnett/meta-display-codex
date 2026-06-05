#!/usr/bin/env python3
"""Fetch Stella/smart-glasses OTA metadata using the Meta AI app request shape.

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


DEFAULT_FIELDS = (
    "update_interval,"
    "ota{"
    "download_uri,target_version,base_version,file_size,release_channel_id,"
    "file_checksum,release_tag,release_notes_cms,extra_install_options,"
    "build_number_display_name"
    "},"
    "metadata{release_notes,build_number_display_name}"
)


def bearer_from_env() -> str:
    value = os.environ.get("META_AUTHORIZATION", "").strip()
    if not value:
        raise SystemExit("META_AUTHORIZATION is not set")
    if value.lower().startswith("oauth "):
        return value
    return f"OAuth {value}"


def request_json(
    url: str,
    params: dict[str, str],
    authorization: str,
    timeout: int,
    include_authorization_header: bool,
) -> dict:
    body = urllib.parse.urlencode(params).encode("utf-8")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": "MetaAI/ota-static-check",
    }
    if include_authorization_header:
        headers["Authorization"] = authorization
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            parsed = {"error": raw.decode("utf-8", "replace")}
        parsed["_http_status"] = exc.code
        return parsed
    return json.loads(raw.decode("utf-8", "replace"))


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


def extract_ota(response: dict) -> dict | None:
    ota = response.get("ota")
    if isinstance(ota, list) and ota:
        first = ota[0]
        return first if isinstance(first, dict) else None
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--device-type", required=True, help="Example: ota.supernova.user")
    parser.add_argument("--host", default="https://ar-genai.graph.meta.com/firmware_ota_update")
    parser.add_argument("--fields", default=DEFAULT_FIELDS)
    parser.add_argument("--out-dir", default="firmware")
    parser.add_argument("--full-update-only", action="store_true")
    parser.add_argument(
        "--no-method-param",
        action="store_true",
        help="Do not add the app's Graph method=GET form parameter.",
    )
    parser.add_argument(
        "--no-authorization-header",
        action="store_true",
        help="Send access_token only as a form parameter.",
    )
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    params = {
        "access_token": bearer_from_env().removeprefix("OAuth "),
        "device_type": args.device_type.lower(),
        "version": args.version,
        "device_serial": args.serial,
        "fields": args.fields,
    }
    if not args.no_method_param:
        params["method"] = "GET"
    if args.full_update_only:
        params["full_update_only"] = "true"

    response = request_json(
        args.host,
        params,
        bearer_from_env(),
        args.timeout,
        include_authorization_header=not args.no_authorization_header,
    )
    stamp = time.strftime("%Y%m%d-%H%M%S") + f"-{time.time_ns() % 1_000_000_000:09d}"
    safe_type = args.device_type.lower().replace(".", "_")
    safe_host = urllib.parse.urlparse(args.host).netloc.replace(".", "_")
    auth_mode = "authhdr" if not args.no_authorization_header else "paramonly"
    response_path = out_dir / f"glasses_{args.version}_{safe_type}_{safe_host}_{auth_mode}_{stamp}_response.json"
    response_path.write_text(json.dumps(response, indent=2, sort_keys=True), encoding="utf-8")

    ota = extract_ota(response)
    summary = {
        "response_path": str(response_path),
        "http_status": response.get("_http_status", 200),
        "device_type": args.device_type.lower(),
        "host": safe_host,
        "has_ota": ota is not None,
    }
    if ota:
        for key in (
            "target_version",
            "base_version",
            "file_size",
            "release_channel_id",
            "file_checksum",
            "release_tag",
            "build_number_display_name",
        ):
            if key in ota:
                summary[key] = ota[key]
        if args.download and ota.get("download_uri"):
            suffix = ".bin"
            parsed_path = urllib.parse.urlparse(ota["download_uri"]).path
            if parsed_path.endswith(".zip"):
                suffix = ".zip"
            dest = out_dir / f"glasses_{args.version}_{safe_type}_ota{suffix}"
            download_file(ota["download_uri"], dest, args.timeout)
            summary["download_path"] = str(dest)
            digest = sha256_file(dest)
            summary["download_sha256"] = digest
            expected = str(ota.get("file_checksum") or "").lower()
            if expected:
                summary["checksum_match"] = digest == expected

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
