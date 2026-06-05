#!/usr/bin/env python3
"""Probe Meta's native AirShield PrivateKey parser on a rooted Android target.

Default output is redacted: lengths and SHA-256 prefixes only. The input key is
read from a local file or argument and sent over the local Frida session to the
target app process.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_PACKAGE = "com.facebook.stella"
DEFAULT_OUT_DIR = Path("reverse/identity-probes")
DEFAULT_FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
DEFAULT_ADB_TIMEOUT_SECONDS = 15.0


def sha256_prefix(data: bytes, prefix_bytes: int = 8) -> str:
    return hashlib.sha256(data).digest()[:prefix_bytes].hex()


def read_base64(args: argparse.Namespace) -> str:
    if args.base64 and args.base64_file:
        raise SystemExit("Use only one of --base64 or --base64-file.")
    if args.base64_file:
        text = Path(args.base64_file).read_text(encoding="utf-8")
    elif args.base64:
        text = args.base64
    else:
        raise SystemExit("Provide --base64-file or --base64.")
    compact = "".join(text.split())
    if not compact:
        raise SystemExit("Base64 input is empty.")
    try:
        base64.b64decode(compact + ("=" * (-len(compact) % 4)), validate=False)
    except Exception as error:
        raise SystemExit(f"Base64 input could not be decoded locally: {error}") from error
    return compact


def decoded_summary(base64_value: str) -> dict[str, Any]:
    decoded = base64.b64decode(base64_value + ("=" * (-len(base64_value) % 4)), validate=False)
    return {
        "length": len(decoded),
        "prefixHex": decoded[:8].hex(),
        "sha256PrefixHex": sha256_prefix(decoded),
    }


def adb_base(serial: str | None) -> list[str]:
    cmd = ["adb"]
    if serial:
        cmd.extend(["-s", serial])
    return cmd


def adb_run(
    serial: str | None,
    args: list[str],
    check: bool = False,
    timeout: float = DEFAULT_ADB_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    cmd = adb_base(serial) + args
    try:
        return subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        if check:
            raise SystemExit(f"ADB command timed out after {timeout:.0f}s: {' '.join(cmd)}") from error
        return subprocess.CompletedProcess(
            cmd,
            124,
            stdout=error.stdout or "",
            stderr=(error.stderr or "") + f"\nADB command timed out after {timeout:.0f}s.",
        )


def first_adb_device() -> str:
    proc = adb_run(None, ["devices"], check=True)
    for line in proc.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            return parts[0]
    raise SystemExit("No adb device in device state.")


def ensure_frida_server(serial: str, path: str) -> None:
    proc = adb_run(serial, ["shell", "ps -A | grep '[f]rida-server'"], check=False)
    if proc.returncode == 0 and proc.stdout.strip():
        return
    test = adb_run(serial, ["shell", "test", "-x", path], check=False)
    if test.returncode != 0:
        raise SystemExit(f"frida-server is not running and was not found at {path} on {serial}.")
    adb_run(serial, ["shell", f"nohup '{path}' >/data/local/tmp/frida-server.log 2>&1 &"], check=False)
    time.sleep(1)


def pidof(serial: str, package: str) -> int | None:
    proc = adb_run(serial, ["shell", "pidof", package], check=False)
    text = proc.stdout.strip().replace("\r", "")
    if not text:
        return None
    try:
        return int(text.split()[0])
    except ValueError:
        return None


def load_frida():
    try:
        import frida  # type: ignore
    except ImportError as error:
        raise SystemExit(
            "Python module 'frida' is not installed. Install with: python3 -m pip install --user frida-tools"
        ) from error
    return frida


def require_frida_java_bridge(session: Any, *, serial: str, package: str, pid: int) -> None:
    script = session.create_script(
        """
        rpc.exports = {
          check: function() {
            return {
              hasJava: typeof Java !== 'undefined',
              arch: typeof Process !== 'undefined' ? Process.arch : null
            };
          }
        };
        """
    )
    script.load()
    try:
        result = script.exports_sync.check()
    finally:
        script.unload()
    if isinstance(result, dict) and result.get("hasJava") is True:
        return
    arch = result.get("arch") if isinstance(result, dict) else None
    raise RuntimeError(
        "Frida attached but the Java bridge is unavailable "
        f"(serial={serial}, package={package}, pid={pid}, arch={arch}). "
        "Use a rooted Google APIs emulator/device where Frida exposes Java, "
        "start frida-server as root, and keep the Mac frida Python package "
        "version aligned with frida-server."
    )


def run_probe(
    *,
    serial: str,
    package: str,
    script_path: Path,
    base64_value: str,
    force_spawn: bool,
    timeout_seconds: float,
) -> dict[str, Any]:
    frida = load_frida()
    device = frida.get_device(serial, timeout=timeout_seconds)

    pid: int | None = None
    spawned = False
    if force_spawn:
        adb_run(serial, ["shell", "am", "force-stop", package], check=False)

    current_pid = None if force_spawn else pidof(serial, package)
    if current_pid is None:
        pid = device.spawn([package])
        spawned = True
    else:
        pid = current_pid

    try:
        session = device.attach(pid)
    except Exception as error:
        raise RuntimeError(
            f"Unable to attach Frida to {package} pid {pid} on {serial}. "
            "If this is a rooted emulator, run `adb root` and restart frida-server as root."
        ) from error

    try:
        if spawned:
            device.resume(pid)
            time.sleep(1)
        require_frida_java_bridge(session, serial=serial, package=package, pid=pid)
        script = session.create_script(script_path.read_text(encoding="utf-8"))
        script.load()
        probe = script.exports_sync.probe(base64_value)
    finally:
        session.detach()

    if not isinstance(probe, dict):
        raise RuntimeError("Frida probe returned an unexpected result shape.")
    probe["target"] = {
        "adbSerial": serial,
        "package": package,
        "pid": pid,
        "spawned": spawned,
    }
    return probe


def output_path_for_args(args: argparse.Namespace) -> Path:
    if args.output:
        return args.output
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_slot = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in args.slot)
    return args.out_dir / f"airshield-private-key-probe-{safe_slot}-{stamp}.json"


def write_report(path: Path, output: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(path)


def self_test() -> None:
    base64_value = base64.b64encode(b"A" * 32).decode("ascii")
    args = argparse.Namespace(base64=base64_value, base64_file=None)
    if read_base64(args) != base64_value:
        raise SystemExit("self-test: expected direct Base64 input")
    summary = decoded_summary(base64_value)
    if summary["length"] != 32 or not summary["sha256PrefixHex"]:
        raise SystemExit("self-test: expected decoded input summary")
    path_args = argparse.Namespace(output=None, out_dir=Path("reverse/identity-probes"), slot="acdc/app private key")
    output_path = output_path_for_args(path_args)
    if not output_path.name.startswith("airshield-private-key-probe-acdc_app_private_key-"):
        raise SystemExit("self-test: expected sanitized output path")
    failed_probe = {
        "nativeSetRawSucceeded": False,
        "errors": ["synthetic failure"],
        "target": {"adbSerial": None, "package": DEFAULT_PACKAGE, "pid": None, "spawned": None},
    }
    output = {
        "schema": "codex_airshield_private_key_probe_report_v1",
        "probeStatus": "failed",
        "slot": "acdc-app-private-key",
        "input": summary,
        "native": failed_probe,
    }
    if output["native"]["errors"][0] != "synthetic failure":
        raise SystemExit("self-test: expected failed artifact error")
    print("self-test: OK")


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe native AirShield PrivateKey parsing via Frida.")
    parser.add_argument("--serial", default=os.environ.get("DEVICE_SERIAL"))
    parser.add_argument("--package", default=DEFAULT_PACKAGE)
    parser.add_argument("--base64-file")
    parser.add_argument("--base64")
    parser.add_argument("--slot", default="unknown")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--force-spawn", action="store_true")
    parser.add_argument("--frida-server-path", default=os.environ.get("FRIDA_SERVER_PATH", DEFAULT_FRIDA_SERVER_PATH))
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--include-secret-material", action="store_true")
    parser.add_argument("--self-test", action="store_true", help="run local validation without ADB/Frida and exit")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0

    base64_value = read_base64(args)
    output_path = output_path_for_args(args)
    root = Path(__file__).resolve().parents[2]
    script_path = root / "tools/android-trace/probe_airshield_private_key.js"
    serial = args.serial
    try:
        serial = serial or first_adb_device()
        ensure_frida_server(serial, args.frida_server_path)
        probe = run_probe(
            serial=serial,
            package=args.package,
            script_path=script_path,
            base64_value=base64_value,
            force_spawn=args.force_spawn,
            timeout_seconds=args.timeout,
        )
        probe_status = "completed"
    except (RuntimeError, SystemExit) as error:
        probe = {
            "nativeSetRawSucceeded": False,
            "errors": [str(error)],
            "target": {
                "adbSerial": serial,
                "package": args.package,
                "pid": None,
                "spawned": None,
            },
        }
        probe_status = "failed"

    output: dict[str, Any] = {
        "schema": "codex_airshield_private_key_probe_report_v1",
        "createdAt": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "probeStatus": probe_status,
        "slot": args.slot,
        "input": decoded_summary(base64_value),
        "native": probe,
    }
    if args.include_secret_material:
        output["secretMaterial"] = {
            "inputBase64": base64_value,
        }

    write_report(output_path, output)
    return 0 if probe.get("nativeSetRawSucceeded") else 1


if __name__ == "__main__":
    raise SystemExit(main())
