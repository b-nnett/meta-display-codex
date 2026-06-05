#!/usr/bin/env python3
"""Probe Meta's native AirShield Framing.pack on Android through Frida."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_PACKAGE = "com.facebook.stella"
DEFAULT_OUT_DIR = Path("reverse/framing-probes")
DEFAULT_FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
DEFAULT_ADB_TIMEOUT_SECONDS = 15.0

DEFAULT_LOCAL_PRIVATE_KEY_HEX = "01".rjust(64, "0")
DEFAULT_REMOTE_PRIVATE_KEY_HEX = "02".rjust(64, "0")
DEFAULT_CHALLENGE_HEX = "00112233445566778899aabbccddeeff"
DEFAULT_SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
DEFAULT_IV_HEX = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
DEFAULT_PLAINTEXT_HEX = "806080008100000502001000080110011a1050a68dfb8f45453396d60f2cd3528a3d"


def sha256_prefix_hex(data: bytes, prefix_bytes: int = 8) -> str:
    return hashlib.sha256(data).digest()[:prefix_bytes].hex()


def normalize_hex(value: str, *, expected_bytes: int | None = None, name: str) -> str:
    normalized = "".join(str(value).split()).lower()
    if len(normalized) % 2 != 0:
        raise SystemExit(f"{name} hex has odd length.")
    try:
        raw = bytes.fromhex(normalized)
    except ValueError as error:
        raise SystemExit(f"{name} is not valid hex: {error}") from error
    if expected_bytes is not None and len(raw) != expected_bytes:
        raise SystemExit(f"{name} must be {expected_bytes} bytes, got {len(raw)}.")
    return normalized


def hex_summary(hex_value: str) -> dict[str, Any]:
    raw = bytes.fromhex(hex_value)
    return {
        "length": len(raw),
        "prefixHex": raw[:8].hex(),
        "sha256PrefixHex": sha256_prefix_hex(raw),
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
    config: dict[str, Any],
    force_spawn: bool,
    timeout_seconds: float,
) -> dict[str, Any]:
    frida = load_frida()
    device = frida.get_device(serial, timeout=timeout_seconds)

    if force_spawn:
      adb_run(serial, ["shell", "am", "force-stop", package], check=False)

    current_pid = None if force_spawn else pidof(serial, package)
    spawned = current_pid is None
    pid = device.spawn([package]) if spawned else current_pid
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
        probe = script.exports_sync.probe(config)
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
    return args.out_dir / f"airshield-framing-probe-{stamp}.json"


def write_report(path: Path, output: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(path)


def self_test() -> None:
    local_private_key_hex = normalize_hex(DEFAULT_LOCAL_PRIVATE_KEY_HEX, expected_bytes=32, name="local private key")
    challenge_hex = normalize_hex(DEFAULT_CHALLENGE_HEX, expected_bytes=16, name="challenge")
    plaintext_hex = normalize_hex(DEFAULT_PLAINTEXT_HEX, expected_bytes=None, name="plaintext")
    if len(bytes.fromhex(local_private_key_hex)) != 32:
        raise SystemExit("self-test: expected local private key length")
    try:
        normalize_hex("abc", name="odd hex")
        raise SystemExit("self-test: expected odd hex to fail")
    except SystemExit as error:
        if "odd length" not in str(error):
            raise
    summary = hex_summary(challenge_hex)
    if summary["length"] != 16 or not summary["sha256PrefixHex"]:
        raise SystemExit("self-test: expected challenge summary")
    path_args = argparse.Namespace(output=None, out_dir=Path("reverse/framing-probes"))
    if not output_path_for_args(path_args).name.startswith("airshield-framing-probe-"):
        raise SystemExit("self-test: expected framing output path")
    output = {
        "schema": "codex_airshield_framing_probe_report_v1",
        "probeStatus": "failed",
        "inputs": {
            "localPrivateKey": hex_summary(local_private_key_hex),
            "challenge": summary,
            "plaintext": hex_summary(plaintext_hex),
        },
        "native": {
            "errors": ["synthetic failure"],
            "pack": {},
        },
    }
    if output["native"]["errors"][0] != "synthetic failure":
        raise SystemExit("self-test: expected failed artifact error")
    print("self-test: OK")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Probe native AirShield Framing.pack with synthetic inputs.")
    parser.add_argument("--serial", default=os.environ.get("DEVICE_SERIAL"))
    parser.add_argument("--package", default=DEFAULT_PACKAGE)
    parser.add_argument("--local-private-key-hex", default=DEFAULT_LOCAL_PRIVATE_KEY_HEX)
    parser.add_argument("--remote-private-key-hex", default=DEFAULT_REMOTE_PRIVATE_KEY_HEX)
    parser.add_argument("--remote-public-key-hex")
    parser.add_argument("--challenge-hex", default=DEFAULT_CHALLENGE_HEX)
    parser.add_argument("--seed-hex", default=DEFAULT_SEED_HEX)
    parser.add_argument("--initialization-vector-hex", default=DEFAULT_IV_HEX)
    parser.add_argument("--plaintext-hex", default=DEFAULT_PLAINTEXT_HEX)
    parser.add_argument("--base", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--no-hkdf", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--force-spawn", action="store_true")
    parser.add_argument("--frida-server-path", default=os.environ.get("FRIDA_SERVER_PATH", DEFAULT_FRIDA_SERVER_PATH))
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--include-secret-material", action="store_true")
    parser.add_argument("--self-test", action="store_true", help="run local validation without ADB/Frida and exit")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    local_private_key_hex = normalize_hex(args.local_private_key_hex, expected_bytes=32, name="local private key")
    remote_private_key_hex = None
    remote_public_key_hex = None
    if args.remote_public_key_hex:
        remote_public_key_hex = normalize_hex(args.remote_public_key_hex, expected_bytes=64, name="remote public key")
    else:
        remote_private_key_hex = normalize_hex(args.remote_private_key_hex, expected_bytes=32, name="remote private key")
    challenge_hex = normalize_hex(args.challenge_hex, expected_bytes=16, name="challenge")
    seed_hex = normalize_hex(args.seed_hex, expected_bytes=32, name="seed")
    iv_hex = normalize_hex(args.initialization_vector_hex, expected_bytes=16, name="initialization vector")
    plaintext_hex = normalize_hex(args.plaintext_hex, expected_bytes=None, name="plaintext")

    config: dict[str, Any] = {
        "localPrivateKeyHex": local_private_key_hex,
        "remotePrivateKeyHex": remote_private_key_hex,
        "remotePublicKeyHex": remote_public_key_hex,
        "challengeHex": challenge_hex,
        "seedHex": seed_hex,
        "initializationVectorHex": iv_hex,
        "plaintextHex": plaintext_hex,
        "base": args.base,
        "usesHKDF": not args.no_hkdf,
    }

    redacted_inputs = {
        "localPrivateKey": hex_summary(local_private_key_hex),
        "remotePrivateKey": hex_summary(remote_private_key_hex) if remote_private_key_hex else None,
        "remotePublicKey": hex_summary(remote_public_key_hex) if remote_public_key_hex else None,
        "challenge": hex_summary(challenge_hex),
        "seed": hex_summary(seed_hex),
        "initializationVector": hex_summary(iv_hex),
        "plaintext": hex_summary(plaintext_hex),
        "base": args.base,
        "usesHKDF": not args.no_hkdf,
    }

    output_path = output_path_for_args(args)
    root = Path(__file__).resolve().parents[2]
    script_path = root / "tools/android-trace/probe_airshield_framing.js"
    serial = args.serial
    try:
        serial = serial or first_adb_device()
        ensure_frida_server(serial, args.frida_server_path)
        probe = run_probe(
            serial=serial,
            package=args.package,
            script_path=script_path,
            config=config,
            force_spawn=args.force_spawn,
            timeout_seconds=args.timeout,
        )
        probe_status = "completed"
    except (RuntimeError, SystemExit) as error:
        probe = {
            "errors": [str(error)],
            "pack": {},
            "target": {
                "adbSerial": serial,
                "package": args.package,
                "pid": None,
                "spawned": None,
            },
        }
        probe_status = "failed"

    output: dict[str, Any] = {
        "schema": "codex_airshield_framing_probe_report_v1",
        "createdAt": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "probeStatus": probe_status,
        "inputs": redacted_inputs,
        "native": probe,
    }
    if args.include_secret_material:
        output["secretMaterial"] = config

    write_report(output_path, output)
    return 0 if not probe.get("errors") else 1


if __name__ == "__main__":
    raise SystemExit(main())
