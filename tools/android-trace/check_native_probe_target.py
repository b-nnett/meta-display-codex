#!/usr/bin/env python3
"""Preflight an Android target for Java-backed AirShield native probes."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_PACKAGE = "com.facebook.stella"
DEFAULT_FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
DEFAULT_OUT_DIR = Path("reverse/native-probe-targets")
DEFAULT_ADB_TIMEOUT_SECONDS = 15.0


def adb_base(serial: str | None) -> list[str]:
    cmd = ["adb"]
    if serial:
        cmd.extend(["-s", serial])
    return cmd


def adb_run(
    serial: str | None,
    args: list[str],
    *,
    timeout: float = DEFAULT_ADB_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    cmd = adb_base(serial) + args
    try:
        return subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        return subprocess.CompletedProcess(
            cmd,
            124,
            stdout=error.stdout or "",
            stderr=(error.stderr or "") + f"\nADB command timed out after {timeout:.0f}s.",
        )


def adb_devices() -> list[dict[str, str]]:
    proc = adb_run(None, ["devices", "-l"])
    devices: list[dict[str, str]] = []
    for line in proc.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        devices.append({
            "serial": parts[0],
            "state": parts[1],
            "detail": " ".join(parts[2:]),
        })
    return devices


def first_device_serial(devices: list[dict[str, str]]) -> str | None:
    for device in devices:
        if device.get("state") == "device":
            return device.get("serial")
    return None


def clean(text: str) -> str:
    return text.strip().replace("\r", "")


def shell_value(serial: str, command: str) -> str | None:
    proc = adb_run(serial, ["shell", command])
    if proc.returncode != 0:
        return None
    value = clean(proc.stdout)
    return value or None


def load_frida() -> tuple[Any | None, str | None]:
    try:
        import frida  # type: ignore
    except ImportError as error:
        return None, str(error)
    return frida, None


def ensure_frida_server(serial: str, path: str, *, start: bool) -> tuple[bool, str]:
    proc = adb_run(serial, ["shell", "ps -A | grep '[f]rida-server'"])
    if proc.returncode == 0 and proc.stdout.strip():
        return True, "running"
    test = adb_run(serial, ["shell", "test", "-x", path])
    if test.returncode != 0:
        return False, f"not found at {path}"
    if not start:
        return False, "present but not running"
    adb_run(serial, ["shell", f"nohup '{path}' >/data/local/tmp/frida-server.log 2>&1 &"])
    time.sleep(1)
    proc = adb_run(serial, ["shell", "ps -A | grep '[f]rida-server'"])
    if proc.returncode == 0 and proc.stdout.strip():
        return True, "started"
    return False, "start attempted but process not observed"


def package_installed(serial: str, package: str) -> tuple[bool, list[str]]:
    proc = adb_run(serial, ["shell", "pm", "path", package])
    paths = [clean(line) for line in proc.stdout.splitlines() if clean(line)]
    return proc.returncode == 0 and bool(paths), paths


def pidof(serial: str, package: str) -> int | None:
    value = shell_value(serial, f"pidof {package}")
    if not value:
        return None
    try:
        return int(value.split()[0])
    except ValueError:
        return None


def java_bridge_check(
    *,
    serial: str,
    package: str,
    force_spawn: bool,
    timeout_seconds: float,
) -> dict[str, Any]:
    frida, error = load_frida()
    if frida is None:
        return {"ok": False, "error": f"Python frida unavailable: {error}"}
    try:
        device = frida.get_device(serial, timeout=timeout_seconds)
    except Exception as error:
        return {"ok": False, "error": f"Unable to get Frida device: {error}"}

    if force_spawn:
        adb_run(serial, ["shell", "am", "force-stop", package])
    current_pid = None if force_spawn else pidof(serial, package)
    spawned = current_pid is None
    pid: int | None = None
    session = None
    try:
        pid = device.spawn([package]) if spawned else current_pid
        session = device.attach(pid)
        if spawned:
            device.resume(pid)
            time.sleep(1)
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
    except Exception as error:
        return {
            "ok": False,
            "error": str(error),
            "pid": pid,
            "spawned": spawned,
        }
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass

    has_java = isinstance(result, dict) and result.get("hasJava") is True
    return {
        "ok": has_java,
        "pid": pid,
        "spawned": spawned,
        "arch": result.get("arch") if isinstance(result, dict) else None,
        "hasJava": result.get("hasJava") if isinstance(result, dict) else None,
    }


def output_path(out_dir: Path, explicit: Path | None) -> Path:
    if explicit:
        return explicit
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return out_dir / f"airshield-native-probe-target-{stamp}.json"


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(path)


def self_test() -> None:
    report = {
        "schema": "codex_airshield_native_probe_target_preflight_v1",
        "checks": {
            "adb_device": {"ok": True},
            "frida_java_bridge": {"ok": False, "hasJava": False},
        },
    }
    ok = all(item.get("ok") is True for item in report["checks"].values())
    if ok:
        raise SystemExit("self-test: expected mixed checks to fail overall")
    print("self-test: OK")


def main() -> int:
    parser = argparse.ArgumentParser(description="Preflight an Android target for AirShield native probes.")
    parser.add_argument("--serial", default=os.environ.get("DEVICE_SERIAL"))
    parser.add_argument("--package", default=DEFAULT_PACKAGE)
    parser.add_argument("--frida-server-path", default=os.environ.get("FRIDA_SERVER_PATH", DEFAULT_FRIDA_SERVER_PATH))
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--skip-adb-root", action="store_true")
    parser.add_argument("--skip-frida-start", action="store_true")
    parser.add_argument("--skip-java-bridge-check", action="store_true")
    parser.add_argument("--force-spawn", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0

    devices = adb_devices()
    serial = args.serial or first_device_serial(devices)
    checks: dict[str, dict[str, Any]] = {}
    if serial is None:
        checks["adb_device"] = {"ok": False, "detail": "no adb device in device state"}
        report = {
            "schema": "codex_airshield_native_probe_target_preflight_v1",
            "createdAt": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "target": {"adbSerial": None, "package": args.package},
            "adbDevices": devices,
            "checks": checks,
        }
        write_report(output_path(args.out_dir, args.output), report)
        return 1

    checks["adb_device"] = {"ok": True, "serial": serial}
    if not args.skip_adb_root:
        root_proc = adb_run(serial, ["root"])
        checks["adb_root"] = {
            "ok": root_proc.returncode == 0,
            "stdout": clean(root_proc.stdout),
            "stderr": clean(root_proc.stderr),
        }
        time.sleep(1)

    checks["boot_completed"] = {
        "ok": shell_value(serial, "getprop sys.boot_completed") == "1",
        "value": shell_value(serial, "getprop sys.boot_completed"),
    }
    checks["device_identity"] = {
        "ok": True,
        "abi": shell_value(serial, "getprop ro.product.cpu.abi"),
        "androidRelease": shell_value(serial, "getprop ro.build.version.release"),
        "id": shell_value(serial, "id"),
    }
    installed, paths = package_installed(serial, args.package)
    checks["package_installed"] = {"ok": installed, "paths": paths}
    frida_server_ok, frida_server_detail = ensure_frida_server(
        serial,
        args.frida_server_path,
        start=not args.skip_frida_start,
    )
    checks["frida_server"] = {"ok": frida_server_ok, "detail": frida_server_detail}
    frida, frida_error = load_frida()
    checks["frida_python"] = {
        "ok": frida is not None,
        "version": getattr(frida, "__version__", None) if frida is not None else None,
        "error": frida_error,
    }
    if not args.skip_java_bridge_check and installed and frida_server_ok and frida is not None:
        checks["frida_java_bridge"] = java_bridge_check(
            serial=serial,
            package=args.package,
            force_spawn=args.force_spawn,
            timeout_seconds=args.timeout,
        )
    elif args.skip_java_bridge_check:
        checks["frida_java_bridge"] = {"ok": None, "detail": "skipped"}
    else:
        checks["frida_java_bridge"] = {"ok": False, "detail": "prerequisites missing"}

    report = {
        "schema": "codex_airshield_native_probe_target_preflight_v1",
        "createdAt": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "target": {"adbSerial": serial, "package": args.package},
        "adbDevices": devices,
        "checks": checks,
    }
    write_report(output_path(args.out_dir, args.output), report)
    required = [
        checks.get("adb_device", {}).get("ok"),
        checks.get("boot_completed", {}).get("ok"),
        checks.get("package_installed", {}).get("ok"),
        checks.get("frida_server", {}).get("ok"),
        checks.get("frida_python", {}).get("ok"),
        checks.get("frida_java_bridge", {}).get("ok"),
    ]
    return 0 if all(item is True for item in required) else 1


if __name__ == "__main__":
    raise SystemExit(main())
