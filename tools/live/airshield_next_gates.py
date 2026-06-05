#!/usr/bin/env python3
"""Run the current AirShield evidence gates and summarize the next blockers."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


TRANSPORT_BLOCKER_STATES = {
    "PAIRING_RESET_RECOMMENDED",
    "STALE_PAIRING",
    "PAIRING_REQUIRED_FOR_PROTECTED_GATT",
}


@dataclass(frozen=True)
class CommandResult:
    name: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class GateResult:
    name: str
    ok: bool
    detail: str
    next_action: str | None
    command: list[str]
    returncode: int


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def relative_command(command: list[str], root: Path) -> str:
    formatted: list[str] = []
    for part in command:
        try:
            path = Path(part)
            if path.is_absolute():
                formatted.append(str(path.relative_to(root)))
                continue
        except ValueError:
            pass
        formatted.append(part)
    return " ".join(formatted)


def run_command(name: str, command: list[str], root: Path) -> CommandResult:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        command,
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return CommandResult(
        name=name,
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def first_matching_line(text: str, prefixes: tuple[str, ...]) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if any(stripped.startswith(prefix) for prefix in prefixes):
            return stripped
    return None


def missing_lines(text: str, *, limit: int = 5) -> list[str]:
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- "):
            lines.append(stripped[2:])
        elif stripped.startswith("[MISSING] "):
            lines.append(stripped.removeprefix("[MISSING] "))
        elif stripped.startswith("missing input:"):
            lines.append(stripped)
        elif stripped.startswith("No ") and stripped.endswith("found."):
            lines.append(stripped)
        if len(lines) >= limit:
            break
    return lines


def parse_status(result: CommandResult) -> GateResult:
    try:
        status = json.loads(result.stdout)
    except json.JSONDecodeError:
        detail = first_matching_line(result.stderr, ("Traceback", "error", "Error")) or "status JSON could not be parsed"
        return GateResult(result.name, False, detail, None, result.command, result.returncode)
    state = str(status.get("state") or "-")
    summary_path = str(status.get("summary_path") or "-")
    next_action = str(status.get("next_action") or "")
    scan = status.get("scan") if isinstance(status.get("scan"), dict) else {}
    exact_count = scan.get("exact_band_seen_count", 0)
    l2cap = status.get("l2cap") if isinstance(status.get("l2cap"), dict) else {}
    opened_psms = l2cap.get("opened_psms") if isinstance(l2cap.get("opened_psms"), list) else []
    detail = f"state={state} exact_seen={exact_count} opened_psms={opened_psms} summary={summary_path}"
    return GateResult(
        result.name,
        result.returncode == 0 and state not in TRANSPORT_BLOCKER_STATES,
        detail,
        next_action or None,
        result.command,
        result.returncode,
    )


def parse_json_identity_import(result: CommandResult) -> GateResult:
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        return parse_text_gate(result)
    current = report.get("input_is_current_schema") is True
    selected_slot = report.get("selected_slot") or "-"
    input_path = report.get("input_path") or "-"
    next_action = report.get("next_step")
    detail = f"current_schema={current} selected_slot={selected_slot} input={input_path}"
    return GateResult(
        result.name,
        result.returncode == 0 and current,
        detail,
        str(next_action) if next_action else None,
        result.command,
        result.returncode,
    )


def parse_text_gate(result: CommandResult) -> GateResult:
    overall = first_matching_line(result.stdout, ("Overall:",))
    missing = missing_lines(result.stdout)
    stderr_hint = first_matching_line(result.stderr, ("No ", "error", "Error", "Traceback"))
    if overall:
        detail = overall
    elif missing:
        detail = "; ".join(missing)
    elif stderr_hint:
        detail = stderr_hint
    else:
        detail = "command completed" if result.returncode == 0 else "command failed"
    next_action = None
    if missing:
        next_action = "; ".join(missing[:3])
    elif result.returncode != 0 and stderr_hint:
        next_action = stderr_hint
    return GateResult(
        result.name,
        result.returncode == 0,
        detail,
        next_action,
        result.command,
        result.returncode,
    )


def build_commands(root: Path) -> list[tuple[str, list[str], str]]:
    python = "python3"
    return [
        (
            "Static DataX framing parity",
            [python, "tools/native/analyze_datax_native.py"],
            "text",
        ),
        (
            "Static first-write parity",
            [python, "tools/static/analyze_airshield_first_write.py"],
            "text",
        ),
        (
            "Static WIS gesture-stream parity",
            [python, "tools/static/analyze_wis_gesture_stream_static.py"],
            "text",
        ),
        (
            "Mac live transport",
            [python, "tools/live/airshield_status.py", "--latest", "--json"],
            "status",
        ),
        (
            "Saved evidence audit",
            [python, "tools/live/airshield_artifact_audit.py", "--latest", "--missing-limit", "6"],
            "text",
        ),
        (
            "Current identity import plan",
            [python, "tools/live/prepare_airshield_identity_import.py", "--latest", "--require-current-schema"],
            "identity_import",
        ),
        (
            "Native probe readiness",
            [python, "tools/live/airshield_readiness.py", "--latest-native-probes"],
            "text",
        ),
        (
            "Identity parity",
            [python, "tools/live/compare_airshield_identity.py", "--latest-artifacts", "--strict"],
            "text",
        ),
        (
            "Framing parity",
            [python, "tools/live/compare_airshield_framing.py", "--latest-artifacts", "--strict"],
            "text",
        ),
    ]


def parse_result(result: CommandResult, parser_name: str) -> GateResult:
    if parser_name == "status":
        return parse_status(result)
    if parser_name == "identity_import":
        return parse_json_identity_import(result)
    return parse_text_gate(result)


def summarize(gates: list[GateResult]) -> dict[str, Any]:
    blocked = [gate for gate in gates if not gate.ok]
    return {
        "schema": "codex_airshield_next_gates_v1",
        "overall": "READY" if not blocked else "BLOCKED",
        "blocked_count": len(blocked),
        "gate_count": len(gates),
        "gates": [
            {
                "name": gate.name,
                "ok": gate.ok,
                "detail": gate.detail,
                "next_action": gate.next_action,
                "returncode": gate.returncode,
                "command": gate.command,
            }
            for gate in gates
        ],
    }


def print_report(gates: list[GateResult], root: Path) -> None:
    blocked = [gate for gate in gates if not gate.ok]
    print("AirShield Next Gates")
    print(f"Overall: {'READY' if not blocked else 'BLOCKED'} ({len(gates) - len(blocked)}/{len(gates)} passed)")
    print()
    for gate in gates:
        marker = "OK" if gate.ok else "BLOCKED"
        print(f"[{marker}] {gate.name}")
        print(f"  detail: {gate.detail}")
        if gate.next_action:
            print(f"  next: {gate.next_action}")
        print(f"  command: {relative_command(gate.command, root)}")
        if gate.returncode:
            print(f"  exit: {gate.returncode}")
        print()


def self_test() -> None:
    status = CommandResult(
        name="Mac live transport",
        command=["python3", "tools/live/airshield_status.py", "--latest", "--json"],
        returncode=0,
        stdout=json.dumps({
            "state": "PAIRING_RESET_RECOMMENDED",
            "next_action": "Reset pairing.",
            "summary_path": "/tmp/session-summary.json",
            "scan": {"exact_band_seen_count": 1},
            "l2cap": {"opened_psms": []},
        }),
        stderr="",
    )
    status_gate = parse_status(status)
    if status_gate.ok or "PAIRING_RESET_RECOMMENDED" not in status_gate.detail:
        raise SystemExit("self-test: expected pairing reset status to block")

    identity = CommandResult(
        name="Current identity import plan",
        command=["python3", "tools/live/prepare_airshield_identity_import.py", "--latest", "--require-current-schema"],
        returncode=4,
        stdout=json.dumps({
            "input_is_current_schema": False,
            "selected_slot": None,
            "input_path": "reverse/extracted-state/old.json",
            "next_step": "Rerun extract_airshield_state.py with --require-identity-slot using the current extractor before importing.",
        }),
        stderr="",
    )
    identity_gate = parse_json_identity_import(identity)
    if identity_gate.ok or "current_schema=False" not in identity_gate.detail:
        raise SystemExit("self-test: expected stale identity import to block")

    audit = CommandResult(
        name="Saved evidence audit",
        command=["python3", "tools/live/airshield_artifact_audit.py", "--latest"],
        returncode=1,
        stdout="\n".join([
            "Best Native PrivateKey Probe",
            "  no artifacts found",
            "Overall: EVIDENCE_INCOMPLETE",
        ]),
        stderr="",
    )
    audit_gate = parse_text_gate(audit)
    if audit_gate.ok or audit_gate.detail != "Overall: EVIDENCE_INCOMPLETE":
        raise SystemExit("self-test: expected evidence audit incomplete gate")

    ready = summarize([GateResult("ok", True, "done", None, ["true"], 0)])
    if ready["overall"] != "READY":
        raise SystemExit("self-test: expected all-ok summary to be ready")
    blocked = summarize([status_gate, identity_gate, audit_gate])
    if blocked["overall"] != "BLOCKED" or blocked["blocked_count"] != 3:
        raise SystemExit("self-test: expected blocked summary")
    print("self-test: OK")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the current live/static AirShield gates and summarize remaining blockers."
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable gate summary.")
    parser.add_argument("--self-test", action="store_true", help="Run synthetic parser checks and exit.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    root = repo_root()
    gates: list[GateResult] = []
    for name, command, parser_name in build_commands(root):
        result = run_command(name, command, root)
        gates.append(parse_result(result, parser_name))
    if args.json:
        print(json.dumps(summarize(gates), indent=2, sort_keys=True))
    else:
        print_report(gates, root)
    return 0 if all(gate.ok for gate in gates) else 1


if __name__ == "__main__":
    raise SystemExit(main())
