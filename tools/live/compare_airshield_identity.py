#!/usr/bin/env python3
"""Compare redacted AirShield identity evidence across Android prefs, traces, and Mac logs."""

from __future__ import annotations

import argparse
import io
import json
import tempfile
from contextlib import redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


DEFAULT_ANDROID_TRACE_GLOB = "reverse/captures/airshield-datax-*.jsonl"
DEFAULT_IDENTITY_PREFS_GLOB = "reverse/extracted-state/com.facebook.stella-airshield-state-*.json"
DEFAULT_NATIVE_PROBE_GLOB = "reverse/identity-probes/airshield-private-key-probe-*.json"
DEFAULT_SESSIONS_DIR = Path.home() / "Library/Logs/CodexBandBridge/sessions"


@dataclass(frozen=True)
class IdentityEvidence:
    source: str
    kind: str
    fingerprint: str | None
    length: int | None
    slot: str | None = None
    line_no: int | None = None
    detail: str | None = None


def int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def fingerprint_matches(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    left = left.lower()
    right = right.lower()
    return left.startswith(right) or right.startswith(left)


def read_jsonl(path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                loaded = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(loaded, dict):
                yield line_no, loaded


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def latest_repo_artifact(pattern: str, *, label: str) -> Path | None:
    candidates = sorted(
        repo_root().glob(pattern),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def latest_mac_session(sessions_dir: Path) -> Path | None:
    candidates = sorted(
        sessions_dir.glob("session-*.jsonl"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def append_latest(existing: list[Path], latest: Path | None) -> list[Path]:
    if existing or latest is None:
        return existing
    return [latest]


def latest_identity_inputs_ready(
    prefs_items: list[IdentityEvidence],
    probe_items: list[IdentityEvidence],
    trace_items: list[IdentityEvidence],
    mac_items: list[IdentityEvidence],
) -> bool:
    return bool(prefs_items and probe_items and trace_items and mac_items)


def event_name(event: dict[str, Any]) -> str:
    return str(event.get("event") or event.get("type") or "unknown")


def summary_fingerprint(summary: Any) -> str | None:
    if not isinstance(summary, dict):
        return None
    return str_or_none(summary.get("sha256PrefixHex") or summary.get("sha256_prefix") or summary.get("sha256_12"))


def summary_length(summary: Any) -> int | None:
    if not isinstance(summary, dict):
        return None
    return int_or_none(summary.get("length") or summary.get("decoded_length") or summary.get("len"))


def android_trace_evidence(path: Path) -> list[IdentityEvidence]:
    evidence: list[IdentityEvidence] = []
    for line_no, event in read_jsonl(path):
        name = event_name(event)
        if name in (
            "airshield.identity.private_key.set_raw",
            "airshield.identity.private_key.serialize",
        ):
            raw_private = event.get("rawPrivateKey")
            evidence.append(IdentityEvidence(
                source=str(path),
                kind=name,
                fingerprint=summary_fingerprint(raw_private),
                length=summary_length(raw_private),
                line_no=line_no,
            ))
        elif name == "airshield.identity.private_key.recover_public_key":
            public_key = event.get("publicKey")
            evidence.append(IdentityEvidence(
                source=str(path),
                kind=name,
                fingerprint=summary_fingerprint(public_key),
                length=summary_length(public_key),
                line_no=line_no,
            ))
        elif name in (
            "airshield.identity.public_key.set_raw",
            "airshield.identity.public_key.serialize",
        ):
            public_key = event.get("publicKey")
            evidence.append(IdentityEvidence(
                source=str(path),
                kind=name,
                fingerprint=summary_fingerprint(public_key),
                length=summary_length(public_key),
                line_no=line_no,
            ))
        elif name == "airshield.auth.accept_key_candidate":
            public_key = event.get("originalPublicKey")
            evidence.append(IdentityEvidence(
                source=str(path),
                kind=name,
                fingerprint=summary_fingerprint(public_key),
                length=summary_length(public_key),
                line_no=line_no,
                detail=f"variant={event.get('variant')} asMain={event.get('asMain')}",
            ))
        elif name == "airshield.acceptAuthentication":
            public_key = event.get("publicKey")
            evidence.append(IdentityEvidence(
                source=str(path),
                kind=name,
                fingerprint=summary_fingerprint(public_key) or str_or_none(event.get("pubKeyFingerprint")),
                length=summary_length(public_key) or int_or_none(event.get("pubKeyLength")),
                line_no=line_no,
            ))
    return [item for item in evidence if item.fingerprint]


def mac_session_evidence(path: Path) -> list[IdentityEvidence]:
    evidence: list[IdentityEvidence] = []
    for line_no, event in read_jsonl(path):
        name = event_name(event)
        if name not in (
            "airshield.identity.imported",
            "airshield.identity.loaded",
            "airshield.probe_state_ready",
        ):
            continue
        identity = event.get("identity") if name == "airshield.probe_state_ready" else event
        if not isinstance(identity, dict):
            continue
        slot = str_or_none(identity.get("slot"))
        private_fp = str_or_none(identity.get("private_key_fingerprint"))
        if private_fp:
            evidence.append(IdentityEvidence(
                source=str(path),
                kind=f"{name}.private_key",
                fingerprint=private_fp,
                length=int_or_none(identity.get("raw_private_key_length")),
                slot=slot,
                line_no=line_no,
            ))
        public_fp = str_or_none(identity.get("public_key_fingerprint"))
        if public_fp and public_fp != "nil":
            evidence.append(IdentityEvidence(
                source=str(path),
                kind=f"{name}.public_key.primary",
                fingerprint=public_fp,
                length=int_or_none(identity.get("raw_public_key_length")),
                slot=slot,
                line_no=line_no,
            ))
        accepted_auth_fp = str_or_none(identity.get("accepted_auth_public_key_fingerprint"))
        if accepted_auth_fp and accepted_auth_fp != "nil":
            evidence.append(IdentityEvidence(
                source=str(path),
                kind=f"{name}.accepted_auth_public_key.primary",
                fingerprint=accepted_auth_fp,
                length=int_or_none(identity.get("accepted_auth_public_key_length")),
                slot=slot,
                line_no=line_no,
            ))
        for candidate in identity.get("public_key_candidates") or []:
            if not isinstance(candidate, dict):
                continue
            candidate_fp = str_or_none(candidate.get("public_key_fingerprint"))
            if candidate_fp and candidate_fp != "nil":
                evidence.append(IdentityEvidence(
                    source=str(path),
                    kind=f"{name}.public_key.candidate",
                    fingerprint=candidate_fp,
                    length=int_or_none(candidate.get("raw_public_key_length")),
                    slot=slot,
                    line_no=line_no,
                    detail=str_or_none(candidate.get("source")),
                ))
            candidate_accepted_auth_fp = str_or_none(candidate.get("accepted_auth_public_key_fingerprint"))
            if candidate_accepted_auth_fp and candidate_accepted_auth_fp != "nil":
                evidence.append(IdentityEvidence(
                    source=str(path),
                    kind=f"{name}.accepted_auth_public_key.candidate",
                    fingerprint=candidate_accepted_auth_fp,
                    length=int_or_none(candidate.get("accepted_auth_public_key_length")),
                    slot=slot,
                    line_no=line_no,
                    detail=str_or_none(candidate.get("source")),
                ))
    return evidence


def identity_prefs_rows(path: Path) -> list[dict[str, Any]]:
    loaded = read_json(path)
    if isinstance(loaded, list):
        return [row for row in loaded if isinstance(row, dict)]
    if isinstance(loaded, dict):
        slots = loaded.get("identity_key_slots")
        if isinstance(slots, dict):
            rows = []
            for slot, summary in slots.items():
                if isinstance(summary, dict) and summary.get("present"):
                    rows.append({
                        "slot": slot,
                        "decoded_length": summary.get("base64_decoded_length"),
                        "sha256_prefix": summary.get("base64_decoded_sha256"),
                        "file": summary.get("path"),
                    })
            return rows
    return []


def prefs_evidence(path: Path) -> list[IdentityEvidence]:
    evidence: list[IdentityEvidence] = []
    for row in identity_prefs_rows(path):
        fingerprint = str_or_none(row.get("sha256_prefix") or row.get("base64_decoded_sha256"))
        if not fingerprint:
            continue
        evidence.append(IdentityEvidence(
            source=str(path),
            kind="android_prefs.private_key_slot",
            fingerprint=fingerprint,
            length=int_or_none(row.get("decoded_length") or row.get("base64_decoded_length")),
            slot=str_or_none(row.get("slot")),
            detail=str_or_none(row.get("file")),
        ))
    return evidence


def native_probe_summary_evidence(
    path: Path,
    *,
    kind: str,
    summary: Any,
    slot: str | None,
) -> IdentityEvidence | None:
    if not isinstance(summary, dict):
        return None
    fingerprint = str_or_none(summary.get("sha256PrefixHex") or summary.get("sha256_prefix"))
    if not fingerprint:
        return None
    return IdentityEvidence(
        source=str(path),
        kind=kind,
        fingerprint=fingerprint,
        length=int_or_none(summary.get("length") or summary.get("decoded_length")),
        slot=slot,
    )


def native_probe_evidence(path: Path) -> list[IdentityEvidence]:
    loaded = read_json(path)
    if not isinstance(loaded, dict):
        return []
    slot = str_or_none(loaded.get("slot"))
    native = loaded.get("native")
    if not isinstance(native, dict):
        return []

    evidence: list[IdentityEvidence] = []
    rows = [
        ("native_probe.private_key.input", loaded.get("input")),
        ("native_probe.private_key.set_raw", native.get("inputRawPrivateKey")),
        ("native_probe.private_key.serialize", native.get("nativeSerialize")),
        ("native_probe.private_key.recover_public_key", native.get("nativeRecoverPublicKey")),
        ("native_probe.accepted_auth_public_key", native.get("acceptedAuthenticationPublicKey")),
    ]
    for kind, summary in rows:
        item = native_probe_summary_evidence(path, kind=kind, summary=summary, slot=slot)
        if item is not None:
            evidence.append(item)
    return evidence


def classify(items: list[IdentityEvidence], needle: str) -> list[IdentityEvidence]:
    return [item for item in items if needle in item.kind]


def format_item(item: IdentityEvidence) -> str:
    where = f" line {item.line_no}" if item.line_no is not None else ""
    slot = f" slot={item.slot}" if item.slot else ""
    detail = f" {item.detail}" if item.detail else ""
    return (
        f"{item.kind}{where}{slot} len={item.length if item.length is not None else '-'} "
        f"fp={item.fingerprint or '-'}{detail}"
    )


def print_items(title: str, items: list[IdentityEvidence]) -> None:
    print(title)
    if not items:
        print("  none")
        return
    for item in items:
        print(f"  {format_item(item)}")


def print_comparisons(
    title: str,
    left: list[IdentityEvidence],
    right: list[IdentityEvidence],
    left_name: str,
    right_name: str,
) -> bool:
    print()
    print(title)
    if not left or not right:
        print(f"  missing input: {left_name}={len(left)} {right_name}={len(right)}")
        return False
    matched = False
    for left_item in left:
        ranked = []
        for right_item in right:
            points = 0
            matches = []
            mismatches = []
            if fingerprint_matches(left_item.fingerprint, right_item.fingerprint):
                points += 6
                matches.append("fingerprint")
            else:
                points -= 4
                mismatches.append(f"fingerprint {left_name}={left_item.fingerprint} {right_name}={right_item.fingerprint}")
            if left_item.length is not None and right_item.length is not None:
                if left_item.length == right_item.length:
                    points += 1
                    matches.append("length")
                else:
                    mismatches.append(f"length {left_name}={left_item.length} {right_name}={right_item.length}")
            ranked.append((points, matches, mismatches, right_item))
        ranked.sort(key=lambda item: item[0], reverse=True)
        for points, matches, mismatches, right_item in ranked[:5]:
            if points > 0:
                matched = True
            print(f"  score={points:>3} {left_name}: {format_item(left_item)}")
            print(f"            {right_name}: {format_item(right_item)}")
            print(f"    matches: {', '.join(matches) if matches else '-'}")
            print(f"    mismatches: {', '.join(mismatches) if mismatches else '-'}")
    return matched


def self_test() -> None:
    private_fp = "aabbccddeeff0011"
    public_fp = "1122334455667788"
    accepted_public_fp = "9988776655443322"
    with (
        tempfile.NamedTemporaryFile("w", suffix="-prefs.json", delete=True, encoding="utf-8") as prefs_handle,
        tempfile.NamedTemporaryFile("w", suffix="-probe.json", delete=True, encoding="utf-8") as probe_handle,
        tempfile.NamedTemporaryFile("w", suffix="-trace.jsonl", delete=True, encoding="utf-8") as trace_handle,
        tempfile.NamedTemporaryFile("w", suffix="-mac.jsonl", delete=True, encoding="utf-8") as mac_handle,
    ):
        json.dump(
            {
                "identity_key_slots": {
                    "acdc-app-private-key": {
                        "present": True,
                        "base64_decoded_length": 32,
                        "base64_decoded_sha256": private_fp,
                        "path": "/data/data/com.facebook.stella/shared_prefs/acdc-shared-pref.xml",
                    }
                }
            },
            prefs_handle,
        )
        prefs_handle.flush()

        json.dump(
            {
                "slot": "acdc-app-private-key",
                "input": {"length": 32, "sha256PrefixHex": private_fp},
                "native": {
                    "inputRawPrivateKey": {"length": 32, "sha256PrefixHex": private_fp},
                    "nativeSerialize": {"length": 32, "sha256PrefixHex": private_fp},
                    "nativeRecoverPublicKey": {"length": 64, "sha256PrefixHex": public_fp},
                    "acceptedAuthenticationPublicKey": {"length": 64, "sha256PrefixHex": accepted_public_fp},
                },
            },
            probe_handle,
        )
        probe_handle.flush()

        for event in (
            {
                "event": "airshield.identity.private_key.set_raw",
                "rawPrivateKey": {"length": 32, "sha256PrefixHex": private_fp},
            },
            {
                "event": "airshield.identity.private_key.recover_public_key",
                "publicKey": {"length": 64, "sha256PrefixHex": public_fp},
            },
            {
                "event": "airshield.acceptAuthentication",
                "publicKey": {"length": 64, "sha256PrefixHex": accepted_public_fp},
            },
        ):
            trace_handle.write(json.dumps(event, sort_keys=True) + "\n")
        trace_handle.flush()

        mac_handle.write(json.dumps({
            "type": "airshield.identity.imported",
            "slot": "acdc-app-private-key",
            "private_key_fingerprint": private_fp,
            "raw_private_key_length": 32,
            "public_key_fingerprint": public_fp,
            "raw_public_key_length": 64,
            "accepted_auth_public_key_fingerprint": accepted_public_fp,
            "accepted_auth_public_key_length": 64,
            "public_key_candidates": [
                {
                    "source": "self-test",
                    "public_key_fingerprint": public_fp,
                    "raw_public_key_length": 64,
                    "accepted_auth_public_key_fingerprint": accepted_public_fp,
                    "accepted_auth_public_key_length": 64,
                }
            ],
        }, sort_keys=True) + "\n")
        mac_handle.flush()

        prefs_items = prefs_evidence(Path(prefs_handle.name))
        probe_items = native_probe_evidence(Path(probe_handle.name))
        trace_items = android_trace_evidence(Path(trace_handle.name))
        mac_items = mac_session_evidence(Path(mac_handle.name))

    if len(prefs_items) != 1:
        raise SystemExit(f"self-test: expected one prefs item, got {len(prefs_items)}")
    if len(classify(probe_items, "private_key.serialize")) != 1:
        raise SystemExit("self-test: expected native probe serialize evidence")
    if len(classify(probe_items, "recover_public_key")) != 1:
        raise SystemExit("self-test: expected native probe recovered public-key evidence")
    if len(classify(trace_items, "private_key.set_raw")) != 1:
        raise SystemExit("self-test: expected Android trace private-key load evidence")
    if len(classify(trace_items, "acceptAuthentication")) != 1:
        raise SystemExit("self-test: expected Android trace acceptAuthentication evidence")
    if len(classify(mac_items, "private_key")) != 1:
        raise SystemExit("self-test: expected Mac private-key evidence")
    if len(classify(mac_items, "public_key")) < 2:
        raise SystemExit("self-test: expected Mac public-key candidate evidence")
    quiet_output = io.StringIO()
    with redirect_stdout(quiet_output):
        private_match = print_comparisons(
            "self-test private match",
            prefs_items,
            classify(mac_items, "private_key"),
            "prefs",
            "mac",
        )
        public_match = print_comparisons(
            "self-test probe public match",
            classify(probe_items, "recover_public_key"),
            classify(mac_items, "public_key"),
            "probe",
            "mac",
        )
        mismatch_match = print_comparisons(
            "self-test mismatch",
            [IdentityEvidence(source="left", kind="left", fingerprint="deadbeef", length=32)],
            [IdentityEvidence(source="right", kind="right", fingerprint="feedface", length=32)],
            "left",
            "right",
        )
    if not private_match:
        raise SystemExit("self-test: expected prefs private-key slot to match Mac import")
    if not public_match:
        raise SystemExit("self-test: expected probe recovered public key to match Mac candidate")
    if mismatch_match:
        raise SystemExit("self-test: expected mismatched fingerprints to fail")
    if not latest_identity_inputs_ready(prefs_items, probe_items, trace_items, mac_items):
        raise SystemExit("self-test: expected populated latest inputs to be ready")
    if latest_identity_inputs_ready([], probe_items, trace_items, mac_items):
        raise SystemExit("self-test: expected missing prefs to fail latest input readiness")
    with tempfile.TemporaryDirectory() as temp_root:
        root_path = Path(temp_root)
        older = root_path / "reverse/captures/airshield-datax-old.jsonl"
        newer = root_path / "reverse/captures/airshield-datax-new.jsonl"
        newer.parent.mkdir(parents=True, exist_ok=True)
        older.write_text("{}", encoding="utf-8")
        newer.write_text("{}", encoding="utf-8")
        older.touch()
        newer.touch()
        original_repo_root = globals()["repo_root"]
        try:
            globals()["repo_root"] = lambda: root_path
            selected = latest_repo_artifact(DEFAULT_ANDROID_TRACE_GLOB, label="Android trace")
            if selected != newer:
                raise SystemExit("self-test: expected latest Android trace selection")
            if append_latest([], selected) != [newer]:
                raise SystemExit("self-test: expected latest append")
            if append_latest([older], selected) != [older]:
                raise SystemExit("self-test: explicit path should not be overridden")
        finally:
            globals()["repo_root"] = original_repo_root
    print("self-test: OK")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare redacted AirShield identity evidence without printing private key material."
    )
    parser.add_argument("--android-trace", action="append", type=Path, default=[], help="Android Frida JSONL trace.")
    parser.add_argument("--identity-prefs", action="append", type=Path, default=[], help="JSON from extract_airshield_identity_prefs.py or extract_airshield_state.py.")
    parser.add_argument("--native-probe", action="append", type=Path, default=[], help="JSON from probe_airshield_private_key.py.")
    parser.add_argument("--mac-session", action="append", type=Path, default=[], help="Mac bridge session JSONL log.")
    parser.add_argument("--latest-artifacts", action="store_true", help="Use newest saved trace, identity state, native PrivateKey probe, and Mac session when explicit paths are omitted.")
    parser.add_argument("--android-trace-glob", default=DEFAULT_ANDROID_TRACE_GLOB)
    parser.add_argument("--identity-prefs-glob", default=DEFAULT_IDENTITY_PREFS_GLOB)
    parser.add_argument("--native-probe-glob", default=DEFAULT_NATIVE_PROBE_GLOB)
    parser.add_argument("--sessions-dir", type=Path, default=DEFAULT_SESSIONS_DIR)
    parser.add_argument("--strict", action="store_true", help="Exit nonzero unless at least one private and one public-key match are found when comparable inputs exist.")
    parser.add_argument("--self-test", action="store_true", help="Run synthetic redacted identity comparison checks and exit.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    android_trace_paths = args.android_trace
    identity_prefs_paths = args.identity_prefs
    native_probe_paths = args.native_probe
    mac_session_paths = args.mac_session
    if args.latest_artifacts:
        android_trace_paths = append_latest(android_trace_paths, latest_repo_artifact(args.android_trace_glob, label="Android trace"))
        identity_prefs_paths = append_latest(identity_prefs_paths, latest_repo_artifact(args.identity_prefs_glob, label="identity prefs"))
        native_probe_paths = append_latest(native_probe_paths, latest_repo_artifact(args.native_probe_glob, label="native PrivateKey probe"))
        mac_session_paths = append_latest(mac_session_paths, latest_mac_session(args.sessions_dir.expanduser()))

    trace_items = [item for path in android_trace_paths for item in android_trace_evidence(path.expanduser())]
    prefs_items = [item for path in identity_prefs_paths for item in prefs_evidence(path.expanduser())]
    probe_items = [item for path in native_probe_paths for item in native_probe_evidence(path.expanduser())]
    mac_items = [item for path in mac_session_paths for item in mac_session_evidence(path.expanduser())]

    print_items("Android trace identity evidence", trace_items)
    print()
    print_items("Android preference identity evidence", prefs_items)
    print()
    print_items("Native PrivateKey probe evidence", probe_items)
    print()
    print_items("Mac identity evidence", mac_items)

    private_matches = [
        print_comparisons(
            "Prefs private-key slot vs Mac imported private key",
            prefs_items,
            classify(mac_items, "private_key"),
            "prefs",
            "mac",
        ),
        print_comparisons(
            "Android native loaded/serialized private key vs Mac imported private key",
            classify(trace_items, "private_key.set_raw") + classify(trace_items, "private_key.serialize"),
            classify(mac_items, "private_key"),
            "android",
            "mac",
        ),
        print_comparisons(
            "Prefs private-key slot vs Android native loaded/serialized private key",
            prefs_items,
            classify(trace_items, "private_key.set_raw") + classify(trace_items, "private_key.serialize"),
            "prefs",
            "android",
        ),
        print_comparisons(
            "Prefs private-key slot vs native PrivateKey probe",
            prefs_items,
            classify(probe_items, "private_key.input") + classify(probe_items, "private_key.set_raw") + classify(probe_items, "private_key.serialize"),
            "prefs",
            "probe",
        ),
        print_comparisons(
            "Native PrivateKey probe vs Mac imported private key",
            classify(probe_items, "private_key.input") + classify(probe_items, "private_key.set_raw") + classify(probe_items, "private_key.serialize"),
            classify(mac_items, "private_key"),
            "probe",
            "mac",
        ),
    ]

    public_matches = [
        print_comparisons(
            "Android recovered/accepted public key vs Mac public-key candidates",
            classify(trace_items, "recover_public_key") + classify(trace_items, "accept_key_candidate") + classify(trace_items, "acceptAuthentication"),
            classify(mac_items, "public_key"),
            "android",
            "mac",
        ),
        print_comparisons(
            "Native PrivateKey recovered public key vs Mac public-key candidates",
            classify(probe_items, "recover_public_key") + classify(probe_items, "accepted_auth_public_key"),
            classify(mac_items, "public_key"),
            "probe",
            "mac",
        )
    ]

    if args.latest_artifacts and args.strict and not latest_identity_inputs_ready(prefs_items, probe_items, trace_items, mac_items):
        print()
        print("Overall: IDENTITY_MATCH_INCOMPLETE")
        return 1

    if args.strict and ((prefs_items or trace_items or probe_items) and mac_items):
        if not any(private_matches) or not any(public_matches):
            print()
            print("Overall: IDENTITY_MATCH_INCOMPLETE")
            return 1

    print()
    print("Overall: IDENTITY_REPORT_COMPLETE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
