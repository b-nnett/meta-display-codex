#!/usr/bin/env python3
"""Generate static evidence for AirShield pairing/bond requirements.

The goal is to distinguish Android OS Bluetooth pairing from AirShield's
stream-encryption and preamble-authentication layers.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Check:
    label: str
    passed: bool
    evidence: str


@dataclass(frozen=True)
class Hit:
    path: Path
    line: int
    text: str


BOND_PATTERNS = (
    "createBond(",
    "getBondState(",
    "removeBond(",
    "BOND_BONDED",
    "BOND_BONDING",
    "BOND_NONE",
)

AUTH_KEY_PATTERNS = (
    "app-private-key",
    "acdc-app-private-key",
    "device-identity-device-ec-kdk-",
    "key-derivation-key-",
    "PrivateKey",
    "recoverPublicKey",
    "acceptAuthentication",
)

AIRSHIELD_AUTH_FILES = (
    "reverse/meta-ai-jadx/sources/com/facebook/wearable/airshield",
    "reverse/meta-ai-jadx/sources/com/facebook/wearable/connectivity/security/streamsecurer",
    "reverse/meta-ai-jadx/sources/com/facebook/wearable/companion/connectivity/security/prototypeidentity/PrototypeIdentity.java",
    "reverse/meta-ai-jadx/sources/X/C30564Fwc.java",
    "reverse/meta-ai-jadx/sources/X/C30565Fwd.java",
    "reverse/meta-ai-jadx/sources/X/G44.java",
    "reverse/meta-ai-jadx/sources/X/GD5.java",
    "reverse/meta-ai-jadx/sources/X/GCS.java",
    "reverse/meta-ai-jadx/sources/X/C30908GCi.java",
    "reverse/meta-ai-jadx/sources/X/GC0.java",
    "reverse/meta-ai-jadx/sources/X/GEd.java",
    "reverse/meta-ai-jadx/sources/X/GDO.java",
    "reverse/meta-ai-jadx/sources/X/GEY.java",
    "reverse/meta-ai-jadx/sources/X/C30907GCh.java",
)

PAIRING_MANAGER_FILES = (
    "reverse/meta-ai-jadx/sources/X/C32453HOn.java",
    "reverse/meta-ai-jadx/sources/X/HMT.java",
    "reverse/meta-ai-jadx/sources/X/C19350xh.java",
    "reverse/meta-ai-jadx/sources/X/G95.java",
    "reverse/meta-ai-jadx/sources/X/G4Q.java",
    "reverse/meta-ai-jadx/sources/com/facebook/wearable/connectivity/bluetooth/multiconnection/BleConnection2.java",
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def java_files(root: Path, entries: tuple[str, ...]) -> list[Path]:
    out: list[Path] = []
    for entry in entries:
        path = root / entry
        if path.is_dir():
            out.extend(sorted(path.rglob("*.java")))
        elif path.exists():
            out.append(path)
    return sorted(set(out))


def find_hits(paths: list[Path], patterns: tuple[str, ...]) -> list[Hit]:
    hits: list[Hit] = []
    for path in paths:
        text = read(path)
        for line_number, line in enumerate(text.splitlines(), 1):
            if any(pattern in line for pattern in patterns):
                hits.append(Hit(path=path, line=line_number, text=line.strip()))
    return hits


def regex_check(label: str, path: Path, pattern: str, evidence: str) -> Check:
    text = read(path)
    return Check(label, re.search(pattern, text, re.S) is not None, evidence)


def contains_check(label: str, path: Path, needle: str) -> Check:
    text = read(path)
    return Check(label, needle in text, needle)


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def render(root: Path) -> tuple[str, list[Check]]:
    auth_paths = java_files(root, AIRSHIELD_AUTH_FILES)
    pairing_paths = java_files(root, PAIRING_MANAGER_FILES)

    auth_bond_hits = find_hits(auth_paths, BOND_PATTERNS)
    auth_key_hits = find_hits(auth_paths, AUTH_KEY_PATTERNS)
    pairing_bond_hits = find_hits(pairing_paths, BOND_PATTERNS)

    checks: list[Check] = [
        Check(
            "No Android bond API use in AirShield/link-securer/auth-delegate set",
            not auth_bond_hits,
            f"{len(auth_bond_hits)} bond marker hit(s) across {len(auth_paths)} auth file(s)",
        ),
        Check(
            "Android OS pairing layer does use bond APIs",
            bool(pairing_bond_hits),
            f"{len(pairing_bond_hits)} bond marker hit(s) across pairing-manager files",
        ),
        regex_check(
            "Preamble success hands a 64-byte public key to native acceptAuthentication",
            root / "reverse/meta-ai-jadx/sources/X/G44.java",
            r"Arrays\.copyOf\(bArr,\s*64\).*?acceptAuthentication\(bArrCopyOf",
            "G44 pads/truncates delegate byte[] to 64 bytes before Preamble.acceptAuthentication.",
        ),
        contains_check(
            "Normal identity delegate uses app-private-key storage",
            root / "reverse/meta-ai-jadx/sources/X/GC0.java",
            "app-private-key",
        ),
        contains_check(
            "ACDC delegate uses acdc-app-private-key storage",
            root / "reverse/meta-ai-jadx/sources/X/GEd.java",
            "acdc-app-private-key",
        ),
        contains_check(
            "Production identity storage includes device EC KDK",
            root / "reverse/meta-ai-jadx/sources/X/GDO.java",
            "device-identity-device-ec-kdk-",
        ),
        contains_check(
            "Prototype identity storage includes key-derivation-key",
            root / "reverse/meta-ai-jadx/sources/X/C30907GCh.java",
            "key-derivation-key-",
        ),
        regex_check(
            "Hypernova path can select identity-plus-prototype preamble auth delegate",
            root / "reverse/meta-ai-jadx/sources/X/C2WE.java",
            r"new C30908GCi\(.*?Hypernova-Preamble",
            "C2WE constructs LinkSecurerForStream for Hypernova-Preamble with C30908GCi.",
        ),
        regex_check(
            "ACDC path constructs LinkSecurerForStream with GCS delegate",
            root / "reverse/meta-ai-jadx/sources/X/HOI.java",
            r"new LinkSecurerForStream\(.*?gcs",
            "HOI performs AirShield with LinkSecurerForStream and a GCS/ACDC delegate.",
        ),
    ]

    failed = [check for check in checks if not check.passed]
    lines = [
        "# AirShield Bond Requirements Static Report",
        "",
        "This report separates Android OS Bluetooth pairing from AirShield stream setup and preamble authentication.",
        "",
        "## Result",
        "",
        f"- Status: `{'FAILED' if failed else 'OK'}`" + (f" ({len(failed)} check(s) failed)" if failed else ""),
        "- Conclusion: static evidence does not show Android bond-derived secrets feeding the AirShield preamble or stream KDF directly.",
        "- Practical blocker remains accepted Identity/ACDC app key material, plus native-confirmed stream framing parity.",
        "",
        "## Interpretation",
        "",
        "- Android pairing manager code uses `createBond()`, `getBondState()`, and `removeBond()` for OS-level device pairing and connection gating.",
        "- The AirShield core, `LinkSecurerForStream`, preamble callbacks, and known Identity/ACDC delegates do not reference those bond APIs in this scan.",
        "- The AirShield acceptance path instead moves through a preamble DataX authentication service and then `Preamble.acceptAuthentication(publicKey64, ...)`.",
        "- Durable material visible in static code is stored app/ACDC identity material: `app-private-key`, `acdc-app-private-key`, device EC KDK slots, and prototype `key-derivation-key-*` slots.",
        "- This is not proof that Android bonding is unnecessary for transport discovery/connectivity. It is evidence that the cryptographic AirShield blocker is identity auth rather than an Android bond-secret KDF.",
        "",
        "## Checks",
        "",
        "| Check | Status | Evidence |",
        "| --- | --- | --- |",
    ]
    for check in checks:
        status = "ok" if check.passed else "FAIL"
        lines.append(f"| {check.label} | `{status}` | `{check.evidence}` |")

    lines.extend([
        "",
        "## Bond API Hits Outside AirShield Auth",
        "",
        "| File | Line | Evidence |",
        "| --- | ---: | --- |",
    ])
    for hit in pairing_bond_hits[:40]:
        lines.append(f"| `{rel(hit.path, root)}` | {hit.line} | `{hit.text}` |")
    if len(pairing_bond_hits) > 40:
        lines.append(f"| ... | ... | {len(pairing_bond_hits) - 40} additional hit(s) omitted |")

    lines.extend([
        "",
        "## AirShield/Auth Key-Material Hits",
        "",
        "| File | Line | Evidence |",
        "| --- | ---: | --- |",
    ])
    for hit in auth_key_hits[:80]:
        lines.append(f"| `{rel(hit.path, root)}` | {hit.line} | `{hit.text}` |")
    if len(auth_key_hits) > 80:
        lines.append(f"| ... | ... | {len(auth_key_hits) - 80} additional hit(s) omitted |")

    lines.extend([
        "",
        "## Boundary",
        "",
        "This is a static source scan over the decompiled APK. It does not replace a live trace showing which delegate path the real band/glasses accept, nor does it prove that OS-level bonding can be skipped for every transport path.",
        "",
    ])
    return "\n".join(lines), checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AirShield bond requirement evidence report.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("reverse/airshield-bond-requirements.md"))
    args = parser.parse_args()

    report, checks = render(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(args.output)
    return 0 if all(check.passed for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
