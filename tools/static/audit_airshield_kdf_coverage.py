#!/usr/bin/env python3
"""Audit static coverage for AirShield transcript/KDF reconstruction.

This does not prove live/native output parity. It checks that the static native
report, Swift implementation, and Swift validation suite cover the recovered
transcript/KDF structure well enough to mark that static TODO separately from
the remaining native-output comparison gates.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Check:
    label: str
    passed: bool
    evidence: str


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def contains(label: str, text: str, needle: str, evidence: str | None = None) -> Check:
    return Check(label, needle in text, evidence or needle)


def all_contains(label: str, text: str, needles: list[str], evidence: str) -> Check:
    missing = [needle for needle in needles if needle not in text]
    return Check(label, not missing, evidence if not missing else f"missing: {', '.join(missing)}")


def render(root: Path) -> tuple[str, list[Check]]:
    report_path = root / "reverse/airshield-kdf-framing-report.md"
    swift_path = root / "BandBridgeMac/Sources/AirShieldSession.swift"
    validation_path = root / "tools/swift/DataXCodecValidation.swift"
    shared_validation_path = root / "tools/swift/SharedCoreValidation.swift"

    report = read(report_path)
    swift = read(swift_path)
    validation = read(validation_path)
    shared_validation = read(shared_validation_path)

    checks = [
        all_contains(
            "Native report pins transcript windows",
            report,
            [
                "16-byte builder transcript challenge window at `0x108...0x117`",
                "32-byte transcript/material window at `0x218...0x237`",
                "`setChallengeNative([B)` fills raw challenge bytes at `0x110...0x11f`",
                "`setSeedNative([B)` fills seed bytes at `0x220...0x23f`",
            ],
            "challenge/material windows and setter overlaps are documented",
        ),
        all_contains(
            "Native report pins normal KDF schedule",
            report,
            [
                "`stp q0, q1, [x28, #0x20]` writes that digest to the work-area cipher-material half",
                "`bl 0xdb17b4` runs the normal default-label expansion when HKDF is enabled",
                "`stp q0, q1, [sp, #0x190]` writes the selected 32-byte material into the validation-key half",
                "validation-key half and cipher-key half are equal immediately before config construction",
            ],
            "normal path digest, optional db17b4 expansion, and work-area copy are documented",
        ),
        all_contains(
            "Native report pins expansion contexts",
            report,
            [
                "static `AirShield` label",
                "length `9`",
                "Explicit context `0x25d60b` length `0x88`",
                "trailer `0x2000000000010000`",
            ],
            "default label and explicit 0x88 context are documented",
        ),
        contains(
            "Native report keeps live parity boundary explicit",
            report,
            "remaining gap is native confirmation of candidate key material and byte-for-byte comparison against native `Framing.packNative` / `Framing.unpackNative` output",
        ),
        all_contains(
            "Swift constructs recovered transcript windows",
            swift,
            [
                "transcriptChallengeWindow.append(localChallenge.prefix(8))",
                "transcriptMaterialWindow.append(Data(repeating: 0, count: 7))",
                "transcriptMaterialWindow.append(seed.prefix(24))",
                "digestInput.append(sharedHashMaterial)",
                "digestInput.append(transcriptChallengeWindow)",
                "digestInput.append(transcriptMaterialWindow)",
            ],
            "Swift mirrors shared material plus transcript challenge/material windows",
        ),
        all_contains(
            "Swift covers KDF/expansion variants",
            swift,
            [
                "__db17b4_default_label",
                "__db17b4_shared_material_context",
                "__db17b4_explicit_context_0x88",
                "__direct_transcript_digest",
                "validationKey: variant.keyMaterial",
                "cipherKey: variant.keyMaterial",
            ],
            "Swift prepares default-label, explicit-context, shared-material-context, and direct digest candidates",
        ),
        all_contains(
            "Swift validation covers transcript/KDF logging",
            validation,
            [
                "AirShield transcript challenge window fingerprint is short hex",
                "AirShield transcript material window fingerprint is short hex",
                "AirShield normal material transcript digest fingerprint is short hex",
                "AirShield HKDF candidate list covers native expansion context variants",
                "AirShield normal material keeps validation/cipher halves equal on default path",
            ],
            "DataX validation asserts transcript fingerprints, context variants, and equal key halves",
        ),
        all_contains(
            "Shared-core validation covers crypto without UI/Bluetooth dependencies",
            shared_validation,
            [
                "AirShieldFramingExpansion.expandDefaultLabelCounter1",
                "AirShieldFraming.encryptedFrameCandidate",
                "AirShieldFraming.decryptedFrameCandidate",
            ],
            "shared-core validation exercises expansion and frame candidate helpers",
        ),
    ]

    failed = [check for check in checks if not check.passed]
    lines = [
        "# AirShield Transcript/KDF Static Coverage Audit",
        "",
        "This audit checks whether the static transcript/KDF reconstruction is documented and test-covered separately from live/native output parity.",
        "",
        "## Result",
        "",
        f"- Status: `{'FAILED' if failed else 'OK'}`" + (f" ({len(failed)} check(s) failed)" if failed else ""),
        "- Scope: static transcript/KDF structure, Swift candidate construction, and fixture coverage.",
        "- Boundary: this does not prove the final key material matches native output; that remains gated by Android/native traces and `Framing.packNative` comparison.",
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
        "## Remaining Native-Parity Gates",
        "",
        "- Confirm Java-visible `PrivateKey.deriveNative` output against Swift P-256 shared material representation.",
        "- Compare Swift validation/cipher key fingerprints against native setup fingerprints.",
        "- Compare Swift validation-prefix and encrypted outer-frame candidates against native `Framing.packNative` output.",
        "",
    ])
    return "\n".join(lines), checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit AirShield KDF static coverage.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("reverse/airshield-kdf-static-coverage.md"))
    args = parser.parse_args()

    report, checks = render(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(args.output)
    return 0 if all(check.passed for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
