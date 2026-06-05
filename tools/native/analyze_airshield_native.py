#!/usr/bin/env python3
import argparse
import re
import subprocess
from collections import defaultdict
from pathlib import Path


PATTERNS = {
    "airshield_jni": re.compile(
        r"airshield|StreamSecurer|Preamble|CipherBuilder|Framing|EndLinkSetup|"
        r"RequestEncryption|EnableEncryption",
        re.IGNORECASE,
    ),
    "framing": re.compile(
        r"framing|outerFrame|cipherPayload|packNative|unpackNative|partial data|"
        r"Invalid Framing|framing indicator",
        re.IGNORECASE,
    ),
    "kdf_challenge": re.compile(
        r"hkdf|hmac|hmac_derive|sha256|challenge|seed|nonce|derive",
        re.IGNORECASE,
    ),
    "crypto": re.compile(
        r"curve25519|x25519|chacha|xchacha|poly1305|secretstream|aes|gcm|"
        r"EVP_|crypto_|mbedtls",
        re.IGNORECASE,
    ),
}


def run_text(command):
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    if proc.returncode not in (0, 1):
        return proc.stdout + proc.stderr
    return proc.stdout


def collect_strings(path):
    output = run_text(["strings", "-a", "-t", "x", str(path)])
    matches = defaultdict(list)
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(maxsplit=1)
        if len(parts) != 2:
            continue
        offset, value = parts
        for category, pattern in PATTERNS.items():
            if pattern.search(value):
                matches[category].append((offset, value))
    return matches


def collect_dynamic_symbols(path):
    output = run_text(["nm", "-D", str(path)])
    matches = defaultdict(list)
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        for category, pattern in PATTERNS.items():
            if pattern.search(stripped):
                matches[category].append(stripped)
    return matches


def render_report(lib_dir):
    libs = sorted(lib_dir.glob("*.so"))
    lines = [
        "# AirShield Native Evidence",
        "",
        f"Library directory: `{lib_dir}`",
        "",
        "This report is generated from ELF dynamic symbols and printable strings. "
        "It is evidence for native surfaces and constants, not a full disassembly.",
        "",
    ]

    for lib in libs:
        string_matches = collect_strings(lib)
        symbol_matches = collect_dynamic_symbols(lib)
        lines.extend(
            [
                f"## {lib.name}",
                "",
                f"- Size: {lib.stat().st_size} bytes",
                "",
            ]
        )

        any_symbols = any(symbol_matches.values())
        if any_symbols:
            lines.append("### Dynamic Symbols")
            lines.append("")
            for category in PATTERNS:
                values = symbol_matches.get(category, [])
                if not values:
                    continue
                lines.append(f"#### {category}")
                for value in values[:80]:
                    lines.append(f"- `{value}`")
                if len(values) > 80:
                    lines.append(f"- ... {len(values) - 80} more")
                lines.append("")

        any_strings = any(string_matches.values())
        if any_strings:
            lines.append("### Strings")
            lines.append("")
            for category in PATTERNS:
                values = string_matches.get(category, [])
                if not values:
                    continue
                lines.append(f"#### {category}")
                for offset, value in values[:120]:
                    safe_value = value.replace("`", "'")
                    lines.append(f"- `0x{offset}` `{safe_value}`")
                if len(values) > 120:
                    lines.append(f"- ... {len(values) - 120} more")
                lines.append("")

        if not any_symbols and not any_strings:
            lines.append("- No scoped AirShield/DataX native evidence matched.")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description="Extract scoped AirShield native evidence from APK ELF libraries.")
    parser.add_argument(
        "--lib-dir",
        type=Path,
        default=Path("reverse/native-libs/lib/arm64-v8a"),
        help="directory containing unpacked .so files",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reverse/native-airshield-report.md"),
        help="markdown report path",
    )
    args = parser.parse_args()

    report = render_report(args.lib_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
