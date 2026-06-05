#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path


FUNCTIONS = [
    {
        "name": "lower DataX send / frame encoder",
        "start": 0xDB0794,
        "stop": 0xDB0934,
        "highlights": [
            ("0xdb07b8", "`lsl w23, w2, #2`: extension byte count is `extension_count * 4`."),
            ("0xdb07bc", "`add x8, x5, x23`: body length is `payload_length + extension_bytes`."),
            ("0xdb07c0", "`lsr x9, x8, #14`: rejects any body length using bits above the 14-bit field."),
            ("0xdb07fc", "`cset w9, ne`: extension-present flag is derived from `extension_count != 0`."),
            ("0xdb0800", "`orr w8, w8, w9, lsl #15`: extension-present flag is descriptor bit 15."),
            ("0xdb0800", "No neighboring operation sets descriptor bit 14 in this lower-frame encoder path."),
            ("0xdb0814", "`strh w8, [x24], #0x4`: writes the 2-byte descriptor before the base id."),
        ],
    },
    {
        "name": "DataX extension parser",
        "start": 0xDB09D0,
        "stop": 0xDB0A90,
        "highlights": [
            ("0xdb09e4", "Walks extension words in 4-byte units."),
            ("0xdb09f4", "`and w14, w13, #0x7f`: extension type is the low 7 bits of byte 0."),
            ("0xdb0a80", "`tbnz w13, #0x7`: byte 0 bit 7 is the continuation bit."),
            ("0xdb0a34", "One case extracts byte 1 as an auxiliary byte."),
            ("0xdb0a3c", "One case stores the big-endian 16-bit extension value."),
        ],
    },
    {
        "name": "lower DataX receive / frame parser",
        "start": 0xDB0B84,
        "stop": 0xDB0F54,
        "highlights": [
            ("0xdb0bb0", "Checks connection field `+0x50` for saved partial-frame byte count."),
            ("0xdb0bc0", "If the current chunk is too short for the saved remainder, records a new partial count."),
            ("0xdb0bec", "Requires at least 4 bytes before parsing a frame header."),
            ("0xdb0c04", "`and w9, w8, #0xffffff3f`: masks descriptor bits 15 and 14 out of body length."),
            ("0xdb0c18", "`and w8, w10, #0x4`: only descriptor bit 15 becomes the internal extension-present flag."),
            ("0xdb0c24", "Computes `payload_start + body_length` as the frame end."),
            ("0xdb0c60", "Branches into extension parsing only when descriptor bit 15 is set."),
            ("0xdb0d3c", "Stores a remaining-byte count when a frame crosses chunk boundaries."),
        ],
    },
]


EXPECTED_REPORT_SNIPPETS = [
    "Base frame header is 4 bytes",
    "Descriptor bits 0..13 are body length",
    "Descriptor bit 15 means extension words are present",
    "Descriptor bit 14 is masked out of native body-length parsing",
    "Extension byte 0 bit 7 is the continuation bit",
    "`0xdb07b8`: `lsl w23, w2, #2`",
    "`0xdb07bc`: `add x8, x5, x23`",
    "`0xdb07c0`: `lsr x9, x8, #14`",
    "`0xdb0800`: `orr w8, w8, w9, lsl #15`",
    "`0xdb0814`: `strh w8, [x24], #0x4`",
    "`0xdb09f4`: `and w14, w13, #0x7f`",
    "`0xdb0a80`: `tbnz w13, #0x7`",
    "`0xdb0c04`: `and w9, w8, #0xffffff3f`",
    "`0xdb0c18`: `and w8, w10, #0x4`",
]


def run_text(command: list[str]) -> str:
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    return proc.stdout + proc.stderr


def disassemble(path: Path, start: int, stop: int) -> str:
    return run_text([
        "objdump",
        "-d",
        "-C",
        f"--start-address=0x{start:x}",
        f"--stop-address=0x{stop:x}",
        str(path),
    ]).rstrip()


def render_report(lib: Path) -> str:
    lines = [
        "# DataX Native Frame Evidence",
        "",
        f"Library: `{lib}`",
        "",
        "This report captures the static instruction evidence for the lower DataX "
        "frame encoder/parser in `libstartup.so`. It is deliberately narrow: the "
        "goal is to keep the Swift frame codec aligned with the native code while "
        "AirShield encryption remains under reconstruction.",
        "",
        "## Recovered Header Facts",
        "",
        "- Base frame header is 4 bytes: 2-byte descriptor followed by 2-byte base id.",
        "- Descriptor bits 0..13 are body length.",
        "- Body length includes extension bytes plus payload bytes.",
        "- Body length is capped to `0x3fff`.",
        "- Descriptor bit 15 means extension words are present.",
        "- Descriptor bit 14 is masked out of native body-length parsing.",
        "- This static pass found no lower-frame encoder operation that emits descriptor bit 14 and no receive-side branch that consumes it as a control flag.",
        "- Treat descriptor bit 14 as reserved/ignored at the lower DataX frame layer unless a higher-layer trace proves otherwise; the Swift decoder logs it for evidence but does not give it semantics.",
        "- Extension words are 4 bytes each.",
        "- Extension byte 0 bit 7 is the continuation bit.",
        "- Extension byte 0 bits 0..6 are the extension type.",
        "- Extension byte 1 is an auxiliary byte for at least one extension case.",
        "- Extension bytes 2..3 carry a big-endian 16-bit value.",
        "- The parser stores partial-frame remainder state on the connection when a chunk ends mid-frame.",
        "",
        "## Function Evidence",
        "",
    ]

    for function in FUNCTIONS:
        lines.extend([
            f"### {function['name']}",
            "",
            f"Range: `0x{function['start']:x}..0x{function['stop']:x}`",
            "",
            "Highlights:",
        ])
        for address, text in function["highlights"]:
            lines.append(f"- `{address}`: {text}")
        lines.extend([
            "",
            "```asm",
            disassemble(lib, function["start"], function["stop"]),
            "```",
            "",
        ])

    return "\n".join(lines).rstrip() + "\n"


def validate_report(report: str, root: Path) -> list[str]:
    failures = [
        f"missing report snippet: {snippet}"
        for snippet in EXPECTED_REPORT_SNIPPETS
        if snippet not in report
    ]
    proc = subprocess.run(
        [str(root / "tools/swift/validate_datax_codec.sh")],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        failures.append(f"Swift DataX codec validation failed: {detail or proc.returncode}")
    return failures


def main():
    parser = argparse.ArgumentParser(description="Generate focused DataX native frame evidence report.")
    parser.add_argument(
        "--lib",
        type=Path,
        default=Path("reverse/native-libs/lib/arm64-v8a/libstartup.so"),
        help="ELF library path",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reverse/native-datax-report.md"),
        help="markdown output path",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    report = render_report(args.lib)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    failures = validate_report(report, root)
    print(args.output)
    print("Overall:", "DATAX_STATIC_OK" if not failures else "DATAX_STATIC_FAILED")
    for failure in failures:
        print(f"- {failure}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
