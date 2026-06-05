#!/usr/bin/env python3
import argparse
import re
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Section:
    name: str
    addr: int
    offset: int
    size: int


@dataclass(frozen=True)
class Registration:
    table_addr: int
    class_name_addr: int
    class_name: str
    register_fn_addr: int


class ELFImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:4] != b"\x7fELF":
            raise ValueError(f"{path} is not an ELF file")
        if self.data[4] != 2 or self.data[5] != 1:
            raise ValueError("only little-endian ELF64 is supported")
        self.sections = self._parse_sections()

    def _parse_sections(self):
        e_shoff = struct.unpack_from("<Q", self.data, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", self.data, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", self.data, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", self.data, 0x3E)[0]

        raw_sections = []
        for index in range(e_shnum):
            offset = e_shoff + index * e_shentsize
            name_offset = struct.unpack_from("<I", self.data, offset)[0]
            addr = struct.unpack_from("<Q", self.data, offset + 0x10)[0]
            file_offset = struct.unpack_from("<Q", self.data, offset + 0x18)[0]
            size = struct.unpack_from("<Q", self.data, offset + 0x20)[0]
            raw_sections.append((name_offset, addr, file_offset, size))

        shstr_name_offset, _, shstr_offset, shstr_size = raw_sections[e_shstrndx]
        del shstr_name_offset
        shstr = self.data[shstr_offset:shstr_offset + shstr_size]

        def section_name(name_offset: int) -> str:
            end = shstr.find(b"\0", name_offset)
            if end < 0:
                return ""
            return shstr[name_offset:end].decode("utf-8", "replace")

        return [
            Section(section_name(name_offset), addr, file_offset, size)
            for name_offset, addr, file_offset, size in raw_sections
        ]

    def section(self, name: str) -> Section:
        for section in self.sections:
            if section.name == name:
                return section
        raise KeyError(name)

    def vma_to_offset(self, vma: int) -> Optional[int]:
        for section in self.sections:
            if section.addr <= vma < section.addr + section.size:
                return section.offset + (vma - section.addr)
        return None

    def cstring_at_vma(self, vma: int) -> Optional[str]:
        offset = self.vma_to_offset(vma)
        if offset is None or offset >= len(self.data):
            return None
        end = self.data.find(b"\0", offset)
        if end < 0:
            return None
        return self.data[offset:end].decode("utf-8", "replace")

    def u64_at_offset(self, offset: int) -> int:
        return struct.unpack_from("<Q", self.data, offset)[0]


def run_text(command: list[str]) -> str:
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    return proc.stdout + proc.stderr


def extract_registrations(image: ELFImage) -> list[Registration]:
    section = image.section("pre_merge_jni_libraries")
    registrations: list[Registration] = []
    for relative in range(0, section.size, 16):
        offset = section.offset + relative
        class_name_addr = image.u64_at_offset(offset)
        register_fn_addr = image.u64_at_offset(offset + 8)
        class_name = image.cstring_at_vma(class_name_addr)
        if class_name:
            registrations.append(
                Registration(
                    table_addr=section.addr + relative,
                    class_name_addr=class_name_addr,
                    class_name=class_name,
                    register_fn_addr=register_fn_addr,
                )
            )
    return registrations


def disassemble(path: Path, start: int, byte_count: int) -> str:
    if start == 0:
        return ""
    stop = start + byte_count
    return run_text([
        "objdump",
        "-d",
        "-C",
        f"--start-address=0x{start:x}",
        f"--stop-address=0x{stop:x}",
        str(path),
    ]).rstrip()


def render_report(path: Path, pattern: re.Pattern[str], disassembly_bytes: int) -> str:
    image = ELFImage(path)
    registrations = extract_registrations(image)
    selected = [registration for registration in registrations if pattern.search(registration.class_name)]

    lines = [
        "# JNI Registration Report",
        "",
        f"Library: `{path}`",
        "",
        "This report decodes the `pre_merge_jni_libraries` table used by `JNI_OnLoad`. "
        "It gives us the native registration function for merged JNI libraries even when "
        "their method implementations are stripped.",
        "",
        "Objdump labels inside snippets are nearest exported symbols and are not reliable "
        "function names for these stripped registration functions.",
        "",
        f"- Total registrations: {len(registrations)}",
        f"- Matching registrations: {len(selected)}",
        "",
        "## Matches",
        "",
        "| Table VMA | Class / Library | Name VMA | Register Function |",
        "| --- | --- | --- | --- |",
    ]

    for registration in selected:
        lines.append(
            "| "
            f"`0x{registration.table_addr:x}` | "
            f"`{registration.class_name}` | "
            f"`0x{registration.class_name_addr:x}` | "
            f"`0x{registration.register_fn_addr:x}` |"
        )

    if disassembly_bytes > 0:
        lines.append("")
        lines.append("## Disassembly Snippets")
        for registration in selected:
            if registration.register_fn_addr == 0:
                continue
            lines.extend([
                "",
                f"### {registration.class_name}",
                "",
                f"- Register function: `0x{registration.register_fn_addr:x}`",
                "",
                "```asm",
                disassemble(path, registration.register_fn_addr, disassembly_bytes),
                "```",
            ])

    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description="Decode merged JNI registration entries from libstartup.so.")
    parser.add_argument(
        "--lib",
        type=Path,
        default=Path("reverse/native-libs/lib/arm64-v8a/libstartup.so"),
        help="ELF library path",
    )
    parser.add_argument(
        "--pattern",
        default=r"airshield|datax|wearable",
        help="case-insensitive regex for class/library names",
    )
    parser.add_argument(
        "--disassembly-bytes",
        type=lambda value: int(value, 0),
        default=0x360,
        help="bytes to disassemble from each matching register function; use 0 to disable",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reverse/jni-registration-report.md"),
        help="markdown output path",
    )
    args = parser.parse_args()

    pattern = re.compile(args.pattern, re.IGNORECASE)
    report = render_report(args.lib, pattern, args.disassembly_bytes)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
