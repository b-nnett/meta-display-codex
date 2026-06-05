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
class StringReference:
    pc: int
    register: int
    target: int
    value: str


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

        _, _, shstr_offset, shstr_size = raw_sections[e_shstrndx]
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

    def section_for_vma(self, vma: int) -> Optional[Section]:
        for section in self.sections:
            if section.addr <= vma < section.addr + section.size:
                return section
        return None

    def cstring_at_vma(self, vma: int) -> Optional[str]:
        section = self.section_for_vma(vma)
        if section is None or section.name not in {".rodata", ".dynstr"}:
            return None
        offset = self.vma_to_offset(vma)
        if offset is None or offset >= len(self.data):
            return None
        end = self.data.find(b"\0", offset)
        if end < 0 or end == offset:
            return None
        value = self.data[offset:end]
        if any(byte < 0x09 or (0x0d < byte < 0x20) for byte in value):
            return None
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def bytes_for_vma_range(self, start: int, stop: int) -> bytes:
        start_offset = self.vma_to_offset(start)
        stop_offset = self.vma_to_offset(stop - 1)
        if start_offset is None or stop_offset is None:
            raise ValueError("range is not fully inside a file-backed section")
        return self.data[start_offset:stop_offset + 1]


def sign_extend(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (value ^ sign_bit) - sign_bit


def decode_adr_or_adrp(instruction: int, pc: int) -> Optional[tuple[int, int]]:
    if instruction & 0x9F000000 == 0x90000000:
      rd = instruction & 0x1F
      immlo = (instruction >> 29) & 0x3
      immhi = (instruction >> 5) & 0x7FFFF
      imm = sign_extend((immhi << 2) | immlo, 21) << 12
      return rd, (pc & ~0xFFF) + imm
    if instruction & 0x9F000000 == 0x10000000:
      rd = instruction & 0x1F
      immlo = (instruction >> 29) & 0x3
      immhi = (instruction >> 5) & 0x7FFFF
      imm = sign_extend((immhi << 2) | immlo, 21)
      return rd, pc + imm
    return None


def decode_add_immediate(instruction: int) -> Optional[tuple[int, int, int]]:
    if instruction & 0x7F000000 != 0x11000000:
        return None
    rd = instruction & 0x1F
    rn = (instruction >> 5) & 0x1F
    imm12 = (instruction >> 10) & 0xFFF
    shift = 12 if ((instruction >> 22) & 0x1) else 0
    return rd, rn, imm12 << shift


def collect_string_references(image: ELFImage, start: int, stop: int) -> list[StringReference]:
    code = image.bytes_for_vma_range(start, stop)
    registers: dict[int, int] = {}
    references: list[StringReference] = []

    for offset in range(0, len(code) - 3, 4):
        pc = start + offset
        instruction = struct.unpack_from("<I", code, offset)[0]

        adr = decode_adr_or_adrp(instruction, pc)
        if adr is not None:
            rd, target = adr
            registers[rd] = target
            value = image.cstring_at_vma(target)
            if value:
                references.append(StringReference(pc=pc, register=rd, target=target, value=value))
            continue

        add = decode_add_immediate(instruction)
        if add is not None:
            rd, rn, immediate = add
            if rn in registers:
                target = registers[rn] + immediate
                registers[rd] = target
                value = image.cstring_at_vma(target)
                if value:
                    references.append(StringReference(pc=pc, register=rd, target=target, value=value))
            continue

    deduped: list[StringReference] = []
    seen = set()
    for reference in references:
        key = (reference.pc, reference.target, reference.value)
        if key not in seen:
            seen.add(key)
            deduped.append(reference)
    return deduped


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


def render_report(path: Path, start: int, stop: int, interesting: re.Pattern[str]) -> str:
    image = ELFImage(path)
    references = collect_string_references(image, start, stop)
    selected = [reference for reference in references if interesting.search(reference.value)]

    lines = [
        "# AirShield Registration String References",
        "",
        f"Library: `{path}`",
        f"Scan range: `0x{start:x}..0x{stop:x}`",
        "",
        "This report resolves AArch64 `ADR`/`ADRP + ADD` string references in the "
        "merged AirShield JNI registration region. It is static evidence for which "
        "Java classes, native method names, and signatures are touched by registration.",
        "",
        f"- Resolved string references: {len(references)}",
        f"- Interesting references: {len(selected)}",
        "",
        "## Interesting References",
        "",
        "| PC | Register | Target | String |",
        "| --- | --- | --- | --- |",
    ]

    for reference in selected:
        safe_value = reference.value.replace("`", "'")
        lines.append(
            f"| `0x{reference.pc:x}` | `x{reference.register}` | "
            f"`0x{reference.target:x}` | `{safe_value}` |"
        )

    lines.extend([
        "",
        "## Nearby Disassembly",
        "",
        "```asm",
        disassemble(path, start, min(stop, start + 0x1400)),
        "```",
    ])
    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description="Resolve strings referenced from the AirShield JNI registration region.")
    parser.add_argument(
        "--lib",
        type=Path,
        default=Path("reverse/native-libs/lib/arm64-v8a/libstartup.so"),
        help="ELF library path",
    )
    parser.add_argument("--start", type=lambda value: int(value, 0), default=0xD9A140)
    parser.add_argument("--stop", type=lambda value: int(value, 0), default=0xDA3000)
    parser.add_argument(
        "--interesting",
        default=(
            r"airshield|StreamSecurer|Preamble|CipherBuilder|Framing|Native|"
            r"Challenge|Encryption|Stream|Lcom/facebook/wearable/airshield|"
            r"\(|\)|\[B|\[Z"
        ),
        help="case-insensitive regex for strings to include in the main table",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reverse/airshield-registration-xrefs.md"),
        help="markdown output path",
    )
    args = parser.parse_args()

    report = render_report(args.lib, args.start, args.stop, re.compile(args.interesting, re.IGNORECASE))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
