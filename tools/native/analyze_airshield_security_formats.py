#!/usr/bin/env python3
"""Report Java-facing AirShield Hash/Signature byte formats from libstartup.so."""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM


DEFAULT_LIBRARY = Path("reverse/native-libs/lib/arm64-v8a/libstartup.so")
DEFAULT_OUTPUT = Path("reverse/airshield-security-formats.md")


@dataclass(frozen=True)
class Section:
    name: str
    addr: int
    offset: int
    size: int


class ELFImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:4] != b"\x7fELF" or self.data[4] != 2 or self.data[5] != 1:
            raise ValueError("expected little-endian ELF64")
        self.sections = self._sections()

    def _sections(self) -> list[Section]:
        e_shoff = struct.unpack_from("<Q", self.data, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", self.data, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", self.data, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", self.data, 0x3E)[0]
        raw = []
        for index in range(e_shnum):
            offset = e_shoff + index * e_shentsize
            name_offset = struct.unpack_from("<I", self.data, offset)[0]
            addr = struct.unpack_from("<Q", self.data, offset + 0x10)[0]
            file_offset = struct.unpack_from("<Q", self.data, offset + 0x18)[0]
            size = struct.unpack_from("<Q", self.data, offset + 0x20)[0]
            raw.append((name_offset, addr, file_offset, size))

        _, _, shstr_offset, shstr_size = raw[e_shstrndx]
        shstr = self.data[shstr_offset:shstr_offset + shstr_size]

        def section_name(name_offset: int) -> str:
            end = shstr.find(b"\0", name_offset)
            return shstr[name_offset:end].decode("utf-8", "replace")

        return [
            Section(section_name(name_offset), addr, file_offset, size)
            for name_offset, addr, file_offset, size in raw
        ]

    def vma_to_offset(self, vma: int) -> int:
        for section in self.sections:
            if section.addr <= vma < section.addr + section.size:
                return section.offset + (vma - section.addr)
        raise ValueError(f"VMA 0x{vma:x} is not file-backed")

    def bytes_at_vma(self, vma: int, size: int) -> bytes:
        offset = self.vma_to_offset(vma)
        return self.data[offset:offset + size]


def disassemble(image: ELFImage, start: int, stop: int) -> list[str]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    return [
        f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}".rstrip()
        for insn in md.disasm(image.bytes_at_vma(start, stop - start), start)
    ]


def contains(disassembly: list[str], needle: str) -> bool:
    return any(needle in line for line in disassembly)


def require_evidence(label: str, disassembly: list[str], needle: str) -> None:
    if not contains(disassembly, needle):
        raise SystemExit(f"{label}: missing evidence `{needle}`")


def fenced(lines: list[str]) -> list[str]:
    return ["```asm", *lines, "```"]


def render_report(library: Path) -> str:
    image = ELFImage(library)
    snippets = {
        "iv_to_byte_array": disassemble(image, 0xDA0BFC, 0xDA0C44),
        "hash_to_byte_array": disassemble(image, 0xDA2AE0, 0xDA2B24),
        "hash_equals": disassemble(image, 0xDA2B70, 0xDA2BC4),
        "hash_set_raw": disassemble(image, 0xDA2D10, 0xDA2DA4),
        "private_key_sign": disassemble(image, 0xDA4568, 0xDA4610),
        "signature_to_byte_array": disassemble(image, 0xDA6028, 0xDA6070),
        "signature_equals": disassemble(image, 0xDA60B8, 0xDA610C),
        "signature_size_or_hash": disassemble(image, 0xDA615C, 0xDA61BC),
    }

    require_evidence("InitializationVector.toByteArray", snippets["iv_to_byte_array"], "movz w3, #0x10")
    require_evidence("Hash.equalsNative", snippets["hash_equals"], "cmp x10, #0x20")
    require_evidence("Hash.setRaw", snippets["hash_set_raw"], "cmp w21, #0x20")
    require_evidence("PrivateKey.signNative result copy", snippets["private_key_sign"], "stur q1, [x0, #0x48]")
    require_evidence("Signature.equalsNative", snippets["signature_equals"], "cmp x10, #0x40")
    require_evidence("Signature size/setRaw group", snippets["signature_size_or_hash"], "cmp x8, #0x40")

    lines = [
        "# AirShield Security Byte Formats",
        "",
        f"Library: `{library}`",
        "",
        "This report narrows the Java-facing byte formats for the AirShield security",
        "wrappers used by preamble authentication. It is generated from focused",
        "AArch64 disassembly around the JNI rows listed in",
        "`reverse/airshield-security-jni-candidates.md`.",
        "",
        "## Findings",
        "",
        "- `InitializationVector.toByteArray()` returns 16 bytes. Its JNI body passes `w3 = 0x10` into the Java byte-array copy helper.",
        "- `Hash.toByteArray()` is in the 32-byte `Hash` wrapper group. Neighboring `Hash.equalsNative` compares `0x20` bytes and `Hash.setRaw(...)` accepts only `0x20` bytes.",
        "- `PrivateKey.signNative(Hash)` produces a 64-byte native `Signature` object. The result constructor copies four 16-byte SIMD chunks into the returned signature storage.",
        "- `Signature.toByteArray()` is in the 64-byte `Signature` wrapper group. Neighboring `Signature.equalsNative` compares `0x40` bytes and the adjacent size/setRaw group uses `0x40`.",
        "- For production Identity `EnableTrust`, Android therefore sends a 32-byte hash input into native signing and expects a raw 64-byte P-256 ECDSA signature-like value, not DER.",
        "",
        "## Method Rows",
        "",
        "| Class inference | JNI row | Method | Thunk/body | Format evidence |",
        "| --- | --- | --- | --- | --- |",
        "| `Hash` | `0xffa060` | `toByteArray()[B` | `0xda2ae0` | 32-byte wrapper group |",
        "| `Hash` | `0xffa0c0` | `setRaw([B)V` | `0xda2d04`/`0xda3154` | requires `0x20` bytes |",
        "| `PrivateKey` | `0xffa360` | `signNative(J)` | `0xda4568`/`0xda4574` | builds 64-byte `Signature` |",
        "| `Signature` | `0xffa6d8` | `toByteArray()[B` | `0xda6028` | 64-byte wrapper group |",
        "",
        "## Evidence Snippets",
        "",
        "### IV length control",
        *fenced(snippets["iv_to_byte_array"]),
        "",
        "### Hash `toByteArray` body",
        *fenced(snippets["hash_to_byte_array"]),
        "",
        "### Hash 32-byte equality loop",
        *fenced(snippets["hash_equals"]),
        "",
        "### Hash 32-byte `setRaw` guard",
        *fenced(snippets["hash_set_raw"]),
        "",
        "### `PrivateKey.signNative` 64-byte signature object construction",
        *fenced(snippets["private_key_sign"]),
        "",
        "### Signature `toByteArray` body",
        *fenced(snippets["signature_to_byte_array"]),
        "",
        "### Signature 64-byte equality loop",
        *fenced(snippets["signature_equals"]),
        "",
        "### Signature 64-byte size/setRaw group",
        *fenced(snippets["signature_size_or_hash"]),
        "",
        "## Remaining Gap",
        "",
        "The byte formats are now static-confirmed, and the Mac bridge prepares a",
        "native-format raw64 candidate through macOS Security's raw-digest ECDSA",
        "path. CryptoKit comparison candidates remain non-native because",
        "`signature(for: Data)` signs `SHA256(data)`. Keep Mac `EnableTrust`",
        "transmit gated until Android accepted-identity path matching proves which",
        "imported key and identifier source should be used.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, default=DEFAULT_LIBRARY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = render_report(args.library)
    args.output.write_text(report, encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
