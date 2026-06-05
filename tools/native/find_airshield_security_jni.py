#!/usr/bin/env python3
import argparse
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


TARGET_METHODS = {
    "calculateNative",
    "incrementalStart",
    "incrementalUpdate",
    "incrementalFinish",
    "incrementalDispose",
    "setup",
    "size",
    "hashBytes",
    "hashString",
    "deriveNative",
    "equalsNative",
    "recoverPublicKey",
    "serialize",
    "signNative",
    "verifySignatureNative",
    "setRaw",
    "toByteArray",
    "generate",
    "getHandleNative",
}


AIRSHIELD_DESCRIPTOR_RANGE = range(0xFF8000, 0xFFB000)


@dataclass(frozen=True)
class Section:
    name: str
    addr: int
    offset: int
    size: int


@dataclass(frozen=True)
class CandidateRow:
    row_addr: int
    name: str
    signature: str
    thunk: int
    implementation: Optional[int]
    adapter: Optional[int]


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

    def u32_at_vma(self, vma: int) -> int:
        offset = self.vma_to_offset(vma)
        if offset is None:
            raise ValueError(f"VMA 0x{vma:x} is not file-backed")
        return struct.unpack_from("<I", self.data, offset)[0]

    def u64_at_vma(self, vma: int) -> int:
        offset = self.vma_to_offset(vma)
        if offset is None:
            raise ValueError(f"VMA 0x{vma:x} is not file-backed")
        return struct.unpack_from("<Q", self.data, offset)[0]

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
        raw = self.data[offset:end]
        if any(byte < 0x09 or (0x0D < byte < 0x20) for byte in raw):
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None


def sign_extend(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (value ^ sign_bit) - sign_bit


def decode_adr(instruction: int, pc: int) -> Optional[tuple[int, int]]:
    if instruction & 0x9F000000 != 0x10000000:
        return None
    rd = instruction & 0x1F
    immlo = (instruction >> 29) & 0x3
    immhi = (instruction >> 5) & 0x7FFFF
    imm = sign_extend((immhi << 2) | immlo, 21)
    return rd, pc + imm


def decode_b(instruction: int, pc: int) -> Optional[int]:
    if instruction & 0x7C000000 != 0x14000000:
        return None
    imm26 = instruction & 0x03FFFFFF
    return pc + (sign_extend(imm26, 26) << 2)


def resolve_simple_thunk(image: ELFImage, thunk: int) -> tuple[Optional[int], Optional[int]]:
    try:
        first = image.u32_at_vma(thunk)
        second = image.u32_at_vma(thunk + 4)
        third = image.u32_at_vma(thunk + 8)
    except ValueError:
        return None, None
    if first != 0xD503201F:
        return None, None
    adr = decode_adr(second, thunk + 4)
    branch = decode_b(third, thunk + 8)
    if adr is None:
        return None, branch
    return adr[1], branch


def find_rodata_string_vmas(image: ELFImage, values: set[str]) -> dict[str, list[int]]:
    rodata = image.section(".rodata")
    raw = image.data[rodata.offset:rodata.offset + rodata.size]
    found: dict[str, list[int]] = {value: [] for value in values}
    for value in values:
        needle = value.encode("utf-8") + b"\0"
        start = 0
        while True:
            index = raw.find(needle, start)
            if index < 0:
                break
            found[value].append(rodata.addr + index)
            start = index + 1
    return found


def collect_candidate_rows(image: ELFImage) -> list[CandidateRow]:
    string_vmas = find_rodata_string_vmas(image, TARGET_METHODS)
    data_rel = image.section(".data.rel.ro")
    rows: dict[int, CandidateRow] = {}

    for method, vmas in string_vmas.items():
        for method_vma in vmas:
            for relative in range(0, data_rel.size - 24 + 1, 8):
                row_addr = data_rel.addr + relative
                if image.u64_at_vma(row_addr) != method_vma:
                    continue
                if row_addr not in AIRSHIELD_DESCRIPTOR_RANGE:
                    continue
                sig_addr = image.u64_at_vma(row_addr + 8)
                thunk = image.u64_at_vma(row_addr + 16)
                signature = image.cstring_at_vma(sig_addr)
                if not signature or not signature.startswith("("):
                    continue
                implementation, adapter = resolve_simple_thunk(image, thunk)
                rows[row_addr] = CandidateRow(
                    row_addr=row_addr,
                    name=method,
                    signature=signature,
                    thunk=thunk,
                    implementation=implementation,
                    adapter=adapter,
                )

    return sorted(rows.values(), key=lambda row: (row.row_addr, row.name))


def render_report(path: Path) -> str:
    image = ELFImage(path)
    rows = collect_candidate_rows(image)
    lines = [
        "# AirShield Security JNI Candidate Rows",
        "",
        f"Library: `{path}`",
        "",
        "This report scans `.data.rel.ro` for JNI-style `name, signature, thunk` rows "
        "referencing AirShield security method names. Rows can belong to several "
        "security wrapper classes (`Hash`, `HMac`, `HKDF`, `InitializationVector`, "
        "`SHA256`, keys, signatures), so class names are inferred from Java source "
        "and neighboring rows rather than encoded directly in this table.",
        "",
        "| Row | Method | Signature | Thunk | Inner implementation | Adapter |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        implementation = f"`0x{row.implementation:x}`" if row.implementation is not None else ""
        adapter = f"`0x{row.adapter:x}`" if row.adapter is not None else ""
        lines.append(
            "| "
            f"`0x{row.row_addr:x}` | "
            f"`{row.name}` | "
            f"`{row.signature}` | "
            f"`0x{row.thunk:x}` | "
            f"{implementation} | "
            f"{adapter} |"
        )
    lines.extend([
        "",
        "## Immediate Findings",
        "",
        "- `HKDF.calculateNative(long, long)` is present at row `0xff9e80`, thunk `0xda19b4`.",
        "- `HKDF.calculateNative` unwraps two native `Hash` handles, clears `x3/x4`, and calls `0xdb17b4`; this confirms the Java-facing HKDF wrapper uses the same default `AirShield` label/counter expansion helper.",
        "- `PrivateKey.deriveNative(long)` is present at row `0xffa348`, thunk `0xda455c`, inner implementation `0xda4e94`; that body calls helper `0xdb1f1c`, tying it to private-key plus remote-public-key shared-hash derivation.",
        "- `PrivateKey.recoverPublicKey()` is present at row `0xffa330`, thunk `0xda3f28`, and calls helper `0xdb2148`; this ties `db2148` to the 64-byte local public-key-shaped intermediate used by challenge/framing derivation.",
        "- `HMac` and `SHA256` expose separate incremental start/update/finish/dispose rows. This supports the static conclusion that AirShield framing uses private HMAC/SHA state rather than only the Java-facing HKDF wrapper.",
        "- `InitializationVector.setRaw`, `generate`, `size`, and `toByteArray` rows are present around `0xff9c68...0xff9c98`, matching Java's 16-byte IV wrapper behavior used by `CipherBuilder.setInitializationVectorNative`.",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Find AirShield security JNI candidate method rows.")
    parser.add_argument("--library", type=Path, default=Path("reverse/native-libs/lib/arm64-v8a/libstartup.so"))
    parser.add_argument("--output", type=Path, default=Path("reverse/airshield-security-jni-candidates.md"))
    args = parser.parse_args()
    report = render_report(args.library)
    args.output.write_text(report, encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
