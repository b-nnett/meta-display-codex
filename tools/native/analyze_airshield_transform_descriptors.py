#!/usr/bin/env python3
import argparse
import struct
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
class DescriptorRoot:
    index: int
    row_addr: int
    descriptor_addr: int
    auxiliary: int
    descriptor_word: int
    family_type: Optional[int]


class ELFImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:4] != b"\x7fELF":
            raise ValueError(f"{path} is not an ELF file")
        if self.data[4] != 2 or self.data[5] != 1:
            raise ValueError("only little-endian ELF64 is supported")
        self.sections = self._parse_sections()

    def _parse_sections(self) -> list[Section]:
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

    def vma_to_offset(self, vma: int) -> Optional[int]:
        for section in self.sections:
            if section.addr <= vma < section.addr + section.size:
                return section.offset + (vma - section.addr)
        return None

    def offset_to_vma(self, offset: int) -> Optional[tuple[int, str]]:
        for section in self.sections:
            if section.offset <= offset < section.offset + section.size:
                return section.addr + (offset - section.offset), section.name
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


DESCRIPTOR_ROOT_TABLE = 0xFFB0E8
FAMILY_TABLE = 0xFFB1B0
DESCRIPTOR_ROW_SIZE = 16
LOOKUP_MATERIAL_BITS = 0x100
LOOKUP_MODE = 2


TRANSFORM_HANDOFF_INSTRUCTIONS = [
    (
        0xE97A20,
        0xAA0003F3,
        "`mov x19, x0` preserves the selected transform-state base for the generic setter direct-copy path.",
    ),
    (
        0xE97A24,
        0x9100E000,
        "`add x0, x0, #0x38` makes the direct-copy destination `transform_state + 0x38`.",
    ),
    (
        0xDB1908,
        0xF802C263,
        "`stur x3, [x19, #0x2c]` stores the lower 64 bits of the selected setup window in the AirShield cipher-context wrapper.",
    ),
    (
        0xDB190C,
        0xF8034264,
        "`stur x4, [x19, #0x34]` stores the upper 64 bits of the selected setup window directly after it.",
    ),
    (
        0xDB19B0,
        0x52800202,
        "`mov w2, #0x10` passes a 16-byte setter length to the transform setter.",
    ),
    (
        0xDB19B4,
        0x97E26D8B,
        "`bl 0x64cfe0` calls the generic transform material/state setter with that 16-byte window.",
    ),
    (
        0x64D048,
        0xAA0203F4,
        "`mov x20, x2` preserves the requested setter length before the direct-copy path.",
    ),
    (
        0x64D04C,
        0x9421FCB1,
        "`bl memcpy` copies the 16-byte setter input to `transform_state + 0x38`.",
    ),
    (
        0x64D050,
        0xF9002674,
        "`str x20, [x19, #0x48]` records the copied setter length in transform state.",
    ),
    (
        0x64C0DC,
        0x9100C2A2,
        "`add x2, x21, #0x30` passes the partial-block offset storage to the mode-2 CTR helper.",
    ),
    (
        0x64C0E0,
        0x9100E2A3,
        "`add x3, x21, #0x38` passes `transform_state + 0x38` as the CTR counter-block pointer.",
    ),
    (
        0x64C0E4,
        0x910082A4,
        "`add x4, x21, #0x20` passes the cached keystream-block pointer to the mode-2 CTR helper.",
    ),
    (
        0x64C0E8,
        0xF9400D08,
        "`ldr x8, [x8, #0x18]` selects the family CTR payload helper slot.",
    ),
    (
        0xDB2F84,
        0xAA0303F8,
        "`mov x24, x3` makes the helper's counter pointer equal to `transform_state + 0x38`.",
    ),
    (
        0xDB19EC,
        0x1000A008,
        "`adr x8, 0xdb2dec` loads the selected mode-2 completion/output-pointer helper.",
    ),
    (
        0xDB19F0,
        0xA901229F,
        "`stp xzr, x8, [x20, #0x10]` installs the mode-2 helper in the transform object.",
    ),
    (
        0xDB3014,
        0x97E0838C,
        "`bl 0x5d3e44` transforms the current 16-byte counter block before the increment sequence.",
    ),
    (
        0xDB301C,
        0x52800188,
        "`mov w8, #0xc` starts post-block increment at counter byte offset 12.",
    ),
    (
        0xDB3020,
        0xB8686B09,
        "`ldr w9, [x24, x8]` reads the current big-endian counter word.",
    ),
    (
        0xDB3034,
        0xB8286B0A,
        "`str w10, [x24, x8]` writes the incremented big-endian counter word.",
    ),
]


def decode_descriptor_word(word: int) -> dict[str, int]:
    return {
        "block_size": word & 0x1F,
        "minimum_key_bytes": (word >> 3) & 0x1C,
        "material_bits": (word >> 2) & 0x3C0,
        "mode": (word >> 12) & 0xF,
        "bypass_size_check": (word >> 25) & 0x1,
        "family_index": (word >> 26) & 0x1F,
    }


def collect_descriptor_roots(image: ELFImage) -> list[DescriptorRoot]:
    roots: list[DescriptorRoot] = []
    index = 0
    while True:
        row_addr = DESCRIPTOR_ROOT_TABLE + index * DESCRIPTOR_ROW_SIZE
        descriptor_addr = image.u64_at_vma(row_addr)
        auxiliary = image.u64_at_vma(row_addr + 8)
        if descriptor_addr == 0:
            break
        descriptor_word = image.u32_at_vma(descriptor_addr + 8)
        decoded = decode_descriptor_word(descriptor_word)
        family_ptr = image.u64_at_vma(FAMILY_TABLE + decoded["family_index"] * 8)
        family_type = image.u32_at_vma(family_ptr) if family_ptr else None
        roots.append(DescriptorRoot(
            index=index,
            row_addr=row_addr,
            descriptor_addr=descriptor_addr,
            auxiliary=auxiliary,
            descriptor_word=descriptor_word,
            family_type=family_type,
        ))
        index += 1
    return roots


def selected_root(roots: list[DescriptorRoot]) -> Optional[DescriptorRoot]:
    for root in roots:
        decoded = decode_descriptor_word(root.descriptor_word)
        if (
            root.family_type == 2
            and decoded["material_bits"] == LOOKUP_MATERIAL_BITS
            and decoded["mode"] == LOOKUP_MODE
        ):
            return root
    return None


def find_strings(image: ELFImage, needles: list[bytes]) -> dict[str, list[tuple[int, str]]]:
    hits: dict[str, list[tuple[int, str]]] = {}
    for needle in needles:
        label = needle.decode("ascii")
        hits[label] = []
        start = 0
        while True:
            offset = image.data.find(needle, start)
            if offset < 0:
                break
            mapped = image.offset_to_vma(offset)
            if mapped is not None:
                hits[label].append(mapped)
            start = offset + 1
    return hits


def find_pattern_vmas(image: ELFImage, patterns: dict[str, bytes]) -> dict[str, list[tuple[int, str]]]:
    hits: dict[str, list[tuple[int, str]]] = {}
    for label, pattern in patterns.items():
        hits[label] = []
        start = 0
        while True:
            offset = image.data.find(pattern, start)
            if offset < 0:
                break
            mapped = image.offset_to_vma(offset)
            if mapped is not None:
                hits[label].append(mapped)
            start = offset + 1
    return hits


def instruction_check_lines(image: ELFImage) -> list[str]:
    lines = [
        "| Address | Check | Instruction evidence |",
        "| --- | --- | --- |",
    ]
    for address, expected, description in TRANSFORM_HANDOFF_INSTRUCTIONS:
        actual = image.u32_at_vma(address)
        check = "ok" if actual == expected else f"mismatch: `0x{actual:08x}`"
        lines.append(f"| `0x{address:x}` | {check} | {description} |")
    return lines


def render_report(path: Path) -> str:
    image = ELFImage(path)
    roots = collect_descriptor_roots(image)
    selected = selected_root(roots)
    string_hits = find_strings(image, [
        b"AES_encrypt",
        b"AES_set_encrypt_key",
        b"aes-128-ctr",
        b"aes-192-ctr",
        b"aes-256-ctr",
    ])
    aes_pattern_hits = find_pattern_vmas(image, {
        "AES inverse S-box prefix": bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"),
        "AES Rcon prefix": bytes.fromhex("01020408102040801b36"),
    })

    lines = [
        "# AirShield Transform Descriptor Report",
        "",
        f"Library: `{path}`",
        "",
        "This report decodes the transform descriptor root table used by helper "
        "`0x64bf18`, then applies the AirShield cipher context lookup observed at "
        "`0xdb1960...0xdb1968` (`w0 = 0x100`, `w1 = 2`).",
        "",
        "The descriptor words are static addresses/values from the APK's "
        "`libstartup.so`.",
        "",
        "## Lookup Result",
        "",
    ]
    if selected is None:
        lines.append("- No descriptor matched the observed AirShield lookup.")
    else:
        decoded = decode_descriptor_word(selected.descriptor_word)
        lines.extend([
            f"- Selected root index: `{selected.index}`",
            f"- Descriptor root row: `0x{selected.row_addr:x}`",
            f"- Descriptor struct: `0x{selected.descriptor_addr:x}`",
            f"- Descriptor word at struct+8: `0x{selected.descriptor_word:08x}`",
            f"- Family type: `{selected.family_type}`",
            f"- Block size: `{decoded['block_size']}` bytes",
            f"- Minimum key/material setter size: `{decoded['minimum_key_bytes']}` bytes",
            f"- Material size field: `0x{decoded['material_bits']:x}` bits",
            f"- Mode: `{decoded['mode']}`",
            f"- Algorithm family index: `{decoded['family_index']}`",
            f"- Bypass size check bit: `{decoded['bypass_size_check']}`",
            "",
            "Static call-site evidence:",
            "",
            "- `0xdb1960`: `mov w0, #0x100`",
            "- `0xdb1964`: `mov w1, #0x2`",
            "- `0xdb1968`: `bl 0x64bf18` selects the descriptor above.",
            "- `0xdb19b0`: `mov w2, #0x10` before `0x64cfe0`, so the setup copies 16 bytes into transform state.",
            "- Setter/call-site evidence maps that 16-byte input as the final eight raw seed bytes (`seed[24..<32]`, builder `0x238...0x23f`) followed by the first eight raw IV bytes (`iv[0..<8]`, builder `0x240...0x247`).",
            "- `0xdb19c8`: `mov w2, #0x100` before `0x63327c`, so final transform configuration uses the same 256-bit material size field.",
            "- `0xdb19d8...0xdb19f4`: if descriptor mode is `2`, the context installs helper `0xdb2dec` into the transform object.",
            "- `0x64c0dc...0x64c0e8`: the generic transform dispatcher passes state offset `0x38` as the counter-block pointer to the family-0 mode-2 payload helper.",
            "- `0xdb2f54...0xdb3060`: family-0 CTR-like helper consumes the current 16-byte counter block at state offset `0x38`, then increments it as a big-endian 128-bit value by starting at byte offset `12`, carrying through offsets `8`, `4`, then `0` on overflow.",
        ])

    lines.extend([
        "",
        "## Selected Transform Setup And Counter Handoff",
        "",
        *instruction_check_lines(image),
        "",
        "Interpretation of the checked instructions:",
        "",
        "- AirShield stores the mapped setup window as two adjacent 64-bit words in the cipher-context wrapper at offsets `0x2c` and `0x34`.",
        "- The generic setter is called with length `0x10`; its direct-copy path changes the copy destination to `transform_state + 0x38`, copies the 16-byte setter input there, and records the copied length at transform-state offset `0x48`, with no byte-swap instruction between the AirShield wrapper store and the state copy.",
        "- Mode `2` installs helper `0xdb2dec` after configuration. That helper only returns the selected output pointer through caller-provided storage and clears the secondary pointer, so it is not an alternate cipher or counter derivation step.",
        "- The mode-2 dispatcher passes `transform_state + 0x38` as the CTR counter-block pointer, and the CTR payload helper keeps that pointer in `x24`; it calls the AES block transform at `0xdb3014` before incrementing that counter at `0xdb301c...0xdb3034`. Swift's `seed[24..<32] + iv[0..<8]` current-counter-then-increment candidate matches this ordering.",
        "",
        "## Selected Family Function Table",
        "",
        "| Family offset | Function | Role evidence |",
        "| --- | --- | --- |",
        "| `+0x08` | `0x64c278` | Returns through helper `0x5d3e44`; selected family low-level block helper slot. |",
        "| `+0x10` | `0xdb2e24` | Block-aligned transform helper; calls `0x5d3e44` for 16-byte blocks and XORs block output with payload. |",
        "| `+0x18` | `0xdb2f54` | CTR-like payload helper; XORs with generated block material and increments the 16-byte counter block at transform-state offset `0x38`. |",
        "| `+0x20` | `0x6332ec` | Direct branch to `0x5d271c`, the AES key schedule helper. Selected when AirShield passes the nonzero configure flag. |",
        "| `+0x28` | `0xdb3064` | Reverse/alternate key-schedule path; calls `0x5d271c`, then derives a transformed schedule using AES tables. Selected when AirShield passes the zero configure flag. |",
        "| `+0x30` | `0x633128` | Allocation/copy helper slot for this transform family. |",
        "| `+0x38` | `0x652d28` | Cleanup/free helper slot for this transform family. |",
    ])

    lines.extend([
        "",
        "## Descriptor Roots",
        "",
        "| Index | Root row | Descriptor struct | Auxiliary | Descriptor word | Family type | Block | Min setter bytes | Material bits | Mode | Family | Bypass | Match |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ])
    for root in roots:
        decoded = decode_descriptor_word(root.descriptor_word)
        is_match = root == selected
        lines.append(
            "| "
            f"`{root.index}` | "
            f"`0x{root.row_addr:x}` | "
            f"`0x{root.descriptor_addr:x}` | "
            f"`0x{root.auxiliary:x}` | "
            f"`0x{root.descriptor_word:08x}` | "
            f"`{root.family_type}` | "
            f"`{decoded['block_size']}` | "
            f"`{decoded['minimum_key_bytes']}` | "
            f"`0x{decoded['material_bits']:x}` | "
            f"`{decoded['mode']}` | "
            f"`{decoded['family_index']}` | "
            f"`{decoded['bypass_size_check']}` | "
            f"{'yes' if is_match else ''} |"
        )

    lines.extend([
        "",
        "## AES/CTR Static Evidence",
        "",
        "| String | VMAs |",
        "| --- | --- |",
    ])
    for label, hits in string_hits.items():
        rendered_hits = ", ".join(f"`0x{vma:x}` ({section})" for vma, section in hits) or ""
        lines.append(f"| `{label}` | {rendered_hits} |")

    lines.extend([
        "",
        "## AES Helper Evidence",
        "",
        "| Evidence | VMAs |",
        "| --- | --- |",
    ])
    for label, hits in aes_pattern_hits.items():
        rendered_hits = ", ".join(f"`0x{vma:x}` ({section})" for vma, section in hits) or ""
        lines.append(f"| `{label}` | {rendered_hits} |")
    lines.extend([
        "",
        "- Helper `0x5d271c` branches on key sizes `0x80`, `0xc0`, and `0x100`, and writes AES round counts `10`, `12`, and `14`.",
        "- Helper `0x5d271c` generates AES S-box/T-table state using `0x1b` finite-field reduction and AES Rcon material.",
        "- Helper `0x5d3e44` uses the generated AES T-tables for 16-byte block transforms.",
        "- Selected family helper `0xdb2f54` feeds those 16-byte block transforms into a CTR-style XOR path.",
    ])

    lines.extend([
        "",
        "## Interpretation",
        "",
        "- The AirShield framing context builder does not leave the transform descriptor open-ended: static lookup selects descriptor word `0x00072490`.",
        "- That descriptor is a 16-byte block, mode-2, 256-bit-material transform in family index `0` with family type `2`.",
        "- The separate mode-6 buffered stream helper still belongs to the same transform library, but it is not the descriptor selected by the observed `0xdb18d4` AirShield setup path.",
        "- Family-0 helper `0xdb2f54` is CTR-like: it XORs input/output with generated block material and increments a 32-bit counter at offset `12` of the 16-byte counter block copied into transform-state offset `0x38`.",
        "- Counter increment is post-block and big-endian at the 128-bit block level: bytes `12...15` are incremented first, with carry toward bytes `0...3`.",
        "- The selected 256-bit material field, selected family key-schedule path, AES constants/tables, and CTR-like payload helper now support AES-256-CTR as the selected transform.",
        "- Corrected JNI setter evidence maps the selected setup input as `seed[24..<32] + iv[0..<8]`; static transform-dispatch evidence now shows that exact copied 16-byte state at offset `0x38` is the first CTR counter block consumed by the mode-2 payload helper.",
    ])
    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description="Decode AirShield transform descriptor table evidence.")
    parser.add_argument(
        "--lib",
        type=Path,
        default=Path("reverse/native-libs/lib/arm64-v8a/libstartup.so"),
        help="ELF library path",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reverse/airshield-transform-descriptors.md"),
        help="markdown output path",
    )
    args = parser.parse_args()

    report = render_report(args.lib)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
