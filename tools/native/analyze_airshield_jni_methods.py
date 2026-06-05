#!/usr/bin/env python3
import argparse
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
class MethodRow:
    class_name: str
    row_addr: int
    name: str
    signature: str
    thunk: int
    implementation: Optional[int]
    adapter: Optional[int]


TABLES = [
    {
        "class_name": "com/facebook/wearable/airshield/stream/CipherBuilder",
        "start": 0xFFA7F0,
        "rows": 10,
        "layout": "name_sig_fn",
    },
    {
        "class_name": "com/facebook/wearable/airshield/stream/Framing",
        "start": 0xFFAA20,
        "rows": 6,
        "layout": "name_sig_fn",
    },
]


INTERESTING_METHODS = {
    "setPrivateKey",
    "setChallengeNative",
    "setSeedNative",
    "setInitializationVectorNative",
    "setRemotePublicKeyNative",
    "buildRxChallengeNative",
    "buildTxChallengeNative",
    "buildEncryptionFramingNative",
    "buildDecryptionFramingNative",
    "outerFrameSizeNative",
    "packNative",
    "unpackNative",
    "cipherPayloadSizeNative",
}


FRAMING_BODY_DETAILS = {
    "packNative": (0xDA7A5C, 0xDA79BC),
    "unpackNative": (0xDA7918, 0xDA79BC),
}


FRAMING_OUTER_FRAME_INSTRUCTIONS = [
    (0xDA7680, 0x52820129, "`mov w9, #0x1009` sets the over-limit outer-frame error value."),
    (0xDA7684, 0x12000D08, "`and w8, w8, #0xf` computes 16-byte padding alignment."),
    (0xDA7690, 0x11002508, "`add w8, w8, #0x9` adds the fixed 9-byte encrypted outer-frame overhead."),
    (0xDA77A0, 0x7100667F, "`cmp w19, #0x19` requires at least 25 bytes for one encrypted outer frame."),
    (0xDA77AC, 0x39402108, "`ldrb w8, [x8, #0x8]` reads the cipher-payload size indicator at byte 8."),
    (0xDA77B0, 0xD37CED08, "`lsl x8, x8, #4` multiplies the indicator by 16 bytes."),
    (0xDA77B4, 0x91006509, "`add x9, x8, #0x19` adds 25 bytes, proving payload size `(indicator + 1) * 16` plus 9 overhead."),
    (0xDB1424, 0x91002698, "`add x24, x20, #0x9` sets the pack cipher-payload write pointer to outer-frame byte 9."),
    (0xDB1430, 0x39002288, "`strb w8, [x20, #0x8]` writes byte 8 as the cipher-payload block-count indicator."),
    (0xDB1524, 0x91020261, "`add x1, x19, #0x80` selects the computed 8-byte validation-prefix buffer."),
    (0xDB1538, 0xF9000288, "`str x8, [x20]` writes the computed 8-byte validation prefix to outer-frame bytes 0...7."),
    (0xDB15D4, 0xF100645F, "`cmp x2, #0x19` makes unpack reject frames shorter than one 9-byte overhead plus one 16-byte block."),
    (0xDB15E8, 0x38408EE8, "`ldrb w8, [x23, #0x8]!` reads byte 8 and advances the unpack pointer to that indicator byte."),
    (0xDB15EC, 0xD37CED19, "`lsl x25, x8, #4` computes the encrypted payload length minus the first 16-byte block."),
    (0xDB15F0, 0x91006728, "`add x8, x25, #0x19` verifies the full encrypted frame fits before decrypt/copy."),
]


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
        value = self.data[offset:end]
        if any(byte < 0x09 or (0x0D < byte < 0x20) for byte in value):
            return None
        try:
            return value.decode("utf-8")
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
    if first != 0xD503201F:  # nop
        return None, None
    adr = decode_adr(second, thunk + 4)
    branch = decode_b(third, thunk + 8)
    if adr is None or branch is None:
        return None, branch
    _, target = adr
    return target, branch


def collect_rows(image: ELFImage) -> list[MethodRow]:
    rows: list[MethodRow] = []
    for table in TABLES:
        for index in range(table["rows"]):
            row_addr = table["start"] + index * 24
            a = image.u64_at_vma(row_addr)
            b = image.u64_at_vma(row_addr + 8)
            c = image.u64_at_vma(row_addr + 16)
            if table["layout"] == "name_sig_fn":
                name_addr, sig_addr, thunk = a, b, c
            elif table["layout"] == "fn_name_sig":
                thunk, name_addr, sig_addr = a, b, c
            else:
                raise ValueError(table["layout"])
            name = image.cstring_at_vma(name_addr) or f"0x{name_addr:x}"
            signature = image.cstring_at_vma(sig_addr) or f"0x{sig_addr:x}"
            implementation, adapter = resolve_simple_thunk(image, thunk)
            if implementation is None and name in FRAMING_BODY_DETAILS:
                implementation, adapter = FRAMING_BODY_DETAILS[name]
            rows.append(MethodRow(
                class_name=table["class_name"],
                row_addr=row_addr,
                name=name,
                signature=signature,
                thunk=thunk,
                implementation=implementation,
                adapter=adapter,
            ))
    return rows


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


def framing_outer_frame_check_lines(image: ELFImage) -> list[str]:
    lines = [
        "| Address | Check | Interpretation |",
        "| --- | --- | --- |",
    ]
    for address, expected, description in FRAMING_OUTER_FRAME_INSTRUCTIONS:
        actual = image.u32_at_vma(address)
        check = "ok" if actual == expected else f"mismatch: `0x{actual:08x}`"
        lines.append(f"| `0x{address:x}` | {check} | {description} |")
    return lines


def render_report(path: Path) -> str:
    image = ELFImage(path)
    rows = collect_rows(image)
    interesting_rows = [row for row in rows if row.name in INTERESTING_METHODS]

    lines = [
        "# AirShield JNI Method Address Report",
        "",
        f"Library: `{path}`",
        "",
        "This report decodes the AirShield `CipherBuilder` and `Framing` JNI method "
        "descriptor tables in `.data.rel.ro`. It recovers native thunk addresses and, "
        "for simple fbjni thunks, the inner implementation function and adapter target.",
        "",
        "Rows in this report are static addresses in the APK's `libstartup.so`; runtime "
        "addresses need the module base added by Frida or a debugger.",
        "",
        "## Method Table",
        "",
        "| Class | Row | Method | Signature | Thunk | Inner implementation | Adapter |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]

    for row in interesting_rows:
        implementation = f"`0x{row.implementation:x}`" if row.implementation is not None else ""
        adapter = f"`0x{row.adapter:x}`" if row.adapter is not None else ""
        lines.append(
            "| "
            f"`{row.class_name}` | "
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
        "- `CipherBuilder` and `Framing` method descriptors use `name, signature, thunk` rows in `.data.rel.ro`.",
        "- `CipherBuilder.buildEncryptionFramingNative(int, boolean)` resolves through thunk `0xda66b0` to inner implementation `0xda7124`.",
        "- `CipherBuilder.buildDecryptionFramingNative(int, boolean)` resolves through thunk `0xda66bc` to inner implementation `0xda66c8`.",
        "- `CipherBuilder.buildTxChallengeNative()` resolves through thunk `0xda66a4` to inner implementation `0xda71c8`.",
        "- `CipherBuilder.buildRxChallengeNative()` resolves through thunk `0xda6698` to inner implementation `0xda728c`.",
        "- `Framing.outerFrameSizeNative(int)` is a direct JNI body at `0xda7660`; it rounds payload size up to a 16-byte boundary and adds 9 bytes, capped with error value `0x1009` above `0x1000` input.",
        "- `Framing.cipherPayloadSizeNative(ByteBuffer, int, int)` is a direct JNI body at `0xda776c`; it requires at least 25 outer-frame bytes, reads byte `frameOffset + 8`, and returns `(indicator << 4) + 16` only when `(indicator << 4) + 25 <= availableLength`.",
        "- `Framing.packNative(...)` stores implementation pointer `0xda7a5c` and dispatches through shared adapter `0xda79bc`; the pack helper writes an 8-byte validation prefix, byte `8` as `(cipherPayloadBlocks - 1)`, and encrypted payload bytes starting at offset `9`.",
        "- `Framing.unpackNative(...)` stores implementation pointer `0xda7918` and dispatches through shared adapter `0xda79bc`; the unpack helper validates bytes `0...7`, reads byte `8`, decrypts/copies bytes starting at offset `9`, then removes native padding from the recovered plaintext length.",
        "- The shared pack/unpack helpers are at `0xdb139c` and `0xdb15c4`. They use Framing object offset `0xa4` as a per-frame counter and offset `0x80` as the computed 8-byte validation prefix buffer.",
        "- The size helpers and pack/unpack flow imply AirShield encrypted frame overhead is 9 bytes beyond the padded cipher payload, and encrypted payloads are 16-byte aligned.",
        "",
        "## Encrypted Outer-Frame Layout Instruction Checks",
        "",
        *framing_outer_frame_check_lines(image),
        "",
        "Interpretation of the checked instructions:",
        "",
        "- AirShield encrypted stream records are not nested base DataX frames. The encrypted outer frame is `validation_prefix[0...7] || size_indicator[8] || cipher_payload[9...]`.",
        "- Byte `8` stores `cipherPayloadBlocks - 1`, so the indicated encrypted payload length is `(byte8 + 1) * 16`.",
        "- The only per-frame integrity bytes in this native outer-frame layer are the 8-byte validation prefix; no separate checksum/footer is present in the mapped pack/unpack flow.",
        "",
        "## CipherBuilder State And Derivation Findings",
        "",
        "- Challenge/framing derivation helper `0xd9bfd0` initializes two SHA-256 contexts and feeds a 16-byte builder transcript challenge window at `0x108...0x117` plus a 32-byte transcript/material window at `0x218...0x237`. The first window overlaps only the first eight raw challenge bytes at `0x110...0x117`; the second overlaps only the first 24 raw seed bytes at `0x220...0x237`.",
        "- `buildTxChallengeNative()` calls `0xd9bfd0` with direction flag `1` and cleared caller context args. `buildRxChallengeNative()` calls it with direction flag `0` and cleared caller context args. Separate challenge-check call sites at `0xd9da84` and `0xd9dafc` pass a 16-byte caller context.",
        "- Fold updates inside `0xd9bfd0` use length `0x40`, matching native `Hash`/public-key storage as two 32-byte halves. Helper `0xdb2240` copies those halves from native object offsets `0xc0` and `0xd0`; helper `0xdb2148` is tied to `PrivateKey.recoverPublicKey()` (`0xffa330` / thunk `0xda3f28`) and builds the 64-byte local public-key-shaped intermediate folded by the challenge/framing path.",
        "- Direction flag `1` folds builder source `0x118` into the challenge-window digest context first, then folds the recovered-public-key intermediate into the transcript/material-window digest context. Direction flag `0` does the opposite order: recovered-public-key intermediate into the challenge-window digest context first, then builder source `0x118` into the transcript/material-window digest context when `0x210` is set.",
        "- Builder byte `0x210` is branch-relevant but not yet semantically named: `setRemotePublicKeyNative(J)` clears it when installing the remote key, and `0xd9bfd0` / `0xd9de60` branch on it during challenge/framing setup.",
        "- Helper `0xd9bfd0` also derives an intermediate 32-byte digest, optionally updates it with caller-supplied context bytes, finalizes it, and frees all three SHA contexts. This is the current best anchor for the transcript-hash path.",
        "- Framing derivation helper `0xdb17b4` takes 32 bytes of keying material, initializes an HMAC/SHA context through `0xd9a0cc` / `0xdb1b38`, updates it with either the caller-provided label/context or the static 9-byte `AirShield` label at `0x25d693`, appends a one-byte counter value `0x01`, and writes a 32-byte output blob.",
        "- Java-facing `PrivateKey.deriveNative(long)` is present at security JNI row `0xffa348`, thunk `0xda455c`, inner implementation `0xda4e94`; that body calls `0xdb1f1c`, tying the helper to private-key plus remote-public-key shared-hash derivation. `PrivateKey.recoverPublicKey()` is present at row `0xffa330`, thunk `0xda3f28`, and calls `0xdb2148`.",
        "- Corrected JNI setter evidence shows concrete builder storage used by the derivation path: `setChallengeNative([B)` validates/copies 16 bytes to builder offset `0x110`; `setRemotePublicKeyNative(J)` initializes/copies native public-key state at builder offsets `0x120` and `0x1e0`, then sets byte `0x218` as the remote-public-key active flag; `setSeedNative([B)` validates/copies 32 raw seed bytes to builder offset `0x220`; `setInitializationVectorNative(J)` copies the 16-byte native IV payload to builder offset `0x240`.",
        "- Java call-site evidence gives the semantic setup order: the responder clones the current private key, then sets the peer `RequestEncryption.challenge` and `RequestEncryption.publicKey` before building TX encryption framing; the initiator sets the peer `EnableEncryption.publicKey`, `EnableEncryption.iv`, and `EnableEncryption.seed` before building RX decryption framing.",
        "- Native option-packing evidence maps the Java `base` integer to setup option word offset `0x00` and the HKDF boolean (`EnableEncryption.parameters & 1`) to setup option byte offset `0x04`; option bytes `0x05...0x0b` are zeroed by the regular Java builder path.",
        "- RX/state setup helper `0xd9de60` derives at least two 32-byte blobs, repeatedly calls `0xdb17b4`, builds cipher context state through `0xdb18d4`, and finally passes a stack-built Framing config into `0xdb12ec`.",
        "- The normal encrypted path stages a 64-byte work area at stack `0x190`: the first 32 bytes are copied to the primary Framing config at stack `0x90` as config validation key offset `0x00`, while the second 32 bytes at stack `0x1b0` are staged as cipher key material input to `0xdb18d4`. The alternate relay config is built at stack `0x110` and also copies the first 32 work-area bytes as its validation key.",
        "- `db17b4` expansion call sites use a temporary expansion object at stack `0x40` with inline tag/status at `0x60`; successful inline output is copied into the work-area cipher-material half. A later expansion uses output object stack `0x1d0` with inline tag/status at `0x1f0`, and successful inline output is copied back into the work-area validation-key half. The derivation context buffer is staged at stack `0x200`.",
        "- When setup option byte `0x09` is `1`, the expansion calls receive explicit context pointer `0x25d60b` and length `0x88`; otherwise those args are zero and `db17b4` falls back to its default `AirShield` label.",
        "- The 0x88-byte explicit context is `AirShield`, zero padding, and trailer bytes `20 00 00 00 00 01 00 00`; Swift coverage preserves that byte sequence and the deterministic HMAC fixture for key material `00...1f`.",
        "- Framing config copy helper `0xdb12ec` is the bridge from constructor output to the runtime Framing object. It initializes the object HMAC/SHA context through `0xdb1b38` from a 32-byte validation key at config offset `0x00` plus inline-key tag at config `0x20`; the runtime object owns the HMAC/SHA context pointer at `0x00`, inline key copy at `0x08`, and key tag at `0x28`. It then copies/claims a cipher context into object offset `0x30`, writes config bytes `0x78/0x7a` into object offset `0xa0`, and writes config word `0x7c` into object offset `0xa4`.",
        "- This ties the constructor path to the pack/unpack path: the HMAC/SHA context initialized by `0xdb1b38`, plus the same `0xa0` validation mode word and `0xa4` frame counter copied by `0xdb12ec`, are consumed by `0xdb139c` and `0xdb15c4` for per-frame validation prefixes.",
        "- These findings narrow the remaining encrypted-frame gap to exact transcript/label ordering, 64-byte work-area derivation, and how the selected transform interprets its mapped setup input as the initial CTR block.",
        "",
        "## Cipher Context Findings",
        "",
        "- Cipher context builder helper `0xdb18d4` builds a small optional-like cipher context wrapper: inline state copies 32-byte material, while non-inline state stores/claims a pointer. That wrapper is later copied into the runtime Framing object by `0xdb12ec`.",
        "- Transform descriptor lookup helper `0x64bf18` resolves descriptor metadata from a table at `0xffb0e8` and dispatch metadata from `0xffb1b0`, while validating block/key sizing constraints.",
        "- The AirShield cipher context builder calls `0x64bf18` with `w0 = 0x100` and `w1 = 2`, selecting descriptor root index `5` at `0xffb138`. The selected descriptor struct is `0xffb210`; its descriptor word at struct offset `+8` is `0x00072490`.",
        "- Descriptor `0x00072490` decodes as block size `16`, minimum setter size `16`, material size field `0x100` bits, mode `2`, algorithm family index `0`, and no bypass-size-check bit.",
        "- Transform configure helper `0x63327c` configures the transform object from descriptor bits: bit `25` bypasses the normal size check, `(descriptor >> 2) & 0x3c0` encodes an expected key/material size, bits `12...15` select mode, and bits `26...30` select the algorithm/table family.",
        "- Transform key/material setter helper `0x64cfe0` validates the descriptor and required length. For the selected mode-2 descriptor, the AirShield setup calls it with `w2 = 0x10`, so it copies 16 bytes into transform state while recording the material length.",
        "- The selected RX/state setup path loads two 64-bit words from builder offsets `0x238` and `0x240` immediately before calling cipher context builder helper `0xdb18d4`; since `setSeedNative([B)` stores raw seed bytes through builder `0x23f` and `setInitializationVectorNative(J)` stores the native IV payload starting at `0x240`, this maps the setter input to the final eight raw seed bytes followed by the first eight raw IV bytes.",
        "- `0xdb18d4` stores those two 64-bit words into its cipher-context wrapper at offsets `0x2c` and `0x34`, then calls transform setter `0x64cfe0` with `x1 = wrapper + 0x2c` and length `0x10`. This proves the selected transform receives the exact 16-byte `0x238...0x247` window as its setter input.",
        "- Final transform configuration then calls `0x63327c` with `w2 = 0x100`, matching the selected 256-bit material-size field.",
        "- After configuration, helper `0xdb19d8...0xdb19f4` detects selected descriptor mode `2` and installs `0xdb2dec` into the transform object as a small mode-2 completion/output-pointer helper.",
        "- Cipher/block transform dispatch helper `0x64bf68` routes operations by mode. The selected AirShield descriptor is mode `2`; separate mode `6` descriptors enter buffered stream helper `0x64c7d8`, but those mode-6 descriptors are not the descriptor selected by `0xdb18d4`.",
        "- Buffered stream helper `0x64c7d8` tracks total processed bytes at object offset `0x158`, keeps partial-block state around offsets `0x160`, `0x184`, and `0x188`, and calls `0x64c948` for chunk processing. This remains useful for understanding the transform library, not as proof of the selected AirShield mode.",
        "- Stream XOR block helper `0x64c948` recursively asks `0x64bf68` to produce/process a 16-byte block at object offset `0x178`, then XORs that block with input/output.",
        "- The selected family table links setup slot `+0x20` to `0x6332ec`, which directly branches to AES key-schedule helper `0x5d271c`; alternate setup slot `+0x28` is `0xdb3064`, which also calls `0x5d271c` and derives a transformed schedule using AES tables.",
        "- Helper `0x5d271c` branches on key sizes `0x80`, `0xc0`, and `0x100`, writes AES round counts `10`, `12`, and `14`, and generates AES S-box/T-table state using `0x1b` finite-field reduction plus Rcon material.",
        "- Helper `0x5d3e44` uses the generated AES T-tables for 16-byte block transforms; selected family helper `0xdb2f54` feeds those block transforms into a CTR-style XOR path.",
        "- Family-0 function pointers include block helper `0xdb2e24`, CTR XOR/counter helper `0xdb2f54`, and AES schedule setup helpers `0x6332ec` / `0xdb3064`; combined with the selected 256-bit material field, static evidence supports AES-256-CTR as the selected transform.",
        "- CTR-like helper `0xdb2f54` consumes the current 16-byte counter block, then increments it as a big-endian 128-bit value by starting at byte offset `12` and carrying through offsets `8`, `4`, then `0`.",
        "- The remaining cipher gap is now narrowed to how the mapped `seed[24..<32] + iv[0..<8]` setter input becomes the initial CTR block and how this selected mode-2 transform composes with the 64-byte work-area derivation path.",
        "",
        "Transform descriptor/config excerpts:",
        "",
        "```asm",
        disassemble(path, 0x64BF18, 0x64C080),
        "```",
        "",
        "```asm",
        disassemble(path, 0x63327C, 0x6332EC),
        "```",
        "",
        "Transform key/material and stream excerpts:",
        "",
        "```asm",
        disassemble(path, 0x64CFE0, 0x64D060),
        "```",
        "",
        "```asm",
        disassemble(path, 0x64C7D8, 0x64CA80),
        "```",
        "",
        "Block primitive/tweak setup excerpts:",
        "",
        "```asm",
        disassemble(path, 0x64C51C, 0x64C760),
        "```",
        "",
        "Selected family-0 helper excerpts:",
        "",
        "```asm",
        disassemble(path, 0xDB2DEC, 0xDB3180),
        "```",
        "",
        "Challenge/framing derivation excerpt:",
        "",
        "```asm",
        disassemble(path, 0xD9BFD0, 0xD9C118),
        "```",
        "",
        "Framing key derivation excerpt:",
        "",
        "```asm",
        disassemble(path, 0xDB17B4, 0xDB18D4),
        "```",
        "",
        "RX/state setup and Framing config copy excerpts:",
        "",
        "```asm",
        disassemble(path, 0xD9DE60, 0xD9E210),
        "```",
        "",
        "```asm",
        disassemble(path, 0xDB12EC, 0xDB139C),
        "```",
        "",
        "```asm",
        disassemble(path, 0xDB18D4, 0xDB19F8),
        "```",
        "",
        "## Frame Validation Helper Findings",
        "",
        "- Pack helper `0xdb139c` computes padded outer size, writes byte `8` as `(cipherPayloadBlocks - 1)`, conditionally stages the nonzero runtime mode word from object offset `0xa0`, stages the 32-bit frame counter from object offset `0xa4`, writes the computed 8-byte validation prefix from object offset `0x80` to frame bytes `0...7`, and increments the counter.",
        "- Unpack helper `0xdb15c4` reads byte `8`, verifies the indicated encrypted payload fits, conditionally feeds object offset `0xa0` and always feeds the current object offset `0xa4` counter into the validation state, recomputes the expected 8-byte prefix at object offset `0x80`, constant-time compares it against frame bytes `0...7`, decrypts/copies bytes from offset `9`, removes native padding from the plaintext length, and increments the counter.",
        "- Helper `0xdb1558` decides whether the first 4 bytes from object offset `0xa0` participate directly in the validation-prefix state. Mode and counter words are native little-endian stores, followed by outer-frame byte `8` plus encrypted payload bytes `9...cipherEnd`.",
        "- Helper `0x5d39a0` matches SHA-256 update behavior: it updates a 64-byte block buffer and calls compression helper `0x62dfd0` for full blocks.",
        "- Helper `0x62dfd0` is SHA-256 compression: it uses the SHA-256 rotation schedule and constants, then updates the 8-word state.",
        "- Helper `0x62e954` matches SHA-256 finalization: it appends `0x80`, pads/counts, calls `0x62dfd0`, and writes byte-swapped digest words.",
        "- Helper `0x62dbdc` is HMAC-SHA256-like: it fills a pad with `0x36`, xors in key bytes, and drives the SHA-256 helpers for inner/outer state. Runtime HMAC/SHA ownership is mapped to the Framing object; exact 64-byte work-area derivation still needs reconstruction.",
        "- Helper `0x64bf68` is a cipher/block-transform dispatch wrapper, not the MAC itself. It validates a transform object and dispatches through mode-specific function pointers. Exact work-area derivation and final MAC construction remain open.",
        "- The remaining bridge gap is no longer the outer frame layout, validation-prefix byte ordering, runtime HMAC/SHA ownership, or helper identities; it is reconstructing the exact 64-byte work-area and cipher material derived by `CipherBuilder` before valid encrypted frames can be produced outside native AirShield.",
        "",
        "Pack helper excerpt:",
        "",
        "```asm",
        disassemble(path, 0xDB139C, 0xDB1558),
        "```",
        "",
        "Unpack helper excerpt:",
        "",
        "```asm",
        disassemble(path, 0xDB15C4, 0xDB17B4),
        "```",
        "",
        "HMAC/SHA/cipher helper excerpts:",
        "",
        "```asm",
        disassemble(path, 0x62DBDC, 0x62DF08),
        "```",
        "",
        "```asm",
        disassemble(path, 0x5D39A0, 0x5D3AA0),
        "```",
        "",
        "```asm",
        disassemble(path, 0x62E954, 0x62EDF0),
        "```",
        "",
        "```asm",
        disassemble(path, 0x64BF68, 0x64C120),
        "```",
        "",
        "## Thunks And Implementations",
        "",
    ])

    for row in interesting_rows:
        lines.extend([
            f"### {row.class_name}.{row.name}",
            "",
            f"- Signature: `{row.signature}`",
            f"- Descriptor row: `0x{row.row_addr:x}`",
            f"- Thunk: `0x{row.thunk:x}`",
        ])
        if row.implementation is not None:
            lines.append(f"- Inner implementation: `0x{row.implementation:x}`")
        if row.adapter is not None:
            lines.append(f"- Adapter: `0x{row.adapter:x}`")
        lines.extend([
            "",
            "```asm",
            disassemble(path, row.thunk, row.thunk + 0x60),
            "```",
            "",
        ])
        if row.implementation is not None and row.implementation != row.thunk:
            lines.extend([
                "Inner implementation snippet:",
                "",
                "```asm",
                disassemble(path, row.implementation, row.implementation + 0x180),
                "```",
                "",
            ])

    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description="Recover selected AirShield JNI method addresses from libstartup.so.")
    parser.add_argument(
        "--lib",
        type=Path,
        default=Path("reverse/native-libs/lib/arm64-v8a/libstartup.so"),
        help="ELF library path",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reverse/airshield-jni-method-addresses.md"),
        help="markdown output path",
    )
    args = parser.parse_args()

    report = render_report(args.lib)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
