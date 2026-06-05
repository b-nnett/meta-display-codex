#!/usr/bin/env python3
import argparse
import hashlib
import hmac
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

        def name_at(name_offset: int) -> str:
            end = shstr.find(b"\0", name_offset)
            return shstr[name_offset:end].decode("utf-8", "replace")

        return [
            Section(name_at(name_offset), addr, file_offset, size)
            for name_offset, addr, file_offset, size in raw
        ]

    def cstring_at(self, vma: int) -> tuple[Optional[str], Optional[bytes]]:
        for section in self.sections:
            if section.addr <= vma < section.addr + section.size:
                offset = section.offset + (vma - section.addr)
                end = self.data.find(b"\0", offset)
                if end < 0:
                    return section.name, None
                return section.name, self.data[offset:end]
        return None, None

    def bytes_at(self, vma: int, size: int) -> tuple[Optional[str], Optional[bytes]]:
        for section in self.sections:
            if section.addr <= vma and vma + size <= section.addr + section.size:
                offset = section.offset + (vma - section.addr)
                return section.name, self.data[offset:offset + size]
        return None, None

    def u32_at(self, vma: int) -> int:
        for section in self.sections:
            if section.addr <= vma < section.addr + section.size:
                offset = section.offset + (vma - section.addr)
                return struct.unpack_from("<I", self.data, offset)[0]
        raise ValueError(f"VMA 0x{vma:x} is not file-backed")


def run_text(command: list[str]) -> str:
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    return (proc.stdout + proc.stderr).rstrip()


def disassemble(path: Path, start: int, stop: int) -> str:
    return run_text([
        "objdump",
        "-d",
        "-C",
        f"--start-address=0x{start:x}",
        f"--stop-address=0x{stop:x}",
        str(path),
    ])


def label_line(image: ELFImage, addr: int) -> str:
    section, raw = image.cstring_at(addr)
    if raw is None:
        return f"- `0x{addr:x}`: not resolved"
    text = raw.decode("utf-8", "replace")
    return f"- `0x{addr:x}` in `{section}`: `{text}` is {len(raw)} label bytes; c-string storage including NUL is {len(raw) + 1} bytes"


def explicit_context_lines(image: ELFImage) -> list[str]:
    context_addr = 0x25D60B
    context_len = 0x88
    section, context = image.bytes_at(context_addr, context_len)
    if context is None:
        return [f"- `0x{context_addr:x}` length `0x{context_len:x}`: not resolved"]

    label = b"AirShield"
    trailer = bytes.fromhex("2000000000010000")
    prefix_ok = context.startswith(label)
    padding = context[len(label):-len(trailer)]
    padding_ok = all(byte == 0 for byte in padding)
    trailer_ok = context.endswith(trailer)
    fixture_key = bytes(range(32))
    fixture = hmac.new(fixture_key, context + b"\x01", hashlib.sha256).digest()

    return [
        f"- Explicit context `0x{context_addr:x}` length `0x{context_len:x}` resolves in `{section}`.",
        f"- Context prefix check: `{'ok' if prefix_ok else 'mismatch'}`; bytes `0x{context[:16].hex()}`.",
        f"- Context zero-padding check: `{'ok' if padding_ok else 'mismatch'}`; padding length `{len(padding)}` bytes.",
        f"- Context trailer check: `{'ok' if trailer_ok else 'mismatch'}`; trailer `0x{context[-8:].hex()}`.",
        f"- HMAC fixture for key `00...1f` over `context || 01`: `{fixture.hex()}`.",
    ]


KDF_SCHEDULE_INSTRUCTIONS = [
    (
        0xD9DEA0,
        0x910643FC,
        "`add x28, sp, #0x190` anchors the 64-byte setup work area.",
    ),
    (
        0xD9DF64,
        0x910422C1,
        "`add x1, x22, #0x108` selects the 16-byte transcript challenge window.",
    ),
    (
        0xD9DF6C,
        0x52800202,
        "`mov w2, #0x10` passes the challenge-window length.",
    ),
    (
        0xD9DF74,
        0x910862C1,
        "`add x1, x22, #0x218` selects the 32-byte transcript/material window.",
    ),
    (
        0xD9DF88,
        0xAD4207E0,
        "`ldp q0, q1, [sp, #0x40]` loads the finalized 32-byte transcript digest.",
    ),
    (
        0xD9DF90,
        0xAD010780,
        "`stp q0, q1, [x28, #0x20]` writes that digest to the work-area cipher-material half at `sp+0x1b0`.",
    ),
    (
        0xD9DFE4,
        0x39401288,
        "`ldrb w8, [x20, #0x4]` reads the normal HKDF option byte.",
    ),
    (
        0xD9DFFC,
        0x91008382,
        "`add x2, x28, #0x20` passes the cipher-material half as `db17b4` key material.",
    ),
    (
        0xD9E00C,
        0x94004DEA,
        "`bl 0xdb17b4` runs the normal default-label expansion when HKDF is enabled.",
    ),
    (
        0xD9E018,
        0xAD4207E0,
        "`ldp q0, q1, [sp, #0x40]` loads the expansion output after a successful inline result.",
    ),
    (
        0xD9E01C,
        0xAD010780,
        "`stp q0, q1, [x28, #0x20]` writes the expansion output back to the cipher-material half.",
    ),
    (
        0xD9E020,
        0xAD410780,
        "`ldp q0, q1, [x28, #0x20]` reloads the selected cipher-material half.",
    ),
    (
        0xD9E024,
        0x14000029,
        "`b 0xd9e0c8` takes the normal path to copy the selected half into the validation-key half.",
    ),
    (
        0xD9E0C8,
        0xAD0C87E0,
        "`stp q0, q1, [sp, #0x190]` writes the selected 32-byte material into the validation-key half.",
    ),
]


FRAMING_WRAPPER_INSTRUCTIONS = [
    (
        0xDA6788,
        0xF90017F6,
        "`str x22, [sp, #0x28]` stages the Java `CipherBuilder` native handle for the shared `(IZ)` adapter.",
    ),
    (
        0xDA678C,
        0xB90027F5,
        "`str w21, [sp, #0x24]` stages the Java `base` integer for the shared `(IZ)` adapter.",
    ),
    (
        0xDA6790,
        0x390083F4,
        "`strb w20, [sp, #0x20]` stages the Java HKDF boolean for the shared `(IZ)` adapter.",
    ),
    (
        0xDA6798,
        0x9100A3E0,
        "`add x0, sp, #0x28` passes the staged builder-handle slot to the selected inner wrapper.",
    ),
    (
        0xDA679C,
        0x910093E1,
        "`add x1, sp, #0x24` passes the staged `base` slot to the selected inner wrapper.",
    ),
    (
        0xDA67A0,
        0x910083E2,
        "`add x2, sp, #0x20` passes the staged HKDF-boolean slot to the selected inner wrapper.",
    ),
    (
        0xDA67A4,
        0xD63F0260,
        "`blr x19` calls the selected inner wrapper with those staged arguments.",
    ),
    (
        0xDA7154,
        0x52800022,
        "`buildEncryptionFramingNative` loads `w2 = 1` before entering shared setup.",
    ),
    (
        0xDA7158,
        0x97FFDB42,
        "`buildEncryptionFramingNative` calls shared setup helper `0xd9de60`.",
    ),
    (
        0xDA66F8,
        0x2A1F03E2,
        "`buildDecryptionFramingNative` loads `w2 = 0` before entering shared setup.",
    ),
    (
        0xDA66FC,
        0x97FFDDD9,
        "`buildDecryptionFramingNative` calls shared setup helper `0xd9de60`.",
    ),
]


def kdf_schedule_check_lines(image: ELFImage) -> list[str]:
    lines = [
        "| Address | Check | Interpretation |",
        "| --- | --- | --- |",
    ]
    for address, expected, description in KDF_SCHEDULE_INSTRUCTIONS:
        actual = image.u32_at(address)
        check = "ok" if actual == expected else f"mismatch: `0x{actual:08x}`"
        lines.append(f"| `0x{address:x}` | {check} | {description} |")
    return lines


def instruction_check_lines(image: ELFImage, checks: list[tuple[int, int, str]]) -> list[str]:
    lines = [
        "| Address | Check | Interpretation |",
        "| --- | --- | --- |",
    ]
    for address, expected, description in checks:
        actual = image.u32_at(address)
        check = "ok" if actual == expected else f"mismatch: `0x{actual:08x}`"
        lines.append(f"| `0x{address:x}` | {check} | {description} |")
    return lines


def render_report(path: Path) -> str:
    image = ELFImage(path)
    lines = [
        "# AirShield KDF And Framing Focus Report",
        "",
        f"Library: `{path}`",
        "",
        "This report narrows the native AirShield gap between the decoded "
        "`EnableEncryption` message and a usable encrypted stream. It focuses on "
        "the helper functions that consume challenge/seed/keying material and "
        "construct `Framing` state.",
        "",
        "## Label Strings",
        "",
        label_line(image, 0x25D60B),
        label_line(image, 0x25D693),
        "",
        "Both addresses resolve to the static `AirShield` label. Native code uses "
        "length `9`, matching the label bytes without the trailing NUL terminator.",
        "",
        "## Explicit Expansion Context `0x25d60b`",
        "",
        *explicit_context_lines(image),
        "",
        "The explicit setup context is the `AirShield` label, zero padding, and "
        "the trailer bytes `20 00 00 00 00 01 00 00`. Native call sites pass "
        "this 0x88-byte context to `0xdb17b4` only when setup option byte `0x09` "
        "is `1`; otherwise they pass null context args and use the default label path.",
        "",
        "## Normal KDF Schedule Instruction Checks",
        "",
        *kdf_schedule_check_lines(image),
        "",
        "Interpretation of the checked instructions:",
        "",
        "- The normal path writes the finalized transcript digest into the work-area cipher-material half at `sp+0x1b0`.",
        "- If the HKDF option byte at options offset `0x04` is enabled, native calls `0xdb17b4` with that half as the 32-byte key material and writes the expansion output back to the same half.",
        "- The normal branch then reloads the selected cipher-material half and writes it into the validation-key half at `sp+0x190`, so validation and cipher key material are equal immediately before Framing config construction on this path.",
        "",
        "## Framing JNI Wrapper Instruction Checks",
        "",
        *instruction_check_lines(image, FRAMING_WRAPPER_INSTRUCTIONS),
        "",
        "Interpretation of the checked instructions:",
        "",
        "- The shared fbjni `(int, boolean)` adapter preserves the Java `base` integer and HKDF boolean as distinct staged values before dispatching to the selected inner wrapper.",
        "- `buildEncryptionFramingNative(int, boolean)` enters shared setup helper `0xd9de60` with direction flag `1`.",
        "- `buildDecryptionFramingNative(int, boolean)` enters shared setup helper `0xd9de60` with direction flag `0`.",
        "",
        "## Challenge Digest Helper `0xd9bfd0`",
        "",
        "- Creates two SHA-256-like contexts through helper `0xdb2494`.",
        "- Updates one context with a 16-byte builder transcript window at `0x108...0x117`; this overlaps only the first eight raw challenge bytes because `setChallengeNative([B)` writes raw challenge bytes at `0x110...0x11f`.",
        "- Updates the other with a 32-byte builder transcript/material window at `0x218...0x237`; this overlaps only the first 24 raw seed bytes because `setSeedNative([B)` writes raw seed bytes at `0x220...0x23f`.",
        "- Direction flag `w25` and builder byte `0x210` choose which digest path is copied/finalized first; `buildTxChallengeNative()` calls with direction flag `1`, while `buildRxChallengeNative()` calls with direction flag `0`.",
        "- The standalone TX/RX challenge builders clear caller context args (`x3 = xzr`, `x4 = xzr`) before entering this helper; the challenge-check caller at `0xd9da84` / `0xd9dafc` supplies a 16-byte context.",
        "- Fold updates inside the helper use length `0x40`, matching native `Hash`/public-key storage as two 32-byte halves. Helper `0xdb2240` copies those halves from native object offsets `0xc0` and `0xd0` into a 64-byte destination.",
        "- When `0x210` is set, helper thunk `0xeba18c` copies the native-hash-shaped builder source at `0x118` into the 64-byte fold buffer at `sp+0x10`, then the helper updates the challenge-window digest context with that fold buffer.",
        "- Helper `0xdb2148` is tied to `PrivateKey.recoverPublicKey()` (`0xffa330` / thunk `0xda3f28`) and builds one additional 64-byte local public-key-shaped intermediate from builder private-key state before it is folded into the selected digest path.",
        "- Direction flag `1` path: if `0x210` is set, fold builder `0x118` into the challenge-window digest context; then build/copy the recovered-public-key intermediate and fold it into the transcript/material-window digest context.",
        "- Direction flag `0` path: build/copy the recovered-public-key intermediate and fold it into the challenge-window digest context first; if `0x210` is set, fold builder `0x118` into the transcript/material-window digest context second.",
        "- `setRemotePublicKeyNative(J)` clears builder byte `0x210`, but the exact semantic name of this branch flag is still unresolved.",
        "- Produces a 32-byte digest on the stack, optionally adds caller-supplied context bytes, then finalizes.",
        "- Setter evidence now shows byte `0x218` is also the remote-public-key active flag and raw seed starts at `0x220`, so this digest input window should not be named as a simple seed field yet.",
        "",
        "```asm",
        disassemble(path, 0xD9BFD0, 0xD9C118),
        "```",
        "",
        "## Framing Expansion Helper `0xdb17b4`",
        "",
        "- Copies 32 bytes from `x2` into a local HMAC/SHA keying buffer.",
        "- Initializes a digest/HMAC context via `0xd9a0cc` and `0xdb1b38`.",
        "- If caller label/context pointers are absent, uses static label `AirShield` at `0x25d693` with length `9`.",
        "- Appends a one-byte counter value `0x01` before finalization.",
        "- Writes 32 output bytes to the destination object at `x19`.",
        "- This is HKDF-expand-like but should remain named as native framing expansion until exact RFC-style inputs are proven.",
        "- Swift coverage: `AirShieldFramingExpansion.expandContextCounter1` implements the confirmed primitive, `HMAC-SHA256(key: 32-byte key material, data: context || 0x01)`, with deterministic default-label and explicit-context fixtures in `tools/swift/DataXCodecValidation.swift`.",
        "- Java-facing `HKDF.calculateNative(long,long)` is present at security JNI row `0xff9e80`, thunk `0xda19b4`; it unwraps two native `Hash` handles, clears `x3/x4`, and calls `0xdb17b4`, confirming the public HKDF wrapper uses this same default-label expansion path.",
        "- Java-facing `PrivateKey.deriveNative(long)` is present at security JNI row `0xffa348`, thunk `0xda455c`, inner implementation `0xda4e94`; that body calls `0xdb1f1c`, tying the helper to private-key plus remote-public-key shared-hash derivation. `PrivateKey.recoverPublicKey()` is present at row `0xffa330`, thunk `0xda3f28`, and calls `0xdb2148`.",
        "",
        "```asm",
        disassemble(path, 0xDB17B4, 0xDB18D4),
        "```",
        "",
        "## RX/State Setup Helper `0xd9de60`",
        "",
        "- Builds a 64-byte zeroed local work area at stack offset `0x190`.",
        "- `buildEncryptionFramingNative(int, boolean)` calls this helper with direction flag `w2 = 1`; `buildDecryptionFramingNative(int, boolean)` calls it with direction flag `w2 = 0`.",
        "- Normal Java builder option packing maps the `base` integer to setup option word offset `0x00` and the HKDF boolean to option byte offset `0x04`; option bytes `0x05...0x0b` are zeroed on this regular link setup path.",
        "- When builder byte `0x210` is set, derives/copies a 32-byte value from builder state around offset `0x118`.",
        "- `setRemotePublicKeyNative(J)` clears builder byte `0x210`; the setup path branches on this byte before deriving/copying from the local builder state.",
        "- Feeds the 16-byte builder transcript challenge window at `0x108...0x117` and the 32-byte transcript/material window at `0x218...0x237` into the digest path.",
        "- Uses 64-byte native `Hash`-shaped fold inputs; the native copy helper stores two 32-byte halves.",
        "- Corrected setter evidence: remote public-key state is copied around `0x120` and `0x1e0`, byte `0x218` is the remote-public-key active flag, raw seed bytes start at `0x220`, and raw IV bytes start at `0x240`.",
        "- Calls `0xdb17b4` at `0xd9e00c`, `0xd9e088`, and `0xd9e0b8` to derive successive 32-byte blobs.",
        "- On the normal Java option path, option bytes `0x05...0x0b` are zero except the HKDF byte at `0x04`; that path computes a 32-byte transcript digest, optionally runs one `db17b4` expansion when HKDF is enabled, and then copies the same resulting 32-byte value into both work-area halves.",
        "- The normal transcript digest path finalizes SHA-256 over the cached/private-key-derived 32-byte material, the 16-byte builder transcript challenge window at `0x108...0x117`, and the 32-byte transcript/material window at `0x218...0x237`.",
        "- `CipherBuilder` construction at `0xda657c` zeroes the 16-byte transcript challenge window (`0x108...0x117`), byte `0x118`, byte `0x210`, the 32-byte transcript/material window (`0x218...0x237`), and the 16-byte selected setup window (`0x238...0x247`).",
        "- On the fresh normal path, `setChallengeNative([B)` fills raw challenge bytes at `0x110...0x11f`, so the digest's 16-byte challenge window is eight zero bytes followed by `challenge[0..<8]`.",
        "- On the fresh normal path, `setRemotePublicKeyNative(J)` sets byte `0x218` to one and `setSeedNative([B)` fills seed bytes at `0x220...0x23f`, so the digest's 32-byte transcript/material window is `01`, seven zero bytes, then `seed[0..<24]`.",
        "- Live/native output is still needed to confirm whether the Java-visible `PrivateKey.deriveNative` output is byte-for-byte CryptoKit's raw P-256 shared secret.",
        "- Loads builder offsets `0x238` and `0x240` into `x3/x4` immediately before cipher context builder `0xdb18d4`.",
        "- Narrowed IV evidence: `setSeedNative([B)` writes raw seed bytes at builder `0x220...0x23f` and `setInitializationVectorNative(J)` writes raw IV bytes at builder `0x240...0x24f`. The selected setup consumes the 16-byte window `0x238...0x247`, so its setter input is the final eight raw seed bytes (`seed[24..<32]`, builder `0x238...0x23f`) followed by the first eight raw IV bytes (`iv[0..<8]`, builder `0x240...0x247`).",
        "- `0xdb18d4` stores those two 64-bit window words into its cipher-context wrapper at offsets `0x2c` and `0x34`, then calls transform setter `0x64cfe0` with `x1 = wrapper + 0x2c` and length `0x10`. The setter direct-copy path sets its destination to `transform_state + 0x38`, so the selected transform copies the exact 16-byte `0x238...0x247` window into its counter-block state.",
        "- The generic mode-2 dispatcher later passes `transform_state + 0x38` as the counter pointer to family helper `0xdb2f54`; that helper keeps the pointer in `x24`, calls AES block transform `0x5d3e44` on the current block first, then increments the same 16-byte state from byte offset `12` with carry toward offset `0`. This statically confirms `seed[24..<32] + iv[0..<8]` is the first CTR block.",
        "- The normal encrypted path copies the first 32 bytes of that work area (`sp+0x190...0x1af`) into the primary Framing config at stack `0x90` as config validation key offset `0x00`; it stages the second 32 bytes (`sp+0x1b0...0x1cf`) as cipher key material input for `0xdb18d4`.",
        "- For the normal Java branch, the validation-key half and cipher-key half are equal immediately before config construction; relay/debug branches can diverge through the later `0xd9e088` / `0xd9e0b8` expansion path.",
        "- The alternate relay config is built at stack `0x110` and also copies the first 32 work-area bytes as its validation key.",
        "- `db17b4` expansion call sites use a temporary expansion object at stack `0x40` with inline tag/status at `0x60`; successful inline output is copied from `0x40...0x5f` into the work-area cipher-material half at `0x1b0`.",
        "- A later expansion uses output object stack `0x1d0` with inline tag/status at `0x1f0`; successful inline output is copied back into the work-area validation-key half at `0x190`. The derivation context buffer used by these call sites is staged at stack `0x200`.",
        "- When setup option byte `0x09` is `1`, the expansion calls receive explicit context pointer `0x25d60b` and length `0x88`; otherwise those args are zero and `db17b4` falls back to its default `AirShield` label.",
        "- The 0x88-byte explicit context is `AirShield`, zero padding, and trailer bytes `20 00 00 00 00 01 00 00`; Swift test-covers this exact byte sequence and its HMAC fixture.",
        "- Copies Framing config into runtime objects through `0xdb12ec` at `0xd9e108` and `0xd9e1cc`.",
        "",
        "```asm",
        disassemble(path, 0xD9DE60, 0xD9E210),
        "```",
        "",
        "## Framing Config Copy Helper `0xdb12ec`",
        "",
        "- Initializes runtime Framing digest/HMAC state via `0xdb1b38`.",
        "- `db1b38` initializes that state from a 32-byte validation key at Framing config offset `0x00`, with an inline-key tag at config offset `0x20`; the runtime Framing object stores the HMAC/SHA context pointer at `0x00`, inline key copy at `0x08`, and runtime key tag at `0x28` before cipher context state starts at `0x30`.",
        "- Copies config bytes `0x78`, `0x7a`, and word `0x7c` into Framing offsets `0xa0` and `0xa4`.",
        "- These offsets are consumed later by pack/unpack for validation-prefix mode and per-frame counter.",
        "- Copies or claims cipher context material from config offset `0x28` into runtime Framing offset `0x30`.",
        "- Swift coverage: `AirShieldFraming` now test-covers the native direction flags and setup/config/runtime offsets, including the 64-byte work-area split, expansion scratch/output objects, derivation context buffer, primary/relay config stack offsets, validation key ownership, runtime validation-prefix buffer offset `0x80`, and frame counter offset `0xa4`.",
        "- Pack/unpack evidence maps the validation-prefix frame inputs as optional nonzero 4-byte runtime mode word, 4-byte frame counter, then outer-frame byte `8` plus encrypted payload bytes from `9...cipherEnd`; the two words are native little-endian stores.",
        "- Runtime validation mode is packed as `uint16(config+0x78) | (uint8(config+0x7a) << 24)`, and helper `0xdb1558` includes the little-endian mode word in prefix state when this runtime word is nonzero.",
        "- Swift coverage also includes the validation-prefix scratch layout and authenticated input composition: scratch mode offset `0`, scratch counter offset `4`, mode/counter lengths `4` bytes each, little-endian word order, and authenticated frame range `8..<cipherEnd`.",
        "- Swift now implements a guarded offline validation-prefix candidate for native comparison: first eight bytes of HMAC-SHA256 over the mapped authenticated input, keyed by a 32-byte validation-key candidate.",
        "- Pack helper `0xdb139c` pads non-aligned plaintext with repeated byte `0xc0 + paddingLength`; already aligned plaintext gets no extra block. Unpack helper `0xdb15c4` calls padding recovery helper `0x906468`, which recognizes that same tail pattern and subtracts the recovered length.",
        "- Swift now implements a guarded offline encrypted-frame candidate for native comparison: native padding, explicit-counter AES-256-CTR over padded plaintext, byte `8` block indicator, and the offline validation-prefix candidate.",
        "- `AirShieldSession` now applies that offline encrypted-frame candidate to the minimal gesture-enable DataX frame when live `EnableEncryption` supplies usable seed, IV, and base counter values. Logs include only comparison data: lengths, base frame counter, validation prefix, and short cipher/outer fingerprints.",
        "- `AirShieldSession` also keeps passive receive-side candidates in memory. Incoming encrypted frames are accepted only if the validation prefix verifies; then Swift decrypts with the explicit-counter AES-256-CTR candidate, removes native padding, and routes recovered plaintext into a separate decrypted DataX decoder.",
        "- Swift now buffers AirShield encrypted outer frames across L2CAP reads and handles coalesced encrypted frames before candidate decrypt.",
        "- Passive decrypt searches a bounded receive frame-counter window from the current candidate counter through `current + 8`; a frame is accepted only on validation-prefix match, and logs include the matched counter offset.",
        "- The Mac UI and per-run session summary now expose AirShield validation status: match/miss counts, last matched material source, counter-search offset, plaintext length, and last gesture-enable tx-ready fields.",
        "- The Mac UI has a manual encrypted `Enable Gestures` action, but it stays disabled until passive receive-side candidate decrypt validates. When enabled, it sends only the matching in-memory gesture-enable encrypted-frame candidate on explicit user action.",
        "- Swift coverage also includes runtime validation-mode packing and the nonzero mode-word inclusion branch.",
        "- Swift coverage also includes the raw IV payload range `0x240..<0x250`, selected transform setup window `0x238..<0x248`, seed-tail range `0x238..<0x240`, and IV-head range `0x240..<0x248`.",
        "- Swift coverage includes the cipher-context IV window copy offsets `0x2c` and `0x34`, selected transform setter input length `0x10`, setter destination/counter-block state offset `0x38`, cached keystream block offset `0x20`, and partial-block offset `0x30`.",
        "",
        "```asm",
        disassemble(path, 0xDB12EC, 0xDB139C),
        "```",
        "",
        "## Current Implementation Boundary",
        "",
        "- The Mac bridge now has the decoded `EnableEncryption` fields and P-256 ECDH shared secret.",
        "- The next missing transformation is native-equivalent derivation from shared secret, seed, local/remote challenges, AirShield label/context, base/counter fields, and IV wrapper bytes into the 64-byte setup work area whose halves become validation key and cipher key material.",
        "- Swift now has deliberately gated normal-path material candidates that compute the observed digest/expansion schedule and log short fingerprints from live `EnableEncryption` packets, but it does not yet emit encrypted frames because native trace confirmation is still pending.",
        "- The primary Swift candidate uses CryptoKit's raw P-256 shared secret bytes as the shared material, matching the expected native mbedTLS P-256 x-coordinate path. Two secondary comparison candidates log `SHA256(raw)` and byte-reversed raw shared material so a native trace can quickly rule out common representation mismatches.",
        "- The selected transform setter input is now mapped as `seed[24..<32] + iv[0..<8]`, and static transform-dispatch evidence confirms that copied 16-byte state is the initial CTR block consumed by the selected mode-2 transform.",
        "- The validation-prefix byte ordering, runtime HMAC/SHA ownership, work-area split, native padding, explicit-counter AES-CTR pack/decrypt candidate, initial CTR block, and offline HMAC-prefix candidate are now mapped; the remaining gap is native confirmation of candidate key material and byte-for-byte comparison against native `Framing.packNative` / `Framing.unpackNative` output.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate focused AirShield KDF/framing evidence report.")
    parser.add_argument("--library", type=Path, default=Path("reverse/native-libs/lib/arm64-v8a/libstartup.so"))
    parser.add_argument("--output", type=Path, default=Path("reverse/airshield-kdf-framing-report.md"))
    args = parser.parse_args()
    report = render_report(args.library)
    args.output.write_text(report)
    print(args.output)


if __name__ == "__main__":
    main()
