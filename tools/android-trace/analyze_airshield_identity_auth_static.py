#!/usr/bin/env python3
"""Generate a static report for AirShield production/prototype identity auth paths."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
JADX = ROOT / "reverse/meta-ai-jadx/sources"
OUTPUT = ROOT / "reverse/airshield-identity-auth-static.md"


@dataclass(frozen=True)
class Source:
    label: str
    path: Path


SOURCES = {
    "identity": Source(
        "production Identity",
        JADX / "com/facebook/wearable/companion/connectivity/security/auth/Identity.java",
    ),
    "gd5": Source("IdentityAuthenticationDelegate", JADX / "X/GD5.java"),
    "gy4": Source("production EnableTrust sender", JADX / "X/GY4.java"),
    "receiver": Source("production Identity receiver", JADX / "X/C32445HOf.java"),
    "gdl": Source("production Identity typed-buffer enum", JADX / "X/GDL.java"),
    "prototype": Source(
        "PrototypeIdentity",
        JADX / "com/facebook/wearable/companion/connectivity/security/prototypeidentity/PrototypeIdentity.java",
    ),
    "proto_enum": Source("PrototypeIdentity typed-buffer enum", JADX / "X/EnumC30456FtO.java"),
}


def read_lines(source: Source) -> list[str]:
    return source.path.read_text(encoding="utf-8", errors="replace").splitlines()


def first_line(source: Source, needle: str) -> int | None:
    for index, line in enumerate(read_lines(source), 1):
        if needle in line:
            return index
    return None


def evidence(source_key: str, needle: str, conclusion: str) -> str:
    source = SOURCES[source_key]
    line = first_line(source, needle)
    if line is None:
        return f"| {source.label} | missing | `{needle}` | {conclusion} |"
    rel = source.path.relative_to(ROOT)
    return f"| {source.label} | `{rel}:{line}` | `{needle}` | {conclusion} |"


def render_report() -> str:
    rows = [
        evidence(
            "identity",
            "this.A0C = hash;",
            "`A0C` is the preamble `txChallenge` passed to `Identity`.",
        ),
        evidence(
            "identity",
            "this.A0B = hash2;",
            "`A0B` is the preamble `rxChallenge` passed to `Identity`.",
        ),
        evidence(
            "identity",
            "connection.openChannel(36)",
            "Production Identity uses DataX service/channel `36`.",
        ),
        evidence(
            "gd5",
            "new Identity(c30745G2g.A00, looper, hash, hash2",
            "`BZa(looper, hash, hash2, connection)` forwards challenge arguments into `Identity` unchanged.",
        ),
        evidence(
            "gd5",
            "Identity.A01(identity, new TypedBuffer(GDL.A08.value",
            "Unowned/provisioning path sends `IDENTITY_REQUEST` rather than immediate trust.",
        ),
        evidence(
            "gd5",
            'C004901t.A0C("IdentityAuthenticationDelegate", "Device is owned");',
            "Owned-device path skips provisioning and calls the production `EnableTrust` sender.",
        ),
        evidence(
            "gy4",
            "Hash hash = identity.A0C;",
            "Production TX trust signs the preamble tx challenge.",
        ),
        evidence(
            "gy4",
            "signatureSign = privateKey.sign(hash);",
            "`EnableTrust.signature` is native raw64 signing output over `identity.A0C`.",
        ),
        evidence(
            "gy4",
            "hash2.hashBytes(bArrA1a);",
            "`EnableTrust.identifier` is `Hash(app_private_key_bytes).toByteArray()`.",
        ),
        evidence(
            "gy4",
            "provisioningCapabilities_ = 2;",
            "Production `EnableTrust` sets provisioning capabilities to `2`.",
        ),
        evidence(
            "gy4",
            "new TypedBuffer(i, AbstractC24971D8q.A1Y(c31682GmnNewBuilder))",
            "Production `EnableTrust` is sent as a typed buffer payload.",
        ),
        evidence(
            "gdl",
            'new GDL("ENABLE_TRUST", 0, 4096)',
            "Production `ENABLE_TRUST` typed-buffer type is `4096`.",
        ),
        evidence(
            "gdl",
            'new GDL("ENABLE_EC_AUTH", 15, 20481)',
            "Successful RX trust can trigger empty `ENABLE_EC_AUTH` type `20481`.",
        ),
        evidence(
            "receiver",
            "Hash hash = identity.A0B;",
            "Production RX trust verification checks the peer signature against the preamble rx challenge.",
        ),
        evidence(
            "receiver",
            "hash2.hashBytes(bArrAMQ);",
            "Peer `EnableTrust.identifier` is compared with `Hash(saved_device_identity_bytes)`.",
        ),
        evidence(
            "receiver",
            "Bvh(AbstractC30151FnI.A1b(kli4), hash.toByteArray())",
            "Peer `EnableTrust.signature` verifies over `identity.A0B.toByteArray()`.",
        ),
        evidence(
            "prototype",
            "Signature signatureSign = privateKey.sign(hash2);",
            "PrototypeIdentity separately signs its own tx challenge.",
        ),
        evidence(
            "proto_enum",
            'new EnumC30456FtO("ENABLE_TRUST", 0, 4096)',
            "Prototype service also uses type `4096`, but on service `77`.",
        ),
    ]

    return "\n".join([
        "# AirShield Identity Auth Static Report",
        "",
        "This report summarizes static JADX evidence for AirShield preamble authentication. "
        "It is redacted to control-flow, typed-buffer IDs, and byte-format semantics.",
        "",
        "## Evidence",
        "",
        "| Area | Source | Static anchor | Conclusion |",
        "| --- | --- | --- | --- |",
        *rows,
        "",
        "## Mac Bridge Implications",
        "",
        "- For production Identity service `36`, owned-device auth sends `ENABLE_TRUST` directly; `IDENTITY_REQUEST` belongs to the provisioning path.",
        "- The Mac-side production `EnableTrust` candidate should be keyed to the preamble TX challenge (`identity.A0C`), not the RX challenge.",
        "- The peer's production `EnableTrust` is verified against the preamble RX challenge (`identity.A0B`).",
        "- The identifier source is the native Java `Hash` over the app private-key bytes. Static byte-format analysis already confirms `Hash.toByteArray()` is 32 bytes and `Signature.toByteArray()` is raw 64 bytes.",
        "- PrototypeIdentity has a similar `ENABLE_TRUST` payload shape, but it is a separate service path and should not be selected unless the delegate trace proves service `77` was accepted.",
        "- Android trace events should include redacted `txChallenge` and `rxChallenge` summaries from `BZa(...)` so Mac candidate fingerprints can be compared to the accepted challenge path.",
        "",
    ])


def main() -> None:
    report = render_report()
    OUTPUT.write_text(report, encoding="utf-8")
    print(OUTPUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
