#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


HEX_RE = re.compile(r"^[0-9a-fA-F]+(?:\.\.\.)?$")

AIRSHIELD_LINK_SETUP_TYPES = {
    1: "REQUEST_ENCRYPTION",
    2: "ENABLE_ENCRYPTION",
    3: "LINK_SETUP_CONFIG",
    4096: "END_LINK_SETUP",
    8192: "BYPASS_LINK_SETUP_2P",
    8193: "IDENTIFY_3P",
    8194: "ASSOCIATE_3P",
}

AIRSHIELD_AUTH_TYPED_BUFFER_TYPES = {
    36: {
        4096: "ENABLE_TRUST",
        4097: "ENABLE_TRUST_EC",
        8192: "SKIP_CHALLENGE",
        8193: "SKIP_CHALLENGE_RESPONSE",
        8194: "START_CHANGE_OWNER",
        8195: "START_CHANGE_OWNER_RESPONSE",
        8196: "FINISH_CHANGE_OWNER",
        8197: "FINISH_CHANGE_OWNER_RESPONSE",
        12288: "IDENTITY_REQUEST",
        12289: "IDENTITY_RESPONSE",
        16384: "NUX_REGISTRATION_CHALLENGE",
        16385: "NUX_REGISTRATION_CHALLENGE_RESPONSE",
        16386: "NUX_INSTALL_DEVICE_IDENTITY",
        16387: "NUX_INSTALL_DEVICE_IDENTITY_RESPONSE",
        20480: "MANIFEST_KEY",
        20481: "ENABLE_EC_AUTH",
    },
    77: {
        4096: "ENABLE_TRUST",
        8192: "REGISTER_KEY",
        8193: "KEY_ACCEPTED",
    },
}


def clean_hex(value):
    if not isinstance(value, str) or not value:
        return b""
    value = value.replace("...", "")
    if len(value) % 2:
        value = value[:-1]
    if not HEX_RE.match(value):
        return b""
    return bytes.fromhex(value)


def decode_datax_frames(data):
    frames = []
    offset = 0
    while offset + 4 <= len(data):
        descriptor = int.from_bytes(data[offset : offset + 2], "big")
        body_len = descriptor & 0x3FFF
        total_len = 4 + body_len
        if total_len < 4 or total_len > 0x4003:
            break
        if offset + total_len > len(data):
            break

        frame = data[offset : offset + total_len]
        base_id = int.from_bytes(frame[2:4], "big")
        has_ext = bool(descriptor & 0x8000)
        reserved_header_bit14 = bool(descriptor & 0x4000)
        pos = 4
        extensions = []
        if has_ext:
            while pos + 4 <= len(frame):
                word = frame[pos : pos + 4]
                raw_type = word[0]
                extensions.append(
                    {
                        "raw_type": raw_type,
                        "type": raw_type & 0x7F,
                        "continues": bool(raw_type & 0x80),
                        "aux": word[1],
                        "value": int.from_bytes(word[2:4], "big"),
                        "hex": word.hex(),
                    }
                )
                pos += 4
                if not raw_type & 0x80:
                    break

        frames.append(
            {
                "offset": offset,
                "total_len": total_len,
                "body_len": body_len,
                "base_id": base_id,
                "has_ext": has_ext,
                "reserved_header_bit14": reserved_header_bit14,
                "extensions": extensions,
                "payload_len": max(0, total_len - pos),
                "payload_hex": frame[pos:total_len].hex()[:160],
            }
        )
        offset += total_len
    return frames


class ProtoReader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def read_varint(self):
        result = 0
        shift = 0
        while self.offset < len(self.data) and shift < 64:
            byte = self.data[self.offset]
            self.offset += 1
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7
        return None

    def next_field(self):
        key = self.read_varint()
        if key is None:
            return None
        number = key >> 3
        wire_type = key & 0x07
        if number <= 0:
            return None
        return number, wire_type

    def read_length_delimited(self):
        length = self.read_varint()
        if length is None:
            self.offset = len(self.data)
            return None
        end = min(self.offset + length, len(self.data))
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def skip(self, wire_type):
        if wire_type == 0:
            self.read_varint()
        elif wire_type == 1:
            self.offset = min(self.offset + 8, len(self.data))
        elif wire_type == 2:
            self.read_length_delimited()
        elif wire_type == 5:
            self.offset = min(self.offset + 4, len(self.data))
        else:
            self.offset = len(self.data)


def fingerprint_bytes(value):
    if value is None:
        return None
    return {
        "len": len(value),
        "sha256_12": hashlib.sha256(value).hexdigest()[:12],
    }


def short_sha256_hex(value, prefix_bytes=8):
    if not value:
        return None
    return hashlib.sha256(value).digest()[:prefix_bytes].hex()


def buffer_bytes(buffer):
    if not isinstance(buffer, dict):
        return b"", False
    data = clean_hex(buffer.get("hex"))
    complete = buffer.get("complete")
    if isinstance(complete, bool):
        return data, complete
    return data, len(data) == int(buffer.get("length") or 0)


def buffer_sha256_12(buffer, data, complete):
    if isinstance(buffer, dict):
        fingerprint = buffer.get("sha256PrefixHex") or buffer.get("sha256_12")
        if isinstance(fingerprint, str) and fingerprint and not fingerprint.startswith("error:"):
            return fingerprint[:12]
    if complete and data:
        return hashlib.sha256(data).hexdigest()[:12]
    return None


def outer_frame_summary(data, buffer, complete):
    if len(data) < 9:
        return None
    indicator = data[8]
    expected_outer_len = indicator * 16 + 25
    cipher = data[9:expected_outer_len] if len(data) >= expected_outer_len else data[9:]
    return {
        "captured_len": len(data),
        "expected_outer_len": expected_outer_len,
        "complete": len(data) >= expected_outer_len,
        "validation_prefix": data[:8].hex(),
        "cipher_payload_indicator": indicator,
        "cipher_payload_len": max(0, expected_outer_len - 9),
        "cipher_sha256_12": hashlib.sha256(cipher).hexdigest()[:12] if complete and cipher else None,
        "outer_sha256_12": buffer_sha256_12(buffer, data[:expected_outer_len], complete),
    }


def framing_trace_summary(line_no, event):
    plaintext_buffer = event.get("plaintext")
    outer_buffer = event.get("outerFrame")
    plaintext, plaintext_complete = buffer_bytes(plaintext_buffer)
    outer_frame, outer_complete = buffer_bytes(outer_buffer)
    plaintext_frames = decode_datax_frames(plaintext) if plaintext else []
    return {
        "line_no": line_no,
        "event_name": event.get("event"),
        "result": event.get("result"),
        "plain_len": event.get("plainConsumed", event.get("plainWritten")),
        "plain_captured_len": len(plaintext),
        "plain_complete": plaintext_complete,
        "plain_sha256_12": buffer_sha256_12(plaintext_buffer, plaintext, plaintext_complete),
        "outer_len": event.get("outerWritten", event.get("outerConsumed")),
        "outer_captured_len": len(outer_frame),
        "outer_complete": outer_complete,
        "outer": outer_frame_summary(outer_frame, outer_buffer, outer_complete),
        "plaintext_datax_frames": plaintext_frames,
    }


def decode_request_encryption(data):
    reader = ProtoReader(data)
    decoded = {
        "public_key": None,
        "challenge": None,
        "elliptic_curve": None,
        "supported_parameters": None,
        "hkdf": None,
        "key_hints": [],
        "quirks": None,
        "airshield_version": None,
    }
    seen = set()

    while True:
        field = reader.next_field()
        if field is None:
            break
        number, wire_type = field
        seen.add(number)
        if number == 1 and wire_type == 2:
            decoded["public_key"] = fingerprint_bytes(reader.read_length_delimited())
        elif number == 2 and wire_type == 2:
            decoded["challenge"] = fingerprint_bytes(reader.read_length_delimited())
        elif number == 3 and wire_type == 0:
            decoded["elliptic_curve"] = reader.read_varint()
        elif number == 4 and wire_type == 0:
            decoded["supported_parameters"] = reader.read_varint()
            decoded["hkdf"] = bool(decoded["supported_parameters"] & 1)
        elif number == 5 and wire_type == 2:
            decoded["key_hints"].append(fingerprint_bytes(reader.read_length_delimited()))
        elif number == 6 and wire_type == 0:
            decoded["quirks"] = reader.read_varint()
        elif number == 7 and wire_type == 0:
            decoded["airshield_version"] = reader.read_varint()
        else:
            reader.skip(wire_type)

    if not ({1, 2} & seen):
        return None
    return decoded


def decode_enable_encryption(data):
    reader = ProtoReader(data)
    decoded = {
        "public_key": None,
        "seed": None,
        "iv": None,
        "base": None,
        "parameters": None,
        "hkdf": None,
        "quirks": None,
        "phased_link_setup_supported": None,
        "supported_link_setup_services": None,
        "link_switch_version_supported": None,
    }
    seen = set()

    while True:
        field = reader.next_field()
        if field is None:
            break
        number, wire_type = field
        seen.add(number)
        if number == 1 and wire_type == 2:
            decoded["public_key"] = fingerprint_bytes(reader.read_length_delimited())
        elif number == 2 and wire_type == 2:
            decoded["seed"] = fingerprint_bytes(reader.read_length_delimited())
        elif number == 3 and wire_type == 2:
            decoded["iv"] = fingerprint_bytes(reader.read_length_delimited())
        elif number == 4 and wire_type == 0:
            decoded["base"] = reader.read_varint()
        elif number == 5 and wire_type == 0:
            decoded["parameters"] = reader.read_varint()
            decoded["hkdf"] = bool(decoded["parameters"] & 1)
        elif number == 6 and wire_type == 0:
            decoded["quirks"] = reader.read_varint()
        elif number == 7 and wire_type == 0:
            decoded["phased_link_setup_supported"] = bool(reader.read_varint())
        elif number == 8 and wire_type == 0:
            decoded["supported_link_setup_services"] = reader.read_varint()
        elif number == 9 and wire_type == 0:
            decoded["link_switch_version_supported"] = reader.read_varint()
        else:
            reader.skip(wire_type)

    if not ({1, 2, 3} & seen):
        return None
    return decoded


def decode_end_link_setup(data):
    reader = ProtoReader(data)
    decoded = {
        "state": None,
        "state_name": None,
        "uuid": None,
        "link_uuid": None,
        "user_data_entries": 0,
    }
    seen = set()

    while True:
        field = reader.next_field()
        if field is None:
            break
        number, wire_type = field
        seen.add(number)
        if number == 1 and wire_type == 0:
            decoded["state"] = reader.read_varint()
            decoded["state_name"] = {0: "READY", 1: "MAIN"}.get(decoded["state"], "UNKNOWN")
        elif number == 2 and wire_type == 2:
            decoded["uuid"] = fingerprint_bytes(reader.read_length_delimited())
        elif number == 3 and wire_type == 2:
            decoded["link_uuid"] = fingerprint_bytes(reader.read_length_delimited())
        elif number == 4:
            decoded["user_data_entries"] += 1
            reader.skip(wire_type)
        else:
            reader.skip(wire_type)

    if not seen:
        return None
    return decoded


def decode_airshield_link_setup(type_value, data):
    if type_value == 1:
        return decode_request_encryption(data)
    if type_value == 2:
        return decode_enable_encryption(data)
    if type_value == 4096:
        return decode_end_link_setup(data)
    return None


def iter_json_events(path):
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield line_no, event


def buffer_candidates(event):
    candidates = []
    event_name = event.get("event", "")

    if "hex" in event:
        candidates.append(("hex", event.get("hex")))
    if "rolloverHex" in event:
        candidates.append(("rolloverHex", event.get("rolloverHex")))
    if "pubKeyPrefixHex" in event:
        candidates.append(("pubKeyPrefixHex", event.get("pubKeyPrefixHex")))

    for key in ("header", "payload", "bytes"):
        value = event.get(key)
        if isinstance(value, dict) and "hex" in value:
            candidates.append((key, value.get("hex")))

    if event_name in ("datax.localChannel.send", "datax.remoteChannel.send", "datax.typedBuffer.initByteArray"):
        candidates.append(("typedBuffer", event.get("hex")))

    return candidates


def message_type_name(value):
    if value in AIRSHIELD_LINK_SETUP_TYPES:
        return AIRSHIELD_LINK_SETUP_TYPES[value]
    names = {
        1: "PING",
        10: "EMG",
        11: "IMU",
        12: "INFERENCE",
        13: "GESTURE",
        20: "REQUEST",
        21: "RESPONSE",
        22: "STREAM_UPDATE",
        23: "AUTHENTICATION",
        24: "ENCRYPTION",
        41: "EMG_IMU_BATCH",
    }
    return names.get(value, f"UNKNOWN_{value}")


def auth_typed_buffer_name(service, type_value):
    if service is None or type_value is None:
        return None
    return AIRSHIELD_AUTH_TYPED_BUFFER_TYPES.get(service, {}).get(type_value)


def byte_summary_fingerprint(summary):
    if not isinstance(summary, dict):
        return None
    return summary.get("sha256PrefixHex") or summary.get("sha256_prefix")


def byte_summary_length(summary):
    if not isinstance(summary, dict):
        return None
    return summary.get("length") or summary.get("decoded_length")


def summarize(path):
    events = []
    counts = Counter()
    hooks = []
    milestones = []
    datax_decodes = []
    typed_counts = Counter()
    type_examples = defaultdict(list)
    link_setup_decodes = []
    native_register_hooks = []
    native_hook_summary = []
    native_static_hooks = []
    native_static_missing = []
    native_classes = {}
    native_methods = {}
    native_hook_failures = []
    native_calls = Counter()
    framing_traces = []
    native_framing_configs = []
    native_cipher_contexts = []
    accepted_auth_keys = []
    auth_typed_buffers = []
    channel_services = {}

    for line_no, event in iter_json_events(path):
        events.append((line_no, event))
        event_name = event.get("event", "unknown")
        counts[event_name] += 1

        if event_name in ("hook.installed", "hook.missing"):
            hooks.append((line_no, event))

        if (
            event_name.startswith("airshield.")
            or event_name.startswith("ble.")
            or event_name.startswith("datax.")
            or event_name.startswith("native.")
        ):
            milestones.append((line_no, event))

        if event_name == "native.registerNatives.hookInstalled":
            native_register_hooks.append((line_no, event))
        elif event_name == "native.registerNatives.hookSummary":
            native_hook_summary.append((line_no, event))
        elif event_name == "native.airshield.staticHooks.installed":
            native_static_hooks.append((line_no, event))
        elif event_name == "native.airshield.staticHooks.moduleMissing":
            native_static_missing.append((line_no, event))
        elif event_name == "native.registerNatives.airshieldClass":
            class_name = event.get("className") or "unknown"
            native_classes[class_name] = {
                "line_no": line_no,
                "method_count": event.get("methodCount"),
                "symbol": event.get("symbol"),
            }
        elif event_name == "native.registerNatives.airshieldMethod":
            key = (
                event.get("className") or "unknown",
                event.get("methodName") or "unknown",
                event.get("signature") or "",
            )
            native_methods[key] = {
                "line_no": line_no,
                "module": event.get("module"),
                "module_offset": event.get("moduleOffset"),
                "pointer": event.get("pointer"),
            }
        elif event_name == "native.airshield.method.hookFailed":
            native_hook_failures.append((line_no, event))
        elif event_name == "native.airshield.method.enter":
            key = (
                event.get("className") or "unknown",
                event.get("methodName") or "unknown",
                event.get("signature") or "",
            )
            native_calls[key] += 1
        elif event_name == "native.airshield.framing_config":
            native_framing_configs.append((line_no, event))
        elif event_name == "native.airshield.cipher_context_setup":
            native_cipher_contexts.append((line_no, event))

        if event_name == "datax.localChannel.init":
            channel_id = event.get("channelId")
            service = event.get("service")
            if channel_id is not None and service is not None:
                channel_services[channel_id] = service
        elif event_name in ("datax.localChannel.send", "datax.remoteChannel.send"):
            channel_id = event.get("channelId")
            service = event.get("service")
            if channel_id is not None and service is not None:
                channel_services[channel_id] = service

        if event_name == "airshield.auth.accept_key_candidate":
            public_key = event.get("originalPublicKey")
            accepted_auth_keys.append({
                "line_no": line_no,
                "event_name": event_name,
                "length": byte_summary_length(public_key),
                "fingerprint": byte_summary_fingerprint(public_key),
                "variant": event.get("variant"),
                "as_main": event.get("asMain"),
            })
        elif event_name == "airshield.acceptAuthentication":
            public_key = event.get("publicKey")
            accepted_auth_keys.append({
                "line_no": line_no,
                "event_name": event_name,
                "length": byte_summary_length(public_key) or event.get("pubKeyLength"),
                "fingerprint": byte_summary_fingerprint(public_key) or event.get("pubKeyFingerprint"),
            })

        if event_name in ("airshield.framing.pack", "airshield.framing.unpack"):
            framing_traces.append(framing_trace_summary(line_no, event))

        if event_name in ("datax.localChannel.send", "datax.remoteChannel.send", "datax.typedBuffer.initByteBuffer", "datax.typedBuffer.initByteArray"):
            type_value = event.get("type")
            if type_value is not None:
                typed_counts[type_value] += 1
                if len(type_examples[type_value]) < 3:
                    type_examples[type_value].append((line_no, event))
                data = clean_hex(event.get("hex"))
                if not data and isinstance(event.get("bytes"), dict):
                    data = clean_hex(event["bytes"].get("hex"))
                channel_id = event.get("channelId")
                service = event.get("service")
                if service is None and channel_id is not None:
                    service = channel_services.get(channel_id)
                auth_name = auth_typed_buffer_name(service, type_value)
                if auth_name:
                    auth_typed_buffers.append({
                        "line_no": line_no,
                        "event_name": event_name,
                        "service": service,
                        "type": type_value,
                        "type_name": auth_name,
                        "payload_len": len(data),
                        "payload_fingerprint": short_sha256_hex(data),
                        "channel_id": channel_id,
                        "service_inferred": event.get("service") is None,
                    })
                decoded = decode_airshield_link_setup(type_value, data)
                if decoded is not None:
                    link_setup_decodes.append(
                        {
                            "line_no": line_no,
                            "event_name": event_name,
                            "type": type_value,
                            "type_name": AIRSHIELD_LINK_SETUP_TYPES.get(type_value, f"UNKNOWN_{type_value}"),
                            "service": event.get("service"),
                            "channel_id": event.get("channelId"),
                            "payload_len": len(data),
                            "decoded": decoded,
                        }
                    )

        for label, hex_value in buffer_candidates(event):
            data = clean_hex(hex_value)
            if len(data) < 4:
                continue
            frames = decode_datax_frames(data)
            if frames:
                datax_decodes.append((line_no, event_name, label, frames))

    return {
        "path": path,
        "events": events,
        "counts": counts,
        "hooks": hooks,
        "milestones": milestones,
        "datax_decodes": datax_decodes,
        "typed_counts": typed_counts,
        "type_examples": type_examples,
        "link_setup_decodes": link_setup_decodes,
        "native_register_hooks": native_register_hooks,
        "native_hook_summary": native_hook_summary,
        "native_static_hooks": native_static_hooks,
        "native_static_missing": native_static_missing,
        "native_classes": native_classes,
        "native_methods": native_methods,
        "native_hook_failures": native_hook_failures,
        "native_calls": native_calls,
        "framing_traces": framing_traces,
        "native_framing_configs": native_framing_configs,
        "native_cipher_contexts": native_cipher_contexts,
        "accepted_auth_keys": accepted_auth_keys,
        "auth_typed_buffers": auth_typed_buffers,
        "channel_services": channel_services,
    }


def print_summary(summary, show_events=False):
    path = summary["path"]
    print(f"Trace: {path}")
    print(f"JSON events: {len(summary['events'])}")

    print("\nEvent counts:")
    for event_name, count in summary["counts"].most_common():
        print(f"  {event_name}: {count}")

    missing_hooks = [event for _, event in summary["hooks"] if event.get("event") == "hook.missing"]
    print("\nHook status:")
    print(f"  installed: {summary['counts'].get('hook.installed', 0)}")
    print(f"  missing: {len(missing_hooks)}")
    for event in missing_hooks:
        print(f"    {event.get('className')}: {event.get('error')}")

    print("\nHandshake evidence:")
    for name in (
        "ble.createInsecureL2capChannel",
        "airshield.initialize",
        "airshield.start",
        "airshield.onSend",
        "airshield.preambleReady",
        "datax.registerService",
        "airshield.auth.delegate.register_services",
        "airshield.auth.delegate.start",
        "airshield.auth.accept_key_candidate",
        "airshield.auth.result_callback",
        "airshield.identity.private_key.set_raw",
        "airshield.identity.private_key.serialize",
        "airshield.identity.private_key.recover_public_key",
        "airshield.identity.public_key.set_raw",
        "airshield.identity.public_key.serialize",
        "airshield.acceptAuthentication",
        "airshield.streamReady",
    ):
        print(f"  {name}: {summary['counts'].get(name, 0)}")

    print("\nAccepted auth public-key evidence:")
    if summary["accepted_auth_keys"]:
        for item in summary["accepted_auth_keys"][:30]:
            detail = []
            if item.get("variant") is not None:
                detail.append(f"variant={item.get('variant')}")
            if item.get("as_main") is not None:
                detail.append(f"asMain={item.get('as_main')}")
            detail_text = f" {' '.join(detail)}" if detail else ""
            print(
                f"  line {item['line_no']} {item['event_name']} "
                f"len={item.get('length')} fp={item.get('fingerprint')}{detail_text}"
            )
    else:
        print("  none")

    print("\nNative AirShield evidence:")
    print(f"  RegisterNatives hooks installed: {len(summary['native_register_hooks'])}")
    print(f"  Static AirShield offset hook batches: {len(summary['native_static_hooks'])}")
    if summary["native_static_hooks"]:
        latest_static = summary["native_static_hooks"][-1][1]
        print(
            "  Static AirShield offset hooks latest: "
            f"moduleBase={latest_static.get('moduleBase')} methods={latest_static.get('methodCount')}"
        )
    if summary["native_static_missing"]:
        latest_missing = summary["native_static_missing"][-1][1]
        print(
            "  Static AirShield offset hooks missing module: "
            f"attempts={latest_missing.get('attempts')}"
        )
    if summary["native_hook_summary"]:
        latest = summary["native_hook_summary"][-1][1]
        print(
            "  RegisterNatives hook summary: "
            f"candidates={latest.get('candidateCount')} installed={latest.get('installedCount')}"
        )
    print(f"  AirShield classes registered: {len(summary['native_classes'])}")
    for class_name, item in sorted(summary["native_classes"].items()):
        print(
            f"    line {item['line_no']} {class_name}: "
            f"methods={item['method_count']} symbol={item['symbol']}"
        )
    print(f"  AirShield native methods seen: {len(summary['native_methods'])}")
    for (class_name, method_name, signature), item in sorted(summary["native_methods"].items())[:80]:
        location = item.get("module_offset") or item.get("pointer")
        module = item.get("module") or "unknown-module"
        print(f"    line {item['line_no']} {class_name}.{method_name}{signature} @ {module}+{location}")
    if len(summary["native_methods"]) > 80:
        print(f"    ... {len(summary['native_methods']) - 80} more")
    if summary["native_calls"]:
        print("  AirShield native method calls:")
        for (class_name, method_name, signature), count in summary["native_calls"].most_common(50):
            print(f"    {class_name}.{method_name}{signature}: {count}")
    else:
        print("  AirShield native method calls: none")
    if summary["native_hook_failures"]:
        print("  Native hook failures:")
        for line_no, event in summary["native_hook_failures"][:20]:
            print(
                f"    line {line_no} {event.get('className')}.{event.get('methodName')}"
                f"{event.get('signature')}: {event.get('error')}"
            )

    print("\nNative framing setup fingerprints:")
    if summary["native_framing_configs"]:
        print("  Framing configs:")
        for line_no, event in summary["native_framing_configs"][:30]:
            print(
                f"    line {line_no} frameCounter={event.get('frameCounter')} "
                f"runtimeMode={event.get('runtimeValidationMode')} "
                f"validationKeyFp={event.get('validationKeyFingerprint')}"
            )
    else:
        print("  Framing configs: none")
    if summary["native_cipher_contexts"]:
        print("  Cipher contexts:")
        for line_no, event in summary["native_cipher_contexts"][:30]:
            print(
                f"    line {line_no} modeArg={event.get('transformModeArg')} "
                f"cipherKeyFp={event.get('cipherKeyFingerprint')} "
                f"initialCounterFp={event.get('initialCounterBlockFingerprint')}"
            )
    else:
        print("  Cipher contexts: none")

    print("\nNative Framing pack/unpack traces:")
    if summary["framing_traces"]:
        for item in summary["framing_traces"][:30]:
            outer = item["outer"] or {}
            frame_text = ""
            if outer:
                frame_text = (
                    f" prefix={outer.get('validation_prefix')}"
                    f" indicator={outer.get('cipher_payload_indicator')}"
                    f" expected_outer={outer.get('expected_outer_len')}"
                    f" outer_fp={outer.get('outer_sha256_12')}"
                    f" cipher_fp={outer.get('cipher_sha256_12')}"
                )
            print(
                f"  line {item['line_no']} {item['event_name']} result={item['result']} "
                f"plain={item['plain_len']}B outer={item['outer_len']}B{frame_text}"
            )
            if item["plaintext_datax_frames"]:
                for frame in item["plaintext_datax_frames"][:3]:
                    ext = ", ".join(
                        f"type={entry['type']} value={entry['value']}"
                        for entry in frame["extensions"]
                    )
                    print(
                        "    plaintext DataX "
                        f"base=0x{frame['base_id']:04x} payload={frame['payload_len']} ext=[{ext}]"
                    )
    else:
        print("  none")

    if summary["typed_counts"]:
        print("\nTypedBuffer types:")
        for type_value, count in sorted(summary["typed_counts"].items()):
            suffix = ""
            if isinstance(type_value, int):
                suffix = f" ({message_type_name(type_value)})"
            print(f"  {type_value}{suffix}: {count}")

    if summary["auth_typed_buffers"]:
        print("\nAirShield auth service typed buffers:")
        for item in summary["auth_typed_buffers"][:30]:
            context = []
            if item.get("service") is not None:
                context.append(f"service={item.get('service')}")
            if item.get("channel_id") is not None:
                context.append(f"channel={item.get('channel_id')}")
            if item.get("service_inferred"):
                context.append("service_inferred=true")
            context_text = f" {' '.join(context)}" if context else ""
            print(
                f"  line {item['line_no']} {item['event_name']} "
                f"type={item['type']} ({item['type_name']}) len={item['payload_len']} "
                f"fp={item.get('payload_fingerprint')}{context_text}"
            )

    if summary["link_setup_decodes"]:
        print("\nAirShield link-setup typed buffers:")
        for item in summary["link_setup_decodes"][:30]:
            context = []
            if item["service"] is not None:
                context.append(f"service={item['service']}")
            if item["channel_id"] is not None:
                context.append(f"channel={item['channel_id']}")
            context_text = f" {' '.join(context)}" if context else ""
            print(
                f"  line {item['line_no']} {item['event_name']} "
                f"type={item['type']} ({item['type_name']}) len={item['payload_len']}{context_text}"
            )
            print(f"    {json.dumps(item['decoded'], sort_keys=True)}")

    if summary["datax_decodes"]:
        print("\nDataX-shaped buffers:")
        for line_no, event_name, label, frames in summary["datax_decodes"][:30]:
            print(f"  line {line_no} {event_name}.{label}: {len(frames)} frame(s)")
            for frame in frames[:5]:
                ext = ", ".join(
                    f"type={item['type']} value={item['value']} hex={item['hex']}"
                    for item in frame["extensions"]
                )
                print(
                    "    "
                    f"offset={frame['offset']} total={frame['total_len']} body={frame['body_len']} "
                    f"base=0x{frame['base_id']:04x} ext={len(frame['extensions'])} "
                    f"reservedBit14={frame['reserved_header_bit14']} payload={frame['payload_len']} {ext}"
                )
    else:
        print("\nDataX-shaped buffers: none")

    if show_events:
        print("\nMilestone events:")
        for line_no, event in summary["milestones"]:
            compact = dict(event)
            compact.pop("ts", None)
            print(f"  line {line_no}: {json.dumps(compact, sort_keys=True)}")


def main():
    parser = argparse.ArgumentParser(description="Summarize AirShield/DataX Frida JSONL captures.")
    parser.add_argument("capture", type=Path)
    parser.add_argument("--events", action="store_true", help="print milestone events")
    args = parser.parse_args()

    summary = summarize(args.capture)
    print_summary(summary, show_events=args.events)


if __name__ == "__main__":
    main()
