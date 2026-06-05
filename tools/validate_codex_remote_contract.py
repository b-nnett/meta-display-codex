#!/usr/bin/env python3
"""Validate the Codex remote contract against the installed desktop app-server.

This is intentionally dependency-free. It validates the pieces this iOS app
depends on: generated method inventories, required request params, notification
names, server request names, and the live-only thread turn pagination route.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import select
import subprocess
import sys
import time
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "build" / "codex-app-server-schema"
CATALOG = ROOT / "CodexRayBan" / "Remote" / "CodexRemoteAPICatalog.swift"
CODEX = pathlib.Path("/Applications/Codex.app/Contents/Resources/codex")

LIVE_ONLY_METHODS = {"thread/turns/list"}


def load_json(path: pathlib.Path) -> Any:
    with path.open() as f:
        return json.load(f)


def generate_schemas() -> None:
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [str(CODEX), "app-server", "generate-json-schema", "--out", str(SCHEMA_DIR)],
        check=True,
    )


def schema_methods(schema_name: str) -> set[str]:
    schema = load_json(SCHEMA_DIR / schema_name)
    methods: set[str] = set()
    for item in schema.get("oneOf", []):
        method_schema = item.get("properties", {}).get("method", {})
        methods.update(method_schema.get("enum", []))
        if isinstance(method_schema.get("const"), str):
            methods.add(method_schema["const"])
    return methods


def client_request_param_refs() -> dict[str, str]:
    schema = load_json(SCHEMA_DIR / "ClientRequest.json")
    refs: dict[str, str] = {}
    for item in schema.get("oneOf", []):
        props = item.get("properties", {})
        method_schema = props.get("method", {})
        method_values = method_schema.get("enum") or [method_schema.get("const")]
        method = method_values[0] if method_values else None
        ref = props.get("params", {}).get("$ref")
        if isinstance(method, str) and isinstance(ref, str):
            refs[method] = ref
    return refs


def client_request_param_schemas() -> dict[str, dict[str, Any]]:
    schema = load_json(SCHEMA_DIR / "ClientRequest.json")
    schemas: dict[str, dict[str, Any]] = {}
    for item in schema.get("oneOf", []):
        props = item.get("properties", {})
        method_schema = props.get("method", {})
        method_values = method_schema.get("enum") or [method_schema.get("const")]
        method = method_values[0] if method_values else None
        params_schema = props.get("params")
        if isinstance(method, str) and isinstance(params_schema, dict):
            schemas[method] = params_schema
    return schemas


def schema_for_ref(ref: str) -> dict[str, Any]:
    name = ref.split("/")[-1]
    direct = SCHEMA_DIR / "v2" / f"{name}.json"
    if direct.exists():
        return load_json(direct)
    protocol = load_json(SCHEMA_DIR / "ClientRequest.json")
    definition = protocol.get("definitions", {}).get(name)
    if isinstance(definition, dict):
        return definition
    raise AssertionError(f"Could not resolve schema ref {ref}")


def swift_string_set(name: str) -> set[str]:
    source = CATALOG.read_text()
    marker = f"static let {name}: Set<String> = ["
    start = source.find(marker)
    if start == -1:
        raise AssertionError(f"Missing Swift set {name}")
    start = source.find("[", start)
    depth = 0
    end = None
    for index in range(start, len(source)):
        char = source[index]
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end is None:
        raise AssertionError(f"Unterminated Swift set {name}")
    body = source[start : end + 1]
    return set(re.findall(r'"([^"]+)"', body))


def catalog_rpc_methods() -> set[str]:
    source = CATALOG.read_text()
    return set(re.findall(r'rpcMethod:\s*"([^"]+)"', source))


def catalog_notification_names() -> set[str]:
    source = CATALOG.read_text()
    names: set[str] = set()
    for body in re.findall(r"notificationNames:\s*\[([^\]]*)\]", source):
        names.update(re.findall(r'"([^"]+)"', body))
    return names


def validate_catalog_against_schema() -> None:
    generated_methods = schema_methods("ClientRequest.json")
    server_notifications = schema_methods("ServerNotification.json")
    server_requests = schema_methods("ServerRequest.json")

    swift_observed_methods = swift_string_set("observedAppServerMethods")
    swift_notifications = swift_string_set("observedServerNotifications")
    swift_requests = swift_string_set("observedServerRequests")
    swift_live_only = swift_string_set("liveOnlyAppServerMethods")

    if swift_live_only != LIVE_ONLY_METHODS:
        raise AssertionError(f"Unexpected live-only methods: {sorted(swift_live_only)}")

    missing_from_swift = (generated_methods | LIVE_ONLY_METHODS) - swift_observed_methods
    if missing_from_swift:
        raise AssertionError(f"Swift method catalog missing: {sorted(missing_from_swift)}")

    invalid_swift_methods = swift_observed_methods - generated_methods - LIVE_ONLY_METHODS
    if invalid_swift_methods:
        raise AssertionError(f"Swift method catalog has unknown methods: {sorted(invalid_swift_methods)}")

    unknown_rpc = catalog_rpc_methods() - generated_methods - LIVE_ONLY_METHODS
    if unknown_rpc:
        raise AssertionError(f"Catalog RPC methods are not schema-backed or live-probed: {sorted(unknown_rpc)}")

    unknown_notifications = swift_notifications - server_notifications
    if unknown_notifications:
        raise AssertionError(f"Swift notification catalog has unknown names: {sorted(unknown_notifications)}")

    unknown_requests = swift_requests - server_requests
    if unknown_requests:
        raise AssertionError(f"Swift server request catalog has unknown names: {sorted(unknown_requests)}")

    unknown_catalog_names = catalog_notification_names() - server_notifications - server_requests
    if unknown_catalog_names:
        raise AssertionError(f"Capability notification/request names are unknown: {sorted(unknown_catalog_names)}")


REQUEST_FIXTURES: dict[str, dict[str, Any]] = {
    "initialize": {
        "clientInfo": {"name": "Codex Ray-Ban", "version": "0.1"},
        "capabilities": {"experimentalApi": True},
    },
    "thread/list": {
        "limit": 50,
        "archived": False,
        "sortKey": "updated_at",
        "sortDirection": "desc",
        "useStateDbOnly": False,
        "cursor": None,
    },
    "thread/read": {"threadId": "thread-1", "includeTurns": True},
    "thread/loaded/list": {},
    "thread/start": {"cwd": "/Users/example/Documents/meta-display-codex", "model": "gpt-5-codex"},
    "thread/resume": {"threadId": "thread-1"},
    "thread/archive": {"threadId": "thread-1"},
    "thread/unarchive": {"threadId": "thread-1"},
    "thread/name/set": {"threadId": "thread-1", "name": "New name"},
    "thread/goal/set": {"threadId": "thread-1", "objective": "Ship mobile client"},
    "thread/goal/clear": {"threadId": "thread-1"},
    "thread/fork": {"threadId": "thread-1"},
    "thread/compact/start": {"threadId": "thread-1"},
    "thread/rollback": {"threadId": "thread-1", "numTurns": 1},
    "thread/approveGuardianDeniedAction": {"threadId": "thread-1", "event": {"type": "approved"}},
    "thread/shellCommand": {"threadId": "thread-1", "command": "pwd"},
    "turn/start": {
        "threadId": "thread-1",
        "input": [
            {"type": "text", "text": "Hello"},
            {"type": "localImage", "path": "/tmp/image.png", "detail": "auto"},
        ],
    },
    "turn/steer": {
        "threadId": "thread-1",
        "expectedTurnId": "turn-1",
        "input": [{"type": "text", "text": "Continue"}],
    },
    "turn/interrupt": {"threadId": "thread-1", "turnId": "turn-1"},
    "fs/readFile": {"path": "/Users/example/file.swift"},
    "fs/readDirectory": {"path": "/Users/example/Documents"},
    "fs/getMetadata": {"path": "/Users/example/file.swift"},
    "fuzzyFileSearch": {"query": "CodexHomeView", "roots": ["/Users/example/Documents/meta-display-codex"]},
    "model/list": {"limit": 50, "includeHidden": False},
    "account/read": {"refreshToken": False},
    "account/rateLimits/read": None,
    "config/read": {"cwd": "/Users/example/Documents/meta-display-codex", "includeLayers": True},
}


def validate_basic_schema_value(schema: dict[str, Any], value: Any, path: str = "$") -> None:
    if "anyOf" in schema:
        errors = []
        for option in schema["anyOf"]:
            try:
                validate_basic_schema_value(option, value, path)
                return
            except AssertionError as error:
                errors.append(str(error))
        raise AssertionError(f"{path} did not match anyOf: {errors[:3]}")

    if "oneOf" in schema:
        matches = 0
        errors = []
        for option in schema["oneOf"]:
            try:
                validate_basic_schema_value(option, value, path)
                matches += 1
            except AssertionError as error:
                errors.append(str(error))
        if matches != 1:
            raise AssertionError(f"{path} matched {matches} oneOf schemas: {errors[:3]}")
        return

    if "allOf" in schema:
        for option in schema["allOf"]:
            validate_basic_schema_value(option, value, path)
        return

    expected_type = schema.get("type")
    if isinstance(expected_type, list):
        if value is None and "null" in expected_type:
            return
        concrete = [t for t in expected_type if t != "null"]
        if concrete:
            validate_basic_schema_value({**schema, "type": concrete[0]}, value, path)
        return

    if expected_type == "object":
        if not isinstance(value, dict):
            raise AssertionError(f"{path} expected object")
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                raise AssertionError(f"{path} missing required key {key}")
        properties = schema.get("properties", {})
        for key, child in properties.items():
            if key in value and isinstance(child, dict):
                validate_basic_schema_value(resolve_schema(child, schema), value[key], f"{path}.{key}")
        return

    if expected_type == "array":
        if not isinstance(value, list):
            raise AssertionError(f"{path} expected array")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                validate_basic_schema_value(resolve_schema(item_schema, schema), item, f"{path}[{index}]")
        return

    if expected_type == "string":
        if not isinstance(value, str):
            raise AssertionError(f"{path} expected string")
        if "enum" in schema and value not in schema["enum"]:
            raise AssertionError(f"{path} expected one of {schema['enum']}, got {value}")
        return

    if expected_type == "boolean":
        if not isinstance(value, bool):
            raise AssertionError(f"{path} expected boolean")
        return

    if expected_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise AssertionError(f"{path} expected integer")
        return

    if expected_type == "null":
        if value is not None:
            raise AssertionError(f"{path} expected null")
        return


def resolve_schema(schema: dict[str, Any], root_schema: dict[str, Any]) -> dict[str, Any]:
    if "$ref" not in schema:
        return schema
    ref = schema["$ref"]
    name = ref.split("/")[-1]
    definition = root_schema.get("definitions", {}).get(name)
    if isinstance(definition, dict):
        return definition
    return schema_for_ref(ref)


def validate_request_fixtures() -> None:
    param_schemas = client_request_param_schemas()
    for method, params in REQUEST_FIXTURES.items():
        raw_schema = param_schemas.get(method)
        if raw_schema is None:
            raise AssertionError(f"No generated params schema for fixture method {method}")
        schema = schema_for_ref(raw_schema["$ref"]) if "$ref" in raw_schema else raw_schema
        validate_basic_schema_value(schema, params, f"{method}.params")


def send(proc: subprocess.Popen[str], request_id: str, method: str, params: dict[str, Any]) -> None:
    proc.stdin.write(
        json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}, separators=(",", ":"))
        + "\n"
    )
    proc.stdin.flush()


def notify(proc: subprocess.Popen[str], method: str, params: dict[str, Any]) -> None:
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params}, separators=(",", ":")) + "\n")
    proc.stdin.flush()


def wait_for(proc: subprocess.Popen[str], wanted: set[str], timeout: float) -> dict[str, Any]:
    deadline = time.time() + timeout
    got: dict[str, Any] = {}
    while time.time() < deadline and wanted - got.keys():
        ready, _, _ = select.select([proc.stdout, proc.stderr], [], [], 0.2)
        for stream in ready:
            line = stream.readline()
            if not line or stream is proc.stderr:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if "id" in payload:
                got[str(payload["id"])] = payload
    return got


def live_probe_turn_pagination() -> None:
    proc = subprocess.Popen(
        [str(CODEX), "app-server", "--listen", "stdio://"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    try:
      send(proc, "1", "initialize", {"clientInfo": {"name": "contract-validator", "version": "0.1"}, "capabilities": {"experimentalApi": True}})
      notify(proc, "initialized", {})
      send(proc, "2", "thread/list", {"limit": 1, "archived": False, "sortKey": "updated_at", "sortDirection": "desc", "useStateDbOnly": False})
      got = wait_for(proc, {"1", "2"}, 12)
      thread_response = got.get("2")
      if not thread_response or "result" not in thread_response:
          raise AssertionError(f"thread/list did not return a result: {thread_response}")
      data = thread_response["result"].get("data") or []
      if not data:
          raise AssertionError("thread/list returned no threads to probe")
      thread_id = data[0]["id"]
      send(proc, "3", "thread/turns/list", {"threadId": thread_id, "limit": 2, "cursor": None})
      got = wait_for(proc, {"3"}, 12)
      page1 = got.get("3")
      if not page1 or "result" not in page1:
          raise AssertionError(f"thread/turns/list page 1 failed: {page1}")
      result1 = page1["result"]
      for key in ["data", "nextCursor", "backwardsCursor"]:
          if key not in result1:
              raise AssertionError(f"thread/turns/list missing {key}: {result1}")
      if not isinstance(result1["data"], list):
          raise AssertionError("thread/turns/list data is not a list")
      cursor = result1.get("nextCursor")
      if cursor is not None:
          if not isinstance(cursor, str):
              raise AssertionError(f"Unexpected nextCursor shape: {cursor}")
          cursor_payload = json.loads(cursor)
          if not isinstance(cursor_payload, dict) or "turnId" not in cursor_payload or "includeAnchor" not in cursor_payload:
              raise AssertionError(f"Unexpected nextCursor payload: {cursor_payload}")
          send(proc, "4", "thread/turns/list", {"threadId": thread_id, "limit": 2, "cursor": cursor})
          got = wait_for(proc, {"4"}, 12)
          page2 = got.get("4")
          if not page2 or "result" not in page2:
              raise AssertionError(f"thread/turns/list page 2 failed: {page2}")
    finally:
      proc.terminate()
      try:
          proc.wait(timeout=3)
      except Exception:
          proc.kill()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-live", action="store_true", help="Skip the local app-server pagination probe.")
    args = parser.parse_args()

    generate_schemas()
    validate_catalog_against_schema()
    validate_request_fixtures()
    if not args.skip_live:
        live_probe_turn_pagination()

    print("Codex remote contract validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
