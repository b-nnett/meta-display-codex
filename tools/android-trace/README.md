# Android AirShield / DataX Trace

This captures the first secure-link evidence we need from the official Meta AI app without logging account tokens.

## Requirements

- Rooted Android emulator or device.
- Meta AI app installed as `com.facebook.stella`.
- `adb` on the Mac.
- Frida tools on the Mac.
- Matching `frida-server` running on the Android side.
- The target process must expose Frida's Java bridge. The native probe runners
  now check this explicitly after attach; if they report that `Java` is
  unavailable, use a different rooted image/device or restart `frida-server` as
  root with a Mac `frida` Python package version matching the server.
- Native probe runner ADB calls are timeout-bounded. If an emulator wedges after
  attach or root restart, the runner should fail with a clear ADB timeout rather
  than waiting indefinitely.
- When probe inputs have already been parsed, native probe failures still write
  redacted JSON artifacts with `probeStatus=failed` and `native.errors`. The
  readiness/audit tools show these attempts but continue to fail closed until
  native `PrivateKey` / `Framing.pack` outputs are present.

Install the Mac-side Frida tools if needed:

```sh
python3 -m pip install --user frida-tools
```

## Native Probe Target Preflight

Before running `probe_airshield_private_key.py` or
`probe_airshield_framing.py`, check whether the current Android target can
actually support the Java-backed native probes:

```sh
python3 tools/android-trace/check_native_probe_target.py
```

The preflight writes a redacted report under `reverse/native-probe-targets/`
covering ADB state, optional `adb root`, package install state, `frida-server`,
Mac-side Frida version, and a minimal Frida Java-bridge attach check. It exits
success only when the target is ready for the native probe scripts.

Run local probe-runner self-tests without Android/Frida:

```sh
python3 tools/android-trace/probe_airshield_private_key.py --self-test
python3 tools/android-trace/probe_airshield_framing.py --self-test
```

These checks cover local input validation, output path shaping, and failed
artifact structure. They do not replace native probe artifacts from a rooted
target.

## Run

```sh
/Users/example/Documents/meta-display-codex/tools/android-trace/run_airshield_trace.sh
```

The runner starts `com.facebook.stella`, injects `airshield_datax_trace.js`, and writes JSONL output to:

```text
/Users/example/Documents/meta-display-codex/reverse/captures/
```

In this workspace the runner defaults to the first adb device in `device` state, starts `/data/local/tmp/frida-server` if it is not already running, and attaches to the running app process by PID. Override the adb target when needed:

```sh
DEVICE_SERIAL=emulator-5554 /Users/example/Documents/meta-display-codex/tools/android-trace/run_airshield_trace.sh
```

If the package name changes, pass it explicitly:

```sh
/Users/example/Documents/meta-display-codex/tools/android-trace/run_airshield_trace.sh com.facebook.stella
```

For native AirShield method registration evidence, start the trace against a fresh
app process. `RegisterNatives` happens early; if the app was already running, the
Java hooks may still install but the native method table can already be missed.
Use `FORCE_SPAWN=1` when you specifically want that early native evidence:

```sh
FORCE_SPAWN=1 DEVICE_SERIAL=emulator-5554 \
  /Users/example/Documents/meta-display-codex/tools/android-trace/run_airshield_trace.sh
```

## Events To Find

- `ble.createInsecureL2capChannel`
  - Confirms the Android app chose PSM `255`.
- `airshield.initialize`
  - Confirms normal secure-link flags.
- `airshield.start`
  - Marks native AirShield starting.
- `native.registerNatives.airshieldClass`
  - Shows AirShield JNI classes registered by the native library.
- `native.registerNatives.airshieldMethod`
  - Shows AirShield native method pointers, signatures, and module offsets.
- `native.airshield.staticHooks.installed`
  - Shows static `libstartup.so` offset hooks installed for recovered AirShield `CipherBuilder` / `Framing` JNI methods.
- `native.airshield.method.enter` / `native.airshield.method.leave`
  - Shows calls into selected AirShield native methods without dumping raw key material.
- `native.airshield.framing_config`
  - Redacted `db12ec` / Framing-config state: validation-key SHA-256 prefix, runtime validation mode, and frame counter.
- `native.airshield.cipher_context_setup`
  - Redacted `db18d4` / cipher-context setup state: cipher-key SHA-256 prefix, transform mode argument, and initial counter-block SHA-256 prefix.
- `airshield.framing.pack`
  - Captures Java-wrapper `Framing.pack(ByteBuffer, ByteBuffer)` before/after state: plaintext bytes, outer encrypted frame bytes, validation prefix, cipher-size indicator, lengths, capture-completeness flags, and full-window SHA-256 prefixes.
- `airshield.framing.unpack`
  - Captures Java-wrapper `Framing.unpack(ByteBuffer, ByteBuffer)` before/after state: encrypted outer frame bytes, recovered plaintext bytes, validation prefix, cipher-size indicator, lengths, capture-completeness flags, and full-window SHA-256 prefixes.
- `airshield.onSend`
  - The critical raw bytes written by AirShield to the L2CAP stream.
- `airshield.preambleReady`
  - Native AirShield parsed the peer preamble and exposed the temporary DataX connection.
- `datax.registerService`
  - Shows which auth service is registered during preamble auth.
- `airshield.auth.delegate.register_services`
  - Shows which Java auth delegate registered services on the temporary preamble connection.
- `airshield.auth.delegate.start`
  - Shows which Java auth delegate begins authentication: normal identity (`GD5`), ACDC/Constellation (`GCS`), or identity-plus-prototype fallback (`C30908GCi`).
- `airshield.auth.accept_key_candidate`
  - Redacted `G44` callback event for the app public-key candidate before it is padded/truncated to the 64-byte AirShield preamble-auth shape.
- `airshield.auth.result_callback`
  - Redacted retry/result callback evidence for the identity and ACDC paths.
- `airshield.identity.private_key.set_raw`
  - Redacted native `PrivateKey.setRaw(...)` load evidence: raw blob length and SHA-256 prefix only.
- `airshield.identity.private_key.serialize`
  - Redacted native `PrivateKey.serialize()` evidence for comparing Android SharedPreferences blobs with Mac keychain imports.
- `airshield.identity.private_key.recover_public_key`
  - Redacted native `PrivateKey.recoverPublicKey().serialize()` evidence for comparing the accepted public key with a Mac-derived public key.
- `airshield.identity.public_key.set_raw` / `airshield.identity.public_key.serialize`
  - Redacted public-key load/serialization fingerprints, useful for pairing accepted `G44` auth keys to stored identity slots.
- `datax.handleWrite`
  - Captures DataX frame header/payload buffers generated by native DataX.
- `datax.localChannel.send` / `datax.remoteChannel.send`
  - Captures typed-buffer type and payload before native framing.
  - The analyzer names AirShield preamble-auth service traffic when service IDs
    are known: production identity service `36` (`IDENTITY_REQUEST` `12288`,
    `IDENTITY_RESPONSE` `12289`, plus ownership/provisioning message types) and
    prototype identity service `77` (`REGISTER_KEY` `8192`, `KEY_ACCEPTED`
    `8193`).
  - `datax.localChannel.init` records channel IDs when available, and the
    analyzer uses those channel-to-service mappings to name later
    `RemoteChannel.send` auth messages even if the send event has no service
    field.
- `airshield.acceptAuthentication`
  - Confirms the final preamble-auth public-key handoff; only length and SHA-256 fingerprint are logged.
- `airshield.endLinkSetup.setAsMain` / `airshield.endLinkSetup.setUserData`
  - Shows how Java configures the end-link setup callback. User data is reduced to length and SHA-256 fingerprint.
- `airshield.streamReady`
  - Secure stream is ready; rollover bytes may be the first decrypted DataX bytes.

## Analyze A Capture

```sh
/Users/example/Documents/meta-display-codex/tools/android-trace/analyze_airshield_trace.py \
  /Users/example/Documents/meta-display-codex/reverse/captures/airshield-datax-YYYYMMDD-HHMMSS.jsonl
```

Add `--events` to print the milestone events in order.

The analyzer reports:

- event counts
- hook install/missing status
- whether each expected handshake milestone appeared

## Extract Identity Slots

For pulled Android `SharedPreferences` XML, use:

```sh
/Users/example/Documents/meta-display-codex/tools/android-trace/extract_airshield_identity_prefs.py \
  /path/to/shared_prefs
```

The extractor reports AirShield identity slots with lengths and SHA-256
prefixes only. Add `--show-base64` only when importing the chosen slot into the
Mac bridge. See `reverse/airshield-identity-import.md` for the slot mapping.
- native AirShield `RegisterNatives` hooks, class registrations, method pointers,
  and selected native method call counts
- static AirShield offset hook installation status
- native `Framing.pack/unpack` comparison fields, including validation prefix,
  cipher-size indicator, outer/cipher fingerprints, and any plaintext DataX frames
- redacted native framing setup fingerprints for validation key, cipher key,
  frame counter, runtime validation mode, and initial counter block
- observed DataX typed-buffer types
- redacted AirShield link-setup protobufs when typed buffers match
  `RequestEncryption`, `EnableEncryption`, or `EndLinkSetup`
- any DataX-shaped raw buffers found in the capture

AirShield link-setup payloads are summarized without dumping raw keys or random
seeds. The analyzer prints byte lengths and short SHA-256 fingerprints for
public keys, challenges, seeds, IVs, UUIDs, and user-data payloads. Framing
pack/unpack raw hex payloads are capped by the trace script's `MAX_HEX_BYTES`,
but the trace records full-window SHA-256 prefixes and completion flags, so large
frames can still be compared without dumping full ciphertext.

## Extract AirShield / ACDC State

Static analysis shows the app stores reusable AirShield key material in app-private
SharedPreferences, especially `acdc-shared-pref`. On a rooted target, generate a
redacted report like this:

```sh
/Users/example/Documents/meta-display-codex/tools/android-trace/extract_airshield_state.py
```

Override the adb target when needed:

```sh
DEVICE_SERIAL=emulator-5554 \
  /Users/example/Documents/meta-display-codex/tools/android-trace/extract_airshield_state.py \
  --serial emulator-5554
```

The default report records key names, value lengths, and SHA-256 fingerprints,
but redacts private keys, certificates, and manifests. Reports are written under:

```text
/Users/example/Documents/meta-display-codex/reverse/extracted-state/
```

For local bridge development only, use `--include-secret-material` to write raw
values into the JSON report. Do not paste that output into chat or commit it.

The report also summarizes the identity key slots that matter for preamble
authentication:

- `app-private-key`
- `acdc-app-private-key`
- `constellation-manifest-authority-key`

Presence plus decoded length/fingerprint is enough to tell whether the rooted
target has reusable identity state without exposing the private key material.

To turn an extracted-state report into a Mac bridge import plan, use the local
helper. It prints only slot metadata by default:

```sh
python3 /Users/example/Documents/meta-display-codex/tools/live/prepare_airshield_identity_import.py \
  /Users/example/Documents/meta-display-codex/reverse/extracted-state/com.facebook.stella-airshield-state-redacted-YYYYMMDD-HHMMSS.json
```

If the report was created with `--include-secret-material`, the helper can write
the chosen slot's Base64 value to a local `0600` file without printing the
secret:

```sh
python3 /Users/example/Documents/meta-display-codex/tools/live/prepare_airshield_identity_import.py \
  /Users/example/Documents/meta-display-codex/reverse/extracted-state/com.facebook.stella-airshield-state-with-secrets-YYYYMMDD-HHMMSS.json \
  --slot acdc-app-private-key \
  --export-base64
```

The helper prefers `acdc-app-private-key`, then `app-private-key`, then
`constellation-manifest-authority-key` when no slot is specified. Keep the
exported Base64 file local; it is private identity material. In the Mac bridge,
select the same slot, paste the exported file path into `Base64 identity file
path`, and press `Load File`.

After importing a slot into the Mac bridge, compare the redacted Android state,
optional native parser probe, Android trace, and Mac session identity evidence:

```sh
python3 /Users/example/Documents/meta-display-codex/tools/live/compare_airshield_identity.py \
  --latest-artifacts \
  --strict

python3 /Users/example/Documents/meta-display-codex/tools/live/compare_airshield_identity.py \
  --identity-prefs /Users/example/Documents/meta-display-codex/reverse/extracted-state/com.facebook.stella-airshield-state-redacted-YYYYMMDD-HHMMSS.json \
  --native-probe /Users/example/Documents/meta-display-codex/reverse/identity-probes/airshield-private-key-probe-acdc-app-private-key-YYYYMMDD-HHMMSS.json \
  --android-trace /Users/example/Documents/meta-display-codex/reverse/captures/airshield-datax-YYYYMMDD-HHMMSS.jsonl \
  --mac-session ~/Library/Logs/CodexBandBridge/sessions/session-UUID.jsonl \
  --strict
```

Use `--latest-artifacts --strict` for normal operator checks after the newest
state/probe/trace/Mac artifacts have been written. The explicit path form is
for reviewing a specific older artifact set.

That comparison should show a private-key fingerprint match between the Android
slot and Mac import, plus a public-key fingerprint match between Android's
accepted/recovered auth key and one Mac-derived public-key candidate.

To test Meta's native `PrivateKey.setRaw` / `serialize` /
`recoverPublicKey` behavior without a live band, save a local Base64 slot value
and run:

```sh
python3 /Users/example/Documents/meta-display-codex/tools/android-trace/probe_airshield_private_key.py \
  --serial emulator-5554 \
  --slot acdc-app-private-key \
  --base64-file /path/to/acdc-app-private-key.base64
```

The probe writes a redacted JSON artifact under `reverse/identity-probes/`. Use
`--include-secret-material` only for a local trusted artifact; do not paste that
output into chat or commit it.

## Probe Native Framing Pack

To compare Swift's offline encrypted-frame candidate against Meta's native
`Framing.pack(...)` without a live band, run a synthetic native framing probe on
the rooted emulator:

```sh
python3 /Users/example/Documents/meta-display-codex/tools/android-trace/probe_airshield_framing.py \
  --serial emulator-5554 \
  --base 0 \
  --include-secret-material
```

By default the probe uses deterministic local/remote P-256 scalar candidates,
challenge, seed, IV, and an `EndLinkSetup`-shaped plaintext. The normal output
is redacted to lengths and SHA-256 prefixes; `--include-secret-material` stores
the synthetic input hex values locally so Swift/Python comparison tools can
reproduce the exact frame. Do not use `--include-secret-material` with real
identity slots or paste its output into chat.

The artifact is written under:

```text
/Users/example/Documents/meta-display-codex/reverse/framing-probes/
```

Useful fields:

- `native.txChallenge` / `native.rxChallenge`
- `native.localPublicKey` and `native.remotePublicKey`
- `native.pack.outerFrame`
- `native.pack.validationPrefixHex`
- `native.pack.cipherPayload`
- `native.pack.inputFullyConsumed`
- `native.pack.expectedPaddedPlaintextLength`
- `native.pack.expectedCipherPayloadLength` / `actualCipherPayloadLength`
- `native.pack.expectedOuterFrameLength` / `actualOuterFrameLength`
- `native.pack.expectedSizeIndicator` / `actualSizeIndicator`

Summarize or compare the probe artifact with:

```sh
python3 /Users/example/Documents/meta-display-codex/tools/live/compare_airshield_framing.py \
  --latest-artifacts \
  --strict

python3 /Users/example/Documents/meta-display-codex/tools/live/compare_airshield_framing.py \
  --native-framing-probe /Users/example/Documents/meta-display-codex/reverse/framing-probes/airshield-framing-probe-YYYYMMDD-HHMMSS.json
```

Use `--latest-artifacts --strict` for normal operator checks after the newest
trace/probe/Mac artifacts have been written. The explicit path form is for
reviewing a specific older artifact set.

When a Mac session contains matching synthetic Swift candidates, add
`--mac-session ~/Library/Logs/CodexBandBridge/sessions/session-UUID.jsonl` to
score prefix/cipher/outer fingerprints.

For the synthetic probe path, the tighter local comparison is:

```sh
/Users/example/Documents/meta-display-codex/tools/swift/compare_airshield_framing_probe.sh \
  /Users/example/Documents/meta-display-codex/reverse/framing-probes/airshield-framing-probe-YYYYMMDD-HHMMSS.json
```

This requires the probe artifact to include `secretMaterial`, so generate it
with `--include-secret-material` only when using deterministic synthetic inputs.
It computes the same Swift offline frame candidates used by the bridge and
scores them against the native probe's validation prefix, cipher-payload
fingerprint, and outer-frame fingerprint.

## Expected MVP Use

1. Put the band in pairing/connection state and run this trace.
2. Let the official app connect until the band is shown as usable.
3. Stop the trace after `airshield.streamReady` and the first gesture-enable traffic.
4. Run `analyze_airshield_trace.py` against the JSONL to verify DataX frame layout and AirShield message order.
5. Only after that, implement Mac-side transmit.
