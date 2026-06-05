# Live Band Validation Tools

These helpers read the Mac bridge logs under:

```text
~/Library/Logs/CodexBandBridge/sessions/
```

## AirShield status

Run once:

```sh
python3 tools/live/airshield_status.py
```

Equivalent explicit latest-session form:

```sh
python3 tools/live/airshield_status.py --latest
```

Watch during a pairing/handshake run:

```sh
python3 tools/live/airshield_status.py --watch 2
```

Run the built-in synthetic state/action checks:

```sh
python3 tools/live/airshield_status.py --self-test
```

Send a system notification when the latest run reaches an actionable state,
such as pairing reset needed or a manual gated send becoming ready:

```sh
python3 tools/live/airshield_notify.py --watch 2
```

Use `--dry-run --once` to print the notification text without notifying.

The useful states are:

- `SCANNING_FOR_BAND`: the Mac bridge is scanning and has not requested a connection to the exact band yet.
- `WAITING_FOR_AIRSHIELD_VALIDATION`: no encrypted receive candidate has matched yet.
- `PAIRING_REQUIRED_FOR_PROTECTED_GATT`: the band connected, but protected Meta characteristics returned insufficient authentication/encryption before the L2CAP PSM could be read.
- `IDENTITY_READY`: an AirShield identity slot was loaded or imported locally.
- `REQUEST_ENCRYPTION_SENT`: the Mac bridge staged and sent a RequestEncryption probe.
- `AUTH_CANDIDATES_STAGED`: local EnableTrust auth candidates were prepared from the imported identity and probe challenge.
- `CANDIDATE_MISSES_ONLY`: encrypted-looking frames arrived, but none matched the current key/framing candidates.
- `AUTH_GATE_LOADED`: a comparator-produced EnableTrust gate was loaded, but the current session has not yet made the matching staged auth frame sendable.
- `READY_TO_SEND_ENABLE_TRUST`: L2CAP is open and the current probe staged the exact EnableTrust candidate named by the loaded gate.
- `ENABLE_TRUST_SENT`: the gated EnableTrust auth frame was sent.
- `ENABLE_INPUTS_READY`: EnableEncryption was decoded and Swift KDF/framing candidates were staged, but no encrypted receive candidate has validated yet.
- `AIRSHIELD_RX_VALIDATED`: passive receive-side AirShield decrypt matched, but no encrypted follow-up frame is ready yet.
- `READY_TO_SEND_END_LINK_SETUP`: the matching encrypted EndLinkSetup candidate is staged and the manual button should be enabled.
- `END_LINK_SETUP_SENT`: the gated encrypted EndLinkSetup frame was sent.
- `READY_TO_SEND_GESTURE_ENABLE`: EndLinkSetup was sent and the matching gesture-enable candidate is staged.
- `GESTURE_ENABLE_SENT`: the gated gesture-enable frame was sent.
- `GESTURE_STREAM_ACTIVE`: stream-control response/update reported the gesture stream active.
- `GESTURES_DECODED`: at least one gesture payload was decoded and recorded.

The status output understands the current Mac session field names such as
`shared_material_source`, `validation_prefix_hex`,
`cipher_payload_fingerprint`, and `outer_frame_fingerprint`. It also shows the
last identity snapshot, RequestEncryption probe, EnableTrust candidate staging,
WIS stream-control counters, the last active-stream evidence, and the last
decoded gesture from the session summary. It also shows scan counters so a fresh
post-reset run is distinguishable from an AirShield wait state. Once
`EnableEncryption` has been
decoded it also shows the last input/candidate snapshot, including candidate
count, AirShield parameters/quirks/phased-link metadata, derivation mode,
context source, redacted fingerprints, and the staged EndLinkSetup /
gesture-enable candidate fingerprints.

The text output includes a `Next` line, and `--json` includes top-level
`next_action`, so a live pairing run can follow the current gated action without
inspecting the full JSONL log. The `--self-test` check covers the same
state/`next_action` ladder without requiring current Bluetooth logs.

Use `--json` if another script needs to consume the current status.

Current live transport note, 2026-06-05: the strongest earlier run reached
protected GATT, read PSM `255`, opened LE L2CAP, then hit the no-write-space
case. The latest run, session `561BBB6C-52E5-4B2A-A587-811029E7D1BA`, now
reports `PAIRING_RESET_RECOMMENDED` after three CoreBluetooth connect timeouts
before service discovery. Reset/forget `Meta Band 000J` in macOS Bluetooth
settings, put the band back in pairing mode, then relaunch or rescan with the
bridge before expecting new AirShield evidence.

If the bridge app is already running, request a fresh scan without UI
automation:

```sh
python3 tools/live/request_rescan.py
```

When the bridge reaches L2CAP again, the remaining transport risk is transmit
readiness: CoreBluetooth previously reported the output stream as open but
without write space, so the helper logged guarded `l2cap.tx_failed` attempts
instead of making a blocking write. After those retries, the bridge sent one
experimental `DADA` GATT DataX fallback frame and recorded
`gatt.datax_tx_count`; that run had `datax_tx=1`, `datax_rx=0`, `l2cap tx=0`,
and no AirShield response.

The Mac app also has a manual `Direct Write` diagnostic beside `Send Probe`.
Use it only for the L2CAP no-write-space case: it tries the same prepared
RequestEncryption frame from a background queue and closes L2CAP if the write
does not return quickly. `airshield_status.py` shows the Direct Write counts on
the `L2CAP` line and prints the last diagnostic event. `airshield_status.py`
also shows Direct Write and Rescan trigger counters on the `Control` line. The
session summary also
keeps `last_direct_write_diagnostic` and `last_tx_failed`, while the raw JSONL
still records `l2cap.direct_write_diagnostic_started`, `finished`, `blocked`,
and `timeout` events.

## Local gesture relay

When a decrypted gesture `DataX` frame is decoded, the Mac bridge forwards a
versioned JSON event to:

- `~/Library/Logs/CodexBandBridge/gesture-events.jsonl`
- TCP JSONL stream `127.0.0.1:49731`
- WebSocket stream `ws://127.0.0.1:49732`
- HTTP pull API `http://127.0.0.1:49733`
- LAN HTTP pull API `http://<mac-lan-ip>:49734`
- macOS distributed notification `com.example.codexbandbridge.gesture`

The relay schema is `codex_band_bridge.gesture.v1`. Stable fields include
`event_type=gesture`, `action`, `normalized_action`, `finger`,
`sequence_number`, `timestamp`, raw `finger`/`action`/`derived_action` values,
DataX `channel_alias` / `app_id` / `message_type`, and EMG/IMU provenance
fields when present. The local Swift validation fixture covers this payload
shape without opening the sockets.

HTTP paths:

- `/health`: server status and event count.
- `/latest`: latest gesture event or `null`.
- `/events`: JSON snapshot of retained recent events.
- `/events.ndjson`: retained recent events as newline-delimited JSON.

The Mac app displays the concrete LAN URL in the monitor. Use that URL from a
physical iPhone on the same Wi-Fi network; the loopback URL is for the Mac and
iPhone Simulator only.

To replay captured gesture events and prove the recorded normalized names still
match the current decoder, run:

```sh
python3 tools/live/validate_gesture_events.py \
  ~/Library/Logs/CodexBandBridge/gesture-events.jsonl
```

To generate a local forwarded-schema fixture for client/MVP work without a live
band, run:

```sh
python3 tools/live/validate_gesture_events.py \
  --write-fixture /tmp/codex-band-forwarded-fixture.jsonl

python3 tools/live/validate_gesture_events.py \
  /tmp/codex-band-forwarded-fixture.jsonl \
  --expect-forwarded-schema \
  --expect-live-band-actions
```

The same tool can also read session JSONL files because the Mac bridge records
`datax.gesture_decoded` events with `frame_payload_hex`. Use
`--expect-standard-actions` for the bridge's normalized action set, or
`--expect-live-band-actions` for the TODO live pass covering tap, double tap,
up/down, in/out, press, hold, and release. `tools/live/airshield_readiness.py`
includes this replay as the `Normalized gesture replay validates` gate. It also
checks for `Decrypted DataX frames` and `Decrypted gesture replay validates`;
its own `--expect-live-band-actions` flag adds the full live action coverage
check using only session events with `frame_source=airshield.decrypted`.
Readiness also fails closed if decrypted inner DataX frames use unknown
app/message routes.

For MVP relay validation, add `--expect-forwarded-schema` against
`gesture-events.jsonl`. That makes the replay fail unless every decoded event is
the versioned local forwarding schema and carries the gesture route
`app_id=2` / `message_type=13`, alongside the normalized action/finger fields
that are recomputed from `frame_payload_hex`.

The same flag is available on `tools/live/airshield_readiness.py` so a full live
run can require both decrypted gesture replay and the local relay contract in
one checklist.

To answer the narrower post-handshake question "did AirShield plaintext become
inner DataX/WIS protobuf traffic?", validate a Mac session directly:

```sh
python3 tools/live/validate_decrypted_datax_shape.py \
  ~/Library/Logs/CodexBandBridge/sessions/session-UUID.jsonl \
  --expect-active-stream \
  --expect-gesture
```

That checker counts only `source=airshield.decrypted` `datax.frame_source`
events, reports app/message routes such as `rpc.response`,
`rpc.stream_update`, and `emg_imu.gesture`, and fails if no decrypted inner
DataX frames are present.

## Shared Swift core

The protocol core intended to migrate to iOS is kept separate from the macOS
Bluetooth/UI/relay shell. Run:

```sh
tools/swift/validate_shared_core.sh
```

That check compiles only `DataXCodec.swift`, `GestureDecoder.swift`, and
`AirShieldSession.swift` with a small fixture target. It intentionally excludes
CoreBluetooth scanners, SwiftUI views, local sockets, and macOS notification
forwarding.

`tools/swift/validate_datax_codec.sh` adds the fuller bridge fixture coverage,
including AirShield encrypted-frame decrypt into a DataX gesture frame and
normalized `EmgImu$GestureEvent` output. This is local correctness evidence;
the readiness gates below still require live or native-probe evidence.

For static WIS routing drift checks, run:

```sh
python3 tools/static/analyze_wis_gesture_stream_static.py
```

It regenerates `reverse/wis-gesture-stream-static.md` and verifies the APK's
gesture/RPC app IDs, message types, stream-control wrapper fields, and the
Swift gesture-enable fixture constants still agree.

## Evidence readiness checklist

Start with the consolidated latest-state sweep:

```sh
python3 tools/live/airshield_next_gates.py
```

This runs static DataX framing parity, static first-write parity, static WIS
gesture-stream parity, latest live transport status, saved-artifact audit,
current-schema identity import prep, native-probe readiness, strict identity
parity, and strict framing parity checks. It exits nonzero until every gate is
satisfied, and each blocked gate prints the command it wrapped plus the next
missing action. Use `--json` if another script needs the same summary.

Current expected state, 2026-06-05: static DataX framing, first-write, and WIS
gesture-stream parity should pass; macOS pairing state needs a reset for
`Meta Band 000J`; the latest Android extracted-state report is stale and lacks
current-schema identity slot evidence; no native PrivateKey or Framing probe
artifacts have been captured yet.

Check whether the current logs contain enough evidence for an AirShield parity
decision:

```sh
python3 tools/live/airshield_readiness.py \
  --android-trace reverse/captures/airshield-datax-YYYYMMDD-HHMMSS.jsonl \
  --mac-session ~/Library/Logs/CodexBandBridge/sessions/session-UUID.jsonl
```

Run without arguments to inspect the latest Mac session only:

```sh
python3 tools/live/airshield_readiness.py
```

Equivalent explicit latest-session form:

```sh
python3 tools/live/airshield_readiness.py --latest
```

For a faster live operator view, use:

```sh
python3 tools/live/airshield_status.py
```

If the state is `STALE_PAIRING`, macOS has stale bond state for the band. If the
state is `PAIRING_RESET_RECOMMENDED`, CoreBluetooth saw the exact band but timed
out repeatedly before GATT discovery. If the state is
`PAIRING_REQUIRED_FOR_PROTECTED_GATT`, CoreBluetooth connected but could not read
the Meta protected characteristics until the band is paired/bonded. In these
cases, forget/reset the band if needed, put the band back in pairing mode, accept
the macOS Bluetooth pairing prompt, then rediscover services. These conditions
are distinct from AirShield failure; no DataX/L2CAP evidence can be collected
until CoreBluetooth can read the protected PSM characteristic.

To rank all saved local artifacts and see the strongest available evidence in
one pass, run:

```sh
python3 tools/live/airshield_artifact_audit.py
```

During a live pairing run, use `--latest` to force the Mac transport and Mac
AirShield sections to inspect the newest session instead of the strongest older
session:

```sh
python3 tools/live/airshield_artifact_audit.py --latest
```

The audit picks the strongest Android trace, extracted identity state, native
probe-target preflight, native probe, native framing probe, identity parity
comparison, Mac BLE transport session, and Mac AirShield session it can find,
then prints the remaining missing gates. This is a fast way to confirm whether a
run contains a usable probe target, real native framing evidence, a
CoreBluetooth transport blocker, the exact-band scan/RSSI evidence behind a
pairing reset, or only hook/session smoke-test output.

The command exits nonzero while evidence is incomplete, and `READY_FOR_PARITY_DECISION`
requires all six artifact groups to be present and fully passing: Android trace,
extracted identity state, native PrivateKey probe, native Framing probe,
identity parity, and Mac session. The native probe-target preflight and Mac BLE
transport sections are diagnostic; they help pick a usable emulator/device and
explain why the Mac has not reached L2CAP, but they do not replace successful
native PrivateKey, Framing, Android trace, identity-parity, or Mac AirShield
artifacts. For extracted identity state, a missing `identity_key_slots` summary
means the saved report came from an older extractor or an incomplete/stale state
pull; rerun the extractor on a paired/logged-in target before treating the lack
of key slots as meaningful. The identity parity section compares the extracted
preference slot,
native `PrivateKey` probe, Android trace identity events, and Mac imported
identity candidates by redacted length/fingerprint. The important Android gates
are auth delegate selection, native private-key load/serialize evidence, tx/rx
preamble challenge fingerprints, CipherBuilder challenge/seed/remote
public-key/IV input fingerprints, native `PrivateKey.derive` shared-hash
fingerprint, native state-setup input snapshots, accepted auth public-key
fingerprint, native framing-expansion input/output calls, native identity
public-key recovery, native setup fingerprints, and native pack/unpack bytes.

Run readiness self-tests without Android or the band:

```sh
python3 tools/live/airshield_readiness.py --self-test
```

This generates a temporary synthetic native-framing probe and verifies that the
readiness checker can drive the Swift comparator path end to end. It also
checks the Mac-session extractor for native-format `EnableTrust` local channel
variants.

The important Mac gates are identity import plus public-key candidates,
native-format raw64 EnableTrust candidate preparation, native-plausible
`EnableTrust` channel variants `0`/`1`/`2`, RequestEncryption tx plus decoded
DataX route validation for AirShield service `5` / typed buffer `1`, eligible
EnableTrust auth gate load/ready/sent evidence, EnableEncryption decode, Swift
KDF input fingerprints, Swift setup candidates, passive decrypt match,
EndLinkSetup ready/sent, gesture-enable ready/sent, decoded stream-control
active evidence from `source=airshield.decrypted`, decrypted DataX frames, and
decoded gesture frames. The RequestEncryption route check intentionally needs
either a decoded `datax.tx_frame` summary or raw TX hex in the session log;
without one of those, readiness fails closed instead of trusting the event
label.

Prepare an AirShield identity import from an extracted Android state report
without printing private key material:

```sh
python3 tools/android-trace/extract_airshield_state.py \
  --adb-timeout 15 \
  --require-identity-slot

python3 tools/live/prepare_airshield_identity_import.py \
  --latest \
  --require-current-schema \
```

`--require-identity-slot` writes the report but exits nonzero if no
`app-private-key`, `acdc-app-private-key`, or
`constellation-manifest-authority-key` slot is present. That catches stale or
pre-pairing pulls before they get mistaken for useful AirShield identity
evidence. `--adb-timeout` bounds each ADB call so an offline emulator or stale
USB target fails quickly with a clear message. The extractor scans every
SharedPreferences XML for AirShield/ACDC key names, then writes only matching
redacted entries, so renamed preference files are still covered without dumping
unrelated preference values. Current reports carry
`schema=codex_airshield_state_v2` plus `scan_policy.shared_prefs_xml`; the
artifact audit requires that metadata before treating extracted identity state
as current evidence. `prepare_airshield_identity_import.py` also copies that
freshness metadata into its plan and tells you to rerun extraction when the
input report is stale. Add `--require-current-schema` during normal operator
runs so stale reports fail closed before any Base64 export or Mac import step.
Add `--latest` to select the newest extracted-state report automatically.

When the input report was created with `--include-secret-material`, add
`--export-base64` to write the selected slot to a local `0600` Base64 file for
the Mac bridge import UI. Select the same slot in the Mac bridge, paste the
exported file path into `Base64 identity file path`, then press `Load File`.
The helper reports the slot, decoded length, and fingerprints only; it never
prints the Base64 value.

The readiness checker also accepts the offline native probe artifacts:

```sh
python3 tools/live/airshield_readiness.py --latest-native-probes

python3 tools/live/airshield_readiness.py \
  --native-probe reverse/identity-probes/airshield-private-key-probe-acdc-app-private-key-YYYYMMDD-HHMMSS.json \
  --native-framing-probe reverse/framing-probes/airshield-framing-probe-YYYYMMDD-HHMMSS.json
```

Use `--latest-native-probes` for normal operator checks after both native probe
artifacts have been written. The explicit path form is useful when comparing a
specific older probe pair.

The native private-key probe gates require `setRaw`, `serialize`, recovered
public-key, and accepted-auth public-key fingerprints. The synthetic framing
probe gates require native `Framing.pack` status, plaintext consumption,
native padded length, cipher-payload length, outer-frame length, size-indicator
consistency, validation prefix, cipher and outer-frame fingerprints, tx/rx
challenge fingerprints, public-key fingerprints, and `secretMaterial` so
`tools/swift/compare_airshield_framing_probe.sh` can recompute Swift candidates
from the same deterministic inputs. Readiness now requires that comparator to
run and report a full Swift/native fingerprint match for the public keys,
validation prefix, cipher payload, and outer frame.
Probe runners write redacted `probeStatus=failed` artifacts for attach/preflight
failures after inputs are parsed; the audit will show those attempts, but they
remain incomplete evidence.

Run the Swift framing-probe comparator self-test without Android:

```sh
tools/swift/compare_airshield_framing_probe.sh --self-test
```

That check proves the comparator ranks a synthetic candidate using local/remote
public-key fingerprints plus validation-prefix, cipher-payload, and outer-frame
fingerprints.

To emit the self-test probe JSON used by the readiness self-test:

```sh
tools/swift/compare_airshield_framing_probe.sh --self-test-probe-json
```

The wrapper reuses `build/tools/CompareAirShieldFramingProbe` when the Swift
sources have not changed, which keeps readiness/audit runs from recompiling the
comparator every time.

## Native-vs-Swift AirShield framing comparison

After capturing official-app `Framing.pack/unpack` events with the Android trace
tooling, compare them with a Mac bridge session log:

```sh
python3 tools/live/compare_airshield_framing.py \
  --latest-artifacts \
  --strict

python3 tools/live/compare_airshield_framing.py \
  --android-trace reverse/captures/airshield-datax-YYYYMMDD-HHMMSS.jsonl \
  --mac-session ~/Library/Logs/CodexBandBridge/sessions/session-UUID.jsonl
```

Use `--latest-artifacts --strict` for normal operator checks after the newest
trace/probe/Mac artifacts have been written. The explicit path form is for
reviewing a specific older artifact set.

The comparator scores identity fingerprints, setup fingerprints, then frame
bytes: final `Preamble.acceptAuthentication`, accepted-candidate, and recovered
public-key fingerprints, validation key, cipher key, initial counter block,
frame counter, runtime validation mode, direction, lengths, validation prefix,
cipher payload fingerprint, outer-frame fingerprint, and plaintext fingerprint
where both logs contain those fields. A strong match means the Swift candidate
is byte-aligned with native framing for that captured frame; the comparator
prefers full-window Android SHA-256 fields when present and avoids treating
truncated hex as a full-frame hash. A prefix/hash mismatch means either the
imported identity or the remaining AirShield KDF/counter/cipher candidate is
wrong.

The comparator also lists Android `CipherBuilder` challenge/seed/remote-key/IV
input fingerprints against Swift `EnableEncryption` input fingerprints, then
compares Android's derived transcript-window fingerprints against Swift
transcript-window fingerprints for each normal material candidate. It also
compares both Android `PrivateKey.derive(PublicKey)` raw shared-hash prefixes
and SHA-256 prefixes against Swift shared-material candidates, which should
select the correct shared-secret representation before final frame comparisons.
Native `d9de60` state-setup snapshots compare the exact builder transcript
windows and selected counter input against the Swift model.
Native `db17b4` expansion calls list key-material/context source, length, and
fingerprints plus the 32-byte expansion output fingerprint, then compare them
with Swift's logged expansion-context and validation/cipher-key candidates.
The Mac bridge now prepares native default-label, shared-material-context, and
explicit `0x88` context variants under each shared-material representation.

Mac candidate frames include both gated encrypted `EndLinkSetup` and
gesture-enable frames. The comparison report labels which candidate kind matched
best, so the first official `Framing.pack` event should usually compare against
`end_link_setup` before any gesture-enable frame. Candidate, ready, and sent
events now carry redacted plaintext, cipher-payload, and outer-frame
fingerprints, so a manual-send run can still be compared if only the later
ready/sent events are present in the saved session.

Run the Python comparator extraction self-test without Android:

```sh
python3 tools/live/compare_airshield_framing.py --self-test
```

## AirShield identity comparison

Before trusting the Mac-side AirShield candidates, compare the imported key
against Android's redacted identity evidence:

```sh
python3 tools/live/compare_airshield_identity.py \
  --identity-prefs reverse/extracted-state/com.facebook.stella-airshield-state-redacted-YYYYMMDD-HHMMSS.json \
  --android-trace reverse/captures/airshield-datax-YYYYMMDD-HHMMSS.jsonl \
  --mac-session ~/Library/Logs/CodexBandBridge/sessions/session-UUID.jsonl \
  --strict
```

The tool prints only lengths and SHA-256 prefixes. It compares Android
SharedPreferences private-key slots, native `PrivateKey.setRaw()` /
`serialize()` events, native `recoverPublicKey()` / accepted auth public-key
events, and the Mac bridge's imported private-key plus derived public-key
candidates. A strict pass requires both the private slot and public-key
candidate sides to match when comparable inputs are present.

Run the identity comparator self-test without Android or the band:

```sh
python3 tools/live/compare_airshield_identity.py --self-test
```

## AirShield auth-flow report

To decide which Android preamble-auth path the Mac bridge needs to mimic, run:

```sh
python3 tools/live/compare_airshield_auth_flow.py \
  reverse/captures/airshield-datax-YYYYMMDD-HHMMSS.jsonl
```

Run the auth-flow gate self-test without Android or the band:

```sh
python3 tools/live/compare_airshield_auth_flow.py --self-test
```

That check covers the eligible `PAYLOAD_AND_TX_CHALLENGE_MATCH` path plus the
fail-closed cases where either the payload fingerprint differs or only the RX
challenge matches.

The report summarizes auth delegates (`GD5`, `GCS`, `C30908GCi`), identity
service/channel use, service `36` / service `77` typed-buffer names, accepted
public-key fingerprints, and whether the trace reached `streamReady`. It keeps
payloads and key material redacted. Newer traces also include redacted
`txChallenge` and `rxChallenge` summaries from the delegate registration call;
production Identity signs the TX challenge. If present, direct
`Preamble.getTxChallenge` / `getRxChallenge` and `CipherBuilder.buildTxChallenge`
/ `buildRxChallenge` return fingerprints are shown in the same challenge section.
The report also shows redacted `CipherBuilder` setter fingerprints for the
challenge, seed, remote public key, and initialization vector that feed the
native transcript/KDF path.

Pass one or more Mac bridge sessions to compare Android production Identity
`ENABLE_TRUST` payload fingerprints against Mac's non-transmitting
EnableTrust candidates:

```sh
python3 tools/live/compare_airshield_auth_flow.py \
  reverse/captures/airshield-datax-YYYYMMDD-HHMMSS.jsonl \
  --mac-session ~/Library/Logs/CodexBandBridge/sessions/session-UUID.jsonl
```

The comparison scores payload fingerprint, payload length, and whether the Mac
candidate uses the native-confirmed raw64 raw-digest signature format. Newer
traces also score Android's redacted TX/RX preamble challenge fingerprints
against Mac candidate challenge hashes; production Identity should match the TX
challenge, not the RX challenge. The report prints
`Recommended gated EnableTrust candidate` and includes the same object as
`recommended_enable_trust_candidate` in `--json` output. `TX_CHALLENGE_MATCH_ONLY`
is comparison evidence but is not transmit-eligible; `PAYLOAD_AND_TX_CHALLENGE_MATCH`
means the same native-format raw64 candidate matched both Android TX challenge
and Android `ENABLE_TRUST` payload fingerprints, which is the planned evidence
gate before enabling manual Mac-side auth transmit for that exact identity path.
Use the recommended candidate's `candidate_id` as the durable selector; it is a
short redacted hash over non-secret candidate descriptors plus payload/frame
fingerprints, so it is more stable than a log line number.
When the Mac bridge has an imported identity and sends a probe, it stages the
corresponding `EnableTrust` frames in memory by `candidate_id` and shows only
the staged count in the UI. Each payload is framed across the native-plausible
local channel ids `0`, `1`, and `2`; the report prints `localChannel` and
`baseID` so Android evidence can choose the exact frame fingerprint. Those
frames are sent only after an eligible gate artifact names the exact staged
candidate.

To create the gate artifact required by the Mac-side manual auth button, add
`--write-auth-gate`:

```sh
python3 tools/live/compare_airshield_auth_flow.py \
  reverse/captures/airshield-datax-YYYYMMDD-HHMMSS.jsonl \
  --mac-session ~/Library/Logs/CodexBandBridge/sessions/session-UUID.jsonl \
  --write-auth-gate reverse/gates/enable-trust-gate-YYYYMMDD-HHMMSS.json
```

This command fails closed and does not write the file unless the recommendation
status is `PAYLOAD_AND_TX_CHALLENGE_MATCH`.

In the Mac bridge UI, paste that gate path into `EnableTrust gate JSON path` and
press `Load Gate`. `Send Auth` remains disabled until L2CAP is open and the
current probe has staged the exact `candidate_id` named by the gate. Pressing
`Send Auth` writes only that staged frame and records redacted tx evidence.

The shared Swift validation suite fixtures the same gate checks used by the UI:
schema, eligible status, manual-transmit flag, non-empty `candidate_id`, and
abbreviated frame-fingerprint matching. That local fixture proves the guard
logic, but a real send still requires a comparator-produced eligible gate from
matching Android evidence.
