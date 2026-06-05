# Meta Neural Band Bridge TODO

## Current Known State

- Mac helper app is locally signed with stable bundle ID `com.example.codexbandbridge`.
- Exact band is discovered as `Meta Band 000J`.
- Pairing-mode scan can also show unrelated `HwZ_...` devices. A live check on
  2026-06-04 rejected `HwZ_fb152dd2d7002b2a12` as a Cypress dev-kit style
  peripheral (`AC00`, `00060000-F8CE-11E4-ABF4-0002A5D5C51B`, `180A`) and
  timed out connecting to `HwZ_fb01403442002b1019`; neither exposed the Meta
  DataX/PSM services in that run.
- Device identity read over GATT:
  - Serial: `306GP9BH4N000J`
  - Firmware: `919024347`
  - Manufacturer: `Meta Platforms, Inc.`
- GATT service map:
  - `180F`: battery, characteristic `2A19`
  - `180A`: device info
  - `0000FEB8-0000-1000-8000-00805F9B34FB`: WIS/DataX PSM service
  - `FD5F`: characteristic `05ACBE9F-6F61-4CA9-80BF-C8BBB52991C0`
  - `0000EFF0-0000-0000-8000-34635C9B94FB`: characteristic `0000DADA-0000-0000-8000-34635C9B94FB`
- PSM characteristic value `ff00` decodes to LE L2CAP PSM `255`.
- LE L2CAP PSM `255` opens successfully from the Mac helper.
- Live run on 2026-06-05 now reaches protected GATT and L2CAP on exact
  `Meta Band 000J`. The band reports serial `306GP9BH4N000J`, software
  revision `919024347`, protected PSM bytes `ff00`, and opens PSM `255`.
- Previous live blocker: the CoreBluetooth L2CAP output stream opened but never
  reports write space, so the guarded Mac helper records `l2cap.tx_failed`
  instead of blocking the UI. A file-triggered Direct Write diagnostic bypassed
  the write-space guard, but the background stream write timed out and returned
  `bytes_written=0`. One experimental `DADA` GATT DataX fallback sent the same
  AirShield `RequestEncryption` frame, but no response was observed.
- Current live blocker: latest session
  `561BBB6C-52E5-4B2A-A587-811029E7D1BA` saw exact `Meta Band 000J`
  advertisement once (`rssi=-43`) and then reached
  `PAIRING_RESET_RECOMMENDED` after three CoreBluetooth connect timeouts before
  service discovery. Next live action is to forget/reset `Meta Band 000J` in
  macOS Bluetooth settings, put the band back in pairing mode, and rescan with
  the already running bridge.
- Current identity-artifact blocker: latest extracted Android state
  `reverse/extracted-state/com.facebook.stella-airshield-state-redacted-20260604-184713.json`
  is an older/stale export with no `identity_key_slots` summary and only
  pre-pairing asset prefs, so it cannot supply or prove the app-private key
  path. Next Android-side action is to rerun `extract_airshield_state.py` on a
  paired/logged-in Stella target with `--require-identity-slot`, using
  `--include-secret-material` only on a trusted local machine when we need to
  export the selected Base64 identity slot.
- No gesture/event frames appear until the app performs the higher-level DataX/AirShield handshake and stream-control enable flow.
- Glasses firmware lookup path is now identified for serial `2Y0YBYPJ0H0015`, version `125.0.0.190.412`; see `tools/ota/fetch_stella_ota.py`.

## Priority 1: Make The Bluetooth Capture Stable

- [x] Keep the helper auto-selecting `Meta Band 000J`, but stop auto-connecting to generic `HwZ_...` devices.
- [x] Persist one structured connection session per run:
  - [x] session id in JSONL log entries
  - [x] structured session JSONL and summary JSON paths
  - [x] band name
  - [x] serial
  - [x] firmware
  - [x] GATT services/characteristics/properties
  - [x] PSM values
  - [x] L2CAP open/close events
  - [x] L2CAP rx frames
  - [x] L2CAP tx frames once AirShield/DataX transmit is enabled
  - [x] deterministic L2CAP helper coverage for PSM parsing/range checks and stream-status labels
- [x] Add a UI toggle for:
  - [x] auto-connect exact band
  - [x] guarded one-shot connect/sweep for likely pairing-mode `HwZ_...` devices, default off
  - [x] auto-open detected L2CAP PSM
  - [x] dump raw frames
  - [x] attempt DataX handshake
  - [x] manual AirShield RequestEncryption probe trigger after L2CAP is open
- [x] Add reconnect handling when the band drops after handshake experiments.
  - [x] bounded retry/backoff for the exact target band only
  - [x] connection timeout for stuck CoreBluetooth connect attempts
  - [x] suppress reconnect after manual disconnect
  - [x] close stale L2CAP streams and reset frame state on disconnect/stream end
  - [x] record reconnect scheduling/attempts in the structured session log
  - [x] stop futile reconnect retries on stale macOS pairing state and surface
        `STALE_PAIRING` in live status output
  - [x] stop after three consecutive CoreBluetooth connect timeouts and surface
        `PAIRING_RESET_RECOMMENDED` in live status output
  - [x] surface protected GATT authentication/encryption failures as
        `PAIRING_REQUIRED_FOR_PROTECTED_GATT` so pairing/bonding blockers are
        separate from AirShield/L2CAP blockers

## Priority 2: Reverse The DataX Framing

- [x] Inspect DataX classes in the APK:
  - [x] `C32443HOd`
  - [x] `C36087Jjj`
  - [x] `C36243JnQ`
  - [x] `com.facebook.wearable.datax.*`
  - [x] any references to `DataX-Protocol-Handler`
- [x] Determine the packet header format used on the L2CAP stream:
  - [x] native encoder/parser locations
  - [x] 4-byte base header plus optional extension words
  - [x] 14-bit payload length / fragment cap
  - [x] WIS Java framing confirms extension type `1` = service alias and type `2` = `(appId << 8) | messageType`
  - [x] base DataX descriptor bit layout: bits `0...13` body length, bit `15` extension-present, bit `14` masked/reserved by native parser
  - [x] base DataX extension-word layout: byte `0` continuation/type, byte `1` auxiliary, bytes `2...3` big-endian value
  - [x] focused native DataX frame evidence report at `reverse/native-datax-report.md`
  - [x] make `tools/native/analyze_datax_native.py` fail closed on missing native frame-layout anchors and run the Swift DataX codec fixture, so lower-frame static parity is enforced in the consolidated next-gates sweep.
  - [x] exact lower-frame semantics of reserved descriptor bit `14`: static native pass found no encoder emission and no parser control-flag consumer; Swift preserves/logs it only as reserved evidence unless future higher-layer traces prove otherwise
  - [x] encrypted AirShield stream frame/checksum bytes: generated native checks show encrypted records are not nested base DataX frames; they are `validation_prefix[0...7] || size_indicator[8] || cipher_payload[9...]`, with no separate checksum/footer in the mapped pack/unpack flow
  - [x] AirShield encrypted frame size math from native `Framing.outerFrameSizeNative` / `cipherPayloadSizeNative`
- [ ] Find the first bytes the Android app writes after `L2CAP connected using DataX PSM`.
  - [x] Android Frida trace tooling prepared and hook-installed against `com.facebook.stella`.
  - [x] Capture analyzer added for AirShield/DataX JSONL traces.
  - [x] Static first-write reconstruction at `reverse/airshield-first-write-static.md`: official Java builds `RequestEncryption { publicKey, challenge, Secp256r1, supportedParameters=1 }` and sends typed buffer `REQUEST_ENCRYPTION = 1`; Mac Swift fixture wraps the same payload as AirShield service `5`, typed buffer `1`.
  - [x] Native `LocalChannel.open/send` parity note at `reverse/native-datax-localchannel-send.md`: AirShield service `5`, auth services `36`/`77`, and local WIS plaintext use base id `localChannelID ^ 0x8000`, extension type `1` for service id, and extension type `2` for typed-buffer id.
  - [x] Deterministic non-secret first-write vector at `tools/swift/emit_airshield_first_write_vector.sh` for fixed RequestEncryption DataX route/fingerprint comparison.
  - [x] Make `tools/static/analyze_airshield_first_write.py` run the Swift vector emitter and native LocalChannel evidence checks, so `reverse/airshield-first-write-static.md` is regenerated from enforced parity checks rather than manual notes.
  - [ ] Capture a real band connection with `airshield.onSend` events, if using a physical Android device with Bluetooth access.
  - [x] Continue static native analysis because the local emulator has no Bluetooth passthrough: KDF/static coverage audit at `reverse/airshield-kdf-static-coverage.md`
- [ ] Implement a small DataX frame encoder/decoder in Swift.
  - [x] passive frame decoder scaffold
  - [x] static frame encoder scaffold for recovered header/extension layout
  - [x] local round-trip verification for recovered WIS frame layout
  - [x] native-compatible reserved descriptor bit `14` fixture
  - [x] AirShield service-5 RequestEncryption DataX frame fixture
  - [ ] verified frame encoder against live/official transmitted bytes
- [x] Log decoded frame headers separately from raw hex.
- [x] Add redacted payload SHA-256 fingerprints to decoded DataX frame/source logs for Android/Mac correlation without dumping payload bytes.
- [x] Add redacted generic protobuf summaries for opaque WIS authentication/encryption DataX payloads so live decrypted traffic can be mapped without dumping secrets.
- [x] Add Mac-side DataX classification for AirShield preamble-auth services `36`/`77` and typed-buffer names (`IDENTITY_REQUEST`, `IDENTITY_RESPONSE`, `REGISTER_KEY`, `KEY_ACCEPTED`, ownership/provisioning variants).

## Priority 3: AirShield/Secure Link Handshake

- [x] Inspect AirShield setup classes:
  - [x] `LinkSecurerForStream`
  - [x] `StreamSecurerImpl`
  - [x] `CipherBuilder`
  - [x] `PrivateKey`
  - [x] `PublicKey`
  - [x] `Preamble`
  - [x] `Hint`
  - [x] `HKDF`
  - [x] `HMac`
  - [x] `SHA256`
- [x] Identify whether the band requires:
  - [x] ephemeral per-stream key exchange for AirShield encryption/framing
  - [x] paired-device key material: static scan shows durable Identity/ACDC slots, not Android bond-derived stream KDF input
  - [x] app/device-bound identity material for preamble authentication
  - [x] bond-derived secrets: no static evidence in AirShield/link-securer/auth-delegate paths; OS bonding remains a transport/discovery concern
  - [x] recoverable app-private AirShield key material in app SharedPreferences
  - [x] redacted Android extractor for AirShield/ACDC SharedPreferences state
  - [x] key-source report at `reverse/airshield-key-source-report.md`
  - [x] bond-vs-identity static report at `reverse/airshield-bond-requirements.md`
  - [x] Mac keychain-backed import scaffold for native `PrivateKey.serialize()` Base64 slots (`acdc-app-private-key` / `app-private-key`)
  - [x] Mac bridge can import an exported Base64 identity file path directly, so local helper output does not need to be opened or pasted as raw key text.
  - [x] Mac identity import parser derives redacted candidate public-key fingerprints from full/first32/last32 native-looking blobs for Android trace comparison.
  - [x] Mac identity logging now normalizes the Android-style 64-byte `Preamble.acceptAuthentication` public-key handoff and records redacted accepted-auth fingerprints for direct trace comparison.
  - [x] SharedPreferences slot extractor at `tools/android-trace/extract_airshield_identity_prefs.py`
  - [x] Extracted-state import prep helper at `tools/live/prepare_airshield_identity_import.py` to choose a slot and optionally export a local `0600` Base64 file without printing secrets.
  - [x] Redacted identity evidence comparator at `tools/live/compare_airshield_identity.py` for Android preference slots, Android native identity trace events, and Mac imported public-key candidates.
  - [x] Add `compare_airshield_identity.py --latest-artifacts --strict` so newest saved identity state, Android trace, native PrivateKey probe, and Mac session can be compared without timestamped paths while still failing closed on missing evidence.
  - [x] Guard `tools/android-trace/extract_airshield_state.py` with `--require-identity-slot` and a self-test, so stale/pre-pairing exports fail visibly when identity material is expected.
  - [x] Bound `extract_airshield_state.py` ADB calls with `--adb-timeout` so offline/flaky emulators fail quickly instead of hanging identity extraction.
  - [x] Widen `extract_airshield_state.py` SharedPreferences XML scanning so renamed preference files can still surface AirShield identity slots while only AirShield/ACDC-matching entries are written.
  - [x] Add `codex_airshield_state_v2` schema and scan-policy metadata to extracted-state reports, and require/report that metadata in the saved-artifact audit.
  - [x] Carry extracted-state schema/scan-policy freshness into `prepare_airshield_identity_import.py` plans, with stale-report rerun guidance before Mac import.
  - [x] Add `prepare_airshield_identity_import.py --require-current-schema` so normal import prep fails closed on stale extracted-state reports.
  - [x] Add `prepare_airshield_identity_import.py --latest` so operator import prep can select the newest extracted-state report without copying timestamped filenames.
- [x] Locate native AirShield implementation, if present:
  - [x] unpacked `.so` files
  - [x] merged JNI symbols
  - [x] string references around `airshield_jni`
  - [x] generated scoped native evidence report at `reverse/native-airshield-report.md`
  - [x] decoded merged JNI registration anchors at `reverse/jni-registration-report.md`
  - [x] decoded AirShield registration string xrefs at `reverse/airshield-registration-xrefs.md`
- [ ] Reconstruct handshake message order:
  - [x] native stream securer starts and emits outbound bytes through `onSend`
  - [x] `onPreambleReady` exposes temporary DataX connection and tx/rx challenges
  - [x] Java authentication delegate returns a padded/truncated 64-byte public key
  - [x] `Preamble.acceptAuthentication` and `EndLinkSetupMessage.setAsMain`
  - [x] `onStreamReady` returns secure stream plus rollover bytes
  - [x] AirShield `CipherBuilder` uses ephemeral private key, challenge, seed, IV, and remote public key to build TX/RX challenges/framing
  - [x] preamble DataX link-setup service `5` and typed messages `RequestEncryption`, `EnableEncryption`, and `EndLinkSetup`
  - [x] native strings confirm Request/Enable validation, relay-framing branches, and `Preamble succeeded` milestone
  - [x] Java preamble authentication callback path: `onPreambleReady` registers identity/ACDC services, delegate returns app public key, `G44` pads/truncates to 64 bytes, then calls `Preamble.acceptAuthentication(...)`
  - [x] map production Identity service `36` and PrototypeIdentity service `77` typed-buffer IDs enough for Android trace analyzer naming (`IDENTITY_REQUEST`, `IDENTITY_RESPONSE`, `REGISTER_KEY`, `KEY_ACCEPTED`, ownership/provisioning variants)
  - [x] transcript hash / KDF details: static structure audited at `reverse/airshield-kdf-static-coverage.md`; native-output parity remains tracked below
  - [x] encrypted outer-frame byte ranges: bytes `0...7` validation prefix, byte `8` cipher-size indicator, bytes `9...` encrypted payload
  - [x] encrypted stream validation-prefix state offsets: Framing object `0x80` prefix buffer and `0xa4` per-frame counter
  - [x] SHA/HMAC helper identities behind the validation-prefix path: SHA-256 update/final/compress and HMAC-SHA256-like helper
  - [x] identify `0x64bf68` as cipher/block-transform dispatch rather than the MAC itself
  - [x] identify derivation anchors: challenge/framing digest helper `0xd9bfd0`, framing key derivation helper `0xdb17b4`, and static 9-byte `AirShield` label
  - [x] map constructor-to-Framing field handoff: `0xdb12ec` copies validation mode to `0xa0`, frame counter to `0xa4`, and cipher context to `0x30`
  - [x] map cipher context dispatch enough to identify selected descriptor `0x00072490` and descriptor-driven object layout
  - [x] correct `CipherBuilder` JNI registration table decoding and map challenge/seed/IV native builder offsets
  - [x] identify selected transform descriptor value: mode 2, 16-byte block, 256-bit material, 16-byte transform-state setter
  - [x] identify selected transform as AES-256-CTR from descriptor, selected family setup, AES key-schedule/table helpers, and CTR-like payload helper
  - [x] map selected transform counter increment: current block first, then big-endian 128-bit increment from bytes `12...15` toward byte `0`
  - [x] direct family-helper-to-cipher proof
  - [x] focused KDF/framing report at `reverse/airshield-kdf-framing-report.md`
  - [x] confirm static AirShield label length is 9 bytes without the trailing NUL
  - [x] implement guarded Swift primitive for native `0xdb17b4` default-label expansion: 32-byte key material, static 9-byte `AirShield` label, counter byte `0x01`, 32-byte HMAC-SHA256 output
  - [x] map native framing direction flags: `buildEncryptionFramingNative` enters shared setup with flag `1`; `buildDecryptionFramingNative` enters with flag `0`
  - [x] add generated wrapper/adapter instruction checks proving the Java `(base, hkdf)` arguments are staged separately and the encryption/decryption wrappers call shared setup with direction flags `1`/`0`
  - [x] preserve/test Framing config handoff offsets: config `0x28/0x78/0x7a/0x7c` maps to runtime `0x30/0xa0/0xa4`, with validation-prefix buffer at runtime `0x80`
  - [x] map validation-prefix frame inputs from pack/unpack: optional 4-byte mode word, 4-byte frame counter, then outer-frame byte `8` plus encrypted payload bytes `9...`
  - [x] map runtime validation mode packing: `uint16(config+0x78) | (uint8(config+0x7a) << 24)`; include the mode word in prefix state when this runtime word is nonzero
  - [x] map validation HMAC/SHA state ownership: `db12ec/db1b38` initializes the Framing runtime context from a 32-byte validation key at config offset `0x00`, inline-key tag at config `0x20`, runtime context pointer at `0x00`, inline key at runtime `0x08`, and runtime key tag at `0x28`
  - [x] map `d9de60` Framing-config staging: 64-byte work area at stack `0x190`; first 32 bytes copied as the validation key into config `0x00`; second 32 bytes at stack `0x1b0` staged as cipher key material for `db18d4` on the normal encrypted path; primary config at stack `0x90`, relay config at stack `0x110`
  - [x] map `db17b4` expansion scratch staging inside `d9de60`: temporary expansion object at stack `0x40` with inline tag `0x60`, key-material/writeback half at stack `0x1b0`; final expansion output object at stack `0x1d0` with inline tag `0x1f0`, key-material/writeback half at stack `0x190`; derivation context buffer at stack `0x200`; explicit context selector uses rodata `0x25d60b` length `0x88`
  - [x] add generated instruction checks for the normal KDF schedule: transcript digest to `sp+0x1b0`, optional default-label `db17b4` expansion in place, then selected material copied to validation-key half `sp+0x190`
  - [x] add generated byte-level check for explicit expansion context `0x25d60b`: `AirShield`, zero padding, trailer `20 00 00 00 00 01 00 00`, and HMAC fixture parity with Swift
  - [x] map selected transform setup window: setter writes raw 32-byte seed at builder `0x220...0x23f` and raw 16-byte IV at builder `0x240...0x24f`; selected setup consumes `seed[24..<32] + iv[0..<8]` from builder window `0x238...0x247`
  - [x] map selected transform IV setter handoff: `0xdb18d4` stores loaded words from builder `0x238`/`0x240` into cipher-context wrapper `0x2c`/`0x34`, then calls `0x64cfe0` with `x1 = wrapper + 0x2c` and length `0x10`
  - [x] add generated instruction checks for selected transform handoff: direct 16-byte setter length recording, mode-2 helper install, and current-counter-before-increment CTR ordering.
  - [x] correct remote-key/seed builder map: remote public-key state at `0x120`/`0x1e0` with active flag byte `0x218`; raw seed starts at `0x220`; the digest helper still consumes a 32-byte window beginning at `0x218`
  - [x] map challenge digest windows and call-site flags: digest challenge window `0x108...0x117` overlaps only first eight raw challenge bytes; digest material window `0x218...0x237` overlaps only first 24 raw seed bytes; TX challenge flag `1`, RX challenge flag `0`, standalone challenge builders clear caller context args
  - [x] map native challenge fold size: helper folds 64-byte native `Hash`/public-key-shaped values made of two 32-byte halves; helper `0xdb2148` is tied to `PrivateKey.recoverPublicKey()` and builds the local public-key-shaped intermediate from builder private-key state
  - [x] map challenge digest branch ordering: direction flag `1` folds builder source `0x118` into challenge-window digest first, then recovered-public-key intermediate into material-window digest; direction flag `0` folds recovered-public-key intermediate into challenge-window digest first, then builder source `0x118` into material-window digest when `0x210` is set
  - [x] map branch evidence for builder byte `0x210`: remote-public-key setup clears it, while challenge/framing derivation branches on it to decide whether the builder source at `0x118` participates in the fold
  - [x] tie Java-facing `PrivateKey.deriveNative(long)` to helper `0xdb1f1c` and `PrivateKey.recoverPublicKey()` to helper `0xdb2148`
  - [x] decode AirShield security JNI candidate rows at `reverse/airshield-security-jni-candidates.md`
  - [x] confirm Java-facing `HKDF.calculateNative(long,long)` uses the same default-label `0xdb17b4` expansion helper with cleared label/context args
  - [x] exact encrypted stream validation-prefix input ordering: optional nonzero runtime mode word little-endian, frame counter little-endian, then outer-frame byte `8` plus encrypted payload bytes `9...`
  - [x] implement guarded Swift normal-path work-area material candidates: raw P-256 shared material plus transcript windows plus optional `db17b4` expansion, with secondary `SHA256(raw)` and reversed-raw candidates for native trace comparison; log short validation/cipher key fingerprints only
  - [x] log the modeled native 64-byte setup work area fingerprint plus validation/cipher half fingerprints and source offsets (`0x190` / `0x1b0`) for each Swift normal material candidate.
  - [x] add Swift fixture coverage for the normal-path no-HKDF/direct transcript-digest branch, including candidate source ordering, equal validation/cipher halves, and staged EndLinkSetup/gesture-enable counters.
  - [x] distinguish shared-material raw prefixes from SHA-256 fingerprints in Mac session logs and native-vs-Swift framing comparisons
  - [x] verify normal-path transcript prefix bytes from native builder initialization and setters: challenge window is eight zero bytes plus `challenge[0..<8]`; material window is `01`, seven zero bytes, then `seed[0..<24]`
  - [x] implement guarded Swift offline validation-prefix candidate: first 8 bytes of HMAC-SHA256 over the mapped mode/counter/frame input, keyed by a 32-byte validation-key candidate
  - [x] map encrypted stream padding bytes: pad tail length `n` uses repeated byte `0xc0 + n`, with no extra block for already aligned plaintext
  - [x] implement guarded Swift offline encrypted-frame candidate: native padding, explicit-counter AES-256-CTR loop, and validation-prefix candidate
  - [x] log non-transmitting gesture-enable encrypted-frame candidate summaries from live `EnableEncryption` inputs: plaintext/padded/cipher/outer lengths, sequenced frame counter, validation prefix, and short cipher/outer fingerprints
  - [x] add passive receive-side encrypted-frame candidate validation/decrypt: verify validation prefix, AES-CTR decrypt, remove native padding, and route recovered plaintext into a separate DataX decoder
  - [x] add local fixture proving an AirShield encrypted outer frame can decrypt into a DataX gesture frame and then normalize through the gesture parser
  - [x] buffer passive AirShield encrypted outer frames across L2CAP reads and handle coalesced encrypted frames before decrypting candidates
  - [x] add bounded passive receive counter resync: try current counter through current+8, accept only on validation-prefix match, log matched offset
  - [x] add manual encrypted gesture-enable transmit gate: button remains disabled until passive receive-side candidate decrypt validates, then sends the matching in-memory candidate frame only on user action
  - [x] expose live AirShield validation status in the Mac UI and session summary: match/miss counts, last matched material source, counter offset, lengths, and gesture-enable tx readiness
  - [x] add live summary reader at `tools/live/airshield_status.py` to watch AirShield match/miss and gesture-enable readiness during pairing runs
  - [x] expose L2CAP Direct Write diagnostic counts and last-event details in session summaries and `tools/live/airshield_status.py`
  - [x] add Direct Write and ordinary L2CAP failure frame fingerprints plus last-failure details to live status output, so manual bypass attempts are distinguishable from guarded retry failures.
  - [x] track active-vs-previously-opened L2CAP state plus last close reason in session summaries and live status output.
  - [x] surface `L2CAP_CLOSED` as a distinct live status state after direct-write timeouts or stream errors, instead of continuing to say the bridge is waiting for AirShield.
  - [x] add a local Direct Write trigger file plus helper script so the L2CAP bypass diagnostic can be requested without UI automation permissions.
  - [x] add a local Rescan trigger file plus helper script so the next post-pairing-reset scan can be requested without relaunching or UI automation.
  - [x] preserve Direct Write diagnostic labels and stream timeout errors in live status output.
  - [x] expose GATT DataX fallback TX/failure counts and last-event details in session summaries and `tools/live/airshield_status.py`
  - [x] require native-format `EnableTrust` local-channel variant coverage in `tools/live/airshield_readiness.py`
  - [x] require first-write `RequestEncryption` L2CAP TX route validation in `tools/live/airshield_readiness.py`: decoded DataX AirShield service `5`, typed buffer `1`, 64-byte public key, 16-byte challenge, Secp256r1, and HKDF supported-parameter bit when raw TX hex is available.
  - [x] record redacted `datax.tx_frame` summaries for full L2CAP DataX writes, so first-write route validation can pass without storing raw TX bytes.
  - [x] persist `EnableEncryption` input readiness in session summaries and surface candidate source/derivation/counter fingerprints in live status output.
  - [x] persist AirShield identity loaded/imported, RequestEncryption probe, and EnableTrust candidate-staging snapshots in session summaries and live status output.
  - [x] add deterministic `next_action` guidance to live AirShield status output for the current gated handshake step.
  - [x] add self-test coverage for the live AirShield status state/`next_action` ladder.
  - [x] surface active scanning as `SCANNING_FOR_BAND` in live status output so pre-connect runs are not mislabeled as AirShield waits.
  - [x] accept explicit `--latest` on live status/readiness/audit helpers for consistent operator commands.
  - [x] add `tools/live/airshield_readiness.py --latest-native-probes` to inspect newest saved native PrivateKey and Framing probe artifacts without copying timestamped paths.
  - [x] add consolidated operator gate sweep at `tools/live/airshield_next_gates.py` to run static DataX framing parity, static first-write parity, static WIS gesture-stream parity, latest live transport, saved-artifact audit, current identity import prep, native-probe readiness, identity parity, and framing parity checks in one fail-closed report.
  - [x] add a live status notifier wrapper so pairing reset/manual-send states can trigger a macOS notification during validation runs.
  - [x] distinguish `L2CAP_TX_BLOCKED_GATT_FALLBACK_SENT` from a true AirShield wait state, so live status does not imply handshake progress when no L2CAP bytes were written.
  - [x] extend live summary/status with WIS stream-active and decoded-gesture counters plus last event snapshots.
  - [x] add evidence readiness checker at `tools/live/airshield_readiness.py` to gate native/Mac logs before AirShield parity decisions
  - [x] require real L2CAP `RequestEncryption` TX evidence in readiness; GATT fallback no longer counts as handshake progress.
  - [x] add saved-artifact audit at `tools/live/airshield_artifact_audit.py` to rank Android traces, extracted identity state, native probes, native framing probes, and Mac sessions by available evidence before parity decisions.
  - [x] surface Mac BLE transport state in the saved-artifact audit as diagnostic evidence, separate from AirShield parity gates.
  - [x] include scan/exact-band advertisement counts, last exact RSSI, and active scan state in the saved-artifact audit's Mac BLE transport evidence.
  - [x] make `tools/live/airshield_artifact_audit.py --latest` inspect the newest Mac transport/session instead of ranking an older best-ever L2CAP session.
  - [x] enrich stale Mac transport summaries from raw session JSONL in the saved-artifact audit, and treat zero-byte L2CAP writes as blocked rather than sent handshake evidence.
  - [x] distinguish stale/old extracted-state exports with no `identity_key_slots` summary from current exports that actually scanned identity slots.
  - [x] add saved-artifact identity parity checks requiring extracted preference slot, native `PrivateKey` probe, Android trace identity events, and Mac imported identity candidates to agree by redacted length/fingerprint before the audit reports ready.
  - [x] make saved-artifact audit fail closed unless all required artifact groups are present and fully passing.
  - [x] update readiness gates for auth delegate/public-key recovery evidence plus staged Mac EndLinkSetup ready/sent before gesture-enable ready/sent
  - [x] update readiness gates for Android private-key load/serialize evidence and Mac identity import/public-key candidate evidence
  - [x] update session summary, live status, and readiness gates for comparator-backed EnableTrust auth gate loaded/ready/sent evidence
  - [x] update session summary, live status, and readiness gates for distinct encrypted EndLinkSetup and gesture-enable ready/sent evidence
  - [x] update readiness gates for native PrivateKey and synthetic Framing probe artifacts
  - [ ] encrypted stream 64-byte work-area derivation and native-confirmed final frame construction
    - [x] Add emulator-native synthetic `CipherBuilder` / `Framing.pack(...)` probe tooling at `tools/android-trace/probe_airshield_framing.py` plus comparator support via `--native-framing-probe` and `tools/swift/compare_airshield_framing_probe.sh`.
    - [x] Add probe-runner Frida Java-bridge preflight and emulator status note at `reverse/airshield-native-probe-emulator-status.md` after API 36.1 exposed no Frida Java bridge and API 34 stayed ADB-offline, including a solo API 34 retry on default port.
    - [x] Tighten the Swift synthetic framing-probe comparator with public-key fingerprint scoring and a local self-test.
    - [x] Require the readiness checker to run the Swift synthetic framing comparator and pass only on a full public-key/frame fingerprint match; add synthetic self-test coverage.
    - [x] Cache the compiled Swift framing-probe comparator so readiness/audit self-tests do not recompile it on every run.
    - [x] Extend native Framing probe artifacts and readiness gates with exact frame-shape evidence: plaintext consumed, native padded length, cipher payload length, outer frame length, and size indicator consistency.
  - [x] Retry API 36.1 rooted emulator framing probe and harden native-probe ADB helpers with timeouts; Java bridge remains unavailable on that image.
  - [x] Write redacted failed native-probe artifacts with `probeStatus=failed` / `native.errors` so audit output distinguishes blocked attempts from no attempts.
  - [x] Add local `--self-test` coverage to native PrivateKey and Framing probe runners for input validation, output paths, and failed-artifact shape without ADB/Frida.
  - [x] Add native-probe target preflight at `tools/android-trace/check_native_probe_target.py` for ADB/root/package/frida-server/Frida-Java readiness before full probe runs.
  - [x] Surface saved native-probe target preflight reports in `tools/live/airshield_artifact_audit.py` without treating them as native parity proof.
  - [x] Retry current native-probe target preflight on 2026-06-05; no ADB target reached `device` state, recorded at `reverse/native-probe-targets/airshield-native-probe-target-current.json`.
  - [ ] Run the synthetic framing probe on a rooted emulator and compare native outer-frame fingerprints against Swift's offline candidate.
  - [ ] verify normal-path candidate against native output: raw P-256 shared-secret equivalence and final validation/cipher key fingerprints
  - [ ] verify offline validation-prefix candidate against native `Framing.packNative` output
  - [ ] verify offline encrypted-frame candidate against native `Framing.packNative` output
  - [x] final confirmation that copied setup input `seed[24..<32] + iv[0..<8]` is the first CTR block: setter direct-copy path writes to transform state `+0x38`, generic mode-2 dispatch passes state `+0x38` as the counter pointer, and helper `0xdb2f54` transforms before incrementing that same block
- [ ] Implement handshake tracing first, then encryption.
  - [x] Frida hooks for AirShield `initialize`, `start`, `onSend`, `preambleReady`, `acceptAuthentication`, and `streamReady`.
  - [x] Frida hooks for DataX `handleWrite`, typed-buffer creation, and channel sends.
  - [x] Native `RegisterNatives` hook for AirShield JNI method pointers and selected method calls.
  - [x] Static `libstartup.so` offset hooks for recovered `CipherBuilder`/`Framing` JNI methods.
  - [x] Static helper hooks for AirShield pack/unpack validation-prefix and cipher-transform helpers.
  - [x] Java-wrapper hooks and analyzer summary for native `Framing.pack/unpack` byte comparison: plaintext, outer frame, validation prefix, indicator, and short fingerprints.
  - [x] Android `Framing.pack/unpack` trace windows include capture-completeness flags and full-window SHA-256 prefixes; the analyzer/comparator prefer those over truncated raw-hex hashes.
  - [x] Redacted native setup fingerprints from `db12ec` and `db18d4`: validation key, cipher key, frame counter, runtime validation mode, and initial counter block.
  - [x] Mac link-setup session logs preserve recovered optional RequestEncryption/EnableEncryption fields, including key-hint fingerprints, quirks, phased-link support, supported services, and link-switch version for Android trace comparison.
  - [x] Redacted Java auth-delegate tracing for preamble authentication: normal identity (`GD5`), ACDC/Constellation (`GCS`), identity-plus-prototype fallback (`C30908GCi`), `G44` public-key handoff fingerprint, and retry/result callbacks.
  - [x] Redacted final `Preamble.acceptAuthentication` public-key fingerprint matching is included in identity comparison/readiness, and EndLinkSetup user-data tracing avoids raw byte logging.
  - [x] Android trace analyzer names preamble-auth service typed buffers for production Identity service `36` and PrototypeIdentity service `77`, including channel-to-service inference for later send events.
  - [x] Redacted auth-flow report at `tools/live/compare_airshield_auth_flow.py` summarizes Android delegate path, identity service/channel use, service `36` / `77` typed-buffer names, accepted public-key fingerprints, and `streamReady` completion.
  - [x] Mac bridge decodes redacted AirShield preamble-auth payloads for production Identity (`EnableTrust`, `EnableTrustEC`, `IdentityRequest`, `IdentityResponse`) and PrototypeIdentity (`EnableTrust`, `RegisterKey`, `KeyAccepted`) into structured session logs.
  - [x] Redacted native identity tracing for `PrivateKey.setRaw`, `PrivateKey.serialize`, `PrivateKey.recoverPublicKey`, and public-key raw/serialize fingerprints.
  - [x] Redacted identity comparison tool at `tools/live/compare_airshield_identity.py` with strict private-slot and accepted/recovered public-key matching gates.
  - [x] Static identity-auth report at `reverse/airshield-identity-auth-static.md` maps production service `36` owned-device `ENABLE_TRUST`: identifier is `Hash(app_private_key_bytes)`, signature is native raw64 over preamble TX challenge, and peer verification uses preamble RX challenge.
  - [x] Android auth-delegate trace now records redacted `txChallenge` / `rxChallenge` summaries from `BZa(...)`, and readiness requires those fingerprints for parity decisions.
  - [x] Android AirShield trace now records redacted `Preamble.getTxChallenge` / `getRxChallenge` plus `CipherBuilder.buildTxChallenge` / `buildRxChallenge` return fingerprints, so native challenge parity can be checked directly without raw challenge bytes.
  - [x] Android AirShield trace records redacted `CipherBuilder` challenge, seed, remote-public-key, and IV setter fingerprints; readiness requires them so Swift KDF transcript inputs can be compared directly.
  - [x] Android AirShield trace computes redacted native transcript challenge/material window fingerprints from `CipherBuilder` setters, matching the Swift KDF model's `00*8 + challenge[0..<8]` and `01 + 00*7 + seed[0..<24]` windows.
  - [x] Android AirShield trace records redacted `PrivateKey.derive(PublicKey)` shared-hash prefixes and SHA-256 fingerprints so Swift shared-material candidates can be selected by native evidence.
  - [x] Android native setup hook records redacted `d9de60` builder-window snapshots: transcript challenge/material windows, selected counter input, raw challenge/seed/IV fingerprints, and direction flag.
  - [x] Android native hook records redacted `db17b4` framing-expansion inputs and outputs: 32-byte key material fingerprint, context source/length/fingerprint, default-vs-explicit context classification, output fingerprint, and inline tag/status word.
  - [x] Mac bridge logs redacted EnableEncryption KDF input fingerprints plus Swift transcript challenge/material/digest-input fingerprints for each normal material candidate; framing comparator reports them beside Android `CipherBuilder` inputs.
  - [x] Mac bridge now prepares guarded normal-material variants for native `db17b4` default-label, shared-material context, and explicit `0x88` context under each shared-secret representation; default-label candidates are tried first for native parity, and logs include redacted expansion context source/length/fingerprint.
  - [x] Native-vs-Swift framing comparator at `tools/live/compare_airshield_framing.py` for Android trace `Framing.pack/unpack`, identity public-key fingerprints including final `Preamble.acceptAuthentication`, and setup events versus Mac AirShield candidate session logs, including setup fingerprints, frame counter, runtime validation mode, EndLinkSetup candidates, and gesture-enable candidates.
  - [x] Comparator output includes Swift key-derivation mode/context details so native `db17b4` output can be distinguished from direct transcript-digest candidates during parity review.
  - [x] Add `compare_airshield_framing.py --latest-artifacts --strict` so newest Android trace, native Framing probe, and Mac session can be compared without timestamped paths while failing closed on missing frame evidence.
  - [x] Mac encrypted EndLinkSetup/gesture-enable candidate, ready, and sent logs now include redacted plaintext fingerprints alongside plaintext/cipher/outer lengths and cipher/outer fingerprints, so native-vs-Swift framing comparisons can score sent manual frames without raw plaintext.
  - [x] Add `tools/live/compare_airshield_framing.py --self-test` coverage for extracting redacted plaintext/cipher/outer fingerprints from Mac ready/sent events.
  - [x] Recovered `CipherBuilder`/`Framing` JNI method address report at `reverse/airshield-jni-method-addresses.md`.
  - [x] Swift receive-only AirShield encrypted-frame size/metadata helpers and fixtures.
  - [x] Swift constants and minimal protobuf wire encoders/decoders for AirShield link-setup messages.
  - [x] Trace analyzer redacts and decodes AirShield `RequestEncryption`, `EnableEncryption`, and `EndLinkSetup` typed buffers.
  - [x] Mac bridge can import and persist the selected Android AirShield app identity slot, log only key length/fingerprint, and derive a public-key fingerprint when the raw blob is a 32-byte P-256 scalar.
  - [x] Mac bridge prepares redacted, non-transmitting production Identity `EnableTrust` candidate summaries from parseable imported P-256 scalar windows and explicit challenge-hash candidates, covering imported-blob/scalar identifiers plus DER comparison output and native-format raw64 ECDSA signature summaries.
  - [x] Mac `EnableTrust` candidate summaries now include a stable redacted `candidate_id`, derived from non-secret candidate descriptors and payload/frame fingerprints, so comparator recommendations can select one exact candidate without relying on log line numbers.
  - [x] Mac bridge stages non-transmitting `EnableTrust` frames in memory by `candidate_id` and exposes only the staged count in UI/logs; no auth transmit path is enabled yet.
  - [x] Static native report at `reverse/airshield-security-formats.md` confirms Java-facing `Hash.toByteArray()` is 32 bytes and `Signature.toByteArray()` is raw 64 bytes for production Identity `EnableTrust`.
  - [x] Mac bridge can prepare a non-transmitting native-format raw64 `EnableTrust` signature over the supplied 32-byte challenge hash using macOS Security raw-digest ECDSA, distinct from CryptoKit's SHA256-over-data comparison signature.
  - [x] Auth-flow comparator can score Android production Identity `ENABLE_TRUST` payload fingerprints against Mac non-transmitting candidates, with a readiness gate for native-format raw64 candidates.
  - [x] Auth-flow comparator can also score Android preamble TX challenge fingerprints against Mac non-transmitting `EnableTrust` challenge-hash candidates, separate from full payload comparison.
  - [x] Auth-flow comparator now emits a machine-readable recommended gated `EnableTrust` candidate with `candidate_id`; it only marks manual Mac auth transmit eligible when the same native-format raw64 candidate matches both Android TX challenge and Android `ENABLE_TRUST` payload fingerprints.
  - [x] Auth-flow comparator has a synthetic self-test covering the eligible gate path plus payload-mismatch and RX-challenge-only fail-closed paths.
  - [x] Mac bridge can load an eligible `codex_band_bridge_enable_trust_gate_v1` artifact, enable `Send Auth` only for the exact staged `candidate_id`, send the gated frame on manual action, and record redacted loaded/ready/sent evidence in session summaries.
  - [x] Shared Swift fixture covers `EnableTrust` gate parsing, eligibility rejection, candidate-id requirement, and abbreviated frame-fingerprint matching.
  - [x] Auth-flow comparator can write a redacted `enable_trust_gate_v1` JSON artifact via `--write-auth-gate`; it fails closed unless the recommendation is `PAYLOAD_AND_TX_CHALLENGE_MATCH`.
  - [x] Mac bridge can load an eligible `enable_trust_gate_v1` artifact, verify it names a staged `candidate_id`, and expose a manual `Send Auth` action only while that exact candidate is staged and L2CAP is open.
  - [x] Mac `EnableTrust` staging now covers native-plausible local channel ids `0`, `1`, and `2`, with `local_channel_id`/`base_id` logged so the Android evidence gate chooses the exact frame fingerprint.
  - [x] Swift can emit a gated AirShield `RequestEncryption` probe over L2CAP with structured TX logging.
  - [x] Swift decodes AirShield service-5 `RequestEncryption`, `EnableEncryption`, and `EndLinkSetup` DataX frames on receive.
  - [x] Swift retains the local ephemeral private key/challenge for the probe and derives the P-256 ECDH shared secret from `EnableEncryption.publicKey`.
  - [x] Swift prepares a manual, encrypted `EndLinkSetup { state = MAIN, uuid }` candidate per framing material source and exposes it only after passive encrypted-frame validation.
  - [x] Swift TX candidate ordering reserves the `EnableEncryption.base` counter for `EndLinkSetup` and prepares gesture-enable at `base + 1`; gesture-enable stays disabled until EndLinkSetup is fully written.
  - [x] Add deterministic Swift fixture proving passive encrypted-frame validation unlocks only the matching EndLinkSetup and gesture-enable transmit frames.
  - [ ] Real connection trace containing the first AirShield/DataX bytes, if hardware capture becomes available.
  - [x] Static reconstruction of equivalent AirShield/DataX first-write sequence at `reverse/airshield-first-write-static.md`.
  - [ ] Complete `EnableEncryption` handling by applying AirShield KDF/challenge derivation and building equivalent RX/TX framing.
  - [ ] Use the Java auth-delegate trace to identify the accepted app identity path, then implement Mac-side preamble authentication acceptance using the imported key material.
  - [ ] Use Android trace or imported identity evidence to select the accepted production Identity path, then run the gated Mac-side auth transmit for the matching raw64 `EnableTrust` candidate with a real eligible gate artifact.
    - [x] Implement the Mac-side gate loader and manual send path; still requires a real eligible gate artifact from matching Android evidence.
    - [x] Add local fixture coverage for gate schema/eligibility/candidate-id/fingerprint checks; live transmit still requires the real eligible gate.
  - [ ] Confirm native `PrivateKey.serialize()` / `recoverPublicKey()` parity when the imported key is not directly parseable as a 32-byte P-256 scalar.
    - [x] Add emulator-native `PrivateKey.setRaw` / `serialize` / `recoverPublicKey` probe tooling at `tools/android-trace/probe_airshield_private_key.py` plus comparator support via `--native-probe`.
    - [x] Add redacted import-prep flow for extracted-state reports so the chosen identity slot can be exported locally for Mac import/native probe input without exposing Base64 in logs.
    - [x] Add `tools/live/compare_airshield_identity.py --self-test` coverage for redacted preference-slot, native-probe, Android-trace, and Mac imported identity comparisons.
    - [ ] Run the native probe against a real extracted `app-private-key` or `acdc-app-private-key` slot and compare recovered public-key fingerprints against Mac candidates.
  - [ ] Validate passive encrypted-frame decrypt against live post-handshake traffic.
  - [ ] Validate against live band that the gated encrypted `EndLinkSetup` frame is accepted.
- [ ] Confirm whether decrypted traffic becomes protobuf/DataX payloads.
  - [x] Local fixture covers encrypted outer frame -> decrypted DataX frame -> `EmgImu$GestureEvent` decode.
  - [x] Add `tools/live/validate_decrypted_datax_shape.py` to validate live session logs for `source=airshield.decrypted` inner DataX/WIS routes, active stream evidence, and decrypted gesture events.
  - [x] Add readiness gate for recognized decrypted inner DataX routes so post-AirShield plaintext must decode to known WIS app/message IDs before live parity passes.
  - [ ] Confirm the same shape with live post-handshake traffic.

## Priority 4: Enable Gesture Streams

- [x] Inspect stream-control request construction:
  - [x] `StreamControl$StreamControlReq`
  - [x] `StreamControl$StreamControlResp`
  - [x] `Rpc$RpcRequest`
  - [x] `Rpc$RpcResponse`
  - [x] `Rpc$RpcStreamUpdate`
  - [x] `WearableInputService`
- [x] Identify the minimal request to enable gestures only.
- [x] Add static WIS gesture stream route/enable report at `reverse/wis-gesture-stream-static.md`.
- [x] Map stream-control response/update wrapper fields for active/lost/info state.
- [x] Record decoded stream-control response/update evidence as `wis.stream_control.response` / `wis.stream_control.update` session events and add readiness gates for active gesture stream plus decrypted active-stream source.
- [x] Add minimal gesture-enable RPC payload bytes to the Swift protocol scaffold, but keep transmit disabled until secure DataX is established.
- [x] Add manual Swift decoders for RPC stream-control responses and lost/info/active stream updates.
- [x] Build protobuf descriptors or generated Swift equivalents for:
  - [x] stream control request recovered subset at `reverse/protos/wearable_input_bridge.proto`
  - [x] stream control response recovered subset at `reverse/protos/wearable_input_bridge.proto`
  - [x] gesture event recovered subset at `reverse/protos/wearable_input_bridge.proto`
  - [x] stream update wrapper recovered subset at `reverse/protos/wearable_input_bridge.proto`
  - [x] current Mac MVP uses manual Swift parsers instead of generated Swift equivalents, keeping the recovered `.proto` as documentation/validation source
- [ ] Send gesture-enable request after secure DataX connection.
  - [x] Manual Mac UI action exists, but is gated behind passive encrypted-frame validation.
  - [x] Static WIS gesture-stream parity is enforced in `tools/static/analyze_wis_gesture_stream_static.py` and included in the consolidated next-gates sweep.
  - [ ] Validate against live band that the gated encrypted gesture-enable frame is accepted.
- [ ] Confirm incoming gesture events for:
  - [ ] tap
  - [ ] double tap
  - [ ] swipe up
  - [ ] swipe down
  - [ ] swipe in/out
  - [ ] press/hold/release

## Priority 5: Decode And Forward Events

- [x] Parse `EmgImu$GestureEvent`.
- [x] Add a manual Swift parser for `EmgImu$GestureEvent` protobuf payloads.
- [x] Add local Swift validation fixture for gesture protobuf decoding.
- [x] Add local Swift validation fixture for stream-control response/update decoding.
- [x] Add static gesture enum/name mapping report at `reverse/gesture-event-mapping-static.md`.
- [x] Map event fields:
  - [x] `finger`
  - [x] `action`
  - [x] `derivedAction`
  - [x] `sequenceNumber`
  - [x] `timestamp`
  - [x] `emgRawGestureId`
  - [x] `isSyntheticGesture`
  - [x] EMG/IMU provenance and timing fields (`emgBatchIDLow`, `emgBatchIDHigh`, `imuSequenceNumber`, `deviceLatencyMicros`, `inferenceTriggerEMGOffset`)
- [x] Confirm whether mapped actions are already high-level events, not geometry.
- [ ] Emit normalized local events:
  - [x] `tap`
  - [x] `double_tap`
  - [x] `swipe_up`
  - [x] `swipe_down`
  - [x] `swipe_left`
  - [x] `swipe_right`
  - [x] `press`
  - [x] `release`
  - [x] Add replay validator at `tools/live/validate_gesture_events.py` to re-decode captured `frame_payload_hex` and compare recorded normalized names/fingers/raw fields.
  - [x] Add validator/readiness presets for the standard action set and live band action coverage set.
  - [x] Cover every live validation action in the validator self-test: tap, double tap, up/down, in/out, press, hold, release.
  - [x] Cover every live validation action in the Swift forwarded-payload fixture, including schema, route, normalized action, and replay payload hex.
  - [x] Extend replay validator to check the versioned local forwarding contract (`codex_band_bridge.gesture.v1`) including route fields `app_id=2` / `message_type=13`.
  - [x] Add readiness flag `--expect-forwarded-schema` so MVP relay runs fail unless forwarded gesture JSONL events satisfy the versioned schema.
  - [x] Add Swift fixture coverage for per-session `datax.gesture_decoded` replay payloads, including `frame_source` and `frame_payload_hex`.
  - [x] Require decrypted-session gesture replay for readiness coverage, so live action checks prove post-AirShield `source=airshield.decrypted` events.
  - [x] Add readiness self-test coverage for synthetic decrypted gesture replay plus forwarded-schema replay across the full live validation action set.
  - [x] Add stream-control negative fixtures so inactive/lost/info WIS responses do not count as gesture stream active.
  - [x] Add `validate_gesture_events.py --write-fixture` to emit a reusable forwarded-schema JSONL fixture covering the live validation actions for local client/MVP testing.
  - [ ] Validate normalized names against live decrypted gesture payloads.
- [x] Forward events to a local bridge:
  - [x] JSONL log
  - [x] local localhost JSONL socket
  - [x] local WebSocket for browser-native relay prototypes
  - [x] macOS notification/debug console
  - [x] stable versioned JSON payload fixture for TCP/WebSocket/iPhone relay prototypes
  - [x] optional iPhone Simulator/browser pull API at `http://127.0.0.1:49733`
  - [x] optional physical-iPhone local-network read-only HTTP relay at `http://<mac-lan-ip>:49734`
  - [x] HTTP relay schema discovery at `/schema`, including pull paths, route IDs, normalized action lists, and required/optional payload fields.
  - [x] HTTP relay CORS/preflight support for browser and iPhone prototype clients.

## Priority 6: Mac MVP Shape

- [x] Keep Swift/CoreBluetooth code shared-friendly for later iOS migration.
  - [x] shared protocol/crypto/gesture core compiles without CoreBluetooth, SwiftUI, sockets, or macOS notification code via `tools/swift/validate_shared_core.sh`
- [x] Split the helper into modules:
  - [x] `BandScanner`
  - [x] `GattSession`
  - [x] `L2CAPSession`
  - [x] `DataXCodec`
  - [x] `AirShieldSession`
  - [x] `GestureDecoder`
  - [x] `EventForwarder`
- [x] Add a minimal SwiftUI event monitor:
  - [x] connection state
  - [x] L2CAP state
  - [x] latest decoded event
  - [x] event history
  - [x] raw frame count
  - [x] secure-link state
  - [x] reconnect state
- [x] Add a local socket/API for the iPhone-side prototype to consume.
  - [x] localhost JSONL TCP stream at `127.0.0.1:49731`
  - [x] choose a WebSocket wrapper for browser/iPhone relay prototypes at `ws://127.0.0.1:49732`
  - [x] HTTP pull endpoints at `http://127.0.0.1:49733/health`, `/latest`, `/events`, and `/events.ndjson`
  - [x] LAN-visible HTTP pull endpoints at `http://<mac-lan-ip>:49734/health`, `/schema`, `/latest`, `/events`, and `/events.ndjson`
  - [x] Browser preflight support via `OPTIONS` and explicit CORS headers on HTTP relay responses
  - [x] versioned gesture event JSON schema `codex_band_bridge.gesture.v1` with normalized action, raw action fields, DataX app/message IDs, and EMG/IMU provenance metadata
  - [x] replay validation can require that forwarded schema for MVP/iPhone relay runs via `tools/live/validate_gesture_events.py --expect-forwarded-schema`

## Reference Notes

- Official app reads PSM from `0000FEB8-0000-1000-8000-00805F9B34FB`.
- PSM characteristics seen:
  - `2D41DA7A-82B6-42AA-B34E-E2E01DF8CC1A`
  - `2D41DA7C-82B6-42AA-B34E-E2E01DF8CC1A`
- Official app opens an insecure LE L2CAP channel with PSM `255`.
- APK logs describe the post-L2CAP path as `DATAX` and `secure_connection=true`.
- Gesture payloads in the APK are protobuf-based and include high-level action fields, so the band/glasses stack classifies gestures before app delivery.
- Normal gesture path uses `EmgImu$GestureEvent` with `finger`, `action`, `derivedAction`, sequence/timestamp, and EMG/IMU provenance IDs.
- Static gesture mapping report at `reverse/gesture-event-mapping-static.md` ties Swift normalized names back to the APK's `GestureEvent`, finger/action enums, derived-action enums, and converter helper.
- Static WIS gesture stream report at `reverse/wis-gesture-stream-static.md` ties Swift app/message IDs, gesture-enable RPC bytes, and active stream response handling back to APK WIS constants and protobuf wrappers.
- Glasses OTA helper reads auth from `META_AUTHORIZATION` only and defaults to `https://ar-genai.graph.meta.com/firmware_ota_update`.
