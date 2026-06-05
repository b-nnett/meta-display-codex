# What APK Decompilation Taught Us About Codex Mobile

This is a quick overview of what we have learned while reverse engineering the Meta AI Android APK for the Codex mobile and wearable prototype. The short version: the mobile app is not just forwarding Bluetooth bytes. It is running a layered transport stack that discovers the wearable over BLE, opens a protected L2CAP channel, upgrades that channel through Meta's DataX and AirShield protocols, authenticates app/device identity, and only then sends the higher-level wearable input messages we care about.

Our current Codex mobile work depends on understanding that stack well enough to reproduce the safe parts of it from our own bridge code, without guessing at packet shapes or treating the band as a raw Bluetooth peripheral.

## The Stack Is Layered

The biggest finding is that the official app uses a clean split between transport, framing, encryption, identity, and application messages.

At the bottom, the band exposes a BLE service that points the app to an LE L2CAP Protocol/Service Multiplexer. In our live runs, the target band appears as `Meta Band 000J`, reports serial `306GP9BH4N000J`, and exposes protected PSM bytes `ff00`, which decode to LE L2CAP PSM `255`.

The Android app reads that PSM and opens an insecure LE L2CAP channel. That sounds surprising at first, but the channel is only the carrier. The real protection comes immediately afterward, through the higher-level AirShield setup.

Above L2CAP is DataX, Meta's multiplexed frame protocol. DataX gives the stream channels, service IDs, typed-buffer IDs, and protobuf payloads. AirShield then uses DataX during a preamble phase to negotiate an encrypted stream. Once AirShield reports the stream as ready, normal app traffic can flow through the secured channel.

In rough terms:

```text
BLE discovery
  -> protected GATT read of DataX PSM
  -> LE L2CAP stream
  -> DataX lower frames
  -> AirShield preamble and encrypted stream
  -> Identity / ACDC authentication
  -> WIS gesture and RPC messages
```

That layering matters because every stage has a different job. Pairing gets us to the device. DataX structures the stream. AirShield protects it. Identity proves that the app is accepted by the wearable. WIS carries the input events.

## DataX Is The Frame Router

The APK and native library gave us enough evidence to model the DataX frame envelope.

The lower DataX frame header is four bytes: a two-byte descriptor followed by a two-byte base ID. The descriptor carries a 14-bit body length, with bit 15 marking whether extension words are present. Extension words are four bytes each. The extension type and value are how the sender labels which service and typed message a frame belongs to.

For AirShield link setup, the recovered native send path opens service `5` and sends typed buffers such as:

- `1`: `REQUEST_ENCRYPTION`
- `2`: `ENABLE_ENCRYPTION`
- `4096`: `END_LINK_SETUP`

The first AirShield write is now statically mapped: the app builds a `RequestEncryption` protobuf with a public key, a 16-byte challenge, the `Secp256r1` curve enum, and the HKDF-supported parameter bit. DataX wraps that payload as service `5`, typed buffer `1`.

This is one of the more useful discoveries because it turns the first connection write from a mystery blob into a reproducible structured message.

## AirShield Is The Secure Stream Upgrade

AirShield is the native secure-stream layer. The Java class names make the lifecycle fairly clear: `StreamSecurerImpl`, `Preamble`, `CipherBuilder`, `Framing`, `Stream`, and `EndLinkSetupMessage`.

The official flow looks like this:

1. The app opens the L2CAP stream.
2. It starts `StreamSecurerImpl`.
3. Native AirShield emits bytes through an `onSend` callback.
4. AirShield creates a preamble DataX connection.
5. The app runs authentication services over that preamble.
6. The app calls `Preamble.acceptAuthentication(...)`.
7. Native AirShield eventually reports `onStreamReady`.
8. The original link is wrapped as an encrypted stream, including any rollover bytes already received.

The cryptography is not a single shared static key. The APK shows that `CipherBuilder` creates fresh per-stream material: a P-256 private key, challenge, seed, and initialization vector. The native side uses these to build challenge hashes, framing keys, encrypted payload transforms, and validation prefixes.

Our native analysis also recovered several important framing facts:

- Encrypted AirShield records are not ordinary nested DataX frames.
- The encrypted outer record starts with an 8-byte validation prefix.
- Byte `8` is a cipher payload size indicator.
- Encrypted payload begins at byte `9`.
- Payloads are padded to 16-byte boundaries with a native padding scheme.
- The selected transform evidence points to AES-256-CTR-style payload encryption.

The practical result is that a bridge cannot simply encode a DataX packet and write it to L2CAP. It must first match AirShield's native framing behavior, or the wearable will reject the stream before any application message is visible.

## Identity Auth Is Separate From Stream Encryption

One of the more important lessons is that AirShield stream encryption and app identity authentication are separate.

The stream setup uses ephemeral per-session key exchange. But after `onPreambleReady`, the Java layer registers authentication services on the temporary preamble connection. The authentication delegate returns app identity material, and Java passes a padded or truncated 64-byte public key into `Preamble.acceptAuthentication(...)`.

The production Identity path uses service `36`. Static evidence shows the owned-device path sends an `ENABLE_TRUST` typed buffer directly. That message signs the preamble TX challenge with the app identity private key, and the peer verifies against the corresponding RX challenge. The APK also has related ACDC and prototype identity paths, so the bridge has to treat this as a real authentication layer, not just a cosmetic callback.

This separates the blockers cleanly:

- Android OS bonding appears to be a transport and discovery requirement.
- AirShield ephemeral crypto is required for stream encryption.
- Identity or ACDC app key material is required for the wearable to accept the app.

The static scan did not find Android bond-derived secrets feeding directly into the AirShield stream KDF. That does not mean pairing can be skipped. It means the cryptographic acceptance blocker is app identity, not a hidden Bluetooth bond secret.

## Gestures Are High-Level Events

The APK also clarified what we can expect after the secure stream is established.

The wearable input service does not appear to send display geometry, paths, or raw spatial commands for the high-level gesture path we care about. It sends enum-based gesture events with sequence numbers, timestamps, finger labels, raw actions, derived actions, EMG/IMU batch metadata, raw gesture IDs, and a synthetic flag.

Recovered mappings include:

- Fingers: thumb, index, middle, and not-applicable.
- Raw actions: press, release, tap, double tap, click, swipes, wake, Meta AI, and partial variants.
- Derived actions: tap, double tap, hold, release, directional button actions, press, and hold-release.

The gesture-enable request is also mapped. The app sends a WIS RPC request for stream control, with `enableGestures` set in the nested request. Static evidence supports the app/message routing constants used by the bridge: RPC requests use app ID `3`, message type `20`; gesture events use app ID `2`, message type `13`.

So the product implication is encouraging: once AirShield and identity auth are handled, gesture handling should be a normal decoded event stream, not a computer-vision or motion-reconstruction problem.

## Where The Prototype Stands

The Mac bridge now has a much clearer path:

1. Discover the exact band and read its protected GATT metadata.
2. Open the DataX L2CAP PSM.
3. Emit a native-shaped AirShield `RequestEncryption`.
4. Decode `EnableEncryption` when available.
5. Build passive AirShield framing candidates.
6. Match native encrypted-frame behavior before enabling transmit.
7. Satisfy Identity or ACDC preamble authentication.
8. Send encrypted WIS stream-control messages.
9. Decode gesture events and forward them into the Codex mobile experience.

The current live blocker is lower-level than the protocol model: on macOS, CoreBluetooth opens the LE L2CAP stream, but the output stream has not reported write space in the guarded retry window. The bridge records that as a non-blocking transmit failure and includes a manual direct-write diagnostic so we can test whether Android's direct `OutputStream.write(...)` behavior can be approximated from CoreBluetooth.

## Why This Matters For Codex Mobile

The APK decompilation changed the project from guesswork into a protocol implementation effort.

Before this research, "make Codex work on mobile/wearables" could have meant anything from sending raw BLE commands to trying to mirror a UI through a vendor SDK. After the decompilation, the shape is much sharper:

- The mobile app discovers a wearable transport.
- It upgrades that transport through a native secure stream.
- It authenticates app identity separately from stream encryption.
- It requests high-level input streams through WIS RPC.
- It receives normalized gesture events that can be mapped into product actions.

That is a strong foundation for a Codex mobile experience. The remaining hard work is not figuring out what kind of system exists; it is proving byte-for-byte parity at the AirShield boundary, completing accepted identity auth, and then building a small, careful application layer on top.

## Internal Evidence Notes

Key repo notes behind this overview:

- `reverse/NOTES-datax-airshield.md`
- `reverse/native-datax-report.md`
- `reverse/native-datax-localchannel-send.md`
- `reverse/airshield-first-write-static.md`
- `reverse/native-airshield-report.md`
- `reverse/airshield-kdf-framing-report.md`
- `reverse/airshield-key-source-report.md`
- `reverse/airshield-bond-requirements.md`
- `reverse/airshield-identity-auth-static.md`
- `reverse/wis-gesture-stream-static.md`
- `reverse/gesture-event-mapping-static.md`
- `reverse/live-band-transport-2026-06-05.md`
