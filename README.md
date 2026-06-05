# Codex Ray-Ban

Codex Ray-Ban is a SwiftUI iOS app for using Codex through Meta smart glasses. It connects to Meta Wearables DAT, launches a display app on the glasses, signs in to OpenAI/Codex remote control, and mirrors Codex chats, projects, pets, and voice input into the glasses UI.

## What It Does

- Registers and manages supported Meta smart glasses through Meta Wearables DAT.
- Starts a DAT display session and sends Codex status, chat, and pet screens to the glasses.
- Signs in with the Codex desktop OAuth flow and enrolls the phone as a Codex remote-control client.
- Lists online Codex Desktop hosts, connects over the Codex remote websocket, and reads chats, projects, models, and thread state.
- Sends chat actions from the glasses back to Codex, including opening chats, creating messages, selecting models, and toggling display modes.
- Supports voice capture from the glasses microphone and transcription for dictated Codex messages.

## Requirements

- Xcode with iOS 17 SDK support.
- An Apple Developer team for signing the app.
- A physical iPhone. The glasses integration depends on Bluetooth, local network, external accessory, and DAT runtime behavior that is not useful on the simulator.
- Compatible Meta smart glasses with Developer Mode enabled.
- The Meta AI app installed on the test phone.
- Access to a Codex Desktop host signed in to the same OpenAI account.

The Xcode project resolves one Swift package dependency:

- `MetaWearablesDAT` from `https://github.com/facebook/meta-wearables-dat-ios`, currently pinned at `0.7.0`.

## Setup

1. Open `CodexRayBan.xcodeproj` in Xcode.
2. Select the `CodexRayBan` target.
3. In Signing & Capabilities, choose your Apple Developer team.
4. Keep the bundle identifier as `com.example.codexrayban`, or update it consistently across the Xcode project and universal-link configuration.
5. Configure local build settings for `CODEX_OAUTH_CLIENT_ID`, `MWDAT_META_APP_ID`, and `MWDAT_CLIENT_TOKEN`.
6. Build and run on a physical iPhone.

The app is configured with:

- URL scheme: `codexrayban://`
- DAT modules: `MWDATCore`, `MWDATDisplay`
- DAT app model: `MWDAT.DAMEnabled = true`
- External accessory protocol: `com.meta.ar.wearable`
- Universal link entitlement: `applinks:example.com`

Private signing, OAuth, and Meta Wearables app values are intentionally not committed. Set them locally in Xcode or in an untracked local xcconfig.

See [CodexRayBan-Setup.md](CodexRayBan-Setup.md) for universal-link hosting and Cloudflare Worker deployment details.

## First Run

1. Install and open the Meta AI app on the phone.
2. Enable Developer Mode for the glasses.
3. Run Codex Ray-Ban from Xcode.
4. In the app, go to Settings and register/connect the glasses.
5. In Settings > Codex, sign in to OpenAI.
6. Enroll the phone for Codex remote control.
7. Make sure Codex Desktop is running and online on the host you want to control.
8. Return to the Codex tab, choose a host if needed, and refresh.
9. Open a chat or create a new one, then use the glasses display controls to show chat or pet mode.

When glasses are connected, the app auto-launches the Codex display app and keeps the active chat or home screen in sync.

## Project Layout

- `CodexRayBan/CodexRayBanApp.swift` - SwiftUI app entry point, tab layout, display auto-launch, and glasses action routing.
- `CodexRayBan/Views/` - iOS screens for home, chat, settings, registration, OAuth, and the local web host preview.
- `CodexRayBan/ViewModels/WearablesViewModel.swift` - DAT registration, device discovery, link state, and firmware compatibility.
- `CodexRayBan/ViewModels/DisplayViewModel.swift` - DAT display session lifecycle and display sends.
- `CodexRayBan/ViewModels/CodexAuthViewModel.swift` - OpenAI sign-in, Codex remote enrollment, token refresh, and host discovery.
- `CodexRayBan/ViewModels/CodexWorkspaceViewModel.swift` - Codex remote websocket transport and workspace/chat state.
- `CodexRayBan/ViewModels/CodexDisplayAppState.swift` - Codable state sent into the glasses display app.
- `CodexRayBan/ViewModels/CodexDisplayAppBridge.swift` - Display action parsing and state mutation glue.
- `CodexRayBan/Samples/` - MWDAT display definitions used for cards and the Codex display app.
- `codex-display-app.html` - Web UI bundled into the app and rendered for the glasses display experience.
- `CodexRayBanTests/` - Contract, serialization, display bridge, and remote API catalog tests.
- `UniversalLinks/` and `cloudflare/` - Apple App Site Association examples and deployment support.
- `tools/` - Supporting research, validation, and live diagnostic scripts.

## Building and Testing

List targets and schemes:

```sh
xcodebuild -list -project CodexRayBan.xcodeproj
```

Build the app:

```sh
xcodebuild build \
  -project CodexRayBan.xcodeproj \
  -scheme CodexRayBan \
  -destination 'generic/platform=iOS'
```

Run unit tests on an available simulator:

```sh
xcodebuild test \
  -project CodexRayBan.xcodeproj \
  -scheme CodexRayBan \
  -destination 'platform=iOS Simulator,name=iPhone 16'
```

For glasses behavior, prefer testing on a physical phone with glasses connected. Simulator tests are useful for model, serialization, bridge, and remote API contract coverage, but they do not validate the DAT runtime path.

## Runtime Notes

- OAuth uses the Codex desktop-style PKCE flow and captures the localhost callback inside a web view.
- Remote control uses `https://chatgpt.com/backend-api` for enrollment and host listing, then `wss://chatgpt.com/backend-api/codex/remote/control/client` for app-server JSON-RPC.
- Remote enrollment creates a device key in the iOS keychain and uses signed device-key proofs for enrollment, refresh, and websocket challenge handling.
- Voice transcription uses Codex account tokens when available and supports an OpenAI API key fallback in developer diagnostics.
- Developer diagnostics expose auth logs, token import, host refresh, and extra display test actions.

## Related Docs

- [CodexRayBan-Setup.md](CodexRayBan-Setup.md) - signing, DAT, and universal-link setup.
- [CodexRayBan-TODO.md](CodexRayBan-TODO.md) - outstanding iOS app work.
- [BAND_BRIDGE_TODO.md](BAND_BRIDGE_TODO.md) - bridge and accessory investigation notes.
- [tools/live/README.md](tools/live/README.md) - live diagnostic scripts.
- [tools/android-trace/README.md](tools/android-trace/README.md) - Android trace tooling notes.
- [tools/ota/README.md](tools/ota/README.md) - OTA research tools.
