# Codebase Audit Todo

## 1. Test Isolation

- [x] Add injectable auth/session/network dependencies for app startup.
- [x] Disable auto-launch, token refresh, host refresh, and websocket connection under test.
- [x] Add tests proving launch does not touch saved keychain or live network.

## 2. Remote Transport Reliability

- [x] Add request timeouts to websocket RPC calls.
- [x] Surface websocket disconnects into `connectionState`.
- [x] Add reconnect/backoff behavior.
- [x] Avoid tearing down the whole connection for ignorable foreign/client-mismatch frames.
- [x] Add focused tests for timeout configuration, disconnect failure propagation, and bridge fallback behavior.

## 3. Device Key Security

- [x] Replace raw P-256 keychain storage with Secure Enclave/nonextractable key support where available.
- [x] Or change enrollment metadata so it does not claim `os_protected_nonextractable`.
- [x] Add tests around key creation, reload, and proof signing.

## 4. Send Message Flow

- [x] Make `sendMessage` await the actual create-thread/start-turn result.
- [x] Return success/failure state to iPhone UI and glasses bridge.
- [x] Keep optimistic user messages, but mark failed sends instead of adding duplicate/system-only confusion.
- [x] Add tests for send failure reporting, optimistic message state, and bridge behavior.

## 5. Chat Event Handling

- [x] Process non-active chat events for active indicators, unread state, project ordering, and pinned/archive changes.
- [x] Keep full message streaming only for the active/open chat.
- [x] Add tests for project activity and unread indicator export.

## 6. Project/Chat Grouping

- [x] Put every project-backed chat under its project, including singleton projects.
- [x] Keep non-project chats only in the recent chats section.
- [x] Sort projects and chats by newest activity.
- [x] Update tests currently expecting singleton project groups to be hidden.

## 7. Glasses Action Routing

- [x] Fix `switchesGlassesToPetAfterHandling` so opening a chat switches the glasses to the pet.
- [x] Verify open chat, open project, dictate, send, pin, and file actions through the display bridge.
- [x] Add bridge tests for the production glasses action surface.

## 8. Production Settings Cleanup

- [x] Move debug controls behind a debug/developer flag.
- [x] Hide token import, hello-world send, auth log, and diagnostics in production.
- [x] Reduce console logging and redact account/host/error details.

## 9. BandBridgeMac Security

- [x] Bind LAN server only when explicitly enabled.
- [x] Add auth/token protection or local-only mode.
- [x] Remove wildcard CORS for production usage.
- [x] Avoid exposing raw frame payloads unless debug mode is on.

## 10. Glasses Layout

- [x] Remove the 18-line invisible measurement reserve hack.
- [x] Replace it with explicit layout constraints that match the display.
- [x] Re-test home, project, chat, pet, dictation, transcript, and file views with renderer smoke coverage.

## 11. Pagination Cursor

- [x] Replace hand-built cursor JSON with `JSONEncoder`.
- [x] Fuzz cursor parsing/encoding with quotes, backslashes, empty strings, and malformed JSON.
- [x] Confirm pagination behavior against the live route.

## 12. PKCE Randomness

- [x] Make `SecRandomCopyBytes` failure throw.
- [x] Add a small unit test around generated verifier/challenge shape.

## 13. Transcription

- [x] Avoid loading large audio files fully into memory where possible.
- [x] Cap recording duration/file size.
- [x] Improve transcription error redaction.
- [x] Add tests for session-based transcription request shape and audio meter handling.

## 14. Regression Coverage

- [x] Add unit tests for auth refresh waiters and refresh failure propagation.
- [x] Add focused websocket transport regression coverage where it can run deterministically in unit tests.
- [x] Add glasses DAT/action renderer tests.
- [x] Add iPhone device test coverage for home, chat, dictation, transcript, settings-adjacent state, and pet flows.

## Verification

- [x] `xcodebuild test -project CodexRayBan.xcodeproj -scheme CodexRayBan -destination 'platform=iOS,id=00008140-000461511412801C'`
- [x] `./BandBridgeMac/build.sh`
- [x] `python3 tools/validate_codex_remote_contract.py`
