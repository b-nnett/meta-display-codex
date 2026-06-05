# Codex Ray-Ban TODO

## Current Foundation

- [x] Create SwiftUI iOS project.
- [x] Add Meta Wearables DAT SDK package.
- [x] Link `MWDATCore`.
- [x] Link `MWDATDisplay`.
- [x] Configure `MWDAT` plist dictionary with Meta app ID and client token.
- [x] Enable `MWDAT.DAMEnabled`.
- [x] Add `codexrayban://` callback scheme.
- [x] Add DAT external accessory, Bluetooth, local network, and background mode plist keys.
- [x] Add Meta AI callback handling through `Wearables.shared.handleUrl(_:)`.
- [x] Add registration and device-state UI.
- [x] Add display-capable device session flow.
- [x] Add simple Codex-branded display cards.
- [x] Configure Associated Domains for `example.com`.
- [x] Deploy Cloudflare Worker for Apple App Site Association.
- [x] Verify `https://example.com/.well-known/apple-app-site-association`.
- [x] Verify simulator build succeeds.

## App Identity And Distribution

- [ ] Confirm final bundle identifier: `com.example.codexrayban`.
- [ ] Confirm final display name: `Codex Ray-Ban`.
- [ ] Confirm the Meta Wearables project uses the same bundle ID.
- [ ] Confirm the Apple Developer app identifier has Associated Domains enabled.
- [ ] Confirm provisioning profile includes `applinks:example.com`.
- [ ] Build and run on a physical iPhone.
- [ ] Register the app from the iPhone through Meta AI.
- [ ] Confirm Ray-Ban Display appears as a display-capable device.
- [ ] Confirm the ready card renders on the glasses.
- [ ] Confirm DAT app and firmware update buttons work when required.

## Codex OAuth

- [ ] Add a `CodexAuthService`.
- [ ] Implement PKCE verifier generation.
- [ ] Implement SHA-256 PKCE challenge generation.
- [ ] Add OAuth state generation and verification.
- [ ] Build desktop-method authorization URL:
  - [ ] issuer: `https://auth.openai.com`
  - [ ] authorize path: `/oauth/authorize`
  - [ ] client id: configure locally with `CODEX_OAUTH_CLIENT_ID`
  - [ ] scope: `codex.remote_control.enroll`
  - [ ] redirect URI: `https://example.com/oauth/callback`
  - [ ] `originator=Codex Desktop`
  - [ ] `reauth=remote_control`
  - [ ] `max_age=0`
  - [ ] `codex_cli_simplified_flow=true`
- [ ] Add app route handling for `https://example.com/oauth/callback`.
- [ ] Exchange authorization code for step-up token.
- [ ] Decode and validate returned step-up JWT:
  - [ ] scope is `codex.remote_control.enroll`
  - [ ] issue time is recent
  - [ ] password auth time is recent when present
  - [ ] account user id is present
- [ ] Add signed-in/auth-needed UI states.
- [ ] Show OAuth status on the glasses.

## Codex Normal Access Token Question

- [ ] Resolve how an independent client gets the normal ChatGPT/Codex bearer token required by:
  - [ ] `enroll/start`
  - [ ] environment listing
  - [ ] environment detail
- [ ] Confirm whether the desktop OAuth client can request a broader normal access token without reading desktop `auth.json`.
- [ ] If not, identify the correct independent mobile/desktop-compatible login path.
- [ ] Document the final auth-token model before implementing enrollment.

## Secure Storage

- [ ] Add Keychain wrapper.
- [ ] Store OAuth refresh/access material only in Keychain.
- [ ] Store remote-control enrollment metadata in Keychain:
  - [ ] `client_id`
  - [ ] `account_user_id`
  - [ ] `remote_control_token`
  - [ ] `expires_at`
  - [ ] scopes
- [ ] Store P-256 device private key in Secure Enclave or Keychain.
- [ ] Ensure private key is nonextractable when possible.
- [ ] Add a full sign-out path that deletes tokens, enrollment, and device key.

## Device Key And Proofs

- [ ] Add `CodexDeviceKeyService`.
- [ ] Generate P-256 ECDSA key.
- [ ] Export public key as SPKI DER base64.
- [ ] Build `device_identity`:
  - [ ] `key_id`
  - [ ] `public_key_spki_der_base64`
  - [ ] `algorithm=ecdsa_p256_sha256`
  - [ ] `protection_class=os_protected_nonextractable`
- [ ] Implement device identity hash with desktop-compatible JSON property order.
- [ ] Implement canonical signed payload builder:
  - [ ] `domain=codex-device-key-sign-payload/v1`
  - [ ] `payload={...}`
- [ ] Sign canonical payload bytes with ECDSA P-256 SHA-256.
- [ ] Output DER signature as standard base64.
- [ ] Output signed payload bytes as standard base64.
- [ ] Unit test signature payload JSON exactly matches the docs.

## Remote-Control Enrollment

- [ ] Add `CodexRemoteControlClient`.
- [ ] Implement backend REST base URL: `https://chatgpt.com/backend-api`.
- [ ] Implement common request headers:
  - [ ] `Authorization`
  - [ ] `ChatGPT-Account-Id`
  - [ ] `originator: Codex Desktop`
  - [ ] desktop-like user agent if possible
  - [ ] JSON content type
- [ ] Implement `POST /codex/remote/control/client/enroll/start`.
- [ ] Validate enrollment challenge fields.
- [ ] Build enrollment signed payload.
- [ ] Implement `POST /codex/remote/control/client/enroll/finish`.
- [ ] Validate enrollment finish response:
  - [ ] `client_id` matches
  - [ ] `account_user_id` matches
  - [ ] token exists
  - [ ] expiry is in the future
  - [ ] scope is `remote_control_controller_websocket`
- [ ] Persist enrollment.
- [ ] Add enrollment status UI.
- [ ] Add glasses card for enrollment success/failure.

## Remote-Control Refresh

- [ ] Implement `POST /codex/remote/control/client/refresh/start`.
- [ ] Validate refresh challenge includes device identity hash.
- [ ] Build refresh signed payload.
- [ ] Implement `POST /codex/remote/control/client/refresh/finish`.
- [ ] Validate refresh token response.
- [ ] Persist refreshed token and expiry.
- [ ] Refresh before expiry.
- [ ] Refresh immediately before websocket connect if token is near expiry.
- [ ] Add refresh failure recovery flow.

## Environment Listing

- [ ] Implement `GET /codex/remote/control/environments`.
- [ ] Implement pagination cursor support.
- [ ] Model environment fields:
  - [ ] `env_id`
  - [ ] `display_name`
  - [ ] online/busy state
  - [ ] OS/version/arch
  - [ ] app server version
  - [ ] last seen
- [ ] Add environments list in iPhone UI.
- [ ] Add selected environment state.
- [ ] Add compact environment status on glasses.
- [ ] Handle no online environments.
- [ ] Handle busy environments.

## Remote-Control Websocket

- [ ] Confirm websocket endpoint URL and whether HTTP headers can be set from native URLSession.
- [ ] Implement websocket connect to `/codex/remote/control/client`.
- [ ] Send headers:
  - [ ] `x-codex-client-session-token`
  - [ ] `x-codex-client-id`
  - [ ] `x-codex-protocol-version=3`
  - [ ] optional subscribe cursor
- [ ] Implement websocket lifecycle state:
  - [ ] disconnected
  - [ ] connecting
  - [ ] connected
  - [ ] authenticating device key
  - [ ] ready
  - [ ] failed
- [ ] Implement connection device-key challenge proof if challenged.
- [ ] Verify `remoteControlClientConnection` payload shape.
- [ ] Implement reconnect with backoff.
- [ ] Refresh token before reconnect when needed.

## Websocket Relay Protocol Gap

- [ ] Capture or discover complete remote-control websocket relay framing.
- [ ] Identify frame types.
- [ ] Identify how app-server JSON-RPC messages are embedded.
- [ ] Identify environment selection/session routing.
- [ ] Identify subscribe cursor behavior.
- [ ] Identify server notifications and error frames.
- [ ] Do not mark remote websocket complete until verified with:
  - [ ] successful websocket connect
  - [ ] successful device-key proof
  - [ ] successful app-server `initialize`
  - [ ] successful `thread/list`
  - [ ] reconnect after token refresh
  - [ ] reconnect with subscribe cursor if emitted

## App-Server JSON-RPC Over Remote

- [ ] Add JSON-RPC request/response model.
- [ ] Add request id generator.
- [ ] Add pending request table.
- [ ] Add timeout handling.
- [ ] Add notification handling.
- [ ] Send `initialize`.
- [ ] Send `initialized` notification.
- [ ] Implement read-only methods:
  - [ ] `account/read`
  - [ ] `thread/list`
  - [ ] `thread/read`
  - [ ] `thread/turns/list`
  - [ ] `model/list`
  - [ ] `config/read`
- [ ] Implement controlled side-effect methods:
  - [ ] `thread/start`
  - [ ] `thread/resume`
  - [ ] `turn/start`
  - [ ] `turn/steer`
  - [ ] `turn/interrupt`
- [ ] Gate dangerous methods behind explicit user confirmation.

## Codex UI On iPhone

- [ ] Add onboarding flow:
  - [ ] Register glasses
  - [ ] Sign in to Codex
  - [ ] Enroll remote-control client
  - [ ] Select environment
  - [ ] Connect
- [ ] Add account status screen.
- [ ] Add environment picker.
- [ ] Add recent threads list.
- [ ] Add thread detail screen.
- [ ] Add prompt composer.
- [ ] Add approval queue.
- [ ] Add logs/debug screen.
- [ ] Add sign-out/reset screen.

## Codex UI On Glasses

- [ ] Define display states:
  - [ ] auth needed
  - [ ] no environment
  - [ ] connecting
  - [ ] connected
  - [ ] busy
  - [ ] waiting for approval
  - [ ] streaming response
  - [ ] error
- [ ] Build compact environment card.
- [ ] Build current thread card.
- [ ] Build approval card with accept/reject actions.
- [ ] Build response summary card.
- [ ] Build interruption card.
- [ ] Build reconnect/error card.
- [ ] Keep text short enough for Ray-Ban Display.
- [ ] Avoid long prompts or multiline overflow on the glasses.

## Codex Pets On Glasses

- [ ] Reuse the Apple Watch pet model from `b-nnett/codex-apple-watch` instead of creating a separate pet taxonomy.
- [ ] Port `PetVisualState` equivalents:
  - [ ] `idle`
  - [ ] `running`
  - [ ] `running-left`
  - [ ] `running-right`
  - [ ] `thinking`
  - [ ] `waiting`
  - [ ] `review`
  - [ ] `failed`
  - [ ] `waving`
  - [ ] `jumping`
  - [ ] `recording`
- [ ] Preserve Watch state mappings:
  - [ ] `thinking` uses the `running` animation.
  - [ ] `recording` uses the `jumping` animation.
  - [ ] active/loading/working maps to `running`.
  - [ ] approval/input/request maps to `review`.
  - [ ] errors/cancelled maps to `failed`.
- [ ] Reuse built-in pet IDs:
  - [ ] `codex`
  - [ ] `dewey`
  - [ ] `fireball`
  - [ ] `rocky`
  - [ ] `seedy`
  - [ ] `stacky`
  - [ ] `bsod`
  - [ ] `null-signal`
- [ ] Import v4 pet spritesheets from the Watch implementation.
- [ ] Keep the existing atlas contract:
  - [ ] 8 columns.
  - [ ] 9 rows.
  - [ ] 192 x 208 frame cells.
  - [ ] nearest-neighbor rendering.
  - [ ] transparent unused cells.
- [ ] Port animation timing:
  - [ ] idle row timing.
  - [ ] app-state row timings.
  - [ ] loop start behavior.
  - [ ] review loops until read/dismissed.
- [ ] Add pet selection UI on iPhone.
- [ ] Persist selected pet in app storage.
- [ ] Add pet preview in iPhone UI.
- [ ] Add pet state binding to Codex task state.
- [ ] Add pet state binding to voice/recording state.
- [ ] Add pet state binding to approval/review state.
- [ ] Add unread/review persistence like the Watch app where useful.
- [ ] Decide glasses rendering strategy for animated pets:
  - [ ] Option A: periodically send cropped frame images through DAT Display.
  - [ ] Option B: pre-render each pet/state animation as short MP4 and send with `VideoPlayer`.
  - [ ] Option C: send a static representative frame for each state until DAT supports a better animation surface.
- [ ] Prefer MP4 loops if DAT Display cannot animate spritesheets or GIF/WebP images directly.
- [ ] Generate per-pet/per-state hosted media if using `VideoPlayer`.
- [ ] Host pet animation media on Cloudflare under `example.com`.
- [ ] Add cache-busting/versioning for hosted pet media.
- [ ] Add glasses pet card:
  - [ ] pet visual.
  - [ ] one-line Codex state.
  - [ ] optional thread/environment label.
- [ ] Add glasses pet-only idle mode.
- [ ] Add glasses approval mode with pet plus accept/reject buttons.
- [ ] Add glasses thinking/running mode with pet plus compact status.
- [ ] Add glasses failed mode with pet plus short error.
- [ ] Ensure pet visuals remain readable on Ray-Ban Display at small size.
- [ ] Avoid fast flashing or aggressive motion.
- [ ] Respect Reduce Motion on iPhone previews.
- [ ] Add pet animation tests ported from Watch:
  - [ ] review loops from row 8.
  - [ ] thinking uses running animation.
  - [ ] recording uses jumping animation.
  - [ ] unknown desktop states fall back safely.
- [ ] Add visual QA for every built-in pet on the glasses.
- [ ] Document pet asset source and update procedure.

## Permissions And Safety

- [ ] Add local allowlist for app-server methods.
- [ ] Default to read-only mode until user enables actions.
- [ ] Require explicit confirmation for:
  - [ ] command execution
  - [ ] filesystem writes/removes
  - [ ] plugin install/uninstall
  - [ ] MCP tool calls
  - [ ] account login/logout
  - [ ] email/billing nudges
- [ ] Show method and summarized params before approval.
- [ ] Log side-effecting method, params hash, confirmation status, and result.
- [ ] Add emergency disconnect.

## Testing

- [ ] Unit test PKCE generation.
- [ ] Unit test JWT decoding.
- [ ] Unit test canonical payload JSON.
- [ ] Unit test device identity hash.
- [ ] Unit test REST request body shapes.
- [ ] Unit test token expiry/refresh logic.
- [ ] Add URL callback tests.
- [ ] Add Keychain persistence tests.
- [ ] Add websocket reconnect tests once framing is known.
- [ ] Add UI tests for onboarding.
- [ ] Test on simulator for non-DAT UI.
- [ ] Test on physical iPhone for DAT registration.
- [ ] Test with Meta Ray-Ban Display hardware.

## Cloudflare And Universal Links

- [x] Install Wrangler.
- [x] Authenticate Wrangler with `developer@example.com`.
- [x] Deploy AASA Worker.
- [x] Verify public AASA endpoint.
- [ ] Add OAuth callback handling for `/oauth/callback`.
- [ ] Decide whether Cloudflare should only serve AASA or also act as a lightweight callback landing page.
- [ ] If callback landing page is needed, return a mobile-friendly page that deep-links into `codexrayban://`.
- [ ] Add cache invalidation procedure for AASA updates.

## Documentation

- [ ] Document app setup in Xcode.
- [ ] Document Meta Wearables setup.
- [ ] Document Cloudflare deployment.
- [ ] Document Codex auth architecture.
- [ ] Document remote-control protocol assumptions.
- [ ] Document known websocket relay gap.
- [ ] Document how to reset all local credentials.
- [ ] Document how to run on a test iPhone.

## Release Readiness

- [ ] Replace placeholder app icon.
- [ ] Add privacy strings for all real data usage.
- [ ] Add privacy manifest if required by dependencies.
- [ ] Confirm Meta Wearables developer terms and analytics opt-out choice.
- [ ] Confirm OpenAI/Codex auth terms for this client shape.
- [ ] Add crash/error reporting if desired.
- [ ] Prepare TestFlight build.
- [ ] Add release channel/tester setup in Meta Wearables Developer Center.
