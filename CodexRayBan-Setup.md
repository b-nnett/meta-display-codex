# Codex Ray-Ban iOS Setup

## Xcode

1. Open `CodexRayBan.xcodeproj`.
2. Select the `CodexRayBan` target.
3. In Signing & Capabilities, choose your Apple Developer team.
4. Keep the bundle identifier as `com.example.codexrayban`, or update it in the project and in the Apple App Site Association file.
5. Configure private local build settings for `CODEX_OAUTH_CLIENT_ID`, `MWDAT_META_APP_ID`, and `MWDAT_CLIENT_TOKEN`.

## Meta Wearables DAT

The app is configured with:

- URL scheme: `codexrayban://`
- DAT modules: `MWDATCore`, `MWDATDisplay`
- DAT App Model: `MWDAT.DAMEnabled = true`
- External accessory protocol: `com.meta.ar.wearable`

The project intentionally commits placeholders only. Keep Apple team IDs, OAuth client IDs, Meta app IDs, and DAT client tokens in local Xcode settings or an untracked xcconfig.

On a test phone, install the latest Meta AI app, enable Developer Mode for the glasses, run the app, then use Settings > Register.

## Universal Links

The entitlement currently uses:

```text
applinks:example.com
```

Host `UniversalLinks/apple-app-site-association.example` as:

```text
https://example.com/.well-known/apple-app-site-association
```

Serve it without a file extension and with `application/json`.

There is also a Cloudflare Worker version in `cloudflare/`. If Wrangler is installed and authenticated with access to `example.com`, deploy it with:

```sh
cd cloudflare
wrangler deploy
```
