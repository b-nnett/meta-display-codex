# OTA helpers

## Ground rules

- Never put auth tokens on the command line or in files.
- Export `META_AUTHORIZATION` in the shell that runs the helper. The helpers
  accept either the raw token or an `OAuth ...` value.
- Keep response JSON files, but scan them before sharing. They should contain
  firmware metadata and CDN URLs, not auth material.
- Prefer the app's numeric firmware versions. Display versions such as
  `125.0.0.190.412` may not be accepted by Graph/AR OTA endpoints.

## Auth source in a rooted emulator

The Meta AI app stores the account token used by the legacy Stella OTA checker
in:

```text
/data/data/com.facebook.stella/app_light_prefs/com.facebook.stella/meta_token_storage
key: meta_account_access_token
```

The session token that worked for the Constellation/Neural Band GraphQL path is
in:

```text
/data/data/com.facebook.stella/app_light_prefs/com.facebook.stella/meta_user_session
key: AT
```

Do not print either value. Extract it into process memory and export only in the
current shell:

```sh
export META_AUTHORIZATION='<redacted token value>'
```

## Neural Band / system firmware lookup

`fetch_constellation_system_ota.py` mirrors the Ceres/Neural Band system OTA
path used by the app:

- endpoint: `https://ar.graph.meta.com/graphql`
- friendly name: `FetchSystemUpdates`
- root field: `xar_fetch_constellation_system_updates`
- client document id: `297447816511635678041173512248`
- request variable: `fetch_request.topology_fetch_update_info[]`
- request fields: `custom_ota_fetch_type`, `device_serial_number`,
  `device_type`, `full_update_only`, `fw_version`
- app-derived device type format: `ota.<DeviceSystemInfo.device_type>.user`

Command template:

```sh
export META_AUTHORIZATION='<redacted token value>'
python3 tools/ota/fetch_constellation_system_ota.py \
  --serial 306GP9BH4N000J \
  --version '<numeric firmware version to report>' \
  --device-type ota.ceres.user \
  --download
```

The server may return no update if the reported version is already current, if
the device type is wrong, or if the logged-in account/session is not eligible
for that serial. A cached successful response from this session is:

```text
firmware/meta_neural_band_919024347_fetch_response.json
```

That response contained:

```text
target_version: 919024347
base_version: 1
build_number_display_name: 5
file_size: 10537961
file_checksum: 41f7bd4bf3a176a4faf6bbcef6148b6adfd09d665b927f03ac0b1b9170a02101
release_tag: normal
```

The downloaded file is a zip payload. The verified local copy is:

```text
firmware/meta_neural_band_919024347_ota.zip
```

The zip contains:

```text
manifest.json
cert.pem
manifest_signature.txt
FW/fw_blob.bin
ML/ml_blob.bin
```

## Glasses firmware lookup

`fetch_stella_ota.py` mirrors the Meta AI app's Stella/smart-glasses OTA checker:

- endpoint path: `firmware_ota_update`
- default host: `https://ar-genai.graph.meta.com/firmware_ota_update`
- alternate host: `https://ar.graph.meta.com/firmware_ota_update`
- request fields: `access_token`, `device_type`, `version`, `device_serial`, `fields`
- app quirk: request is `POST`, but includes `method=GET` as a form parameter
- response: top-level `update_interval`, optional `metadata`, and optional `ota[]`

The script reads auth only from `META_AUTHORIZATION`.

```sh
export META_AUTHORIZATION='<redacted authorization value>'
python3 tools/ota/fetch_stella_ota.py \
  --serial 2Y0YBYPJ0H0015 \
  --version '<numeric firmware version>' \
  --device-type ota.hypernova.user \
  --host https://ar.graph.meta.com/firmware_ota_update \
  --no-authorization-header \
  --download
```

The exact glasses `device_type` is derived by the app as:

```text
ota.<DeviceSystemInfo.device_type>.<DeviceSystemInfo.build_flavor>
```

Candidate families visible in this APK include `supernova`, `greatsupernova`,
`hypernova`, `paloma`, `spritz`, and `aperolbellini`.

For the glasses serial we tested (`2Y0YBYPJ0H0015`), the emulator was not paired
to the glasses (`AllDeviceRecords(records=[])`), so the app did not have the
real `DeviceSystemInfo` row. The legacy endpoint accepted numeric versions and
returned `update_interval`, but no `ota[]` payload for the visible candidates.

To try the visible user-channel candidates for the provided glasses:

```sh
export META_AUTHORIZATION='<redacted authorization value>'
tools/ota/try_glasses_ota_candidates.sh
```

## Newer Constellation glasses queries

The APK also contains Constellation GraphQL OTA queries:

```text
FetchConstellationUpdates:        client_doc_id 155904535312145351313127065007
FetchFirmwareBuildReleaseNotes:   client_doc_id 318196474216952449187050460246
FetchSystemUpdates:               client_doc_id 297447816511635678041173512248
```

`FetchFirmwareBuildReleaseNotes` succeeded with:

```text
endpoint: https://ar.graph.meta.com/graphql
form keys: client_doc_id, fb_api_req_friendly_name, variables
variables.fetch_request.constellation_updates_request_info[]
```

For glasses it returned `firmware_update_info: null` against our guessed device
types, which is expected if the serial is not associated with the logged-in app
state or if the wrong product/build flavor is supplied.

For display glasses with serial prefix `2Y`, the emulator pre-pair asset bundle
references `Greatwhite-PairingMode-CaseVideoAsset`, and the APK constellation
device enum maps `GREATWHITE` to `greatwhite` / ordinal `5`. The OTA device type
builder is:

```text
ota.<DeviceSystemInfo.deviceName>.<DeviceSystemInfo.buildFlavor>
```

So the highest-confidence API value for this serial family is:

```text
ota.greatwhite.user
```

The fuller `FetchConstellationUpdates` payload shape is:

```json
{
  "fetch_request": {
    "constellation_updates_request_info": [
      {
        "device_type": "ota.greatwhite.user",
        "device_serial": "2Y0YBYPJ0H0015",
        "device_firmware_version": "65394930068600080",
        "device_feature_list": [],
        "device_artifact_list": [],
        "device_firmware_full_update_only": true,
        "device_firmware_rollout_token": null,
        "device_manage_mode": null
      }
    ]
  }
}
```

With the emulator session token this returned HTTP 200 and a valid GraphQL
response, but `firmware_update_info: null` and `resource_updates_info: []`.
Changing `device_firmware_full_update_only` to `false` did not expose a delta
artifact. This suggests the API path and product key are correct, but the server
is not offering an eligible update for the current logged-in app state / serial /
version tuple.

If the glasses are already on the latest build, the same query can still return
the current full OTA by sending a very low current firmware version:

```text
device_type: ota.greatwhite.user
device_serial: 2Y0YBYPJ0H0015
device_firmware_version: 1
device_firmware_full_update_only: true
```

That returned:

```text
target_version: 65394930068600080
build_number_display_name: 125
release_channel_id: 1489521022200485
file_size: 1420356371
file_checksum: 1f9e817737a35360fbde3b5b0557fd20f5b1eb11b8be522cacce2dde366791d7
```

Downloaded and verified:

```text
firmware/glasses_greatwhite_65394930068600080_ota.zip
sha256: 1f9e817737a35360fbde3b5b0557fd20f5b1eb11b8be522cacce2dde366791d7
size: 1420356371
```

The archive is a standard Android A/B OTA zip containing `payload.bin`,
`payload_properties.txt`, metadata, care map, and OTA cert.
