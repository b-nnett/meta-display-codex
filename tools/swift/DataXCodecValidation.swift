import Foundation
import CoreBluetooth
import CryptoKit

@inline(__always)
func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
  if !condition() {
    fputs("FAIL: \(message)\n", stderr)
    exit(1)
  }
}

func data(_ bytes: [UInt8]) -> Data {
  Data(bytes)
}

func validateBandScanner() {
  expect(BandScanner.exactBandName == "Meta Band 000J", "BandScanner exact target name")
  expect(BandScanner.isExactTargetBand(name: "Meta Band 000J"), "BandScanner exact band matches")
  expect(BandScanner.isExactTargetBand(name: "meta band 000j"), "BandScanner exact band is case-insensitive")
  expect(!BandScanner.isExactTargetBand(name: "Meta Band 000K"), "BandScanner rejects nearby serial suffix")
  expect(!BandScanner.isExactTargetBand(name: nil), "BandScanner rejects nil exact name")

  expect(BandScanner.isLikelyBand(name: "Meta Band 000J", advertisementSummary: ""), "BandScanner likely detects Meta band name")
  expect(BandScanner.isLikelyBand(name: "HwZ_fb152dd2d7002b2a12", advertisementSummary: ""), "BandScanner likely detects HwZ pairing-mode name")
  expect(BandScanner.isLikelyBand(name: "Ceres Wrist", advertisementSummary: ""), "BandScanner likely detects Ceres name")
  expect(BandScanner.isLikelyBand(name: nil, advertisementSummary: "serviceData=neural-band"), "BandScanner likely detects neural advertisement")
  expect(!BandScanner.isLikelyBand(name: "Keyboard", advertisementSummary: "service=180f"), "BandScanner rejects unrelated peripheral")

  let exact = DiscoveredPeripheral(
    id: UUID(),
    name: "Meta Band 000J",
    rssi: -55,
    advertisementSummary: "",
    isCandidate: true,
    isExactBand: true
  )
  let likely = DiscoveredPeripheral(
    id: UUID(),
    name: "Neural Wrist",
    rssi: -42,
    advertisementSummary: "",
    isCandidate: true,
    isExactBand: false
  )
  let hwz = DiscoveredPeripheral(
    id: UUID(),
    name: "HwZ_fb152dd2d7002b2a12",
    rssi: -30,
    advertisementSummary: "",
    isCandidate: true,
    isExactBand: false
  )
  let unrelated = DiscoveredPeripheral(
    id: UUID(),
    name: "Keyboard",
    rssi: -20,
    advertisementSummary: "",
    isCandidate: false,
    isExactBand: false
  )
  expect(exact.candidatePriority == 4, "BandScanner exact priority is highest")
  expect(likely.candidatePriority == 2, "BandScanner likely candidate priority")
  expect(hwz.candidatePriority == 1, "BandScanner HwZ priority stays below named likely candidates")
  expect(unrelated.candidatePriority == 0, "BandScanner unrelated priority")

  let advertisement = BandScanner.advertisementSummary([
    "kCBAdvDataTimestamp": 123,
    "kCBAdvDataLocalName": "Meta Band 000J",
    "kCBAdvDataManufacturerData": Data([0xab, 0xcd]),
    "kCBAdvDataServiceUUIDs": [CBUUID(string: "FD5F")]
  ])
  expect(!advertisement.contains("Timestamp"), "BandScanner advertisement summary drops volatile timestamp")
  expect(advertisement.contains("kCBAdvDataLocalName=Meta Band 000J"), "BandScanner advertisement summary includes local name")
  expect(advertisement.contains("kCBAdvDataManufacturerData=abcd"), "BandScanner advertisement summary hex encodes manufacturer data")
  expect(advertisement.contains("kCBAdvDataServiceUUIDs=FD5F"), "BandScanner advertisement summary lists service UUIDs")
}

func validateGattSession() {
  expect(GattSession.psmFromLittleEndianValue(Data([0xff, 0x00])) == 255, "GattSession decodes little-endian DataX PSM")
  expect(GattSession.psmFromLittleEndianValue(Data([0x80, 0x00])) == 128, "GattSession decodes minimum accepted PSM shape")
  expect(GattSession.psmFromLittleEndianValue(Data([0x00])) == nil, "GattSession rejects short PSM value")
  expect(GattSession.psmFromLittleEndianValue(Data([0x00, 0x01, 0x02])) == nil, "GattSession rejects long PSM value")

  expect(GattSession.deviceInfoField(for: CBUUID(string: "2A25")) == "serial", "GattSession serial UUID")
  expect(GattSession.deviceInfoField(for: CBUUID(string: "2A26")) == "firmware", "GattSession firmware UUID")
  expect(GattSession.deviceInfoField(for: CBUUID(string: "2A29")) == "manufacturer", "GattSession manufacturer UUID")
  expect(GattSession.deviceInfoField(for: CBUUID(string: "2A24")) == "model", "GattSession model UUID")
  expect(GattSession.deviceInfoField(for: CBUUID(string: "2A19")) == nil, "GattSession battery UUID is not device info")

  expect(GattSession.propertiesDescription([]) == "none", "GattSession empty properties")
  let properties: CBCharacteristicProperties = [.read, .notify, .writeWithoutResponse]
  expect(
    GattSession.propertiesDescription(properties) == "read,writeWithoutResponse,notify",
    "GattSession property description order"
  )
}

func validateL2CAPSession() {
  expect(L2CAPSession.parsePSMText("255") == 255, "L2CAPSession parses decimal PSM")
  expect(L2CAPSession.parsePSMText(" 0xff ") == 255, "L2CAPSession parses hex PSM")
  expect(L2CAPSession.parsePSMText("0X80") == 128, "L2CAPSession parses uppercase hex prefix")
  expect(L2CAPSession.parsePSMText("") == nil, "L2CAPSession rejects empty PSM text")
  expect(L2CAPSession.parsePSMText("not-a-psm") == nil, "L2CAPSession rejects invalid PSM text")
  expect(L2CAPSession.parsePSMText("70000") == nil, "L2CAPSession rejects out-of-UInt16 PSM")

  expect(!L2CAPSession.isDynamicLEPSM(0x007f), "L2CAPSession rejects below dynamic LE PSM range")
  expect(L2CAPSession.isDynamicLEPSM(0x0080), "L2CAPSession accepts lower dynamic LE PSM range")
  expect(L2CAPSession.isDynamicLEPSM(0x00ff), "L2CAPSession accepts upper dynamic LE PSM range")
  expect(!L2CAPSession.isDynamicLEPSM(0x0100), "L2CAPSession rejects above dynamic LE PSM range")

  expect(L2CAPSession.streamStatusDescription(.notOpen) == "notOpen", "L2CAPSession stream status notOpen")
  expect(L2CAPSession.streamStatusDescription(.open) == "open", "L2CAPSession stream status open")
  expect(L2CAPSession.streamStatusDescription(.writing) == "writing", "L2CAPSession stream status writing")
  expect(L2CAPSession.streamStatusDescription(.error) == "error", "L2CAPSession stream status error")
}

func validateGestureEnableRPC() {
  let payload = WISProtocol.streamControlEnableGesturesRpc(seq: 1)
  expect(payload.hexString == "080122021801", "gesture-enable RPC payload")

  let frame = try! DataXFrameEncoder.encode(
    baseID: 0x8000,
    payload: payload,
    extensions: WISProtocol.dataXExtensions(appID: .rpc, messageType: .request)
  )
  expect(frame.hexString == "800e80008100ce5602000314080122021801", "WIS RPC DataX frame bytes")

  var decoder = DataXFrameDecoder()
  let frames = decoder.append(frame)
  expect(frames.count == 1, "one decoded RPC frame")
  expect(frames[0].bodyLength == 14, "RPC frame body length includes extensions")
  expect(frames[0].baseID == 0x8000, "RPC frame base id")
  expect(frames[0].hasExtensions, "RPC frame has extensions")
  expect(frames[0].extensions.count == 2, "RPC frame extension count")
  expect(frames[0].extensions[0].type == 1, "RPC frame channel alias extension")
  expect(frames[0].extensions[0].value == WISProtocol.localServiceID, "RPC frame channel alias value")
  expect(frames[0].decodedAppID == WISProtocol.AppID.rpc.rawValue, "RPC frame app id")
  expect(frames[0].decodedMessageType == WISProtocol.MessageType.request.rawValue, "RPC frame message type")
  expect(frames[0].payload == payload, "RPC frame payload")
}

func validateDecoderBuffering() {
  let gesturePayload = data([0x08, 0x2a, 0x10, 0xe7, 0x07, 0x18, 0x01, 0x20, 0x03, 0x28, 0x01])
  let encoded = try! DataXFrameEncoder.encode(
    baseID: 0x8000,
    payload: gesturePayload,
    extensions: WISProtocol.dataXExtensions(appID: .emgImu, messageType: .gesture)
  )

  var decoder = DataXFrameDecoder()
  expect(decoder.append(encoded.prefix(5)).isEmpty, "partial frame waits for more data")
  let frames = decoder.append(encoded.dropFirst(5))
  expect(frames.count == 1, "partial frame completes after second chunk")
  expect(frames[0].decodedAppID == WISProtocol.AppID.emgImu.rawValue, "gesture frame app id")
  expect(frames[0].decodedMessageType == WISProtocol.MessageType.gesture.rawValue, "gesture frame message type")
  expect(frames[0].payload == gesturePayload, "gesture frame payload")
  expect(frames[0].payloadFingerprint == gesturePayload.shortSHA256Fingerprint, "gesture frame payload fingerprint")
}

func validateReservedHeaderBit14() {
  let payload = data([0x08, 0x01])
  let encoded = try! DataXFrameEncoder.encode(
    baseID: 0x8000,
    payload: payload,
    extensions: [],
    reservedHeaderBit14: true
  )
  expect(encoded.hexString == "400280000801", "reserved bit 14 encoded outside body length")

  var decoder = DataXFrameDecoder()
  let frames = decoder.append(encoded)
  expect(frames.count == 1, "reserved bit 14 frame decodes")
  expect(frames[0].bodyLength == payload.count, "reserved bit 14 is masked from body length")
  expect(frames[0].reservedHeaderBit14, "reserved bit 14 is surfaced for logging")
  expect(!frames[0].hasExtensions, "reserved bit 14 does not imply extensions")
  expect(frames[0].payload == payload, "reserved bit 14 payload")
}

func validateAirShieldAuthServiceMapping() {
  expect(AirShieldAuthService.serviceName(36) == "identity", "AirShield auth identity service name")
  expect(AirShieldAuthService.serviceName(77) == "prototype_identity", "AirShield auth prototype service name")
  expect(AirShieldAuthService.serviceName(5) == nil, "AirShield auth ignores link setup service")
  expect(AirShieldAuthService.typedBufferName(serviceID: 36, typedBufferType: 12288) == "IDENTITY_REQUEST", "AirShield auth identity request type")
  expect(AirShieldAuthService.typedBufferName(serviceID: 36, typedBufferType: 12289) == "IDENTITY_RESPONSE", "AirShield auth identity response type")
  expect(AirShieldAuthService.typedBufferName(serviceID: 77, typedBufferType: 8192) == "REGISTER_KEY", "AirShield auth prototype register key type")
  expect(AirShieldAuthService.typedBufferName(serviceID: 77, typedBufferType: 8193) == "KEY_ACCEPTED", "AirShield auth prototype key accepted type")

  let identityFrame = try! AirShieldAuthService.encodeDataXFrame(
    serviceID: AirShieldAuthService.identityServiceID,
    typedBufferType: 12288,
    payload: Data([0x08, 0x01]),
    baseID: NativeDataXLocalChannel.baseID(localChannelID: 0)
  )
  expect(
    identityFrame.hexString == "800a800081000024020030000801",
    "AirShield auth native LocalChannel openChannel(36).send(type=12288) frame"
  )
  var identityDecoder = DataXFrameDecoder()
  let identityFrames = identityDecoder.append(identityFrame)
  expect(identityFrames.count == 1, "AirShield auth identity frame decodes")
  expect(identityFrames[0].airShieldAuthServiceName == "identity", "AirShield auth identity frame service")
  expect(identityFrames[0].airShieldAuthTypedBufferName == "IDENTITY_REQUEST", "AirShield auth identity frame type")
  expect(identityFrames[0].description.contains("airShieldAuthType=IDENTITY_REQUEST"), "AirShield auth identity description")

  let prototypeFrame = try! AirShieldAuthService.encodeDataXFrame(
    serviceID: AirShieldAuthService.prototypeIdentityServiceID,
    typedBufferType: 8192,
    payload: Data([0x0a, 0x02, 0xaa, 0xbb]),
    baseID: NativeDataXLocalChannel.baseID(localChannelID: 0)
  )
  var prototypeDecoder = DataXFrameDecoder()
  let prototypeFrames = prototypeDecoder.append(prototypeFrame)
  expect(prototypeFrames.count == 1, "AirShield auth prototype frame decodes")
  expect(prototypeFrames[0].airShieldAuthServiceName == "prototype_identity", "AirShield auth prototype frame service")
  expect(prototypeFrames[0].airShieldAuthTypedBufferName == "REGISTER_KEY", "AirShield auth prototype frame type")
}

func field(_ summary: AirShieldAuthPayloadSummary?, named name: String) -> AirShieldAuthPayloadSummary.Field? {
  summary?.fields.first { $0.name == name }
}

func validateAirShieldAuthPayloadDecode() {
  var enableTrustPayload = Data()
  let identifier = Data((0..<32).map { UInt8($0 & 0xff) })
  let signature = Data((0..<64).map { UInt8(0x80 + ($0 & 0x3f)) })
  enableTrustPayload.appendProtoLengthDelimited(field: 1, identifier)
  enableTrustPayload.appendProtoLengthDelimited(field: 2, signature)
  enableTrustPayload.appendProtoVarint(field: 3, 2)

  let enableTrust = AirShieldAuthPayloadDecoder.decode(
    serviceID: AirShieldAuthService.identityServiceID,
    typedBufferType: 4096,
    payload: enableTrustPayload
  )
  expect(enableTrust?.serviceName == "identity", "AirShield auth payload identity service")
  expect(enableTrust?.typedBufferName == "ENABLE_TRUST", "AirShield auth payload enable trust type")
  expect(field(enableTrust, named: "identifier")?.length == 32, "AirShield EnableTrust identifier length")
  expect(field(enableTrust, named: "identifier")?.fingerprint == identifier.shortSHA256Fingerprint, "AirShield EnableTrust identifier fingerprint")
  expect(field(enableTrust, named: "signature")?.length == 64, "AirShield EnableTrust signature length")
  expect(field(enableTrust, named: "provisioning_capabilities")?.value == "2", "AirShield EnableTrust provisioning capabilities")
  expect(enableTrust?.unknownFieldCount == 0, "AirShield EnableTrust no unknown fields")

  var identityResponsePayload = Data()
  let certificate = Data([0xaa, 0xbb, 0xcc])
  let secondaryCertificate = Data([0xdd, 0xee])
  identityResponsePayload.appendProtoLengthDelimited(field: 1, certificate)
  identityResponsePayload.appendProtoLengthDelimited(field: 2, Data("306GP9BH4N000J".utf8))
  identityResponsePayload.appendProtoLengthDelimited(field: 3, Data("registration-package".utf8))
  identityResponsePayload.appendProtoVarint(field: 4, 1)
  identityResponsePayload.appendProtoLengthDelimited(field: 5, secondaryCertificate)

  let identityResponse = AirShieldAuthPayloadDecoder.decode(
    serviceID: AirShieldAuthService.identityServiceID,
    typedBufferType: 12289,
    payload: identityResponsePayload
  )
  expect(identityResponse?.typedBufferName == "IDENTITY_RESPONSE", "AirShield IdentityResponse type")
  expect(field(identityResponse, named: "certificate")?.length == 3, "AirShield IdentityResponse certificate length")
  expect(field(identityResponse, named: "serial")?.value == "306GP9BH4N000J", "AirShield IdentityResponse serial")
  expect(field(identityResponse, named: "registration_challenge_request_package")?.value == "registration-package", "AirShield IdentityResponse registration package")
  expect(field(identityResponse, named: "drk_certificate_present")?.value == "true", "AirShield IdentityResponse DRK bool")
  expect(field(identityResponse, named: "secondary_certificate")?.fingerprint == secondaryCertificate.shortSHA256Fingerprint, "AirShield IdentityResponse secondary cert fingerprint")

  var registerKeyPayload = Data()
  let pubkey = Data((0..<64).map { UInt8(0x40 + ($0 & 0x3f)) })
  registerKeyPayload.appendProtoLengthDelimited(field: 1, pubkey)
  registerKeyPayload.appendProtoLengthDelimited(field: 2, Data("prototype-user".utf8))

  let registerKey = AirShieldAuthPayloadDecoder.decode(
    serviceID: AirShieldAuthService.prototypeIdentityServiceID,
    typedBufferType: 8192,
    payload: registerKeyPayload
  )
  expect(registerKey?.serviceName == "prototype_identity", "AirShield prototype auth payload service")
  expect(registerKey?.typedBufferName == "REGISTER_KEY", "AirShield RegisterKey type")
  expect(field(registerKey, named: "pubkey")?.length == 64, "AirShield RegisterKey pubkey length")
  expect(field(registerKey, named: "user_id")?.value == "prototype-user", "AirShield RegisterKey user id")

  var keyAcceptedPayload = Data()
  let acceptorPubkey = Data((0..<64).map { UInt8(0x10 + ($0 & 0x3f)) })
  let keyDerivationKey = Data((0..<64).map { UInt8(0x20 + ($0 & 0x3f)) })
  keyAcceptedPayload.appendProtoLengthDelimited(field: 1, acceptorPubkey)
  keyAcceptedPayload.appendProtoLengthDelimited(field: 2, keyDerivationKey)
  keyAcceptedPayload.appendProtoVarint(field: 9, 7)

  let keyAccepted = AirShieldAuthPayloadDecoder.decode(
    serviceID: AirShieldAuthService.prototypeIdentityServiceID,
    typedBufferType: 8193,
    payload: keyAcceptedPayload
  )
  expect(keyAccepted?.typedBufferName == "KEY_ACCEPTED", "AirShield KeyAccepted type")
  expect(field(keyAccepted, named: "acceptor_pubkey")?.length == 64, "AirShield KeyAccepted acceptor pubkey length")
  expect(field(keyAccepted, named: "key_derivation_key")?.length == 64, "AirShield KeyAccepted KDK length")
  expect(keyAccepted?.unknownFieldCount == 1, "AirShield auth payload counts unknown fields")

  let emptyIdentityRequest = AirShieldAuthPayloadDecoder.decode(
    serviceID: AirShieldAuthService.identityServiceID,
    typedBufferType: 12288,
    payload: Data()
  )
  expect(emptyIdentityRequest?.fields.isEmpty == true, "AirShield IdentityRequest is empty")

  let decodedFrame = try! DataXFrameEncoder.encode(
    baseID: 0x8000,
    payload: enableTrustPayload,
    extensions: [
      DataXExtensionWord(rawType: 1, value: AirShieldAuthService.identityServiceID),
      DataXExtensionWord(rawType: 2, value: 4096)
    ]
  )
  var decoder = DataXFrameDecoder()
  let frames = decoder.append(decodedFrame)
  expect(frames.count == 1, "AirShield auth payload DataX frame decodes")
  expect(frames[0].decodedAirShieldAuthPayload?.typedBufferName == "ENABLE_TRUST", "AirShield auth payload attached to DataX frame")
  expect(frames[0].description.contains("airShieldAuthPayload="), "AirShield auth payload appears in frame description")
}

func validateAirShieldFramingSizes() {
  expect(AirShieldFraming.outerFrameSize(forPlaintextLength: 0) == 0, "AirShield empty outer frame size")
  expect(AirShieldFraming.outerFrameSize(forPlaintextLength: 1) == 25, "AirShield one-byte payload rounds to one block plus overhead")
  expect(AirShieldFraming.outerFrameSize(forPlaintextLength: 16) == 25, "AirShield 16-byte payload uses one block plus overhead")
  expect(AirShieldFraming.outerFrameSize(forPlaintextLength: 17) == 41, "AirShield 17-byte payload rounds to two blocks plus overhead")
  expect(AirShieldFraming.outerFrameSize(forPlaintextLength: 0x1000) == 0x1009, "AirShield maximum payload size")
  expect(AirShieldFraming.outerFrameSize(forPlaintextLength: 0x1001) == 0x1009, "AirShield over-limit error value")
  expect(AirShieldFraming.validationPrefixScratchModeOffset == 0, "AirShield validation prefix scratch mode offset")
  expect(AirShieldFraming.validationPrefixScratchCounterOffset == 4, "AirShield validation prefix scratch counter offset")
  expect(AirShieldFraming.validationPrefixModeLength == 4, "AirShield validation prefix mode length")
  expect(AirShieldFraming.validationPrefixFrameCounterLength == 4, "AirShield validation prefix frame counter length")
  expect(AirShieldFraming.validationPrefixAuthenticatedFrameOffset == 8, "AirShield validation prefix authenticated frame offset")

  var oneBlockFrame = Data(repeating: 0, count: 25)
  oneBlockFrame[8] = 0
  expect(AirShieldFraming.requiredOuterFrameSize(fromCipherPayloadIndicator: 0) == 25, "AirShield indicator zero outer length")
  expect(AirShieldFraming.cipherPayloadSize(fromOuterFrame: oneBlockFrame) == 16, "AirShield indicator zero cipher payload")

  var twoBlockFrame = Data(repeating: 0, count: 41)
  twoBlockFrame[8] = 1
  expect(AirShieldFraming.requiredOuterFrameSize(fromCipherPayloadIndicator: 1) == 41, "AirShield indicator one outer length")
  expect(AirShieldFraming.cipherPayloadSize(fromOuterFrame: twoBlockFrame) == 32, "AirShield indicator one cipher payload")
  expect(AirShieldFraming.cipherPayloadSize(fromOuterFrame: twoBlockFrame, availableLength: 40) == nil, "AirShield rejects incomplete indicated frame")

  var framed = Data((0..<41).map { UInt8($0 & 0xff) })
  framed[8] = 1
  let metadata = AirShieldFraming.parseOuterFrameMetadata(from: framed)
  expect(metadata?.validationPrefix == Data(0..<8), "AirShield validation prefix range")
  expect(metadata?.cipherPayloadIndicator == 1, "AirShield metadata indicator")
  expect(metadata?.outerFrameRange == 0..<41, "AirShield metadata outer range")
  expect(metadata?.cipherPayloadRange == 9..<41, "AirShield metadata cipher payload range")
  expect(metadata?.cipherPayloadSize == 32, "AirShield metadata cipher payload size")
  expect(metadata.map { AirShieldFraming.validationPrefixAuthenticatedFrameRange(from: $0) } == 8..<41, "AirShield validation prefix frame range includes indicator and cipher payload")
  let authenticatedInputWithMode = AirShieldFraming.validationPrefixAuthenticatedInput(
    runtimeValidationMode: 0x56001234,
    frameCounter: 0x01020304,
    outerFrame: framed,
    metadata: metadata!
  )
  expect(
    authenticatedInputWithMode?.hexString == "341200560403020101090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728",
    "AirShield validation prefix input includes little-endian mode, little-endian counter, then frame byte 8 onward"
  )
  let authenticatedInputWithoutMode = AirShieldFraming.validationPrefixAuthenticatedInput(
    runtimeValidationMode: 0,
    frameCounter: 0x01020304,
    outerFrame: framed,
    metadata: metadata!
  )
  expect(
    authenticatedInputWithoutMode?.hexString == "0403020101090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728",
    "AirShield validation prefix input omits zero mode word"
  )
  let validationKey = Data((0..<32).map { UInt8($0 & 0xff) })
  let validationPrefixCandidate = AirShieldFraming.validationPrefixCandidate(
    validationKey: validationKey,
    runtimeValidationMode: 0x56001234,
    frameCounter: 0x01020304,
    outerFrame: framed,
    metadata: metadata!
  )
  expect(
    validationPrefixCandidate?.hexString == "e0d143a1ef4ac138",
    "AirShield validation prefix candidate is first eight bytes of HMAC-SHA256 over mapped input"
  )
  expect(
    AirShieldFraming.validationPrefixCandidate(
      validationKey: Data([0x00]),
      runtimeValidationMode: 0x56001234,
      frameCounter: 0x01020304,
      outerFrame: framed,
      metadata: metadata!
    ) == nil,
    "AirShield validation prefix candidate rejects non-native validation-key length"
  )
  expect(AirShieldFraming.parseOuterFrameMetadata(from: framed, availableLength: 40) == nil, "AirShield metadata rejects incomplete frame")

  expect(AirShieldFraming.runtimeValidationMode(configLow16: 0x1234, configHighByte: 0x56) == 0x56001234, "AirShield runtime validation mode packing")
  expect(!AirShieldFraming.validationPrefixIncludesModeWord(runtimeValidationMode: 0), "AirShield zero validation mode is not included in prefix state")
  expect(AirShieldFraming.validationPrefixIncludesModeWord(runtimeValidationMode: 0x00000001), "AirShield low validation mode byte is included in prefix state")
  expect(AirShieldFraming.validationPrefixIncludesModeWord(runtimeValidationMode: 0x56000000), "AirShield high validation mode byte is included in prefix state")
}

func validateAirShieldSelectedTransformCounter() {
  expect(AirShieldFraming.selectedTransformDescriptor == 0x00072490, "AirShield selected transform descriptor")
  expect(AirShieldFraming.selectedTransformCipherName == "AES-256-CTR", "AirShield selected transform cipher")
  expect(AirShieldFraming.selectedTransformMode == 2, "AirShield selected transform mode")
  expect(AirShieldFraming.selectedTransformMaterialBits == 0x100, "AirShield selected transform material bits")
  expect(AirShieldFraming.selectedTransformGenericSetter == 0x64cfe0, "AirShield selected transform generic setter helper")
  expect(AirShieldFraming.selectedTransformMode2CompletionHelper == 0xdb2dec, "AirShield selected transform mode-2 completion helper")
  expect(AirShieldFraming.selectedTransformCTRPayloadHelper == 0xdb2f54, "AirShield selected transform CTR payload helper")
  expect(AirShieldFraming.selectedTransformAESBlockHelper == 0x5d3e44, "AirShield selected transform AES block helper")
  expect(AirShieldFraming.nativeHashHalfLength == 32, "AirShield native hash half length")
  expect(AirShieldFraming.nativeHashByteLength == 64, "AirShield native hash byte length")
  expect(AirShieldFraming.javaHashToByteArrayLength == 32, "AirShield Java Hash.toByteArray length")
  expect(AirShieldFraming.javaSignatureToByteArrayLength == 64, "AirShield Java Signature.toByteArray length")
  expect(AirShieldFraming.challengeDigestFoldInputLength == 64, "AirShield challenge digest fold input length")
  expect(AirShieldFraming.privateKeyDeriveNativeThunk == 0xda455c, "AirShield PrivateKey.deriveNative thunk")
  expect(AirShieldFraming.privateKeyDeriveNativeImplementation == 0xda4e94, "AirShield PrivateKey.deriveNative implementation")
  expect(AirShieldFraming.privateKeyDeriveSharedHashHelper == 0xdb1f1c, "AirShield shared-hash derive helper")
  expect(AirShieldFraming.privateKeySignNativeThunk == 0xda4568, "AirShield PrivateKey.signNative thunk")
  expect(AirShieldFraming.privateKeySignNativeImplementation == 0xda4574, "AirShield PrivateKey.signNative implementation")
  expect(AirShieldFraming.privateKeyRecoverPublicKeyNativeThunk == 0xda3f28, "AirShield PrivateKey.recoverPublicKey thunk")
  expect(AirShieldFraming.privateKeyRecoverPublicKeyHelper == 0xdb2148, "AirShield recover-public-key helper")
  expect(AirShieldFraming.nativePublicKeyCopyHelper == 0xdb2240, "AirShield native public key copy helper")
  expect(AirShieldFraming.builderTranscriptChallengeWindowOffset == 0x108, "AirShield transcript challenge window offset")
  expect(AirShieldFraming.builderTranscriptChallengeWindowLength == 16, "AirShield transcript challenge window length")
  expect(AirShieldFraming.builderChallengePayloadOffset == 0x110, "AirShield challenge native payload offset")
  expect(AirShieldFraming.builderChallengePayloadLength == 16, "AirShield challenge native payload length")
  expect(AirShieldFraming.builderLocalNativeHashSourceOffset == 0x118, "AirShield local native hash source offset")
  expect(AirShieldFraming.builderLocalNativeHashActiveFlagOffset == 0x210, "AirShield local native hash active flag offset")
  expect(AirShieldFraming.builderRemotePublicKeyStateOffset == 0x120, "AirShield remote public key native state offset")
  expect(AirShieldFraming.builderRemotePublicKeySecondaryStateOffset == 0x1e0, "AirShield remote public key secondary native state offset")
  expect(AirShieldFraming.builderRemotePublicKeyActiveFlagOffset == 0x218, "AirShield remote public key active flag offset")
  expect(AirShieldFraming.builderTranscriptMaterialWindowOffset == 0x218, "AirShield transcript material window offset")
  expect(AirShieldFraming.builderTranscriptMaterialWindowLength == 32, "AirShield transcript material window length")
  expect(AirShieldFraming.builderSeedPayloadOffset == 0x220, "AirShield seed native payload offset")
  expect(AirShieldFraming.builderSeedPayloadLength == 32, "AirShield seed native payload length")
  expect(AirShieldFraming.builderInitializationVectorPayloadOffset == 0x240, "AirShield IV native payload offset")
  expect(AirShieldFraming.builderInitializationVectorPayloadLength == 16, "AirShield IV native payload length")
  expect(AirShieldFraming.selectedTransformSetupIVLoadLowerOffset == 0x238, "AirShield selected transform IV lower load offset")
  expect(AirShieldFraming.selectedTransformSetupIVLoadUpperOffset == 0x240, "AirShield selected transform IV upper load offset")
  expect(AirShieldFraming.selectedTransformSetupIVWindowOffset == 0x238, "AirShield selected transform IV window offset")
  expect(AirShieldFraming.selectedTransformSetupIVWindowLength == 16, "AirShield selected transform IV window length")
  expect(AirShieldFraming.selectedTransformSetupSeedTailLength == 8, "AirShield selected transform setup seed tail length")
  expect(AirShieldFraming.selectedTransformSetupIVHeadLength == 8, "AirShield selected transform setup IV head length")
  expect(AirShieldFraming.cipherContextIVWindowLowerWordOffset == 0x2c, "AirShield cipher context IV lower word offset")
  expect(AirShieldFraming.cipherContextIVWindowUpperWordOffset == 0x34, "AirShield cipher context IV upper word offset")
  expect(AirShieldFraming.selectedTransformSetterIVWindowInputLength == 16, "AirShield selected transform setter IV window input length")
  expect(AirShieldFraming.selectedTransformStateKeystreamBlockOffset == 0x20, "AirShield selected transform keystream block state offset")
  expect(AirShieldFraming.selectedTransformStatePartialBlockOffset == 0x30, "AirShield selected transform partial-block state offset")
  expect(AirShieldFraming.selectedTransformStateCounterBlockOffset == 0x38, "AirShield selected transform counter block state offset")
  expect(AirShieldFraming.selectedTransformSetterDestinationOffset == AirShieldFraming.selectedTransformStateCounterBlockOffset, "AirShield setter destination is the CTR counter block")
  expect(AirShieldFraming.selectedTransformSetterCopiedLengthOffset == 0x48, "AirShield selected transform setter copied length offset")
  expect(AirShieldFraming.selectedTransformCounterIncrementStartOffset == 12, "AirShield selected transform counter increment starts at byte 12")
  expect(AirShieldFraming.challengeDigestCallerContextLength == 16, "AirShield challenge digest caller context length")
  expect(AirShieldFraming.buildRxChallengeDirectionFlag == 0, "AirShield buildRxChallenge direction flag")
  expect(AirShieldFraming.buildTxChallengeDirectionFlag == 1, "AirShield buildTxChallenge direction flag")
  expect(AirShieldFraming.builderChallengePayloadRange == 0x110..<0x120, "AirShield challenge native payload range")
  expect(AirShieldFraming.builderSeedPayloadRange == 0x220..<0x240, "AirShield seed native payload range")
  expect(AirShieldFraming.builderTranscriptChallengeWindowRange == 0x108..<0x118, "AirShield transcript challenge window range")
  expect(AirShieldFraming.builderTranscriptMaterialWindowRange == 0x218..<0x238, "AirShield transcript material window range")
  expect(AirShieldFraming.builderTranscriptChallengePayloadOverlapRange == 0x110..<0x118, "AirShield transcript challenge window overlaps first eight challenge payload bytes")
  expect(AirShieldFraming.builderTranscriptMaterialSeedOverlapRange == 0x220..<0x238, "AirShield transcript material window overlaps first 24 seed payload bytes")
  expect(AirShieldFraming.builderInitializationVectorPayloadRange == 0x240..<0x250, "AirShield IV native payload range")
  expect(AirShieldFraming.selectedTransformSetupIVWindowRange == 0x238..<0x248, "AirShield selected transform IV setup window range")
  expect(AirShieldFraming.selectedTransformSetupIVWindowPayloadOverlapRange == 0x240..<0x248, "AirShield selected transform IV setup window overlaps first eight IV payload bytes")
  expect(AirShieldFraming.selectedTransformSetupSeedTailRange == 0x238..<0x240, "AirShield selected transform setup uses final eight seed bytes")
  expect(AirShieldFraming.selectedTransformSetupIVHeadRange == 0x240..<0x248, "AirShield selected transform setup uses first eight IV bytes")
  expect(AirShieldFraming.buildDecryptionDirectionFlag == 0, "AirShield buildDecryption direction flag")
  expect(AirShieldFraming.buildEncryptionDirectionFlag == 1, "AirShield buildEncryption direction flag")
  expect(AirShieldFraming.stateSetupWorkAreaOffset == 0x190, "AirShield state setup work area offset")
  expect(AirShieldFraming.stateSetupWorkAreaLength == 64, "AirShield state setup work area length")
  expect(AirShieldFraming.stateSetupValidationKeyMaterialOffset == 0x190, "AirShield validation key material work offset")
  expect(AirShieldFraming.stateSetupValidationKeyMaterialLength == 32, "AirShield validation key material length")
  expect(AirShieldFraming.stateSetupCipherKeyMaterialOffset == 0x1b0, "AirShield cipher key material work offset")
  expect(AirShieldFraming.stateSetupCipherKeyMaterialLength == 32, "AirShield cipher key material length")
  expect(AirShieldFraming.stateSetupPrimaryFramingConfigOffset == 0x90, "AirShield primary Framing config stack offset")
  expect(AirShieldFraming.stateSetupRelayFramingConfigOffset == 0x110, "AirShield relay Framing config stack offset")
  expect(AirShieldFraming.stateSetupOptionsFrameCounterOffset == 0x00, "AirShield setup options frame counter offset")
  expect(AirShieldFraming.stateSetupOptionsHKDFOffset == 0x04, "AirShield setup options HKDF offset")
  expect(AirShieldFraming.stateSetupOptionsDefaultZeroTailOffset == 0x05, "AirShield setup options default zero tail offset")
  expect(AirShieldFraming.stateSetupOptionsDefaultZeroTailLength == 7, "AirShield setup options default zero tail length")
  expect(AirShieldFraming.stateSetupOptionsValidationModeLowOffset == 0x07, "AirShield setup options validation mode low offset")
  expect(AirShieldFraming.stateSetupOptionsValidationModeHighOffset == 0x09, "AirShield setup options validation mode high offset")
  expect(AirShieldFraming.stateSetupOptionsRelayConfigFlagOffset == 0x0b, "AirShield setup options relay config flag offset")
  expect(AirShieldFraming.stateSetupExpansionScratchOffset == 0x40, "AirShield setup expansion scratch object offset")
  expect(AirShieldFraming.stateSetupExpansionScratchInlineTagOffset == 0x60, "AirShield setup expansion scratch inline tag offset")
  expect(AirShieldFraming.stateSetupExpansionKeyMaterialOffset == 0x1b0, "AirShield setup expansion key material offset")
  expect(AirShieldFraming.stateSetupExpansionWritebackOffset == 0x1b0, "AirShield setup expansion writeback offset")
  expect(AirShieldFraming.stateSetupFinalExpansionOutputOffset == 0x1d0, "AirShield setup final expansion output object offset")
  expect(AirShieldFraming.stateSetupFinalExpansionOutputInlineTagOffset == 0x1f0, "AirShield setup final expansion output inline tag offset")
  expect(AirShieldFraming.stateSetupFinalExpansionKeyMaterialOffset == 0x190, "AirShield setup final expansion key material offset")
  expect(AirShieldFraming.stateSetupFinalExpansionWritebackOffset == 0x190, "AirShield setup final expansion writeback offset")
  expect(AirShieldFraming.stateSetupDerivationContextBufferOffset == 0x200, "AirShield setup derivation context buffer offset")
  expect(AirShieldFraming.stateSetupExplicitExpansionContextAddress == 0x25d60b, "AirShield setup explicit expansion context address")
  expect(AirShieldFraming.stateSetupExplicitExpansionContextLength == 0x88, "AirShield setup explicit expansion context length")
  expect(AirShieldFraming.framingConfigValidationKeyOffset == 0x00, "AirShield config validation key offset")
  expect(AirShieldFraming.framingConfigValidationKeyLength == 32, "AirShield config validation key length")
  expect(AirShieldFraming.framingConfigValidationKeyInlineTagOffset == 0x20, "AirShield config validation key inline tag offset")
  expect(AirShieldFraming.framingConfigCipherContextOffset == 0x28, "AirShield config cipher context offset")
  expect(AirShieldFraming.framingConfigValidationModeLowOffset == 0x78, "AirShield config validation mode low offset")
  expect(AirShieldFraming.framingConfigValidationModeHighOffset == 0x7a, "AirShield config validation mode high offset")
  expect(AirShieldFraming.framingConfigFrameCounterOffset == 0x7c, "AirShield config frame counter offset")
  expect(AirShieldFraming.runtimeValidationMacContextOffset == 0x00, "AirShield runtime validation HMAC/SHA context offset")
  expect(AirShieldFraming.runtimeValidationKeyInlineOffset == 0x08, "AirShield runtime validation inline key offset")
  expect(AirShieldFraming.runtimeValidationKeyInlineTagOffset == 0x28, "AirShield runtime validation inline key tag offset")
  expect(AirShieldFraming.runtimeCipherContextOffset == 0x30, "AirShield runtime cipher context offset")
  expect(AirShieldFraming.runtimeValidationPrefixBufferOffset == 0x80, "AirShield runtime validation prefix buffer offset")
  expect(AirShieldFraming.runtimeValidationModeOffset == 0xa0, "AirShield runtime validation mode offset")
  expect(AirShieldFraming.runtimeFrameCounterOffset == 0xa4, "AirShield runtime frame counter offset")

  var counter = Data([
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f
  ])
  let firstBlockCounter = AirShieldFraming.selectedTransformCounterBlockForCurrentCipherBlock(&counter)
  expect(firstBlockCounter?.hexString == "000102030405060708090a0b0c0d0e0f", "AirShield CTR uses current counter before increment")
  expect(counter.hexString == "000102030405060708090a0b0c0d0e10", "AirShield CTR increments last byte")

  var carryCounter = Data([
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff
  ])
  _ = AirShieldFraming.selectedTransformCounterBlockForCurrentCipherBlock(&carryCounter)
  expect(carryCounter.hexString == "00000000000000000000000100000000", "AirShield CTR carries from word 3 to word 2")

  var wrapCounter = Data(repeating: 0xff, count: 16)
  expect(AirShieldFraming.incrementSelectedTransformCounterBlock(&wrapCounter), "AirShield CTR accepts 16-byte counter")
  expect(wrapCounter == Data(repeating: 0, count: 16), "AirShield CTR wraps on full overflow")

  var invalidCounter = Data([0x00, 0x01])
  expect(!AirShieldFraming.incrementSelectedTransformCounterBlock(&invalidCounter), "AirShield CTR rejects non-16-byte counter")
  expect(invalidCounter.hexString == "0001", "AirShield CTR leaves invalid counter unchanged")
}

func validateAirShieldEncryptedFrameCandidate() {
  let oneBytePlaintext = Data([0xaa])
  expect(AirShieldFraming.nativePaddingLength(forPlaintextLength: oneBytePlaintext.count) == 15, "AirShield native padding length for one-byte payload")
  expect(
    AirShieldFraming.nativePaddedPlaintextCandidate(oneBytePlaintext)?.hexString == "aacfcfcfcfcfcfcfcfcfcfcfcfcfcfcf",
    "AirShield native padding bytes use 0xc0 plus padding length"
  )
  expect(
    AirShieldFraming.nativePaddedPlaintextCandidate(Data(repeating: 0x11, count: 15))?.suffix(1) == Data([0xc1]),
    "AirShield one-byte padding uses 0xc1"
  )
  expect(
    AirShieldFraming.nativePaddedPlaintextCandidate(Data(repeating: 0x22, count: 16))?.count == 16,
    "AirShield aligned plaintext gets no extra padding block"
  )
  expect(
    AirShieldFraming.nativePaddingLengthCandidate(fromPaddedPlaintext: Data([0xaa] + Array(repeating: 0xcf, count: 15))) == 15,
    "AirShield native padding recovery accepts repeated 0xc0 plus padding length"
  )
  expect(
    AirShieldFraming.nativePaddingLengthCandidate(fromPaddedPlaintext: Data(repeating: 0x22, count: 16)) == 0,
    "AirShield native padding recovery returns zero for no recognized padding"
  )

  let seed = Data((0..<32).map { UInt8($0 & 0xff) })
  let iv = Data((0..<16).map { UInt8(0xa0 + $0) })
  expect(
    AirShieldFraming.selectedTransformInitialCounterBlockCandidate(seed: seed, initializationVector: iv)?.hexString == "18191a1b1c1d1e1fa0a1a2a3a4a5a6a7",
    "AirShield selected transform initial counter candidate is seed tail plus IV head"
  )

  let nistAES256Key = Data([
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
  ])
  let nistCounter = Data([
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
  ])
  let nistPlaintext = Data([
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
  ])
  let nistCiphertext = AirShieldFraming.selectedTransformCTRApplyCandidate(
    input: nistPlaintext,
    cipherKey: nistAES256Key,
    initialCounterBlock: nistCounter
  )
  expect(
    nistCiphertext?.hexString == "601ec313775789a5b7a7f504bbf3d228",
    "AirShield AES-256-CTR candidate matches NIST first-block vector with explicit counter block"
  )

  let validationKey = Data((0..<32).map { UInt8($0 & 0xff) })
  let frameCandidate = AirShieldFraming.encryptedFrameCandidate(
    plaintext: nistPlaintext,
    validationKey: validationKey,
    cipherKey: nistAES256Key,
    initialCounterBlock: nistCounter,
    runtimeValidationMode: 0,
    frameCounter: 0
  )
  expect(frameCandidate?.paddedPlaintext == nistPlaintext, "AirShield encrypted-frame candidate keeps aligned plaintext unpadded")
  expect(frameCandidate?.cipherPayload == nistCiphertext, "AirShield encrypted-frame candidate embeds AES-CTR cipher payload")
  expect(frameCandidate?.validationPrefix.hexString == "a76ba489dbdd111b", "AirShield encrypted-frame candidate validation prefix fixture")
  expect(
    frameCandidate?.outerFrame.hexString == "a76ba489dbdd111b00601ec313775789a5b7a7f504bbf3d228",
    "AirShield encrypted-frame candidate outer frame fixture"
  )
  let decryptedFrameCandidate = AirShieldFraming.decryptedFrameCandidate(
    outerFrame: frameCandidate!.outerFrame,
    validationKey: validationKey,
    cipherKey: nistAES256Key,
    initialCounterBlock: nistCounter,
    runtimeValidationMode: 0,
    frameCounter: 0
  )
  expect(decryptedFrameCandidate?.plaintext == nistPlaintext, "AirShield encrypted-frame candidate decrypts aligned plaintext")
  expect(decryptedFrameCandidate?.paddingLength == 0, "AirShield decrypt candidate reports no padding for aligned plaintext")
  expect(decryptedFrameCandidate?.validationPrefix.hexString == "a76ba489dbdd111b", "AirShield decrypt candidate preserves validation prefix")
  expect(decryptedFrameCandidate?.counterSearchOffset == 0, "AirShield decrypt candidate exact counter offset")

  let paddedFrameCandidate = AirShieldFraming.encryptedFrameCandidate(
    plaintext: oneBytePlaintext,
    validationKey: validationKey,
    cipherKey: nistAES256Key,
    initialCounterBlock: nistCounter,
    runtimeValidationMode: 0,
    frameCounter: 7
  )
  let paddedDecryptedFrameCandidate = AirShieldFraming.decryptedFrameCandidate(
    outerFrame: paddedFrameCandidate!.outerFrame,
    validationKey: validationKey,
    cipherKey: nistAES256Key,
    initialCounterBlock: nistCounter,
    runtimeValidationMode: 0,
    frameCounter: 7
  )
  expect(paddedDecryptedFrameCandidate?.plaintext == oneBytePlaintext, "AirShield decrypt candidate removes native padding")
  expect(paddedDecryptedFrameCandidate?.paddingLength == 15, "AirShield decrypt candidate reports native padding length")
  let resyncedDecryptedFrameCandidate = AirShieldFraming.decryptedFrameCandidate(
    outerFrame: paddedFrameCandidate!.outerFrame,
    validationKey: validationKey,
    cipherKey: nistAES256Key,
    initialCounterBlock: nistCounter,
    runtimeValidationMode: 0,
    startingFrameCounter: 5,
    counterSearchWindow: 4
  )
  expect(resyncedDecryptedFrameCandidate?.plaintext == oneBytePlaintext, "AirShield decrypt candidate searches bounded frame-counter window")
  expect(resyncedDecryptedFrameCandidate?.frameCounter == 7, "AirShield decrypt candidate reports matched frame counter")
  expect(resyncedDecryptedFrameCandidate?.counterSearchOffset == 2, "AirShield decrypt candidate reports counter search offset")
  expect(
    AirShieldFraming.decryptedFrameCandidate(
      outerFrame: paddedFrameCandidate!.outerFrame,
      validationKey: validationKey,
      cipherKey: nistAES256Key,
      initialCounterBlock: nistCounter,
      runtimeValidationMode: 0,
      startingFrameCounter: 5,
      counterSearchWindow: 1
    ) == nil,
    "AirShield decrypt candidate rejects frame outside counter search window"
  )

  var tamperedFrame = frameCandidate!.outerFrame
  tamperedFrame[0] ^= 0xff
  expect(
    AirShieldFraming.decryptedFrameCandidate(
      outerFrame: tamperedFrame,
      validationKey: validationKey,
      cipherKey: nistAES256Key,
      initialCounterBlock: nistCounter,
      runtimeValidationMode: 0,
      frameCounter: 0
    ) == nil,
    "AirShield decrypt candidate rejects validation-prefix mismatch"
  )

  var encryptedFrameDecoder = AirShieldEncryptedFrameDecoder()
  let firstPart = frameCandidate!.outerFrame.prefix(10)
  let secondPart = frameCandidate!.outerFrame.dropFirst(10)
  expect(encryptedFrameDecoder.append(firstPart).isEmpty, "AirShield encrypted frame decoder waits for full outer frame")
  let splitDecodedFrames = encryptedFrameDecoder.append(secondPart)
  expect(splitDecodedFrames.count == 1, "AirShield encrypted frame decoder emits split frame after second chunk")
  expect(splitDecodedFrames[0] == frameCandidate!.outerFrame, "AirShield encrypted frame decoder preserves split frame bytes")

  encryptedFrameDecoder.reset()
  let coalescedDecodedFrames = encryptedFrameDecoder.append(frameCandidate!.outerFrame + paddedFrameCandidate!.outerFrame)
  expect(coalescedDecodedFrames.count == 2, "AirShield encrypted frame decoder emits coalesced frames")
  expect(coalescedDecodedFrames[0] == frameCandidate!.outerFrame, "AirShield encrypted frame decoder first coalesced frame")
  expect(coalescedDecodedFrames[1] == paddedFrameCandidate!.outerFrame, "AirShield encrypted frame decoder second coalesced frame")

  let gesturePayload = data([
    0x08, 0x2a,       // sequence_number = 42
    0x10, 0xe7, 0x07, // timestamp = 999
    0x18, 0x01,       // finger = THUMB
    0x20, 0x03,       // action = TAP
    0x28, 0x01        // derived_action = SINGLE_TAP
  ])
  let gestureDataXFrame = try! DataXFrameEncoder.encode(
    baseID: 0x8000,
    payload: gesturePayload,
    extensions: WISProtocol.dataXExtensions(appID: .emgImu, messageType: .gesture)
  )
  let encryptedGestureFrame = AirShieldFraming.encryptedFrameCandidate(
    plaintext: gestureDataXFrame,
    validationKey: validationKey,
    cipherKey: nistAES256Key,
    initialCounterBlock: nistCounter,
    runtimeValidationMode: 0,
    frameCounter: 9
  )
  let decryptedGestureFrame = AirShieldFraming.decryptedFrameCandidate(
    outerFrame: encryptedGestureFrame!.outerFrame,
    validationKey: validationKey,
    cipherKey: nistAES256Key,
    initialCounterBlock: nistCounter,
    runtimeValidationMode: 0,
    frameCounter: 9
  )
  expect(decryptedGestureFrame?.plaintext == gestureDataXFrame, "AirShield decrypt candidate recovers DataX gesture frame plaintext")
  var decryptedDataXDecoder = DataXFrameDecoder()
  let decryptedDataXFrames = decryptedDataXDecoder.append(decryptedGestureFrame!.plaintext)
  expect(decryptedDataXFrames.count == 1, "AirShield decrypted plaintext decodes as one DataX frame")
  expect(decryptedDataXFrames[0].decodedAppID == WISProtocol.AppID.emgImu.rawValue, "AirShield decrypted DataX frame app id")
  expect(decryptedDataXFrames[0].decodedMessageType == WISProtocol.MessageType.gesture.rawValue, "AirShield decrypted DataX frame message type")
  let decryptedGesture = GestureEventDecoder.decode(decryptedDataXFrames[0].payload)
  expect(decryptedGesture?.normalizedAction == "tap", "AirShield decrypted DataX gesture normalizes action")
  expect(decryptedGesture?.fingerName == "thumb", "AirShield decrypted DataX gesture normalizes finger")
}

func validateAirShieldFramingExpansion() {
  expect(AirShieldFramingExpansion.nativeDefaultLabel.hexString == "416972536869656c64", "AirShield framing expansion default label")
  expect(AirShieldFramingExpansion.nativeDefaultLabel.count == 9, "AirShield framing expansion default label length")
  expect(AirShieldFramingExpansion.nativeDefaultLabel.count == AirShieldFramingExpansion.nativeDefaultLabelLength, "AirShield framing expansion label length constant")
  expect(AirShieldFramingExpansion.nativeCounterByte == 0x01, "AirShield framing expansion counter byte")
  expect(AirShieldFramingExpansion.nativeExplicitContextLength == 0x88, "AirShield framing expansion explicit context length")
  expect(
    AirShieldFramingExpansion.nativeExplicitContext.hexString == "416972536869656c6400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000010000",
    "AirShield framing expansion explicit context bytes"
  )

  let keyMaterial = Data((0..<32).map { UInt8($0 & 0xff) })
  let expanded = try! AirShieldFramingExpansion.expandDefaultLabelCounter1(keyMaterial: keyMaterial)
  expect(expanded.count == AirShieldFramingExpansion.outputLength, "AirShield framing expansion output length")
  expect(expanded.hexString == "d7536d4f76ad769088686b1e1059a17f2d17b4f94c9e8c88e13254ba155ef799", "AirShield framing expansion fixture")
  let explicitExpanded = try! AirShieldFramingExpansion.expandExplicitContextCounter1(keyMaterial: keyMaterial)
  expect(explicitExpanded.count == AirShieldFramingExpansion.outputLength, "AirShield explicit-context framing expansion output length")
  expect(explicitExpanded.hexString == "c4ac2929da26e7f1c757dd486a4c8716ee1b0edd2bab65f3dbea7a9e0c6c13b4", "AirShield explicit-context framing expansion fixture")

  do {
    _ = try AirShieldFramingExpansion.expandDefaultLabelCounter1(keyMaterial: Data([0x00]))
    expect(false, "AirShield framing expansion rejects short key material")
  } catch AirShieldFramingExpansionError.invalidKeyMaterialLength(let length) {
    expect(length == 1, "AirShield framing expansion invalid key length error")
  } catch {
    expect(false, "AirShield framing expansion short-key error shape")
  }
}

func validateGestureDecode() {
  let tapPayload = data([
    0x08, 0x2a,       // sequence_number = 42
    0x10, 0xe7, 0x07, // timestamp = 999
    0x18, 0x01,       // finger = THUMB
    0x20, 0x03,       // action = TAP
    0x28, 0x01,       // derived_action = SINGLE_TAP
    0x58, 0x7b,       // emg_raw_gesture_id = 123
    0x60, 0x01        // synthetic = true
  ])
  let tap = GestureEventDecoder.decode(tapPayload)
  expect(tap != nil, "tap payload decodes")
  expect(tap?.sequenceNumber == 42, "tap sequence")
  expect(tap?.timestamp == 999, "tap timestamp")
  expect(tap?.fingerName == "thumb", "tap finger")
  expect(tap?.normalizedAction == "tap", "tap normalized action")
  expect(tap?.emgRawGestureID == 123, "tap raw gesture id")
  expect(tap?.isSyntheticGesture == true, "tap synthetic flag")

  let swipePayload = data([
    0x18, 0x04, // finger = NOT_APPLICABLE
    0x20, 0x06, // action = UP
    0x28, 0x05  // derived_action = BUTTON_UP
  ])
  let swipe = GestureEventDecoder.decode(swipePayload)
  expect(swipe?.normalizedAction == "swipe_up", "derived button up normalizes to swipe_up")
  expect(swipe?.fingerName == "not_applicable", "swipe finger")

  let metadataPayload = data([
    0x08, 0x63,       // sequence_number = 99
    0x10, 0x80, 0x40, // timestamp = 8192
    0x18, 0x02,       // finger = INDEX
    0x20, 0x0b,       // action = SWIPE_IN
    0x30, 0x11,       // emg_batch_id_low = 17
    0x38, 0x12,       // emg_batch_id_high = 18
    0x40, 0x13,       // imu_sequence_number = 19
    0x48, 0x14,       // device_latency_us = 20
    0x50, 0x15,       // inference_trigger_emg_offset = 21
    0x58, 0x16,       // emg_raw_gesture_id = 22
    0x60, 0x00        // synthetic = false
  ])
  let metadata = GestureEventDecoder.decode(metadataPayload)
  expect(metadata?.fingerName == "index", "gesture metadata finger")
  expect(metadata?.normalizedAction == "swipe_in", "gesture metadata swipe_in action")
  expect(metadata?.emgBatchIDLow == 17, "gesture metadata emg low")
  expect(metadata?.emgBatchIDHigh == 18, "gesture metadata emg high")
  expect(metadata?.imuSequenceNumber == 19, "gesture metadata imu sequence")
  expect(metadata?.deviceLatencyMicros == 20, "gesture metadata latency")
  expect(metadata?.inferenceTriggerEMGOffset == 21, "gesture metadata inference offset")
  expect(metadata?.emgRawGestureID == 22, "gesture metadata raw gesture id")
  expect(metadata?.isSyntheticGesture == false, "gesture metadata synthetic false")

  let actionNames: [(UInt64, String)] = [
    (1, "press"),
    (2, "release"),
    (3, "tap"),
    (4, "double_tap"),
    (5, "click"),
    (6, "swipe_up"),
    (7, "swipe_down"),
    (8, "swipe_left"),
    (9, "swipe_right"),
    (10, "wake"),
    (11, "swipe_in"),
    (12, "swipe_out"),
    (13, "meta_ai"),
    (14, "partial_press"),
    (15, "partial_release"),
    (16, "partial_click"),
    (17, "partial_up"),
    (18, "partial_down"),
    (19, "partial_left"),
    (20, "partial_right")
  ]
  for (action, name) in actionNames {
    expect(GestureEvent(action: action).normalizedAction == name, "gesture action \(action) normalizes to \(name)")
  }

  let derivedNames: [(UInt64, String)] = [
    (1, "tap"),
    (2, "double_tap"),
    (3, "hold"),
    (4, "release"),
    (5, "swipe_up"),
    (6, "swipe_down"),
    (7, "swipe_left"),
    (8, "swipe_right"),
    (9, "press"),
    (10, "hold_release")
  ]
  for (derivedAction, name) in derivedNames {
    expect(
      GestureEvent(action: 13, derivedAction: derivedAction).normalizedAction == name,
      "derived gesture action \(derivedAction) overrides raw action as \(name)"
    )
  }
}

func validateGestureForwardPayload() {
  let payload = data([
    0x08, 0x2a,
    0x10, 0xe7, 0x07,
    0x18, 0x01,
    0x20, 0x03,
    0x28, 0x01,
    0x30, 0x11,
    0x38, 0x12,
    0x40, 0x13,
    0x48, 0x14,
    0x50, 0x15,
    0x58, 0x7b,
    0x60, 0x01
  ])
  let frameBytes = try! DataXFrameEncoder.encode(
    baseID: 0x8000,
    payload: payload,
    extensions: WISProtocol.dataXExtensions(appID: .emgImu, messageType: .gesture)
  )
  var decoder = DataXFrameDecoder()
  let frame = decoder.append(frameBytes)[0]
  let gesture = GestureEventDecoder.decode(payload)!
  let formatter = ISO8601DateFormatter()
  let json = EventForwarder.payloadJSON(
    gesture: gesture,
    source: "Meta Band 000J",
    frame: frame,
    date: Date(timeIntervalSince1970: 0),
    formatter: formatter
  )
  expect(json["schema"] as? String == EventForwarder.payloadSchema, "forwarded gesture schema")
  expect(json["event_type"] as? String == "gesture", "forwarded gesture event type")
  expect(json["action"] as? String == "tap", "forwarded gesture action")
  expect(json["normalized_action"] as? String == "tap", "forwarded gesture normalized action")
  expect(json["finger"] as? String == "thumb", "forwarded gesture finger")
  expect(json["source"] as? String == "Meta Band 000J", "forwarded gesture source")
  expect(json["frame_base_id"] as? UInt16 == 0x8000, "forwarded gesture frame base")
  expect(json["channel_alias"] as? UInt16 == WISProtocol.localServiceID, "forwarded gesture channel alias")
  expect(json["app_id"] as? UInt8 == WISProtocol.AppID.emgImu.rawValue, "forwarded gesture app id")
  expect(json["message_type"] as? UInt16 == WISProtocol.MessageType.gesture.rawValue, "forwarded gesture message type")
  expect(frame.payloadFingerprint == payload.shortSHA256Fingerprint, "forwarded gesture frame payload fingerprint")
  expect(json["sequence_number"] as? UInt64 == 42, "forwarded gesture sequence")
  expect(json["timestamp"] as? UInt64 == 999, "forwarded gesture timestamp")
  expect(json["raw_finger"] as? UInt64 == 1, "forwarded gesture raw finger")
  expect(json["raw_action"] as? UInt64 == 3, "forwarded gesture raw action")
  expect(json["derived_action"] as? UInt64 == 1, "forwarded gesture derived action")
  expect(json["emg_batch_id_low"] as? UInt64 == 17, "forwarded gesture emg low")
  expect(json["emg_batch_id_high"] as? UInt64 == 18, "forwarded gesture emg high")
  expect(json["imu_sequence_number"] as? UInt64 == 19, "forwarded gesture imu sequence")
  expect(json["device_latency_micros"] as? UInt64 == 20, "forwarded gesture latency")
  expect(json["inference_trigger_emg_offset"] as? UInt64 == 21, "forwarded gesture inference offset")
  expect(json["emg_raw_gesture_id"] as? UInt64 == 123, "forwarded gesture raw gesture id")
  expect(json["is_synthetic_gesture"] as? Bool == true, "forwarded gesture synthetic")
  expect(JSONSerialization.isValidJSONObject(json), "forwarded gesture JSON is serializable")

  let sessionJSON = EventForwarder.sessionPayloadJSON(
    gesture: gesture,
    source: "Meta Band 000J",
    frame: frame,
    frameSource: "airshield.decrypted",
    date: Date(timeIntervalSince1970: 0),
    formatter: formatter
  )
  expect(sessionJSON["schema"] as? String == EventForwarder.payloadSchema, "session gesture schema")
  expect(sessionJSON["event_type"] as? String == "gesture", "session gesture event type")
  expect(sessionJSON["frame_source"] as? String == "airshield.decrypted", "session gesture frame source")
  expect(sessionJSON["frame_payload_hex"] as? String == payload.hexString, "session gesture replay payload hex")
  expect(sessionJSON["normalized_action"] as? String == "tap", "session gesture normalized action")
  expect(sessionJSON["finger"] as? String == "thumb", "session gesture finger")
  expect(JSONSerialization.isValidJSONObject(sessionJSON), "session gesture JSON is serializable")

  let loopbackHTTPServer = LocalHTTPEventServer(autoStart: false)
  expect(loopbackHTTPServer.endpoint == "http://127.0.0.1:49733", "loopback HTTP endpoint")
  let lanHTTPServer = LocalHTTPEventServer(
    port: 49734,
    bindAddress: "0.0.0.0",
    displayHost: "192.0.2.10",
    autoStart: false
  )
  expect(lanHTTPServer.endpoint == "http://192.0.2.10:49734", "LAN HTTP endpoint")
  if let lanAddress = LocalHTTPEventServer.preferredLANIPv4Address() {
    expect(!lanAddress.isEmpty, "preferred LAN IPv4 address is non-empty when present")
    expect(lanAddress != "127.0.0.1", "preferred LAN IPv4 address is not loopback")
  }

  let latestResponse = LocalHTTPEventServer.httpResponse(
    for: "GET /latest HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    events: [json]
  )
  let latestBody = httpResponseBody(latestResponse)
  let latestObject = try! JSONSerialization.jsonObject(with: latestBody) as! [String: Any]
  expect(latestObject["schema"] as? String == EventForwarder.payloadSchema, "HTTP latest schema")
  expect(latestObject["event_count"] as? Int == 1, "HTTP latest event count")
  let latestEvent = latestObject["latest"] as? [String: Any]
  expect(latestEvent?["action"] as? String == "tap", "HTTP latest event action")

  let eventsResponse = LocalHTTPEventServer.httpResponse(
    for: "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    events: [json]
  )
  let eventsObject = try! JSONSerialization.jsonObject(with: httpResponseBody(eventsResponse)) as! [String: Any]
  expect(eventsObject["event_count"] as? Int == 1, "HTTP events count")
  expect((eventsObject["events"] as? [[String: Any]])?.count == 1, "HTTP events array")

  let ndjsonResponse = LocalHTTPEventServer.httpResponse(
    for: "GET /events.ndjson HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    events: [json]
  )
  let ndjsonText = String(data: httpResponseBody(ndjsonResponse), encoding: .utf8) ?? ""
  expect(ndjsonText.split(separator: "\n").count == 1, "HTTP NDJSON one line")
  expect(ndjsonText.contains("\"schema\""), "HTTP NDJSON contains event JSON")

  let healthResponseText = String(
    data: LocalHTTPEventServer.httpResponse(
      for: "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
      events: []
    ),
    encoding: .utf8
  ) ?? ""
  expect(healthResponseText.contains("HTTP/1.1 200 OK"), "HTTP health status")

  let schemaResponse = LocalHTTPEventServer.httpResponse(
    for: "GET /schema HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    events: []
  )
  let schemaObject = try! JSONSerialization.jsonObject(with: httpResponseBody(schemaResponse)) as! [String: Any]
  expect(schemaObject["schema"] as? String == EventForwarder.payloadSchema, "HTTP schema endpoint schema")
  expect(schemaObject["event_type"] as? String == "gesture", "HTTP schema endpoint event type")
  expect((schemaObject["paths"] as? [String])?.contains("/events.ndjson") == true, "HTTP schema endpoint includes NDJSON path")
  let schemaMethods = schemaObject["methods"] as? [String] ?? []
  expect(Set(schemaMethods) == Set(["GET", "OPTIONS"]), "HTTP schema endpoint methods")
  let schemaRoute = schemaObject["route"] as? [String: Any]
  expect(schemaRoute?["app_id"] as? Int == Int(WISProtocol.AppID.emgImu.rawValue), "HTTP schema endpoint app id")
  expect(schemaRoute?["message_type"] as? Int == Int(WISProtocol.MessageType.gesture.rawValue), "HTTP schema endpoint message type")
  let liveValidationActions = schemaObject["live_validation_actions"] as? [String] ?? []
  expect(
    Set(liveValidationActions) == Set(["tap", "double_tap", "swipe_up", "swipe_down", "swipe_in", "swipe_out", "press", "hold", "release"]),
    "HTTP schema endpoint live validation actions"
  )
  expect((schemaObject["required_fields"] as? [String])?.contains("frame_payload_hex") == true, "HTTP schema endpoint replay field")
  expect((schemaObject["optional_fields"] as? [String])?.contains("emg_raw_gesture_id") == true, "HTTP schema endpoint provenance field")

  let optionsResponseText = String(
    data: LocalHTTPEventServer.httpResponse(
      for: "OPTIONS /schema HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1:3000\r\nAccess-Control-Request-Method: GET\r\n\r\n",
      events: []
    ),
    encoding: .utf8
  ) ?? ""
  expect(optionsResponseText.contains("HTTP/1.1 204 No Content"), "HTTP OPTIONS status")
  expect(optionsResponseText.contains("Access-Control-Allow-Origin: *"), "HTTP CORS allow origin")
  expect(optionsResponseText.contains("Access-Control-Allow-Methods: GET, OPTIONS"), "HTTP CORS allow methods")
  expect(optionsResponseText.contains("Access-Control-Allow-Headers: Content-Type, Accept"), "HTTP CORS allow headers")
  expect(optionsResponseText.contains("Content-Length: 0"), "HTTP OPTIONS empty body")

  let missingResponseText = String(
    data: LocalHTTPEventServer.httpResponse(
      for: "GET /missing HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
      events: []
    ),
    encoding: .utf8
  ) ?? ""
  expect(missingResponseText.contains("HTTP/1.1 404 Not Found"), "HTTP missing status")

  let liveActionFixtures: [(UInt64, UInt64?, String)] = [
    (3, 1, "tap"),
    (4, 2, "double_tap"),
    (6, 5, "swipe_up"),
    (7, 6, "swipe_down"),
    (11, nil, "swipe_in"),
    (12, nil, "swipe_out"),
    (1, 9, "press"),
    (1, 3, "hold"),
    (2, 4, "release")
  ]
  var forwardedActions: Set<String> = []
  for (rawAction, derivedAction, expectedAction) in liveActionFixtures {
    var livePayload = Data()
    livePayload.appendProtoVarint(field: 3, rawAction == 6 || rawAction == 7 ? 4 : 1)
    livePayload.appendProtoVarint(field: 4, rawAction)
    if let derivedAction {
      livePayload.appendProtoVarint(field: 5, derivedAction)
    }
    let liveFrameBytes = try! DataXFrameEncoder.encode(
      baseID: 0x8000,
      payload: livePayload,
      extensions: WISProtocol.dataXExtensions(appID: .emgImu, messageType: .gesture)
    )
    var liveDecoder = DataXFrameDecoder()
    let liveFrame = liveDecoder.append(liveFrameBytes)[0]
    let liveGesture = GestureEventDecoder.decode(livePayload)!
    let liveJSON = EventForwarder.payloadJSON(
      gesture: liveGesture,
      source: "self-test",
      frame: liveFrame,
      date: Date(timeIntervalSince1970: 1),
      formatter: formatter
    )
    expect(liveJSON["schema"] as? String == EventForwarder.payloadSchema, "live action \(expectedAction) forwarded schema")
    expect(liveJSON["event_type"] as? String == "gesture", "live action \(expectedAction) forwarded event type")
    expect(liveJSON["action"] as? String == expectedAction, "live action \(expectedAction) forwarded action")
    expect(liveJSON["normalized_action"] as? String == expectedAction, "live action \(expectedAction) forwarded normalized action")
    expect(liveJSON["frame_payload_hex"] as? String == livePayload.hexString, "live action \(expectedAction) forwarded payload hex")
    expect(liveJSON["app_id"] as? UInt8 == WISProtocol.AppID.emgImu.rawValue, "live action \(expectedAction) forwarded app id")
    expect(liveJSON["message_type"] as? UInt16 == WISProtocol.MessageType.gesture.rawValue, "live action \(expectedAction) forwarded message type")
    expect(JSONSerialization.isValidJSONObject(liveJSON), "live action \(expectedAction) forwarded JSON is serializable")
    forwardedActions.insert(expectedAction)
  }
  expect(
    forwardedActions == Set(["tap", "double_tap", "swipe_up", "swipe_down", "swipe_in", "swipe_out", "press", "hold", "release"]),
    "forwarded gesture fixture covers every live validation action"
  )
}

func httpResponseBody(_ response: Data) -> Data {
  let separator = Data([0x0d, 0x0a, 0x0d, 0x0a])
  guard let range = response.range(of: separator) else {
    return Data()
  }
  return Data(response[range.upperBound...])
}

func streamControlResponsePayload(enabledGestures: Bool, streamType: UInt64, streamState: UInt64) -> Data {
  var streamStateEntry = Data()
  streamStateEntry.appendProtoVarint(field: 1, streamType)
  streamStateEntry.appendProtoVarint(field: 2, streamState)

  var response = Data()
  response.appendProtoVarint(field: 3, enabledGestures ? 1 : 0)
  response.appendProtoLengthDelimited(field: 35, streamStateEntry)
  return response
}

func validateStreamControlDecode() {
  let responsePayload = streamControlResponsePayload(
    enabledGestures: true,
    streamType: 1,
    streamState: 2
  )

  var rpcResponsePayload = Data()
  rpcResponsePayload.appendProtoVarint(field: 1, 7)
  rpcResponsePayload.appendProtoVarint(field: 2, 1)
  rpcResponsePayload.appendProtoLengthDelimited(field: 5, responsePayload)

  let rpcResponse = StreamControlDecoder.decodeRPCResponse(rpcResponsePayload)
  expect(rpcResponse?.sequenceNumber == 7, "RPC response sequence")
  expect(rpcResponse?.code == 1, "RPC response success code")
  expect(rpcResponse?.streamControlResponse?.enabledGestures == true, "RPC response enabled gestures")
  expect(rpcResponse?.streamControlResponse?.streamStates[1] == 2, "RPC response gesture stream active")
  expect(rpcResponse?.streamControlResponse?.isGestureStreamActive == true, "RPC response active helper")
  expect(rpcResponse?.logFields["gesture_stream_active"] as? Bool == true, "RPC response log active helper")
  expect(rpcResponse?.logFields["enabled_gestures"] as? Bool == true, "RPC response log enabled gestures")
  expect(rpcResponse?.logFields["code_name"] as? String == "success", "RPC response log code name")
  let responseStreamStates = rpcResponse?.logFields["stream_states"] as? [[String: Any]]
  expect(responseStreamStates?.first?["stream_type_name"] as? String == "gesture", "RPC response log stream type")
  expect(responseStreamStates?.first?["stream_state_name"] as? String == "active", "RPC response log stream state")

  var streamControlUpdatePayload = Data()
  streamControlUpdatePayload.appendProtoLengthDelimited(field: 3, responsePayload)
  streamControlUpdatePayload.appendProtoVarint(field: 7, 9)

  var rpcStreamUpdatePayload = Data()
  rpcStreamUpdatePayload.appendProtoLengthDelimited(field: 16, streamControlUpdatePayload)

  let rpcStreamUpdate = StreamControlDecoder.decodeRPCStreamUpdate(rpcStreamUpdatePayload)
  expect(rpcStreamUpdate?.streamControlUpdate?.notification == "active", "stream update notification")
  expect(rpcStreamUpdate?.streamControlUpdate?.sequenceNumber == 9, "stream update sequence")
  expect(rpcStreamUpdate?.streamControlUpdate?.response?.enabledGestures == true, "stream update enabled gestures")
  expect(rpcStreamUpdate?.streamControlUpdate?.response?.isGestureStreamActive == true, "stream update active helper")
  expect(rpcStreamUpdate?.logFields["notification"] as? String == "active", "stream update log notification")
  expect(rpcStreamUpdate?.logFields["sequence_number"] as? Int == 9, "stream update log sequence")
  expect(rpcStreamUpdate?.logFields["gesture_stream_active"] as? Bool == true, "stream update log active helper")

  let inactiveResponsePayload = streamControlResponsePayload(
    enabledGestures: false,
    streamType: 1,
    streamState: 1
  )
  var inactiveRPCResponsePayload = Data()
  inactiveRPCResponsePayload.appendProtoVarint(field: 1, 8)
  inactiveRPCResponsePayload.appendProtoVarint(field: 2, 1)
  inactiveRPCResponsePayload.appendProtoLengthDelimited(field: 5, inactiveResponsePayload)
  let inactiveRPCResponse = StreamControlDecoder.decodeRPCResponse(inactiveRPCResponsePayload)
  expect(inactiveRPCResponse?.streamControlResponse?.enabledGestures == false, "inactive RPC response disabled gestures")
  expect(inactiveRPCResponse?.streamControlResponse?.isGestureStreamActive == false, "inactive RPC response is not active")
  expect(inactiveRPCResponse?.logFields["gesture_stream_active"] as? Bool == false, "inactive RPC response log inactive")
  let inactiveStreamStates = inactiveRPCResponse?.logFields["stream_states"] as? [[String: Any]]
  expect(inactiveStreamStates?.first?["stream_state_name"] as? String == "inactive", "inactive RPC response state name")

  var lostUpdatePayload = Data()
  lostUpdatePayload.appendProtoLengthDelimited(field: 1, inactiveResponsePayload)
  lostUpdatePayload.appendProtoVarint(field: 7, 10)
  var rpcLostUpdatePayload = Data()
  rpcLostUpdatePayload.appendProtoLengthDelimited(field: 16, lostUpdatePayload)
  let lostUpdate = StreamControlDecoder.decodeRPCStreamUpdate(rpcLostUpdatePayload)
  expect(lostUpdate?.streamControlUpdate?.notification == "lost", "lost stream update notification")
  expect(lostUpdate?.streamControlUpdate?.response?.isGestureStreamActive == false, "lost stream update is not active")
  expect(lostUpdate?.logFields["gesture_stream_active"] as? Bool == false, "lost stream update log inactive")

  var infoUpdatePayload = Data()
  infoUpdatePayload.appendProtoLengthDelimited(field: 2, inactiveResponsePayload)
  infoUpdatePayload.appendProtoVarint(field: 7, 11)
  var rpcInfoUpdatePayload = Data()
  rpcInfoUpdatePayload.appendProtoLengthDelimited(field: 16, infoUpdatePayload)
  let infoUpdate = StreamControlDecoder.decodeRPCStreamUpdate(rpcInfoUpdatePayload)
  expect(infoUpdate?.streamControlUpdate?.notification == "info", "info stream update notification")
  expect(infoUpdate?.streamControlUpdate?.response?.isGestureStreamActive == false, "info stream update is not active")
  expect(infoUpdate?.logFields["gesture_stream_active"] as? Bool == false, "info stream update log inactive")

  var ackPayload = Data()
  ackPayload.appendProtoVarint(field: 1, 12)
  ackPayload.appendProtoLengthDelimited(field: 27, Data())
  let ackResponse = StreamControlDecoder.decodeRPCResponse(ackPayload)
  expect(ackResponse?.hasStreamUpdateAckResponse == true, "RPC response stream update ack")
  expect(ackResponse?.logFields["stream_update_ack"] as? Bool == true, "RPC response stream update ack log")
}

func validateProtoMessageSummary() {
  var payload = Data()
  payload.appendProtoVarint(field: 1, 150)
  payload.appendProtoLengthDelimited(field: 2, Data([0xaa, 0xbb, 0xcc]))
  payload.append(contentsOf: [0x1d, 0x44, 0x33, 0x22, 0x11]) // field 3, fixed32
  payload.append(contentsOf: [0x21, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]) // field 4, fixed64

  let summary = ProtoMessageSummarizer.summarize(payload)
  expect(summary.payloadLength == payload.count, "proto summary payload length")
  expect(summary.fields.count == 4, "proto summary field count")
  expect(!summary.truncated, "proto summary not truncated")
  expect(summary.fields[0].number == 1, "proto summary varint field number")
  expect(summary.fields[0].wireTypeName == "varint", "proto summary varint wire type")
  expect(summary.fields[0].value == 150, "proto summary varint value")
  expect(summary.fields[1].number == 2, "proto summary length-delimited field number")
  expect(summary.fields[1].wireTypeName == "lengthDelimited", "proto summary length-delimited wire type")
  expect(summary.fields[1].length == 3, "proto summary length-delimited length")
  expect(summary.fields[1].fingerprint?.count == 16, "proto summary length-delimited fingerprint")
  expect(summary.fields[2].wireTypeName == "fixed32", "proto summary fixed32 wire type")
  expect(summary.fields[2].length == 4, "proto summary fixed32 length")
  expect(summary.fields[3].wireTypeName == "fixed64", "proto summary fixed64 wire type")
  expect(summary.fields[3].length == 8, "proto summary fixed64 length")

  let limited = ProtoMessageSummarizer.summarize(payload, maxFields: 2)
  expect(limited.fields.count == 2, "proto summary max fields")
  expect(limited.truncated, "proto summary truncated when max fields reached")
}

func validateAirShieldProtobufs() {
  let publicKey = Data((0..<64).map { UInt8($0 & 0xff) })
  let challenge = Data((0..<16).map { UInt8(0xa0 + $0) })
  let request = AirShieldLinkSetup.encodeRequestEncryption(publicKey: publicKey, challenge: challenge)
  let decodedRequest = AirShieldLinkSetup.decodeRequestEncryption(request)
  expect(decodedRequest.publicKey == publicKey, "AirShield request public key round-trip")
  expect(decodedRequest.challenge == challenge, "AirShield request challenge round-trip")
  expect(decodedRequest.ellipticCurve == 0, "AirShield request curve")
  expect(decodedRequest.supportedParameters == 1, "AirShield request HKDF bit")
  expect(decodedRequest.usesHKDF, "AirShield request uses HKDF")
  var requestWithExtras = request
  let requestHintA = Data([0xde, 0xad, 0xbe, 0xef])
  let requestHintB = Data([0xca, 0xfe])
  requestWithExtras.appendProtoLengthDelimited(field: 5, requestHintA)
  requestWithExtras.appendProtoLengthDelimited(field: 5, requestHintB)
  requestWithExtras.appendProtoVarint(field: 6, 1)
  requestWithExtras.appendProtoVarint(field: 7, 0x0102)
  let decodedRequestWithExtras = AirShieldLinkSetup.decodeRequestEncryption(requestWithExtras)
  expect(decodedRequestWithExtras.keyHints == [requestHintA, requestHintB], "AirShield request key hints decode")
  expect(decodedRequestWithExtras.quirks == 1, "AirShield request quirks decode")
  expect(decodedRequestWithExtras.airShieldVersion == 0x0102, "AirShield request version decode")

  let requestFrame = try! AirShieldLinkSetup.encodeDataXFrame(
    typedMessage: .requestEncryption,
    payload: request
  )
  expect(
    NativeDataXLocalChannel.baseID(localChannelID: 7) == 0x8007,
    "AirShield native local channel base ID rule"
  )
  let emptyRequestFrame = try! AirShieldLinkSetup.encodeDataXFrame(
    typedMessage: .requestEncryption,
    payload: Data(),
    baseID: NativeDataXLocalChannel.baseID(localChannelID: 0)
  )
  expect(
    emptyRequestFrame.hexString == "800880008100000502000001",
    "AirShield native LocalChannel openChannel(5).send(type=1) empty frame"
  )
  expect(
    requestFrame.hexString == "8060800081000005020000010a40000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f1210a0a1a2a3a4a5a6a7a8a9aaabacadaeaf18002001",
    "AirShield request DataX frame bytes"
  )
  var requestFrameDecoder = DataXFrameDecoder()
  let requestFrames = requestFrameDecoder.append(requestFrame)
  expect(requestFrames.count == 1, "AirShield request frame decodes")
  expect(requestFrames[0].channelAlias == AirShieldLinkSetup.dataXServiceID, "AirShield request channel alias")
  expect(requestFrames[0].typedBufferType == AirShieldLinkSetup.TypedMessage.requestEncryption.rawValue, "AirShield request typed buffer type")
  expect(requestFrames[0].airShieldTypedMessage == .requestEncryption, "AirShield request typed message")
  if case .requestEncryption(let decodedFramedRequest)? = requestFrames[0].decodedAirShieldMessage {
    expect(decodedFramedRequest.publicKey == publicKey, "AirShield framed request public key")
    expect(decodedFramedRequest.challenge == challenge, "AirShield framed request challenge")
  } else {
    expect(false, "AirShield framed request decodes as RequestEncryption")
  }

  let seed = Data((0..<32).map { UInt8(0x40 + $0) })
  let iv = Data((0..<24).map { UInt8(0x70 + $0) })
  let enable = AirShieldLinkSetup.encodeEnableEncryption(
    publicKey: publicKey,
    seed: seed,
    initializationVector: iv,
    base: 0x1234
  )
  let decodedEnable = AirShieldLinkSetup.decodeEnableEncryption(enable)
  expect(decodedEnable.publicKey == publicKey, "AirShield enable public key round-trip")
  expect(decodedEnable.seed == seed, "AirShield enable seed round-trip")
  expect(decodedEnable.initializationVector == iv, "AirShield enable IV round-trip")
  expect(decodedEnable.base == 0x1234, "AirShield enable base")
  expect(decodedEnable.usesHKDF, "AirShield enable uses HKDF")
  var enableWithExtras = enable
  enableWithExtras.appendProtoVarint(field: 6, 1)
  enableWithExtras.appendProtoVarint(field: 7, 1)
  enableWithExtras.appendProtoVarint(field: 8, 0x1001)
  enableWithExtras.appendProtoVarint(field: 9, 3)
  let decodedEnableWithExtras = AirShieldLinkSetup.decodeEnableEncryption(enableWithExtras)
  expect(decodedEnableWithExtras.quirks == 1, "AirShield enable quirks decode")
  expect(decodedEnableWithExtras.phasedLinkSetupSupported == true, "AirShield enable phased link setup decode")
  expect(decodedEnableWithExtras.supportedLinkSetupServices == 0x1001, "AirShield enable supported services decode")
  expect(decodedEnableWithExtras.linkSwitchVersionSupported == 3, "AirShield enable link switch version decode")

  let enableFrame = try! AirShieldLinkSetup.encodeDataXFrame(
    typedMessage: .enableEncryption,
    payload: enable
  )
  var enableFrameDecoder = DataXFrameDecoder()
  let enableFrames = enableFrameDecoder.append(enableFrame)
  expect(enableFrames.count == 1, "AirShield enable frame decodes")
  expect(enableFrames[0].channelAlias == AirShieldLinkSetup.dataXServiceID, "AirShield enable channel alias")
  expect(enableFrames[0].airShieldTypedMessage == .enableEncryption, "AirShield enable typed message")
  if case .enableEncryption(let decodedFramedEnable)? = enableFrames[0].decodedAirShieldMessage {
    expect(decodedFramedEnable.publicKey == publicKey, "AirShield framed enable public key")
    expect(decodedFramedEnable.seed == seed, "AirShield framed enable seed")
    expect(decodedFramedEnable.initializationVector == iv, "AirShield framed enable IV")
    expect(decodedFramedEnable.base == 0x1234, "AirShield framed enable base")
  } else {
    expect(false, "AirShield framed enable decodes as EnableEncryption")
  }

  let uuid = Data((0..<16).map { UInt8(0x10 + $0) })
  let linkUUID = Data((0..<16).map { UInt8(0x30 + $0) })
  let end = AirShieldLinkSetup.encodeEndLinkSetup(state: .main, uuid: uuid, linkUUID: linkUUID)
  let decodedEnd = AirShieldLinkSetup.decodeEndLinkSetup(end)
  expect(decodedEnd.state == AirShieldLinkSetup.LinkState.main.rawValue, "AirShield end state")
  expect(decodedEnd.uuid == uuid, "AirShield end uuid")
  expect(decodedEnd.linkUUID == linkUUID, "AirShield end link uuid")
}

func validateAirShieldSessionState() {
  let challenge = Data((0..<16).map { UInt8(0xb0 + $0) })
  let responderChallenge = Data((0..<16).map { UInt8(0xc0 + $0) })
  let initiator = AirShieldSession()
  let responder = AirShieldSession()
  let initiatorProbe = try! initiator.makeRequestEncryptionProbe(challenge: challenge)
  let responderProbe = try! responder.makeRequestEncryptionProbe(challenge: responderChallenge)

  expect(initiatorProbe.publicKey.count == 64, "AirShield session local public key is raw 64-byte point")
  expect(initiatorProbe.challenge == challenge, "AirShield session keeps challenge")
  expect(responderProbe.publicKey.count == 64, "AirShield session peer public key fixture")

  let enable = AirShieldLinkSetup.EnableEncryptionMessage(
    publicKey: responderProbe.publicKey,
    seed: Data((0..<32).map { UInt8(0xd0 + $0) }),
    initializationVector: Data((0..<24).map { UInt8(0x20 + $0) }),
    base: 0x12345678,
    parameters: 1,
    quirks: nil,
    phasedLinkSetupSupported: true,
    supportedLinkSetupServices: nil,
    linkSwitchVersionSupported: nil
  )
  let inputs = try! initiator.processEnableEncryption(enable)
  expect(initiator.hasReceiveCandidates, "AirShield session has passive receive candidates after complete EnableEncryption")
  expect(!initiator.hasValidatedReceiveCandidate, "AirShield session has no validated receive candidate before decrypt match")
  expect(initiator.preparedGestureEnableFrameForValidatedReceiveCandidate() == nil, "AirShield gesture-enable transmit frame stays gated before decrypt match")
  expect(inputs.peerPublicKeyLength == 64, "AirShield enable inputs peer public key length")
  expect(inputs.peerPublicKeyFingerprint.count == 16, "AirShield enable inputs peer public key fingerprint")
  expect(inputs.seedLength == 32, "AirShield enable inputs seed length")
  expect(inputs.seedFingerprint?.count == 16, "AirShield enable inputs seed fingerprint")
  expect(inputs.initializationVectorLength == 24, "AirShield enable inputs IV length")
  expect(inputs.initializationVectorFingerprint?.count == 16, "AirShield enable inputs IV fingerprint")
  expect(inputs.base == 0x12345678, "AirShield enable inputs base")
  expect(inputs.usesHKDF, "AirShield enable inputs HKDF")
  expect(inputs.sharedSecretLength == 32, "AirShield ECDH shared secret length")
  expect(inputs.sharedSecretFingerprint.count == 16, "AirShield shared secret fingerprint is short hex")
  expect(inputs.normalMaterialCandidate != nil, "AirShield normal material candidate is available for complete EnableEncryption")
  expect(inputs.normalMaterialCandidates.count == 9, "AirShield normal material candidate variants")
  expect(inputs.normalMaterialCandidates.map(\.sharedMaterialSource) == [
    "raw_p256_shared_secret__db17b4_default_label",
    "raw_p256_shared_secret__db17b4_shared_material_context",
    "raw_p256_shared_secret__db17b4_explicit_context_0x88",
    "sha256_raw_p256_shared_secret__db17b4_default_label",
    "sha256_raw_p256_shared_secret__db17b4_shared_material_context",
    "sha256_raw_p256_shared_secret__db17b4_explicit_context_0x88",
    "reversed_raw_p256_shared_secret__db17b4_default_label",
    "reversed_raw_p256_shared_secret__db17b4_shared_material_context",
    "reversed_raw_p256_shared_secret__db17b4_explicit_context_0x88"
  ], "AirShield normal material candidate source ordering")
  expect(inputs.normalMaterialCandidate?.sharedMaterialSource == "raw_p256_shared_secret__db17b4_default_label", "AirShield primary normal material candidate source")
  expect(inputs.normalMaterialCandidate?.sharedMaterialPrefixHex.count == 16, "AirShield primary normal material shared prefix is short hex")
  expect(inputs.normalMaterialCandidate?.sharedMaterialFingerprint.count == 16, "AirShield primary normal material shared fingerprint is short hex")
  expect(inputs.normalMaterialCandidate?.sharedMaterialSHA256Fingerprint.count == 16, "AirShield primary normal material shared SHA-256 fingerprint is short hex")
  expect(
    inputs.normalMaterialCandidate?.sharedMaterialPrefixHex == inputs.normalMaterialCandidate?.sharedMaterialFingerprint,
    "AirShield legacy shared fingerprint remains the raw prefix"
  )
  expect(inputs.normalMaterialCandidate?.transcriptChallengeWindowFingerprint.count == 16, "AirShield transcript challenge window fingerprint is short hex")
  expect(inputs.normalMaterialCandidate?.transcriptMaterialWindowFingerprint.count == 16, "AirShield transcript material window fingerprint is short hex")
  expect(inputs.normalMaterialCandidate?.transcriptDigestInputFingerprint.count == 16, "AirShield transcript digest input fingerprint is short hex")
  expect(inputs.normalMaterialCandidate?.keyDerivationMode == "db17b4_expansion_candidate", "AirShield HKDF path logs expansion derivation mode")
  expect(inputs.normalMaterialCandidate?.expansionContextSource == "default_airshield_label", "AirShield HKDF path logs expansion context source")
  expect(inputs.normalMaterialCandidate?.expansionContextLength == 9, "AirShield HKDF path logs default expansion context length")
  expect(inputs.normalMaterialCandidate?.expansionContextFingerprint?.count == 16, "AirShield HKDF path logs expansion context fingerprint")
  expect(
    Set(inputs.normalMaterialCandidates.compactMap(\.expansionContextSource)) == Set([
      "default_airshield_label",
      "shared_material_candidate",
      "explicit_airshield_context_0x88"
    ]),
    "AirShield HKDF candidate list covers native expansion context variants"
  )
  expect(
    Set(inputs.normalMaterialCandidates.compactMap(\.expansionContextLength)) == Set([9, 32, 136]),
    "AirShield HKDF candidate list covers native expansion context lengths"
  )
  expect(inputs.normalMaterialCandidate?.transcriptDigestFingerprint.count == 16, "AirShield normal material transcript digest fingerprint is short hex")
  expect(inputs.normalMaterialCandidate?.workAreaFingerprint.count == 16, "AirShield normal material work-area fingerprint is short hex")
  expect(inputs.normalMaterialCandidate?.workAreaValidationHalfFingerprint == inputs.normalMaterialCandidate?.validationKeyFingerprint, "AirShield work-area validation half feeds validation key")
  expect(inputs.normalMaterialCandidate?.workAreaCipherHalfFingerprint == inputs.normalMaterialCandidate?.cipherKeyFingerprint, "AirShield work-area cipher half feeds cipher key")
  expect(inputs.normalMaterialCandidate?.validationKeyFingerprint.count == 16, "AirShield normal material validation fingerprint is short hex")
  expect(inputs.normalMaterialCandidate?.cipherKeyFingerprint.count == 16, "AirShield normal material cipher fingerprint is short hex")
  expect(inputs.normalMaterialCandidate?.validationEqualsCipher == true, "AirShield normal material keeps validation/cipher halves equal on default path")
  expect(inputs.normalMaterialCandidate?.validationKeySource == "state_setup_work_area_0x190", "AirShield validation key source is native work-area half")
  expect(inputs.normalMaterialCandidate?.cipherKeySource == "state_setup_work_area_0x1b0", "AirShield cipher key source is native work-area half")
  expect(inputs.normalMaterialCandidate?.transcriptPrefixSource == "native_builder_zero_init_and_remote_key_flag", "AirShield normal material transcript prefix source")
  expect(inputs.normalMaterialCandidate?.initialCounterBlockSource == "seed_tail_8_plus_iv_head_8", "AirShield normal material initial counter block source")
  expect(inputs.normalMaterialCandidate?.initialCounterBlockFingerprint?.count == 16, "AirShield normal material initial counter block fingerprint is short hex")
  expect(inputs.normalMaterialCandidate?.endLinkSetupFrameCandidate != nil, "AirShield normal material EndLinkSetup frame candidate is available")
  expect(inputs.normalMaterialCandidate?.endLinkSetupFrameCandidate?.plaintextSource == "airshield_end_link_setup_state_1", "AirShield EndLinkSetup frame candidate source")
  expect(inputs.normalMaterialCandidate?.endLinkSetupFrameCandidate?.plaintextLength == 32, "AirShield EndLinkSetup frame candidate plaintext length")
  expect(inputs.normalMaterialCandidate?.endLinkSetupFrameCandidate?.paddedPlaintextLength == 32, "AirShield EndLinkSetup frame candidate padded length")
  expect(inputs.normalMaterialCandidate?.endLinkSetupFrameCandidate?.cipherPayloadLength == 32, "AirShield EndLinkSetup frame candidate cipher payload length")
  expect(inputs.normalMaterialCandidate?.endLinkSetupFrameCandidate?.outerFrameLength == 41, "AirShield EndLinkSetup frame candidate outer frame length")
  expect(inputs.normalMaterialCandidate?.endLinkSetupFrameCandidate?.runtimeValidationMode == 0, "AirShield EndLinkSetup frame candidate normal runtime validation mode")
  expect(inputs.normalMaterialCandidate?.endLinkSetupFrameCandidate?.frameCounter == 0x12345678, "AirShield EndLinkSetup frame candidate base counter")
  expect(inputs.normalMaterialCandidate?.endLinkSetupFrameCandidate?.validationPrefixHex.count == 16, "AirShield EndLinkSetup frame candidate prefix hex")
  expect(inputs.normalMaterialCandidate?.endLinkSetupFrameCandidate?.cipherPayloadFingerprint.count == 16, "AirShield EndLinkSetup frame candidate cipher fingerprint")
  expect(inputs.normalMaterialCandidate?.endLinkSetupFrameCandidate?.outerFrameFingerprint.count == 16, "AirShield EndLinkSetup frame candidate outer frame fingerprint")
  expect(inputs.normalMaterialCandidate?.gestureEnableFrameCandidate != nil, "AirShield normal material gesture-enable frame candidate is available")
  expect(inputs.normalMaterialCandidate?.gestureEnableFrameCandidate?.plaintextSource == "wis_gesture_enable_rpc_seq_1_datax_frame", "AirShield gesture-enable frame candidate source")
  expect(inputs.normalMaterialCandidate?.gestureEnableFrameCandidate?.plaintextLength == 18, "AirShield gesture-enable frame candidate plaintext length")
  expect(inputs.normalMaterialCandidate?.gestureEnableFrameCandidate?.paddedPlaintextLength == 32, "AirShield gesture-enable frame candidate padded length")
  expect(inputs.normalMaterialCandidate?.gestureEnableFrameCandidate?.cipherPayloadLength == 32, "AirShield gesture-enable frame candidate cipher payload length")
  expect(inputs.normalMaterialCandidate?.gestureEnableFrameCandidate?.outerFrameLength == 41, "AirShield gesture-enable frame candidate outer frame length")
  expect(inputs.normalMaterialCandidate?.gestureEnableFrameCandidate?.runtimeValidationMode == 0, "AirShield gesture-enable frame candidate normal runtime validation mode")
  expect(inputs.normalMaterialCandidate?.gestureEnableFrameCandidate?.frameCounter == 0x12345679, "AirShield gesture-enable frame candidate follows EndLinkSetup counter")
  expect(inputs.normalMaterialCandidate?.gestureEnableFrameCandidate?.validationPrefixHex.count == 16, "AirShield gesture-enable frame candidate prefix hex")
  expect(inputs.normalMaterialCandidate?.gestureEnableFrameCandidate?.cipherPayloadFingerprint.count == 16, "AirShield gesture-enable frame candidate cipher fingerprint")
  expect(inputs.normalMaterialCandidate?.gestureEnableFrameCandidate?.outerFrameFingerprint.count == 16, "AirShield gesture-enable frame candidate outer frame fingerprint")
  expect(inputs.localChallengeLength == 16, "AirShield enable inputs local challenge length")
  expect(inputs.localChallengeFingerprint.count == 16, "AirShield enable inputs local challenge fingerprint")

  let directDigestSession = AirShieldSession()
  _ = try! directDigestSession.makeRequestEncryptionProbe(challenge: challenge)
  let noHKDFEnable = AirShieldLinkSetup.EnableEncryptionMessage(
    publicKey: responderProbe.publicKey,
    seed: Data((0..<32).map { UInt8(0xe0 + $0) }),
    initializationVector: Data((0..<24).map { UInt8(0x40 + $0) }),
    base: 0x01020304,
    parameters: 0,
    quirks: nil,
    phasedLinkSetupSupported: true,
    supportedLinkSetupServices: nil,
    linkSwitchVersionSupported: nil
  )
  let noHKDFInputs = try! directDigestSession.processEnableEncryption(noHKDFEnable)
  expect(!noHKDFInputs.usesHKDF, "AirShield no-HKDF enable inputs disable HKDF")
  expect(directDigestSession.hasReceiveCandidates, "AirShield no-HKDF path still prepares receive candidates")
  expect(noHKDFInputs.normalMaterialCandidates.count == 3, "AirShield no-HKDF direct transcript digest candidate variants")
  expect(noHKDFInputs.normalMaterialCandidates.map(\.sharedMaterialSource) == [
    "raw_p256_shared_secret__direct_transcript_digest",
    "sha256_raw_p256_shared_secret__direct_transcript_digest",
    "reversed_raw_p256_shared_secret__direct_transcript_digest"
  ], "AirShield no-HKDF candidate source ordering")
  expect(noHKDFInputs.normalMaterialCandidate?.keyDerivationMode == "direct_transcript_digest", "AirShield no-HKDF path logs direct transcript digest mode")
  expect(noHKDFInputs.normalMaterialCandidate?.expansionContextSource == nil, "AirShield no-HKDF path has no expansion context source")
  expect(noHKDFInputs.normalMaterialCandidate?.expansionContextLength == nil, "AirShield no-HKDF path has no expansion context length")
  expect(noHKDFInputs.normalMaterialCandidate?.expansionContextFingerprint == nil, "AirShield no-HKDF path has no expansion context fingerprint")
  expect(noHKDFInputs.normalMaterialCandidate?.transcriptDigestFingerprint.count == 16, "AirShield no-HKDF transcript digest fingerprint is short hex")
  expect(noHKDFInputs.normalMaterialCandidate?.workAreaValidationHalfFingerprint == noHKDFInputs.normalMaterialCandidate?.transcriptDigestFingerprint, "AirShield no-HKDF validation half is transcript digest")
  expect(noHKDFInputs.normalMaterialCandidate?.workAreaCipherHalfFingerprint == noHKDFInputs.normalMaterialCandidate?.transcriptDigestFingerprint, "AirShield no-HKDF cipher half is transcript digest")
  expect(noHKDFInputs.normalMaterialCandidate?.validationKeyFingerprint == noHKDFInputs.normalMaterialCandidate?.transcriptDigestFingerprint, "AirShield no-HKDF validation key is direct transcript digest")
  expect(noHKDFInputs.normalMaterialCandidate?.cipherKeyFingerprint == noHKDFInputs.normalMaterialCandidate?.transcriptDigestFingerprint, "AirShield no-HKDF cipher key is direct transcript digest")
  expect(noHKDFInputs.normalMaterialCandidate?.validationEqualsCipher == true, "AirShield no-HKDF keeps validation/cipher halves equal")
  expect(noHKDFInputs.normalMaterialCandidate?.initialCounterBlockSource == "seed_tail_8_plus_iv_head_8", "AirShield no-HKDF initial counter source")
  expect(noHKDFInputs.normalMaterialCandidate?.endLinkSetupFrameCandidate?.frameCounter == 0x01020304, "AirShield no-HKDF EndLinkSetup uses base counter")
  expect(noHKDFInputs.normalMaterialCandidate?.gestureEnableFrameCandidate?.frameCounter == 0x01020305, "AirShield no-HKDF gesture-enable follows base counter")

  let incompleteEnable = AirShieldLinkSetup.EnableEncryptionMessage(
    publicKey: responderProbe.publicKey,
    seed: nil,
    initializationVector: nil,
    base: 0x12345678,
    parameters: 1,
    quirks: nil,
    phasedLinkSetupSupported: nil,
    supportedLinkSetupServices: nil,
    linkSwitchVersionSupported: nil
  )
  let incompleteInputs = try! initiator.processEnableEncryption(incompleteEnable)
  expect(incompleteInputs.normalMaterialCandidate == nil, "AirShield normal material candidate requires seed material")
  expect(incompleteInputs.normalMaterialCandidates.isEmpty, "AirShield normal material candidate list requires seed material")
  expect(!initiator.hasReceiveCandidates, "AirShield session clears passive receive candidates when EnableEncryption lacks seed")
  expect(!initiator.hasValidatedReceiveCandidate, "AirShield session clears validated receive candidate when EnableEncryption lacks seed")

  let incompleteIVEnable = AirShieldLinkSetup.EnableEncryptionMessage(
    publicKey: responderProbe.publicKey,
    seed: Data((0..<32).map { UInt8(0xd0 + $0) }),
    initializationVector: nil,
    base: 0x12345678,
    parameters: 1,
    quirks: nil,
    phasedLinkSetupSupported: nil,
    supportedLinkSetupServices: nil,
    linkSwitchVersionSupported: nil
  )
  let incompleteIVInputs = try! initiator.processEnableEncryption(incompleteIVEnable)
  expect(incompleteIVInputs.normalMaterialCandidate != nil, "AirShield normal material candidate still derives without IV")
  expect(incompleteIVInputs.normalMaterialCandidate?.initialCounterBlockFingerprint == nil, "AirShield initial counter block candidate requires IV")
  expect(incompleteIVInputs.normalMaterialCandidate?.endLinkSetupFrameCandidate == nil, "AirShield EndLinkSetup frame candidate requires IV")
  expect(incompleteIVInputs.normalMaterialCandidate?.gestureEnableFrameCandidate == nil, "AirShield gesture-enable frame candidate requires IV")
  expect(!initiator.hasReceiveCandidates, "AirShield passive receive candidates require IV")
  expect(initiator.preparedGestureEnableFrameForValidatedReceiveCandidate() == nil, "AirShield gated gesture-enable frame requires IV")

  let deterministicLocalPrivateRaw = Data((1...32).map { UInt8($0) })
  let deterministicRemotePrivateRaw = Data((33...64).map { UInt8($0) })
  let deterministicLocalPrivateKey = try! P256.KeyAgreement.PrivateKey(rawRepresentation: deterministicLocalPrivateRaw)
  let deterministicRemotePrivateKey = try! P256.KeyAgreement.PrivateKey(rawRepresentation: deterministicRemotePrivateRaw)
  let deterministicRemotePublicRaw = Data(deterministicRemotePrivateKey.publicKey.x963Representation.dropFirst())
  let deterministicSession = AirShieldSession()
  let deterministicChallenge = Data((0..<16).map { UInt8(0x70 + $0) })
  _ = try! deterministicSession.makeRequestEncryptionProbe(
    challenge: deterministicChallenge,
    privateKey: deterministicLocalPrivateKey
  )
  let deterministicSeed = Data((0..<32).map { UInt8(0x90 + $0) })
  let deterministicIV = Data((0..<24).map { UInt8(0x30 + $0) })
  let deterministicEnable = AirShieldLinkSetup.EnableEncryptionMessage(
    publicKey: deterministicRemotePublicRaw,
    seed: deterministicSeed,
    initializationVector: deterministicIV,
    base: 0x01020304,
    parameters: 1,
    quirks: nil,
    phasedLinkSetupSupported: nil,
    supportedLinkSetupServices: nil,
    linkSwitchVersionSupported: nil
  )
  _ = try! deterministicSession.processEnableEncryption(deterministicEnable)
  expect(deterministicSession.hasReceiveCandidates, "AirShield deterministic session has receive candidates before gate fixture")
  expect(deterministicSession.preparedEndLinkSetupFrameForValidatedReceiveCandidate() == nil, "AirShield deterministic EndLinkSetup is gated before decrypt match")
  expect(deterministicSession.preparedGestureEnableFrameForValidatedReceiveCandidate() == nil, "AirShield deterministic gesture-enable is gated before decrypt match")
  let deterministicPlaintext = try! AirShieldLinkSetup.encodeDataXFrame(
    typedMessage: .endLinkSetup,
    payload: AirShieldLinkSetup.encodeEndLinkSetup(
      state: .main,
      uuid: Data(repeating: 0x42, count: 16)
    )
  )
  let deterministicFrames = try! AirShieldSession.syntheticFramingProbeCandidates(
    localPrivateKeyRaw: deterministicLocalPrivateRaw,
    remotePrivateKeyRaw: deterministicRemotePrivateRaw,
    remotePublicKeyRaw: nil,
    localChallenge: deterministicChallenge,
    seed: deterministicSeed,
    initializationVector: deterministicIV,
    plaintext: deterministicPlaintext,
    base: 0x01020304,
    usesHKDF: true
  )
  guard let deterministicFrame = deterministicFrames.first(where: {
    $0.sharedMaterialSource == "raw_p256_shared_secret__db17b4_default_label"
  }) else {
    expect(false, "AirShield deterministic primary frame candidate exists")
    return
  }
  let deterministicMatches = deterministicSession.decryptReceivedEncryptedFrameCandidates(deterministicFrame.frame.outerFrame)
  expect(deterministicMatches.count == 1, "AirShield deterministic passive decrypt produces one match")
  expect(
    deterministicMatches.first?.sharedMaterialSource == "raw_p256_shared_secret__db17b4_default_label",
    "AirShield deterministic passive decrypt validates primary material source"
  )
  expect(deterministicSession.hasValidatedReceiveCandidate, "AirShield deterministic session records validated receive source")
  expect(
    deterministicSession.preparedEndLinkSetupFrameForValidatedReceiveCandidate()?.sharedMaterialSource == deterministicMatches.first?.sharedMaterialSource,
    "AirShield deterministic EndLinkSetup unlocks for validated source"
  )
  expect(
    deterministicSession.preparedGestureEnableFrameForValidatedReceiveCandidate()?.sharedMaterialSource == deterministicMatches.first?.sharedMaterialSource,
    "AirShield deterministic gesture-enable unlocks for validated source"
  )

  let missingProbeSession = AirShieldSession()
  do {
    _ = try missingProbeSession.processEnableEncryption(enable)
    expect(false, "AirShield session rejects EnableEncryption before RequestEncryption probe")
  } catch AirShieldSessionError.missingProbe {
  } catch {
    expect(false, "AirShield session missing-probe error shape")
  }
}

func validateAirShieldIdentityImport() {
  let scalar = Data(repeating: 0x01, count: 32)
  let rawMaterial = AirShieldIdentityMaterial.fromRawPrivateKey(slot: .acdcAppPrivateKey, raw: scalar)
  expect(rawMaterial.rawPrivateKey == scalar, "AirShield identity keeps raw private-key blob")
  expect(rawMaterial.publicKeyCandidates.count == 1, "AirShield identity parses raw 32-byte scalar")
  expect(rawMaterial.publicKeyCandidates.first?.source == "raw_32", "AirShield identity raw scalar candidate source")
  expect(rawMaterial.publicKeyCandidates.first?.rawPublicKey.count == 64, "AirShield identity raw scalar public key length")
  expect(rawMaterial.publicKeyFingerprint?.count == 16, "AirShield identity public key fingerprint length")
  expect(rawMaterial.acceptedAuthenticationPublicKey?.count == 64, "AirShield accepted-auth public key is 64 bytes")
  expect(rawMaterial.acceptedAuthenticationPublicKey == rawMaterial.rawPublicKey, "AirShield accepted-auth public key passes raw 64-byte point through")
  expect(rawMaterial.acceptedAuthenticationPublicKeyFingerprint == rawMaterial.publicKeyFingerprint, "AirShield accepted-auth fingerprint matches raw point for 64-byte candidate")
  expect(rawMaterial.publicKeyCandidates.first?.acceptedAuthenticationPublicKeyFingerprint == rawMaterial.publicKeyFingerprint, "AirShield accepted-auth candidate fingerprint is logged")

  let shortPublicKey = Data([0x01, 0x02, 0x03])
  let shortAcceptedKey = AirShieldIdentityMaterial.acceptedAuthenticationPublicKey(from: shortPublicKey)
  expect(shortAcceptedKey.count == 64, "AirShield accepted-auth short key pads to 64 bytes")
  expect(shortAcceptedKey.prefix(3) == shortPublicKey, "AirShield accepted-auth padded key preserves prefix")
  expect(shortAcceptedKey.dropFirst(3).allSatisfy { $0 == 0 }, "AirShield accepted-auth padded key uses zero tail")

  let longPublicKey = Data((0..<70).map { UInt8($0 & 0xff) })
  let longAcceptedKey = AirShieldIdentityMaterial.acceptedAuthenticationPublicKey(from: longPublicKey)
  expect(longAcceptedKey.count == 64, "AirShield accepted-auth long key truncates to 64 bytes")
  expect(longAcceptedKey == longPublicKey.prefix(64), "AirShield accepted-auth long key preserves first 64 bytes")

  let prefixed = Data([0xaa, 0xbb]) + scalar
  let prefixedMaterial = AirShieldIdentityMaterial.fromRawPrivateKey(slot: .linkedAppPrivateKey, raw: prefixed)
  expect(prefixedMaterial.publicKeyCandidates.contains { $0.source == "last_32" }, "AirShield identity parses last 32 bytes of native-like blob")
  expect(prefixedMaterial.publicKeyCandidates.contains { $0.publicKeyFingerprint == rawMaterial.publicKeyFingerprint }, "AirShield identity last32 candidate fingerprint matches raw scalar")

  let suffixed = scalar + Data([0xcc, 0xdd])
  let suffixedMaterial = AirShieldIdentityMaterial.fromRawPrivateKey(slot: .linkedAppPrivateKey, raw: suffixed)
  expect(suffixedMaterial.publicKeyCandidates.contains { $0.source == "first_32" }, "AirShield identity parses first 32 bytes of native-like blob")
  expect(suffixedMaterial.publicKeyCandidates.contains { $0.publicKeyFingerprint == rawMaterial.publicKeyFingerprint }, "AirShield identity first32 candidate fingerprint matches raw scalar")

  let repeated = scalar + scalar
  let repeatedMaterial = AirShieldIdentityMaterial.fromRawPrivateKey(slot: .linkedAppPrivateKey, raw: repeated)
  expect(repeatedMaterial.publicKeyCandidates.count == 1, "AirShield identity de-duplicates equivalent first/last candidates")

  let imported = try! AirShieldIdentityMaterial.imported(
    slot: .acdcAppPrivateKey,
    base64: scalar.base64EncodedString()
  )
  expect(imported.publicKeyFingerprint == rawMaterial.publicKeyFingerprint, "AirShield identity Base64 import parses scalar")
  let challengeHash = Data((0..<32).map { UInt8(0xe0 + ($0 & 0x1f)) })
  let enableTrustCandidates = imported.enableTrustCandidateSummaries(challengeHash: challengeHash)
  expect(enableTrustCandidates.count == 9, "AirShield identity EnableTrust candidates include three signatures across three local channel ids")
  expect(Set(enableTrustCandidates.map(\.signatureFormat)).contains("cryptokit_p256_ecdsa_der_sha256_over_challenge_hash"), "AirShield EnableTrust candidates include DER signature")
  expect(Set(enableTrustCandidates.map(\.signatureFormat)).contains("native_format_raw64_but_swift_sha256_over_challenge_hash"), "AirShield EnableTrust candidates include native-format raw64 signature")
  expect(Set(enableTrustCandidates.map(\.signatureFormat)).contains("security_p256_ecdsa_raw64_digest_challenge_hash_native_format"), "AirShield EnableTrust candidates include Security raw-digest native-format raw64 signature")
  expect(Set(enableTrustCandidates.map(\.localChannelID)) == Set(AirShieldAuthService.candidateLocalChannelIDs), "AirShield EnableTrust candidates cover native local channel id variants")
  expect(enableTrustCandidates.allSatisfy { $0.baseID == NativeDataXLocalChannel.baseID(localChannelID: $0.localChannelID) }, "AirShield EnableTrust candidate base ids follow native rule")
  expect(enableTrustCandidates.allSatisfy { $0.scalarSource == "raw_32" }, "AirShield EnableTrust raw scalar source")
  expect(enableTrustCandidates.allSatisfy { $0.identifierLength == 32 }, "AirShield EnableTrust identifier length")
  expect(enableTrustCandidates.allSatisfy { $0.challengeHashLength == 32 }, "AirShield EnableTrust challenge hash length")
  expect(enableTrustCandidates.allSatisfy { $0.payloadLength > 0 && $0.frameLength > $0.payloadLength }, "AirShield EnableTrust candidates include payload and DataX frame summaries")
  expect(enableTrustCandidates.allSatisfy { $0.transmitState == "not_transmitted_requires_identity_path_match" }, "AirShield EnableTrust candidates are non-transmitting")
  expect(enableTrustCandidates.allSatisfy { $0.candidateID.count == 24 }, "AirShield EnableTrust candidates include stable short candidate id")
  expect(Set(enableTrustCandidates.map(\.candidateID)).count == enableTrustCandidates.count, "AirShield EnableTrust candidate ids are unique for fixture")
  expect(enableTrustCandidates.filter { $0.signatureFormat.contains("raw64") }.allSatisfy { $0.signatureLength == 64 }, "AirShield raw64 signature candidate length")

  let prefixedEnableTrustCandidates = prefixedMaterial.enableTrustCandidateSummaries(challengeHash: challengeHash)
  expect(prefixedEnableTrustCandidates.count >= 12, "AirShield native-like blob EnableTrust candidates cover blob/scalar identifiers and channel variants")
  expect(Set(prefixedEnableTrustCandidates.map(\.identifierSource)).contains("sha256_imported_private_blob"), "AirShield EnableTrust includes imported blob identifier")
  expect(Set(prefixedEnableTrustCandidates.map(\.identifierSource)).contains("sha256_last_32_scalar"), "AirShield EnableTrust includes scalar identifier")
  expect(Set(prefixedEnableTrustCandidates.map(\.signatureFormat)).contains("cryptokit_p256_ecdsa_der_sha256_over_challenge_hash"), "AirShield native-like EnableTrust includes DER signature")
  expect(Set(prefixedEnableTrustCandidates.map(\.signatureFormat)).contains("native_format_raw64_but_swift_sha256_over_challenge_hash"), "AirShield native-like EnableTrust includes native-format raw64 signature")
  expect(Set(prefixedEnableTrustCandidates.map(\.signatureFormat)).contains("security_p256_ecdsa_raw64_digest_challenge_hash_native_format"), "AirShield native-like EnableTrust includes Security raw-digest native-format signature")

  do {
    _ = try AirShieldIdentityMaterial.imported(slot: .acdcAppPrivateKey, base64: "not base64")
    expect(false, "AirShield identity rejects invalid Base64")
  } catch AirShieldIdentityImportError.invalidBase64 {
  } catch {
    expect(false, "AirShield identity invalid Base64 error shape")
  }
}

func validateAirShieldEnableTrustGate() {
  let validGateJSON: [String: Any] = [
    "schema": AirShieldEnableTrustGate.schema,
    "status": AirShieldEnableTrustGate.eligibleStatus,
    "eligible_for_manual_mac_auth_transmit": true,
    "candidate_id": "security-raw64-candidate",
    "frame_fingerprint": "aabbccddeeff0011"
  ]
  let validGateData = try! JSONSerialization.data(withJSONObject: validGateJSON)
  let validGate = try! AirShieldEnableTrustGate.parse(data: validGateData)
  expect(validGate.candidateID == "security-raw64-candidate", "AirShield gate parses candidate_id")
  expect(validGate.frameFingerprint == "aabbccddeeff0011", "AirShield gate parses frame fingerprint")

  do {
    _ = try AirShieldEnableTrustGate.parse(json: validGateJSON.merging(["schema": "wrong"]) { _, new in new })
    expect(false, "AirShield gate rejects invalid schema")
  } catch AirShieldEnableTrustGateError.invalidSchema {
  } catch {
    expect(false, "AirShield gate invalid schema error shape")
  }

  do {
    _ = try AirShieldEnableTrustGate.parse(json: validGateJSON.merging(["status": "TX_CHALLENGE_MATCH_ONLY"]) { _, new in new })
    expect(false, "AirShield gate rejects ineligible status")
  } catch AirShieldEnableTrustGateError.notEligible {
  } catch {
    expect(false, "AirShield gate ineligible status error shape")
  }

  do {
    _ = try AirShieldEnableTrustGate.parse(json: validGateJSON.merging(["eligible_for_manual_mac_auth_transmit": false]) { _, new in new })
    expect(false, "AirShield gate rejects false eligibility flag")
  } catch AirShieldEnableTrustGateError.notEligible {
  } catch {
    expect(false, "AirShield gate ineligible flag error shape")
  }

  do {
    _ = try AirShieldEnableTrustGate.parse(json: validGateJSON.merging(["candidate_id": "  "]) { _, new in new })
    expect(false, "AirShield gate rejects empty candidate_id")
  } catch AirShieldEnableTrustGateError.missingCandidateID {
  } catch {
    expect(false, "AirShield gate missing candidate id error shape")
  }

  do {
    _ = try AirShieldEnableTrustGate.parse(data: Data("[1,2,3]".utf8))
    expect(false, "AirShield gate rejects non-object JSON")
  } catch AirShieldEnableTrustGateError.invalidJSON {
  } catch {
    expect(false, "AirShield gate invalid JSON error shape")
  }

  expect(AirShieldEnableTrustGate.fingerprintMatches("aabbccdd", "AABBCCDDEEFF0011"), "AirShield gate fingerprint accepts logged prefix")
  expect(AirShieldEnableTrustGate.fingerprintMatches("aabbccddeeff0011", "aabbccdd"), "AirShield gate fingerprint accepts staged prefix")
  expect(!AirShieldEnableTrustGate.fingerprintMatches("aabbccdd", "bbccddeeff0011"), "AirShield gate fingerprint rejects mismatch")
}

@main
struct DataXCodecValidation {
  static func main() {
    validateBandScanner()
    validateGattSession()
    validateL2CAPSession()
    validateGestureEnableRPC()
    validateDecoderBuffering()
    validateReservedHeaderBit14()
    validateAirShieldAuthServiceMapping()
    validateAirShieldAuthPayloadDecode()
    validateAirShieldFramingSizes()
    validateAirShieldSelectedTransformCounter()
    validateAirShieldEncryptedFrameCandidate()
    validateAirShieldFramingExpansion()
    validateGestureDecode()
    validateGestureForwardPayload()
    validateStreamControlDecode()
    validateProtoMessageSummary()
    validateAirShieldProtobufs()
    validateAirShieldSessionState()
    validateAirShieldIdentityImport()
    validateAirShieldEnableTrustGate()
    print("DataXCodecValidation passed")
  }
}
