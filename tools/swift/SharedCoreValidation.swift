import Foundation

@inline(__always)
func expectShared(_ condition: @autoclosure () -> Bool, _ message: String) {
  if !condition() {
    fputs("FAIL: \(message)\n", stderr)
    exit(1)
  }
}

func sharedData(_ bytes: [UInt8]) -> Data {
  Data(bytes)
}

func validateSharedDataXCore() {
  let payload = WISProtocol.streamControlEnableGesturesRpc(seq: 1)
  expectShared(payload.hexString == "080122021801", "shared core gesture-enable payload")

  let frame = try! DataXFrameEncoder.encode(
    baseID: 0x8000,
    payload: payload,
    extensions: WISProtocol.dataXExtensions(appID: .rpc, messageType: .request)
  )
  var decoder = DataXFrameDecoder()
  let frames = decoder.append(frame)
  expectShared(frames.count == 1, "shared core DataX frame decodes")
  expectShared(frames[0].decodedAppID == WISProtocol.AppID.rpc.rawValue, "shared core DataX app id")
  expectShared(frames[0].decodedMessageType == WISProtocol.MessageType.request.rawValue, "shared core DataX message type")
}

func validateSharedGestureCore() {
  let payload = sharedData([
    0x08, 0x2a,
    0x10, 0xe7, 0x07,
    0x18, 0x01,
    0x20, 0x03,
    0x28, 0x01,
    0x58, 0x7b,
    0x60, 0x01
  ])
  let gesture = GestureEventDecoder.decode(payload)
  expectShared(gesture?.sequenceNumber == 42, "shared core gesture sequence")
  expectShared(gesture?.fingerName == "thumb", "shared core gesture finger")
  expectShared(gesture?.normalizedAction == "tap", "shared core gesture normalized action")
  expectShared(gesture?.emgRawGestureID == 123, "shared core gesture raw id")
  expectShared(gesture?.isSyntheticGesture == true, "shared core gesture synthetic flag")
}

func validateSharedAirShieldCore() {
  expectShared(AirShieldFraming.validationPrefixLength == 8, "shared core AirShield validation prefix length")
  expectShared(AirShieldFraming.cipherPayloadSizeIndicatorOffset == 8, "shared core AirShield size indicator offset")
  expectShared(AirShieldFraming.cipherPayloadOffset == 9, "shared core AirShield cipher payload offset")
  expectShared(AirShieldFraming.outerFrameSize(forPlaintextLength: 17) == 41, "shared core AirShield outer size")

  let keyMaterial = Data((0..<32).map { UInt8($0 & 0xff) })
  let expanded = try! AirShieldFramingExpansion.expandDefaultLabelCounter1(keyMaterial: keyMaterial)
  expectShared(
    expanded.hexString == "d7536d4f76ad769088686b1e1059a17f2d17b4f94c9e8c88e13254ba155ef799",
    "shared core AirShield expansion fixture"
  )

  let nistAES256Key = sharedData([
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
  ])
  let nistCounter = sharedData([
    0xf0, 0xf1, 0xf2, 0xf3,
    0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff
  ])
  let nistPlaintext = sharedData([
    0x6b, 0xc1, 0xbe, 0xe2,
    0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11,
    0x73, 0x93, 0x17, 0x2a
  ])
  let ciphertext = AirShieldFraming.selectedTransformCTRApplyCandidate(
    input: nistPlaintext,
    cipherKey: nistAES256Key,
    initialCounterBlock: nistCounter
  )
  expectShared(
    ciphertext?.hexString == "601ec313775789a5b7a7f504bbf3d228",
    "shared core AES-CTR fixture"
  )

  let validationKey = keyMaterial
  let frameCandidate = AirShieldFraming.encryptedFrameCandidate(
    plaintext: nistPlaintext,
    validationKey: validationKey,
    cipherKey: nistAES256Key,
    initialCounterBlock: nistCounter,
    runtimeValidationMode: 0,
    frameCounter: 0
  )
  expectShared(
    frameCandidate?.outerFrame.hexString == "a76ba489dbdd111b00601ec313775789a5b7a7f504bbf3d228",
    "shared core AirShield encrypted-frame fixture"
  )

  let decryptedFrameCandidate = AirShieldFraming.decryptedFrameCandidate(
    outerFrame: frameCandidate!.outerFrame,
    validationKey: validationKey,
    cipherKey: nistAES256Key,
    initialCounterBlock: nistCounter,
    runtimeValidationMode: 0,
    frameCounter: 0
  )
  expectShared(decryptedFrameCandidate?.plaintext == nistPlaintext, "shared core AirShield decrypt round trip")
  expectShared(decryptedFrameCandidate?.counterSearchOffset == 0, "shared core AirShield decrypt counter offset")

  let syntheticCandidates = try! AirShieldSession.syntheticFramingProbeCandidates(
    localPrivateKeyRaw: Data((1...32).map(UInt8.init)),
    remotePrivateKeyRaw: Data((2...33).map(UInt8.init)),
    remotePublicKeyRaw: nil,
    localChallenge: sharedData([
      0x00, 0x11, 0x22, 0x33,
      0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb,
      0xcc, 0xdd, 0xee, 0xff
    ]),
    seed: sharedData((0x00...0x1f).map(UInt8.init)),
    initializationVector: sharedData((0xa0...0xaf).map(UInt8.init)),
    plaintext: nistPlaintext,
    base: 0,
    usesHKDF: true
  )
  expectShared(syntheticCandidates.count == 9, "shared core synthetic framing probe candidate count")
  expectShared(
    syntheticCandidates.first?.sharedMaterialSource == "raw_p256_shared_secret__db17b4_default_label",
    "shared core synthetic framing probe primary candidate"
  )
  expectShared(
    syntheticCandidates.allSatisfy { $0.frame.summary.outerFrameLength == 25 },
    "shared core synthetic framing probe aligned outer frame length"
  )
}

@main
struct SharedCoreValidation {
  static func main() {
    validateSharedDataXCore()
    validateSharedGestureCore()
    validateSharedAirShieldCore()
    print("SharedCoreValidation passed")
  }
}
