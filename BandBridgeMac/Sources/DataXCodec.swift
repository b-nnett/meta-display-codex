import CryptoKit
import CommonCrypto
import Foundation

enum NativeDataXLocalChannel {
  static let defaultLocalChannelID: UInt16 = 0

  static func baseID(localChannelID: UInt16 = defaultLocalChannelID) -> UInt16 {
    localChannelID ^ 0x8000
  }
}

enum WISProtocol {
  static let localServiceID: UInt16 = 52822
  static let outboundTypedBufferType: UInt16 = 788

  enum AppID: UInt8 {
    case unknown = 0
    case test = 1
    case emgImu = 2
    case rpc = 3
    case security = 4
  }

  enum MessageType: UInt16 {
    case ping = 1
    case emg = 10
    case imu = 11
    case inference = 12
    case gesture = 13
    case request = 20
    case response = 21
    case streamUpdate = 22
    case authentication = 23
    case encryption = 24
    case emgImuBatch = 41
  }

  static func streamControlEnableGesturesRpc(seq: UInt8 = 1) -> Data {
    // RpcRequest { seq, streamControlReq { enableGestures: true } }
    Data([0x08, seq, 0x22, 0x02, 0x18, 0x01])
  }

  static func messageTypeValue(appID: AppID, messageType: MessageType) -> UInt16 {
    (UInt16(appID.rawValue) << 8) | UInt16(UInt8(messageType.rawValue & 0xff))
  }

  static func dataXExtensions(
    appID: AppID,
    messageType: MessageType,
    includeChannelAlias: Bool = true
  ) -> [DataXExtensionWord] {
    var words: [DataXExtensionWord] = []
    if includeChannelAlias {
      words.append(DataXExtensionWord(rawType: 1, value: localServiceID))
    }
    words.append(DataXExtensionWord(
      rawType: 2,
      value: messageTypeValue(appID: appID, messageType: messageType)
    ))
    return words
  }
}

enum AirShieldLinkSetup {
  static let dataXServiceID: UInt16 = 5

  enum TypedMessage: UInt16 {
    case requestEncryption = 1
    case enableEncryption = 2
    case linkSetupConfig = 3
    case endLinkSetup = 4096
    case bypassLinkSetup2P = 8192
    case identify3P = 8193
    case associate3P = 8194
  }

  enum LinkState: UInt64 {
    case ready = 0
    case main = 1
  }

  struct RequestEncryptionMessage: Hashable {
    var publicKey: Data?
    var challenge: Data?
    var ellipticCurve: UInt64?
    var supportedParameters: UInt64?
    var keyHints: [Data]
    var quirks: UInt64?
    var airShieldVersion: UInt64?

    var usesHKDF: Bool {
      ((supportedParameters ?? 0) & 1) == 1
    }

    var description: String {
      [
        "RequestEncryption",
        "publicKey=\(publicKey?.count ?? 0)B",
        "challenge=\(challenge?.count ?? 0)B",
        "curve=\(ellipticCurve.map(String.init) ?? "nil")",
        "hkdf=\(usesHKDF)",
        "keyHints=\(keyHints.count)",
        "quirks=\(quirks.map(String.init) ?? "nil")",
        "version=\(airShieldVersion.map(String.init) ?? "nil")"
      ].joined(separator: " ")
    }
  }

  struct EnableEncryptionMessage: Hashable {
    var publicKey: Data?
    var seed: Data?
    var initializationVector: Data?
    var base: UInt64?
    var parameters: UInt64?
    var quirks: UInt64?
    var phasedLinkSetupSupported: Bool?
    var supportedLinkSetupServices: UInt64?
    var linkSwitchVersionSupported: UInt64?

    var usesHKDF: Bool {
      ((parameters ?? 0) & 1) == 1
    }

    var description: String {
      [
        "EnableEncryption",
        "publicKey=\(publicKey?.count ?? 0)B",
        "seed=\(seed?.count ?? 0)B",
        "iv=\(initializationVector?.count ?? 0)B",
        "base=\(base.map(String.init) ?? "nil")",
        "hkdf=\(usesHKDF)",
        "quirks=\(quirks.map(String.init) ?? "nil")",
        "phased=\(phasedLinkSetupSupported.map(String.init) ?? "nil")",
        "services=\(supportedLinkSetupServices.map(String.init) ?? "nil")",
        "linkSwitch=\(linkSwitchVersionSupported.map(String.init) ?? "nil")"
      ].joined(separator: " ")
    }
  }

  struct EndLinkSetupMessage: Hashable {
    var state: UInt64?
    var uuid: Data?
    var linkUUID: Data?
    var userDataFieldCount: Int

    var description: String {
      [
        "EndLinkSetup",
        "state=\(state.map(String.init) ?? "nil")",
        "uuid=\(uuid?.count ?? 0)B",
        "linkUUID=\(linkUUID?.count ?? 0)B",
        "userDataFields=\(userDataFieldCount)"
      ].joined(separator: " ")
    }
  }

  enum DecodedMessage: Hashable, CustomStringConvertible {
    case requestEncryption(RequestEncryptionMessage)
    case enableEncryption(EnableEncryptionMessage)
    case endLinkSetup(EndLinkSetupMessage)
    case knownButUndecoded(TypedMessage, payloadLength: Int)

    var description: String {
      switch self {
      case .requestEncryption(let message):
        return message.description
      case .enableEncryption(let message):
        return message.description
      case .endLinkSetup(let message):
        return message.description
      case .knownButUndecoded(let typedMessage, let payloadLength):
        return "AirShield \(typedMessage) payload=\(payloadLength)B"
      }
    }
  }

  static func encodeRequestEncryption(publicKey: Data, challenge: Data) -> Data {
    var data = Data()
    data.appendProtoLengthDelimited(field: 1, publicKey)
    data.appendProtoLengthDelimited(field: 2, challenge)
    data.appendProtoVarint(field: 3, 0) // Secp256r1
    data.appendProtoVarint(field: 4, 1) // supportedParameters bit 0 = HKDF
    return data
  }

  static func dataXExtensions(typedMessage: TypedMessage) -> [DataXExtensionWord] {
    [
      DataXExtensionWord(rawType: 1, value: dataXServiceID),
      DataXExtensionWord(rawType: 2, value: typedMessage.rawValue)
    ]
  }

  static func encodeDataXFrame(
    typedMessage: TypedMessage,
    payload: Data,
    baseID: UInt16 = NativeDataXLocalChannel.baseID()
  ) throws -> Data {
    try DataXFrameEncoder.encode(
      baseID: baseID,
      payload: payload,
      extensions: dataXExtensions(typedMessage: typedMessage)
    )
  }

  static func encodeEnableEncryption(
    publicKey: Data,
    seed: Data,
    initializationVector: Data,
    base: UInt64,
    usesHKDF: Bool = true
  ) -> Data {
    var data = Data()
    data.appendProtoLengthDelimited(field: 1, publicKey)
    data.appendProtoLengthDelimited(field: 2, seed)
    data.appendProtoLengthDelimited(field: 3, initializationVector)
    data.appendProtoVarint(field: 4, base)
    data.appendProtoVarint(field: 5, usesHKDF ? 1 : 0)
    return data
  }

  static func encodeEndLinkSetup(state: LinkState, uuid: Data, linkUUID: Data? = nil) -> Data {
    var data = Data()
    data.appendProtoVarint(field: 1, state.rawValue)
    data.appendProtoLengthDelimited(field: 2, uuid)
    if let linkUUID {
      data.appendProtoLengthDelimited(field: 3, linkUUID)
    }
    return data
  }

  static func decode(typedMessage: TypedMessage, payload: Data) -> DecodedMessage {
    switch typedMessage {
    case .requestEncryption:
      return .requestEncryption(decodeRequestEncryption(payload))
    case .enableEncryption:
      return .enableEncryption(decodeEnableEncryption(payload))
    case .endLinkSetup:
      return .endLinkSetup(decodeEndLinkSetup(payload))
    default:
      return .knownButUndecoded(typedMessage, payloadLength: payload.count)
    }
  }

  static func decodeRequestEncryption(_ data: Data) -> RequestEncryptionMessage {
    var reader = ProtoReader(data)
    var message = RequestEncryptionMessage(
      publicKey: nil,
      challenge: nil,
      ellipticCurve: nil,
      supportedParameters: nil,
      keyHints: [],
      quirks: nil,
      airShieldVersion: nil
    )

    while let field = reader.nextField() {
      switch field.number {
      case 1:
        message.publicKey = reader.readLengthDelimited()
      case 2:
        message.challenge = reader.readLengthDelimited()
      case 3:
        message.ellipticCurve = reader.readVarint()
      case 4:
        message.supportedParameters = reader.readVarint()
      case 5:
        if let keyHint = reader.readLengthDelimited() {
          message.keyHints.append(keyHint)
        }
      case 6:
        message.quirks = reader.readVarint()
      case 7:
        message.airShieldVersion = reader.readVarint()
      default:
        reader.skip(wireType: field.wireType)
      }
    }
    return message
  }

  static func decodeEnableEncryption(_ data: Data) -> EnableEncryptionMessage {
    var reader = ProtoReader(data)
    var message = EnableEncryptionMessage(
      publicKey: nil,
      seed: nil,
      initializationVector: nil,
      base: nil,
      parameters: nil,
      quirks: nil,
      phasedLinkSetupSupported: nil,
      supportedLinkSetupServices: nil,
      linkSwitchVersionSupported: nil
    )

    while let field = reader.nextField() {
      switch field.number {
      case 1:
        message.publicKey = reader.readLengthDelimited()
      case 2:
        message.seed = reader.readLengthDelimited()
      case 3:
        message.initializationVector = reader.readLengthDelimited()
      case 4:
        message.base = reader.readVarint()
      case 5:
        message.parameters = reader.readVarint()
      case 6:
        message.quirks = reader.readVarint()
      case 7:
        message.phasedLinkSetupSupported = (reader.readVarint() ?? 0) != 0
      case 8:
        message.supportedLinkSetupServices = reader.readVarint()
      case 9:
        message.linkSwitchVersionSupported = reader.readVarint()
      default:
        reader.skip(wireType: field.wireType)
      }
    }
    return message
  }

  static func decodeEndLinkSetup(_ data: Data) -> EndLinkSetupMessage {
    var reader = ProtoReader(data)
    var message = EndLinkSetupMessage(state: nil, uuid: nil, linkUUID: nil, userDataFieldCount: 0)

    while let field = reader.nextField() {
      switch field.number {
      case 1:
        message.state = reader.readVarint()
      case 2:
        message.uuid = reader.readLengthDelimited()
      case 3:
        message.linkUUID = reader.readLengthDelimited()
      case 4:
        message.userDataFieldCount += 1
        reader.skip(wireType: field.wireType)
      default:
        reader.skip(wireType: field.wireType)
      }
    }
    return message
  }
}

enum AirShieldAuthService {
  static let identityServiceID: UInt16 = 36
  static let prototypeIdentityServiceID: UInt16 = 77
  static let identityEnableTrustType: UInt16 = 4096
  static let prototypeRegisterKeyType: UInt16 = 8192
  static let candidateLocalChannelIDs: [UInt16] = [0, 1, 2]

  static func serviceName(_ serviceID: UInt16) -> String? {
    switch serviceID {
    case identityServiceID:
      return "identity"
    case prototypeIdentityServiceID:
      return "prototype_identity"
    default:
      return nil
    }
  }

  static func typedBufferName(serviceID: UInt16, typedBufferType: UInt16) -> String? {
    switch serviceID {
    case identityServiceID:
      return identityTypedBufferName(typedBufferType)
    case prototypeIdentityServiceID:
      return prototypeIdentityTypedBufferName(typedBufferType)
    default:
      return nil
    }
  }

  private static func identityTypedBufferName(_ value: UInt16) -> String? {
    switch value {
    case 4096: return "ENABLE_TRUST"
    case 4097: return "ENABLE_TRUST_EC"
    case 8192: return "SKIP_CHALLENGE"
    case 8193: return "SKIP_CHALLENGE_RESPONSE"
    case 8194: return "START_CHANGE_OWNER"
    case 8195: return "START_CHANGE_OWNER_RESPONSE"
    case 8196: return "FINISH_CHANGE_OWNER"
    case 8197: return "FINISH_CHANGE_OWNER_RESPONSE"
    case 12288: return "IDENTITY_REQUEST"
    case 12289: return "IDENTITY_RESPONSE"
    case 16384: return "NUX_REGISTRATION_CHALLENGE"
    case 16385: return "NUX_REGISTRATION_CHALLENGE_RESPONSE"
    case 16386: return "NUX_INSTALL_DEVICE_IDENTITY"
    case 16387: return "NUX_INSTALL_DEVICE_IDENTITY_RESPONSE"
    case 20480: return "MANIFEST_KEY"
    case 20481: return "ENABLE_EC_AUTH"
    default: return nil
    }
  }

  private static func prototypeIdentityTypedBufferName(_ value: UInt16) -> String? {
    switch value {
    case 4096: return "ENABLE_TRUST"
    case 8192: return "REGISTER_KEY"
    case 8193: return "KEY_ACCEPTED"
    default: return nil
    }
  }

  static func dataXExtensions(serviceID: UInt16, typedBufferType: UInt16) -> [DataXExtensionWord] {
    [
      DataXExtensionWord(rawType: 1, value: serviceID),
      DataXExtensionWord(rawType: 2, value: typedBufferType)
    ]
  }

  static func encodeDataXFrame(
    serviceID: UInt16,
    typedBufferType: UInt16,
    payload: Data,
    baseID: UInt16 = NativeDataXLocalChannel.baseID()
  ) throws -> Data {
    try DataXFrameEncoder.encode(
      baseID: baseID,
      payload: payload,
      extensions: dataXExtensions(serviceID: serviceID, typedBufferType: typedBufferType)
    )
  }

  static func encodeIdentityEnableTrust(
    identifier: Data,
    signature: Data,
    provisioningCapabilities: UInt64 = 2
  ) -> Data {
    var data = Data()
    data.appendProtoLengthDelimited(field: 1, identifier)
    data.appendProtoLengthDelimited(field: 2, signature)
    data.appendProtoVarint(field: 3, provisioningCapabilities)
    return data
  }

  static func encodePrototypeRegisterKey(publicKey: Data, userID: String) -> Data {
    var data = Data()
    data.appendProtoLengthDelimited(field: 1, publicKey)
    data.appendProtoLengthDelimited(field: 2, Data(userID.utf8))
    return data
  }
}

struct AirShieldAuthPayloadSummary: CustomStringConvertible {
  struct Field: CustomStringConvertible {
    var name: String
    var kind: String
    var length: Int?
    var fingerprint: String?
    var value: String?

    var logFields: [String: Any] {
      var fields: [String: Any] = [
        "name": name,
        "kind": kind
      ]
      if let length {
        fields["length"] = length
      }
      if let fingerprint {
        fields["fingerprint"] = fingerprint
      }
      if let value {
        fields["value"] = value
      }
      return fields
    }

    var description: String {
      var parts = ["\(name)=\(kind)"]
      if let length {
        parts.append("\(length)B")
      }
      if let fingerprint {
        parts.append("fp=\(fingerprint)")
      }
      if let value {
        parts.append("value=\(value)")
      }
      return parts.joined(separator: " ")
    }
  }

  var serviceID: UInt16
  var serviceName: String
  var typedBufferType: UInt16
  var typedBufferName: String
  var payloadLength: Int
  var fields: [Field]
  var unknownFieldCount: Int

  var logFields: [String: Any] {
    [
      "service_id": Int(serviceID),
      "service_name": serviceName,
      "typed_buffer_type": Int(typedBufferType),
      "typed_buffer_name": typedBufferName,
      "payload_length": payloadLength,
      "field_count": fields.count,
      "unknown_field_count": unknownFieldCount,
      "fields": fields.map(\.logFields)
    ]
  }

  var description: String {
    let fieldText = fields.isEmpty ? "empty" : fields.map(\.description).joined(separator: "; ")
    return "AirShieldAuth \(serviceName).\(typedBufferName) payload=\(payloadLength)B unknown=\(unknownFieldCount) \(fieldText)"
  }
}

enum AirShieldAuthPayloadDecoder {
  static func decode(serviceID: UInt16, typedBufferType: UInt16, payload: Data) -> AirShieldAuthPayloadSummary? {
    guard let serviceName = AirShieldAuthService.serviceName(serviceID),
          let typedBufferName = AirShieldAuthService.typedBufferName(serviceID: serviceID, typedBufferType: typedBufferType) else {
      return nil
    }

    let fields: [AirShieldAuthPayloadSummary.Field]
    let unknownFieldCount: Int
    switch (serviceID, typedBufferType) {
    case (AirShieldAuthService.identityServiceID, 4096):
      (fields, unknownFieldCount) = decodeKnownFields(
        payload,
        fieldMap: [
          1: .bytes("identifier"),
          2: .bytes("signature"),
          3: .varint("provisioning_capabilities")
        ]
      )
    case (AirShieldAuthService.identityServiceID, 4097):
      (fields, unknownFieldCount) = decodeKnownFields(
        payload,
        fieldMap: [
          1: .bytes("key_hint"),
          2: .bytes("signature"),
          3: .varint("provisioning_capabilities")
        ]
      )
    case (AirShieldAuthService.identityServiceID, 8192):
      (fields, unknownFieldCount) = decodeKnownFields(payload, fieldMap: [:])
    case (AirShieldAuthService.identityServiceID, 12288):
      (fields, unknownFieldCount) = decodeKnownFields(payload, fieldMap: [:])
    case (AirShieldAuthService.identityServiceID, 12289):
      (fields, unknownFieldCount) = decodeKnownFields(
        payload,
        fieldMap: [
          1: .bytes("certificate"),
          2: .string("serial"),
          3: .string("registration_challenge_request_package"),
          4: .bool("drk_certificate_present"),
          5: .bytes("secondary_certificate")
        ]
      )
    case (AirShieldAuthService.prototypeIdentityServiceID, 4096):
      (fields, unknownFieldCount) = decodeKnownFields(
        payload,
        fieldMap: [
          1: .bytes("identifier"),
          2: .bytes("signature")
        ]
      )
    case (AirShieldAuthService.prototypeIdentityServiceID, 8192):
      (fields, unknownFieldCount) = decodeKnownFields(
        payload,
        fieldMap: [
          1: .bytes("pubkey"),
          2: .string("user_id")
        ]
      )
    case (AirShieldAuthService.prototypeIdentityServiceID, 8193):
      (fields, unknownFieldCount) = decodeKnownFields(
        payload,
        fieldMap: [
          1: .bytes("acceptor_pubkey"),
          2: .bytes("key_derivation_key")
        ]
      )
    default:
      return nil
    }

    return AirShieldAuthPayloadSummary(
      serviceID: serviceID,
      serviceName: serviceName,
      typedBufferType: typedBufferType,
      typedBufferName: typedBufferName,
      payloadLength: payload.count,
      fields: fields,
      unknownFieldCount: unknownFieldCount
    )
  }

  private enum FieldSpec {
    case bytes(String)
    case string(String)
    case varint(String)
    case bool(String)
  }

  private static func decodeKnownFields(
    _ payload: Data,
    fieldMap: [Int: FieldSpec]
  ) -> ([AirShieldAuthPayloadSummary.Field], Int) {
    var reader = ProtoReader(payload)
    var fields: [AirShieldAuthPayloadSummary.Field] = []
    var unknownFieldCount = 0

    while let field = reader.nextField() {
      guard let spec = fieldMap[field.number] else {
        unknownFieldCount += 1
        reader.skip(wireType: field.wireType)
        continue
      }

      switch spec {
      case .bytes(let name):
        guard field.wireType == 2, let value = reader.readLengthDelimited() else {
          unknownFieldCount += 1
          reader.skip(wireType: field.wireType)
          continue
        }
        fields.append(.init(
          name: name,
          kind: "bytes",
          length: value.count,
          fingerprint: value.shortSHA256Fingerprint,
          value: nil
        ))
      case .string(let name):
        guard field.wireType == 2, let value = reader.readLengthDelimited() else {
          unknownFieldCount += 1
          reader.skip(wireType: field.wireType)
          continue
        }
        fields.append(.init(
          name: name,
          kind: "string",
          length: value.count,
          fingerprint: value.shortSHA256Fingerprint,
          value: String(data: value, encoding: .utf8) ?? "<non-utf8>"
        ))
      case .varint(let name):
        guard field.wireType == 0, let value = reader.readVarint() else {
          unknownFieldCount += 1
          reader.skip(wireType: field.wireType)
          continue
        }
        fields.append(.init(
          name: name,
          kind: "varint",
          length: nil,
          fingerprint: nil,
          value: String(value)
        ))
      case .bool(let name):
        guard field.wireType == 0, let value = reader.readVarint() else {
          unknownFieldCount += 1
          reader.skip(wireType: field.wireType)
          continue
        }
        fields.append(.init(
          name: name,
          kind: "bool",
          length: nil,
          fingerprint: nil,
          value: value == 0 ? "false" : "true"
        ))
      }
    }

    return (fields, unknownFieldCount)
  }
}

enum AirShieldFraming {
  static let cipherBlockSize = 16
  static let fixedOuterFrameOverhead = 9
  static let minimumOuterFrameLength = 25
  static let maximumPlaintextPayloadLength = 0x1000
  static let invalidOuterFrameSize = 0x1009
  static let validationPrefixLength = 8
  static let cipherPayloadSizeIndicatorOffset = 8
  static let cipherPayloadOffset = 9
  static let validationPrefixScratchModeOffset = 0
  static let validationPrefixScratchCounterOffset = 4
  static let validationPrefixModeLength = 4
  static let validationPrefixFrameCounterLength = 4
  static let validationPrefixAuthenticatedFrameOffset = 8
  static let selectedTransformDescriptor: UInt32 = 0x00072490
  static let selectedTransformCipherName = "AES-256-CTR"
  static let selectedTransformMode = 2
  static let selectedTransformMaterialBits = 0x100
  static let selectedTransformGenericSetter = 0x64cfe0
  static let selectedTransformMode2CompletionHelper = 0xdb2dec
  static let selectedTransformCTRPayloadHelper = 0xdb2f54
  static let selectedTransformAESBlockHelper = 0x5d3e44
  static let nativeHashHalfLength = 32
  static let nativeHashByteLength = 64
  static let javaHashToByteArrayLength = 32
  static let javaSignatureToByteArrayLength = 64
  static let challengeDigestFoldInputLength = 64
  static let privateKeyDeriveNativeThunk = 0xda455c
  static let privateKeyDeriveNativeImplementation = 0xda4e94
  static let privateKeyDeriveSharedHashHelper = 0xdb1f1c
  static let privateKeySignNativeThunk = 0xda4568
  static let privateKeySignNativeImplementation = 0xda4574
  static let privateKeyRecoverPublicKeyNativeThunk = 0xda3f28
  static let privateKeyRecoverPublicKeyHelper = 0xdb2148
  static let nativePublicKeyCopyHelper = 0xdb2240
  static let builderTranscriptChallengeWindowOffset = 0x108
  static let builderTranscriptChallengeWindowLength = 16
  static let builderChallengePayloadOffset = 0x110
  static let builderChallengePayloadLength = 16
  static let builderLocalNativeHashSourceOffset = 0x118
  static let builderLocalNativeHashActiveFlagOffset = 0x210
  static let builderRemotePublicKeyStateOffset = 0x120
  static let builderRemotePublicKeySecondaryStateOffset = 0x1e0
  static let builderRemotePublicKeyActiveFlagOffset = 0x218
  static let builderTranscriptMaterialWindowOffset = 0x218
  static let builderTranscriptMaterialWindowLength = 32
  static let builderSeedPayloadOffset = 0x220
  static let builderSeedPayloadLength = 32
  static let builderInitializationVectorPayloadOffset = 0x240
  static let builderInitializationVectorPayloadLength = 16
  static let selectedTransformSetupIVLoadLowerOffset = 0x238
  static let selectedTransformSetupIVLoadUpperOffset = 0x240
  static let selectedTransformSetupIVWindowOffset = 0x238
  static let selectedTransformSetupIVWindowLength = 16
  static let selectedTransformSetupSeedTailLength = 8
  static let selectedTransformSetupIVHeadLength = 8
  static let cipherContextIVWindowLowerWordOffset = 0x2c
  static let cipherContextIVWindowUpperWordOffset = 0x34
  static let selectedTransformSetterIVWindowInputLength = 16
  static let selectedTransformStateKeystreamBlockOffset = 0x20
  static let selectedTransformStatePartialBlockOffset = 0x30
  static let selectedTransformStateCounterBlockOffset = 0x38
  static let selectedTransformSetterDestinationOffset = 0x38
  static let selectedTransformSetterCopiedLengthOffset = 0x48
  static let selectedTransformCounterIncrementStartOffset = 12
  static let challengeDigestCallerContextLength = 16
  static let buildRxChallengeDirectionFlag = 0
  static let buildTxChallengeDirectionFlag = 1
  static let buildDecryptionDirectionFlag = 0
  static let buildEncryptionDirectionFlag = 1
  static let stateSetupWorkAreaOffset = 0x190
  static let stateSetupWorkAreaLength = 64
  static let stateSetupValidationKeyMaterialOffset = 0x190
  static let stateSetupValidationKeyMaterialLength = 32
  static let stateSetupCipherKeyMaterialOffset = 0x1b0
  static let stateSetupCipherKeyMaterialLength = 32
  static let stateSetupPrimaryFramingConfigOffset = 0x90
  static let stateSetupRelayFramingConfigOffset = 0x110
  static let stateSetupOptionsFrameCounterOffset = 0x00
  static let stateSetupOptionsHKDFOffset = 0x04
  static let stateSetupOptionsDefaultZeroTailOffset = 0x05
  static let stateSetupOptionsDefaultZeroTailLength = 7
  static let stateSetupOptionsValidationModeLowOffset = 0x07
  static let stateSetupOptionsValidationModeHighOffset = 0x09
  static let stateSetupOptionsRelayConfigFlagOffset = 0x0b
  static let stateSetupExpansionScratchOffset = 0x40
  static let stateSetupExpansionScratchInlineTagOffset = 0x60
  static let stateSetupExpansionKeyMaterialOffset = 0x1b0
  static let stateSetupExpansionWritebackOffset = 0x1b0
  static let stateSetupFinalExpansionOutputOffset = 0x1d0
  static let stateSetupFinalExpansionOutputInlineTagOffset = 0x1f0
  static let stateSetupFinalExpansionKeyMaterialOffset = 0x190
  static let stateSetupFinalExpansionWritebackOffset = 0x190
  static let stateSetupDerivationContextBufferOffset = 0x200
  static let stateSetupExplicitExpansionContextAddress = 0x25d60b
  static let stateSetupExplicitExpansionContextLength = 0x88
  static let framingConfigValidationKeyOffset = 0x00
  static let framingConfigValidationKeyLength = 32
  static let framingConfigValidationKeyInlineTagOffset = 0x20
  static let framingConfigCipherContextOffset = 0x28
  static let framingConfigValidationModeLowOffset = 0x78
  static let framingConfigValidationModeHighOffset = 0x7a
  static let framingConfigFrameCounterOffset = 0x7c
  static let runtimeValidationMacContextOffset = 0x00
  static let runtimeValidationKeyInlineOffset = 0x08
  static let runtimeValidationKeyInlineTagOffset = 0x28
  static let runtimeCipherContextOffset = 0x30
  static let runtimeValidationPrefixBufferOffset = 0x80
  static let runtimeValidationModeOffset = 0xa0
  static let runtimeFrameCounterOffset = 0xa4

  struct OuterFrameMetadata: Hashable {
    var validationPrefix: Data
    var cipherPayloadIndicator: UInt8
    var outerFrameRange: Range<Int>
    var cipherPayloadRange: Range<Int>

    var cipherPayloadSize: Int {
      cipherPayloadRange.count
    }
  }

  struct EncryptedFrameCandidate: Hashable {
    var outerFrame: Data
    var paddedPlaintext: Data
    var cipherPayload: Data
    var validationPrefix: Data
    var frameCounter: UInt32
    var runtimeValidationMode: UInt32
  }

  struct DecryptedFrameCandidate: Hashable {
    var plaintext: Data
    var paddedPlaintext: Data
    var cipherPayload: Data
    var validationPrefix: Data
    var paddingLength: Int
    var frameCounter: UInt32
    var runtimeValidationMode: UInt32
    var outerFrameRange: Range<Int>
    var counterSearchOffset: Int
  }

  static func outerFrameSize(forPlaintextLength length: Int) -> Int {
    guard length > 0 else {
      return 0
    }
    guard length <= maximumPlaintextPayloadLength else {
      return invalidOuterFrameSize
    }
    let padding = (-length) & (cipherBlockSize - 1)
    return length + padding + fixedOuterFrameOverhead
  }

  static func nativePaddingLength(forPlaintextLength length: Int) -> Int? {
    guard length > 0, length <= maximumPlaintextPayloadLength else {
      return nil
    }
    return (-length) & (cipherBlockSize - 1)
  }

  static func nativePaddedPlaintextCandidate(_ plaintext: Data) -> Data? {
    guard let paddingLength = nativePaddingLength(forPlaintextLength: plaintext.count) else {
      return nil
    }
    guard paddingLength > 0 else {
      return plaintext
    }

    var padded = plaintext
    padded.append(contentsOf: repeatElement(UInt8(0xc0 + paddingLength), count: paddingLength))
    return padded
  }

  static func nativePaddingLengthCandidate(fromPaddedPlaintext paddedPlaintext: Data) -> Int? {
    guard !paddedPlaintext.isEmpty,
          paddedPlaintext.count.isMultiple(of: cipherBlockSize) else {
      return nil
    }

    let last = paddedPlaintext[paddedPlaintext.count - 1]
    let paddingLength = Int(UInt8(truncatingIfNeeded: last &+ 0x40))
    guard paddingLength > 0, paddingLength < cipherBlockSize, paddingLength <= paddedPlaintext.count else {
      return 0
    }

    guard paddingLength >= 2 else {
      return paddingLength
    }

    let paddingStart = paddedPlaintext.count - paddingLength
    for index in paddingStart..<paddedPlaintext.count where paddedPlaintext[index] != last {
      return 0
    }
    return paddingLength
  }

  static func requiredOuterFrameSize(fromCipherPayloadIndicator indicator: UInt8) -> Int {
    (Int(indicator) * cipherBlockSize) + minimumOuterFrameLength
  }

  static func cipherPayloadSize(fromOuterFrame data: Data, frameOffset: Int = 0, availableLength: Int? = nil) -> Int? {
    guard frameOffset >= 0 else {
      return nil
    }
    let available = availableLength ?? (data.count - frameOffset)
    guard available >= minimumOuterFrameLength else {
      return nil
    }
    let indicatorOffset = frameOffset + cipherPayloadSizeIndicatorOffset
    guard indicatorOffset >= 0, indicatorOffset < data.count else {
      return nil
    }

    let indicator = data[indicatorOffset]
    let requiredOuterFrameSize = requiredOuterFrameSize(fromCipherPayloadIndicator: indicator)
    guard requiredOuterFrameSize <= available else {
      return nil
    }
    guard frameOffset + requiredOuterFrameSize <= data.count else {
      return nil
    }
    return (Int(indicator) * cipherBlockSize) + cipherBlockSize
  }

  static func parseOuterFrameMetadata(
    from data: Data,
    frameOffset: Int = 0,
    availableLength: Int? = nil
  ) -> OuterFrameMetadata? {
    guard let cipherPayloadSize = cipherPayloadSize(
      fromOuterFrame: data,
      frameOffset: frameOffset,
      availableLength: availableLength
    ) else {
      return nil
    }

    let validationPrefixStart = frameOffset
    let validationPrefixEnd = validationPrefixStart + validationPrefixLength
    let indicatorOffset = frameOffset + cipherPayloadSizeIndicatorOffset
    let cipherPayloadStart = frameOffset + cipherPayloadOffset
    let cipherPayloadEnd = cipherPayloadStart + cipherPayloadSize
    guard validationPrefixEnd <= data.count, cipherPayloadEnd <= data.count else {
      return nil
    }

    return OuterFrameMetadata(
      validationPrefix: data[validationPrefixStart..<validationPrefixEnd],
      cipherPayloadIndicator: data[indicatorOffset],
      outerFrameRange: frameOffset..<cipherPayloadEnd,
      cipherPayloadRange: cipherPayloadStart..<cipherPayloadEnd
    )
  }

  static func validationPrefixAuthenticatedFrameRange(from metadata: OuterFrameMetadata) -> Range<Int> {
    let start = metadata.outerFrameRange.lowerBound + validationPrefixAuthenticatedFrameOffset
    return start..<metadata.cipherPayloadRange.upperBound
  }

  static func runtimeValidationMode(configLow16: UInt16, configHighByte: UInt8) -> UInt32 {
    UInt32(configLow16) | (UInt32(configHighByte) << 24)
  }

  static func validationPrefixIncludesModeWord(runtimeValidationMode: UInt32) -> Bool {
    runtimeValidationMode != 0
  }

  static func validationPrefixAuthenticatedInput(
    runtimeValidationMode: UInt32,
    frameCounter: UInt32,
    outerFrame: Data,
    metadata: OuterFrameMetadata
  ) -> Data? {
    let authenticatedFrameRange = validationPrefixAuthenticatedFrameRange(from: metadata)
    guard authenticatedFrameRange.lowerBound >= outerFrame.startIndex,
          authenticatedFrameRange.upperBound <= outerFrame.endIndex else {
      return nil
    }

    var input = Data()
    input.reserveCapacity(
      (validationPrefixIncludesModeWord(runtimeValidationMode: runtimeValidationMode) ? validationPrefixModeLength : 0) +
      validationPrefixFrameCounterLength +
      authenticatedFrameRange.count
    )
    if validationPrefixIncludesModeWord(runtimeValidationMode: runtimeValidationMode) {
      input.appendLEUInt32(runtimeValidationMode)
    }
    input.appendLEUInt32(frameCounter)
    input.append(outerFrame[authenticatedFrameRange])
    return input
  }

  static func validationPrefixCandidate(
    validationKey: Data,
    runtimeValidationMode: UInt32,
    frameCounter: UInt32,
    outerFrame: Data,
    metadata: OuterFrameMetadata
  ) -> Data? {
    guard validationKey.count == framingConfigValidationKeyLength,
          let authenticatedInput = validationPrefixAuthenticatedInput(
            runtimeValidationMode: runtimeValidationMode,
            frameCounter: frameCounter,
            outerFrame: outerFrame,
            metadata: metadata
          ) else {
      return nil
    }

    let digest = HMAC<SHA256>.authenticationCode(
      for: authenticatedInput,
      using: SymmetricKey(data: validationKey)
    )
    return Data(digest.prefix(validationPrefixLength))
  }

  static func selectedTransformInitialCounterBlockCandidate(
    seed: Data,
    initializationVector: Data
  ) -> Data? {
    guard seed.count == builderSeedPayloadLength,
          initializationVector.count >= selectedTransformSetupIVHeadLength else {
      return nil
    }

    var counterBlock = Data()
    counterBlock.reserveCapacity(cipherBlockSize)
    counterBlock.append(seed[(seed.count - selectedTransformSetupSeedTailLength)..<seed.count])
    counterBlock.append(initializationVector[0..<selectedTransformSetupIVHeadLength])
    return counterBlock
  }

  static func selectedTransformCTRApplyCandidate(
    input: Data,
    cipherKey: Data,
    initialCounterBlock: Data
  ) -> Data? {
    guard cipherKey.count == stateSetupCipherKeyMaterialLength,
          initialCounterBlock.count == cipherBlockSize else {
      return nil
    }

    var counterBlock = initialCounterBlock
    var output = Data()
    output.reserveCapacity(input.count)
    var offset = 0

    while offset < input.count {
      guard let keyStreamBlock = aes256EncryptBlockCandidate(
        block: counterBlock,
        key: cipherKey
      ) else {
        return nil
      }

      let blockLength = min(cipherBlockSize, input.count - offset)
      for index in 0..<blockLength {
        output.append(input[offset + index] ^ keyStreamBlock[index])
      }
      offset += blockLength
      guard incrementSelectedTransformCounterBlock(&counterBlock) else {
        return nil
      }
    }

    return output
  }

  static func encryptedFrameCandidate(
    plaintext: Data,
    validationKey: Data,
    cipherKey: Data,
    initialCounterBlock: Data,
    runtimeValidationMode: UInt32,
    frameCounter: UInt32
  ) -> EncryptedFrameCandidate? {
    guard validationKey.count == framingConfigValidationKeyLength,
          let paddedPlaintext = nativePaddedPlaintextCandidate(plaintext),
          let cipherPayload = selectedTransformCTRApplyCandidate(
            input: paddedPlaintext,
            cipherKey: cipherKey,
            initialCounterBlock: initialCounterBlock
          ),
          cipherPayload.count.isMultiple(of: cipherBlockSize),
          cipherPayload.count <= maximumPlaintextPayloadLength else {
      return nil
    }

    let blockCount = cipherPayload.count / cipherBlockSize
    guard blockCount > 0, blockCount <= 256 else {
      return nil
    }

    var outerFrame = Data(repeating: 0, count: fixedOuterFrameOverhead + cipherPayload.count)
    outerFrame[cipherPayloadSizeIndicatorOffset] = UInt8(blockCount - 1)
    outerFrame.replaceSubrange(cipherPayloadOffset..<outerFrame.count, with: cipherPayload)
    guard let metadata = parseOuterFrameMetadata(from: outerFrame),
          let validationPrefix = validationPrefixCandidate(
            validationKey: validationKey,
            runtimeValidationMode: runtimeValidationMode,
            frameCounter: frameCounter,
            outerFrame: outerFrame,
            metadata: metadata
          ) else {
      return nil
    }
    outerFrame.replaceSubrange(0..<validationPrefixLength, with: validationPrefix)
    return EncryptedFrameCandidate(
      outerFrame: outerFrame,
      paddedPlaintext: paddedPlaintext,
      cipherPayload: cipherPayload,
      validationPrefix: validationPrefix,
      frameCounter: frameCounter,
      runtimeValidationMode: runtimeValidationMode
    )
  }

  static func decryptedFrameCandidate(
    outerFrame: Data,
    validationKey: Data,
    cipherKey: Data,
    initialCounterBlock: Data,
    runtimeValidationMode: UInt32,
    frameCounter: UInt32,
    counterSearchOffset: Int = 0
  ) -> DecryptedFrameCandidate? {
    guard let metadata = parseOuterFrameMetadata(from: outerFrame),
          let expectedPrefix = validationPrefixCandidate(
            validationKey: validationKey,
            runtimeValidationMode: runtimeValidationMode,
            frameCounter: frameCounter,
            outerFrame: outerFrame,
            metadata: metadata
          ),
          expectedPrefix == metadata.validationPrefix else {
      return nil
    }

    let cipherPayload = Data(outerFrame[metadata.cipherPayloadRange])
    guard let paddedPlaintext = selectedTransformCTRApplyCandidate(
      input: cipherPayload,
      cipherKey: cipherKey,
      initialCounterBlock: initialCounterBlock
    ),
      let paddingLength = nativePaddingLengthCandidate(fromPaddedPlaintext: paddedPlaintext),
      paddingLength <= paddedPlaintext.count else {
      return nil
    }

    let plaintextEnd = paddedPlaintext.count - paddingLength
    return DecryptedFrameCandidate(
      plaintext: Data(paddedPlaintext.prefix(plaintextEnd)),
      paddedPlaintext: paddedPlaintext,
      cipherPayload: cipherPayload,
      validationPrefix: metadata.validationPrefix,
      paddingLength: paddingLength,
      frameCounter: frameCounter,
      runtimeValidationMode: runtimeValidationMode,
      outerFrameRange: metadata.outerFrameRange,
      counterSearchOffset: counterSearchOffset
    )
  }

  static func decryptedFrameCandidate(
    outerFrame: Data,
    validationKey: Data,
    cipherKey: Data,
    initialCounterBlock: Data,
    runtimeValidationMode: UInt32,
    startingFrameCounter: UInt32,
    counterSearchWindow: Int
  ) -> DecryptedFrameCandidate? {
    guard counterSearchWindow >= 0 else {
      return nil
    }

    for offset in 0...counterSearchWindow {
      let candidateCounter = startingFrameCounter &+ UInt32(offset)
      if let candidate = decryptedFrameCandidate(
        outerFrame: outerFrame,
        validationKey: validationKey,
        cipherKey: cipherKey,
        initialCounterBlock: initialCounterBlock,
        runtimeValidationMode: runtimeValidationMode,
        frameCounter: candidateCounter,
        counterSearchOffset: offset
      ) {
        return candidate
      }
    }
    return nil
  }

  static var builderInitializationVectorPayloadRange: Range<Int> {
    builderInitializationVectorPayloadOffset..<(builderInitializationVectorPayloadOffset + builderInitializationVectorPayloadLength)
  }

  static var builderChallengePayloadRange: Range<Int> {
    builderChallengePayloadOffset..<(builderChallengePayloadOffset + builderChallengePayloadLength)
  }

  static var builderSeedPayloadRange: Range<Int> {
    builderSeedPayloadOffset..<(builderSeedPayloadOffset + builderSeedPayloadLength)
  }

  static var builderTranscriptChallengeWindowRange: Range<Int> {
    builderTranscriptChallengeWindowOffset..<(builderTranscriptChallengeWindowOffset + builderTranscriptChallengeWindowLength)
  }

  static var builderTranscriptMaterialWindowRange: Range<Int> {
    builderTranscriptMaterialWindowOffset..<(builderTranscriptMaterialWindowOffset + builderTranscriptMaterialWindowLength)
  }

  static var builderTranscriptChallengePayloadOverlapRange: Range<Int> {
    max(builderTranscriptChallengeWindowRange.lowerBound, builderChallengePayloadRange.lowerBound)..<min(builderTranscriptChallengeWindowRange.upperBound, builderChallengePayloadRange.upperBound)
  }

  static var builderTranscriptMaterialSeedOverlapRange: Range<Int> {
    max(builderTranscriptMaterialWindowRange.lowerBound, builderSeedPayloadRange.lowerBound)..<min(builderTranscriptMaterialWindowRange.upperBound, builderSeedPayloadRange.upperBound)
  }

  static var selectedTransformSetupIVWindowRange: Range<Int> {
    selectedTransformSetupIVWindowOffset..<(selectedTransformSetupIVWindowOffset + selectedTransformSetupIVWindowLength)
  }

  static var selectedTransformSetupIVWindowPayloadOverlapRange: Range<Int> {
    max(builderInitializationVectorPayloadRange.lowerBound, selectedTransformSetupIVWindowRange.lowerBound)..<min(builderInitializationVectorPayloadRange.upperBound, selectedTransformSetupIVWindowRange.upperBound)
  }

  static var selectedTransformSetupSeedTailRange: Range<Int> {
    max(builderSeedPayloadRange.lowerBound, selectedTransformSetupIVWindowRange.lowerBound)..<min(builderSeedPayloadRange.upperBound, selectedTransformSetupIVWindowRange.upperBound)
  }

  static var selectedTransformSetupIVHeadRange: Range<Int> {
    selectedTransformSetupIVWindowPayloadOverlapRange
  }

  static func incrementSelectedTransformCounterBlock(_ counterBlock: inout Data) -> Bool {
    guard counterBlock.count == cipherBlockSize else {
      return false
    }

    for index in stride(from: cipherBlockSize - 1, through: 0, by: -1) {
      if counterBlock[index] == 0xff {
        counterBlock[index] = 0
      } else {
        counterBlock[index] += 1
        break
      }
    }
    return true
  }

  static func selectedTransformCounterBlockForCurrentCipherBlock(_ counterBlock: inout Data) -> Data? {
    guard counterBlock.count == cipherBlockSize else {
      return nil
    }
    let current = counterBlock
    _ = incrementSelectedTransformCounterBlock(&counterBlock)
    return current
  }

  private static func aes256EncryptBlockCandidate(block: Data, key: Data) -> Data? {
    guard block.count == cipherBlockSize,
          key.count == stateSetupCipherKeyMaterialLength else {
      return nil
    }

    var output = Data(repeating: 0, count: cipherBlockSize + kCCBlockSizeAES128)
    let outputCapacity = output.count
    var bytesMoved = 0
    let status = key.withUnsafeBytes { keyBytes in
      block.withUnsafeBytes { blockBytes in
        output.withUnsafeMutableBytes { outputBytes in
          CCCrypt(
            CCOperation(kCCEncrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionECBMode),
            keyBytes.baseAddress,
            key.count,
            nil,
            blockBytes.baseAddress,
            block.count,
            outputBytes.baseAddress,
            outputCapacity,
            &bytesMoved
          )
        }
      }
    }

    guard status == kCCSuccess, bytesMoved == cipherBlockSize else {
      return nil
    }
    return output.prefix(bytesMoved)
  }
}

struct DataXExtensionWord: Hashable {
  var rawType: UInt8
  var hasContinuation: Bool
  var auxiliary: UInt8
  var value: UInt16
  var rawHex: String

  init(rawType: UInt8, hasContinuation: Bool = false, auxiliary: UInt8 = 0, value: UInt16, rawHex: String = "") {
    self.rawType = rawType
    self.hasContinuation = hasContinuation
    self.auxiliary = auxiliary
    self.value = value
    self.rawHex = rawHex
  }

  var type: UInt8 {
    rawType & 0x7f
  }

  var description: String {
    switch type {
    case 1:
      return "channelAlias=\(value) raw=\(rawHex)"
    case 2:
      let appID = UInt8((value >> 8) & 0xff)
      let messageType = UInt8(value & 0xff)
      return "appID=\(appID) messageType=\(messageType) raw=\(rawHex)"
    case 3:
      return "errorOrControl=\(value) raw=\(rawHex)"
    case 4:
      return "qosOrControl=\(value) raw=\(rawHex)"
    case 5:
      return "qos=\(value) aux=\(auxiliary) raw=\(rawHex)"
    default:
      return "type=\(type) value=\(value) aux=\(auxiliary) raw=\(rawHex)"
    }
  }
}

struct DataXFrameEncoder {
  static let maximumBodyLength = 0x3fff

  static func encode(
    baseID: UInt16,
    payload: Data,
    extensions: [DataXExtensionWord] = [],
    reservedHeaderBit14: Bool = false
  ) throws -> Data {
    let bodyLength = payload.count + (extensions.count * 4)
    guard bodyLength <= maximumBodyLength else {
      throw DataXCodecError.bodyTooLarge(bodyLength)
    }

    var descriptor = UInt16(bodyLength & maximumBodyLength)
    if !extensions.isEmpty {
      descriptor |= 0x8000
    }
    if reservedHeaderBit14 {
      descriptor |= 0x4000
    }

    var bytes = Data()
    bytes.appendBEUInt16(descriptor)
    bytes.appendBEUInt16(baseID)

    for index in extensions.indices {
      let extensionWord = extensions[index]
      let rawType = extensionWord.type | (index < extensions.count - 1 ? 0x80 : 0x00)
      bytes.append(rawType)
      bytes.append(extensionWord.auxiliary)
      bytes.appendBEUInt16(extensionWord.value)
    }
    bytes.append(payload)
    return bytes
  }
}

enum DataXCodecError: Error, CustomStringConvertible {
  case bodyTooLarge(Int)

  var description: String {
    switch self {
    case .bodyTooLarge(let size):
      return "DataX body too large: \(size)"
    }
  }
}

struct DataXFrame: Hashable {
  var totalLength: Int
  var bodyLength: Int
  var baseID: UInt16
  var hasExtensions: Bool
  var reservedHeaderBit14: Bool
  var extensions: [DataXExtensionWord]
  var payload: Data

  var channelAlias: UInt16? {
    extensions.first(where: { $0.type == 1 })?.value
  }

  var typedBufferType: UInt16? {
    extensions.first(where: { $0.type == 2 })?.value
  }

  var payloadFingerprint: String {
    payload.shortSHA256Fingerprint
  }

  var airShieldTypedMessage: AirShieldLinkSetup.TypedMessage? {
    guard channelAlias == AirShieldLinkSetup.dataXServiceID,
          let typedBufferType else {
      return nil
    }
    return AirShieldLinkSetup.TypedMessage(rawValue: typedBufferType)
  }

  var decodedAirShieldMessage: AirShieldLinkSetup.DecodedMessage? {
    guard let airShieldTypedMessage else {
      return nil
    }
    return AirShieldLinkSetup.decode(typedMessage: airShieldTypedMessage, payload: payload)
  }

  var airShieldAuthServiceName: String? {
    guard let channelAlias else {
      return nil
    }
    return AirShieldAuthService.serviceName(channelAlias)
  }

  var airShieldAuthTypedBufferName: String? {
    guard let channelAlias, let typedBufferType else {
      return nil
    }
    return AirShieldAuthService.typedBufferName(serviceID: channelAlias, typedBufferType: typedBufferType)
  }

  var decodedAirShieldAuthPayload: AirShieldAuthPayloadSummary? {
    guard let channelAlias, let typedBufferType else {
      return nil
    }
    return AirShieldAuthPayloadDecoder.decode(
      serviceID: channelAlias,
      typedBufferType: typedBufferType,
      payload: payload
    )
  }

  var decodedMessageType: UInt16? {
    guard let value = typedBufferType else {
      return nil
    }
    return UInt16(UInt8(value & 0xff))
  }

  var decodedAppID: UInt8? {
    guard let value = typedBufferType else {
      return nil
    }
    return UInt8((value >> 8) & 0xff)
  }

  var description: String {
    var parts = [
      "DataX frame",
      "total=\(totalLength)",
      "body=\(bodyLength)",
      "baseID=0x\(Self.hex4(baseID))",
      "baseHighBit=\((baseID & 0x8000) != 0)",
      "extensions=\(extensions.count)",
      "payload=\(payload.count)"
    ]

    if reservedHeaderBit14 {
      parts.append("reservedBit14=true")
    }
    if let decodedAppID {
      parts.append("appID=\(decodedAppID)")
    }
    if let decodedMessageType {
      parts.append("messageType=\(decodedMessageType)")
    }
    if let channelAlias {
      parts.append("channelAlias=\(channelAlias)")
    }
    if let typedBufferType {
      parts.append("typedBufferType=\(typedBufferType)")
    }
    if let airShieldTypedMessage {
      parts.append("airShield=\(airShieldTypedMessage)")
    }
    if let airShieldAuthServiceName {
      parts.append("airShieldAuthService=\(airShieldAuthServiceName)")
    }
    if let airShieldAuthTypedBufferName {
      parts.append("airShieldAuthType=\(airShieldAuthTypedBufferName)")
    }
    if let decodedAirShieldAuthPayload {
      parts.append("airShieldAuthPayload={\(decodedAirShieldAuthPayload.description)}")
    }
    if !extensions.isEmpty {
      parts.append("ext=[\(extensions.map(\.description).joined(separator: "; "))]")
    }
    if !payload.isEmpty {
      parts.append("payloadHex=\(payload.prefix(64).hexString)\(payload.count > 64 ? "..." : "")")
    }
    return parts.joined(separator: " ")
  }

  private static func hex4(_ value: UInt16) -> String {
    String(format: "%04x", value)
  }
}

struct StreamControlResponse: Hashable, CustomStringConvertible {
  var enabledGestures: Bool?
  var streamStates: [UInt64: UInt64] = [:]

  var isGestureStreamActive: Bool {
    streamStates[1] == 2
  }

  var description: String {
    var parts = ["StreamControlResponse"]
    if let enabledGestures {
      parts.append("enabledGestures=\(enabledGestures)")
    }
    if !streamStates.isEmpty {
      let states = streamStates.keys.sorted().map { key in
        "\(Self.streamTypeName(key))=\(Self.streamStateName(streamStates[key] ?? 0))"
      }
      parts.append("streamStates=[\(states.joined(separator: ","))]")
    }
    return parts.joined(separator: " ")
  }

  var logFields: [String: Any] {
    var fields: [String: Any] = [
      "gesture_stream_active": isGestureStreamActive,
      "stream_states": streamStates.keys.sorted().map { key in
        [
          "stream_type": Int(key),
          "stream_type_name": Self.streamTypeName(key),
          "stream_state": Int(streamStates[key] ?? 0),
          "stream_state_name": Self.streamStateName(streamStates[key] ?? 0)
        ]
      }
    ]
    if let enabledGestures {
      fields["enabled_gestures"] = enabledGestures
    }
    return fields
  }

  private static func streamTypeName(_ value: UInt64) -> String {
    switch value {
    case 1: return "gesture"
    case 2: return "emg"
    case 3: return "accel"
    case 4: return "gyro"
    case 5: return "quat"
    case 6: return "inference"
    case 7: return "telem"
    case 8: return "logging"
    case 9: return "deviceState"
    case 10: return "emgImuBatch"
    case 11: return "opaque"
    case 12: return "csa"
    case 13: return "uniband"
    case 14: return "pipeline"
    case 15: return "vcm"
    default: return "stream\(value)"
    }
  }

  private static func streamStateName(_ value: UInt64) -> String {
    switch value {
    case 0: return "released"
    case 1: return "inactive"
    case 2: return "active"
    default: return "state\(value)"
    }
  }
}

struct StreamControlUpdate: Hashable, CustomStringConvertible {
  var notification: String?
  var response: StreamControlResponse?
  var sequenceNumber: UInt64?

  var description: String {
    var parts = ["StreamControlUpdate"]
    if let notification {
      parts.append("notification=\(notification)")
    }
    if let sequenceNumber {
      parts.append("seq=\(sequenceNumber)")
    }
    if let response {
      parts.append(response.description)
    }
    return parts.joined(separator: " ")
  }

  var logFields: [String: Any] {
    var fields: [String: Any] = [:]
    if let notification {
      fields["notification"] = notification
    }
    if let sequenceNumber {
      fields["sequence_number"] = Int(sequenceNumber)
    }
    if let response {
      for (key, value) in response.logFields {
        fields[key] = value
      }
    }
    return fields
  }
}

struct RPCResponse: Hashable, CustomStringConvertible {
  var sequenceNumber: UInt64?
  var code: UInt64?
  var streamControlResponse: StreamControlResponse?
  var hasStreamUpdateAckResponse = false

  var description: String {
    var parts = ["RpcResponse"]
    if let sequenceNumber {
      parts.append("seq=\(sequenceNumber)")
    }
    if let code {
      parts.append("code=\(Self.codeName(code))")
    }
    if let streamControlResponse {
      parts.append(streamControlResponse.description)
    }
    if hasStreamUpdateAckResponse {
      parts.append("streamUpdateAck=true")
    }
    return parts.joined(separator: " ")
  }

  var logFields: [String: Any] {
    var fields: [String: Any] = [
      "stream_update_ack": hasStreamUpdateAckResponse
    ]
    if let sequenceNumber {
      fields["sequence_number"] = Int(sequenceNumber)
    }
    if let code {
      fields["code"] = Int(code)
      fields["code_name"] = Self.codeName(code)
    }
    if let streamControlResponse {
      for (key, value) in streamControlResponse.logFields {
        fields[key] = value
      }
    }
    return fields
  }

  private static func codeName(_ value: UInt64) -> String {
    switch value {
    case 0: return "unknown_error"
    case 1: return "success"
    case 2: return "error"
    case 3: return "timeout"
    case 4: return "error_send"
    case 5: return "error_no_connection"
    default: return "code\(value)"
    }
  }
}

struct RPCStreamUpdate: Hashable, CustomStringConvertible {
  var streamControlUpdate: StreamControlUpdate?

  var description: String {
    if let streamControlUpdate {
      return "RpcStreamUpdate \(streamControlUpdate.description)"
    }
    return "RpcStreamUpdate"
  }

  var logFields: [String: Any] {
    streamControlUpdate?.logFields ?? [:]
  }
}

struct ProtoFieldSummary: Hashable, CustomStringConvertible {
  var number: Int
  var wireType: Int
  var value: UInt64?
  var length: Int?
  var fingerprint: String?

  var wireTypeName: String {
    switch wireType {
    case 0: return "varint"
    case 1: return "fixed64"
    case 2: return "lengthDelimited"
    case 5: return "fixed32"
    default: return "wire\(wireType)"
    }
  }

  var description: String {
    var parts = ["field=\(number)", wireTypeName]
    if let value {
      parts.append("value=\(value)")
    }
    if let length {
      parts.append("len=\(length)")
    }
    if let fingerprint {
      parts.append("fp=\(fingerprint)")
    }
    return parts.joined(separator: " ")
  }
}

struct ProtoMessageSummary: Hashable, CustomStringConvertible {
  var payloadLength: Int
  var fields: [ProtoFieldSummary]
  var truncated: Bool

  var description: String {
    let fieldText = fields.map(\.description).joined(separator: "; ")
    return "ProtoSummary payload=\(payloadLength)B fields=[\(fieldText)] truncated=\(truncated)"
  }

  var logFields: [[String: Any]] {
    fields.map { field in
      var row: [String: Any] = [
        "number": field.number,
        "wire_type": field.wireType,
        "wire_type_name": field.wireTypeName
      ]
      if let value = field.value {
        row["value"] = String(value)
      }
      if let length = field.length {
        row["length"] = length
      }
      if let fingerprint = field.fingerprint {
        row["fingerprint"] = fingerprint
      }
      return row
    }
  }
}

enum ProtoMessageSummarizer {
  static func summarize(_ data: Data, maxFields: Int = 64) -> ProtoMessageSummary {
    var reader = ProtoReader(data)
    var fields: [ProtoFieldSummary] = []
    var truncated = false

    while fields.count < maxFields, let field = reader.nextField() {
      switch field.wireType {
      case 0:
        fields.append(ProtoFieldSummary(
          number: field.number,
          wireType: field.wireType,
          value: reader.readVarint(),
          length: nil,
          fingerprint: nil
        ))
      case 1:
        if let value = reader.readFixed64() {
          fields.append(ProtoFieldSummary(
            number: field.number,
            wireType: field.wireType,
            value: nil,
            length: value.count,
            fingerprint: value.shortSHA256Fingerprint
          ))
        } else {
          truncated = true
        }
      case 2:
        if let value = reader.readLengthDelimited() {
          fields.append(ProtoFieldSummary(
            number: field.number,
            wireType: field.wireType,
            value: nil,
            length: value.count,
            fingerprint: value.shortSHA256Fingerprint
          ))
        } else {
          truncated = true
        }
      case 5:
        if let value = reader.readFixed32() {
          fields.append(ProtoFieldSummary(
            number: field.number,
            wireType: field.wireType,
            value: nil,
            length: value.count,
            fingerprint: value.shortSHA256Fingerprint
          ))
        } else {
          truncated = true
        }
      default:
        truncated = true
        reader.skip(wireType: field.wireType)
      }
    }

    if fields.count == maxFields, reader.hasRemainingBytes {
      truncated = true
    }

    return ProtoMessageSummary(payloadLength: data.count, fields: fields, truncated: truncated)
  }
}

enum StreamControlDecoder {
  static func decodeRPCResponse(_ data: Data) -> RPCResponse? {
    var reader = ProtoReader(data)
    var response = RPCResponse()
    var sawField = false

    while let field = reader.nextField() {
      switch field.number {
      case 1:
        response.sequenceNumber = reader.readVarint()
        sawField = true
      case 2:
        response.code = reader.readVarint()
        sawField = true
      case 5:
        if let payload = reader.readLengthDelimited() {
          response.streamControlResponse = decodeStreamControlResponse(payload)
          sawField = true
        }
      case 27:
        _ = reader.readLengthDelimited()
        response.hasStreamUpdateAckResponse = true
        sawField = true
      default:
        reader.skip(wireType: field.wireType)
      }
    }

    return sawField ? response : nil
  }

  static func decodeRPCStreamUpdate(_ data: Data) -> RPCStreamUpdate? {
    var reader = ProtoReader(data)
    var update = RPCStreamUpdate()
    var sawField = false

    while let field = reader.nextField() {
      switch field.number {
      case 16:
        if let payload = reader.readLengthDelimited() {
          update.streamControlUpdate = decodeStreamControlUpdate(payload)
          sawField = true
        }
      default:
        reader.skip(wireType: field.wireType)
      }
    }

    return sawField ? update : nil
  }

  private static func decodeStreamControlUpdate(_ data: Data) -> StreamControlUpdate {
    var reader = ProtoReader(data)
    var update = StreamControlUpdate()

    while let field = reader.nextField() {
      switch field.number {
      case 1:
        update.notification = "lost"
        update.response = reader.readLengthDelimited().map(decodeStreamControlResponse)
      case 2:
        update.notification = "info"
        update.response = reader.readLengthDelimited().map(decodeStreamControlResponse)
      case 3:
        update.notification = "active"
        update.response = reader.readLengthDelimited().map(decodeStreamControlResponse)
      case 7:
        update.sequenceNumber = reader.readVarint()
      default:
        reader.skip(wireType: field.wireType)
      }
    }

    return update
  }

  private static func decodeStreamControlResponse(_ data: Data) -> StreamControlResponse {
    var reader = ProtoReader(data)
    var response = StreamControlResponse()

    while let field = reader.nextField() {
      switch field.number {
      case 3:
        response.enabledGestures = (reader.readVarint() ?? 0) != 0
      case 35:
        if let payload = reader.readLengthDelimited(),
           let entry = decodeStreamStateEntry(payload) {
          response.streamStates[entry.key] = entry.value
        }
      default:
        reader.skip(wireType: field.wireType)
      }
    }

    return response
  }

  private static func decodeStreamStateEntry(_ data: Data) -> (key: UInt64, value: UInt64)? {
    var reader = ProtoReader(data)
    var key: UInt64?
    var value: UInt64?

    while let field = reader.nextField() {
      switch field.number {
      case 1:
        key = reader.readVarint()
      case 2:
        value = reader.readVarint()
      default:
        reader.skip(wireType: field.wireType)
      }
    }

    guard let key, let value else {
      return nil
    }
    return (key, value)
  }
}

struct ProtoReader {
  private let bytes: [UInt8]
  private var offset = 0

  init(_ data: Data) {
    self.bytes = Array(data)
  }

  mutating func nextField() -> (number: Int, wireType: Int)? {
    guard let key = readVarint() else {
      return nil
    }
    let number = Int(key >> 3)
    let wireType = Int(key & 0x07)
    guard number > 0 else {
      return nil
    }
    return (number, wireType)
  }

  mutating func readVarint() -> UInt64? {
    var result: UInt64 = 0
    var shift: UInt64 = 0
    while offset < bytes.count && shift < 64 {
      let byte = bytes[offset]
      offset += 1
      result |= UInt64(byte & 0x7f) << shift
      if (byte & 0x80) == 0 {
        return result
      }
      shift += 7
    }
    return nil
  }

  mutating func readLengthDelimited() -> Data? {
    guard let length = readVarint() else {
      offset = bytes.count
      return nil
    }
    let end = min(offset + Int(length), bytes.count)
    guard offset <= end else {
      offset = bytes.count
      return nil
    }
    let data = Data(bytes[offset..<end])
    offset = end
    return data
  }

  mutating func readFixed32() -> Data? {
    readFixedByteCount(4)
  }

  mutating func readFixed64() -> Data? {
    readFixedByteCount(8)
  }

  var hasRemainingBytes: Bool {
    offset < bytes.count
  }

  mutating func skip(wireType: Int) {
    switch wireType {
    case 0:
      _ = readVarint()
    case 1:
      offset = min(offset + 8, bytes.count)
    case 2:
      guard let length = readVarint() else {
        offset = bytes.count
        return
      }
      offset = min(offset + Int(length), bytes.count)
    case 5:
      offset = min(offset + 4, bytes.count)
    default:
      offset = bytes.count
    }
  }

  private mutating func readFixedByteCount(_ count: Int) -> Data? {
    guard count >= 0, offset + count <= bytes.count else {
      offset = bytes.count
      return nil
    }
    let data = Data(bytes[offset..<(offset + count)])
    offset += count
    return data
  }
}

struct DataXFrameDecoder {
  private var buffer = Data()

  mutating func reset() {
    buffer.removeAll(keepingCapacity: true)
  }

  mutating func append(_ data: Data) -> [DataXFrame] {
    buffer.append(data)
    var frames: [DataXFrame] = []

    while true {
      guard buffer.count >= 4 else {
        return frames
      }

      let descriptor = Self.readBEUInt16(buffer, at: 0)
      let bodyLength = Int(descriptor & 0x3fff)
      let totalLength = 4 + bodyLength
      guard totalLength <= 0x4003 else {
        buffer.removeAll(keepingCapacity: true)
        return frames
      }
      guard buffer.count >= totalLength else {
        return frames
      }

      let frameBytes = buffer.prefix(totalLength)
      buffer.removeFirst(totalLength)

      let hasExtensions = (descriptor & 0x8000) != 0
      let reservedHeaderBit14 = (descriptor & 0x4000) != 0
      let baseID = Self.readBEUInt16(frameBytes, at: 2)
      var offset = 4
      var extensions: [DataXExtensionWord] = []

      if hasExtensions {
        while offset + 4 <= totalLength {
          let word = frameBytes[offset..<(offset + 4)]
          let bytes = Array(word)
          let rawType = bytes[0]
          let extensionWord = DataXExtensionWord(
            rawType: rawType,
            hasContinuation: (rawType & 0x80) != 0,
            auxiliary: bytes[1],
            value: (UInt16(bytes[2]) << 8) | UInt16(bytes[3]),
            rawHex: Data(bytes).hexString
          )
          extensions.append(extensionWord)
          offset += 4
          if !extensionWord.hasContinuation {
            break
          }
        }
      }

      let payload = offset < totalLength ? Data(frameBytes[offset..<totalLength]) : Data()
      frames.append(DataXFrame(
        totalLength: totalLength,
        bodyLength: bodyLength,
        baseID: baseID,
        hasExtensions: hasExtensions,
        reservedHeaderBit14: reservedHeaderBit14,
        extensions: extensions,
        payload: payload
      ))
    }
  }

  private static func readBEUInt16<D: DataProtocol>(_ data: D, at offset: Int) -> UInt16 {
    let bytes = Array(data)
    return (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
  }
}

struct AirShieldEncryptedFrameDecoder {
  private var buffer = Data()

  mutating func reset() {
    buffer.removeAll(keepingCapacity: true)
  }

  mutating func append(_ data: Data) -> [Data] {
    buffer.append(data)
    var frames: [Data] = []

    while true {
      guard buffer.count >= AirShieldFraming.minimumOuterFrameLength else {
        return frames
      }

      let indicator = Array(buffer)[AirShieldFraming.cipherPayloadSizeIndicatorOffset]
      let requiredLength = AirShieldFraming.requiredOuterFrameSize(fromCipherPayloadIndicator: indicator)
      guard requiredLength <= AirShieldFraming.invalidOuterFrameSize else {
        buffer.removeAll(keepingCapacity: true)
        return frames
      }
      guard buffer.count >= requiredLength else {
        return frames
      }

      frames.append(Data(buffer.prefix(requiredLength)))
      buffer.removeFirst(requiredLength)
    }
  }
}

extension Data {
  var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }

  var printableASCII: String {
    let scalars = compactMap { byte -> UnicodeScalar? in
      guard byte >= 0x20, byte <= 0x7e else {
        return nil
      }
      return UnicodeScalar(byte)
    }
    return String(String.UnicodeScalarView(scalars))
  }

  var shortSHA256Fingerprint: String {
    Data(SHA256.hash(data: self)).prefix(8).hexString
  }

  mutating func appendBEUInt16(_ value: UInt16) {
    append(UInt8((value >> 8) & 0xff))
    append(UInt8(value & 0xff))
  }

  mutating func appendLEUInt32(_ value: UInt32) {
    append(UInt8(value & 0xff))
    append(UInt8((value >> 8) & 0xff))
    append(UInt8((value >> 16) & 0xff))
    append(UInt8((value >> 24) & 0xff))
  }

  mutating func appendProtoVarint(field: Int, _ value: UInt64) {
    appendProtoKey(field: field, wireType: 0)
    appendProtoRawVarint(value)
  }

  mutating func appendProtoLengthDelimited(field: Int, _ value: Data) {
    appendProtoKey(field: field, wireType: 2)
    appendProtoRawVarint(UInt64(value.count))
    append(value)
  }

  private mutating func appendProtoKey(field: Int, wireType: UInt64) {
    appendProtoRawVarint((UInt64(field) << 3) | wireType)
  }

  private mutating func appendProtoRawVarint(_ value: UInt64) {
    var remaining = value
    while remaining >= 0x80 {
      append(UInt8(remaining & 0x7f) | 0x80)
      remaining >>= 7
    }
    append(UInt8(remaining))
  }
}
