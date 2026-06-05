import CryptoKit
import Foundation
import Security

enum AirShieldIdentitySlot: String, CaseIterable, Identifiable {
  case acdcAppPrivateKey = "acdc-app-private-key"
  case linkedAppPrivateKey = "app-private-key"
  case constellationAuthorityKey = "constellation-manifest-authority-key"

  var id: String { rawValue }

  var displayName: String {
    switch self {
    case .acdcAppPrivateKey:
      return "ACDC app private key"
    case .linkedAppPrivateKey:
      return "Linked app private key"
    case .constellationAuthorityKey:
      return "Constellation authority key"
    }
  }
}

struct AirShieldIdentityMaterial: Hashable {
  struct PublicKeyCandidate: Hashable {
    var source: String
    var rawPublicKey: Data
    var publicKeyFingerprint: String
    var acceptedAuthenticationPublicKey: Data {
      AirShieldIdentityMaterial.acceptedAuthenticationPublicKey(from: rawPublicKey)
    }

    var acceptedAuthenticationPublicKeyFingerprint: String {
      AirShieldIdentityMaterial.shortSHA256Fingerprint(acceptedAuthenticationPublicKey)
    }

    var summary: String {
      "\(source):\(publicKeyFingerprint)"
    }
  }

  var slot: AirShieldIdentitySlot
  var rawPrivateKey: Data
  var privateKeyFingerprint: String
  var publicKeyCandidates: [PublicKeyCandidate]
  var parseStatus: String

  var rawPublicKey: Data? {
    publicKeyCandidates.first?.rawPublicKey
  }

  var publicKeyFingerprint: String? {
    publicKeyCandidates.first?.publicKeyFingerprint
  }

  var acceptedAuthenticationPublicKey: Data? {
    publicKeyCandidates.first?.acceptedAuthenticationPublicKey
  }

  var acceptedAuthenticationPublicKeyFingerprint: String? {
    publicKeyCandidates.first?.acceptedAuthenticationPublicKeyFingerprint
  }

  func enableTrustCandidateSummaries(challengeHash: Data) -> [AirShieldIdentityEnableTrustCandidateSummary] {
    Self.enableTrustCandidateSummaries(fromRawPrivateKey: rawPrivateKey, challengeHash: challengeHash)
  }

  var summary: String {
    var parts = [
      slot.rawValue,
      "\(rawPrivateKey.count)B",
      "fp \(privateKeyFingerprint)"
    ]
    if let publicKeyFingerprint {
      parts.append("pub \(publicKeyFingerprint)")
      if publicKeyCandidates.count > 1 {
        parts.append("candidates \(publicKeyCandidates.count)")
      }
    } else {
      parts.append(parseStatus)
    }
    return parts.joined(separator: " / ")
  }

  static func imported(slot: AirShieldIdentitySlot, base64: String) throws -> AirShieldIdentityMaterial {
    let normalized = base64.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalized.isEmpty,
          let raw = Data(base64Encoded: normalized, options: [.ignoreUnknownCharacters]) else {
      throw AirShieldIdentityImportError.invalidBase64
    }
    return fromRawPrivateKey(slot: slot, raw: raw)
  }

  static func fromRawPrivateKey(slot: AirShieldIdentitySlot, raw: Data) -> AirShieldIdentityMaterial {
    let privateFingerprint = shortSHA256Fingerprint(raw)
    let candidates = publicKeyCandidates(fromRawPrivateKey: raw)
    let parseStatus: String
    if candidates.isEmpty {
      parseStatus = "native raw format not parsed; tried full/first32/last32/x963 candidates"
    } else {
      parseStatus = "parsed \(candidates.count) P-256 public-key candidate(s)"
    }

    return AirShieldIdentityMaterial(
      slot: slot,
      rawPrivateKey: raw,
      privateKeyFingerprint: privateFingerprint,
      publicKeyCandidates: candidates,
      parseStatus: parseStatus
    )
  }

  private static func publicKeyCandidates(fromRawPrivateKey raw: Data) -> [PublicKeyCandidate] {
    var candidates: [PublicKeyCandidate] = []
    var seen = Set<String>()

    func appendCandidate(source: String, scalar: Data) {
      guard scalar.count == 32,
            let signingKey = try? P256.Signing.PrivateKey(rawRepresentation: scalar) else {
        return
      }
      let x963 = signingKey.publicKey.x963Representation
      guard x963.count == 65, x963.first == 0x04 else {
        return
      }
      let publicKey = Data(x963.dropFirst())
      let fingerprint = shortSHA256Fingerprint(publicKey)
      guard seen.insert(fingerprint).inserted else {
        return
      }
      candidates.append(PublicKeyCandidate(
        source: source,
        rawPublicKey: publicKey,
        publicKeyFingerprint: fingerprint
      ))
    }

    appendCandidate(source: "raw_32", scalar: raw)
    if raw.count >= 32 {
      appendCandidate(source: "first_32", scalar: raw.prefix(32))
      appendCandidate(source: "last_32", scalar: raw.suffix(32))
    }
    if raw.count == 65, raw.first == 0x04 {
      appendCandidate(source: "x963_public_point_present_first_32", scalar: raw.dropFirst().prefix(32))
      appendCandidate(source: "x963_public_point_present_last_32", scalar: raw.suffix(32))
    }
    return candidates
  }

  private static func scalarCandidates(fromRawPrivateKey raw: Data) -> [(source: String, scalar: Data)] {
    var candidates: [(source: String, scalar: Data)] = []
    var seen = Set<String>()

    func appendCandidate(source: String, scalar: Data) {
      guard scalar.count == 32,
            (try? P256.Signing.PrivateKey(rawRepresentation: scalar)) != nil else {
        return
      }
      let fingerprint = shortSHA256Fingerprint(scalar)
      guard seen.insert(fingerprint).inserted else {
        return
      }
      candidates.append((source, scalar))
    }

    appendCandidate(source: "raw_32", scalar: raw)
    if raw.count >= 32 {
      appendCandidate(source: "first_32", scalar: raw.prefix(32))
      appendCandidate(source: "last_32", scalar: raw.suffix(32))
    }
    if raw.count == 65, raw.first == 0x04 {
      appendCandidate(source: "x963_public_point_present_first_32", scalar: raw.dropFirst().prefix(32))
      appendCandidate(source: "x963_public_point_present_last_32", scalar: raw.suffix(32))
    }
    return candidates
  }

  private static func enableTrustCandidateSummaries(
    fromRawPrivateKey raw: Data,
    challengeHash: Data
  ) -> [AirShieldIdentityEnableTrustCandidateSummary] {
    guard !challengeHash.isEmpty else {
      return []
    }

    let scalarCandidates = scalarCandidates(fromRawPrivateKey: raw)
    guard !scalarCandidates.isEmpty else {
      return []
    }

    var identifierCandidates: [(source: String, identifier: Data)] = [
      ("sha256_imported_private_blob", Data(SHA256.hash(data: raw)))
    ]

    for candidate in scalarCandidates {
      let identifier = Data(SHA256.hash(data: candidate.scalar))
      if !identifierCandidates.contains(where: { $0.identifier == identifier }) {
        identifierCandidates.append(("sha256_\(candidate.source)_scalar", identifier))
      }
    }

    var summaries: [AirShieldIdentityEnableTrustCandidateSummary] = []
    for scalarCandidate in scalarCandidates {
      guard let signingKey = try? P256.Signing.PrivateKey(rawRepresentation: scalarCandidate.scalar),
            let signature = try? signingKey.signature(for: challengeHash) else {
        continue
      }

      let signatureCandidates: [(format: String, value: Data)] = [
        ("cryptokit_p256_ecdsa_der_sha256_over_challenge_hash", signature.derRepresentation),
        ("native_format_raw64_but_swift_sha256_over_challenge_hash", signature.rawRepresentation)
      ] + {
        guard let rawDigestSignature = nativeRawDigestSignature(
          scalar: scalarCandidate.scalar,
          challengeHash: challengeHash
        ) else {
          return []
        }
        return [("security_p256_ecdsa_raw64_digest_challenge_hash_native_format", rawDigestSignature)]
      }()
      for identifierCandidate in identifierCandidates {
        for signatureCandidate in signatureCandidates {
          let payload = AirShieldAuthService.encodeIdentityEnableTrust(
            identifier: identifierCandidate.identifier,
            signature: signatureCandidate.value
          )
          let payloadFingerprint = shortSHA256Fingerprint(payload)
          for localChannelID in AirShieldAuthService.candidateLocalChannelIDs {
            let baseID = NativeDataXLocalChannel.baseID(localChannelID: localChannelID)
            let frame = try? AirShieldAuthService.encodeDataXFrame(
              serviceID: AirShieldAuthService.identityServiceID,
              typedBufferType: AirShieldAuthService.identityEnableTrustType,
              payload: payload,
              baseID: baseID
            )
            let frameFingerprint = frame.map(shortSHA256Fingerprint) ?? "nil"
            let candidateID = enableTrustCandidateID(
              scalarSource: scalarCandidate.source,
              identifierSource: identifierCandidate.source,
              identifierFingerprint: shortSHA256Fingerprint(identifierCandidate.identifier),
              challengeHashFingerprint: shortSHA256Fingerprint(challengeHash),
              signatureFormat: signatureCandidate.format,
              signatureFingerprint: shortSHA256Fingerprint(signatureCandidate.value),
              payloadFingerprint: payloadFingerprint,
              localChannelID: localChannelID,
              baseID: baseID,
              frameFingerprint: frameFingerprint
            )
            summaries.append(AirShieldIdentityEnableTrustCandidateSummary(
              candidateID: candidateID,
              scalarSource: scalarCandidate.source,
              identifierSource: identifierCandidate.source,
              identifierLength: identifierCandidate.identifier.count,
              identifierFingerprint: shortSHA256Fingerprint(identifierCandidate.identifier),
              challengeHashLength: challengeHash.count,
              challengeHashFingerprint: shortSHA256Fingerprint(challengeHash),
              signatureFormat: signatureCandidate.format,
              signatureLength: signatureCandidate.value.count,
              signatureFingerprint: shortSHA256Fingerprint(signatureCandidate.value),
              provisioningCapabilities: 2,
              payloadLength: payload.count,
              payloadFingerprint: payloadFingerprint,
              localChannelID: localChannelID,
              baseID: baseID,
              frameLength: frame?.count ?? 0,
              frameFingerprint: frameFingerprint,
              frame: frame,
              transmitState: "not_transmitted_requires_identity_path_match"
            ))
          }
        }
      }
    }
    return summaries
  }

  private static func enableTrustCandidateID(
    scalarSource: String,
    identifierSource: String,
    identifierFingerprint: String,
    challengeHashFingerprint: String,
    signatureFormat: String,
    signatureFingerprint: String,
    payloadFingerprint: String,
    localChannelID: UInt16,
    baseID: UInt16,
    frameFingerprint: String
  ) -> String {
    let input = [
      scalarSource,
      identifierSource,
      identifierFingerprint,
      challengeHashFingerprint,
      signatureFormat,
      signatureFingerprint,
      payloadFingerprint,
      String(localChannelID),
      String(baseID),
      frameFingerprint
    ].joined(separator: "|")
    return Data(SHA256.hash(data: Data(input.utf8))).prefix(12).hexString
  }

  private static func nativeRawDigestSignature(scalar: Data, challengeHash: Data) -> Data? {
    guard scalar.count == 32,
          challengeHash.count == AirShieldFraming.javaHashToByteArrayLength,
          let signingKey = try? P256.Signing.PrivateKey(rawRepresentation: scalar) else {
      return nil
    }

    let keyData = signingKey.publicKey.x963Representation + scalar
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecAttrKeySizeInBits as String: 256
    ]
    var keyError: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &keyError),
          SecKeyIsAlgorithmSupported(secKey, .sign, .ecdsaSignatureDigestX962SHA256) else {
      return nil
    }
    var signError: Unmanaged<CFError>?
    guard let derSignature = SecKeyCreateSignature(
      secKey,
      .ecdsaSignatureDigestX962SHA256,
      challengeHash as CFData,
      &signError
    ) as Data? else {
      return nil
    }
    return rawP256SignatureFromDERSignature(derSignature)
  }

  private static func rawP256SignatureFromDERSignature(_ der: Data) -> Data? {
    let bytes = Array(der)
    var index = 0

    func readByte() -> UInt8? {
      guard index < bytes.count else { return nil }
      defer { index += 1 }
      return bytes[index]
    }

    func readLength() -> Int? {
      guard let first = readByte() else { return nil }
      if first < 0x80 {
        return Int(first)
      }
      let count = Int(first & 0x7f)
      guard count > 0 && count <= 2 else { return nil }
      var length = 0
      for _ in 0..<count {
        guard let byte = readByte() else { return nil }
        length = (length << 8) | Int(byte)
      }
      return length
    }

    func readInteger32() -> Data? {
      guard readByte() == 0x02,
            let length = readLength(),
            length > 0,
            index + length <= bytes.count else {
        return nil
      }
      var value = Array(bytes[index..<index + length])
      index += length
      while value.count > 32 && value.first == 0 {
        value.removeFirst()
      }
      guard value.count <= 32 else {
        return nil
      }
      return Data(repeating: 0, count: 32 - value.count) + Data(value)
    }

    guard readByte() == 0x30,
          let sequenceLength = readLength(),
          index + sequenceLength == bytes.count,
          let r = readInteger32(),
          let s = readInteger32(),
          index == bytes.count else {
      return nil
    }
    return r + s
  }

  static func acceptedAuthenticationPublicKey(from publicKey: Data) -> Data {
    if publicKey.count == 64 {
      return publicKey
    }
    if publicKey.count > 64 {
      return Data(publicKey.prefix(64))
    }
    var padded = publicKey
    padded.append(Data(repeating: 0, count: 64 - publicKey.count))
    return padded
  }

  static func shortSHA256Fingerprint(_ data: Data) -> String {
    Data(SHA256.hash(data: data)).prefix(8).hexString
  }
}

struct AirShieldIdentityEnableTrustCandidateSummary: Hashable {
  var candidateID: String
  var scalarSource: String
  var identifierSource: String
  var identifierLength: Int
  var identifierFingerprint: String
  var challengeHashLength: Int
  var challengeHashFingerprint: String
  var signatureFormat: String
  var signatureLength: Int
  var signatureFingerprint: String
  var provisioningCapabilities: Int
  var payloadLength: Int
  var payloadFingerprint: String
  var localChannelID: UInt16
  var baseID: UInt16
  var frameLength: Int
  var frameFingerprint: String
  var frame: Data?
  var transmitState: String

  var logFields: [String: Any] {
    [
      "candidate_id": candidateID,
      "scalar_source": scalarSource,
      "identifier_source": identifierSource,
      "identifier_length": identifierLength,
      "identifier_fingerprint": identifierFingerprint,
      "challenge_hash_length": challengeHashLength,
      "challenge_hash_fingerprint": challengeHashFingerprint,
      "signature_format": signatureFormat,
      "signature_length": signatureLength,
      "signature_fingerprint": signatureFingerprint,
      "provisioning_capabilities": provisioningCapabilities,
      "payload_length": payloadLength,
      "payload_fingerprint": payloadFingerprint,
      "local_channel_id": Int(localChannelID),
      "base_id": Int(baseID),
      "frame_length": frameLength,
      "frame_fingerprint": frameFingerprint,
      "transmit_state": transmitState
    ]
  }
}

struct AirShieldEnableTrustGate: Hashable {
  static let schema = "codex_band_bridge_enable_trust_gate_v1"
  static let eligibleStatus = "PAYLOAD_AND_TX_CHALLENGE_MATCH"

  var candidateID: String
  var frameFingerprint: String?

  static func parse(data: Data) throws -> AirShieldEnableTrustGate {
    guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw AirShieldEnableTrustGateError.invalidJSON
    }
    return try parse(json: json)
  }

  static func parse(json: [String: Any]) throws -> AirShieldEnableTrustGate {
    guard json["schema"] as? String == schema else {
      throw AirShieldEnableTrustGateError.invalidSchema
    }
    guard json["eligible_for_manual_mac_auth_transmit"] as? Bool == true,
          json["status"] as? String == eligibleStatus else {
      throw AirShieldEnableTrustGateError.notEligible
    }
    guard let candidateID = json["candidate_id"] as? String,
          !candidateID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
      throw AirShieldEnableTrustGateError.missingCandidateID
    }

    return AirShieldEnableTrustGate(
      candidateID: candidateID,
      frameFingerprint: json["frame_fingerprint"] as? String
    )
  }

  static func fingerprintMatches(_ left: String, _ right: String) -> Bool {
    let lhs = left.lowercased()
    let rhs = right.lowercased()
    return lhs.hasPrefix(rhs) || rhs.hasPrefix(lhs)
  }
}

enum AirShieldEnableTrustGateError: Error, CustomStringConvertible {
  case invalidJSON
  case invalidSchema
  case notEligible
  case missingCandidateID

  var description: String {
    switch self {
    case .invalidJSON:
      return "auth gate is not a JSON object"
    case .invalidSchema:
      return "auth gate schema is not codex_band_bridge_enable_trust_gate_v1"
    case .notEligible:
      return "auth gate is not eligible for manual Mac auth transmit"
    case .missingCandidateID:
      return "auth gate is missing candidate_id"
    }
  }
}

enum AirShieldIdentityImportError: Error, CustomStringConvertible {
  case invalidBase64
  case keychainSaveFailed(OSStatus)
  case keychainLoadFailed(OSStatus)
  case keychainDeleteFailed(OSStatus)

  var description: String {
    switch self {
    case .invalidBase64:
      return "identity value is not valid Base64"
    case .keychainSaveFailed(let status):
      return "keychain save failed status=\(status)"
    case .keychainLoadFailed(let status):
      return "keychain load failed status=\(status)"
    case .keychainDeleteFailed(let status):
      return "keychain delete failed status=\(status)"
    }
  }
}

enum AirShieldIdentityKeychain {
  private static let service = "com.example.codexbandbridge.airshield.identity"
  private static let account = "accepted-app-private-key"
  private static let slotDefaultsKey = "airshield.identity.slot"

  static func load() throws -> AirShieldIdentityMaterial? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound {
      return nil
    }
    guard status == errSecSuccess, let data = item as? Data else {
      throw AirShieldIdentityImportError.keychainLoadFailed(status)
    }
    let slotName = UserDefaults.standard.string(forKey: slotDefaultsKey)
    let slot = slotName.flatMap(AirShieldIdentitySlot.init(rawValue:)) ?? .acdcAppPrivateKey
    return AirShieldIdentityMaterial.fromRawPrivateKey(slot: slot, raw: data)
  }

  static func save(_ material: AirShieldIdentityMaterial) throws {
    let deleteQuery: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account
    ]
    SecItemDelete(deleteQuery as CFDictionary)

    let addQuery: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecValueData as String: material.rawPrivateKey,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    ]
    let status = SecItemAdd(addQuery as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw AirShieldIdentityImportError.keychainSaveFailed(status)
    }
    UserDefaults.standard.set(material.slot.rawValue, forKey: slotDefaultsKey)
  }

  static func delete() throws {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account
    ]
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw AirShieldIdentityImportError.keychainDeleteFailed(status)
    }
    UserDefaults.standard.removeObject(forKey: slotDefaultsKey)
  }
}

struct AirShieldRequestProbe {
  var publicKey: Data
  var challenge: Data
}

struct AirShieldEnableInputs: Hashable {
  var peerPublicKeyLength: Int
  var peerPublicKeyFingerprint: String
  var seedLength: Int
  var seedFingerprint: String?
  var initializationVectorLength: Int
  var initializationVectorFingerprint: String?
  var base: UInt64?
  var usesHKDF: Bool
  var sharedSecretLength: Int
  var sharedSecretFingerprint: String
  var normalMaterialCandidate: AirShieldNormalFramingMaterial?
  var normalMaterialCandidates: [AirShieldNormalFramingMaterial]
  var localChallengeLength: Int
  var localChallengeFingerprint: String
}

struct AirShieldNormalFramingMaterial: Hashable {
  var sharedMaterialSource: String
  var sharedMaterialPrefixHex: String
  var sharedMaterialFingerprint: String
  var sharedMaterialSHA256Fingerprint: String
  var transcriptChallengeWindowFingerprint: String
  var transcriptMaterialWindowFingerprint: String
  var transcriptDigestInputFingerprint: String
  var keyDerivationMode: String
  var expansionContextSource: String?
  var expansionContextLength: Int?
  var expansionContextFingerprint: String?
  var transcriptDigestFingerprint: String
  var workAreaFingerprint: String
  var workAreaValidationHalfFingerprint: String
  var workAreaCipherHalfFingerprint: String
  var validationKeyFingerprint: String
  var cipherKeyFingerprint: String
  var validationEqualsCipher: Bool
  var validationKeySource: String
  var cipherKeySource: String
  var transcriptPrefixSource: String
  var initialCounterBlockSource: String?
  var initialCounterBlockFingerprint: String?
  var endLinkSetupFrameCandidate: AirShieldFrameCandidateSummary?
  var gestureEnableFrameCandidate: AirShieldFrameCandidateSummary?
}

struct AirShieldFrameCandidateSummary: Hashable {
  var plaintextSource: String
  var plaintextLength: Int
  var paddedPlaintextLength: Int
  var cipherPayloadLength: Int
  var outerFrameLength: Int
  var runtimeValidationMode: UInt32
  var frameCounter: UInt32
  var validationPrefixHex: String
  var plaintextFingerprint: String
  var cipherPayloadFingerprint: String
  var outerFrameFingerprint: String
}

struct AirShieldDecryptedFrameCandidate: Hashable {
  var sharedMaterialSource: String
  var plaintext: Data
  var plaintextLength: Int
  var paddedPlaintextLength: Int
  var cipherPayloadLength: Int
  var outerFrameLength: Int
  var paddingLength: Int
  var runtimeValidationMode: UInt32
  var frameCounter: UInt32
  var counterSearchOffset: Int
  var validationPrefixHex: String
  var plaintextFingerprint: String
  var cipherPayloadFingerprint: String
}

struct AirShieldPreparedTransmitFrame: Hashable {
  var sharedMaterialSource: String
  var outerFrame: Data
  var summary: AirShieldFrameCandidateSummary
}

struct AirShieldSyntheticFramingProbeCandidate: Hashable {
  var sharedMaterialSource: String
  var localPublicKeyFingerprint: String
  var remotePublicKeyFingerprint: String
  var sharedSecretFingerprint: String
  var material: AirShieldNormalFramingMaterial
  var frame: AirShieldPreparedTransmitFrame
}

enum AirShieldSessionError: Error, CustomStringConvertible {
  case invalidLocalPublicKey
  case missingProbe
  case missingPeerPublicKey
  case invalidPeerPublicKeyLength(Int)
  case invalidPeerPublicKey

  var description: String {
    switch self {
    case .invalidLocalPublicKey:
      return "invalid local P-256 public key"
    case .missingProbe:
      return "missing local RequestEncryption probe state"
    case .missingPeerPublicKey:
      return "EnableEncryption is missing peer public key"
    case .invalidPeerPublicKeyLength(let length):
      return "EnableEncryption peer public key has invalid length \(length)"
    case .invalidPeerPublicKey:
      return "EnableEncryption peer public key is not a valid P-256 point"
    }
  }
}

enum AirShieldFramingExpansionError: Error, CustomStringConvertible {
  case invalidKeyMaterialLength(Int)

  var description: String {
    switch self {
    case .invalidKeyMaterialLength(let length):
      return "AirShield framing expansion requires 32 bytes of key material, got \(length)"
    }
  }
}

enum AirShieldFramingExpansion {
  static let nativeDefaultLabel = Data("AirShield".utf8)
  static let nativeDefaultLabelLength = 9
  static let nativeCounterByte: UInt8 = 0x01
  static let keyMaterialLength = 32
  static let outputLength = 32
  static let nativeExplicitContextLength = 0x88

  static var nativeExplicitContext: Data {
    var data = Data(repeating: 0, count: nativeExplicitContextLength)
    data.replaceSubrange(0..<nativeDefaultLabel.count, with: nativeDefaultLabel)
    data[0x80] = 0x20
    data[0x85] = 0x01
    return data
  }

  static func expandDefaultLabelCounter1(keyMaterial: Data) throws -> Data {
    try expandContextCounter1(keyMaterial: keyMaterial, context: nativeDefaultLabel)
  }

  static func expandExplicitContextCounter1(keyMaterial: Data) throws -> Data {
    try expandContextCounter1(keyMaterial: keyMaterial, context: nativeExplicitContext)
  }

  static func expandContextCounter1(keyMaterial: Data, context: Data) throws -> Data {
    guard keyMaterial.count == keyMaterialLength else {
      throw AirShieldFramingExpansionError.invalidKeyMaterialLength(keyMaterial.count)
    }

    var input = Data()
    input.reserveCapacity(context.count + 1)
    input.append(context)
    input.append(nativeCounterByte)

    let authenticationCode = HMAC<SHA256>.authenticationCode(
      for: input,
      using: SymmetricKey(data: keyMaterial)
    )
    return Data(authenticationCode)
  }
}

final class AirShieldSession {
  static let receiveCounterSearchWindow = 8

  private struct NormalFramingDerivation {
    var material: AirShieldNormalFramingMaterial
    var receiveCandidate: ReceiveCandidate?
    var endLinkSetupTransmitFrame: AirShieldPreparedTransmitFrame?
    var gestureEnableTransmitFrame: AirShieldPreparedTransmitFrame?
  }

  private struct NormalFramingKeyMaterialVariant {
    var sharedMaterialSource: String
    var keyDerivationMode: String
    var expansionContextSource: String?
    var expansionContextLength: Int?
    var expansionContextFingerprint: String?
    var keyMaterial: Data
  }

  private struct ReceiveCandidate {
    var sharedMaterialSource: String
    var validationKey: Data
    var cipherKey: Data
    var initialCounterBlock: Data
    var runtimeValidationMode: UInt32
    var frameCounter: UInt32
  }

  private var privateKey: P256.KeyAgreement.PrivateKey?
  private(set) var localPublicKey: Data?
  private(set) var localChallenge: Data?
  private(set) var localEndLinkSetupUUID: UUID?
  private(set) var lastEnableInputs: AirShieldEnableInputs?
  private var receiveCandidates: [ReceiveCandidate] = []
  private var endLinkSetupTransmitFrames: [String: AirShieldPreparedTransmitFrame] = [:]
  private var gestureEnableTransmitFrames: [String: AirShieldPreparedTransmitFrame] = [:]
  private(set) var validatedReceiveSources: Set<String> = []

  var hasReceiveCandidates: Bool {
    !receiveCandidates.isEmpty
  }

  var hasValidatedReceiveCandidate: Bool {
    !validatedReceiveSources.isEmpty
  }

  func reset() {
    privateKey = nil
    localPublicKey = nil
    localChallenge = nil
    localEndLinkSetupUUID = nil
    lastEnableInputs = nil
    receiveCandidates = []
    endLinkSetupTransmitFrames = [:]
    gestureEnableTransmitFrames = [:]
    validatedReceiveSources = []
  }

  func makeRequestEncryptionProbe(
    challenge: Data,
    privateKey suppliedPrivateKey: P256.KeyAgreement.PrivateKey? = nil
  ) throws -> AirShieldRequestProbe {
    let privateKey = suppliedPrivateKey ?? P256.KeyAgreement.PrivateKey()
    let publicKey = try Self.rawP256PublicKey(from: privateKey.publicKey)
    self.privateKey = privateKey
    self.localPublicKey = publicKey
    self.localChallenge = challenge
    self.localEndLinkSetupUUID = nil
    self.lastEnableInputs = nil
    self.receiveCandidates = []
    self.endLinkSetupTransmitFrames = [:]
    self.gestureEnableTransmitFrames = [:]
    self.validatedReceiveSources = []
    return AirShieldRequestProbe(publicKey: publicKey, challenge: challenge)
  }

  func processEnableEncryption(_ message: AirShieldLinkSetup.EnableEncryptionMessage) throws -> AirShieldEnableInputs {
    guard let privateKey, let localChallenge else {
      throw AirShieldSessionError.missingProbe
    }
    guard let peerPublicKey = message.publicKey else {
      throw AirShieldSessionError.missingPeerPublicKey
    }
    guard peerPublicKey.count == 64 else {
      throw AirShieldSessionError.invalidPeerPublicKeyLength(peerPublicKey.count)
    }

    let peerKey: P256.KeyAgreement.PublicKey
    do {
      peerKey = try P256.KeyAgreement.PublicKey(x963Representation: Self.x963P256PublicKey(fromRawPoint: peerPublicKey))
    } catch {
      throw AirShieldSessionError.invalidPeerPublicKey
    }

    let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerKey)
    let sharedSecretData = sharedSecret.withUnsafeBytes { rawBuffer in
      Data(rawBuffer)
    }
    let digest = SHA256.hash(data: sharedSecretData)
    let fingerprint = Data(digest).prefix(8).hexString
    let endLinkSetupUUID = UUID()
    let derivations = try Self.deriveNormalFramingMaterialCandidates(
      sharedSecretData: sharedSecretData,
      localChallenge: localChallenge,
      seed: message.seed,
      initializationVector: message.initializationVector,
      base: message.base,
      usesHKDF: message.usesHKDF,
      endLinkSetupUUID: endLinkSetupUUID
    )
    let normalMaterialCandidates = derivations.map(\.material)
    let inputs = AirShieldEnableInputs(
      peerPublicKeyLength: peerPublicKey.count,
      peerPublicKeyFingerprint: Self.shortSHA256Fingerprint(peerPublicKey),
      seedLength: message.seed?.count ?? 0,
      seedFingerprint: message.seed.map(Self.shortSHA256Fingerprint),
      initializationVectorLength: message.initializationVector?.count ?? 0,
      initializationVectorFingerprint: message.initializationVector.map(Self.shortSHA256Fingerprint),
      base: message.base,
      usesHKDF: message.usesHKDF,
      sharedSecretLength: sharedSecretData.count,
      sharedSecretFingerprint: fingerprint,
      normalMaterialCandidate: normalMaterialCandidates.first,
      normalMaterialCandidates: normalMaterialCandidates,
      localChallengeLength: localChallenge.count,
      localChallengeFingerprint: Self.shortSHA256Fingerprint(localChallenge)
    )
    localEndLinkSetupUUID = endLinkSetupUUID
    lastEnableInputs = inputs
    receiveCandidates = derivations.compactMap(\.receiveCandidate)
    endLinkSetupTransmitFrames = Dictionary(
      uniqueKeysWithValues: derivations.compactMap { derivation in
        derivation.endLinkSetupTransmitFrame.map { (derivation.material.sharedMaterialSource, $0) }
      }
    )
    gestureEnableTransmitFrames = Dictionary(
      uniqueKeysWithValues: derivations.compactMap { derivation in
        derivation.gestureEnableTransmitFrame.map { (derivation.material.sharedMaterialSource, $0) }
      }
    )
    validatedReceiveSources = []
    return inputs
  }

  func decryptReceivedEncryptedFrameCandidates(_ outerFrame: Data) -> [AirShieldDecryptedFrameCandidate] {
    guard !receiveCandidates.isEmpty else {
      return []
    }

    var matches: [AirShieldDecryptedFrameCandidate] = []
    for index in receiveCandidates.indices {
      let candidate = receiveCandidates[index]
      guard let decrypted = AirShieldFraming.decryptedFrameCandidate(
        outerFrame: outerFrame,
        validationKey: candidate.validationKey,
        cipherKey: candidate.cipherKey,
        initialCounterBlock: candidate.initialCounterBlock,
        runtimeValidationMode: candidate.runtimeValidationMode,
        startingFrameCounter: candidate.frameCounter,
        counterSearchWindow: Self.receiveCounterSearchWindow
      ) else {
        continue
      }

      receiveCandidates[index].frameCounter = decrypted.frameCounter &+ 1
      validatedReceiveSources.insert(candidate.sharedMaterialSource)
      matches.append(AirShieldDecryptedFrameCandidate(
        sharedMaterialSource: candidate.sharedMaterialSource,
        plaintext: decrypted.plaintext,
        plaintextLength: decrypted.plaintext.count,
        paddedPlaintextLength: decrypted.paddedPlaintext.count,
        cipherPayloadLength: decrypted.cipherPayload.count,
        outerFrameLength: decrypted.outerFrameRange.count,
        paddingLength: decrypted.paddingLength,
        runtimeValidationMode: decrypted.runtimeValidationMode,
        frameCounter: decrypted.frameCounter,
        counterSearchOffset: decrypted.counterSearchOffset,
        validationPrefixHex: decrypted.validationPrefix.hexString,
        plaintextFingerprint: Self.shortSHA256Fingerprint(decrypted.plaintext),
        cipherPayloadFingerprint: Self.shortSHA256Fingerprint(decrypted.cipherPayload)
      ))
    }
    return matches
  }

  func preparedGestureEnableFrameForValidatedReceiveCandidate() -> AirShieldPreparedTransmitFrame? {
    preparedTransmitFrameForValidatedReceiveCandidate(in: gestureEnableTransmitFrames)
  }

  func preparedEndLinkSetupFrameForValidatedReceiveCandidate() -> AirShieldPreparedTransmitFrame? {
    preparedTransmitFrameForValidatedReceiveCandidate(in: endLinkSetupTransmitFrames)
  }

  private func preparedTransmitFrameForValidatedReceiveCandidate(
    in frames: [String: AirShieldPreparedTransmitFrame]
  ) -> AirShieldPreparedTransmitFrame? {
    let preferredSources = [
      "raw_p256_shared_secret__db17b4_default_label",
      "raw_p256_shared_secret__db17b4_shared_material_context",
      "raw_p256_shared_secret__db17b4_explicit_context_0x88",
      "sha256_raw_p256_shared_secret__db17b4_default_label",
      "sha256_raw_p256_shared_secret__db17b4_shared_material_context",
      "sha256_raw_p256_shared_secret__db17b4_explicit_context_0x88",
      "reversed_raw_p256_shared_secret__db17b4_default_label",
      "reversed_raw_p256_shared_secret__db17b4_shared_material_context",
      "reversed_raw_p256_shared_secret__db17b4_explicit_context_0x88",
      "raw_p256_shared_secret__direct_transcript_digest",
      "sha256_raw_p256_shared_secret__direct_transcript_digest",
      "reversed_raw_p256_shared_secret__direct_transcript_digest",
      "raw_p256_shared_secret",
      "sha256_raw_p256_shared_secret",
      "reversed_raw_p256_shared_secret"
    ]
    for source in preferredSources where validatedReceiveSources.contains(source) {
      if let frame = frames[source] {
        return frame
      }
    }
    for source in validatedReceiveSources {
      if let frame = frames[source] {
        return frame
      }
    }
    return nil
  }

  private static func rawP256PublicKey(from publicKey: P256.KeyAgreement.PublicKey) throws -> Data {
    let x963 = publicKey.x963Representation
    guard x963.count == 65, x963.first == 0x04 else {
      throw AirShieldSessionError.invalidLocalPublicKey
    }
    return Data(x963.dropFirst())
  }

  private static func x963P256PublicKey(fromRawPoint rawPoint: Data) -> Data {
    var x963 = Data([0x04])
    x963.append(rawPoint)
    return x963
  }

  static func syntheticFramingProbeCandidates(
    localPrivateKeyRaw: Data,
    remotePrivateKeyRaw: Data?,
    remotePublicKeyRaw: Data?,
    localChallenge: Data,
    seed: Data,
    initializationVector: Data,
    plaintext: Data,
    base: UInt32,
    usesHKDF: Bool
  ) throws -> [AirShieldSyntheticFramingProbeCandidate] {
    let localPrivateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: localPrivateKeyRaw)
    let remotePublicKey: P256.KeyAgreement.PublicKey
    let remotePublicKeyBytes: Data
    if let remotePrivateKeyRaw {
      let remotePrivateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: remotePrivateKeyRaw)
      remotePublicKeyBytes = try rawP256PublicKey(from: remotePrivateKey.publicKey)
      remotePublicKey = try P256.KeyAgreement.PublicKey(
        x963Representation: x963P256PublicKey(fromRawPoint: remotePublicKeyBytes)
      )
    } else if let remotePublicKeyRaw {
      guard remotePublicKeyRaw.count == 64 else {
        throw AirShieldSessionError.invalidPeerPublicKeyLength(remotePublicKeyRaw.count)
      }
      remotePublicKeyBytes = remotePublicKeyRaw
      remotePublicKey = try P256.KeyAgreement.PublicKey(
        x963Representation: x963P256PublicKey(fromRawPoint: remotePublicKeyRaw)
      )
    } else {
      throw AirShieldSessionError.missingPeerPublicKey
    }

    let localPublicKeyBytes = try rawP256PublicKey(from: localPrivateKey.publicKey)
    let sharedSecret = try localPrivateKey.sharedSecretFromKeyAgreement(with: remotePublicKey)
    let sharedSecretData = sharedSecret.withUnsafeBytes { rawBuffer in
      Data(rawBuffer)
    }
    let sharedMaterialVariants: [(source: String, material: Data)] = [
      ("raw_p256_shared_secret", sharedSecretData),
      ("sha256_raw_p256_shared_secret", Data(SHA256.hash(data: sharedSecretData))),
      ("reversed_raw_p256_shared_secret", Data(sharedSecretData.reversed()))
    ]

    var candidates: [AirShieldSyntheticFramingProbeCandidate] = []
    for (sharedMaterialSource, sharedHashMaterial) in sharedMaterialVariants {
      let derivations = try deriveNormalFramingMaterialCandidate(
        sharedMaterialSource: sharedMaterialSource,
        sharedHashMaterial: sharedHashMaterial,
        localChallenge: localChallenge,
        seed: seed,
        initializationVector: initializationVector,
        base: UInt64(base),
        usesHKDF: usesHKDF,
        endLinkSetupUUID: UUID(uuidString: "00000000-0000-0000-0000-000000000000")!
      )

      for derivation in derivations {
        guard let receiveCandidate = derivation.receiveCandidate,
              let frame = makeSyntheticFramingProbeTransmitFrame(
                sharedMaterialSource: derivation.material.sharedMaterialSource,
                plaintext: plaintext,
                validationKey: receiveCandidate.validationKey,
                cipherKey: receiveCandidate.cipherKey,
                initialCounterBlock: receiveCandidate.initialCounterBlock,
                frameCounter: receiveCandidate.frameCounter
              ) else {
          continue
        }
        candidates.append(AirShieldSyntheticFramingProbeCandidate(
          sharedMaterialSource: derivation.material.sharedMaterialSource,
          localPublicKeyFingerprint: shortSHA256Fingerprint(localPublicKeyBytes),
          remotePublicKeyFingerprint: shortSHA256Fingerprint(remotePublicKeyBytes),
          sharedSecretFingerprint: shortSHA256Fingerprint(sharedSecretData),
          material: derivation.material,
          frame: frame
        ))
      }
    }
    return candidates
  }

  private static func deriveNormalFramingMaterialCandidates(
    sharedSecretData: Data,
    localChallenge: Data,
    seed: Data?,
    initializationVector: Data?,
    base: UInt64?,
    usesHKDF: Bool,
    endLinkSetupUUID: UUID
  ) throws -> [NormalFramingDerivation] {
    guard sharedSecretData.count == 32,
          localChallenge.count == 16,
          let seed,
          seed.count == 32 else {
      return []
    }

    let rawSharedSecret = sharedSecretData
    let hashedSharedSecret = Data(SHA256.hash(data: sharedSecretData))
    let reversedSharedSecret = Data(sharedSecretData.reversed())

    return try [
      ("raw_p256_shared_secret", rawSharedSecret),
      ("sha256_raw_p256_shared_secret", hashedSharedSecret),
      ("reversed_raw_p256_shared_secret", reversedSharedSecret)
    ].flatMap { source, material in
      try deriveNormalFramingMaterialCandidate(
        sharedMaterialSource: source,
        sharedHashMaterial: material,
        localChallenge: localChallenge,
        seed: seed,
        initializationVector: initializationVector,
        base: base,
        usesHKDF: usesHKDF,
        endLinkSetupUUID: endLinkSetupUUID
      )
    }
  }

  private static func deriveNormalFramingMaterialCandidate(
    sharedMaterialSource: String,
    sharedHashMaterial: Data,
    localChallenge: Data,
    seed: Data,
    initializationVector: Data?,
    base: UInt64?,
    usesHKDF: Bool,
    endLinkSetupUUID: UUID
  ) throws -> [NormalFramingDerivation] {
    precondition(sharedHashMaterial.count == 32)
    precondition(localChallenge.count == 16)
    precondition(seed.count == 32)

    var transcriptChallengeWindow = Data(repeating: 0, count: 8)
    transcriptChallengeWindow.append(localChallenge.prefix(8))

    // Native CipherBuilder construction zeros this window; setRemotePublicKeyNative
    // sets byte 0x218 to one, then setSeedNative fills bytes 0x220...0x237.
    var transcriptMaterialWindow = Data([0x01])
    transcriptMaterialWindow.append(Data(repeating: 0, count: 7))
    transcriptMaterialWindow.append(seed.prefix(24))

    var digestInput = Data()
    digestInput.reserveCapacity(32 + 16 + 32)
    digestInput.append(sharedHashMaterial)
    digestInput.append(transcriptChallengeWindow)
    digestInput.append(transcriptMaterialWindow)

    let transcriptDigest = Data(SHA256.hash(data: digestInput))
    let initialCounterBlock = initializationVector.flatMap {
      AirShieldFraming.selectedTransformInitialCounterBlockCandidate(
        seed: seed,
        initializationVector: $0
      )
    }
    let frameCounter = base.flatMap(UInt32.init(exactly:))

    let keyMaterialVariants: [NormalFramingKeyMaterialVariant]
    if usesHKDF {
      keyMaterialVariants = [
        NormalFramingKeyMaterialVariant(
          sharedMaterialSource: "\(sharedMaterialSource)__db17b4_default_label",
          keyDerivationMode: "db17b4_expansion_candidate",
          expansionContextSource: "default_airshield_label",
          expansionContextLength: AirShieldFramingExpansion.nativeDefaultLabel.count,
          expansionContextFingerprint: shortSHA256Fingerprint(AirShieldFramingExpansion.nativeDefaultLabel),
          keyMaterial: try AirShieldFramingExpansion.expandDefaultLabelCounter1(keyMaterial: transcriptDigest)
        ),
        NormalFramingKeyMaterialVariant(
          sharedMaterialSource: "\(sharedMaterialSource)__db17b4_shared_material_context",
          keyDerivationMode: "db17b4_expansion_candidate",
          expansionContextSource: "shared_material_candidate",
          expansionContextLength: sharedHashMaterial.count,
          expansionContextFingerprint: shortSHA256Fingerprint(sharedHashMaterial),
          keyMaterial: try AirShieldFramingExpansion.expandContextCounter1(
            keyMaterial: transcriptDigest,
            context: sharedHashMaterial
          )
        ),
        NormalFramingKeyMaterialVariant(
          sharedMaterialSource: "\(sharedMaterialSource)__db17b4_explicit_context_0x88",
          keyDerivationMode: "db17b4_expansion_candidate",
          expansionContextSource: "explicit_airshield_context_0x88",
          expansionContextLength: AirShieldFramingExpansion.nativeExplicitContext.count,
          expansionContextFingerprint: shortSHA256Fingerprint(AirShieldFramingExpansion.nativeExplicitContext),
          keyMaterial: try AirShieldFramingExpansion.expandExplicitContextCounter1(keyMaterial: transcriptDigest)
        )
      ]
    } else {
      keyMaterialVariants = [
        NormalFramingKeyMaterialVariant(
          sharedMaterialSource: "\(sharedMaterialSource)__direct_transcript_digest",
          keyDerivationMode: "direct_transcript_digest",
          expansionContextSource: nil,
          expansionContextLength: nil,
          expansionContextFingerprint: nil,
          keyMaterial: transcriptDigest
        )
      ]
    }

    return try keyMaterialVariants.map { variant in
      let endLinkSetupTransmitFrame = try makeEndLinkSetupTransmitFrame(
        sharedMaterialSource: variant.sharedMaterialSource,
        state: .main,
        uuid: endLinkSetupUUID,
        validationKey: variant.keyMaterial,
        cipherKey: variant.keyMaterial,
        initialCounterBlock: initialCounterBlock,
        frameCounter: frameCounter
      )
      let gestureEnableTransmitFrame = try makeGestureEnableTransmitFrame(
        sharedMaterialSource: variant.sharedMaterialSource,
        validationKey: variant.keyMaterial,
        cipherKey: variant.keyMaterial,
        initialCounterBlock: initialCounterBlock,
        frameCounter: frameCounter.map { $0 &+ 1 }
      )

      var workArea = Data()
      workArea.reserveCapacity(
        AirShieldFraming.stateSetupValidationKeyMaterialLength
          + AirShieldFraming.stateSetupCipherKeyMaterialLength
      )
      workArea.append(variant.keyMaterial)
      workArea.append(variant.keyMaterial)

      let material = AirShieldNormalFramingMaterial(
        sharedMaterialSource: variant.sharedMaterialSource,
        sharedMaterialPrefixHex: sharedHashMaterial.prefix(8).hexString,
        sharedMaterialFingerprint: sharedHashMaterial.prefix(8).hexString,
        sharedMaterialSHA256Fingerprint: shortSHA256Fingerprint(sharedHashMaterial),
        transcriptChallengeWindowFingerprint: shortSHA256Fingerprint(transcriptChallengeWindow),
        transcriptMaterialWindowFingerprint: shortSHA256Fingerprint(transcriptMaterialWindow),
        transcriptDigestInputFingerprint: shortSHA256Fingerprint(digestInput),
        keyDerivationMode: variant.keyDerivationMode,
        expansionContextSource: variant.expansionContextSource,
        expansionContextLength: variant.expansionContextLength,
        expansionContextFingerprint: variant.expansionContextFingerprint,
        transcriptDigestFingerprint: transcriptDigest.prefix(8).hexString,
        workAreaFingerprint: shortSHA256Fingerprint(workArea),
        workAreaValidationHalfFingerprint: variant.keyMaterial.prefix(8).hexString,
        workAreaCipherHalfFingerprint: variant.keyMaterial.prefix(8).hexString,
        validationKeyFingerprint: variant.keyMaterial.prefix(8).hexString,
        cipherKeyFingerprint: variant.keyMaterial.prefix(8).hexString,
        validationEqualsCipher: true,
        validationKeySource: "state_setup_work_area_0x190",
        cipherKeySource: "state_setup_work_area_0x1b0",
        transcriptPrefixSource: "native_builder_zero_init_and_remote_key_flag",
        initialCounterBlockSource: initialCounterBlock == nil ? nil : "seed_tail_8_plus_iv_head_8",
        initialCounterBlockFingerprint: initialCounterBlock.map(shortSHA256Fingerprint),
        endLinkSetupFrameCandidate: endLinkSetupTransmitFrame?.summary,
        gestureEnableFrameCandidate: gestureEnableTransmitFrame?.summary
      )
      let receiveCandidate: ReceiveCandidate?
      if let initialCounterBlock, let frameCounter {
        receiveCandidate = ReceiveCandidate(
          sharedMaterialSource: variant.sharedMaterialSource,
          validationKey: variant.keyMaterial,
          cipherKey: variant.keyMaterial,
          initialCounterBlock: initialCounterBlock,
          runtimeValidationMode: 0,
          frameCounter: frameCounter
        )
      } else {
        receiveCandidate = nil
      }
      return NormalFramingDerivation(
        material: material,
        receiveCandidate: receiveCandidate,
        endLinkSetupTransmitFrame: endLinkSetupTransmitFrame,
        gestureEnableTransmitFrame: gestureEnableTransmitFrame
      )
    }
  }

  private static func makeSyntheticFramingProbeTransmitFrame(
    sharedMaterialSource: String,
    plaintext: Data,
    validationKey: Data,
    cipherKey: Data,
    initialCounterBlock: Data,
    frameCounter: UInt32
  ) -> AirShieldPreparedTransmitFrame? {
    guard let candidate = AirShieldFraming.encryptedFrameCandidate(
      plaintext: plaintext,
      validationKey: validationKey,
      cipherKey: cipherKey,
      initialCounterBlock: initialCounterBlock,
      runtimeValidationMode: 0,
      frameCounter: frameCounter
    ) else {
      return nil
    }

    let summary = AirShieldFrameCandidateSummary(
      plaintextSource: "synthetic_airshield_framing_probe_plaintext",
      plaintextLength: plaintext.count,
      paddedPlaintextLength: candidate.paddedPlaintext.count,
      cipherPayloadLength: candidate.cipherPayload.count,
      outerFrameLength: candidate.outerFrame.count,
      runtimeValidationMode: candidate.runtimeValidationMode,
      frameCounter: candidate.frameCounter,
      validationPrefixHex: candidate.validationPrefix.hexString,
      plaintextFingerprint: shortSHA256Fingerprint(plaintext),
      cipherPayloadFingerprint: shortSHA256Fingerprint(candidate.cipherPayload),
      outerFrameFingerprint: shortSHA256Fingerprint(candidate.outerFrame)
    )
    return AirShieldPreparedTransmitFrame(
      sharedMaterialSource: sharedMaterialSource,
      outerFrame: candidate.outerFrame,
      summary: summary
    )
  }

  private static func makeEndLinkSetupTransmitFrame(
    sharedMaterialSource: String,
    state: AirShieldLinkSetup.LinkState,
    uuid: UUID,
    validationKey: Data,
    cipherKey: Data,
    initialCounterBlock: Data?,
    frameCounter: UInt32?
  ) throws -> AirShieldPreparedTransmitFrame? {
    guard let initialCounterBlock, let frameCounter else {
      return nil
    }

    let plaintext = try AirShieldLinkSetup.encodeDataXFrame(
      typedMessage: .endLinkSetup,
      payload: AirShieldLinkSetup.encodeEndLinkSetup(state: state, uuid: Self.uuidBytes(uuid))
    )
    guard let candidate = AirShieldFraming.encryptedFrameCandidate(
      plaintext: plaintext,
      validationKey: validationKey,
      cipherKey: cipherKey,
      initialCounterBlock: initialCounterBlock,
      runtimeValidationMode: 0,
      frameCounter: frameCounter
    ) else {
      return nil
    }

    let summary = AirShieldFrameCandidateSummary(
      plaintextSource: "airshield_end_link_setup_state_\(state.rawValue)",
      plaintextLength: plaintext.count,
      paddedPlaintextLength: candidate.paddedPlaintext.count,
      cipherPayloadLength: candidate.cipherPayload.count,
      outerFrameLength: candidate.outerFrame.count,
      runtimeValidationMode: candidate.runtimeValidationMode,
      frameCounter: candidate.frameCounter,
      validationPrefixHex: candidate.validationPrefix.hexString,
      plaintextFingerprint: shortSHA256Fingerprint(plaintext),
      cipherPayloadFingerprint: shortSHA256Fingerprint(candidate.cipherPayload),
      outerFrameFingerprint: shortSHA256Fingerprint(candidate.outerFrame)
    )
    return AirShieldPreparedTransmitFrame(
      sharedMaterialSource: sharedMaterialSource,
      outerFrame: candidate.outerFrame,
      summary: summary
    )
  }

  private static func makeGestureEnableTransmitFrame(
    sharedMaterialSource: String,
    validationKey: Data,
    cipherKey: Data,
    initialCounterBlock: Data?,
    frameCounter: UInt32?
  ) throws -> AirShieldPreparedTransmitFrame? {
    guard let initialCounterBlock, let frameCounter else {
      return nil
    }

    let plaintext = try DataXFrameEncoder.encode(
      baseID: NativeDataXLocalChannel.baseID(),
      payload: WISProtocol.streamControlEnableGesturesRpc(seq: 1),
      extensions: WISProtocol.dataXExtensions(appID: .rpc, messageType: .request)
    )
    guard let candidate = AirShieldFraming.encryptedFrameCandidate(
      plaintext: plaintext,
      validationKey: validationKey,
      cipherKey: cipherKey,
      initialCounterBlock: initialCounterBlock,
      runtimeValidationMode: 0,
      frameCounter: frameCounter
    ) else {
      return nil
    }

    let summary = AirShieldFrameCandidateSummary(
      plaintextSource: "wis_gesture_enable_rpc_seq_1_datax_frame",
      plaintextLength: plaintext.count,
      paddedPlaintextLength: candidate.paddedPlaintext.count,
      cipherPayloadLength: candidate.cipherPayload.count,
      outerFrameLength: candidate.outerFrame.count,
      runtimeValidationMode: candidate.runtimeValidationMode,
      frameCounter: candidate.frameCounter,
      validationPrefixHex: candidate.validationPrefix.hexString,
      plaintextFingerprint: shortSHA256Fingerprint(plaintext),
      cipherPayloadFingerprint: shortSHA256Fingerprint(candidate.cipherPayload),
      outerFrameFingerprint: shortSHA256Fingerprint(candidate.outerFrame)
    )
    return AirShieldPreparedTransmitFrame(
      sharedMaterialSource: sharedMaterialSource,
      outerFrame: candidate.outerFrame,
      summary: summary
    )
  }

  private static func shortSHA256Fingerprint(_ data: Data) -> String {
    Data(SHA256.hash(data: data)).prefix(8).hexString
  }

  private static func uuidBytes(_ uuid: UUID) -> Data {
    withUnsafeBytes(of: uuid.uuid) { Data($0) }
  }
}
