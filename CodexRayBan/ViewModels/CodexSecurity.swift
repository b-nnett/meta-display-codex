import CryptoKit
import Foundation
import Security

enum CodexRuntimeEnvironment {
  static var isRunningTests: Bool {
    let environment = ProcessInfo.processInfo.environment
    return environment["XCTestConfigurationFilePath"] != nil
      || environment["XCTestBundlePath"] != nil
      || NSClassFromString("XCTest.XCTestCase") != nil
  }

  static var isDeveloperDiagnosticsEnabled: Bool {
    #if DEBUG
    true
    #else
    false
    #endif
  }

  static var isVerboseLoggingEnabled: Bool {
    #if DEBUG
    !isRunningTests
    #else
    false
    #endif
  }
}

struct CodexAuthSession: Codable, Equatable {
  var normalAccessToken: String?
  var normalRefreshToken: String?
  var normalExpiresAt: Date?
  var accountID: String?
  var accountUserID: String?
  var remoteClientID: String?
  var remoteAccountUserID: String?
  var remoteControlToken: String?
  var remoteControlExpiresAt: Date?
  var deviceKeyID: String?
  var updatedAt: Date = .now

  var isSignedIn: Bool {
    normalAccessToken?.isEmpty == false
  }

  var isRemoteEnrolled: Bool {
    remoteClientID?.isEmpty == false && remoteControlToken?.isEmpty == false
  }

  var remoteTokenIsFresh: Bool {
    guard let remoteControlExpiresAt else { return false }
    return remoteControlExpiresAt > Date().addingTimeInterval(300)
  }
}

enum CodexDeviceKeyProtectionClass {
  static let nonextractable = "os_protected_nonextractable"
  static let extractableKeychain = "os_protected_keychain_extractable"
}

enum CodexDeviceSigningKey {
  case secureEnclave(SecureEnclave.P256.Signing.PrivateKey)
  case software(P256.Signing.PrivateKey)

  var publicKeyX963Representation: Data {
    switch self {
    case .secureEnclave(let key):
      return key.publicKey.x963Representation
    case .software(let key):
      return key.publicKey.x963Representation
    }
  }

  var storedRepresentation: Data {
    switch self {
    case .secureEnclave(let key):
      return key.dataRepresentation
    case .software(let key):
      return key.rawRepresentation
    }
  }

  var protectionClass: String {
    switch self {
    case .secureEnclave:
      return CodexDeviceKeyProtectionClass.nonextractable
    case .software:
      return CodexDeviceKeyProtectionClass.extractableKeychain
    }
  }

  func signature(for data: Data) throws -> P256.Signing.ECDSASignature {
    switch self {
    case .secureEnclave(let key):
      return try key.signature(for: data)
    case .software(let key):
      return try key.signature(for: data)
    }
  }
}

struct CodexDeviceKey {
  let keyID: String
  let signingKey: CodexDeviceSigningKey
  let publicKeySPKIDERBase64: String
  var protectionClassOverride: String? = nil

  var protectionClass: String {
    protectionClassOverride ?? signingKey.protectionClass
  }

  func signature(for data: Data) throws -> P256.Signing.ECDSASignature {
    try signingKey.signature(for: data)
  }
}

enum CodexSecurityError: LocalizedError {
  case keychainReadFailed(OSStatus)
  case keychainWriteFailed(OSStatus)
  case keychainDeleteFailed(OSStatus)
  case missingDeviceKey
  case invalidDeviceKey

  var errorDescription: String? {
    switch self {
    case .keychainReadFailed(let status):
      "Keychain read failed: \(status)"
    case .keychainWriteFailed(let status):
      "Keychain write failed: \(status)"
    case .keychainDeleteFailed(let status):
      "Keychain delete failed: \(status)"
    case .missingDeviceKey:
      "Missing device key."
    case .invalidDeviceKey:
      "Invalid device key."
    }
  }
}

struct CodexSecureStore {
  private let keychain = CodexKeychainStore(service: "com.example.codexrayban.codex")
  private let transcriptionAPIKeyAccount = "transcription-api-key"

  func loadSession() -> CodexAuthSession {
    guard let data = try? keychain.data(for: "auth-session") else {
      return CodexAuthSession()
    }
    return (try? JSONDecoder().decode(CodexAuthSession.self, from: data)) ?? CodexAuthSession()
  }

  func saveSession(_ session: CodexAuthSession) throws {
    let data = try JSONEncoder().encode(session)
    try keychain.set(data, for: "auth-session")
  }

  func clearSession() throws {
    try keychain.delete("auth-session")
  }

  func loadTranscriptionAPIKey() throws -> String? {
    guard let data = try keychain.data(for: transcriptionAPIKeyAccount) else {
      return nil
    }
    return String(data: data, encoding: .utf8)
  }

  func saveTranscriptionAPIKey(_ key: String) throws {
    try keychain.set(Data(key.utf8), for: transcriptionAPIKeyAccount)
  }

  func clearTranscriptionAPIKey() throws {
    try keychain.delete(transcriptionAPIKeyAccount)
  }
}

struct CodexDeviceKeyStore {
  private let keychain = CodexKeychainStore(service: "com.example.codexrayban.codex")

  func loadOrCreate(existingKeyID: String?) throws -> CodexDeviceKey {
    if
      let existingKeyID,
      let keyData = try? keychain.data(for: "device-key-\(existingKeyID)")
    {
      let storedKey = try Self.storedSigningKey(from: keyData)
      return CodexDeviceKey(
        keyID: existingKeyID,
        signingKey: storedKey.signingKey,
        publicKeySPKIDERBase64: publicKeySPKIDERBase64(fromX963Representation: storedKey.signingKey.publicKeyX963Representation),
        protectionClassOverride: storedKey.protectionClassOverride
      )
    }

    let keyID = "ios-\(UUID().uuidString)"
    let signingKey = Self.createSigningKey()
    try keychain.set(Self.storedRepresentation(for: signingKey), for: "device-key-\(keyID)")
    return CodexDeviceKey(
      keyID: keyID,
      signingKey: signingKey,
      publicKeySPKIDERBase64: publicKeySPKIDERBase64(fromX963Representation: signingKey.publicKeyX963Representation)
    )
  }

  func delete(keyID: String?) throws {
    guard let keyID else { return }
    try keychain.delete("device-key-\(keyID)")
  }

  private static func createSigningKey() -> CodexDeviceSigningKey {
    if SecureEnclave.isAvailable, let key = try? SecureEnclave.P256.Signing.PrivateKey() {
      return .secureEnclave(key)
    }
    return .software(P256.Signing.PrivateKey())
  }

  struct StoredSigningKey {
    let signingKey: CodexDeviceSigningKey
    let protectionClassOverride: String?
  }

  static func storedSigningKey(from data: Data) throws -> StoredSigningKey {
    if let envelope = try? JSONDecoder().decode(StoredDeviceKeyEnvelope.self, from: data) {
      let keyData = try envelope.keyData()
      let signingKey: CodexDeviceSigningKey
      switch envelope.kind {
      case StoredDeviceKeyEnvelope.Kind.secureEnclave.rawValue:
        if SecureEnclave.isAvailable, let secureKey = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData) {
          signingKey = .secureEnclave(secureKey)
        } else {
          throw CodexSecurityError.invalidDeviceKey
        }
      case StoredDeviceKeyEnvelope.Kind.software.rawValue:
        signingKey = .software(try P256.Signing.PrivateKey(rawRepresentation: keyData))
      default:
        throw CodexSecurityError.invalidDeviceKey
      }
      return StoredSigningKey(signingKey: signingKey, protectionClassOverride: envelope.protectionClass)
    }

    if data.count == 32 {
      return StoredSigningKey(
        signingKey: .software(try P256.Signing.PrivateKey(rawRepresentation: data)),
        protectionClassOverride: CodexDeviceKeyProtectionClass.nonextractable
      )
    }

    if SecureEnclave.isAvailable, let secureKey = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data) {
      return StoredSigningKey(signingKey: .secureEnclave(secureKey), protectionClassOverride: nil)
    }
    return StoredSigningKey(signingKey: .software(try P256.Signing.PrivateKey(rawRepresentation: data)), protectionClassOverride: nil)
  }

  static func storedRepresentation(for signingKey: CodexDeviceSigningKey) throws -> Data {
    let kind: StoredDeviceKeyEnvelope.Kind
    switch signingKey {
    case .secureEnclave:
      kind = .secureEnclave
    case .software:
      kind = .software
    }
    return try JSONEncoder().encode(StoredDeviceKeyEnvelope(
      version: 1,
      kind: kind.rawValue,
      protectionClass: signingKey.protectionClass,
      keyMaterialBase64: signingKey.storedRepresentation.base64EncodedString()
    ))
  }

  private func publicKeySPKIDERBase64(fromX963Representation publicKeyX963Representation: Data) -> String {
    var data = Data([
      0x30, 0x59,
      0x30, 0x13,
      0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
      0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
      0x03, 0x42, 0x00,
    ])
    data.append(publicKeyX963Representation)
    return data.base64EncodedString()
  }
}

private struct StoredDeviceKeyEnvelope: Codable {
  enum Kind: String {
    case secureEnclave = "secure_enclave"
    case software
  }

  let version: Int
  let kind: String
  let protectionClass: String
  let keyMaterialBase64: String

  func keyData() throws -> Data {
    guard version == 1, let data = Data(base64Encoded: keyMaterialBase64) else {
      throw CodexSecurityError.invalidDeviceKey
    }
    return data
  }
}

struct CodexKeychainStore {
  let service: String

  func data(for account: String) throws -> Data? {
    var query = baseQuery(account: account)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound {
      return nil
    }
    guard status == errSecSuccess else {
      throw CodexSecurityError.keychainReadFailed(status)
    }
    return item as? Data
  }

  func set(_ data: Data, for account: String) throws {
    let query = baseQuery(account: account)
    let update = [
      kSecValueData as String: data,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ] as [String: Any]

    let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
    if updateStatus == errSecSuccess {
      return
    }
    if updateStatus != errSecItemNotFound {
      throw CodexSecurityError.keychainWriteFailed(updateStatus)
    }

    var addQuery = query
    addQuery[kSecValueData as String] = data
    addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
    guard addStatus == errSecSuccess else {
      throw CodexSecurityError.keychainWriteFailed(addStatus)
    }
  }

  func delete(_ account: String) throws {
    let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
    if status == errSecItemNotFound || status == errSecSuccess {
      return
    }
    throw CodexSecurityError.keychainDeleteFailed(status)
  }

  private func baseQuery(account: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
    ]
  }
}

enum CodexJWT {
  static func accountID(from token: String) -> String? {
    guard let payload = payload(from: token) else { return nil }
    if let value = payload["https://api.openai.com/auth.chatgpt_account_id"] as? String {
      return value
    }
    if let auth = payload["https://api.openai.com/auth"] as? [String: Any] {
      return auth["chatgpt_account_id"] as? String ?? auth["account_id"] as? String
    }
    return payload["chatgpt_account_id"] as? String ?? payload["account_id"] as? String
  }

  static func accountUserID(from token: String) -> String? {
    guard let payload = payload(from: token) else { return nil }
    if let value = payload["https://api.openai.com/auth.chatgpt_account_user_id"] as? String {
      return value
    }
    if let auth = payload["https://api.openai.com/auth"] as? [String: Any] {
      return auth["chatgpt_account_user_id"] as? String ?? auth["account_user_id"] as? String
    }
    return payload["chatgpt_account_user_id"] as? String ?? payload["account_user_id"] as? String
  }

  static func expiresAt(from token: String) -> Date? {
    guard let payload = payload(from: token) else { return nil }
    if let exp = payload["exp"] as? TimeInterval {
      return Date(timeIntervalSince1970: exp)
    }
    if let exp = payload["exp"] as? Int {
      return Date(timeIntervalSince1970: TimeInterval(exp))
    }
    return nil
  }

  private static func payload(from token: String) -> [String: Any]? {
    let parts = token.split(separator: ".")
    guard parts.count >= 2 else { return nil }
    guard let data = Data(base64URLEncoded: String(parts[1])) else { return nil }
    return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
  }
}

extension Data {
  init?(base64URLEncoded string: String) {
    var base64 = string.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let padding = (4 - base64.count % 4) % 4
    base64 += String(repeating: "=", count: padding)
    self.init(base64Encoded: base64)
  }

  func base64URLEncodedString() -> String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}
