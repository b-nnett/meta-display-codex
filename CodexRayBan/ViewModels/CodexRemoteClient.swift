import CryptoKit
import Foundation

enum CodexRemoteConstants {
  static let baseURL = URL(string: "https://chatgpt.com/backend-api")!
  static let originator = "Codex Desktop"
  static let userAgent = "Codex Desktop/26.601.21317 (Macintosh; Intel Mac OS X; arm64)"
  static let deviceKeyDomain = "codex-device-key-sign-payload/v1"
  static let websocketScope = "remote_control_controller_websocket"
}

enum CodexRemoteError: LocalizedError {
  case missingNormalToken
  case missingAccountID
  case missingRemoteClientID
  case invalidURL
  case requestFailed(Int, String)
  case decodingFailed(String, String, String)
  case invalidRemoteTokenResponse(String)
  case deviceIdentityHashMismatch

  var errorDescription: String? {
    switch self {
    case .missingNormalToken:
      "Missing OpenAI access token."
    case .missingAccountID:
      "Missing ChatGPT account ID."
    case .missingRemoteClientID:
      "Missing Codex remote client ID."
    case .invalidURL:
      "Invalid Codex remote URL."
    case .requestFailed(let status, let body):
      "Codex remote request failed with HTTP \(status): \(body)"
    case .decodingFailed(let context, let reason, let body):
      "Codex remote decode failed for \(context): \(reason). Body: \(body)"
    case .invalidRemoteTokenResponse(let reason):
      "Invalid remote-control token response: \(reason)"
    case .deviceIdentityHashMismatch:
      "Remote challenge device identity hash does not match the local device key."
    }
  }
}

struct CodexEnvironment: Decodable, Identifiable, Equatable {
  let envID: String
  let displayName: String
  let hostName: String?
  let online: Bool
  let busy: Bool
  let os: String?
  let osVersion: String?
  let arch: String?
  let clientName: String?
  let clientVersion: String?
  let lastSeenAt: String?

  var id: String { envID }

  enum CodingKeys: String, CodingKey {
    case envID = "env_id"
    case displayName = "display_name"
    case hostName = "host_name"
    case online
    case busy
    case os
    case osVersion = "os_version"
    case arch
    case clientName = "client_name"
    case clientVersion = "client_version"
    case lastSeenAt = "last_seen_at"
  }
}

struct CodexEnvironmentsResponse: Decodable {
  let items: [CodexEnvironment]
  let cursor: String?
}

struct CodexDeviceKeyChallenge: Decodable {
  let type: String
  let nonce: String
  let purpose: String
  let audience: String
  let challengeID: String
  let targetOrigin: String
  let targetPath: String
  let accountUserID: String
  let clientID: String
  let challengeToken: String
  let deviceIdentityHash: String?
  let challengeExpiresAt: Int

  enum CodingKeys: String, CodingKey {
    case type
    case nonce
    case purpose
    case audience
    case challengeID = "challenge_id"
    case targetOrigin = "target_origin"
    case targetPath = "target_path"
    case accountUserID = "account_user_id"
    case clientID = "client_id"
    case challengeToken = "challenge_token"
    case deviceIdentityHash = "device_identity_hash"
    case challengeExpiresAt = "challenge_expires_at"
  }
}

struct CodexEnrollStartResponse: Decodable {
  let clientID: String
  let accountUserID: String
  let deviceKeyChallenge: CodexDeviceKeyChallenge

  enum CodingKeys: String, CodingKey {
    case clientID = "client_id"
    case accountUserID = "account_user_id"
    case deviceKeyChallenge = "device_key_challenge"
  }
}

struct CodexRefreshStartResponse: Decodable {
  let deviceKeyChallenge: CodexDeviceKeyChallenge

  enum CodingKeys: String, CodingKey {
    case deviceKeyChallenge = "device_key_challenge"
  }

  init(from decoder: Decoder) throws {
    if let direct = try? CodexDeviceKeyChallenge(from: decoder) {
      self.deviceKeyChallenge = direct
      return
    }

    let container = try decoder.container(keyedBy: CodingKeys.self)
    self.deviceKeyChallenge = try container.decode(CodexDeviceKeyChallenge.self, forKey: .deviceKeyChallenge)
  }
}

struct CodexRemoteTokenResponse: Decodable {
  let clientID: String
  let accountUserID: String
  let remoteControlToken: String
  let expiresAt: Date
  let scopes: [String]

  enum CodingKeys: String, CodingKey {
    case clientID = "client_id"
    case accountUserID = "account_user_id"
    case remoteControlToken = "remote_control_token"
    case expiresAt = "expires_at"
    case scopes
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    self.clientID = try container.decode(String.self, forKey: .clientID)
    self.accountUserID = try container.decode(String.self, forKey: .accountUserID)
    self.remoteControlToken = try container.decode(String.self, forKey: .remoteControlToken)
    self.expiresAt = try container.decode(Date.self, forKey: .expiresAt)
    self.scopes = try container.decodeIfPresent([String].self, forKey: .scopes) ?? []
  }
}

struct CodexDeviceIdentity: Encodable {
  let keyID: String
  let publicKeySPKIDERBase64: String
  let protectionClass: String
  let algorithm = "ecdsa_p256_sha256"

  enum CodingKeys: String, CodingKey {
    case keyID = "key_id"
    case publicKeySPKIDERBase64 = "public_key_spki_der_base64"
    case algorithm
    case protectionClass = "protection_class"
  }
}

struct CodexDeviceKeyProof: Encodable {
  let challengeToken: String
  let keyID: String
  let signatureDERBase64: String
  let signedPayloadBase64: String
  let algorithm = "ecdsa_p256_sha256"

  enum CodingKeys: String, CodingKey {
    case challengeToken = "challenge_token"
    case keyID = "key_id"
    case signatureDERBase64 = "signature_der_base64"
    case signedPayloadBase64 = "signed_payload_base64"
    case algorithm
  }
}

struct CodexEnrollFinishRequest: Encodable {
  let clientID: String
  let stepUpToken: String
  let deviceIdentity: CodexDeviceIdentity
  let deviceKeyProof: CodexDeviceKeyProof

  enum CodingKeys: String, CodingKey {
    case clientID = "client_id"
    case stepUpToken = "step_up_token"
    case deviceIdentity = "device_identity"
    case deviceKeyProof = "device_key_proof"
  }
}

struct CodexRefreshStartRequest: Encodable {
  let clientID: String

  enum CodingKeys: String, CodingKey {
    case clientID = "client_id"
  }
}

struct CodexRefreshFinishRequest: Encodable {
  let clientID: String
  let deviceKeyProof: CodexDeviceKeyProof

  enum CodingKeys: String, CodingKey {
    case clientID = "client_id"
    case deviceKeyProof = "device_key_proof"
  }
}

struct CodexRemoteClient {
  private let jsonEncoder: JSONEncoder
  private let jsonDecoder: JSONDecoder

  init() {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    self.jsonEncoder = encoder

    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .custom { decoder in
      let container = try decoder.singleValueContainer()
      let string = try container.decode(String.self)
      if let date = ISO8601DateFormatter.codexRemoteWithFractionalSeconds.date(from: string) {
        return date
      }
      if let date = ISO8601DateFormatter.codexRemote.date(from: string) {
        return date
      }
      throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid ISO date")
    }
    self.jsonDecoder = decoder
  }

  func listEnvironments(accessToken: String, accountID: String) async throws -> [CodexEnvironment] {
    let data = try await send(
      path: "/codex/remote/control/environments?limit=50",
      method: "GET",
      accessToken: accessToken,
      accountID: accountID
    )
    return try decode(CodexEnvironmentsResponse.self, from: data, context: "list environments").items
  }

  func enrollStart(accessToken: String, accountID: String) async throws -> CodexEnrollStartResponse {
    let data = try await send(
      path: "/codex/remote/control/client/enroll/start",
      method: "POST",
      accessToken: accessToken,
      accountID: accountID,
      body: Data("{}".utf8)
    )
    return try decode(CodexEnrollStartResponse.self, from: data, context: "enroll start")
  }

  func enrollFinish(
    accessToken: String,
    accountID: String,
    request: CodexEnrollFinishRequest
  ) async throws -> CodexRemoteTokenResponse {
    let data = try await send(
      path: "/codex/remote/control/client/enroll/finish",
      method: "POST",
      accessToken: accessToken,
      accountID: accountID,
      body: try jsonEncoder.encode(request)
    )
    return try decode(CodexRemoteTokenResponse.self, from: data, context: "enroll finish")
  }

  func refreshStart(
    accessToken: String,
    accountID: String,
    clientID: String
  ) async throws -> CodexDeviceKeyChallenge {
    let data = try await send(
      path: "/codex/remote/control/client/refresh/start",
      method: "POST",
      accessToken: accessToken,
      accountID: accountID,
      body: try jsonEncoder.encode(CodexRefreshStartRequest(clientID: clientID))
    )
    return try decode(CodexRefreshStartResponse.self, from: data, context: "refresh start").deviceKeyChallenge
  }

  func refreshFinish(
    accessToken: String,
    accountID: String,
    request: CodexRefreshFinishRequest
  ) async throws -> CodexRemoteTokenResponse {
    let data = try await send(
      path: "/codex/remote/control/client/refresh/finish",
      method: "POST",
      accessToken: accessToken,
      accountID: accountID,
      body: try jsonEncoder.encode(request)
    )
    return try decode(CodexRemoteTokenResponse.self, from: data, context: "refresh finish")
  }

  func validateRemoteToken(
    _ response: CodexRemoteTokenResponse,
    clientID: String,
    accountUserID: String
  ) throws {
    if response.clientID != clientID {
      throw CodexRemoteError.invalidRemoteTokenResponse("client_id mismatch")
    }
    if response.accountUserID != accountUserID {
      throw CodexRemoteError.invalidRemoteTokenResponse("account_user_id mismatch")
    }
    if response.remoteControlToken.isEmpty {
      throw CodexRemoteError.invalidRemoteTokenResponse("missing remote_control_token")
    }
    if response.expiresAt <= Date() {
      throw CodexRemoteError.invalidRemoteTokenResponse("expired token")
    }
    if !response.scopes.isEmpty && !response.scopes.contains(CodexRemoteConstants.websocketScope) {
      throw CodexRemoteError.invalidRemoteTokenResponse("unexpected scopes: \(response.scopes.joined(separator: ", "))")
    }
  }

  private func send(
    path: String,
    method: String,
    accessToken: String,
    accountID: String,
    body: Data? = nil
  ) async throws -> Data {
    let url = try remoteURL(for: path)

    var request = URLRequest(url: url)
    request.httpMethod = method
    request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
    request.setValue(accountID, forHTTPHeaderField: "ChatGPT-Account-Id")
    request.setValue(CodexRemoteConstants.originator, forHTTPHeaderField: "originator")
    request.setValue(CodexRemoteConstants.userAgent, forHTTPHeaderField: "User-Agent")
    request.setValue("application/json", forHTTPHeaderField: "Accept")
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = body
    if CodexRuntimeEnvironment.isVerboseLoggingEnabled {
      print("Codex remote request: \(method) \(url.host() ?? "host")\(url.path), bodyBytes=\(body?.count ?? 0)")
    }

    let (data, response) = try await URLSession.shared.data(for: request)
    guard let httpResponse = response as? HTTPURLResponse else {
      throw CodexRemoteError.requestFailed(-1, "Missing HTTP response")
    }
    if CodexRuntimeEnvironment.isVerboseLoggingEnabled {
      print("Codex remote response: \(httpResponse.statusCode) \(url.host() ?? "host")\(url.path), bytes=\(data.count)")
    }

    guard (200..<300).contains(httpResponse.statusCode) else {
      throw CodexRemoteError.requestFailed(
        httpResponse.statusCode,
        redactedBody(data)
      )
    }

    return data
  }

  private func remoteURL(for path: String) throws -> URL {
    guard
      var base = URLComponents(url: CodexRemoteConstants.baseURL, resolvingAgainstBaseURL: false),
      let relative = URLComponents(string: path.trimmingCharacters(in: CharacterSet(charactersIn: "/")))
    else {
      throw CodexRemoteError.invalidURL
    }

    let basePath = base.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    let relativePath = relative.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    base.path = "/" + [basePath, relativePath]
      .filter { !$0.isEmpty }
      .joined(separator: "/")
    base.queryItems = relative.queryItems

    guard let url = base.url else {
      throw CodexRemoteError.invalidURL
    }
    return url
  }

  private func decode<T: Decodable>(_ type: T.Type, from data: Data, context: String) throws -> T {
    do {
      return try jsonDecoder.decode(type, from: data)
    } catch {
      throw CodexRemoteError.decodingFailed(context, error.localizedDescription, redactedBody(data))
    }
  }

  private func redactedBody(_ data: Data) -> String {
    guard !data.isEmpty else {
      return ""
    }
    let raw = String(data: data, encoding: .utf8) ?? "<\(data.count) bytes>"
    let limited = String(raw.prefix(1200))
    let pattern = #""(access_token|refresh_token|remote_control_token|step_up_token|challenge_token|signature_der_base64|signed_payload_base64|public_key_spki_der_base64)"\s*:\s*"[^"]*""#
    guard let regex = try? NSRegularExpression(pattern: pattern) else {
      return limited
    }
    let range = NSRange(limited.startIndex..<limited.endIndex, in: limited)
    return regex.stringByReplacingMatches(
      in: limited,
      range: range,
      withTemplate: #""$1":"[redacted]""#
    )
  }
}

enum CodexDeviceProofBuilder {
  static func deviceIdentity(for key: CodexDeviceKey) -> CodexDeviceIdentity {
    CodexDeviceIdentity(
      keyID: key.keyID,
      publicKeySPKIDERBase64: key.publicKeySPKIDERBase64,
      protectionClass: key.protectionClass
    )
  }

  static func proof(for challenge: CodexDeviceKeyChallenge, key: CodexDeviceKey) throws -> CodexDeviceKeyProof {
    let identityHash = deviceIdentityHash(
      keyID: key.keyID,
      publicKeySPKIDERBase64: key.publicKeySPKIDERBase64,
      protectionClass: key.protectionClass
    )

    if let expectedHash = challenge.deviceIdentityHash, expectedHash != identityHash {
      throw CodexRemoteError.deviceIdentityHashMismatch
    }

    let payload = OrderedJSON.object([
      ("accountUserId", .string(challenge.accountUserID)),
      ("audience", .string(challenge.audience)),
      ("challengeExpiresAt", .int(challenge.challengeExpiresAt)),
      ("challengeId", .string(challenge.challengeID)),
      ("clientId", .string(challenge.clientID)),
      ("deviceIdentitySha256Base64url", .string(identityHash)),
      ("nonce", .string(challenge.nonce)),
      ("targetOrigin", .string(challenge.targetOrigin)),
      ("targetPath", .string(challenge.targetPath)),
      ("type", .string("remoteControlClientEnrollment")),
    ])

    let signedPayload = OrderedJSON.object([
      ("domain", .string(CodexRemoteConstants.deviceKeyDomain)),
      ("payload", payload),
    ]).render()

    let signedPayloadData = Data(signedPayload.utf8)
    let signature = try key.signature(for: signedPayloadData)

    return CodexDeviceKeyProof(
      challengeToken: challenge.challengeToken,
      keyID: key.keyID,
      signatureDERBase64: signature.derRepresentation.base64EncodedString(),
      signedPayloadBase64: signedPayloadData.base64EncodedString()
    )
  }

  private static func deviceIdentityHash(keyID: String, publicKeySPKIDERBase64: String, protectionClass: String) -> String {
    let json = OrderedJSON.object([
      ("algorithm", .string("ecdsa_p256_sha256")),
      ("keyId", .string(keyID)),
      ("protectionClass", .string(protectionClass)),
      ("publicKeySpkiDerBase64", .string(publicKeySPKIDERBase64)),
    ])
    .render()
    return Data(SHA256.hash(data: Data(json.utf8))).base64URLEncodedString()
  }
}

enum OrderedJSON {
  case string(String)
  case int(Int)
  case array([OrderedJSON])
  case object([(String, OrderedJSON)])
  case null

  func render() -> String {
    switch self {
    case .string(let value):
      return Self.quote(value)
    case .int(let value):
      return String(value)
    case .array(let values):
      return "[" + values.map { $0.render() }.joined(separator: ",") + "]"
    case .object(let pairs):
      let body = pairs
        .map { Self.quote($0.0) + ":" + $0.1.render() }
        .joined(separator: ",")
      return "{" + body + "}"
    case .null:
      return "null"
    }
  }

  private static func quote(_ value: String) -> String {
    var result = "\""
    for scalar in value.unicodeScalars {
      switch scalar.value {
      case 0x22:
        result += "\\\""
      case 0x5C:
        result += "\\\\"
      case 0x08:
        result += "\\b"
      case 0x0C:
        result += "\\f"
      case 0x0A:
        result += "\\n"
      case 0x0D:
        result += "\\r"
      case 0x09:
        result += "\\t"
      case 0x00...0x1F:
        result += String(format: "\\u%04X", scalar.value)
      default:
        result.unicodeScalars.append(scalar)
      }
    }
    result += "\""
    return result
  }
}

private extension ISO8601DateFormatter {
  static let codexRemoteWithFractionalSeconds: ISO8601DateFormatter = {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter
  }()

  static let codexRemote: ISO8601DateFormatter = {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    return formatter
  }()
}
